//! Selectable DNS resolver engine: DNS-over-HTTPS (RFC 8484) and
//! DNS-over-TLS (RFC 7858), with a bounded, TTL-respecting cache.
//!
//! # Leak-prevention semantics (fail-closed)
//!
//! When an explicit mode (`DoH`, `DoT`, or `Custom`) is in effect, a
//! query that the selected transport cannot answer fails and stays
//! failed: the engine never retries the query against the platform
//! resolver. A navigation backed by a failed lookup therefore fails
//! rather than silently leaking the hostname to the system resolver.
//! Only `System` mode resolves through the platform resolver, and only
//! `ResolverError::InvalidConfig` (an unusable configuration, detected
//! at configure time) may trigger the shell's config-validation
//! fallback chain (workspace override → global settings → platform);
//! runtime `Network`/`NotFound` outcomes never can. See
//! `ResolverError::is_transport_failure`.
//!
//! Xray's DNS-outbound packet routing stays authoritative whenever a
//! privacy route is active (the route layer rejects system DNS on
//! privacy routes), and this engine serves engine-side hostname
//! resolution when a custom resolver mode is selected.
//!
//! # Honest enforcement surface
//!
//! The vendored Servo network stack exposes no request-level resolver
//! override hook (its `hyper` connector resolves through the system
//! resolver), so direct-mode browser requests still resolve through the
//! platform resolver regardless of the selected mode; this engine
//! cannot intercept them. Enforcement at this layer therefore covers
//! engine-side lookups only, composed with the Xray route guarantees
//! above. One further platform-resolver touch is unavoidable and
//! intentional: the DoH/DoT server's own address bootstraps through the
//! platform resolver at dial time (literal-IP `Custom` UDP servers and
//! literal-IP DoH/DoT hosts skip even that).
//!
//! # Lookup status surface
//!
//! The engine records bounded lookup status — the last lookup's mode,
//! outcome, and handling path plus fixed per-mode handled counters —
//! exposed via `ResolverEngine::status()` for the settings and
//! diagnostics UI. The counters cover engine-scope lookups only:
//! direct-mode browser requests bypass this engine (see above), and
//! literal-IP lookups involve no resolver at all.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use url::Url;

/// Maximum number of cached hostnames. The cache never holds more than
/// this many entries; when full, the soonest-to-expire entry is evicted.
pub const DNS_CACHE_MAX_ENTRIES: usize = 1024;

/// Cap on a single record's cached lifetime so pathological servers cannot
/// pin entries for days.
const DNS_CACHE_MAX_TTL: u64 = 86_400;

/// How long a negative (empty-answer) lookup stays cached.
const DNS_CACHE_NEGATIVE_TTL: u64 = 30;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
const DOT_DEFAULT_PORT: u16 = 853;
const DNS_UDP_DEFAULT_PORT: u16 = 53;
/// Classic DNS over UDP answers fit in 512 bytes unless EDNS is negotiated;
/// accept a multiple of that so untruncated larger replies still parse.
const DNS_UDP_RESPONSE_CAPACITY: usize = 4096;
const DOH_DEFAULT_PATH: &str = "/dns-query";
const DOH_CONTENT_TYPE: &str = "application/dns-message";

/// DNS resolver mode selected in browser settings.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolverMode {
    /// The platform resolver. Default and always valid.
    #[default]
    System,
    /// DNS-over-HTTPS (RFC 8484) against the configured server URL.
    Doh,
    /// DNS-over-TLS (RFC 7858) against the configured server host.
    Dot,
    /// A user-specified server with an explicitly chosen protocol.
    Custom,
}

impl ResolverMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::System => "System resolver",
            Self::Doh => "DNS-over-HTTPS",
            Self::Dot => "DNS-over-TLS",
            Self::Custom => "Custom resolver",
        }
    }

    /// One-line UI description of what the mode resolves against.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::System => {
                "Platform resolution. Xray keeps resolving when a privacy route is active."
            }
            Self::Doh => "DNS-over-HTTPS (RFC 8484) against the server below.",
            Self::Dot => "DNS-over-TLS (RFC 7858) against the server below.",
            Self::Custom => "User-specified server with the protocol chosen below.",
        }
    }

    /// Stable small-integer index for bounded per-mode status counters.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::System => 0,
            Self::Doh => 1,
            Self::Dot => 2,
            Self::Custom => 3,
        }
    }
}

/// Transport protocol for the `Custom` resolver mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustomResolverProtocol {
    /// Classic UDP DNS against a literal server address (`ip:port`).
    #[default]
    Udp,
    /// DNS-over-HTTPS (RFC 8484) against a `https://` endpoint.
    Doh,
    /// DNS-over-TLS (RFC 7858) against a `host[:port]` endpoint.
    Dot,
}

impl CustomResolverProtocol {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Udp => "Plain DNS",
            Self::Doh => "DoH",
            Self::Dot => "DoT",
        }
    }
}

/// Errors produced when configuring a custom resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverConfigError {
    /// The resolver URL is not a valid absolute `https://` URL.
    InvalidServerUrl,
    /// The resolver host is missing or malformed.
    InvalidServerHost,
    /// A resolver requiring a server was configured without one.
    MissingServer,
}

/// User-facing resolver configuration persisted with `BrowserSettings`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolverSettings {
    #[serde(default)]
    pub mode: ResolverMode,
    /// HTTPS endpoint for `DoH`, e.g. `https://dns.example/dns-query`.
    #[serde(default)]
    pub server_url: String,
    /// Host for `DoT`, e.g. `dns.example` or `dns.example:853`.
    #[serde(default)]
    pub server_host: String,
    /// Transport protocol for the `Custom` mode.
    #[serde(default)]
    pub custom_protocol: CustomResolverProtocol,
    /// Server for the `Custom` mode: `ip:port` for plain UDP, a `https://`
    /// URL for `DoH`, or `host[:port]` for `DoT`.
    #[serde(default)]
    pub custom_server: String,
}

impl ResolverSettings {
    /// Validates the settings against the selected mode.
    ///
    /// # Errors
    ///
    /// Returns an error when a non-system mode has no usable server, or
    /// when a provided URL/host does not parse.
    pub fn validate(&self) -> Result<(), ResolverConfigError> {
        match self.mode {
            ResolverMode::System => Ok(()),
            ResolverMode::Doh => {
                let trimmed = self.server_url.trim();
                if trimmed.is_empty() {
                    return Err(ResolverConfigError::MissingServer);
                }
                DohResolver::parse_endpoint(trimmed).map(|_| ())
            }
            ResolverMode::Dot => {
                let trimmed = self.server_host.trim();
                if trimmed.is_empty() {
                    return Err(ResolverConfigError::MissingServer);
                }
                DotResolver::parse_host(trimmed).map(|_| ())
            }
            ResolverMode::Custom => {
                let trimmed = self.custom_server.trim();
                if trimmed.is_empty() {
                    return Err(ResolverConfigError::MissingServer);
                }
                match self.custom_protocol {
                    CustomResolverProtocol::Udp => UdpResolver::parse_server(trimmed).map(|_| ()),
                    CustomResolverProtocol::Doh => DohResolver::parse_endpoint(trimmed).map(|_| ()),
                    CustomResolverProtocol::Dot => DotResolver::parse_host(trimmed).map(|_| ()),
                }
            }
        }
    }
}

/// One cached address-set entry.
#[derive(Clone, Debug)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}

impl CacheEntry {
    fn live(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

/// Bounded, TTL-respecting resolution cache.
///
/// Holds at most [`DNS_CACHE_MAX_ENTRIES`] hostnames. When the bound is
/// reached the entry with the earliest expiry is evicted; expired entries
/// are pruned first on every eviction pass.
#[derive(Default)]
pub struct DnsCache {
    entries: HashMap<String, CacheEntry>,
}

impl DnsCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached addresses for `hostname`, if still live.
    #[must_use]
    pub fn get(&self, hostname: &str) -> Option<&[IpAddr]> {
        let now = Instant::now();
        self.entries
            .get(hostname)
            .filter(|entry| entry.live(now))
            .map(|entry| entry.addresses.as_slice())
    }

    /// Stores an address set with the record TTL, capped at
    /// [`DNS_CACHE_MAX_TTL`]. Negative (empty) answers are capped at
    /// [`DNS_CACHE_NEGATIVE_TTL`] so failures retry quickly.
    pub fn put(&mut self, hostname: &str, addresses: Vec<IpAddr>, ttl: u64) {
        if self.entries.len() >= DNS_CACHE_MAX_ENTRIES {
            self.evict_one();
        }
        let ttl = ttl.min(DNS_CACHE_MAX_TTL);
        let ttl = if addresses.is_empty() {
            ttl.min(DNS_CACHE_NEGATIVE_TTL)
        } else {
            ttl
        };
        self.entries.insert(
            hostname.to_owned(),
            CacheEntry {
                addresses,
                expires_at: Instant::now() + Duration::from_secs(ttl),
            },
        );
    }

    /// Drops expired entries, then — if still full — evicts the entry
    /// with the earliest expiry.
    fn evict_one(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.live(now));
        if self.entries.len() < DNS_CACHE_MAX_ENTRIES {
            return;
        }
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.expires_at)
            .map(|(host, _)| host.clone());
        if let Some(oldest) = oldest {
            self.entries.remove(&oldest);
        }
    }

    /// Number of retained entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Discards every retained entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// True when nothing is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Errors returned by the resolver engine.
///
/// The variants split along the fail-closed boundary: [`Self::Network`]
/// and [`Self::NotFound`] are runtime query outcomes — a failed lookup
/// is final and never retried against the platform resolver — while
/// [`Self::InvalidConfig`] is a configure-time problem that the shell's
/// config-validation fallback chain (override → global → platform) may
/// resolve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolverError {
    /// The configured resolver is not usable (missing/invalid server).
    InvalidConfig(ResolverConfigError),
    /// The transport or query failed.
    Network(String),
    /// The server answered with an empty answer set.
    NotFound,
}

impl ResolverError {
    /// Whether this is a runtime transport/query failure rather than a
    /// configuration problem. Transport failures are terminal (the
    /// lookup fails closed); only [`Self::InvalidConfig`] may fall back
    /// to another configured resolver.
    #[must_use]
    pub const fn is_transport_failure(&self) -> bool {
        matches!(self, Self::Network(_) | Self::NotFound)
    }
}

impl std::fmt::Display for ResolverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "resolver config invalid: {error:?}"),
            Self::Network(message) => write!(formatter, "resolver network failure: {message}"),
            Self::NotFound => write!(formatter, "resolver found no addresses"),
        }
    }
}

impl std::error::Error for ResolverError {}

/// How the engine's resolve path handled a hostname.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverPath {
    /// Answered from the bounded TTL cache.
    Cache,
    /// Sent to the active transport, or to the platform resolver in
    /// `System` mode.
    Transport,
    /// The hostname was a literal IP address; no resolver was involved.
    Literal,
}

/// The outcome of one engine-side lookup, as shown by the resolver
/// status UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverLookupStatus {
    /// The mode active while the lookup ran.
    pub mode: ResolverMode,
    /// The hostname as looked up (IPv6 brackets stripped).
    pub host: String,
    /// How the engine handled the lookup.
    pub path: ResolverPath,
    /// The terminal error on failure; empty on success.
    pub error: Option<ResolverError>,
}

impl ResolverLookupStatus {
    /// True when the lookup produced addresses (including a literal-IP
    /// passthrough, which never consults a resolver).
    #[must_use]
    pub const fn success(&self) -> bool {
        self.error.is_none()
    }

    /// Whether a failed lookup failed closed on a transport or query
    /// failure ([`ResolverError::is_transport_failure`]) rather than a
    /// configuration problem.
    #[must_use]
    pub fn transport_failure(&self) -> bool {
        self.error
            .as_ref()
            .is_some_and(ResolverError::is_transport_failure)
    }
}

/// Bounded status snapshot of the engine's lookups: the last lookup
/// plus fixed per-mode handled counters. No lookup history is
/// retained, so the snapshot never grows with traffic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolverStatus {
    last: Option<ResolverLookupStatus>,
    /// Indexed by [`ResolverMode::index`].
    handled: [u64; 4],
}

impl ResolverStatus {
    /// The most recent lookup, if any.
    #[must_use]
    pub const fn last(&self) -> Option<&ResolverLookupStatus> {
        self.last.as_ref()
    }

    /// Lookups handled by `mode` so far — successes and terminal
    /// failures alike. Literal-IP passthroughs are not counted because
    /// no resolver handled them.
    #[must_use]
    pub const fn handled(&self, mode: ResolverMode) -> u64 {
        self.handled[mode.index()]
    }

    /// Sum of all per-mode counters.
    #[must_use]
    pub fn total_handled(&self) -> u64 {
        self.handled.iter().sum()
    }
}
/// Build a single-question DNS query packet for `hostname`.
fn build_query(hostname: &str, qtype: u16) -> io::Result<Vec<u8>> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS query hostname length is invalid",
        ));
    }
    let mut packet = Vec::with_capacity(12 + hostname.len() + 5);
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    for label in hostname.split('.') {
        let length = u8::try_from(label.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "DNS query label is too long")
        })?;
        packet.push(length);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

/// Skip a (possibly compressed) DNS name starting at `offset`.
fn skip_name(packet: &[u8], offset: usize, limit: usize) -> io::Result<usize> {
    let mut offset = offset;
    let mut jumped = false;
    let mut jump_target = 0usize;
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > limit || offset >= packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS name",
            ));
        }
        let length = packet[offset];
        match length {
            0 => {
                return if jumped {
                    Ok(jump_target)
                } else {
                    Ok(offset + 1)
                };
            }
            0xc0 => {
                if offset + 1 >= packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated DNS pointer",
                    ));
                }
                let pointer =
                    usize::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]) & 0x3fff);
                if !jumped {
                    jump_target = offset + 2;
                }
                jumped = true;
                offset = pointer;
            }
            _ => {
                let next = offset + 1 + usize::from(length);
                if next > packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated DNS label",
                    ));
                }
                offset = next;
            }
        }
    }
}

/// A parsed DNS response: addresses matching `qtype` plus the minimum TTL
/// across matching answers (0 when none matched).
#[derive(Debug)]
pub struct ParsedResponse {
    pub addresses: Vec<IpAddr>,
    pub ttl: u64,
}

/// Parse a DNS response, returning addresses matching `qtype` and the
/// minimum TTL across matching answers.
///
/// # Errors
///
/// Returns [`io::Error`] when the packet is truncated or malformed.
pub fn parse_response(packet: &[u8], qtype: u16) -> io::Result<ParsedResponse> {
    if packet.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DNS response",
        ));
    }
    let answer_count = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    let mut offset = 12usize;
    let mut limit = packet.len() * 2;
    offset = skip_name(packet, offset, limit)?;
    if offset + 4 > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DNS question",
        ));
    }
    offset += 4;
    let mut addresses = Vec::new();
    let mut ttl = 0u64;
    for _ in 0..answer_count {
        offset = skip_name(packet, offset, limit)?;
        limit = packet.len() * 2;
        if offset + 10 > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS answer",
            ));
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let record_ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let data_length = usize::from(u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]));
        offset += 10;
        if offset + data_length > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS RDATA",
            ));
        }
        if record_type == qtype {
            ttl = ttl
                .checked_add(u64::from(record_ttl))
                .unwrap_or(DNS_CACHE_MAX_TTL);
            match qtype {
                DNS_QTYPE_A if data_length == 4 => {
                    addresses.push(IpAddr::V4(std::net::Ipv4Addr::new(
                        packet[offset],
                        packet[offset + 1],
                        packet[offset + 2],
                        packet[offset + 3],
                    )));
                }
                DNS_QTYPE_AAAA if data_length == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[offset..offset + 16]);
                    addresses.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset += data_length;
    }
    Ok(ParsedResponse { addresses, ttl })
}

/// A single-shot DNS query transport: one DNS wire packet in, one out.
trait QueryTransport {
    fn query(&self, packet: &[u8]) -> io::Result<Vec<u8>>;
}

/// RFC 8484 resolver: one HTTPS POST of the wire packet per query.
struct DohResolver {
    host: String,
    port: u16,
    path: String,
}

impl DohResolver {
    /// Parses `https://host[:port]/path` (query strings preserved).
    ///
    /// # Errors
    ///
    /// Returns [`ResolverConfigError`] for non-`https` URLs, embedded
    /// credentials, or a missing host.
    pub fn parse_endpoint(raw: &str) -> Result<Self, ResolverConfigError> {
        let url = Url::parse(raw.trim()).map_err(|_| ResolverConfigError::InvalidServerUrl)?;
        if url.scheme() != "https" {
            return Err(ResolverConfigError::InvalidServerUrl);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ResolverConfigError::InvalidServerUrl);
        }
        let host = url
            .host_str()
            .ok_or(ResolverConfigError::InvalidServerUrl)?
            .to_owned();
        if host.is_empty() {
            return Err(ResolverConfigError::InvalidServerUrl);
        }
        let path = match (url.path(), url.query()) {
            ("/", None) => DOH_DEFAULT_PATH.to_owned(),
            (path, None) => path.to_owned(),
            (path, Some(query)) => format!("{path}?{query}"),
        };
        Ok(Self {
            host,
            port: url.port_or_known_default().unwrap_or(443),
            path,
        })
    }
}

impl QueryTransport for DohResolver {
    fn query(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let stream = connect_tls(self.dial_address()?, &self.host)?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nAccept: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host,
            DOH_CONTENT_TYPE,
            DOH_CONTENT_TYPE,
            packet.len(),
        );
        let mut tls = stream;
        tls.write_all(request.as_bytes())?;
        tls.write_all(packet)?;
        tls.flush()?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response)?;
        parse_doh_http_response(&response)
    }
}

impl DohResolver {
    /// Resolves the server host without recursion: literal IPs pass
    /// through; hostnames bootstrap through the system resolver.
    fn dial_address(&self) -> io::Result<SocketAddr> {
        dial_address(&self.host, self.port)
    }
}

/// RFC 7858 resolver: length-prefixed DNS frames over rustls TLS.
struct DotResolver {
    host: String,
    port: u16,
}

impl DotResolver {
    /// Parses `host[:port]`; bare hosts default to port 853. Bracketed
    /// IPv6 literals are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverConfigError`] when the host is empty, oversized,
    /// or the port does not parse.
    pub fn parse_host(raw: &str) -> Result<Self, ResolverConfigError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ResolverConfigError::InvalidServerHost);
        }
        let (host, port) = if let Some(rest) = trimmed.strip_prefix('[') {
            let close = rest
                .find(']')
                .ok_or(ResolverConfigError::InvalidServerHost)?;
            let host = &rest[..close];
            let port = match rest[close + 1..].strip_prefix(':') {
                Some(text) => text
                    .parse::<u16>()
                    .map_err(|_| ResolverConfigError::InvalidServerHost)?,
                None => DOT_DEFAULT_PORT,
            };
            (host.to_owned(), port)
        } else if let Some((host, port)) = trimmed.rsplit_once(':') {
            if host.is_empty() || host.contains(':') {
                (trimmed.to_owned(), DOT_DEFAULT_PORT)
            } else {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| ResolverConfigError::InvalidServerHost)?;
                (host.to_owned(), port)
            }
        } else {
            (trimmed.to_owned(), DOT_DEFAULT_PORT)
        };
        if host.is_empty() || host.len() > 253 {
            return Err(ResolverConfigError::InvalidServerHost);
        }
        Ok(Self { host, port })
    }
}

impl QueryTransport for DotResolver {
    fn query(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let mut tls = connect_tls(dial_address(&self.host, self.port)?, &self.host)?;
        let length = u16::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS packet is too large"))?;
        tls.write_all(&length.to_be_bytes())?;
        tls.write_all(packet)?;
        tls.flush()?;
        let mut response_length = [0u8; 2];
        tls.read_exact(&mut response_length)?;
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(response_length))];
        tls.read_exact(&mut response)?;
        Ok(response)
    }
}

/// Classic UDP DNS resolver (RFC 1035): one datagram per query against a
/// literal server address. Hostnames are rejected at parse time because a
/// custom resolver that itself needs resolving would recurse through the
/// very resolver being configured.
struct UdpResolver {
    server: SocketAddr,
}

impl UdpResolver {
    /// Parses `ip:port`; a bare IP literal defaults to port 53. Bracketed
    /// IPv6 literals are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverConfigError`] unless the input is a literal IP
    /// address with an explicit or default port.
    pub fn parse_server(raw: &str) -> Result<Self, ResolverConfigError> {
        let trimmed = raw.trim();
        if let Ok(server) = trimmed.parse::<SocketAddr>() {
            if server.port() != 0 {
                return Ok(Self { server });
            }
            return Err(ResolverConfigError::InvalidServerHost);
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(Self {
                server: SocketAddr::new(ip, DNS_UDP_DEFAULT_PORT),
            });
        }
        Err(ResolverConfigError::InvalidServerHost)
    }
}

impl QueryTransport for UdpResolver {
    fn query(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let bind: SocketAddr = if self.server.is_ipv4() {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(DNS_QUERY_TIMEOUT))?;
        socket.set_write_timeout(Some(DNS_QUERY_TIMEOUT))?;
        socket.connect(self.server)?;
        socket.send(packet)?;
        let mut response = vec![0u8; DNS_UDP_RESPONSE_CAPACITY];
        let received = socket.recv(&mut response)?;
        response.truncate(received);
        Ok(response)
    }
}

/// First dialable address for `host:port`, literal IPs passing through.
fn dial_address(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "resolver has no address"))
}

/// Splits an HTTP/1.1 `DoH` response into status check + body.
fn parse_doh_http_response(raw: &[u8]) -> io::Result<Vec<u8>> {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DoH response has no header end")
        })?;
    let headers = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DoH headers not UTF-8"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DoH response status invalid"))?;
    if status != 200 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DoH server returned HTTP {status}"),
        ));
    }
    let body = &raw[header_end + 4..];
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return decode_chunked_body(body);
    }
    Ok(body.to_vec())
}

/// Decodes an HTTP chunked body.
fn decode_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut cursor = 0usize;
    while cursor < body.len() {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size truncated"))?
            + cursor;
        let size_text = std::str::from_utf8(&body[cursor..line_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size not UTF-8"))?;
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size invalid"))?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        if cursor + size > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk truncated",
            ));
        }
        decoded.extend_from_slice(&body[cursor..cursor + size]);
        cursor += size + 2;
    }
    Ok(decoded)
}

/// The selectable resolver engine: mode dispatch, bounded TTL cache, and
/// the query transports.
#[derive(Default)]
pub struct ResolverEngine {
    mode: ResolverMode,
    doh: Option<DohResolver>,
    dot: Option<DotResolver>,
    udp: Option<UdpResolver>,
    cache: Mutex<DnsCache>,
    /// Bounded lookup status for the UI; never grows with traffic.
    status: Mutex<ResolverStatus>,
}
type ResolverTransports = (
    Option<DohResolver>,
    Option<DotResolver>,
    Option<UdpResolver>,
);

/// Builds the single active transport for `settings`, or `None` for the
/// system resolver.
fn transports_from_settings(
    settings: &ResolverSettings,
) -> Result<ResolverTransports, ResolverError> {
    settings.validate().map_err(ResolverError::InvalidConfig)?;
    let transport = match settings.mode {
        ResolverMode::System => (None, None, None),
        ResolverMode::Doh => (
            Some(
                DohResolver::parse_endpoint(settings.server_url.trim())
                    .map_err(ResolverError::InvalidConfig)?,
            ),
            None,
            None,
        ),
        ResolverMode::Dot => (
            None,
            Some(
                DotResolver::parse_host(settings.server_host.trim())
                    .map_err(ResolverError::InvalidConfig)?,
            ),
            None,
        ),
        ResolverMode::Custom => match settings.custom_protocol {
            CustomResolverProtocol::Doh => (
                Some(
                    DohResolver::parse_endpoint(settings.custom_server.trim())
                        .map_err(ResolverError::InvalidConfig)?,
                ),
                None,
                None,
            ),
            CustomResolverProtocol::Dot => (
                None,
                Some(
                    DotResolver::parse_host(settings.custom_server.trim())
                        .map_err(ResolverError::InvalidConfig)?,
                ),
                None,
            ),
            CustomResolverProtocol::Udp => (
                None,
                None,
                Some(
                    UdpResolver::parse_server(settings.custom_server.trim())
                        .map_err(ResolverError::InvalidConfig)?,
                ),
            ),
        },
    };
    Ok(transport)
}

impl ResolverEngine {
    /// Builds an engine from persisted settings.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError::InvalidConfig`] when the selected mode has
    /// a missing or malformed server configuration.
    pub fn from_settings(settings: &ResolverSettings) -> Result<Self, ResolverError> {
        let (doh, dot, udp) = transports_from_settings(settings)?;
        Ok(Self {
            mode: settings.mode,
            doh,
            dot,
            udp,
            status: Mutex::new(ResolverStatus::default()),
            cache: Mutex::new(DnsCache::new()),
        })
    }

    /// Hot-swaps the engine configuration without dropping the engine.
    ///
    /// On success the cached answers are discarded because they belong to
    /// the previous server. On failure the previous configuration stays
    /// active and the cache is untouched.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError::InvalidConfig`] when `settings` is not a
    /// usable resolver configuration.
    pub fn apply_settings(&mut self, settings: &ResolverSettings) -> Result<(), ResolverError> {
        let (doh, dot, udp) = transports_from_settings(settings)?;
        self.mode = settings.mode;
        self.doh = doh;
        self.dot = dot;
        self.udp = udp;
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
        Ok(())
    }

    #[must_use]
    pub const fn mode(&self) -> &ResolverMode {
        &self.mode
    }

    /// Resolves `hostname`, consulting the bounded TTL cache first.
    ///
    /// Literal IPs bypass both cache and transport. System mode delegates
    /// to the platform resolver without caching (the OS keeps its own
    /// caches).
    ///
    /// Explicit modes (`DoH`, `DoT`, `Custom`) are fail-closed: a
    /// transport or query failure is returned as-is and the lookup is
    /// never retried against the platform resolver, so a failed lookup
    /// cannot leak the hostname to the system resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError`] for invalid configuration, transport
    /// failure, or an empty answer set. Transport failures
    /// ([`ResolverError::is_transport_failure`]) are terminal.
    pub fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, ResolverError> {
        let host = hostname
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(hostname);
        let (result, path) = self.resolve_inner(host);
        self.record_status(host, path, result.as_ref().err().cloned());
        result
    }

    /// The resolution logic behind [`Self::resolve`], returning how the
    /// engine handled the lookup.
    fn resolve_inner(&self, host: &str) -> (Result<Vec<IpAddr>, ResolverError>, ResolverPath) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return (Ok(vec![ip]), ResolverPath::Literal);
        }
        if self.mode == ResolverMode::System {
            return (system_resolve(host), ResolverPath::Transport);
        }
        if let Some(cached) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(host).map(<[IpAddr]>::to_vec))
        {
            if cached.is_empty() {
                return (Err(ResolverError::NotFound), ResolverPath::Cache);
            }
            return (Ok(cached), ResolverPath::Cache);
        }
        match self.query_host(host) {
            Ok((addresses, ttl)) => {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.put(host, addresses.clone(), ttl);
                }
                if addresses.is_empty() {
                    (Err(ResolverError::NotFound), ResolverPath::Transport)
                } else {
                    (Ok(addresses), ResolverPath::Transport)
                }
            }
            Err(error) => (Err(error), ResolverPath::Transport),
        }
    }

    /// Records one lookup into the bounded status snapshot. Literal-IP
    /// passthroughs update `last` but leave the per-mode counters alone:
    /// no resolver handled them.
    fn record_status(&self, host: &str, path: ResolverPath, error: Option<ResolverError>) {
        if let Ok(mut status) = self.status.lock() {
            status.last = Some(ResolverLookupStatus {
                mode: self.mode,
                host: host.to_owned(),
                path,
                error,
            });
            if path != ResolverPath::Literal {
                status.handled[self.mode.index()] += 1;
            }
        }
    }

    /// A bounded snapshot of the engine's lookup status for the UI: the
    /// last lookup's mode, outcome, and handling path, plus fixed
    /// per-mode handled counters. Engine-scope only — see the module
    /// docs for what this engine cannot intercept.
    #[must_use]
    pub fn status(&self) -> ResolverStatus {
        self.status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    /// Number of entries currently retained by the cache.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map_or(0, |cache| cache.len())
    }

    /// Queries A then AAAA; returns the addresses and their TTL.
    fn query_host(&self, host: &str) -> Result<(Vec<IpAddr>, u64), ResolverError> {
        let transport: &dyn QueryTransport =
            match (self.doh.as_ref(), self.dot.as_ref(), self.udp.as_ref()) {
                (Some(doh), _, _) => doh,
                (None, Some(dot), _) => dot,
                (None, None, Some(udp)) => udp,
                (None, None, None) => {
                    return Err(ResolverError::InvalidConfig(
                        ResolverConfigError::MissingServer,
                    ));
                }
            };
        let exchange = |packet: &[u8], qtype: u16| -> io::Result<ParsedResponse> {
            let response = transport.query(packet)?;
            if response.len() < 12 || response[2] & 0x80 == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS server did not return a valid response",
                ));
            }
            parse_response(&response, qtype)
        };
        let query_a = build_query(host, DNS_QTYPE_A).map_err(|error| network_error(&error))?;
        let parsed_a = exchange(&query_a, DNS_QTYPE_A).map_err(|error| network_error(&error))?;
        if !parsed_a.addresses.is_empty() {
            return Ok((parsed_a.addresses, parsed_a.ttl));
        }
        let query_aaaa =
            build_query(host, DNS_QTYPE_AAAA).map_err(|error| network_error(&error))?;
        let parsed_aaaa =
            exchange(&query_aaaa, DNS_QTYPE_AAAA).map_err(|error| network_error(&error))?;
        Ok((parsed_aaaa.addresses, parsed_aaaa.ttl))
    }
}

fn network_error(error: &io::Error) -> ResolverError {
    ResolverError::Network(error.to_string())
}

fn system_resolve(host: &str) -> Result<Vec<IpAddr>, ResolverError> {
    let addresses: Vec<IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .map_err(|error| ResolverError::Network(error.to_string()))?
        .map(|socket| socket.ip())
        .collect();
    if addresses.is_empty() {
        return Err(ResolverError::NotFound);
    }
    Ok(addresses)
}

/// Opens a rustls TLS client stream to `address` for `server_name`, using
/// the same webpki root set as the Xray transports.
fn connect_tls(
    address: SocketAddr,
    server_name: &str,
) -> io::Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let stream = TcpStream::connect_timeout(&address, DNS_CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(DNS_QUERY_TIMEOUT))?;
    stream.set_write_timeout(Some(DNS_QUERY_TIMEOUT))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name =
        rustls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid TLS server name: {error}"),
            )
        })?;
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error))?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

#[cfg(test)]
mod tests {
    use super::{
        build_query, parse_doh_http_response, parse_response, CustomResolverProtocol, DnsCache,
        DohResolver, DotResolver, ResolverConfigError, ResolverEngine, ResolverError, ResolverMode,
        ResolverPath, ResolverSettings, UdpResolver, DNS_CACHE_MAX_ENTRIES, DNS_QTYPE_A,
    };
    use std::net::{SocketAddr, UdpSocket};

    #[test]
    fn test_cache_respects_ttl_expiry() {
        let mut cache = DnsCache::new();
        let address = "1.2.3.4".parse().unwrap();
        cache.put("expired.test", vec![address], 0);
        assert!(cache.get("expired.test").is_none());

        cache.put("live.test", vec![address], 300);
        assert_eq!(cache.get("live.test"), Some([address].as_slice()));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_caps_huge_ttl_and_negative_answers() {
        let mut cache = DnsCache::new();
        let address = "1.2.3.4".parse().unwrap();
        cache.put("big.test", vec![address], u64::MAX);
        assert_eq!(cache.get("big.test"), Some([address].as_slice()));

        cache.put("empty.test", Vec::new(), 10_000);
        assert_eq!(cache.get("empty.test"), Some([].as_slice()));
    }

    #[test]
    fn test_cache_evicts_earliest_expiry_when_full() {
        let mut cache = DnsCache::new();
        let address = "1.2.3.4".parse().unwrap();
        for index in 0..DNS_CACHE_MAX_ENTRIES {
            cache.put(&format!("host-{index}.test"), vec![address], 60);
        }
        assert_eq!(cache.len(), DNS_CACHE_MAX_ENTRIES);
        cache.put("overflow.test", vec![address], 60);
        assert_eq!(cache.len(), DNS_CACHE_MAX_ENTRIES);
        assert!(cache.get("host-0.test").is_none());
        assert!(cache.get("overflow.test").is_some());
    }

    #[test]
    fn test_mode_selection_from_settings() {
        let system = ResolverEngine::from_settings(&ResolverSettings::default()).unwrap();
        assert_eq!(system.mode(), &ResolverMode::System);
        assert_eq!(system.cache_len(), 0);

        let doh = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Doh,
            server_url: "https://dns.example/dns-query".to_owned(),
            ..ResolverSettings::default()
        })
        .unwrap();
        assert_eq!(doh.mode(), &ResolverMode::Doh);

        let dot = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Dot,
            server_host: "dns.example".to_owned(),
            ..ResolverSettings::default()
        })
        .unwrap();
        assert_eq!(dot.mode(), &ResolverMode::Dot);
    }

    #[test]
    fn test_invalid_mode_configurations_are_rejected() {
        let missing = ResolverSettings {
            mode: ResolverMode::Doh,
            ..ResolverSettings::default()
        };
        assert!(matches!(
            ResolverEngine::from_settings(&missing),
            Err(ResolverError::InvalidConfig(
                ResolverConfigError::MissingServer
            ))
        ));

        let plaintext = ResolverSettings {
            mode: ResolverMode::Doh,
            server_url: "http://dns.example/dns-query".to_owned(),
            ..ResolverSettings::default()
        };
        assert!(matches!(
            ResolverEngine::from_settings(&plaintext),
            Err(ResolverError::InvalidConfig(
                ResolverConfigError::InvalidServerUrl
            ))
        ));

        let dot_missing = ResolverSettings {
            mode: ResolverMode::Dot,
            ..ResolverSettings::default()
        };
        assert!(matches!(
            ResolverEngine::from_settings(&dot_missing),
            Err(ResolverError::InvalidConfig(
                ResolverConfigError::MissingServer
            ))
        ));
    }

    #[test]
    fn test_doh_endpoint_parsing() {
        let parsed = DohResolver::parse_endpoint("https://dns.example/dns-query?dns").unwrap();
        assert_eq!(parsed.host, "dns.example");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/dns-query?dns");

        let default_path = DohResolver::parse_endpoint("https://dns.example").unwrap();
        assert_eq!(default_path.path, "/dns-query");

        let explicit_port = DohResolver::parse_endpoint("https://dns.example:8443/query").unwrap();
        assert_eq!(explicit_port.port, 8443);

        assert!(matches!(
            DohResolver::parse_endpoint("http://dns.example/dns-query"),
            Err(ResolverConfigError::InvalidServerUrl)
        ));
        assert!(matches!(
            DohResolver::parse_endpoint("https://user:pass@example/dns-query"),
            Err(ResolverConfigError::InvalidServerUrl)
        ));
    }

    #[test]
    fn test_dot_host_parsing() {
        let bare = DotResolver::parse_host("dns.example").unwrap();
        assert_eq!(bare.host, "dns.example");
        assert_eq!(bare.port, 853);

        let ported = DotResolver::parse_host("dns.example:8853").unwrap();
        assert_eq!(ported.port, 8853);

        let literal = DotResolver::parse_host("[2001:db8::1]:853").unwrap();
        assert_eq!(literal.host, "2001:db8::1");
        assert_eq!(literal.port, 853);

        assert!(matches!(
            DotResolver::parse_host(""),
            Err(ResolverConfigError::InvalidServerHost)
        ));
        assert!(matches!(
            DotResolver::parse_host("dns.example:notaport"),
            Err(ResolverConfigError::InvalidServerHost)
        ));
    }

    #[test]
    fn test_parse_response_extracts_ttl_and_addresses() {
        let query = build_query("example.test", DNS_QTYPE_A).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&120u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[1, 2, 3, 4]);

        let parsed = parse_response(&response, DNS_QTYPE_A).unwrap();
        assert_eq!(
            parsed.addresses,
            vec!["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(parsed.ttl, 120);
    }

    #[test]
    fn test_parse_response_empty_answer_yields_negative_entry() {
        let query = build_query("missing.test", DNS_QTYPE_A).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes());
        response.extend_from_slice(&0x8183u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);

        let parsed = parse_response(&response, DNS_QTYPE_A).unwrap();
        assert!(parsed.addresses.is_empty());
        assert_eq!(parsed.ttl, 0);

        let mut cache = DnsCache::new();
        cache.put("missing.test", parsed.addresses.clone(), 10);
        assert_eq!(cache.get("missing.test"), Some([].as_slice()));
        // A zero-TTL negative answer expires immediately, as the server asked.
        cache.put("zero.test", Vec::new(), parsed.ttl);
        assert!(cache.get("zero.test").is_none());
    }

    #[test]
    fn test_doh_http_response_parsing() {
        let body: &[u8] = &[0x12, 0x34];
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut raw = response.into_bytes();
        raw.extend_from_slice(body);
        assert_eq!(parse_doh_http_response(&raw).unwrap(), body.to_vec());

        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n\x12\x34\r\n0\r\n\r\n";
        assert_eq!(parse_doh_http_response(chunked).unwrap(), body.to_vec());

        let rejected = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_doh_http_response(rejected).is_err());
    }

    #[test]
    fn test_literal_ip_bypasses_transports_and_cache() {
        let engine = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Dot,
            server_host: "dns.example".to_owned(),
            ..ResolverSettings::default()
        })
        .unwrap();
        let addresses = engine.resolve("2001:db8::1").unwrap();
        assert_eq!(
            addresses,
            vec!["2001:db8::1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(engine.cache_len(), 0);
    }

    #[test]
    fn test_custom_server_parsing() {
        let ported = UdpResolver::parse_server("1.1.1.1:5353").unwrap();
        assert_eq!(ported.server.to_string(), "1.1.1.1:5353");

        let bare = UdpResolver::parse_server("1.1.1.1").unwrap();
        assert_eq!(bare.server.port(), 53);

        let v6 = UdpResolver::parse_server("[2001:db8::1]:53").unwrap();
        assert_eq!(v6.server.to_string(), "[2001:db8::1]:53");

        // A custom plain-DNS server must be a literal address: resolving
        // its hostname would recurse through the resolver being configured.
        assert!(matches!(
            UdpResolver::parse_server("dns.example"),
            Err(ResolverConfigError::InvalidServerHost)
        ));
        assert!(matches!(
            UdpResolver::parse_server("1.1.1.1:0"),
            Err(ResolverConfigError::InvalidServerHost)
        ));
    }

    #[test]
    fn test_custom_mode_selection_and_validation() {
        let custom = ResolverSettings {
            mode: ResolverMode::Custom,
            custom_protocol: CustomResolverProtocol::Udp,
            custom_server: "1.1.1.1:5353".to_owned(),
            ..ResolverSettings::default()
        };
        custom.validate().unwrap();
        assert_eq!(
            ResolverEngine::from_settings(&custom).unwrap().mode(),
            &ResolverMode::Custom
        );

        let custom_over_https = ResolverSettings {
            mode: ResolverMode::Custom,
            custom_protocol: CustomResolverProtocol::Doh,
            custom_server: "https://dns.example/dns-query".to_owned(),
            ..ResolverSettings::default()
        };
        custom_over_https.validate().unwrap();

        let custom_over_tls = ResolverSettings {
            mode: ResolverMode::Custom,
            custom_protocol: CustomResolverProtocol::Dot,
            custom_server: "dns.example:8853".to_owned(),
            ..ResolverSettings::default()
        };
        custom_over_tls.validate().unwrap();

        let missing = ResolverSettings {
            mode: ResolverMode::Custom,
            ..ResolverSettings::default()
        };
        assert!(matches!(
            missing.validate(),
            Err(ResolverConfigError::MissingServer)
        ));

        let hostname_udp = ResolverSettings {
            mode: ResolverMode::Custom,
            custom_protocol: CustomResolverProtocol::Udp,
            custom_server: "dns.example".to_owned(),
            ..ResolverSettings::default()
        };
        assert!(matches!(
            hostname_udp.validate(),
            Err(ResolverConfigError::InvalidServerHost)
        ));

        let plaintext_doh = ResolverSettings {
            mode: ResolverMode::Custom,
            custom_protocol: CustomResolverProtocol::Doh,
            custom_server: "http://dns.example/dns-query".to_owned(),
            ..ResolverSettings::default()
        };
        assert!(matches!(
            plaintext_doh.validate(),
            Err(ResolverConfigError::InvalidServerUrl)
        ));
    }

    /// Spawns a loopback UDP DNS server answering `queries` queries with a
    /// single A record for `answer`, then returns its bound address.
    fn spawn_udp_dns_server(answer: [u8; 4], queries: usize) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..queries {
                let mut query = [0u8; 512];
                let Ok((received, peer)) = socket.recv_from(&mut query) else {
                    break;
                };
                if received < 12 {
                    continue;
                }
                let mut response = Vec::new();
                response.extend_from_slice(&query[..2]);
                response.extend_from_slice(&0x8180u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&query[12..received]);
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&answer);
                socket.send_to(&response, peer).unwrap();
            }
        });
        address
    }

    #[test]
    fn test_custom_udp_resolve_and_hot_swap_clears_cache() {
        let first = spawn_udp_dns_server([127, 0, 0, 1], 1);
        let second = spawn_udp_dns_server([127, 0, 0, 2], 2);
        let mut engine = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Custom,
            custom_protocol: CustomResolverProtocol::Udp,
            custom_server: first.to_string(),
            ..ResolverSettings::default()
        })
        .unwrap();
        assert_eq!(
            engine.resolve("example.test").unwrap(),
            vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(engine.cache_len(), 1);

        // A successful hot swap discards answers cached from the old server.
        engine
            .apply_settings(&ResolverSettings {
                mode: ResolverMode::Custom,
                custom_protocol: CustomResolverProtocol::Udp,
                custom_server: second.to_string(),
                ..ResolverSettings::default()
            })
            .unwrap();
        assert_eq!(engine.mode(), &ResolverMode::Custom);
        assert_eq!(engine.cache_len(), 0);
        assert_eq!(
            engine.resolve("example.test").unwrap(),
            vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()]
        );

        // A rejected swap keeps the previous configuration fully active.
        assert!(matches!(
            engine.apply_settings(&ResolverSettings {
                mode: ResolverMode::Custom,
                ..ResolverSettings::default()
            }),
            Err(ResolverError::InvalidConfig(
                ResolverConfigError::MissingServer
            ))
        ));
        assert_eq!(engine.mode(), &ResolverMode::Custom);
        assert_eq!(
            engine.resolve("other.test").unwrap(),
            vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    /// A hostname the platform resolver can answer, so any success in
    /// these tests would prove a system fallback happened.
    #[test]
    fn test_transport_failure_is_fail_closed() {
        let engine = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Dot,
            // Loopback port 1 refuses connections: a syntactically valid
            // but unreachable transport, rejected at query time only.
            server_host: "127.0.0.1:1".to_owned(),
            ..ResolverSettings::default()
        })
        .unwrap();
        let error = engine.resolve("localhost").unwrap_err();
        assert!(error.is_transport_failure());
        // Repeated lookups stay failed: no fallback, no cached shortcut.
        assert!(engine.resolve("localhost").is_err());
    }

    #[test]
    fn test_system_mode_uses_the_platform_resolver() {
        let engine = ResolverEngine::default();
        let addresses = engine.resolve("localhost").unwrap();
        assert!(!addresses.is_empty());
        // System mode never caches (the OS keeps its own caches).

        assert_eq!(engine.cache_len(), 0);
    }

    #[test]
    fn test_status_records_handled_lookups_per_mode() {
        let server = spawn_udp_dns_server([127, 0, 0, 1], 1);
        let mut engine = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Custom,
            custom_protocol: CustomResolverProtocol::Udp,
            custom_server: server.to_string(),
            ..ResolverSettings::default()
        })
        .unwrap();
        assert!(engine.resolve("example.test").is_ok());
        // The second lookup is a cache hit, still handled by Custom mode.
        assert!(engine.resolve("example.test").is_ok());

        let status = engine.status();
        assert_eq!(status.handled(ResolverMode::Custom), 2);
        assert_eq!(status.total_handled(), 2);
        let last = status.last().unwrap();
        assert_eq!(last.mode, ResolverMode::Custom);
        assert_eq!(last.host, "example.test");
        assert_eq!(last.path, ResolverPath::Cache);
        assert!(last.success());

        // System-mode lookups land in the System bucket; the Custom
        // counters survive the hot swap.
        engine.apply_settings(&ResolverSettings::default()).unwrap();
        assert!(engine.resolve("localhost").is_ok());
        let status = engine.status();
        assert_eq!(status.handled(ResolverMode::System), 1);
        assert_eq!(status.handled(ResolverMode::Custom), 2);
        assert_eq!(status.last().unwrap().mode, ResolverMode::System);
    }

    #[test]
    fn test_status_records_fail_closed_transport_failures() {
        let engine = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Dot,
            // Loopback port 1 refuses connections: a syntactically valid
            // but unreachable transport.
            server_host: "127.0.0.1:1".to_owned(),
            ..ResolverSettings::default()
        })
        .unwrap();
        let error = engine.resolve("localhost").unwrap_err();
        assert!(error.is_transport_failure());
        assert!(engine.resolve("localhost").is_err());

        // Both failed lookups are handled by Dot mode and the last one
        // is reported as a fail-closed transport failure, so the UI can
        // surface it instead of leaving it silent.
        let status = engine.status();
        assert_eq!(status.handled(ResolverMode::Dot), 2);
        let last = status.last().unwrap();
        assert_eq!(last.mode, ResolverMode::Dot);
        assert!(!last.success());
        assert!(last.transport_failure());
        assert_eq!(last.error, Some(error));
    }

    #[test]
    fn test_status_stays_bounded_across_many_lookups() {
        let engine = ResolverEngine::from_settings(&ResolverSettings {
            mode: ResolverMode::Dot,
            server_host: "dns.example".to_owned(),
            ..ResolverSettings::default()
        })
        .unwrap();
        for index in 0..1000u32 {
            let host = format!("10.{}.{}.1", index / 256, index % 256);
            assert!(engine.resolve(&host).is_ok());
        }

        // Literal IPs involve no resolver: nothing is counted per mode,
        // and only the last lookup is retained — never a history.
        let status = engine.status();
        assert_eq!(status.total_handled(), 0);
        let last = status.last().unwrap();
        assert_eq!(last.path, ResolverPath::Literal);
        assert!(last.success());
        assert_eq!(last.host, "10.3.231.1");
    }
}
