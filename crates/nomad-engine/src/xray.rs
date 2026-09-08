use std::fmt::{Display, Formatter, Write as FmtWrite};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::Engine;
use bytes::Bytes;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, XChaCha20Poly1305, XNonce};
use crc32fast::Hasher as Crc32Hasher;
use h2::SendStream;
use http::Request;
use md5::Md5;
use ring::rand::SecureRandom;
use ring::{aead, hmac, rand};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use sha2::{Digest, Sha224};
use std::fs;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tungstenite::{client, Message, WebSocket};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::network::{ProxyEndpoint, ProxyScheme};

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TARGET_HOST_LENGTH: usize = 255;
const MAX_RELAY_BUFFER: usize = 4 * 1024 * 1024;

#[cfg(feature = "fuzzing")]
pub const FUZZ_INPUT_LIMIT: usize = 1024 * 1024;

#[path = "mkcp.rs"]
mod mkcp;
use mkcp::MkcpStream;

#[path = "reality.rs"]
mod reality;
use reality::RealityStream;

#[path = "wireguard.rs"]
mod wireguard;
use wireguard::WireGuardStream;

/// Xray outbound protocol names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XrayProtocol {
    Blackhole,
    Dns,
    Freedom,
    Http,
    Loopback,
    Shadowsocks,
    Socks,
    Trojan,
    Vless,
    Vmess,
    Hysteria,
    WireGuard,
}

impl XrayProtocol {
    /// Parse an Xray outbound protocol name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "blackhole" | "block" => Self::Blackhole,
            "dns" => Self::Dns,
            "freedom" | "direct" => Self::Freedom,
            "http" => Self::Http,
            "loopback" => Self::Loopback,
            "shadowsocks" => Self::Shadowsocks,
            "socks" => Self::Socks,
            "trojan" => Self::Trojan,
            "vless" => Self::Vless,
            "vmess" => Self::Vmess,
            "hysteria" => Self::Hysteria,
            "wireguard" => Self::WireGuard,
            _ => return None,
        })
    }

    /// Return the canonical Xray JSON protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blackhole => "blackhole",
            Self::Dns => "dns",
            Self::Freedom => "freedom",
            Self::Http => "http",
            Self::Loopback => "loopback",
            Self::Shadowsocks => "shadowsocks",
            Self::Socks => "socks",
            Self::Trojan => "trojan",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Hysteria => "hysteria",
            Self::WireGuard => "wireguard",
        }
    }
}

/// Xray stream transport method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XrayTransport {
    Raw,
    Xhttp,
    Mkcp,
    Grpc,
    WebSocket,
    HttpUpgrade,
    Hysteria,
}

impl XrayTransport {
    /// Parse an Xray `streamSettings.method` or `streamSettings.network` value.
    /// Missing values use RAW; official Xray aliases are accepted alongside
    /// Nomad's canonical names.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Option<Self> {
        Some(match value.unwrap_or("raw") {
            "raw" | "tcp" => Self::Raw,
            "xhttp" => Self::Xhttp,
            "mkcp" | "kcp" => Self::Mkcp,
            "grpc" => Self::Grpc,
            "websocket" | "ws" => Self::WebSocket,
            "httpupgrade" => Self::HttpUpgrade,
            "hysteria" => Self::Hysteria,
            _ => return None,
        })
    }

    /// Return the canonical Xray JSON transport name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Xhttp => "xhttp",
            Self::Mkcp => "mkcp",
            Self::Grpc => "grpc",
            Self::WebSocket => "websocket",
            Self::HttpUpgrade => "httpupgrade",
            Self::Hysteria => "hysteria",
        }
    }
}

/// Transport-layer security used by an Xray stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XraySecurity {
    None,
    Tls,
    Reality,
}

impl XraySecurity {
    /// Parse an Xray `streamSettings.security` value. Missing values use none.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Option<Self> {
        Some(match value.unwrap_or("none") {
            "none" => Self::None,
            "tls" => Self::Tls,
            "reality" => Self::Reality,
            _ => return None,
        })
    }

    /// Return the canonical Xray JSON security name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }
}

/// Validated Xray transport-layer selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XrayTransportConfig {
    pub method: XrayTransport,
    pub security: XraySecurity,
}

impl Default for XrayTransportConfig {
    fn default() -> Self {
        Self {
            method: XrayTransport::Raw,
            security: XraySecurity::None,
        }
    }
}

impl XrayTransportConfig {
    /// Validate the transport/security combination against Xray's matrix.
    ///
    /// # Errors
    ///
    /// Returns [`XrayError::InvalidConfig`] when the selected protocol,
    /// transport, and security layers cannot be combined safely.
    pub fn validate(self, protocol: XrayProtocol) -> Result<(), XrayError> {
        if self.security == XraySecurity::Reality
            && !matches!(self.method, XrayTransport::Raw | XrayTransport::Xhttp)
        {
            return Err(XrayError::InvalidConfig(format!(
                "Xray REALITY is incompatible with {} transport",
                self.method.as_str()
            )));
        }
        if self.method == XrayTransport::Hysteria && self.security != XraySecurity::Tls {
            return Err(XrayError::InvalidConfig(
                "Xray Hysteria transport requires TLS".to_owned(),
            ));
        }
        if matches!(protocol, XrayProtocol::Hysteria) && self.method != XrayTransport::Hysteria {
            return Err(XrayError::InvalidConfig(
                "Xray Hysteria outbound requires Hysteria transport".to_owned(),
            ));
        }
        if matches!(protocol, XrayProtocol::WireGuard) && !matches!(self.method, XrayTransport::Raw)
        {
            return Err(XrayError::InvalidConfig(
                "Xray WireGuard outbound does not use stream transports".to_owned(),
            ));
        }
        Ok(())
    }
}

/// VLESS server and user settings needed by the TCP outbound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessConfig {
    pub server: String,
    pub port: u16,
    pub user_id: [u8; 16],
    pub flow: Option<VlessFlow>,
}

/// VLESS flow-control modes. Only the XTLS Vision padding family is
/// wire-implemented; the direct/splice variants are validated against the same
/// transport/security constraints Xray enforces but are rejected with an
/// explicit "not implemented" error because the splice optimization depends on
/// Go TLS internals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessFlow {
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
    XtlsRprxDirect,
    XtlsRprxSplice,
}

impl VlessFlow {
    #[must_use]
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value {
            Some("xtls-rprx-vision") => Some(Self::XtlsRprxVision),
            Some("xtls-rprx-vision-udp443") => Some(Self::XtlsRprxVisionUdp443),
            Some("xtls-rprx-direct") => Some(Self::XtlsRprxDirect),
            Some("xtls-rprx-splice") => Some(Self::XtlsRprxSplice),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XtlsRprxVision => "xtls-rprx-vision",
            Self::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
            Self::XtlsRprxDirect => "xtls-rprx-direct",
            Self::XtlsRprxSplice => "xtls-rprx-splice",
        }
    }
}

/// Trojan server credentials and destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
}

/// Response emitted by the Xray Blackhole outbound after a local SOCKS
/// request has been accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlackholeResponse {
    None,
    Http,
}

/// DNS strategy for Xray's explicitly selected `freedom` outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreedomDomainStrategy {
    AsIs,
    UseIp,
    UseIpv4,
    UseIpv6,
}

impl FreedomDomainStrategy {
    fn parse(value: Option<&str>) -> Option<Self> {
        Some(match value.unwrap_or("AsIs") {
            "AsIs" => Self::AsIs,
            "UseIP" => Self::UseIp,
            "UseIPv4" => Self::UseIpv4,
            "UseIPv6" => Self::UseIpv6,
            _ => return None,
        })
    }
}

/// Explicit direct-connect settings for Xray's `freedom` outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreedomConfig {
    pub domain_strategy: FreedomDomainStrategy,
}

/// DNS packet network selected by the Xray DNS outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsNetwork {
    Udp,
    Tcp,
}

/// DNS outbound settings. DNS packet routing is kept separate from the
/// browser's TCP SOCKS path so a DNS outbound cannot accidentally become a
/// direct hostname resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    pub network: Option<DnsNetwork>,
    pub address: Option<String>,
    pub port: Option<u16>,
}

/// Packet-level DNS forwarder for an Xray DNS outbound.
pub struct XrayDnsResolver {
    config: DnsConfig,
}

impl XrayDnsResolver {
    /// Create a resolver from an explicit Xray DNS outbound configuration.
    #[must_use]
    pub const fn new(config: DnsConfig) -> Self {
        Self { config }
    }

    /// Forward one complete DNS wire packet and return the complete response.
    ///
    /// No hostname is resolved locally by this method. The configured DNS
    /// server address is the only network destination used.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the packet or configured endpoint is invalid,
    /// the selected DNS transport cannot connect, or the server does not reply.
    pub fn query(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if packet.is_empty() || packet.len() > usize::from(u16::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS packet must fit in the wire protocol limit",
            ));
        }
        let address = self.config.address.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS outbound requires an explicit packet endpoint",
            )
        })?;
        let port = self.config.port.unwrap_or(53);
        let ip = address.parse::<IpAddr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS endpoint must use a numeric IP to prevent local resolution",
            )
        })?;
        let destination = SocketAddr::new(ip, port);
        match self.config.network.unwrap_or(DnsNetwork::Udp) {
            DnsNetwork::Udp => {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
                socket.connect(destination)?;
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                socket.send(packet)?;
                let mut response = vec![0u8; 65_535];
                let length = socket.recv(&mut response)?;
                response.truncate(length);
                Ok(response)
            }
            DnsNetwork::Tcp => {
                let mut stream =
                    TcpStream::connect_timeout(&destination, UPSTREAM_CONNECT_TIMEOUT)?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let length = u16::try_from(packet.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "DNS packet is too large")
                })?;
                stream.write_all(&length.to_be_bytes())?;
                stream.write_all(packet)?;
                let mut response_length = [0u8; 2];
                stream.read_exact(&mut response_length)?;
                let mut response = vec![0u8; usize::from(u16::from_be_bytes(response_length))];
                stream.read_exact(&mut response)?;
                Ok(response)
            }
        }
    }
}

/// Loopback outbound settings for re-entering an in-process routing graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackConfig {
    pub inbound_tag: String,
}

/// Shadowsocks encryption methods accepted by the Xray outbound schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowsocksMethod {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3ChaCha20Poly1305,
}

impl ShadowsocksMethod {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "aes-128-gcm" => Self::Aes128Gcm,
            "aes-256-gcm" => Self::Aes256Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Self::ChaCha20Poly1305,
            "xchacha20-poly1305" | "xchacha20-ietf-poly1305" => Self::XChaCha20Poly1305,
            "2022-blake3-aes-128-gcm" => Self::Blake3Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Self::Blake3Aes256Gcm,
            "2022-blake3-chacha20-poly1305" => Self::Blake3ChaCha20Poly1305,
            _ => return None,
        })
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Blake3Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::XChaCha20Poly1305
            | Self::Blake3Aes256Gcm
            | Self::Blake3ChaCha20Poly1305 => 32,
        }
    }

    const fn is_legacy(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305
        )
    }
}

/// Shadowsocks server settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub port: u16,
    pub method: ShadowsocksMethod,
    pub password: String,
}

/// `VMess` cipher selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmessSecurity {
    Auto,
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

/// `VMess` server settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessConfig {
    pub server: String,
    pub port: u16,
    pub user_id: [u8; 16],
    pub security: VmessSecurity,
}

/// `Hysteria` outbound settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HysteriaConfig {
    pub version: u8,
    pub server: String,
    pub port: u16,
}

/// `WireGuard` peer settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardPeer {
    pub endpoint: String,
    pub public_key: [u8; 32],
    pub pre_shared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
}

/// `WireGuard` outbound settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardConfig {
    pub secret_key: [u8; 32],
    pub addresses: Vec<String>,
    /// Numeric DNS servers reached through the `WireGuard` interface.
    pub dns: Vec<String>,
    pub peers: Vec<WireGuardPeer>,
    pub mtu: u16,
    pub no_kernel_tun: bool,
}

/// HTTP-shaped settings shared by WebSocket and `HTTPUpgrade` transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XrayHttpSettings {
    pub path: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl Default for XrayHttpSettings {
    fn default() -> Self {
        Self {
            path: "/".to_owned(),
            host: None,
            headers: Vec::new(),
        }
    }
}

/// HTTP/2 gRPC transport settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XrayGrpcSettings {
    pub service_name: String,
    pub authority: Option<String>,
    pub user_agent: Option<String>,
    pub multi_mode: bool,
}

impl Default for XrayGrpcSettings {
    fn default() -> Self {
        Self {
            service_name: "GunService".to_owned(),
            authority: None,
            user_agent: None,
            multi_mode: false,
        }
    }
}

/// XHTTP transport settings retained for the XHTTP stream implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XrayXhttpSettings {
    pub path: String,
    pub host: Option<String>,
    pub mode: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XhttpMetadataPlacement {
    Path,
    Header,
    Query,
    Cookie,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XhttpDataPlacement {
    Auto,
    Body,
    Header,
    Cookie,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XhttpRequestOptions {
    session_placement: XhttpMetadataPlacement,
    session_key: String,
    sequence_placement: XhttpMetadataPlacement,
    sequence_key: String,
    uplink_data_placement: XhttpDataPlacement,
    uplink_data_key: String,
    uplink_http_method: String,
}

#[derive(Clone, Copy)]
struct XhttpRequestMetadata<'a> {
    session_id: Option<&'a str>,
    sequence: Option<u64>,
    options: &'a XhttpRequestOptions,
}

impl Default for XhttpRequestOptions {
    fn default() -> Self {
        Self {
            session_placement: XhttpMetadataPlacement::Path,
            session_key: "x_session".to_owned(),
            sequence_placement: XhttpMetadataPlacement::Path,
            sequence_key: "x_seq".to_owned(),
            uplink_data_placement: XhttpDataPlacement::Auto,
            uplink_data_key: "X-Data".to_owned(),
            uplink_http_method: "POST".to_owned(),
        }
    }
}

/// Hysteria v2 HTTP/3 authentication settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XrayHysteriaSettings {
    pub version: u8,
    pub auth: String,
    pub allow_insecure: bool,
}

impl Default for XrayHysteriaSettings {
    fn default() -> Self {
        Self {
            version: 2,
            auth: String::new(),
            allow_insecure: false,
        }
    }
}

impl Default for XrayXhttpSettings {
    fn default() -> Self {
        Self {
            path: "/".to_owned(),
            host: None,
            mode: "auto".to_owned(),
        }
    }
}

/// mKCP transport settings.
///
/// `seed` optionally enables Xray's seed-derived AES-128-GCM datagram
/// encryption; without a seed the legacy `SimpleAuthenticator` is used.
/// Disguise headers other than `none` are parsed and rejected at connect time
/// instead of being silently dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XrayMkcpSettings {
    pub mtu: u16,
    pub tti: u16,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub read_buffer_size: u32,
    pub write_buffer_size: u32,
    /// Optional mKCP payload encryption seed. Xray derives an AES-128-GCM key
    /// from `sha256(seed)[:16]`; without a seed Xray uses its legacy
    /// `SimpleAuthenticator` (FNV-1a + word-wise XOR) on every datagram.
    pub seed: Option<String>,
    /// Optional KCP disguise header (`kcpSettings.header.type`). Only `none`
    /// is wire-implemented; the disguised protocol headers are rejected at
    /// connect time instead of being silently dropped.
    pub header_type: Option<String>,
    pub header_seed: Option<String>,
}

impl Default for XrayMkcpSettings {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            read_buffer_size: 2,
            write_buffer_size: 2,
            seed: None,
            header_type: None,
            header_seed: None,
        }
    }
}

/// REALITY client settings needed for a genuine REALITY handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XrayRealitySettings {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub fingerprint: String,
    pub spider_x: String,
    pub server_name: Option<String>,
}

/// Xray outbound configurations with typed protocol and transport layers.
/// Every live handler preserves destination hostnames until the selected
/// upstream protocol consumes them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XrayOutbound {
    /// Drop the request locally, optionally returning a minimal HTTP 403.
    Blackhole { response: BlackholeResponse },
    /// Explicitly connect to the requested destination without an upstream
    /// tunnel. This is never selected as a failure fallback; it only runs
    /// when the user's Xray profile names `freedom`.
    Freedom(FreedomConfig),
    /// Route DNS packets through the DNS subsystem, not through the TCP
    /// browser proxy listener.
    Dns(DnsConfig),
    /// Forward through an upstream SOCKS5/SOCKS5h server.
    Socks5(ProxyEndpoint),
    /// Forward through an upstream HTTP CONNECT server.
    HttpConnect(ProxyEndpoint),
    /// Shadowsocks TCP outbound.
    Shadowsocks(ShadowsocksConfig),
    /// VLESS TCP outbound. Transport security is carried by `XrayConfig`.
    Vless(VlessConfig),
    /// `VMess` TCP outbound. Transport security is carried by `XrayConfig`.
    Vmess(VmessConfig),
    /// Trojan TCP outbound. Transport security is carried by `XrayConfig`.
    Trojan(TrojanConfig),
    /// Hysteria v2 UDP/QUIC outbound.
    Hysteria(HysteriaConfig),
    /// `WireGuard` userspace outbound.
    WireGuard(WireGuardConfig),
    /// Re-enter Nomad's routing graph with a tagged inbound.
    Loopback(LoopbackConfig),
}

/// Configuration accepted by Nomad's embedded Xray-compatible forwarding
/// core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XrayConfig {
    outbound: XrayOutbound,
    transport: XrayTransportConfig,
    server_name: Option<String>,
    http_settings: XrayHttpSettings,
    grpc_settings: XrayGrpcSettings,
    xhttp_settings: XrayXhttpSettings,
    xhttp_options: XhttpRequestOptions,
    hysteria_settings: XrayHysteriaSettings,
    mkcp_settings: XrayMkcpSettings,
    reality_settings: Option<XrayRealitySettings>,
    /// Optional secondary DNS outbound. When present and the primary outbound
    /// is `freedom` with a `UseIP`-family domain strategy, Nomad resolves
    /// hostnames through this DNS server instead of the system resolver.
    pub dns: Option<DnsConfig>,
}

impl XrayConfig {
    /// Build a forwarding configuration from an upstream endpoint.
    #[must_use]
    pub fn from_upstream(endpoint: ProxyEndpoint) -> Self {
        let outbound = match endpoint.scheme() {
            ProxyScheme::HttpConnect => XrayOutbound::HttpConnect(endpoint),
            ProxyScheme::Socks5 => XrayOutbound::Socks5(endpoint),
        };
        Self {
            outbound,
            transport: XrayTransportConfig {
                method: XrayTransport::Raw,
                security: XraySecurity::None,
            },
            server_name: None,
            http_settings: XrayHttpSettings::default(),
            grpc_settings: XrayGrpcSettings::default(),
            xhttp_settings: XrayXhttpSettings::default(),
            xhttp_options: XhttpRequestOptions::default(),
            hysteria_settings: XrayHysteriaSettings::default(),
            mkcp_settings: XrayMkcpSettings::default(),
            reality_settings: None,
            dns: None,
        }
    }

    /// Parse the Xray JSON outbound shape used by the embedded core.
    ///
    /// The embedded handlers accept local `blackhole`, `socks`, `http`, legacy
    /// `Shadowsocks`, `VMess`, `VLESS`, `Trojan`, and `Hysteria v2` outbounds. `DNS` is
    /// parsed as a typed packet-routing object and is available through
    /// [`XrayDnsResolver`]. `Loopback` requires the explicit connector accepted
    /// by [`XrayCore::start_with_loopback`]. `freedom` is supported only as an
    /// explicit profile selection and never as a fallback when another
    /// outbound fails.
    /// Protocol/security combinations outside the embedded compatibility
    /// matrix are rejected before a listener is created.
    ///
    /// # Errors
    ///
    /// Returns [`XrayError::InvalidConfig`] for malformed or unsupported
    /// configurations.
    pub fn from_json(raw: &str) -> Result<Self, XrayError> {
        let value: Value = serde_json::from_str(raw)
            .map_err(|error| XrayError::InvalidConfig(format!("invalid JSON: {error}")))?;
        let outbounds = value
            .get("outbounds")
            .and_then(Value::as_array)
            .ok_or_else(|| XrayError::InvalidConfig("outbounds array is required".to_owned()))?;
        let primary = outbounds.first().ok_or_else(|| {
            XrayError::InvalidConfig("outbounds must contain a primary outbound".to_owned())
        })?;
        let protocol = primary
            .get("protocol")
            .and_then(Value::as_str)
            .and_then(XrayProtocol::parse)
            .ok_or_else(|| {
                XrayError::InvalidConfig("outbound protocol is missing or unknown".to_owned())
            })?;
        let transport = parse_transport(primary, protocol)?;
        let reality_settings = parse_reality_settings(primary, transport.security)?;
        let server_name = parse_server_name(primary, reality_settings.as_ref());
        let http_settings = parse_http_settings(primary, transport.method)?;
        let grpc_settings = parse_grpc_settings(primary)?;
        let xhttp_settings = parse_xhttp_settings(primary)?;
        let xhttp_options = parse_xhttp_options(primary)?;
        let hysteria_settings = parse_hysteria_settings(primary)?;
        let mkcp_settings = parse_mkcp_settings(primary)?;
        let outbound = parse_outbound(primary).ok_or_else(|| {
            XrayError::InvalidConfig(format!(
                "Xray {} outbound is recognized but has no embedded Rust handler",
                protocol.as_str()
            ))
        })?;
        let dns = parse_secondary_dns_outbound(outbounds)?;
        Ok(Self {
            outbound,
            transport,
            server_name,
            http_settings,
            grpc_settings,
            xhttp_settings,
            xhttp_options,
            hysteria_settings,
            mkcp_settings,
            reality_settings,
            dns,
        })
    }

    /// Return the optional secondary DNS outbound configuration.
    #[must_use]
    pub const fn dns_resolver_config(&self) -> Option<&DnsConfig> {
        self.dns.as_ref()
    }

    /// Load an Xray-compatible JSON profile from a local file.
    ///
    /// # Errors
    ///
    /// Returns [`XrayError::Io`] when the file cannot be read and
    /// [`XrayError::InvalidConfig`] when its contents are not accepted by the
    /// embedded core.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, XrayError> {
        let raw = fs::read_to_string(path).map_err(XrayError::Io)?;
        Self::from_json(&raw)
    }

    /// Return the selected outbound mode.
    #[must_use]
    pub const fn outbound(&self) -> &XrayOutbound {
        &self.outbound
    }

    /// Return validated stream transport settings.
    #[must_use]
    pub const fn transport(&self) -> XrayTransportConfig {
        self.transport
    }

    /// Return the configured TLS/REALITY server name, if present.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Return HTTP transport settings for WebSocket/HTTPUpgrade.
    #[must_use]
    pub const fn http_settings(&self) -> &XrayHttpSettings {
        &self.http_settings
    }

    /// Return gRPC transport settings.
    #[must_use]
    pub const fn grpc_settings(&self) -> &XrayGrpcSettings {
        &self.grpc_settings
    }

    /// Return XHTTP transport settings.
    #[must_use]
    pub const fn xhttp_settings(&self) -> &XrayXhttpSettings {
        &self.xhttp_settings
    }

    fn xhttp_options(&self) -> &XhttpRequestOptions {
        &self.xhttp_options
    }

    /// Return Hysteria v2 HTTP/3 settings.
    #[must_use]
    pub const fn hysteria_settings(&self) -> &XrayHysteriaSettings {
        &self.hysteria_settings
    }

    /// Return mKCP transport settings.
    #[must_use]
    pub const fn mkcp_settings(&self) -> &XrayMkcpSettings {
        &self.mkcp_settings
    }

    /// Return REALITY settings, when the transport uses REALITY.
    #[must_use]
    pub const fn reality_settings(&self) -> Option<&XrayRealitySettings> {
        self.reality_settings.as_ref()
    }

    #[allow(clippy::too_many_lines)]
    fn validate_runtime(&self, loopback_available: bool) -> Result<(), XrayError> {
        if self.transport.method == XrayTransport::Xhttp
            && !self.xhttp_settings.mode.eq_ignore_ascii_case("auto")
            && !self.xhttp_settings.mode.eq_ignore_ascii_case("stream-one")
            && !self.xhttp_settings.mode.eq_ignore_ascii_case("stream-up")
            && !self.xhttp_settings.mode.eq_ignore_ascii_case("packet-up")
        {
            return Err(XrayError::InvalidConfig(
                "XHTTP currently supports auto, packet-up, stream-one, and stream-up modes only"
                    .to_owned(),
            ));
        }
        if self.transport.method == XrayTransport::Xhttp {
            let method = self.xhttp_options.uplink_http_method.as_str();
            if !matches!(method, "GET" | "POST") {
                return Err(XrayError::InvalidConfig(
                    "XHTTP uplink HTTP method must be GET or POST".to_owned(),
                ));
            }
            let packet_mode = self.xhttp_settings.mode.eq_ignore_ascii_case("packet-up")
                || (self.xhttp_settings.mode.eq_ignore_ascii_case("auto")
                    && self.transport.security != XraySecurity::Reality);
            if method == "GET" && !packet_mode {
                return Err(XrayError::InvalidConfig(
                    "XHTTP GET uplink is only valid for packet-up".to_owned(),
                ));
            }
            if method == "GET"
                && self.xhttp_options.uplink_data_placement == XhttpDataPlacement::Body
            {
                return Err(XrayError::InvalidConfig(
                    "XHTTP GET uplink cannot use body data placement".to_owned(),
                ));
            }
        }
        match &self.outbound {
            XrayOutbound::Blackhole { .. }
            | XrayOutbound::Freedom(_)
            | XrayOutbound::Socks5(_)
            | XrayOutbound::HttpConnect(_) => Ok(()),
            XrayOutbound::Dns(_) => Err(XrayError::InvalidConfig(
                "DNS outbound requires DNS packet routing, not the TCP browser listener".to_owned(),
            )),
            XrayOutbound::Loopback(_) if loopback_available => Ok(()),
            XrayOutbound::Loopback(_) => Err(XrayError::InvalidConfig(
                "Loopback requires an in-process routing graph".to_owned(),
            )),
            XrayOutbound::Shadowsocks(shadowsocks) => {
                if self.transport != XrayTransportConfig::default() {
                    return Err(XrayError::InvalidConfig(
                        "Shadowsocks outbound does not use embedded stream settings".to_owned(),
                    ));
                }
                if !shadowsocks.method.is_legacy() {
                    decode_shadowsocks2022_master_key(shadowsocks.method, &shadowsocks.password)
                        .map_err(|error| XrayError::InvalidConfig(error.to_string()))?;
                }
                Ok(())
            }
            XrayOutbound::Vmess(_vmess) => {
                if self.transport.security == XraySecurity::Reality {
                    return Err(XrayError::InvalidConfig(
                        "VMess REALITY transport is not implemented by the embedded core"
                            .to_owned(),
                    ));
                }
                if !matches!(
                    self.transport.method,
                    XrayTransport::Raw
                        | XrayTransport::Xhttp
                        | XrayTransport::Mkcp
                        | XrayTransport::HttpUpgrade
                        | XrayTransport::WebSocket
                        | XrayTransport::Grpc
                ) {
                    return Err(XrayError::InvalidConfig(format!(
                        "VMess {} transport is not implemented by the embedded core",
                        self.transport.method.as_str()
                    )));
                }
                Ok(())
            }
            XrayOutbound::Hysteria(_) => {
                if self.hysteria_settings.version != 2 {
                    return Err(XrayError::InvalidConfig(
                        "Hysteria handler requires version 2".to_owned(),
                    ));
                }
                if self.hysteria_settings.allow_insecure {
                    return Err(XrayError::InvalidConfig(
                        "Hysteria allowInsecure is disabled by the embedded core".to_owned(),
                    ));
                }
                Ok(())
            }
            XrayOutbound::WireGuard(wireguard) => {
                if wireguard.addresses.is_empty() {
                    return Err(XrayError::InvalidConfig(
                        "WireGuard requires at least one local address".to_owned(),
                    ));
                }
                if wireguard.peers.is_empty() {
                    return Err(XrayError::InvalidConfig(
                        "WireGuard requires at least one peer".to_owned(),
                    ));
                }
                if wireguard.peers.len() != 1 {
                    return Err(XrayError::InvalidConfig(
                        "WireGuard currently requires exactly one peer".to_owned(),
                    ));
                }
                if !(576..=1500).contains(&wireguard.mtu) {
                    return Err(XrayError::InvalidConfig(
                        "WireGuard MTU is outside the supported range".to_owned(),
                    ));
                }
                if wireguard.secret_key.iter().all(|byte| *byte == 0)
                    || wireguard.peers[0].public_key.iter().all(|byte| *byte == 0)
                {
                    return Err(XrayError::InvalidConfig(
                        "WireGuard keys cannot be all zeroes".to_owned(),
                    ));
                }
                if wireguard.dns.iter().any(|server| {
                    server
                        .parse::<IpAddr>()
                        .ok()
                        .is_none_or(|address| address.is_unspecified())
                }) {
                    return Err(XrayError::InvalidConfig(
                        "WireGuard DNS servers must be numeric, non-unspecified IP addresses"
                            .to_owned(),
                    ));
                }
                if wireguard.peers.iter().any(|peer| {
                    peer.endpoint
                        .parse::<SocketAddr>()
                        .ok()
                        .is_none_or(|endpoint| endpoint.port() == 0)
                }) {
                    return Err(XrayError::InvalidConfig(
                        "WireGuard peer endpoints must use numeric IP addresses and non-zero ports"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            XrayOutbound::Vless(vless) => {
                if let Some(flow) = vless.flow {
                    // Xray applies flows only to raw TCP protected by TLS or
                    // REALITY; anything else is a rejected configuration.
                    if self.transport.method != XrayTransport::Raw {
                        return Err(XrayError::InvalidConfig(format!(
                            "VLESS flow {} requires the raw TCP transport",
                            flow.as_str()
                        )));
                    }
                    if !matches!(
                        self.transport.security,
                        XraySecurity::Tls | XraySecurity::Reality
                    ) {
                        return Err(XrayError::InvalidConfig(format!(
                            "VLESS flow {} requires TLS or REALITY stream security",
                            flow.as_str()
                        )));
                    }
                    // The direct/splice variants are pure Go-TLS splice
                    // optimizations; they are validated but explicitly rejected
                    // rather than silently downgraded to plain proxying.
                    if matches!(flow, VlessFlow::XtlsRprxDirect | VlessFlow::XtlsRprxSplice) {
                        return Err(XrayError::InvalidConfig(format!(
                            "VLESS flow {} depends on Go TLS internals and is not implemented by the embedded core",
                            flow.as_str()
                        )));
                    }
                }
                if self.transport.security == XraySecurity::Reality
                    && !matches!(
                        self.transport.method,
                        XrayTransport::Raw | XrayTransport::Xhttp
                    )
                {
                    return Err(XrayError::InvalidConfig(
                        "VLESS REALITY is currently supported only over RAW or XHTTP transport"
                            .to_owned(),
                    ));
                }
                if !matches!(
                    self.transport.method,
                    XrayTransport::Raw
                        | XrayTransport::Xhttp
                        | XrayTransport::Mkcp
                        | XrayTransport::HttpUpgrade
                        | XrayTransport::WebSocket
                        | XrayTransport::Grpc
                ) {
                    return Err(XrayError::InvalidConfig(format!(
                        "VLESS {} transport is not implemented by the embedded core",
                        self.transport.method.as_str()
                    )));
                }
                Ok(())
            }
            XrayOutbound::Trojan(trojan) => {
                if trojan.password.is_empty() {
                    return Err(XrayError::InvalidConfig(
                        "Trojan password cannot be empty".to_owned(),
                    ));
                }
                if self.transport.security != XraySecurity::Tls {
                    return Err(XrayError::InvalidConfig(
                        "Trojan public outbound requires TLS in the embedded core".to_owned(),
                    ));
                }
                if !matches!(
                    self.transport.method,
                    XrayTransport::Raw
                        | XrayTransport::Xhttp
                        | XrayTransport::Mkcp
                        | XrayTransport::HttpUpgrade
                        | XrayTransport::WebSocket
                        | XrayTransport::Grpc
                ) {
                    return Err(XrayError::InvalidConfig(format!(
                        "Trojan {} transport is not implemented by the embedded core",
                        self.transport.method.as_str()
                    )));
                }
                Ok(())
            }
        }
    }
}

fn parse_outbound(value: &Value) -> Option<XrayOutbound> {
    let protocol = value.get("protocol")?.as_str()?;
    let settings = value.get("settings")?;
    if matches!(protocol, "blackhole" | "block") {
        let response = settings
            .get("response")
            .and_then(|response| response.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        return Some(XrayOutbound::Blackhole {
            response: match response {
                "none" => BlackholeResponse::None,
                "http" => BlackholeResponse::Http,
                _ => return None,
            },
        });
    }
    if matches!(protocol, "freedom" | "direct") {
        return parse_freedom(settings).map(XrayOutbound::Freedom);
    }
    if protocol == "dns" {
        return parse_dns_config(settings).map(XrayOutbound::Dns);
    }
    if protocol == "loopback" {
        let inbound_tag = settings.get("inboundTag")?.as_str()?;
        if inbound_tag.is_empty() {
            return None;
        }
        return Some(XrayOutbound::Loopback(LoopbackConfig {
            inbound_tag: inbound_tag.to_owned(),
        }));
    }
    if protocol == "shadowsocks" {
        return parse_shadowsocks(settings).map(XrayOutbound::Shadowsocks);
    }
    if protocol == "vmess" {
        return parse_vmess(settings).map(XrayOutbound::Vmess);
    }
    if protocol == "hysteria" {
        return parse_hysteria(value).map(XrayOutbound::Hysteria);
    }
    if protocol == "wireguard" {
        return parse_wireguard(settings).map(XrayOutbound::WireGuard);
    }
    if protocol == "vless" {
        return parse_vless(settings).map(XrayOutbound::Vless);
    }
    if protocol == "trojan" {
        return parse_trojan(settings).map(XrayOutbound::Trojan);
    }
    let server = settings.get("servers")?.as_array()?.first()?;
    if server
        .get("users")
        .and_then(Value::as_array)
        .is_some_and(|users| !users.is_empty())
    {
        return None;
    }
    let address = server.get("address")?.as_str()?;
    let port = u16::try_from(server.get("port")?.as_u64()?).ok()?;
    let scheme = match protocol {
        "socks" => ProxyScheme::Socks5,
        "http" => ProxyScheme::HttpConnect,
        _ => return None,
    };
    let host = address
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(address);
    let endpoint = ProxyEndpoint::new(scheme, host, port);
    Some(match scheme {
        ProxyScheme::Socks5 => XrayOutbound::Socks5(endpoint),
        ProxyScheme::HttpConnect => XrayOutbound::HttpConnect(endpoint),
    })
}

fn parse_dns_config(settings: &Value) -> Option<DnsConfig> {
    let network = match settings
        .get("network")
        .or_else(|| settings.get("rewriteNetwork"))
        .and_then(Value::as_str)
    {
        None => None,
        Some("udp") => Some(DnsNetwork::Udp),
        Some("tcp") => Some(DnsNetwork::Tcp),
        Some(_) => return None,
    };
    let address = settings
        .get("address")
        .or_else(|| settings.get("rewriteAddress"))
        .and_then(Value::as_str)
        .filter(|address| !address.is_empty())
        .map(str::to_owned);
    let port = match settings.get("port").or_else(|| settings.get("rewritePort")) {
        None => None,
        Some(port) => Some(u16::try_from(port.as_u64()?).ok()?),
    };
    Some(DnsConfig {
        network,
        address,
        port,
    })
}

/// Parse an optional secondary `dns` outbound. Xray profiles commonly pair a
/// primary tunnel outbound with a DNS outbound whose server is used for
/// `domainStrategy: UseIP` resolution; Nomad uses it to route DNS packets
/// through the declared server instead of the system resolver.
fn parse_secondary_dns_outbound(outbounds: &[Value]) -> Result<Option<DnsConfig>, XrayError> {
    let mut found: Option<DnsConfig> = None;
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Value::as_str) != Some("dns") {
            continue;
        }
        let Some(settings) = outbound.get("settings") else {
            continue;
        };
        let config = parse_dns_config(settings).ok_or_else(|| {
            XrayError::InvalidConfig("DNS outbound settings are malformed".to_owned())
        })?;
        if found.replace(config).is_some() {
            return Err(XrayError::InvalidConfig(
                "multiple DNS outbounds are not supported".to_owned(),
            ));
        }
    }
    Ok(found)
}

fn parse_freedom(settings: &Value) -> Option<FreedomConfig> {
    if settings
        .get("redirect")
        .and_then(Value::as_str)
        .is_some_and(|redirect| !redirect.is_empty())
    {
        return None;
    }
    Some(FreedomConfig {
        domain_strategy: FreedomDomainStrategy::parse(
            settings.get("domainStrategy").and_then(Value::as_str),
        )?,
    })
}

fn parse_shadowsocks(settings: &Value) -> Option<ShadowsocksConfig> {
    let server_settings = settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .unwrap_or(settings);
    let server = server_settings.get("address")?.as_str()?;
    let port = u16::try_from(server_settings.get("port")?.as_u64()?).ok()?;
    let method = ShadowsocksMethod::parse(server_settings.get("method")?.as_str()?)?;
    let password = server_settings.get("password")?.as_str()?;
    (!server.is_empty() && !password.is_empty()).then(|| ShadowsocksConfig {
        server: server.to_owned(),
        port,
        method,
        password: password.to_owned(),
    })
}

fn parse_vmess(settings: &Value) -> Option<VmessConfig> {
    let (server_settings, user_settings) = settings
        .get("vnext")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .map_or((settings, settings), |server| {
            let user = server
                .get("users")
                .and_then(Value::as_array)
                .and_then(|users| users.first())
                .unwrap_or(server);
            (server, user)
        });
    let server = server_settings.get("address")?.as_str()?;
    let port = u16::try_from(server_settings.get("port")?.as_u64()?).ok()?;
    let user_id = parse_uuid(user_settings.get("id")?.as_str()?)?;
    let security = match user_settings
        .get("security")
        .or_else(|| server_settings.get("security"))
        .and_then(Value::as_str)
        .unwrap_or("auto")
    {
        "auto" => VmessSecurity::Auto,
        "aes-128-gcm" => VmessSecurity::Aes128Gcm,
        "chacha20-poly1305" => VmessSecurity::ChaCha20Poly1305,
        "none" => VmessSecurity::None,
        _ => return None,
    };
    (!server.is_empty()).then_some(VmessConfig {
        server: server.to_owned(),
        port,
        user_id,
        security,
    })
}

fn parse_hysteria(outbound: &Value) -> Option<HysteriaConfig> {
    let settings = outbound.get("settings")?;
    // Xray expresses the Hysteria version in `streamSettings.hysteriaSettings`;
    // also accept a direct `settings.version` for backward compatibility.
    let version = settings
        .get("version")
        .or_else(|| {
            outbound
                .get("streamSettings")
                .and_then(|stream| stream.get("hysteriaSettings"))
                .and_then(|hysteria| hysteria.get("version"))
        })
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())?;
    if version != 2 {
        return None;
    }
    let server = settings.get("address")?.as_str()?;
    let port = u16::try_from(settings.get("port")?.as_u64()?).ok()?;
    (!server.is_empty()).then_some(HysteriaConfig {
        version,
        server: server.to_owned(),
        port,
    })
}

fn parse_wireguard(settings: &Value) -> Option<WireGuardConfig> {
    let secret_key = parse_base64_key(settings.get("secretKey")?.as_str()?)?;
    let addresses = settings
        .get("address")
        .and_then(Value::as_array)
        .and_then(|addresses| {
            addresses
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .map(|addresses| addresses.into_iter().map(str::to_owned).collect())
        })
        .unwrap_or_default();
    let peers = settings
        .get("peers")?
        .as_array()?
        .iter()
        .map(parse_wireguard_peer)
        .collect::<Option<Vec<_>>>()?;
    if peers.is_empty() {
        return None;
    }
    let dns = match settings.get("dns") {
        Some(Value::Array(servers)) => servers
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .map(str::to_owned)
            .collect(),
        Some(Value::String(server)) => vec![server.clone()],
        Some(_) => return None,
        None => Vec::new(),
    };
    let mtu = settings
        .get("mtu")
        .and_then(|mtu| u16::try_from(mtu.as_u64()?).ok())
        .unwrap_or(1420);
    Some(WireGuardConfig {
        secret_key,
        addresses,
        dns,
        peers,
        mtu,
        no_kernel_tun: settings
            .get("noKernelTun")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_wireguard_peer(value: &Value) -> Option<WireGuardPeer> {
    let endpoint = value.get("endpoint")?.as_str()?;
    let public_key = parse_base64_key(value.get("publicKey")?.as_str()?)?;
    let pre_shared_key = match value.get("preSharedKey") {
        None => None,
        Some(value) => Some(parse_base64_key(value.as_str()?)?),
    };
    Some(WireGuardPeer {
        endpoint: endpoint.to_owned(),
        public_key,
        pre_shared_key,
        persistent_keepalive: value
            .get("keepAlive")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok()),
    })
}

fn parse_base64_key(value: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()?;
    bytes.try_into().ok()
}

fn parse_vless(settings: &Value) -> Option<VlessConfig> {
    let server = settings.get("vnext")?.as_array()?.first()?;
    let server_address = server.get("address")?.as_str()?;
    let port = u16::try_from(server.get("port")?.as_u64()?).ok()?;
    let users = server.get("users")?.as_array()?;
    let user = users.first()?;
    if users.len() != 1 || user.get("encryption").and_then(Value::as_str) != Some("none") {
        return None;
    }
    let user_id = parse_uuid(user.get("id")?.as_str()?)?;
    let flow = match user.get("flow").and_then(Value::as_str) {
        None | Some("") => None,
        Some(raw) => Some(VlessFlow::parse(Some(raw))?),
    };
    Some(VlessConfig {
        server: server_address.to_owned(),
        port,
        user_id,
        flow,
    })
}

fn parse_trojan(settings: &Value) -> Option<TrojanConfig> {
    let server_settings = settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .unwrap_or(settings);
    let server = server_settings.get("address")?.as_str()?;
    let port = u16::try_from(server_settings.get("port")?.as_u64()?).ok()?;
    let password = server_settings.get("password")?.as_str()?;
    (!password.is_empty()).then(|| TrojanConfig {
        server: server.to_owned(),
        port,
        password: password.to_owned(),
    })
}

fn parse_uuid(value: &str) -> Option<[u8; 16]> {
    let mut bytes = [0u8; 16];
    let mut output = 0usize;
    let mut high = None;
    for byte in value.bytes() {
        if byte == b'-' {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if let Some(high_nibble) = high.take() {
            if output == bytes.len() {
                return None;
            }
            bytes[output] = (high_nibble << 4) | nibble;
            output += 1;
        } else {
            high = Some(nibble);
        }
    }
    (output == bytes.len() && high.is_none()).then_some(bytes)
}

fn parse_transport(
    value: &Value,
    protocol: XrayProtocol,
) -> Result<XrayTransportConfig, XrayError> {
    let settings = value.get("streamSettings");
    let method = XrayTransport::parse(
        settings
            .and_then(|settings| settings.get("method"))
            .or_else(|| settings.and_then(|settings| settings.get("network")))
            .and_then(Value::as_str),
    )
    .ok_or_else(|| XrayError::InvalidConfig("unknown Xray stream transport".to_owned()))?;
    let security = XraySecurity::parse(
        settings
            .and_then(|settings| settings.get("security"))
            .and_then(Value::as_str),
    )
    .ok_or_else(|| XrayError::InvalidConfig("unknown Xray stream security".to_owned()))?;
    let transport = XrayTransportConfig { method, security };
    transport.validate(protocol)?;
    if !matches!(
        transport,
        XrayTransportConfig {
            method: XrayTransport::Raw,
            security: XraySecurity::None
        }
    ) && matches!(
        protocol,
        XrayProtocol::Blackhole
            | XrayProtocol::Dns
            | XrayProtocol::Freedom
            | XrayProtocol::Loopback
            | XrayProtocol::Socks
            | XrayProtocol::Http
    ) {
        return Err(XrayError::InvalidConfig(format!(
            "Xray {} outbound cannot use embedded stream settings",
            protocol.as_str()
        )));
    }
    Ok(transport)
}

fn parse_server_name(value: &Value, reality: Option<&XrayRealitySettings>) -> Option<String> {
    value
        .get("streamSettings")
        .and_then(|settings| settings.get("tlsSettings"))
        .and_then(|settings| settings.get("serverName"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| reality.and_then(|settings| settings.server_name.clone()))
}

fn parse_grpc_settings(value: &Value) -> Result<XrayGrpcSettings, XrayError> {
    let Some(settings) = value
        .get("streamSettings")
        .and_then(|stream| stream.get("grpcSettings"))
    else {
        return Ok(XrayGrpcSettings::default());
    };
    let service_name = settings
        .get("serviceName")
        .and_then(Value::as_str)
        .unwrap_or("GunService");
    if service_name.is_empty() || service_name.contains(['\r', '\n']) {
        return Err(XrayError::InvalidConfig(
            "invalid Xray grpcSettings.serviceName".to_owned(),
        ));
    }
    let authority = settings
        .get("authority")
        .and_then(Value::as_str)
        .filter(|authority| !authority.is_empty())
        .map(str::to_owned);
    if authority
        .as_deref()
        .is_some_and(|authority| !authority_is_safe(authority))
    {
        return Err(XrayError::InvalidConfig(
            "invalid Xray grpcSettings.authority".to_owned(),
        ));
    }
    let user_agent = settings
        .get("user_agent")
        .and_then(Value::as_str)
        .filter(|user_agent| !user_agent.is_empty())
        .map(str::to_owned);
    Ok(XrayGrpcSettings {
        service_name: service_name.to_owned(),
        authority,
        user_agent,
        multi_mode: settings
            .get("multiMode")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_xhttp_settings(value: &Value) -> Result<XrayXhttpSettings, XrayError> {
    let Some(settings) = value
        .get("streamSettings")
        .and_then(|stream| stream.get("xhttpSettings"))
    else {
        return Ok(XrayXhttpSettings::default());
    };
    let path = settings.get("path").and_then(Value::as_str).unwrap_or("/");
    if path.is_empty() || !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err(XrayError::InvalidConfig(
            "invalid Xray xhttpSettings.path".to_owned(),
        ));
    }
    let host = settings
        .get("host")
        .and_then(Value::as_str)
        .filter(|host| !host.is_empty())
        .map(str::to_owned);
    if host.as_deref().is_some_and(|host| !authority_is_safe(host)) {
        return Err(XrayError::InvalidConfig(
            "invalid Xray xhttpSettings.host".to_owned(),
        ));
    }
    let mode = settings
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if mode.is_empty() || mode.contains(['\r', '\n']) {
        return Err(XrayError::InvalidConfig(
            "invalid Xray xhttpSettings.mode".to_owned(),
        ));
    }
    Ok(XrayXhttpSettings {
        path: path.to_owned(),
        host,
        mode: mode.to_owned(),
    })
}

fn parse_xhttp_options(value: &Value) -> Result<XhttpRequestOptions, XrayError> {
    let Some(settings_value) = value
        .get("streamSettings")
        .and_then(|stream| stream.get("xhttpSettings"))
    else {
        return Ok(XhttpRequestOptions::default());
    };
    let settings = settings_value.as_object().ok_or_else(|| {
        XrayError::InvalidConfig("Xray xhttpSettings must be an object".to_owned())
    })?;
    let defaults = XhttpRequestOptions::default();
    let session_placement =
        parse_xhttp_metadata_placement(settings, "sessionPlacement", defaults.session_placement)?;
    let sequence_placement =
        parse_xhttp_metadata_placement(settings, "seqPlacement", defaults.sequence_placement)?;
    let session_key = parse_xhttp_key(
        settings,
        "sessionKey",
        match session_placement {
            XhttpMetadataPlacement::Header => "X-Session",
            _ => defaults.session_key.as_str(),
        },
        "sessionKey",
    )?;
    let sequence_key = parse_xhttp_key(
        settings,
        "seqKey",
        match sequence_placement {
            XhttpMetadataPlacement::Header => "X-Seq",
            _ => defaults.sequence_key.as_str(),
        },
        "seqKey",
    )?;
    let uplink_data_placement = match settings
        .get("uplinkDataPlacement")
        .and_then(Value::as_str)
        .unwrap_or("auto")
    {
        "auto" => XhttpDataPlacement::Auto,
        "body" => XhttpDataPlacement::Body,
        "header" => XhttpDataPlacement::Header,
        "cookie" => XhttpDataPlacement::Cookie,
        _ => {
            return Err(XrayError::InvalidConfig(
                "invalid Xray xhttpSettings.uplinkDataPlacement".to_owned(),
            ));
        }
    };
    let uplink_data_key = parse_xhttp_key(
        settings,
        "uplinkDataKey",
        defaults.uplink_data_key.as_str(),
        "uplinkDataKey",
    )?;
    let uplink_http_method = settings
        .get("uplinkHTTPMethod")
        .and_then(Value::as_str)
        .unwrap_or("POST")
        .to_ascii_uppercase();
    if !header_name_is_safe(&uplink_http_method) {
        return Err(XrayError::InvalidConfig(
            "invalid Xray xhttpSettings.uplinkHTTPMethod".to_owned(),
        ));
    }
    Ok(XhttpRequestOptions {
        session_placement,
        session_key,
        sequence_placement,
        sequence_key,
        uplink_data_placement,
        uplink_data_key,
        uplink_http_method,
    })
}

fn parse_xhttp_metadata_placement(
    settings: &serde_json::Map<String, Value>,
    key: &str,
    default: XhttpMetadataPlacement,
) -> Result<XhttpMetadataPlacement, XrayError> {
    match settings.get(key).and_then(Value::as_str) {
        None => Ok(default),
        Some("path") => Ok(XhttpMetadataPlacement::Path),
        Some("header") => Ok(XhttpMetadataPlacement::Header),
        Some("query") => Ok(XhttpMetadataPlacement::Query),
        Some("cookie") => Ok(XhttpMetadataPlacement::Cookie),
        Some(_) => Err(XrayError::InvalidConfig(format!(
            "invalid Xray xhttpSettings.{key}"
        ))),
    }
}

fn parse_xhttp_key(
    settings: &serde_json::Map<String, Value>,
    key: &str,
    default: &str,
    label: &str,
) -> Result<String, XrayError> {
    let value = settings.get(key).and_then(Value::as_str).unwrap_or(default);
    if !header_name_is_safe(value) {
        return Err(XrayError::InvalidConfig(format!(
            "invalid Xray xhttpSettings.{label}"
        )));
    }
    Ok(value.to_owned())
}

fn parse_hysteria_settings(value: &Value) -> Result<XrayHysteriaSettings, XrayError> {
    let Some(settings) = value
        .get("streamSettings")
        .and_then(|stream| stream.get("hysteriaSettings"))
    else {
        return Ok(XrayHysteriaSettings::default());
    };
    let version = settings
        .get("version")
        .and_then(Value::as_u64)
        .map(|value| {
            u8::try_from(value).map_err(|_| {
                XrayError::InvalidConfig("Xray hysteriaSettings.version is invalid".to_owned())
            })
        })
        .transpose()?
        .unwrap_or(2);
    if version != 2 {
        return Err(XrayError::InvalidConfig(
            "Xray hysteriaSettings.version must be 2".to_owned(),
        ));
    }
    let auth = settings.get("auth").and_then(Value::as_str).unwrap_or("");
    if auth.contains(['\r', '\n']) {
        return Err(XrayError::InvalidConfig(
            "invalid Xray hysteriaSettings.auth".to_owned(),
        ));
    }
    let allow_insecure = value
        .get("streamSettings")
        .and_then(|stream| stream.get("tlsSettings"))
        .and_then(|tls| tls.get("allowInsecure"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(XrayHysteriaSettings {
        version,
        auth: auth.to_owned(),
        allow_insecure,
    })
}

fn parse_mkcp_settings(value: &Value) -> Result<XrayMkcpSettings, XrayError> {
    let Some(settings) = value
        .get("streamSettings")
        .and_then(|stream| stream.get("kcpSettings"))
    else {
        return Ok(XrayMkcpSettings::default());
    };
    let defaults = XrayMkcpSettings::default();
    let mtu = settings
        .get("mtu")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(defaults.mtu);
    let tti = settings
        .get("tti")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(defaults.tti);
    if !(576..=1460).contains(&mtu) || !(10..=100).contains(&tti) {
        return Err(XrayError::InvalidConfig(
            "Xray kcpSettings mtu/tti is outside the supported range".to_owned(),
        ));
    }
    Ok(XrayMkcpSettings {
        mtu,
        tti,
        uplink_capacity: settings
            .get("uplinkCapacity")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(defaults.uplink_capacity),
        downlink_capacity: settings
            .get("downlinkCapacity")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(defaults.downlink_capacity),
        congestion: settings
            .get("congestion")
            .and_then(Value::as_bool)
            .unwrap_or(defaults.congestion),
        read_buffer_size: settings
            .get("readBufferSize")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(defaults.read_buffer_size),
        write_buffer_size: settings
            .get("writeBufferSize")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(defaults.write_buffer_size),
        seed: settings
            .get("seed")
            .and_then(Value::as_str)
            .map(str::to_owned),
        header_type: settings
            .get("header")
            .and_then(|header| header.get("type"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        header_seed: settings
            .get("header")
            .and_then(|header| header.get("seed"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn parse_reality_settings(
    value: &Value,
    security: XraySecurity,
) -> Result<Option<XrayRealitySettings>, XrayError> {
    if security != XraySecurity::Reality {
        return Ok(None);
    }
    let settings = value
        .get("streamSettings")
        .and_then(|stream| stream.get("realitySettings"))
        .ok_or_else(|| {
            XrayError::InvalidConfig(
                "REALITY transport requires realitySettings.publicKey and shortId".to_owned(),
            )
        })?;
    let public_key = parse_base64_key(
        settings
            .get("publicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| XrayError::InvalidConfig("REALITY publicKey is required".to_owned()))?,
    )
    .ok_or_else(|| {
        XrayError::InvalidConfig("REALITY publicKey must be 32-byte base64".to_owned())
    })?;
    let short_id = parse_hex_bytes(
        settings
            .get("shortId")
            .and_then(Value::as_str)
            .ok_or_else(|| XrayError::InvalidConfig("REALITY shortId is required".to_owned()))?,
    )
    .ok_or_else(|| XrayError::InvalidConfig("REALITY shortId must be hexadecimal".to_owned()))?;
    if short_id.len() > 8 {
        return Err(XrayError::InvalidConfig(
            "REALITY shortId cannot exceed 8 bytes".to_owned(),
        ));
    }
    let fingerprint = settings
        .get("fingerprint")
        .and_then(Value::as_str)
        .unwrap_or("chrome");
    let spider_x = settings
        .get("spiderX")
        .and_then(Value::as_str)
        .unwrap_or("/");
    let server_name = settings
        .get("serverName")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    Ok(Some(XrayRealitySettings {
        public_key,
        short_id,
        fingerprint: fingerprint.to_owned(),
        spider_x: spider_x.to_owned(),
        server_name,
    }))
}

fn parse_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            u8::try_from((high << 4) | low).ok()
        })
        .collect()
}

fn authority_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
        && !value.contains(['/', '?', '#', '@'])
}

fn header_name_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_http_settings(
    value: &Value,
    method: XrayTransport,
) -> Result<XrayHttpSettings, XrayError> {
    let key = match method {
        XrayTransport::WebSocket => "wsSettings",
        XrayTransport::HttpUpgrade => "httpupgradeSettings",
        _ => return Ok(XrayHttpSettings::default()),
    };
    let settings = value
        .get("streamSettings")
        .and_then(|stream| stream.get(key));
    let path = settings
        .and_then(|settings| settings.get("path"))
        .and_then(Value::as_str)
        .unwrap_or("/");
    if path.is_empty() || !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err(XrayError::InvalidConfig(format!("invalid Xray {key}.path")));
    }
    let host = settings
        .and_then(|settings| settings.get("host"))
        .and_then(Value::as_str)
        .filter(|host| !host.is_empty())
        .map(str::to_owned);
    if host.as_deref().is_some_and(|host| !authority_is_safe(host)) {
        return Err(XrayError::InvalidConfig(format!("invalid Xray {key}.host")));
    }
    let mut headers = settings
        .and_then(|settings| settings.get("headers"))
        .and_then(Value::as_object)
        .map(|headers| {
            headers
                .iter()
                .map(|(name, value)| {
                    let value = value.as_str().ok_or_else(|| {
                        XrayError::InvalidConfig(format!(
                            "Xray {key}.headers values must be strings"
                        ))
                    })?;
                    if !header_name_is_safe(name)
                        || value.chars().any(char::is_control)
                        || name.eq_ignore_ascii_case("host")
                    {
                        return Err(XrayError::InvalidConfig(format!(
                            "invalid Xray {key}.headers entry"
                        )));
                    }
                    Ok((name.clone(), value.to_owned()))
                })
                .collect::<Result<Vec<_>, XrayError>>()
        })
        .transpose()?
        .unwrap_or_default();
    headers.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(XrayHttpSettings {
        path: path.to_owned(),
        host,
        headers,
    })
}

const SHADOWSOCKS_TAG_LEN: usize = 16;
const SHADOWSOCKS_MAX_CHUNK: usize = 0x3fff;

struct ShadowsocksCipher {
    key: ShadowsocksCipherKey,
}

enum ShadowsocksCipherKey {
    Ring(Box<aead::LessSafeKey>),
    XChaCha(Box<XChaCha20Poly1305>),
}

impl ShadowsocksCipher {
    fn new(method: ShadowsocksMethod, password: &str, salt: &[u8]) -> io::Result<Self> {
        if !method.is_legacy() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported Shadowsocks AEAD method",
            ));
        }
        let master = evp_bytes_to_key(password.as_bytes(), method.key_len());
        let subkey = shadowsocks_hkdf_sha1(&master, salt, method.key_len());
        let algorithm = match method {
            ShadowsocksMethod::Aes128Gcm => &aead::AES_128_GCM,
            ShadowsocksMethod::Aes256Gcm => &aead::AES_256_GCM,
            ShadowsocksMethod::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
            ShadowsocksMethod::XChaCha20Poly1305 => {
                let key = chacha20poly1305::Key::from_slice(&subkey);
                return Ok(Self {
                    key: ShadowsocksCipherKey::XChaCha(Box::new(XChaCha20Poly1305::new(key))),
                });
            }
            ShadowsocksMethod::Blake3Aes128Gcm
            | ShadowsocksMethod::Blake3Aes256Gcm
            | ShadowsocksMethod::Blake3ChaCha20Poly1305 => unreachable!(),
        };
        let key = aead::UnboundKey::new(algorithm, &subkey).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid Shadowsocks AEAD key")
        })?;
        Ok(Self {
            key: ShadowsocksCipherKey::Ring(Box::new(aead::LessSafeKey::new(key))),
        })
    }

    fn seal(&self, sequence: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut output = plaintext.to_vec();
        match &self.key {
            ShadowsocksCipherKey::Ring(key) => {
                key.seal_in_place_append_tag(
                    shadowsocks_nonce(sequence),
                    aead::Aad::empty(),
                    &mut output,
                )
                .expect("Shadowsocks AEAD buffer has no size limit");
            }
            ShadowsocksCipherKey::XChaCha(key) => key
                .encrypt_in_place(
                    XNonce::from_slice(&shadowsocks_xnonce(sequence)),
                    b"",
                    &mut output,
                )
                .expect("Shadowsocks AEAD buffer has no size limit"),
        }
        output
    }

    fn open(&self, sequence: u64, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = ciphertext.to_vec();
        match &self.key {
            ShadowsocksCipherKey::Ring(key) => {
                let plaintext = key
                    .open_in_place(shadowsocks_nonce(sequence), aead::Aad::empty(), &mut output)
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Shadowsocks AEAD authentication failed",
                        )
                    })?;
                Ok(plaintext.to_vec())
            }
            ShadowsocksCipherKey::XChaCha(key) => {
                key.decrypt_in_place(
                    XNonce::from_slice(&shadowsocks_xnonce(sequence)),
                    b"",
                    &mut output,
                )
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Shadowsocks AEAD authentication failed",
                    )
                })?;
                Ok(output)
            }
        }
    }
}

fn shadowsocks_nonce(sequence: u64) -> aead::Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    aead::Nonce::assume_unique_for_key(nonce)
}

fn shadowsocks_xnonce(sequence: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[16..].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

fn evp_bytes_to_key(password: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut previous = Vec::new();
    while output.len() < length {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password);
        previous = digest.finalize().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(length);
    output
}

fn shadowsocks_hkdf_sha1(master: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let extract_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = hmac::sign(&extract_key, master);
    let expand_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, prk.as_ref());
    let mut output = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while output.len() < length {
        let mut message = previous;
        message.extend_from_slice(b"ss-subkey");
        message.push(counter);
        previous = hmac::sign(&expand_key, &message).as_ref().to_vec();
        output.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    output.truncate(length);
    output
}

enum Shadowsocks2022CipherKey {
    Ring(Box<aead::LessSafeKey>),
    ChaCha(Box<ChaCha20Poly1305>),
}

struct Shadowsocks2022Cipher {
    key: Shadowsocks2022CipherKey,
    nonce: [u8; 12],
}

impl Shadowsocks2022Cipher {
    fn new(method: ShadowsocksMethod, master_key: &[u8], salt: &[u8]) -> io::Result<Self> {
        if method.is_legacy() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 cipher requires a 2022 method",
            ));
        }
        if master_key.len() != method.key_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks 2022 master key length",
            ));
        }

        let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
        hasher.update(master_key);
        hasher.update(salt);
        let mut derived_key = [0u8; 32];
        hasher.finalize_xof().fill(&mut derived_key);
        let key = match method {
            ShadowsocksMethod::Blake3Aes128Gcm => {
                let key = aead::UnboundKey::new(&aead::AES_128_GCM, &derived_key[..16]).map_err(
                    |_| io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-128 key"),
                )?;
                Shadowsocks2022CipherKey::Ring(Box::new(aead::LessSafeKey::new(key)))
            }
            ShadowsocksMethod::Blake3Aes256Gcm => {
                let key =
                    aead::UnboundKey::new(&aead::AES_256_GCM, &derived_key).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-256 key")
                    })?;
                Shadowsocks2022CipherKey::Ring(Box::new(aead::LessSafeKey::new(key)))
            }
            ShadowsocksMethod::Blake3ChaCha20Poly1305 => {
                let key = chacha20poly1305::Key::from_slice(&derived_key);
                Shadowsocks2022CipherKey::ChaCha(Box::new(ChaCha20Poly1305::new(key)))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported Shadowsocks 2022 method",
                ));
            }
        };
        Ok(Self {
            key,
            nonce: [0u8; 12],
        })
    }

    fn increment_nonce(&mut self) {
        for byte in &mut self.nonce {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(plaintext.len() + SHADOWSOCKS_TAG_LEN);
        output.extend_from_slice(plaintext);
        match &self.key {
            Shadowsocks2022CipherKey::Ring(key) => {
                key.seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(self.nonce),
                    aead::Aad::empty(),
                    &mut output,
                )
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Shadowsocks 2022 encryption failed",
                    )
                })?;
            }
            Shadowsocks2022CipherKey::ChaCha(key) => {
                key.encrypt_in_place(ChaChaNonce::from_slice(&self.nonce), b"", &mut output)
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Shadowsocks 2022 encryption failed",
                        )
                    })?;
            }
        }
        self.increment_nonce();
        Ok(output)
    }

    fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = ciphertext.to_vec();
        let result = match &self.key {
            Shadowsocks2022CipherKey::Ring(key) => key
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(self.nonce),
                    aead::Aad::empty(),
                    &mut output,
                )
                .map(|plaintext| plaintext.to_vec())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Shadowsocks 2022 authentication failed",
                    )
                }),
            Shadowsocks2022CipherKey::ChaCha(key) => key
                .decrypt_in_place(ChaChaNonce::from_slice(&self.nonce), b"", &mut output)
                .map(|()| output)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Shadowsocks 2022 authentication failed",
                    )
                }),
        };
        self.increment_nonce();
        result
    }
}

fn decode_shadowsocks2022_master_key(
    method: ShadowsocksMethod,
    password: &str,
) -> io::Result<Vec<u8>> {
    if method.is_legacy() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks 2022 master key requested for a legacy method",
        ));
    }
    let key = base64::engine::general_purpose::STANDARD
        .decode(password)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid Shadowsocks 2022 base64 key: {error}"),
            )
        })?;
    if key.len() != method.key_len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Shadowsocks 2022 key must be {} bytes, got {}",
                method.key_len(),
                key.len()
            ),
        ));
    }
    Ok(key)
}

fn encode_shadowsocks_frame(
    method: ShadowsocksMethod,
    password: &str,
    salt: &[u8],
    sequence: u64,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > SHADOWSOCKS_MAX_CHUNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Shadowsocks chunk length",
        ));
    }
    let cipher = ShadowsocksCipher::new(method, password, salt)?;
    let length = u16::try_from(plaintext.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Shadowsocks chunk too large"))?;
    let encrypted_length = cipher.seal(sequence, &length.to_be_bytes());
    let encrypted_payload = cipher.seal(sequence + 1, plaintext);
    let mut frame = Vec::with_capacity(encrypted_length.len() + encrypted_payload.len());
    frame.extend_from_slice(&encrypted_length);
    frame.extend_from_slice(&encrypted_payload);
    Ok(frame)
}

#[cfg(any(test, feature = "fuzzing"))]
fn decode_shadowsocks_frame(
    method: ShadowsocksMethod,
    password: &str,
    salt: &[u8],
    sequence: u64,
    frame: &[u8],
) -> io::Result<Vec<u8>> {
    if frame.len() < 2 + SHADOWSOCKS_TAG_LEN * 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated Shadowsocks frame",
        ));
    }
    let cipher = ShadowsocksCipher::new(method, password, salt)?;
    let encrypted_length = &frame[..2 + SHADOWSOCKS_TAG_LEN];
    let length = cipher.open(sequence, encrypted_length)?;
    let length =
        u16::from_be_bytes(length.as_slice().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid Shadowsocks length")
        })?) as usize;
    if length == 0 || length > SHADOWSOCKS_MAX_CHUNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Shadowsocks chunk length",
        ));
    }
    let expected = 2 + SHADOWSOCKS_TAG_LEN + length + SHADOWSOCKS_TAG_LEN;
    if frame.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Shadowsocks frame size",
        ));
    }
    cipher.open(sequence + 1, &frame[2 + SHADOWSOCKS_TAG_LEN..])
}

const HYSTERIA_MAX_ADDRESS: usize = 2048;
const HYSTERIA_MAX_MESSAGE: usize = 4096;

fn encode_quic_varint(value: u64, output: &mut Vec<u8>) -> io::Result<()> {
    const MAX_VARINT: u64 = 4_611_686_018_427_387_903;
    if value <= 63 {
        output.push(u8::try_from(value).expect("QUIC one-byte varint range checked"));
    } else if value <= 16_383 {
        let value = u16::try_from(value).expect("QUIC two-byte varint range checked") | 0x4000;
        output.extend_from_slice(&value.to_be_bytes());
    } else if value <= 1_073_741_823 {
        let value =
            u32::try_from(value).expect("QUIC four-byte varint range checked") | 0x8000_0000;
        output.extend_from_slice(&value.to_be_bytes());
    } else if value <= MAX_VARINT {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria QUIC varint is too large",
        ));
    }
    Ok(())
}

fn decode_quic_varint(input: &[u8]) -> io::Result<(u64, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing QUIC varint"))?;
    let length = 1usize << usize::from(first >> 6);
    if input.len() < length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated QUIC varint",
        ));
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

fn encode_hysteria_tcp_request(address: &str, padding: &[u8]) -> io::Result<Vec<u8>> {
    if address.is_empty() || address.len() > HYSTERIA_MAX_ADDRESS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Hysteria target address length",
        ));
    }
    if padding.len() > HYSTERIA_MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Hysteria request padding length",
        ));
    }
    let mut output = Vec::with_capacity(address.len() + padding.len() + 16);
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    encode_quic_varint(padding.len() as u64, &mut output)?;
    output.extend_from_slice(padding);
    Ok(output)
}

#[cfg(any(test, feature = "fuzzing"))]
fn decode_hysteria_tcp_request(input: &[u8]) -> io::Result<(String, usize)> {
    let (address_length, mut offset) = decode_quic_varint(input)?;
    let address_length = usize::try_from(address_length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria address length overflow",
        )
    })?;
    if address_length == 0 || address_length > HYSTERIA_MAX_ADDRESS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria target address length",
        ));
    }
    let address_end = offset
        .checked_add(address_length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Hysteria address overflow"))?;
    let address = input.get(offset..address_end).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated Hysteria address")
    })?;
    offset = address_end;
    let (padding_length, padding_varint_length) =
        decode_quic_varint(input.get(offset..).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing Hysteria padding length",
            )
        })?)?;
    offset += padding_varint_length;
    let padding_length = usize::try_from(padding_length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria padding length overflow",
        )
    })?;
    if padding_length > HYSTERIA_MAX_MESSAGE
        || input
            .get(offset..offset.saturating_add(padding_length))
            .is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria request padding",
        ));
    }
    let address = String::from_utf8(address.to_owned()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria target address is not UTF-8",
        )
    })?;
    Ok((address, padding_length))
}

#[cfg(test)]
fn encode_hysteria_tcp_response(ok: bool, message: &str, padding: &[u8]) -> io::Result<Vec<u8>> {
    if message.len() > HYSTERIA_MAX_MESSAGE || padding.len() > HYSTERIA_MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Hysteria response length",
        ));
    }
    let mut output = Vec::with_capacity(message.len() + padding.len() + 16);
    output.push(u8::from(!ok));
    encode_quic_varint(message.len() as u64, &mut output)?;
    output.extend_from_slice(message.as_bytes());
    encode_quic_varint(padding.len() as u64, &mut output)?;
    output.extend_from_slice(padding);
    Ok(output)
}

#[cfg(any(test, feature = "fuzzing"))]
fn decode_hysteria_tcp_response(input: &[u8]) -> io::Result<(bool, String, usize)> {
    let status = *input
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing Hysteria status"))?;
    if status > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria status",
        ));
    }
    let (message_length, message_varint_length) = decode_quic_varint(&input[1..])?;
    let message_length = usize::try_from(message_length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria message length overflow",
        )
    })?;
    if message_length > HYSTERIA_MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria message length",
        ));
    }
    let message_start = 1 + message_varint_length;
    let message_end = message_start
        .checked_add(message_length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Hysteria message overflow"))?;
    let message = input.get(message_start..message_end).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated Hysteria message")
    })?;
    let (padding_length, padding_varint_length) =
        decode_quic_varint(input.get(message_end..).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing Hysteria padding length",
            )
        })?)?;
    let padding_start = message_end + padding_varint_length;
    let padding_length = usize::try_from(padding_length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria padding length overflow",
        )
    })?;
    if padding_length > HYSTERIA_MAX_MESSAGE
        || input
            .get(padding_start..padding_start.saturating_add(padding_length))
            .is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria response padding",
        ));
    }
    let message = String::from_utf8(message.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Hysteria message is not UTF-8"))?;
    Ok((status == 0, message, padding_length))
}

/// Errors produced by the embedded Xray-compatible core.
#[derive(Debug)]
pub enum XrayError {
    /// The supplied configuration cannot be used safely.
    InvalidConfig(String),
    /// A local listener or tunnel operation failed.
    Io(io::Error),
}

impl Display for XrayError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => formatter.write_str(error),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for XrayError {}

/// In-process connector used by the Xray Loopback outbound.
pub type XrayLoopbackConnector =
    Arc<dyn Fn(&str, &str, u16) -> io::Result<TcpStream> + Send + Sync>;

/// Embedded local SOCKS5 listener backed by one Xray-compatible outbound.
pub struct XrayCore {
    endpoint: ProxyEndpoint,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

fn encode_grpc_message(payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "gRPC message is too large"))?;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn decode_grpc_messages(buffer: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    loop {
        if buffer.len() < 5 {
            break;
        }
        if buffer[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed gRPC messages are not supported",
            ));
        }
        let length = u32::from_be_bytes(buffer[1..5].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid gRPC message length")
        })?) as usize;
        if length > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gRPC message exceeds the safety limit",
            ));
        }
        if buffer.len() < 5 + length {
            break;
        }
        plaintext.extend_from_slice(&buffer[5..5 + length]);
        buffer.drain(..5 + length);
    }
    Ok(plaintext)
}

enum GrpcEvent {
    Data(Vec<u8>),
    Closed,
    Error(String),
}

#[allow(clippy::large_enum_variant)]
enum GrpcIo {
    Plain(Box<tokio::net::TcpStream>),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for GrpcIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for GrpcIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

struct GrpcStream {
    commands: mpsc::Sender<Vec<u8>>,
    events: mpsc::Receiver<GrpcEvent>,
    encoded: Vec<u8>,
    plaintext: Vec<u8>,
    nonblocking: bool,
}

impl GrpcStream {
    fn connect(
        server: &str,
        port: u16,
        security: XraySecurity,
        server_name: &str,
        settings: &XrayGrpcSettings,
    ) -> io::Result<Self> {
        let (commands, command_receiver) = mpsc::channel(64);
        let (event_sender, events) = mpsc::channel(64);
        let (startup_sender, startup_receiver) =
            std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let server = server.to_owned();
        let server_name = server_name.to_owned();
        let settings = settings.clone();
        thread::Builder::new()
            .name("nomad-xray-grpc".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                let startup_for_runtime = startup_sender.clone();
                let result = runtime.block_on(run_grpc(
                    server,
                    port,
                    security,
                    server_name,
                    settings,
                    command_receiver,
                    event_sender.clone(),
                    startup_for_runtime,
                ));
                if let Err(error) = result {
                    let _ = startup_sender.send(Err(error.to_string()));
                    let _ =
                        runtime.block_on(event_sender.send(GrpcEvent::Error(error.to_string())));
                }
            })
            .map_err(io::Error::other)?;
        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                events,
                encoded: Vec::new(),
                plaintext: Vec::new(),
                nonblocking: false,
            }),
            Ok(Err(error)) => Err(io::Error::new(io::ErrorKind::ConnectionRefused, error)),
            Err(error) => Err(io::Error::new(io::ErrorKind::ConnectionRefused, error)),
        }
    }

    fn receive_event(&mut self) -> io::Result<bool> {
        let event = if self.nonblocking {
            match self.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::error::TryRecvError::Empty) => return Ok(false),
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(true),
            }
        } else {
            self.events.blocking_recv().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "gRPC worker stopped")
            })?
        };
        match event {
            GrpcEvent::Data(data) => {
                self.encoded.extend_from_slice(&data);
                self.plaintext
                    .extend_from_slice(&decode_grpc_messages(&mut self.encoded)?);
                Ok(true)
            }
            GrpcEvent::Closed => Ok(true),
            GrpcEvent::Error(error) => Err(io::Error::new(io::ErrorKind::ConnectionReset, error)),
        }
    }
}

impl Read for GrpcStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.plaintext.is_empty() {
                let length = buffer.len().min(self.plaintext.len());
                buffer[..length].copy_from_slice(&self.plaintext[..length]);
                self.plaintext.drain(..length);
                return Ok(length);
            }
            let had_event = self.receive_event()?;
            if !had_event {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "gRPC read pending",
                ));
            }
        }
    }
}

impl Write for GrpcStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let frame = encode_grpc_message(buffer)?;
        if self.nonblocking {
            self.commands.try_send(frame).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "gRPC write pending")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "gRPC worker stopped")
                }
            })?;
        } else {
            self.commands
                .blocking_send(frame)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "gRPC worker stopped"))?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_grpc(
    server: String,
    port: u16,
    security: XraySecurity,
    server_name: String,
    settings: XrayGrpcSettings,
    mut commands: mpsc::Receiver<Vec<u8>>,
    events: mpsc::Sender<GrpcEvent>,
    startup: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> io::Result<()> {
    let stream = connect_tcp(&server, port)?;
    stream.set_nonblocking(true)?;
    let stream = tokio::net::TcpStream::from_std(stream)?;
    let stream = match security {
        XraySecurity::None => GrpcIo::Plain(Box::new(stream)),
        XraySecurity::Tls => {
            let mut roots = RootCertStore::empty();
            roots.extend(TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = ServerName::try_from(server_name.clone()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid gRPC server name: {error}"),
                )
            })?;
            let connector = TlsConnector::from(Arc::new(config));
            GrpcIo::Tls(Box::new(connector.connect(name, stream).await.map_err(
                |error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()),
            )?))
        }
        XraySecurity::Reality => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "gRPC REALITY handler is not implemented",
            ));
        }
    };
    let (sender, connection) = h2::client::Builder::new()
        .handshake(stream)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let authority = settings.authority.as_deref().unwrap_or(&server);
    let service_name = if settings.service_name.starts_with('/') {
        settings.service_name.clone()
    } else {
        let suffix = if settings.multi_mode {
            "TunMulti"
        } else {
            "Tun"
        };
        format!(
            "/{service_name}/{suffix}",
            service_name = settings.service_name
        )
    };
    let uri: http::Uri = format!(
        "{}://{}{}",
        if security == XraySecurity::Tls {
            "https"
        } else {
            "http"
        },
        authority,
        service_name
    )
    .parse()
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid gRPC URI: {error}"),
        )
    })?;
    let mut request = Request::builder()
        .method("POST")
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if let Some(user_agent) = settings.user_agent.as_deref() {
        request = request.header("user-agent", user_agent);
    }
    let request = request
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let mut sender = sender
        .ready()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    let (response, mut send_stream): (h2::client::ResponseFuture, SendStream<Bytes>) = sender
        .send_request(request, false)
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    startup
        .send(Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "gRPC startup receiver closed"))?;
    let mut response = Box::pin(response);
    let mut body: Option<h2::RecvStream> = None;
    loop {
        if let Some(body_stream) = body.as_mut() {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else {
                        let _ = send_stream.send_data(Bytes::new(), true);
                        return Ok(());
                    };
                    send_stream.send_data(Bytes::from(command), false).map_err(|error| io::Error::other(error.to_string()))?;
                }
                data = body_stream.data() => {
                    match data {
                        Some(Ok(data)) => {
                            events.send(GrpcEvent::Data(data.to_vec())).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "gRPC reader closed"))?;
                        }
                        Some(Err(error)) => return Err(io::Error::other(error.to_string())),
                        None => {
                            let _ = events.send(GrpcEvent::Closed).await;
                            return Ok(());
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else {
                        let _ = send_stream.send_data(Bytes::new(), true);
                        return Ok(());
                    };
                    send_stream.send_data(Bytes::from(command), false).map_err(|error| io::Error::other(error.to_string()))?;
                }
                response_result = response.as_mut() => {
                    let response = response_result.map_err(|error| io::Error::other(error.to_string()))?;
                    if !response.status().is_success() {
                        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("gRPC server returned {}", response.status())));
                    }
                    body = Some(response.into_body());
                }
            }
        }
    }
}

enum HysteriaEvent {
    Data(Vec<u8>),
    Closed,
    Error(String),
}

struct HysteriaStream {
    commands: mpsc::Sender<Vec<u8>>,
    events: mpsc::Receiver<HysteriaEvent>,
    plaintext: Vec<u8>,
    nonblocking: bool,
}

impl HysteriaStream {
    fn connect(
        server: &str,
        port: u16,
        server_name: &str,
        settings: &XrayHysteriaSettings,
        target: &Target,
    ) -> io::Result<Self> {
        if settings.version != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria handler requires version 2",
            ));
        }
        if settings.allow_insecure {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hysteria allowInsecure is disabled by the embedded core",
            ));
        }
        let (commands, command_receiver) = mpsc::channel(64);
        let (event_sender, events) = mpsc::channel(64);
        let (startup_sender, startup_receiver) =
            std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let server = server.to_owned();
        let server_name = server_name.to_owned();
        let auth = settings.auth.clone();
        let target = target.clone();
        thread::Builder::new()
            .name("nomad-xray-hysteria".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                let startup_for_runtime = startup_sender.clone();
                let result = runtime.block_on(run_hysteria(
                    server,
                    port,
                    server_name,
                    auth,
                    target,
                    command_receiver,
                    event_sender.clone(),
                    startup_for_runtime,
                ));
                if let Err(error) = result {
                    let _ = startup_sender.send(Err(error.to_string()));
                    let _ = runtime
                        .block_on(event_sender.send(HysteriaEvent::Error(error.to_string())));
                }
            })
            .map_err(io::Error::other)?;
        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                events,
                plaintext: Vec::new(),
                nonblocking: false,
            }),
            Ok(Err(error)) => Err(io::Error::new(io::ErrorKind::ConnectionRefused, error)),
            Err(error) => Err(io::Error::new(io::ErrorKind::ConnectionRefused, error)),
        }
    }

    fn receive_event(&mut self) -> io::Result<bool> {
        let event = if self.nonblocking {
            match self.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::error::TryRecvError::Empty) => return Ok(false),
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(true),
            }
        } else {
            self.events.blocking_recv().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "Hysteria worker stopped")
            })?
        };
        match event {
            HysteriaEvent::Data(data) => {
                self.plaintext.extend_from_slice(&data);
                Ok(true)
            }
            HysteriaEvent::Closed => Ok(true),
            HysteriaEvent::Error(error) => {
                Err(io::Error::new(io::ErrorKind::ConnectionReset, error))
            }
        }
    }
}

impl Read for HysteriaStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.plaintext.is_empty() {
                let length = buffer.len().min(self.plaintext.len());
                buffer[..length].copy_from_slice(&self.plaintext[..length]);
                self.plaintext.drain(..length);
                return Ok(length);
            }
            if !self.receive_event()? {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Hysteria read pending",
                ));
            }
        }
    }
}

impl Write for HysteriaStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.nonblocking {
            self.commands
                .try_send(buffer.to_vec())
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        io::Error::new(io::ErrorKind::WouldBlock, "Hysteria write pending")
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria worker stopped")
                    }
                })?;
        } else {
            self.commands.blocking_send(buffer.to_vec()).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria worker stopped")
            })?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hysteria_padding(minimum: usize, maximum: usize) -> io::Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if minimum >= maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Hysteria padding range",
        ));
    }
    let mut random = [0u8; 8];
    rand::SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("failed to generate Hysteria padding length"))?;
    let span = u64::try_from(maximum - minimum).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria padding range overflow",
        )
    })?;
    let length = minimum
        + usize::try_from(u64::from_be_bytes(random) % span).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria padding length overflow",
            )
        })?;
    let mut output = vec![0u8; length];
    rand::SystemRandom::new()
        .fill(&mut output)
        .map_err(|_| io::Error::other("failed to generate Hysteria padding"))?;
    for byte in &mut output {
        *byte = ALPHABET[usize::from(*byte) % ALPHABET.len()];
    }
    Ok(output)
}

fn hysteria_quic_client_config() -> io::Result<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_hysteria(
    server: String,
    port: u16,
    server_name: String,
    auth: String,
    target: Target,
    mut commands: mpsc::Receiver<Vec<u8>>,
    events: mpsc::Sender<HysteriaEvent>,
    startup: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> io::Result<()> {
    let remote = (server.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Hysteria server has no address"))?;
    let mut endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse::<SocketAddr>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?,
    )?;
    endpoint.set_default_client_config(hysteria_quic_client_config()?);
    let connection = endpoint
        .connect(remote, &server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut h3_connection, mut request_sender) = h3::client::new(h3_connection)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });
    let auth_padding = hysteria_padding(256, 2048)?;
    let request = Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", auth)
        .header("Hysteria-CC-RX", "0")
        .header(
            "Hysteria-Padding",
            http::HeaderValue::from_bytes(&auth_padding)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?,
        )
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let mut auth_stream = request_sender
        .send_request(request)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    auth_stream
        .finish()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    let response = auth_stream
        .recv_response()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    if response.status().as_u16() != 233 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Hysteria authentication returned {}", response.status()),
        ));
    }
    drop(auth_stream);
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    let request_padding = hysteria_padding(64, 512)?;
    let request = encode_hysteria_tcp_request(&target_authority(&target)?, &request_padding)?;
    send.write_all(&request)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionReset, error.to_string()))?;
    let (ok, message) = read_hysteria_tcp_response_async(&mut receive).await?;
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Hysteria proxy rejected target: {message}"),
        ));
    }
    startup.send(Ok(())).map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Hysteria startup receiver closed",
        )
    })?;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    send.finish().map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
                    return Ok(());
                };
                send.write_all(&command).await.map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
            }
            data = receive.read(&mut buffer) => {
                match data {
                    Ok(None | Some(0)) => {
                        let _ = events.send(HysteriaEvent::Closed).await;
                        return Ok(());
                    }
                    Ok(Some(length)) => events.send(HysteriaEvent::Data(buffer[..length].to_vec())).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria reader closed"))?,
                    Err(error) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, error.to_string())),
                }
            }
        }
    }
}

async fn read_quic_varint_async<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let length = 1usize << usize::from(first[0] >> 6);
    let mut encoded = vec![0u8; length];
    encoded[0] = first[0];
    if length > 1 {
        reader.read_exact(&mut encoded[1..]).await?;
    }
    decode_quic_varint(&encoded).map(|(value, _)| value)
}

async fn read_hysteria_tcp_response_async(
    reader: &mut quinn::RecvStream,
) -> io::Result<(bool, String)> {
    let mut status = [0u8; 1];
    reader
        .read_exact(&mut status)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::UnexpectedEof, error.to_string()))?;
    if status[0] > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria status",
        ));
    }
    let message_length = usize::try_from(read_quic_varint_async(reader).await?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria message length overflow",
        )
    })?;
    if message_length > HYSTERIA_MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria message length",
        ));
    }
    let mut message = vec![0u8; message_length];
    reader
        .read_exact(&mut message)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::UnexpectedEof, error.to_string()))?;
    let padding_length = usize::try_from(read_quic_varint_async(reader).await?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria padding length overflow",
        )
    })?;
    if padding_length > HYSTERIA_MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Hysteria response padding",
        ));
    }
    let mut padding = vec![0u8; padding_length];
    reader
        .read_exact(&mut padding)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::UnexpectedEof, error.to_string()))?;
    let message = String::from_utf8(message)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Hysteria message is not UTF-8"))?;
    Ok((status[0] == 0, message))
}

enum RemoteStream {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    WebSocket(Box<WebSocketStream>),
    Xhttp(Box<XhttpStream>),
    XhttpUp(Box<XhttpStreamUp>),
    XhttpPacketUp(Box<XhttpPacketUpStream>),
    Vmess(Box<VmessStream>),
    VlessVision(Box<VlessVisionStream>),
    Shadowsocks(Box<ShadowsocksStream>),
    Shadowsocks2022(Box<Shadowsocks2022Stream>),
    Grpc(Box<GrpcStream>),
    Mkcp(Box<MkcpStream>),
    Reality(Box<RealityStream>),
    WireGuard(Box<WireGuardStream>),
    Hysteria(Box<HysteriaStream>),
}

struct WebSocketStream {
    socket: WebSocket<Box<RemoteStream>>,
    read_buffer: Vec<u8>,
}

enum XhttpIo {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Reality(Box<RealityStream>),
}

#[allow(clippy::struct_excessive_bools)]
struct XhttpStream {
    stream: XhttpIo,
    response_headers_read: bool,
    response_chunk_remaining: usize,
    response_chunked: bool,
    response_closed: bool,
    request_closed: bool,
}

struct XhttpStreamUp {
    upload: XhttpUploadStream,
    download: XhttpStream,
}

struct XhttpUploadStream {
    stream: XhttpIo,
    request_closed: bool,
}

struct XhttpPacketUpStream {
    download: XhttpStream,
    server: String,
    port: u16,
    security: XraySecurity,
    server_name: String,
    path: String,
    host: String,
    session_id: String,
    next_sequence: u64,
    options: XhttpRequestOptions,
    reality_settings: Option<XrayRealitySettings>,
}

struct VmessStream {
    stream: Box<RemoteStream>,
    security: VmessSecurity,
    write_key: [u8; 16],
    write_iv: [u8; 16],
    read_key: [u8; 16],
    read_iv: [u8; 16],
    write_sequence: u16,
    read_sequence: u16,
    read_encrypted: Vec<u8>,
    read_plaintext: Vec<u8>,
    read_closed: bool,
    write_pending: Vec<u8>,
}

struct ShadowsocksStream {
    stream: TcpStream,
    method: ShadowsocksMethod,
    password: String,
    read_salt: Option<Vec<u8>>,
    read_cipher: Option<ShadowsocksCipher>,
    read_sequence: u64,
    read_encrypted: Vec<u8>,
    read_plaintext: Vec<u8>,
    read_closed: bool,
    write_salt: Option<Vec<u8>>,
    write_cipher: Option<ShadowsocksCipher>,
    write_sequence: u64,
    write_pending: Vec<u8>,
}

impl ShadowsocksStream {
    fn new(stream: TcpStream, method: ShadowsocksMethod, password: &str) -> io::Result<Self> {
        if !method.is_legacy() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported Shadowsocks AEAD method",
            ));
        }
        Ok(Self {
            stream,
            method,
            password: password.to_owned(),
            read_salt: None,
            read_cipher: None,
            read_sequence: 0,
            read_encrypted: Vec::new(),
            read_plaintext: Vec::new(),
            read_closed: false,
            write_salt: None,
            write_cipher: None,
            write_sequence: 0,
            write_pending: Vec::new(),
        })
    }

    fn salt_len(&self) -> usize {
        self.method.key_len()
    }

    fn ensure_write_cipher(&mut self) -> io::Result<()> {
        if self.write_cipher.is_some() {
            return Ok(());
        }
        let mut salt = vec![0u8; self.salt_len()];
        rand::SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| io::Error::other("failed to generate Shadowsocks salt"))?;
        self.write_cipher = Some(ShadowsocksCipher::new(self.method, &self.password, &salt)?);
        self.write_pending.extend_from_slice(&salt);
        self.write_salt = Some(salt);
        Ok(())
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        while !self.write_pending.is_empty() {
            match self.stream.write(&self.write_pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks connection closed while writing",
                    ));
                }
                Ok(length) => {
                    self.write_pending.drain(..length);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn pump_read(&mut self) -> io::Result<bool> {
        let mut buffer = [0u8; 16 * 1024];
        match self.stream.read(&mut buffer) {
            Ok(0) => {
                if !self.read_encrypted.is_empty() || self.read_salt.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated Shadowsocks stream",
                    ));
                }
                self.read_closed = true;
                return Ok(true);
            }
            Ok(length) => self.read_encrypted.extend_from_slice(&buffer[..length]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }

        if self.read_salt.is_none() {
            if self.read_encrypted.len() < self.salt_len() {
                return Ok(true);
            }
            let salt = self
                .read_encrypted
                .drain(..self.salt_len())
                .collect::<Vec<_>>();
            self.read_cipher = Some(ShadowsocksCipher::new(self.method, &self.password, &salt)?);
            self.read_salt = Some(salt);
        }

        let Some(cipher) = self.read_cipher.as_ref() else {
            return Err(io::Error::other("missing Shadowsocks read cipher"));
        };
        while self.read_encrypted.len() >= 2 + SHADOWSOCKS_TAG_LEN {
            let encrypted_length = &self.read_encrypted[..2 + SHADOWSOCKS_TAG_LEN];
            let length = cipher.open(self.read_sequence, encrypted_length)?;
            let length = u16::from_be_bytes(length.as_slice().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Shadowsocks length")
            })?) as usize;
            if length == 0 || length > SHADOWSOCKS_MAX_CHUNK {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks chunk length",
                ));
            }
            let frame_len = 2 + SHADOWSOCKS_TAG_LEN + length + SHADOWSOCKS_TAG_LEN;
            if self.read_encrypted.len() < frame_len {
                break;
            }
            let payload = cipher.open(
                self.read_sequence + 1,
                &self.read_encrypted[2 + SHADOWSOCKS_TAG_LEN..frame_len],
            )?;
            self.read_plaintext.extend_from_slice(&payload);
            self.read_encrypted.drain(..frame_len);
            self.read_sequence += 2;
        }
        Ok(true)
    }
}

impl Read for ShadowsocksStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.read_plaintext.is_empty() {
                let length = buffer.len().min(self.read_plaintext.len());
                buffer[..length].copy_from_slice(&self.read_plaintext[..length]);
                self.read_plaintext.drain(..length);
                return Ok(length);
            }
            if self.read_closed {
                return Ok(0);
            }
            let progressed = self.pump_read()?;
            if self.read_plaintext.is_empty() && self.read_closed {
                return Ok(0);
            }
            if self.read_plaintext.is_empty() && !progressed {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Shadowsocks read pending",
                ));
            }
        }
    }
}

impl Write for ShadowsocksStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.flush_pending()?;
        if !self.write_pending.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Shadowsocks write pending",
            ));
        }
        self.ensure_write_cipher()?;
        let length = buffer.len().min(SHADOWSOCKS_MAX_CHUNK);
        let salt = self
            .write_salt
            .as_deref()
            .ok_or_else(|| io::Error::other("missing Shadowsocks write salt"))?;
        let frame = encode_shadowsocks_frame(
            self.method,
            &self.password,
            salt,
            self.write_sequence,
            &buffer[..length],
        )?;
        self.write_sequence += 2;
        self.write_pending.extend_from_slice(&frame);
        self.flush_pending()?;
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()
    }
}

struct Shadowsocks2022Stream {
    stream: TcpStream,
    method: ShadowsocksMethod,
    master_key: Vec<u8>,
    target_address: Vec<u8>,
    write_salt: Vec<u8>,
    write_cipher: Shadowsocks2022Cipher,
    write_pending: Vec<u8>,
    read_encrypted: Vec<u8>,
    read_cipher: Option<Shadowsocks2022Cipher>,
    read_plaintext: Vec<u8>,
    read_next_data_length: Option<usize>,
    read_closed: bool,
}

impl Shadowsocks2022Stream {
    fn new(
        stream: TcpStream,
        method: ShadowsocksMethod,
        password: &str,
        target_address: Vec<u8>,
    ) -> io::Result<Self> {
        let master_key = decode_shadowsocks2022_master_key(method, password)?;
        let mut write_salt = vec![0u8; method.key_len()];
        rand::SystemRandom::new()
            .fill(&mut write_salt)
            .map_err(|_| io::Error::other("failed to generate Shadowsocks 2022 salt"))?;
        let write_cipher = Shadowsocks2022Cipher::new(method, &master_key, &write_salt)?;
        Ok(Self {
            stream,
            method,
            master_key,
            target_address,
            write_salt,
            write_cipher,
            write_pending: Vec::new(),
            read_encrypted: Vec::new(),
            read_cipher: None,
            read_plaintext: Vec::new(),
            read_next_data_length: None,
            read_closed: false,
        })
    }

    fn timestamp() -> io::Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| io::Error::other("system clock is before UNIX epoch"))
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        while !self.write_pending.is_empty() {
            match self.stream.write(&self.write_pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks 2022 connection closed while writing",
                    ));
                }
                Ok(length) => self.write_pending.drain(..length),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            };
        }
        Ok(())
    }

    fn append_encrypted_frame(
        cipher: &mut Shadowsocks2022Cipher,
        length: usize,
        payload: &[u8],
        output: &mut Vec<u8>,
    ) -> io::Result<()> {
        let length = u16::try_from(length).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 chunk is too large",
            )
        })?;
        output.extend_from_slice(&cipher.seal(&length.to_be_bytes())?);
        output.extend_from_slice(&cipher.seal(payload)?);
        Ok(())
    }

    fn start(&mut self) -> io::Result<()> {
        let mut payload = Vec::with_capacity(self.target_address.len() + 2);
        payload.extend_from_slice(&self.target_address);
        payload.extend_from_slice(&0u16.to_be_bytes());
        let timestamp = Self::timestamp()?;
        self.write_pending.extend_from_slice(&self.write_salt);
        let mut header = Vec::with_capacity(1 + 8 + 2);
        header.push(0);
        header.extend_from_slice(&timestamp.to_be_bytes());
        header.extend_from_slice(
            &u16::try_from(payload.len())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "target address is too large")
                })?
                .to_be_bytes(),
        );
        self.write_pending
            .extend_from_slice(&self.write_cipher.seal(&header)?);
        self.write_pending
            .extend_from_slice(&self.write_cipher.seal(&payload)?);
        self.flush_pending()
    }

    #[allow(clippy::too_many_lines)]
    fn parse_response(&mut self) -> io::Result<bool> {
        let salt_len = self.method.key_len();
        if self.read_cipher.is_none() {
            let header_plaintext_len = 1 + 8 + salt_len + 2;
            let header_ciphertext_len = header_plaintext_len + SHADOWSOCKS_TAG_LEN;
            let total = salt_len + header_ciphertext_len;
            if self.read_encrypted.len() < total {
                return Ok(false);
            }
            let server_salt = self.read_encrypted.drain(..salt_len).collect::<Vec<_>>();
            let mut cipher =
                Shadowsocks2022Cipher::new(self.method, &self.master_key, &server_salt)?;
            let encrypted_header = self
                .read_encrypted
                .drain(..header_ciphertext_len)
                .collect::<Vec<_>>();
            let header = cipher.open(&encrypted_header)?;
            if header.len() != header_plaintext_len || header[0] != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks 2022 response header",
                ));
            }
            let timestamp = u64::from_be_bytes(header[1..9].try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks 2022 timestamp",
                )
            })?);
            let now = Self::timestamp()?;
            if now.abs_diff(timestamp) > 30 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stale Shadowsocks 2022 response timestamp",
                ));
            }
            if header[9..9 + salt_len] != self.write_salt {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks 2022 response salt does not match the request",
                ));
            }
            let data_length = usize::from(u16::from_be_bytes(
                header[9 + salt_len..].try_into().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Shadowsocks 2022 length",
                    )
                })?,
            ));
            self.read_next_data_length = (data_length > 0).then_some(data_length);
            self.read_cipher = Some(cipher);
        }

        loop {
            let Some(length) = self.read_next_data_length else {
                if self.read_encrypted.len() < 2 + SHADOWSOCKS_TAG_LEN {
                    return Ok(false);
                }
                let cipher = self
                    .read_cipher
                    .as_mut()
                    .ok_or_else(|| io::Error::other("missing Shadowsocks 2022 read cipher"))?;
                let encrypted_length = self
                    .read_encrypted
                    .drain(..2 + SHADOWSOCKS_TAG_LEN)
                    .collect::<Vec<_>>();
                let length = cipher.open(&encrypted_length)?;
                let length = usize::from(u16::from_be_bytes(length.try_into().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Shadowsocks 2022 length",
                    )
                })?));
                if length > SHADOWSOCKS_MAX_CHUNK {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Shadowsocks 2022 chunk length",
                    ));
                }
                self.read_next_data_length = Some(length);
                continue;
            };
            let encrypted_data_len = length + SHADOWSOCKS_TAG_LEN;
            if self.read_encrypted.len() < encrypted_data_len {
                return Ok(false);
            }
            let encrypted_data = self
                .read_encrypted
                .drain(..encrypted_data_len)
                .collect::<Vec<_>>();
            let cipher = self
                .read_cipher
                .as_mut()
                .ok_or_else(|| io::Error::other("missing Shadowsocks 2022 read cipher"))?;
            let data = cipher.open(&encrypted_data)?;
            self.read_plaintext.extend_from_slice(&data);
            self.read_next_data_length = None;
            if data.is_empty() {
                continue;
            }
            return Ok(true);
        }
    }

    fn pump_read(&mut self) -> io::Result<bool> {
        let mut buffer = [0u8; 16 * 1024];
        match self.stream.read(&mut buffer) {
            Ok(0) => {
                if self.read_cipher.is_none() || !self.read_encrypted.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated Shadowsocks 2022 stream",
                    ));
                }
                self.read_closed = true;
                return Ok(true);
            }
            Ok(length) => self.read_encrypted.extend_from_slice(&buffer[..length]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
        self.parse_response()
    }
}

impl Read for Shadowsocks2022Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.read_plaintext.is_empty() {
                let length = buffer.len().min(self.read_plaintext.len());
                buffer[..length].copy_from_slice(&self.read_plaintext[..length]);
                self.read_plaintext.drain(..length);
                return Ok(length);
            }
            if self.read_closed {
                return Ok(0);
            }
            let progressed = self.pump_read()?;
            if !self.read_plaintext.is_empty() {
                continue;
            }
            if self.read_closed {
                return Ok(0);
            }
            if !progressed {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Shadowsocks 2022 read pending",
                ));
            }
        }
    }
}

impl Write for Shadowsocks2022Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.flush_pending()?;
        if !self.write_pending.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Shadowsocks 2022 write pending",
            ));
        }
        let length = buffer.len().min(SHADOWSOCKS_MAX_CHUNK);
        Self::append_encrypted_frame(
            &mut self.write_cipher,
            length,
            &buffer[..length],
            &mut self.write_pending,
        )?;
        self.flush_pending()?;
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()
    }
}

impl Read for RemoteStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
            Self::WebSocket(stream) => stream.read(buffer),
            Self::Xhttp(stream) => stream.read(buffer),
            Self::XhttpUp(stream) => stream.read(buffer),
            Self::XhttpPacketUp(stream) => stream.read(buffer),
            Self::Vmess(stream) => stream.read(buffer),
            Self::VlessVision(stream) => stream.read(buffer),
            Self::Shadowsocks(stream) => stream.read(buffer),
            Self::Shadowsocks2022(stream) => stream.read(buffer),
            Self::Grpc(stream) => stream.read(buffer),
            Self::Mkcp(stream) => stream.read(buffer),
            Self::Reality(stream) => stream.read(buffer),
            Self::WireGuard(stream) => stream.read(buffer),
            Self::Hysteria(stream) => stream.read(buffer),
        }
    }
}

impl Write for RemoteStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
            Self::WebSocket(stream) => stream.write(buffer),
            Self::Xhttp(stream) => stream.write(buffer),
            Self::XhttpUp(stream) => stream.write(buffer),
            Self::XhttpPacketUp(stream) => stream.write(buffer),
            Self::Vmess(stream) => stream.write(buffer),
            Self::VlessVision(stream) => stream.write(buffer),
            Self::Shadowsocks(stream) => stream.write(buffer),
            Self::Shadowsocks2022(stream) => stream.write(buffer),
            Self::Grpc(stream) => stream.write(buffer),
            Self::Mkcp(stream) => stream.write(buffer),
            Self::Reality(stream) => stream.write(buffer),
            Self::WireGuard(stream) => stream.write(buffer),
            Self::Hysteria(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
            Self::WebSocket(stream) => stream.flush(),
            Self::Xhttp(stream) => stream.flush(),
            Self::XhttpUp(stream) => stream.flush(),
            Self::XhttpPacketUp(stream) => stream.flush(),
            Self::Vmess(stream) => stream.flush(),
            Self::VlessVision(stream) => stream.flush(),
            Self::Shadowsocks(stream) => stream.flush(),
            Self::Shadowsocks2022(stream) => stream.flush(),
            Self::Grpc(stream) => stream.flush(),
            Self::Mkcp(stream) => stream.flush(),
            Self::Reality(stream) => stream.flush(),
            Self::WireGuard(stream) => stream.flush(),
            Self::Hysteria(stream) => stream.flush(),
        }
    }
}

impl RemoteStream {
    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nonblocking(nonblocking),
            Self::Tls(stream) => stream.get_ref().set_nonblocking(nonblocking),
            Self::WebSocket(stream) => stream.socket.get_mut().set_nonblocking(nonblocking),
            Self::Xhttp(stream) => stream.set_nonblocking(nonblocking),
            Self::XhttpUp(stream) => stream.set_nonblocking(nonblocking),
            Self::XhttpPacketUp(stream) => stream.set_nonblocking(nonblocking),
            Self::Vmess(stream) => stream.set_nonblocking(nonblocking),
            Self::VlessVision(stream) => stream.set_nonblocking(nonblocking),
            Self::Shadowsocks(stream) => stream.stream.set_nonblocking(nonblocking),
            Self::Shadowsocks2022(stream) => stream.stream.set_nonblocking(nonblocking),
            Self::Grpc(stream) => {
                stream.nonblocking = nonblocking;
                Ok(())
            }
            Self::Mkcp(stream) => {
                stream.set_nonblocking(nonblocking);
                Ok(())
            }
            Self::Reality(stream) => stream.set_nonblocking(nonblocking),
            Self::WireGuard(stream) => {
                stream.set_nonblocking(nonblocking);
                Ok(())
            }
            Self::Hysteria(stream) => {
                stream.nonblocking = nonblocking;
                Ok(())
            }
        }
    }
}

impl Read for WebSocketStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.read_buffer.is_empty() {
            let length = buffer.len().min(self.read_buffer.len());
            buffer[..length].copy_from_slice(&self.read_buffer[..length]);
            self.read_buffer.drain(..length);
            return Ok(length);
        }
        loop {
            let message = self.socket.read().map_err(websocket_io_error)?;
            match message {
                Message::Binary(data) => {
                    self.read_buffer.extend_from_slice(&data);
                    let length = buffer.len().min(self.read_buffer.len());
                    buffer[..length].copy_from_slice(&self.read_buffer[..length]);
                    self.read_buffer.drain(..length);
                    return Ok(length);
                }
                Message::Close(_) => return Ok(0),
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) | Message::Frame(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Xray WebSocket transport returned non-binary data",
                    ));
                }
            }
        }
    }
}

impl Write for WebSocketStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket
            .send(Message::binary(buffer.to_vec()))
            .map_err(websocket_io_error)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush().map_err(websocket_io_error)
    }
}

impl Read for XhttpIo {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
            Self::Reality(stream) => stream.read(buffer),
        }
    }
}

impl Write for XhttpIo {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
            Self::Reality(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
            Self::Reality(stream) => stream.flush(),
        }
    }
}

impl XhttpStream {
    fn connect(
        server: &str,
        port: u16,
        security: XraySecurity,
        server_name: &str,
        settings: &XrayXhttpSettings,
        options: &XhttpRequestOptions,
        reality_settings: Option<&XrayRealitySettings>,
    ) -> io::Result<Self> {
        if !settings.mode.eq_ignore_ascii_case("auto")
            && !settings.mode.eq_ignore_ascii_case("stream-one")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XHTTP handler supports auto and stream-one modes only",
            ));
        }
        let mut stream = xhttp_connect_io(server, port, security, server_name, reality_settings)?;
        let stream_one = settings.mode.eq_ignore_ascii_case("stream-one")
            || (settings.mode.eq_ignore_ascii_case("auto") && security == XraySecurity::Reality);
        let session_id = (!stream_one).then(xhttp_session_id).transpose()?;
        let host = settings.host.as_deref().unwrap_or(server_name);
        xhttp_write_request(
            &mut stream,
            "POST",
            &settings.path,
            host,
            true,
            XhttpRequestMetadata {
                session_id: session_id.as_deref(),
                sequence: None,
                options,
            },
        )?;
        Ok(Self {
            stream,
            response_headers_read: false,
            response_chunk_remaining: 0,
            response_chunked: false,
            response_closed: false,
            request_closed: false,
        })
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        match &mut self.stream {
            XhttpIo::Tcp(stream) => stream.set_nonblocking(nonblocking),
            XhttpIo::Tls(stream) => stream.get_ref().set_nonblocking(nonblocking),
            XhttpIo::Reality(stream) => stream.set_nonblocking(nonblocking),
        }
    }

    fn read_response_headers(&mut self) -> io::Result<()> {
        let mut headers = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        while headers.len() < 32 * 1024 {
            self.stream.read_exact(&mut byte)?;
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        if !headers.ends_with(b"\r\n\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP response headers exceed 32 KiB",
            ));
        }
        let mut lines = headers.split(|byte| *byte == b'\n');
        let status = lines
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty XHTTP response"))?;
        if !status.starts_with(b"HTTP/1.1 200") && !status.starts_with(b"HTTP/2 200") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "XHTTP server rejected stream",
            ));
        }
        let mut content_length = None;
        for line in lines {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(separator) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            let name = &line[..separator];
            let value = &line[separator + 1..];
            if name.eq_ignore_ascii_case(b"transfer-encoding")
                && trim_ascii_bytes(value)
                    .split(|byte| *byte == b',')
                    .any(|item| trim_ascii_bytes(item).eq_ignore_ascii_case(b"chunked"))
            {
                self.response_chunked = true;
            }
            if name.eq_ignore_ascii_case(b"content-length") {
                content_length = parse_decimal_bytes(trim_ascii_bytes(value));
            }
        }
        if !self.response_chunked && content_length.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XHTTP response is not a streaming body",
            ));
        }
        self.response_headers_read = true;
        if !self.response_chunked {
            self.response_chunk_remaining = content_length.unwrap_or(0);
        }
        Ok(())
    }

    fn read_chunk_size(&mut self) -> io::Result<usize> {
        let line = read_crlf_line(&mut self.stream, 64)?;
        let size = line
            .split(|byte| *byte == b';')
            .next()
            .and_then(|value| parse_hex_number(trim_ascii_bytes(value)))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid XHTTP chunk"))?;
        Ok(size)
    }
}

impl XhttpStreamUp {
    fn connect(
        server: &str,
        port: u16,
        security: XraySecurity,
        server_name: &str,
        settings: &XrayXhttpSettings,
        options: &XhttpRequestOptions,
        reality_settings: Option<&XrayRealitySettings>,
    ) -> io::Result<Self> {
        let session_id = xhttp_session_id()?;
        let host = settings.host.as_deref().unwrap_or(server_name);

        let mut upload = xhttp_connect_io(server, port, security, server_name, reality_settings)?;
        xhttp_write_request(
            &mut upload,
            "POST",
            &settings.path,
            host,
            true,
            XhttpRequestMetadata {
                session_id: Some(&session_id),
                sequence: None,
                options,
            },
        )?;

        let mut download = xhttp_connect_io(server, port, security, server_name, reality_settings)?;
        xhttp_write_request(
            &mut download,
            "GET",
            &settings.path,
            host,
            false,
            XhttpRequestMetadata {
                session_id: Some(&session_id),
                sequence: None,
                options,
            },
        )?;

        Ok(Self {
            upload: XhttpUploadStream {
                stream: upload,
                request_closed: false,
            },
            download: XhttpStream {
                stream: download,
                response_headers_read: false,
                response_chunk_remaining: 0,
                response_chunked: false,
                response_closed: false,
                request_closed: true,
            },
        })
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.upload.set_nonblocking(nonblocking)?;
        self.download.set_nonblocking(nonblocking)
    }
}

impl Read for XhttpStreamUp {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.download.read(buffer)
    }
}

impl Write for XhttpStreamUp {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.upload.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.upload.flush()
    }
}

impl XhttpUploadStream {
    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        match &mut self.stream {
            XhttpIo::Tcp(stream) => stream.set_nonblocking(nonblocking),
            XhttpIo::Tls(stream) => stream.get_ref().set_nonblocking(nonblocking),
            XhttpIo::Reality(stream) => stream.set_nonblocking(nonblocking),
        }
    }
}

impl XhttpPacketUpStream {
    fn connect(
        server: &str,
        port: u16,
        security: XraySecurity,
        server_name: &str,
        settings: &XrayXhttpSettings,
        options: &XhttpRequestOptions,
        reality_settings: Option<&XrayRealitySettings>,
    ) -> io::Result<Self> {
        let session_id = xhttp_session_id()?;
        let host = settings.host.as_deref().unwrap_or(server_name);
        let mut download = xhttp_connect_io(server, port, security, server_name, reality_settings)?;
        xhttp_write_request(
            &mut download,
            "GET",
            &settings.path,
            host,
            false,
            XhttpRequestMetadata {
                session_id: Some(&session_id),
                sequence: None,
                options,
            },
        )?;

        Ok(Self {
            download: XhttpStream {
                stream: download,
                response_headers_read: false,
                response_chunk_remaining: 0,
                response_chunked: false,
                response_closed: false,
                request_closed: true,
            },
            server: server.to_owned(),
            port,
            security,
            server_name: server_name.to_owned(),
            path: settings.path.clone(),
            host: host.to_owned(),
            session_id,
            next_sequence: 0,
            options: options.clone(),
            reality_settings: reality_settings.cloned(),
        })
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.download.set_nonblocking(nonblocking)
    }
}

impl Read for XhttpPacketUpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.download.read(buffer)
    }
}

impl Write for XhttpPacketUpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let sequence = self.next_sequence;
        let mut upload = xhttp_connect_io(
            &self.server,
            self.port,
            self.security,
            &self.server_name,
            self.reality_settings.as_ref(),
        )?;
        let body = xhttp_write_packet_request(
            &mut upload,
            &self.path,
            &self.host,
            Some(&self.session_id),
            Some(sequence),
            &self.options,
            buffer,
        )?;
        if body {
            upload.write_all(buffer)?;
        }
        upload.flush()?;
        read_xhttp_packet_response(&mut upload)?;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for XhttpUploadStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.request_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP upload request body is closed",
            ));
        }
        write!(self.stream, "{:X}\r\n", buffer.len())?;
        self.stream.write_all(buffer)?;
        self.stream.write_all(b"\r\n")?;
        self.stream.flush()?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn xhttp_connect_io(
    server: &str,
    port: u16,
    security: XraySecurity,
    server_name: &str,
    reality_settings: Option<&XrayRealitySettings>,
) -> io::Result<XhttpIo> {
    match security {
        XraySecurity::None => Ok(XhttpIo::Tcp(connect_tcp(server, port)?)),
        XraySecurity::Tls => {
            let stream = connect_tcp(server, port)?;
            Ok(XhttpIo::Tls(Box::new(connect_tls(stream, server_name)?)))
        }
        XraySecurity::Reality => {
            let settings = reality_settings.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY settings are required for XHTTP",
                )
            })?;
            Ok(XhttpIo::Reality(Box::new(RealityStream::connect(
                server,
                port,
                server_name,
                settings,
            )?)))
        }
    }
}

fn xhttp_session_id() -> io::Result<String> {
    let mut session_id = [0u8; 16];
    rand::SystemRandom::new()
        .fill(&mut session_id)
        .map_err(|_| io::Error::other("failed to generate XHTTP session id"))?;
    session_id[6] = (session_id[6] & 0x0f) | 0x40;
    session_id[8] = (session_id[8] & 0x3f) | 0x80;
    let mut encoded = String::with_capacity(36);
    for (index, byte) in session_id.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            encoded.push('-');
        }
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| io::Error::other("failed to encode XHTTP session id"))?;
    }
    Ok(encoded)
}

fn xhttp_write_request(
    stream: &mut XhttpIo,
    method: &str,
    path: &str,
    host: &str,
    chunked: bool,
    metadata: XhttpRequestMetadata<'_>,
) -> io::Result<()> {
    let path = xhttp_request_path(
        path,
        metadata.session_id,
        metadata.sequence,
        metadata.options,
    )?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
    )?;
    xhttp_write_metadata_headers(
        stream,
        metadata.session_id,
        metadata.sequence,
        metadata.options,
    )?;
    if chunked {
        stream.write_all(b"Content-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n")?;
    }
    stream.write_all(b"Connection: keep-alive\r\n\r\n")?;
    stream.flush()
}

fn xhttp_request_path(
    path: &str,
    session_id: Option<&str>,
    sequence: Option<u64>,
    options: &XhttpRequestOptions,
) -> io::Result<String> {
    let (base, query) = xhttp_split_path(path)?;
    let mut output = base;
    let mut query_parameters = Vec::new();
    if !query.is_empty() {
        query_parameters.push(query.to_owned());
    }
    if let Some(session_id) = session_id {
        match options.session_placement {
            XhttpMetadataPlacement::Path => append_xhttp_path_segment(&mut output, session_id),
            XhttpMetadataPlacement::Query => {
                query_parameters.push(format!("{}={session_id}", options.session_key));
            }
            XhttpMetadataPlacement::Header | XhttpMetadataPlacement::Cookie => {}
        }
    }
    if let Some(sequence) = sequence {
        let sequence = sequence.to_string();
        match options.sequence_placement {
            XhttpMetadataPlacement::Path => append_xhttp_path_segment(&mut output, &sequence),
            XhttpMetadataPlacement::Query => {
                query_parameters.push(format!("{}={sequence}", options.sequence_key));
            }
            XhttpMetadataPlacement::Header | XhttpMetadataPlacement::Cookie => {}
        }
    }
    if !query_parameters.is_empty() {
        output.push('?');
        output.push_str(&query_parameters.join("&"));
    }
    Ok(output)
}

fn xhttp_split_path(path: &str) -> io::Result<(String, &str)> {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    if path.is_empty() || !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid XHTTP path",
        ));
    }
    let path = if path == "/" {
        "/".to_owned()
    } else {
        path.trim_end_matches('/').to_owned()
    };
    Ok((path, query))
}

fn append_xhttp_path_segment(path: &mut String, segment: &str) {
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(segment);
}

fn xhttp_write_metadata_headers(
    stream: &mut XhttpIo,
    session_id: Option<&str>,
    sequence: Option<u64>,
    options: &XhttpRequestOptions,
) -> io::Result<()> {
    let mut cookies = Vec::new();
    xhttp_write_metadata_headers_without_cookie(
        stream,
        session_id,
        sequence,
        options,
        &mut cookies,
    )?;
    if !cookies.is_empty() {
        write!(stream, "Cookie: {}\r\n", cookies.join("; "))?;
    }
    Ok(())
}

fn xhttp_write_metadata_headers_without_cookie(
    stream: &mut XhttpIo,
    session_id: Option<&str>,
    sequence: Option<u64>,
    options: &XhttpRequestOptions,
    cookies: &mut Vec<String>,
) -> io::Result<()> {
    if let Some(session_id) = session_id {
        match options.session_placement {
            XhttpMetadataPlacement::Header => {
                write!(stream, "{}: {session_id}\r\n", options.session_key)?;
            }
            XhttpMetadataPlacement::Cookie => {
                cookies.push(format!("{}={session_id}", options.session_key));
            }
            XhttpMetadataPlacement::Path | XhttpMetadataPlacement::Query => {}
        }
    }
    if let Some(sequence) = sequence {
        let sequence = sequence.to_string();
        match options.sequence_placement {
            XhttpMetadataPlacement::Header => {
                write!(stream, "{}: {sequence}\r\n", options.sequence_key)?;
            }
            XhttpMetadataPlacement::Cookie => {
                cookies.push(format!("{}={sequence}", options.sequence_key));
            }
            XhttpMetadataPlacement::Path | XhttpMetadataPlacement::Query => {}
        }
    }
    Ok(())
}

fn xhttp_write_packet_request(
    stream: &mut XhttpIo,
    path: &str,
    host: &str,
    session_id: Option<&str>,
    sequence: Option<u64>,
    options: &XhttpRequestOptions,
    payload: &[u8],
) -> io::Result<bool> {
    let data_placement = match options.uplink_data_placement {
        XhttpDataPlacement::Auto if options.uplink_http_method == "GET" => {
            XhttpDataPlacement::Header
        }
        XhttpDataPlacement::Auto => XhttpDataPlacement::Body,
        placement => placement,
    };
    let body = data_placement == XhttpDataPlacement::Body;
    let path = xhttp_request_path(path, session_id, sequence, options)?;
    write!(
        stream,
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Type: application/grpc\r\n",
        options.uplink_http_method
    )?;
    let mut cookies = Vec::new();
    xhttp_write_metadata_headers_without_cookie(
        stream,
        session_id,
        sequence,
        options,
        &mut cookies,
    )?;
    if !body {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        for (index, chunk) in encoded.as_bytes().chunks(8 * 1024).enumerate() {
            let value = std::str::from_utf8(chunk)
                .map_err(|_| io::Error::other("XHTTP payload encoding is not UTF-8"))?;
            match data_placement {
                XhttpDataPlacement::Header => {
                    write!(stream, "{}-{index}: {value}\r\n", options.uplink_data_key)?;
                }
                XhttpDataPlacement::Cookie => {
                    cookies.push(format!("{}_{index}={value}", options.uplink_data_key));
                }
                XhttpDataPlacement::Auto | XhttpDataPlacement::Body => unreachable!(),
            }
        }
    }
    if !cookies.is_empty() {
        write!(stream, "Cookie: {}\r\n", cookies.join("; "))?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        if body { payload.len() } else { 0 }
    )?;
    stream.flush().map(|()| body)
}

fn read_xhttp_packet_response(stream: &mut XhttpIo) -> io::Result<()> {
    let mut headers = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while headers.len() < 32 * 1024 {
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !headers.ends_with(b"\r\n\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP packet response headers exceed 32 KiB",
        ));
    }
    let status = headers
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty XHTTP packet response"))?;
    if !status.starts_with(b"HTTP/1.1 200") && !status.starts_with(b"HTTP/2 200") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "XHTTP packet upload rejected",
        ));
    }
    Ok(())
}

impl VmessStream {
    fn new(
        stream: RemoteStream,
        security: VmessSecurity,
        write_key: [u8; 16],
        write_iv: [u8; 16],
        read_key: [u8; 16],
        read_iv: [u8; 16],
    ) -> Self {
        Self {
            stream: Box::new(stream),
            security,
            write_key,
            write_iv,
            read_key,
            read_iv,
            write_sequence: 0,
            read_sequence: 0,
            read_encrypted: Vec::new(),
            read_plaintext: Vec::new(),
            read_closed: false,
            write_pending: Vec::new(),
        }
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        while !self.write_pending.is_empty() {
            match self.stream.write(&self.write_pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess connection closed while writing",
                    ));
                }
                Ok(length) => self.write_pending.drain(..length),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            };
        }
        Ok(())
    }

    fn pump_read(&mut self) -> io::Result<bool> {
        let mut buffer = [0u8; 16 * 1024];
        match self.stream.read(&mut buffer) {
            Ok(0) => {
                if !self.read_encrypted.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated VMess body frame",
                    ));
                }
                self.read_closed = true;
                return Ok(true);
            }
            Ok(length) => self.read_encrypted.extend_from_slice(&buffer[..length]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
        while self.read_encrypted.len() >= 2 {
            let frame_length =
                u16::from_be_bytes([self.read_encrypted[0], self.read_encrypted[1]]) as usize;
            let valid_length = if self.security == VmessSecurity::None {
                frame_length <= VMESS_MAX_PAYLOAD
            } else {
                (VMESS_TAG_LEN..=VMESS_MAX_FRAME).contains(&frame_length)
            };
            if !valid_length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid VMess body frame length",
                ));
            }
            let total = 2 + frame_length;
            if self.read_encrypted.len() < total {
                break;
            }
            let payload = vmess_open(
                self.security,
                &self.read_key,
                vmess_chunk_nonce(&self.read_iv, self.read_sequence),
                &self.read_encrypted[2..total],
            )?;
            self.read_plaintext.extend_from_slice(&payload);
            self.read_encrypted.drain(..total);
            self.read_sequence = self.read_sequence.wrapping_add(1);
        }
        Ok(true)
    }
}

impl Read for VmessStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.read_plaintext.is_empty() {
                let length = buffer.len().min(self.read_plaintext.len());
                buffer[..length].copy_from_slice(&self.read_plaintext[..length]);
                self.read_plaintext.drain(..length);
                return Ok(length);
            }
            if self.read_closed {
                return Ok(0);
            }
            let progressed = self.pump_read()?;
            if self.read_plaintext.is_empty() && self.read_closed {
                return Ok(0);
            }
            if self.read_plaintext.is_empty() && !progressed {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "VMess read pending",
                ));
            }
        }
    }
}

impl Write for VmessStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.flush_pending()?;
        if !self.write_pending.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VMess write pending",
            ));
        }
        let length = buffer.len().min(VMESS_MAX_PAYLOAD);
        let encrypted = vmess_seal(
            self.security,
            &self.write_key,
            vmess_chunk_nonce(&self.write_iv, self.write_sequence),
            &buffer[..length],
        )?;
        let frame_length = u16::try_from(encrypted.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "VMess body frame is too large")
        })?;
        self.write_pending
            .extend_from_slice(&frame_length.to_be_bytes());
        self.write_pending.extend_from_slice(&encrypted);
        self.write_sequence = self.write_sequence.wrapping_add(1);
        self.flush_pending()?;
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()?;
        self.stream.flush()
    }
}

const VMESS_TAG_LEN: usize = 16;
const VMESS_MAX_PAYLOAD: usize = 16 * 1024;
const VMESS_MAX_FRAME: usize = VMESS_MAX_PAYLOAD + VMESS_TAG_LEN;

#[allow(clippy::too_many_arguments)]
fn connect_vmess(
    config: &VmessConfig,
    transport: XrayTransportConfig,
    server_name: Option<&str>,
    http_settings: &XrayHttpSettings,
    grpc_settings: &XrayGrpcSettings,
    xhttp_settings: &XrayXhttpSettings,
    xhttp_options: &XhttpRequestOptions,
    mkcp_settings: &XrayMkcpSettings,
    target: &Target,
) -> io::Result<RemoteStream> {
    if transport.security == XraySecurity::Reality {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VMess REALITY transport is not implemented",
        ));
    }
    let mut stream = connect_transport(
        &config.server,
        config.port,
        transport,
        server_name,
        http_settings,
        grpc_settings,
        xhttp_settings,
        xhttp_options,
        mkcp_settings,
        None,
    )?;
    let (header, write_key, write_iv, response_header) =
        encode_vmess_request(config.user_id, config.security, target)?;
    stream.write_all(&header)?;
    stream.flush()?;
    let (read_key, read_iv) = vmess_response_keys(&write_key, &write_iv);
    read_vmess_response_header(&mut stream, response_header, &read_key, &read_iv)?;
    Ok(RemoteStream::Vmess(Box::new(VmessStream::new(
        stream,
        config.security,
        write_key,
        write_iv,
        read_key,
        read_iv,
    ))))
}

type VmessRequest = (Vec<u8>, [u8; 16], [u8; 16], u8);

fn encode_vmess_request(
    user_id: [u8; 16],
    security: VmessSecurity,
    target: &Target,
) -> io::Result<VmessRequest> {
    let security_code = match security {
        VmessSecurity::Auto | VmessSecurity::Aes128Gcm => 3,
        VmessSecurity::ChaCha20Poly1305 => 4,
        VmessSecurity::None => 5,
    };
    let mut random = [0u8; 33];
    rand::SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("failed to generate VMess session keys"))?;
    let mut request_body_iv = [0u8; 16];
    request_body_iv.copy_from_slice(&random[..16]);
    let mut request_body_key = [0u8; 16];
    request_body_key.copy_from_slice(&random[16..32]);
    let response_header = random[32];
    let padding_len = usize::from(random[0] & 0x0f);
    let mut payload = Vec::with_capacity(96 + target.host.len());
    payload.push(1);
    payload.extend_from_slice(&request_body_iv);
    payload.extend_from_slice(&request_body_key);
    payload.push(response_header);
    payload.push(0);
    payload
        .push(u8::try_from(padding_len).expect("VMess padding is at most 15") << 4 | security_code);
    payload.push(0);
    payload.push(1);
    append_address(&mut payload, &target.host, 3, 2)?;
    payload.extend_from_slice(&target.port.to_be_bytes());
    payload.extend(std::iter::repeat_n(0, padding_len));
    let checksum = vmess_fnv1a(&payload);
    payload.extend_from_slice(&checksum.to_be_bytes());
    let cmd_key = vmess_cmd_key(&user_id);
    Ok((
        seal_vmess_aead_header(cmd_key, &payload)?,
        request_body_key,
        request_body_iv,
        response_header,
    ))
}

fn read_vmess_response_header(
    stream: &mut RemoteStream,
    response_header: u8,
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
) -> io::Result<()> {
    let mut encrypted_length = [0u8; 18];
    stream.read_exact(&mut encrypted_length)?;
    let length_key = vmess_kdf16(response_body_key, &[b"AEAD Resp Header Len Key"]);
    let length_nonce = vmess_kdf(response_body_iv, &[b"AEAD Resp Header Len IV"]);
    let length = vmess_open(
        VmessSecurity::Aes128Gcm,
        &length_key,
        length_nonce[..12].try_into().expect("KDF output length"),
        &encrypted_length,
    )?;
    if length.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid VMess response header length",
        ));
    }
    let payload_length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let mut encrypted_payload = vec![0u8; payload_length + VMESS_TAG_LEN];
    stream.read_exact(&mut encrypted_payload)?;
    let payload_key = vmess_kdf16(response_body_key, &[b"AEAD Resp Header Key"]);
    let payload_nonce = vmess_kdf(response_body_iv, &[b"AEAD Resp Header IV"]);
    let payload = vmess_open(
        VmessSecurity::Aes128Gcm,
        &payload_key,
        payload_nonce[..12].try_into().expect("KDF output length"),
        &encrypted_payload,
    )?;
    if payload.first().copied() != Some(response_header) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected VMess response header",
        ));
    }
    Ok(())
}

fn seal_vmess_aead_header(cmd_key: [u8; 16], payload: &[u8]) -> io::Result<Vec<u8>> {
    let auth_id = vmess_auth_id(&cmd_key)?;
    let mut nonce = [0u8; 8];
    rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| io::Error::other("failed to generate VMess header nonce"))?;
    let length = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VMess request header is too large",
        )
    })?;
    let length_key = vmess_kdf16(
        &cmd_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let length_nonce = vmess_kdf(
        &cmd_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let encrypted_length = vmess_seal(
        VmessSecurity::Aes128Gcm,
        &length_key,
        length_nonce[..12].try_into().expect("KDF output length"),
        &length.to_be_bytes(),
    )?;
    let payload_key = vmess_kdf16(&cmd_key, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let payload_nonce = vmess_kdf(&cmd_key, &[b"VMess Header AEAD Nonce", &auth_id, &nonce]);
    let encrypted_payload = vmess_seal_with_aad(
        &payload_key,
        payload_nonce[..12].try_into().expect("KDF output length"),
        &auth_id,
        payload,
    )?;
    let mut output = Vec::with_capacity(16 + 18 + 8 + encrypted_payload.len());
    output.extend_from_slice(&auth_id);
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted_payload);
    Ok(output)
}

fn vmess_auth_id(cmd_key: &[u8; 16]) -> io::Result<[u8; 16]> {
    let mut plain = [0u8; 16];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    rand::SystemRandom::new()
        .fill(&mut plain[8..12])
        .map_err(|_| io::Error::other("failed to generate VMess auth id"))?;
    let mut checksum = Crc32Hasher::new();
    checksum.update(&plain[..12]);
    plain[12..].copy_from_slice(&checksum.finalize().to_be_bytes());
    let key = vmess_kdf16(cmd_key, &[b"AES Auth ID Encryption"]);
    let cipher =
        Aes128::new_from_slice(&key).map_err(|_| io::Error::other("invalid VMess auth id key"))?;
    let mut block = Block::<Aes128>::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

fn vmess_cmd_key(user_id: &[u8; 16]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(user_id);
    digest.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    digest.finalize().into()
}

fn vmess_response_keys(
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    let key = sha2::Sha256::digest(request_body_key);
    let iv = sha2::Sha256::digest(request_body_iv);
    (
        key[..16].try_into().expect("SHA-256 output length"),
        iv[..16].try_into().expect("SHA-256 output length"),
    )
}

fn vmess_chunk_nonce(iv: &[u8; 16], sequence: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv[..12]);
    nonce[..2].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn vmess_kdf16(key: &[u8; 16], path: &[&[u8]]) -> [u8; 16] {
    vmess_kdf(key, path)[..16]
        .try_into()
        .expect("KDF output length")
}

fn vmess_kdf(key: &[u8; 16], path: &[&[u8]]) -> [u8; 32] {
    vmess_nested_hmac(path, key)
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, value)
        .as_ref()
        .try_into()
        .expect("HMAC output length")
}

fn vmess_nested_hmac(path: &[&[u8]], value: &[u8]) -> [u8; 32] {
    let Some((key, parent)) = path.split_last() else {
        return hmac_sha256(b"VMess AEAD KDF", value);
    };
    let mut normalized_key = key.to_vec();
    if normalized_key.len() > 64 {
        normalized_key = vmess_nested_hmac(parent, &normalized_key).to_vec();
    }
    normalized_key.resize(64, 0);
    let mut inner = Vec::with_capacity(64 + value.len());
    let mut outer = Vec::with_capacity(64 + 32);
    for byte in &mut normalized_key {
        *byte ^= 0x36;
    }
    inner.extend_from_slice(&normalized_key);
    inner.extend_from_slice(value);
    let inner_hash = vmess_nested_hmac(parent, &inner);
    for byte in &mut normalized_key {
        *byte ^= 0x36 ^ 0x5c;
    }
    outer.extend_from_slice(&normalized_key);
    outer.extend_from_slice(&inner_hash);
    vmess_nested_hmac(parent, &outer)
}

fn vmess_fnv1a(value: &[u8]) -> u32 {
    value.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn vmess_seal(
    security: VmessSecurity,
    key: &[u8; 16],
    nonce: [u8; 12],
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    vmess_seal_with_aad_key(security, key, nonce, &[], plaintext)
}

fn vmess_seal_with_aad(
    key: &[u8; 16],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    vmess_seal_with_aad_key(VmessSecurity::Aes128Gcm, key, nonce, aad, plaintext)
}

fn vmess_seal_with_aad_key(
    security: VmessSecurity,
    key: &[u8; 16],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    if security == VmessSecurity::None {
        // Xray's SecurityType_NONE uses its NoOpAuthenticator: the request
        // header stays authenticated, the body is passed through unencrypted.
        return Ok(plaintext.to_vec());
    }
    let (algorithm, key_bytes) = match security {
        VmessSecurity::Auto | VmessSecurity::Aes128Gcm => (&aead::AES_128_GCM, key.to_vec()),
        VmessSecurity::ChaCha20Poly1305 => {
            let first = md5_bytes(key);
            let second = md5_bytes(&first);
            let mut key_bytes = Vec::with_capacity(32);
            key_bytes.extend_from_slice(&first);
            key_bytes.extend_from_slice(&second);
            (&aead::CHACHA20_POLY1305, key_bytes)
        }
        VmessSecurity::None => unreachable!("VMess none is handled before key selection"),
    };
    let unbound = aead::UnboundKey::new(algorithm, &key_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid VMess AEAD key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let mut output = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut output)
        .map_err(|_| io::Error::other("VMess AEAD sealing failed"))?;
    Ok(output)
}

fn vmess_open(
    security: VmessSecurity,
    key: &[u8; 16],
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    if security == VmessSecurity::None {
        return Ok(ciphertext.to_vec());
    }
    let (algorithm, key_bytes) = match security {
        VmessSecurity::Auto | VmessSecurity::Aes128Gcm => (&aead::AES_128_GCM, key.to_vec()),
        VmessSecurity::ChaCha20Poly1305 => {
            let first = md5_bytes(key);
            let second = md5_bytes(&first);
            let mut key_bytes = Vec::with_capacity(32);
            key_bytes.extend_from_slice(&first);
            key_bytes.extend_from_slice(&second);
            (&aead::CHACHA20_POLY1305, key_bytes)
        }
        VmessSecurity::None => unreachable!("VMess none is handled before key selection"),
    };
    let unbound = aead::UnboundKey::new(algorithm, &key_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid VMess AEAD key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let mut output = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, aead::Aad::empty(), &mut output)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess AEAD authentication failed",
            )
        })?;
    Ok(plaintext.to_vec())
}

fn md5_bytes(value: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(value);
    digest.finalize().into()
}

impl Read for XhttpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if !self.response_headers_read {
            self.read_response_headers()?;
        }
        if self.response_closed {
            return Ok(0);
        }
        if self.response_chunked {
            if self.response_chunk_remaining == 0 {
                let size = self.read_chunk_size()?;
                if size == 0 {
                    loop {
                        if read_crlf_line(&mut self.stream, 32 * 1024)?.is_empty() {
                            break;
                        }
                    }
                    self.response_closed = true;
                    return Ok(0);
                }
                self.response_chunk_remaining = size;
            }
            let length = buffer.len().min(self.response_chunk_remaining);
            self.stream.read_exact(&mut buffer[..length])?;
            self.response_chunk_remaining -= length;
            if self.response_chunk_remaining == 0 {
                let mut separator = [0u8; 2];
                self.stream.read_exact(&mut separator)?;
                if separator != *b"\r\n" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid XHTTP chunk terminator",
                    ));
                }
            }
            return Ok(length);
        }
        if self.response_chunk_remaining == 0 {
            self.response_closed = true;
            return Ok(0);
        }
        let length = buffer.len().min(self.response_chunk_remaining);
        let read = self.stream.read(&mut buffer[..length])?;
        self.response_chunk_remaining -= read;
        if read == 0 {
            self.response_closed = true;
        }
        Ok(read)
    }
}

impl Write for XhttpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.request_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP request body is closed",
            ));
        }
        write!(self.stream, "{:X}\r\n", buffer.len())?;
        self.stream.write_all(buffer)?;
        self.stream.write_all(b"\r\n")?;
        self.stream.flush()?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn read_crlf_line<R: Read>(stream: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    while line.len() < limit {
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "XHTTP line exceeds limit",
    ))
}

fn trim_ascii_bytes(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn parse_decimal_bytes(value: &[u8]) -> Option<usize> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0usize, |value, byte| {
        value
            .checked_mul(10)?
            .checked_add(usize::from(byte.checked_sub(b'0')?))
    })
}

fn parse_hex_number(value: &[u8]) -> Option<usize> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0usize, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(usize::from(digit))
    })
}

fn websocket_io_error(error: tungstenite::Error) -> io::Error {
    match error {
        tungstenite::Error::Io(error) => error,
        error => io::Error::other(error.to_string()),
    }
}

impl XrayCore {
    /// Start the local core and return the endpoint for browser traffic.
    ///
    /// # Errors
    ///
    /// Returns [`XrayError::Io`] when the loopback listener cannot be opened.
    pub fn start(config: XrayConfig) -> Result<Self, XrayError> {
        Self::start_inner(config, None)
    }

    /// Start the core with an explicit in-process Loopback routing connector.
    ///
    /// The connector receives the configured inbound tag and the original
    /// target. It is the boundary where Nomad's routing graph selects the
    /// next outbound without opening another local SOCKS listener.
    ///
    /// # Errors
    ///
    /// Returns [`XrayError::InvalidConfig`] when the config is not compatible
    /// with the embedded core, or [`XrayError::Io`] when the local listener
    /// cannot be opened.
    pub fn start_with_loopback(
        config: XrayConfig,
        connector: XrayLoopbackConnector,
    ) -> Result<Self, XrayError> {
        Self::start_inner(config, Some(connector))
    }

    fn start_inner(
        config: XrayConfig,
        loopback: Option<XrayLoopbackConnector>,
    ) -> Result<Self, XrayError> {
        config.validate_runtime(loopback.is_some())?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(XrayError::Io)?;
        listener.set_nonblocking(true).map_err(XrayError::Io)?;
        let port = listener.local_addr().map_err(XrayError::Io)?.port();
        let endpoint = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", port);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let config = Arc::new(config);
        let accept_thread = thread::Builder::new()
            .name("nomad-xray-listener".to_owned())
            .spawn(move || accept_loop(listener, config, thread_stop, loopback))
            .map_err(XrayError::Io)?;
        Ok(Self {
            endpoint,
            stop,
            accept_thread: Some(accept_thread),
        })
    }

    /// Return the loopback endpoint consumed by Servo.
    #[must_use]
    pub const fn endpoint(&self) -> &ProxyEndpoint {
        &self.endpoint
    }
}

impl Drop for XrayCore {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn accept_loop(
    listener: TcpListener,
    config: Arc<XrayConfig>,
    stop: Arc<AtomicBool>,
    loopback: Option<XrayLoopbackConnector>,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let config = Arc::clone(&config);
                let loopback = loopback.clone();
                let _ = thread::Builder::new()
                    .name("nomad-xray-connection".to_owned())
                    .spawn(move || handle_connection(stream, &config, loopback.as_ref()));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

#[derive(Clone, Debug)]
struct Target {
    host: String,
    port: u16,
}

fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    connect_tcp_with_domain_strategy(host, port, FreedomDomainStrategy::AsIs, None)
}

const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;

/// Build a single-question DNS query packet for `hostname`.
fn dns_build_query(hostname: &str, qtype: u16) -> io::Result<Vec<u8>> {
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

/// Skip a (possibly compressed) DNS name starting at `offset` within
/// `packet`, returning the offset just past it. `limit` guards pointer loops.
fn dns_skip_name(packet: &[u8], offset: usize, limit: usize) -> io::Result<usize> {
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

/// Parse the answers in a DNS response and return every IP matching `qtype`.
fn dns_parse_addresses(packet: &[u8], qtype: u16) -> io::Result<Vec<IpAddr>> {
    if packet.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DNS response",
        ));
    }
    let answer_count = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    let mut offset = 12usize;
    let mut limit = packet.len() * 2;
    // Skip the question section.
    offset = dns_skip_name(packet, offset, limit)?;
    if offset + 4 > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DNS question",
        ));
    }
    offset += 4;
    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        offset = dns_skip_name(packet, offset, limit)?;
        limit = packet.len() * 2;
        if offset + 10 > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS answer",
            ));
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let data_length = usize::from(u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]));
        offset += 10;
        if offset + data_length > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS RDATA",
            ));
        }
        if record_type == qtype {
            match qtype {
                DNS_QTYPE_A if data_length == 4 => {
                    addresses.push(IpAddr::V4(Ipv4Addr::new(
                        packet[offset],
                        packet[offset + 1],
                        packet[offset + 2],
                        packet[offset + 3],
                    )));
                }
                DNS_QTYPE_AAAA if data_length == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[offset..offset + 16]);
                    addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset += data_length;
    }
    Ok(addresses)
}

/// Resolve `hostname` through the Xray DNS outbound's server, returning the
/// addresses of `qtype`. This routes the DNS packet through the configured
/// server instead of the local system resolver.
fn dns_resolve(resolver: &XrayDnsResolver, hostname: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    if hostname.parse::<IpAddr>().is_ok() {
        return Ok(vec![hostname
            .parse::<IpAddr>()
            .expect("hostname already parsed")]);
    }
    let query = dns_build_query(hostname, qtype)?;
    let response = resolver.query(&query)?;
    if response.len() < 12 || response[2] & 0x80 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS server did not return a valid response",
        ));
    }
    dns_parse_addresses(&response, qtype)
}

fn connect_tcp_with_domain_strategy(
    host: &str,
    port: u16,
    strategy: FreedomDomainStrategy,
    resolver: Option<&XrayDnsResolver>,
) -> io::Result<TcpStream> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    // With an explicit DNS outbound and a `UseIP`-family strategy, resolve the
    // hostname through the configured DNS server (packet routing) rather than
    // the system resolver.
    let mut addresses: Vec<SocketAddr> = Vec::new();
    if let Some(resolver) = resolver.filter(|_| strategy != FreedomDomainStrategy::AsIs) {
        let mut resolved_v4: Vec<IpAddr> = Vec::new();
        let mut resolved_v6: Vec<IpAddr> = Vec::new();
        match strategy {
            FreedomDomainStrategy::UseIpv4 | FreedomDomainStrategy::UseIp => {
                resolved_v4 = dns_resolve(resolver, host, DNS_QTYPE_A)?;
            }
            _ => {}
        }
        match strategy {
            FreedomDomainStrategy::UseIpv6 | FreedomDomainStrategy::UseIp => {
                resolved_v6 = dns_resolve(resolver, host, DNS_QTYPE_AAAA)?;
            }
            _ => {}
        }
        for address in resolved_v4.into_iter().chain(resolved_v6) {
            addresses.push(SocketAddr::new(address, port));
        }
    }
    if addresses.is_empty() {
        addresses = (host, port).to_socket_addrs()?.collect();
    }
    let mut last_error = None;
    for address in &addresses {
        if matches!(strategy, FreedomDomainStrategy::UseIpv4) && !address.is_ipv4() {
            continue;
        }
        if matches!(strategy, FreedomDomainStrategy::UseIpv6) && !address.is_ipv6() {
            continue;
        }
        match TcpStream::connect_timeout(address, UPSTREAM_CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "upstream server has no resolved address",
        )
    }))
}

fn validate_target(target: &Target) -> io::Result<()> {
    if target.host.is_empty() || target.host.len() > MAX_TARGET_HOST_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 target hostname length is invalid",
        ));
    }
    if target.port == 0
        || target
            .host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 target contains invalid request data",
        ));
    }
    Ok(())
}

fn target_authority(target: &Target) -> io::Result<String> {
    validate_target(target)?;
    if target.host.contains(':') {
        Ok(format!("[{}]:{}", target.host, target.port))
    } else {
        Ok(format!("{}:{}", target.host, target.port))
    }
}

fn handle_connection(
    mut client: TcpStream,
    config: &XrayConfig,
    loopback: Option<&XrayLoopbackConnector>,
) {
    if client.set_nonblocking(false).is_err() {
        return;
    }
    let Ok(target) = read_socks_request(&mut client) else {
        let _ = write_socks_reply(&mut client, 0x08);
        return;
    };
    if let XrayOutbound::Blackhole { response } = config.outbound {
        match response {
            BlackholeResponse::None => {
                let _ = write_socks_reply(&mut client, 0x02);
            }
            BlackholeResponse::Http => {
                if write_socks_reply(&mut client, 0x00).is_ok() {
                    let _ = client.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        }
        return;
    }
    let Ok(remote) = connect_outbound(config, &target, loopback) else {
        let _ = write_socks_reply(&mut client, 0x01);
        return;
    };
    if write_socks_reply(&mut client, 0x00).is_err() {
        return;
    }
    relay(client, remote);
}

fn read_socks_request(stream: &mut TcpStream) -> io::Result<Target> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 version"));
    }
    let mut methods = vec![0u8; usize::from(header[1])];
    stream.read_exact(&mut methods)?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff])?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 auth",
        ));
    }
    stream.write_all(&[0x05, 0x00])?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request)?;
    if request[0] != 0x05 || request[1] != 0x01 {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "SOCKS5 command"));
    }
    let host = match request[3] {
        0x01 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes)?;
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            let mut bytes = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut bytes)?;
            String::from_utf8(bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 hostname"))?
        }
        0x04 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes)?;
            std::net::Ipv6Addr::from(bytes).to_string()
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 address")),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let target = Target {
        host,
        port: u16::from_be_bytes(port),
    };
    validate_target(&target)?;
    Ok(target)
}

fn write_socks_reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

fn connect_outbound(
    config: &XrayConfig,
    target: &Target,
    loopback: Option<&XrayLoopbackConnector>,
) -> io::Result<RemoteStream> {
    validate_target(target)?;
    match &config.outbound {
        XrayOutbound::Blackhole { .. } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Blackhole is handled at the local SOCKS boundary",
        )),
        XrayOutbound::Dns(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DNS outbound requires DNS packet routing",
        )),
        XrayOutbound::Loopback(loopback_config) => {
            let connector = loopback.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Loopback requires an in-process routing graph",
                )
            })?;
            connector(&loopback_config.inbound_tag, &target.host, target.port)
                .map(RemoteStream::Tcp)
        }
        XrayOutbound::Freedom(freedom) => {
            let resolver = config
                .dns_resolver_config()
                .cloned()
                .map(XrayDnsResolver::new);
            connect_tcp_with_domain_strategy(
                &target.host,
                target.port,
                freedom.domain_strategy,
                resolver.as_ref(),
            )
            .map(RemoteStream::Tcp)
        }
        XrayOutbound::Vmess(vmess) => connect_vmess(
            vmess,
            config.transport,
            config.server_name(),
            config.http_settings(),
            config.grpc_settings(),
            config.xhttp_settings(),
            config.xhttp_options(),
            config.mkcp_settings(),
            target,
        ),
        XrayOutbound::Hysteria(hysteria) => HysteriaStream::connect(
            &hysteria.server,
            hysteria.port,
            config.server_name().unwrap_or(&hysteria.server),
            config.hysteria_settings(),
            target,
        )
        .map(|stream| RemoteStream::Hysteria(Box::new(stream))),
        XrayOutbound::WireGuard(wireguard) => {
            WireGuardStream::connect(wireguard, &target.host, target.port)
                .map(|stream| RemoteStream::WireGuard(Box::new(stream)))
        }
        XrayOutbound::Socks5(endpoint) => {
            let mut stream = connect_tcp(endpoint.host(), endpoint.port())?;
            connect_upstream_socks5(&mut stream, target)?;
            Ok(RemoteStream::Tcp(stream))
        }
        XrayOutbound::HttpConnect(endpoint) => {
            let mut stream = connect_tcp(endpoint.host(), endpoint.port())?;
            connect_upstream_http(&mut stream, target)?;
            Ok(RemoteStream::Tcp(stream))
        }
        XrayOutbound::Shadowsocks(shadowsocks) => connect_shadowsocks(shadowsocks, target),
        XrayOutbound::Vless(vless) => connect_vless(
            vless,
            config.transport,
            config.server_name(),
            config.http_settings(),
            config.grpc_settings(),
            config.xhttp_settings(),
            config.xhttp_options(),
            config.mkcp_settings(),
            config.reality_settings(),
            target,
        ),
        XrayOutbound::Trojan(trojan) => connect_trojan(
            trojan,
            config.transport,
            config.server_name(),
            config.http_settings(),
            config.grpc_settings(),
            config.xhttp_settings(),
            config.xhttp_options(),
            config.mkcp_settings(),
            target,
        ),
    }
}

fn connect_shadowsocks(config: &ShadowsocksConfig, target: &Target) -> io::Result<RemoteStream> {
    let stream = connect_tcp(&config.server, config.port)?;
    let mut address = Vec::with_capacity(target.host.len() + 18);
    append_shadowsocks_address(&mut address, &target.host)?;
    address.extend_from_slice(&target.port.to_be_bytes());
    if config.method.is_legacy() {
        let mut stream = ShadowsocksStream::new(stream, config.method, &config.password)?;
        stream.write_all(&address)?;
        stream.flush()?;
        Ok(RemoteStream::Shadowsocks(Box::new(stream)))
    } else {
        let mut stream =
            Shadowsocks2022Stream::new(stream, config.method, &config.password, address)?;
        stream.start()?;
        Ok(RemoteStream::Shadowsocks2022(Box::new(stream)))
    }
}

fn append_shadowsocks_address(output: &mut Vec<u8>, host: &str) -> io::Result<()> {
    append_address(output, host, 4, 3)
}

const VISION_COMMAND_CONTINUE: u8 = 0x00;
const VISION_COMMAND_DIRECT: u8 = 0x02;
const VISION_HEADER_BASE: usize = 1 + 2 + 2;
const VISION_LONG_PADDING_THRESHOLD: usize = 900;

/// Wrap `content` in an XTLS Vision padding frame. The frame is
/// `[user-uuid (16, first frame only)] [command (1)] [content-len (2 BE)]
/// [padding-len (2 BE)] [content] [random padding]`. The padding lengths
/// mirror Xray's `ApplyPaddingFromPool` exactly. The RNG is injected for
/// deterministic wire-conformance tests.
fn vision_pad(
    content: &[u8],
    command: u8,
    user_uuid: Option<&[u8; 16]>,
    long_padding: bool,
    mut next: impl FnMut(u32) -> u32,
) -> io::Result<Vec<u8>> {
    let content_len = content.len();
    let padding_len = if content_len < VISION_LONG_PADDING_THRESHOLD && long_padding {
        (next(500) as usize) + VISION_LONG_PADDING_THRESHOLD - content_len
    } else {
        next(256) as usize
    };
    let header_len = VISION_HEADER_BASE + usize::from(user_uuid.is_some()) * 16;
    let mut frame = Vec::with_capacity(header_len + content_len + padding_len);
    if let Some(uuid) = user_uuid {
        frame.extend_from_slice(uuid);
    }
    frame.push(command);
    frame.extend_from_slice(
        &u16::try_from(content_len)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "VLESS vision frame too large")
            })?
            .to_be_bytes(),
    );
    frame.extend_from_slice(
        &u16::try_from(padding_len)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS vision padding too large",
                )
            })?
            .to_be_bytes(),
    );
    frame.extend_from_slice(content);
    let mut random = [0u8; 256];
    let system_random = rand::SystemRandom::new();
    let mut remaining = padding_len;
    while remaining > 0 {
        let take = remaining.min(random.len());
        system_random
            .fill(&mut random[..take])
            .map_err(|_| io::Error::other("failed to generate VLESS vision padding"))?;
        frame.extend_from_slice(&random[..take]);
        remaining -= take;
    }
    Ok(frame)
}

/// A VLESS `xtls-rprx-vision` padded stream. Every write is wrapped in a
/// Continue padding frame (the first write carries the authenticated user
/// UUID); every read strips the padding and returns the content. Nomad does
/// not perform Xray's Go-TLS splice passthrough optimization, but the padding
/// wire format is identical to Xray's vision implementation.
struct VlessVisionStream {
    inner: RemoteStream,
    user_uuid: [u8; 16],
    sent_first: bool,
    raw_buffer: Vec<u8>,
    content_buffer: Vec<u8>,
    first_frame: bool,
}

impl VlessVisionStream {
    fn new(inner: RemoteStream, user_uuid: [u8; 16]) -> Self {
        Self {
            inner,
            user_uuid,
            sent_first: false,
            raw_buffer: Vec::new(),
            content_buffer: Vec::new(),
            first_frame: true,
        }
    }

    fn write_frame(&mut self, content: &[u8], command: u8) -> io::Result<()> {
        let uuid = if self.sent_first {
            None
        } else {
            Some(&self.user_uuid)
        };
        let frame = vision_pad(content, command, uuid, true, |bound| {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut bytes = [0u8; 4];
            let _ = SystemRandom::new().fill(&mut bytes);
            u32::from_be_bytes(bytes) % bound
        })?;
        self.sent_first = true;
        self.inner.write_all(&frame)?;
        self.inner.flush()
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    fn fill_raw_buffer(&mut self) -> io::Result<bool> {
        let mut buffer = [0u8; 16 * 1024];
        match self.inner.read(&mut buffer) {
            Ok(0) => Ok(false),
            Ok(length) => {
                self.raw_buffer.extend_from_slice(&buffer[..length]);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Parse and remove one padding frame from `raw_buffer`, returning its
    /// content. Returns `Ok(None)` at clean EOF between frames.
    fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let header_len = VISION_HEADER_BASE + usize::from(self.first_frame) * 16;
            if self.raw_buffer.len() < header_len {
                if !self.fill_raw_buffer()? {
                    return Ok(None);
                }
                continue;
            }
            let mut offset = 0;
            if self.first_frame {
                offset += 16;
                self.first_frame = false;
            }
            let command = self.raw_buffer[offset];
            let content_len = usize::from(u16::from_be_bytes([
                self.raw_buffer[offset + 1],
                self.raw_buffer[offset + 2],
            ]));
            let padding_len = usize::from(u16::from_be_bytes([
                self.raw_buffer[offset + 3],
                self.raw_buffer[offset + 4],
            ]));
            let frame_len = offset
                .checked_add(5)
                .and_then(|value| value.checked_add(content_len))
                .and_then(|value| value.checked_add(padding_len))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "VLESS vision frame overflow")
                })?;
            if self.raw_buffer.len() < frame_len {
                if !self.fill_raw_buffer()? {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated VLESS vision frame",
                    ));
                }
                continue;
            }
            let content = self.raw_buffer[offset + 5..offset + 5 + content_len].to_vec();
            self.raw_buffer.drain(..frame_len);
            if command == VISION_COMMAND_DIRECT {
                // Xray switches to raw passthrough after a Direct command; Nomad
                // keeps decoding the (identical) framing, so no state change.
            }
            return Ok(Some(content));
        }
    }
}

impl Read for VlessVisionStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.content_buffer.is_empty() {
            match self.read_frame()? {
                Some(content) => self.content_buffer.extend_from_slice(&content),
                None => return Ok(0),
            }
        }
        let length = buffer.len().min(self.content_buffer.len());
        buffer[..length].copy_from_slice(&self.content_buffer[..length]);
        self.content_buffer.drain(..length);
        Ok(length)
    }
}

impl Write for VlessVisionStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.write_frame(buffer, VISION_COMMAND_CONTINUE)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[allow(clippy::too_many_arguments)]
fn connect_vless(
    config: &VlessConfig,
    transport: XrayTransportConfig,
    server_name: Option<&str>,
    http_settings: &XrayHttpSettings,
    grpc_settings: &XrayGrpcSettings,
    xhttp_settings: &XrayXhttpSettings,
    xhttp_options: &XhttpRequestOptions,
    mkcp_settings: &XrayMkcpSettings,
    reality_settings: Option<&XrayRealitySettings>,
    target: &Target,
) -> io::Result<RemoteStream> {
    if !matches!(
        transport.method,
        XrayTransport::Raw
            | XrayTransport::Xhttp
            | XrayTransport::Mkcp
            | XrayTransport::HttpUpgrade
            | XrayTransport::WebSocket
            | XrayTransport::Grpc
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VLESS transport handler is not available for this transport",
        ));
    }
    if config.flow.is_some()
        && !matches!(
            config.flow,
            Some(VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp443)
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VLESS flow handler is not available for this outbound",
        ));
    }
    if transport.security == XraySecurity::Reality
        && !matches!(transport.method, XrayTransport::Raw | XrayTransport::Xhttp)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VLESS REALITY is currently supported only over RAW or XHTTP transport",
        ));
    }
    let mut stream = connect_transport(
        &config.server,
        config.port,
        transport,
        server_name,
        http_settings,
        grpc_settings,
        xhttp_settings,
        xhttp_options,
        mkcp_settings,
        reality_settings,
    )?;
    write_vless_request(&mut stream, config.user_id, target)?;
    read_vless_response(&mut stream)?;
    if matches!(
        config.flow,
        Some(VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp443)
    ) {
        // XTLS Vision pads the post-handshake data stream with length
        // randomization frames. The first frame carries the user UUID.
        return Ok(RemoteStream::VlessVision(Box::new(VlessVisionStream::new(
            stream,
            config.user_id,
        ))));
    }
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
fn connect_trojan(
    config: &TrojanConfig,
    transport: XrayTransportConfig,
    server_name: Option<&str>,
    http_settings: &XrayHttpSettings,
    grpc_settings: &XrayGrpcSettings,
    xhttp_settings: &XrayXhttpSettings,
    xhttp_options: &XhttpRequestOptions,
    mkcp_settings: &XrayMkcpSettings,
    target: &Target,
) -> io::Result<RemoteStream> {
    let mut stream = connect_transport(
        &config.server,
        config.port,
        transport,
        server_name,
        http_settings,
        grpc_settings,
        xhttp_settings,
        xhttp_options,
        mkcp_settings,
        None,
    )?;
    write_trojan_request(&mut stream, &config.password, target)?;
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
fn connect_transport(
    server: &str,
    port: u16,
    transport: XrayTransportConfig,
    server_name: Option<&str>,
    http_settings: &XrayHttpSettings,
    grpc_settings: &XrayGrpcSettings,
    xhttp_settings: &XrayXhttpSettings,
    xhttp_options: &XhttpRequestOptions,
    mkcp_settings: &XrayMkcpSettings,
    reality_settings: Option<&XrayRealitySettings>,
) -> io::Result<RemoteStream> {
    if !matches!(
        transport.method,
        XrayTransport::Raw
            | XrayTransport::Xhttp
            | XrayTransport::Mkcp
            | XrayTransport::HttpUpgrade
            | XrayTransport::WebSocket
            | XrayTransport::Grpc
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Xray transport handler is not available for this transport",
        ));
    }
    if transport.security == XraySecurity::Reality {
        if !matches!(transport.method, XrayTransport::Raw | XrayTransport::Xhttp) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "REALITY is currently supported only over RAW or XHTTP transport",
            ));
        }
        let settings = reality_settings.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "REALITY settings are required for a REALITY transport",
            )
        })?;
        if transport.method == XrayTransport::Raw {
            return Ok(RemoteStream::Reality(Box::new(RealityStream::connect(
                server,
                port,
                server_name.unwrap_or(server),
                settings,
            )?)));
        }
    }
    if transport.method == XrayTransport::Grpc {
        return Ok(RemoteStream::Grpc(Box::new(GrpcStream::connect(
            server,
            port,
            transport.security,
            server_name.unwrap_or(server),
            grpc_settings,
        )?)));
    }
    if transport.method == XrayTransport::Xhttp {
        return connect_xhttp_transport(
            server,
            port,
            transport.security,
            server_name.unwrap_or(server),
            xhttp_settings,
            xhttp_options,
            reality_settings,
        );
    }
    if transport.method == XrayTransport::Mkcp {
        if transport.security != XraySecurity::None {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mKCP TLS/REALITY security is not implemented by the embedded core",
            ));
        }
        return Ok(RemoteStream::Mkcp(Box::new(MkcpStream::connect(
            server,
            port,
            mkcp_settings,
        )?)));
    }
    let stream = connect_tcp(server, port)?;
    let mut stream = match transport.security {
        XraySecurity::None => RemoteStream::Tcp(stream),
        XraySecurity::Tls => RemoteStream::Tls(Box::new(connect_tls(
            stream,
            server_name.unwrap_or(server),
        )?)),
        XraySecurity::Reality => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "REALITY client handler is not available yet",
            ));
        }
    };
    if transport.method == XrayTransport::HttpUpgrade {
        perform_http_upgrade(&mut stream, http_settings, server_name.unwrap_or(server))?;
    } else if transport.method == XrayTransport::WebSocket {
        stream = RemoteStream::WebSocket(Box::new(connect_websocket(
            stream,
            http_settings,
            server_name.unwrap_or(server),
        )?));
    }
    Ok(stream)
}

fn connect_xhttp_transport(
    server: &str,
    port: u16,
    security: XraySecurity,
    server_name: &str,
    settings: &XrayXhttpSettings,
    options: &XhttpRequestOptions,
    reality_settings: Option<&XrayRealitySettings>,
) -> io::Result<RemoteStream> {
    let mode = if settings.mode.eq_ignore_ascii_case("auto") {
        if security == XraySecurity::Reality {
            "stream-one"
        } else {
            "packet-up"
        }
    } else {
        settings.mode.as_str()
    };
    match mode {
        "stream-up" => Ok(RemoteStream::XhttpUp(Box::new(XhttpStreamUp::connect(
            server,
            port,
            security,
            server_name,
            settings,
            options,
            reality_settings,
        )?))),
        "packet-up" => Ok(RemoteStream::XhttpPacketUp(Box::new(
            XhttpPacketUpStream::connect(
                server,
                port,
                security,
                server_name,
                settings,
                options,
                reality_settings,
            )?,
        ))),
        _ => Ok(RemoteStream::Xhttp(Box::new(XhttpStream::connect(
            server,
            port,
            security,
            server_name,
            settings,
            options,
            reality_settings,
        )?))),
    }
}

fn connect_tls(
    stream: TcpStream,
    server_name: &str,
) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(server_name.to_owned()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TLS server name: {error}"),
        )
    })?;
    let connection = ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error))?;
    Ok(StreamOwned::new(connection, stream))
}

fn perform_http_upgrade(
    stream: &mut RemoteStream,
    settings: &XrayHttpSettings,
    fallback_host: &str,
) -> io::Result<()> {
    let host = settings.host.as_deref().unwrap_or(fallback_host);
    if !authority_is_safe(host) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTPUpgrade host is invalid",
        ));
    }
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        settings.path, host
    )?;
    for (name, value) in &settings.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;

    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while response.len() < 16 * 1024 {
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let first_line = response
        .split(|value| *value == b'\n')
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTPUpgrade response"))?;
    if !first_line.starts_with(b"HTTP/1.1 101") && !first_line.starts_with(b"HTTP/1.0 101") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "HTTPUpgrade rejected",
        ));
    }
    Ok(())
}

fn connect_websocket(
    stream: RemoteStream,
    settings: &XrayHttpSettings,
    fallback_host: &str,
) -> io::Result<WebSocketStream> {
    let host = settings.host.as_deref().unwrap_or(fallback_host);
    if !authority_is_safe(host) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WebSocket host is invalid",
        ));
    }
    let mut request = tungstenite::http::Request::builder()
        .method("GET")
        .uri(&settings.path)
        .header("Host", host)
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    for (name, value) in &settings.headers {
        let name = tungstenite::http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let value = tungstenite::http::header::HeaderValue::from_str(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        request.headers_mut().insert(name, value);
    }
    let (socket, _) = client(request, Box::new(stream))
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    Ok(WebSocketStream {
        socket,
        read_buffer: Vec::new(),
    })
}

fn write_vless_request<S: Write>(
    stream: &mut S,
    user_id: [u8; 16],
    target: &Target,
) -> io::Result<()> {
    let mut request = Vec::with_capacity(64 + target.host.len());
    request.push(0);
    request.extend_from_slice(&user_id);
    request.push(0);
    request.push(1);
    request.extend_from_slice(&target.port.to_be_bytes());
    append_vless_address(&mut request, &target.host)?;
    stream.write_all(&request)
}

fn append_vless_address(output: &mut Vec<u8>, host: &str) -> io::Result<()> {
    append_address(output, host, 3, 2)
}

fn append_trojan_address(output: &mut Vec<u8>, host: &str) -> io::Result<()> {
    append_address(output, host, 4, 3)
}

fn append_address(
    output: &mut Vec<u8>,
    host: &str,
    ipv6_type: u8,
    domain_type: u8,
) -> io::Result<()> {
    if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        output.push(1);
        output.extend_from_slice(&address.octets());
    } else if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
        output.push(ipv6_type);
        output.extend_from_slice(&address.octets());
    } else {
        let host = host.as_bytes();
        let length = u8::try_from(host.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hostname too long"))?;
        output.push(domain_type);
        output.push(length);
        output.extend_from_slice(host);
    }
    Ok(())
}

fn write_trojan_request<S: Write>(
    stream: &mut S,
    password: &str,
    target: &Target,
) -> io::Result<()> {
    let password_hash = Sha224::digest(password.as_bytes());
    write!(stream, "{password_hash:x}\r\n")?;
    stream.write_all(&[1])?;
    let mut address = Vec::with_capacity(2 + target.host.len() + 18);
    append_trojan_address(&mut address, &target.host)?;
    address.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&address)?;
    stream.write_all(b"\r\n")
}

fn read_vless_response<S: Read>(stream: &mut S) -> io::Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VLESS response version",
        ));
    }
    let mut addons = vec![0u8; usize::from(header[1])];
    stream.read_exact(&mut addons)?;
    Ok(())
}

fn connect_upstream_socks5(stream: &mut TcpStream, target: &Target) -> io::Result<()> {
    validate_target(target)?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream SOCKS5 auth",
        ));
    }
    let bytes = target.host.as_bytes();
    let length = u8::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hostname too long"))?;
    let mut request = vec![0x05, 0x01, 0x00, 0x03, length];
    request.extend_from_slice(bytes);
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request)?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response)?;
    if response[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "upstream SOCKS5 connect",
        ));
    }
    let address_length = match response[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            usize::from(length[0])
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream SOCKS5 address",
            ));
        }
    };
    let mut bound = vec![0u8; address_length + 2];
    stream.read_exact(&mut bound)?;
    Ok(())
}

fn connect_upstream_http(stream: &mut TcpStream, target: &Target) -> io::Result<()> {
    let authority = target_authority(target)?;
    write!(
        stream,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
    )?;
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while response.len() < 16 * 1024 {
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let first_line = response
        .split(|value| *value == b'\n')
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP proxy response"))?;
    if !first_line.starts_with(b"HTTP/1.1 200") && !first_line.starts_with(b"HTTP/1.0 200") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "HTTP CONNECT rejected",
        ));
    }
    Ok(())
}

fn relay(mut client: TcpStream, remote: RemoteStream) {
    let RemoteStream::Tcp(mut remote) = remote else {
        relay_nonblocking(client, remote);
        return;
    };
    let Ok(mut client_reader) = client.try_clone() else {
        return;
    };
    let Ok(mut remote_writer) = remote.try_clone() else {
        return;
    };
    let writer = thread::spawn(move || {
        let _ = io::copy(&mut client_reader, &mut remote_writer);
        let _ = remote_writer.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut remote, &mut client);
    // The upstream reached EOF: propagate the half-close to the local client
    // so it observes a clean end-of-stream instead of waiting for its own
    // write side to close. The writer thread keeps relaying client traffic
    // until the client closes its side.
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = writer.join();
}

fn relay_nonblocking(mut client: TcpStream, mut remote: RemoteStream) {
    if client.set_nonblocking(true).is_err() || remote.set_nonblocking(true).is_err() {
        return;
    }
    let mut client_to_remote = Vec::new();
    let mut remote_to_client = Vec::new();
    let mut client_closed = false;
    let mut remote_closed = false;
    let mut remote_eof_propagated = false;
    let mut client_buffer = [0u8; 16 * 1024];
    let mut remote_buffer = [0u8; 16 * 1024];

    while !(client_closed
        && remote_closed
        && client_to_remote.is_empty()
        && remote_to_client.is_empty())
    {
        let mut progressed = false;
        if client_closed {
            remote_to_client.clear();
        }
        if remote_closed {
            client_to_remote.clear();
        }
        if !client_closed && client_to_remote.len() < MAX_RELAY_BUFFER {
            let available = (MAX_RELAY_BUFFER - client_to_remote.len()).min(client_buffer.len());
            match client.read(&mut client_buffer[..available]) {
                Ok(0) => client_closed = true,
                Ok(length) => {
                    client_to_remote.extend_from_slice(&client_buffer[..length]);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => client_closed = true,
            }
        }
        if !client_to_remote.is_empty() {
            match remote.write(&client_to_remote) {
                Ok(length) => {
                    client_to_remote.drain(..length);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    remote_closed = true;
                    client_to_remote.clear();
                }
            }
        }
        if !remote_closed && remote_to_client.len() < MAX_RELAY_BUFFER {
            let available = (MAX_RELAY_BUFFER - remote_to_client.len()).min(remote_buffer.len());
            match remote.read(&mut remote_buffer[..available]) {
                Ok(0) => {
                    remote_closed = true;
                    // Propagate the upstream half-close to the local client so
                    // it sees a clean end-of-stream without closing its own
                    // write side.
                    if !remote_eof_propagated {
                        remote_eof_propagated = true;
                        let _ = client.shutdown(std::net::Shutdown::Write);
                    }
                }
                Ok(length) => {
                    remote_to_client.extend_from_slice(&remote_buffer[..length]);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => remote_closed = true,
            }
        }
        if !remote_to_client.is_empty() {
            match client.write(&remote_to_client) {
                Ok(length) => {
                    remote_to_client.drain(..length);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    client_closed = true;
                    remote_to_client.clear();
                }
            }
        }
        if client_closed && client_to_remote.is_empty() {
            let _ = remote.flush();
        }
        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Bounded parser entry points used by the repository's libFuzzer targets.
///
/// This surface is feature-gated so fuzzing can exercise framing and
/// handshake parsers without making those implementation details part of the
/// normal public API.
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use std::io;

    use super::{
        decode_grpc_messages as decode_grpc, decode_hysteria_tcp_request,
        decode_hysteria_tcp_response, decode_quic_varint as decode_varint,
        decode_shadowsocks_frame as decode_ss_frame, ShadowsocksMethod, FUZZ_INPUT_LIMIT,
    };

    fn bounded(input: &[u8]) -> io::Result<&[u8]> {
        if input.len() > FUZZ_INPUT_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fuzz input exceeds the parser safety limit",
            ));
        }
        Ok(input)
    }

    /// Decode complete, uncompressed gRPC messages from a bounded buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the fuzz limit or contains an
    /// invalid gRPC frame.
    pub fn decode_grpc_messages(input: &[u8]) -> io::Result<Vec<u8>> {
        let mut buffer = bounded(input)?.to_vec();
        decode_grpc(&mut buffer)
    }

    /// Parse a Hysteria TCP request frame without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the fuzz limit or is malformed.
    pub fn decode_hysteria_request(input: &[u8]) -> io::Result<()> {
        decode_hysteria_tcp_request(bounded(input)?).map(|_| ())
    }

    /// Parse a Hysteria TCP response frame without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the fuzz limit or is malformed.
    pub fn decode_hysteria_response(input: &[u8]) -> io::Result<()> {
        decode_hysteria_tcp_response(bounded(input)?).map(|_| ())
    }

    /// Decode one QUIC varint from a bounded byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the fuzz limit or is truncated.
    pub fn decode_quic_varint(input: &[u8]) -> io::Result<(u64, usize)> {
        decode_varint(bounded(input)?)
    }

    /// Attempt to authenticate and decode a Shadowsocks AEAD frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the fuzz limit or is malformed
    /// or unauthenticated.
    pub fn decode_shadowsocks_frame(input: &[u8]) -> io::Result<Vec<u8>> {
        decode_ss_frame(
            ShadowsocksMethod::Aes256Gcm,
            "nomad-fuzz-password",
            &[0u8; 32],
            0,
            bounded(input)?,
        )
    }

    /// Parse a REALITY `ClientHello` record without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the fuzz limit or is malformed.
    pub fn parse_reality_client_hello(input: &[u8]) -> io::Result<()> {
        super::reality::fuzz_parse_client_hello(bounded(input)?)
    }

    /// Parse a REALITY `ServerHello` record without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the fuzz limit or is malformed.
    pub fn parse_reality_server_hello(input: &[u8]) -> io::Result<()> {
        super::reality::fuzz_parse_server_hello(bounded(input)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        write_trojan_request, write_vless_request, FreedomDomainStrategy, Target, XrayConfig,
        XrayCore, XrayOutbound, XrayProtocol, XraySecurity, XrayTransport, XrayTransportConfig,
    };
    use base64::Engine as _;
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::thread;

    fn read_test_http_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        request
    }

    fn test_http_header(request: &[u8], name: &str) -> Option<String> {
        let prefix = format!("{name}: ");
        request
            .split(|byte| *byte == b'\n')
            .filter_map(|line| line.strip_suffix(b"\r"))
            .find_map(|line| {
                let line = String::from_utf8_lossy(line);
                line.strip_prefix(&prefix).map(str::to_owned)
            })
    }

    fn assert_packet_upload(request: &[u8], session_id: &str, sequence: u64, payload: &[u8]) {
        let line = request
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|line| line.strip_suffix(b"\r"))
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(line)
                .split_whitespace()
                .nth(1)
                .unwrap(),
            format!("/x?x_seq={sequence}")
        );
        assert_eq!(test_http_header(request, "X-Session").unwrap(), session_id);
        assert!(request
            .windows(b"Content-Length: 0".len())
            .any(|window| window.eq_ignore_ascii_case(b"Content-Length: 0")));
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(test_http_header(request, "X-Data-0").unwrap())
                .unwrap(),
            payload
        );
    }

    #[test]
    fn recognizes_all_xray_outbound_protocol_names() {
        let names = [
            "blackhole",
            "dns",
            "freedom",
            "http",
            "loopback",
            "shadowsocks",
            "socks",
            "trojan",
            "vless",
            "vmess",
            "hysteria",
            "wireguard",
        ];

        for name in names {
            let protocol = XrayProtocol::parse(name).expect("official Xray protocol name");
            assert_eq!(protocol.as_str(), name);
        }
    }

    #[test]
    fn recognizes_all_xray_transport_methods() {
        let names = [
            "raw",
            "xhttp",
            "mkcp",
            "grpc",
            "websocket",
            "httpupgrade",
            "hysteria",
        ];

        for name in names {
            let transport = XrayTransport::parse(Some(name)).expect("official Xray transport");
            assert_eq!(transport.as_str(), name);
        }
    }

    #[test]
    fn recognizes_official_xray_network_aliases() {
        assert_eq!(XrayTransport::parse(Some("tcp")), Some(XrayTransport::Raw));
        assert_eq!(
            XrayTransport::parse(Some("ws")),
            Some(XrayTransport::WebSocket)
        );
        assert_eq!(XrayTransport::parse(Some("kcp")), Some(XrayTransport::Mkcp));

        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {"network": "tcp", "security": "none"}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(config.transport().method, XrayTransport::Raw);
    }

    #[test]
    fn reality_is_limited_to_xray_compatible_transports() {
        assert!(XrayTransportConfig {
            method: XrayTransport::Raw,
            security: XraySecurity::Reality,
        }
        .validate(XrayProtocol::Vless)
        .is_ok());
        assert!(XrayTransportConfig {
            method: XrayTransport::Grpc,
            security: XraySecurity::Reality,
        }
        .validate(XrayProtocol::Vless)
        .is_err());
        assert!(XrayTransportConfig {
            method: XrayTransport::Xhttp,
            security: XraySecurity::Reality,
        }
        .validate(XrayProtocol::Vless)
        .is_ok());
        assert!(XrayTransportConfig {
            method: XrayTransport::WebSocket,
            security: XraySecurity::Reality,
        }
        .validate(XrayProtocol::Vless)
        .is_err());
    }

    #[test]
    fn hysteria_requires_tls_and_hysteria_transport() {
        assert!(XrayTransportConfig {
            method: XrayTransport::Hysteria,
            security: XraySecurity::Tls,
        }
        .validate(XrayProtocol::Hysteria)
        .is_ok());
        assert!(XrayTransportConfig {
            method: XrayTransport::Raw,
            security: XraySecurity::None,
        }
        .validate(XrayProtocol::Hysteria)
        .is_err());
    }

    #[test]
    fn parses_socks_outbound_without_resolving_target_locally() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "socks",
                    "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}
                }]
            }"#,
        )
        .unwrap();

        assert!(matches!(config.outbound(), XrayOutbound::Socks5(_)));
        assert_eq!(config.transport(), XrayTransportConfig::default());
    }

    #[test]
    fn xray_core_forwards_socks5_traffic_without_local_target_resolution() {
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            eprintln!("upstream accepted");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            eprintln!("upstream greeting");
            assert_eq!(&greeting, &[0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).unwrap();

            let mut request = [0u8; 5];
            stream.read_exact(&mut request).unwrap();
            eprintln!("upstream request");
            assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x03]);
            let host_length = usize::from(request[4]);
            let mut host = vec![0u8; host_length];
            stream.read_exact(&mut host).unwrap();
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).unwrap();
            assert_eq!(String::from_utf8(host).unwrap(), "example.com");
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            eprintln!("upstream reply");
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).unwrap();
            eprintln!("upstream payload");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let config = XrayConfig::from_json(&format!(
            r#"{{"outbounds":[{{"protocol":"socks","settings":{{"servers":[{{"address":"127.0.0.1","port":{}}}]}}}}]}}"#,
            upstream_address.port()
        ))
        .unwrap();
        let core = XrayCore::start(config).unwrap();
        let mut client =
            TcpStream::connect((core.endpoint().host(), core.endpoint().port())).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, &[0x05, 0x00]);
        let host = b"example.com";
        let host_length = u8::try_from(host.len()).expect("test host length fits SOCKS5");
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host_length];
        request.extend_from_slice(host);
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0x00);
        client.write_all(b"ping").unwrap();
        let mut body = [0u8; 4];
        client.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"pong");
        drop(client);
        upstream.join().unwrap();
    }

    #[test]
    fn rejects_unknown_transport_in_primary_outbound() {
        let error = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {},
                    "streamSettings": {"method": "not-a-transport"}
                }]
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown Xray stream transport"));
    }

    #[test]
    fn does_not_skip_primary_unsupported_protocol() {
        let error = XrayConfig::from_json(
            r#"{
                "outbounds": [
                    {"protocol": "vless", "settings": {}},
                    {"protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}}
                ]
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("vless"));
    }

    #[test]
    fn rejects_stream_security_on_compatibility_proxy() {
        let error = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "socks",
                    "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]},
                    "streamSettings": {"security": "tls"}
                }]
            }"#,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("cannot use embedded stream settings"));
    }

    #[test]
    fn parses_vless_vnext_and_preserves_transport_selection() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "gateway.example",
                            "port": 443,
                            "users": [{
                                "id": "00112233-4455-6677-8899-aabbccddeeff",
                                "encryption": "none"
                            }]
                        }]
                    },
                    "streamSettings": {"method": "raw", "security": "none"}
                }]
            }"#,
        )
        .unwrap();

        assert!(matches!(config.outbound(), XrayOutbound::Vless(_)));
        assert_eq!(config.transport().method, XrayTransport::Raw);
    }

    #[test]
    fn parses_httpupgrade_settings_without_accepting_host_injection() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "gateway.example",
                            "port": 443,
                            "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]
                        }]
                    },
                    "streamSettings": {
                        "method": "httpupgrade",
                        "security": "tls",
                        "httpupgradeSettings": {
                            "path": "/edge",
                            "host": "front.example",
                            "headers": {"X-Nomad": "1"}
                        }
                    }
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(config.http_settings().path, "/edge");
        assert_eq!(
            config.http_settings().host.as_deref(),
            Some("front.example")
        );
        assert_eq!(
            config.http_settings().headers,
            [("X-Nomad".to_owned(), "1".to_owned())]
        );

        let error = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {"method": "httpupgrade", "httpupgradeSettings": {"headers": {"Host": "evil.example"}}}
                }]
            }"#,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid Xray httpupgradeSettings.headers entry"));

        let error = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {"method": "websocket", "wsSettings": {"host": "front.example\r\nX-Leak: true"}}
                }]
            }"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid Xray wsSettings.host"));
    }

    #[test]
    fn accepts_vless_grpc_runtime_at_core_startup() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {"method": "grpc", "security": "tls"}
                }]
            }"#,
        )
        .unwrap();

        assert!(XrayCore::start(config).is_ok());
    }

    #[test]
    fn encodes_vless_tcp_request_without_resolving_target() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = vec![0u8; 34];
            stream.read_exact(&mut bytes).unwrap();
            bytes
        });

        let mut client = std::net::TcpStream::connect(address).unwrap();
        write_vless_request(
            &mut client,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
            &Target {
                host: "example.com".to_owned(),
                port: 443,
            },
        )
        .unwrap();

        let bytes = server.join().unwrap();
        assert_eq!(
            &bytes[..22],
            &[
                0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0, 1, 1, 0xbb, 2
            ]
        );
        assert_eq!(&bytes[22..], b"\x0bexample.com");
    }

    #[test]
    fn parses_trojan_and_encodes_authenticated_target_header() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "trojan",
                    "settings": {"address": "gateway.example", "port": 443, "password": "secret"},
                    "streamSettings": {"method": "raw", "security": "tls"}
                }]
            }"#,
        )
        .unwrap();
        assert!(matches!(config.outbound(), XrayOutbound::Trojan(_)));
        assert!(XrayCore::start(config).is_ok());

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = vec![0u8; 56 + 2 + 1 + 1 + 1 + 11 + 2 + 2];
            stream.read_exact(&mut bytes).unwrap();
            bytes
        });
        let mut client = std::net::TcpStream::connect(address).unwrap();
        write_trojan_request(
            &mut client,
            "secret",
            &Target {
                host: "example.com".to_owned(),
                port: 443,
            },
        )
        .unwrap();
        let bytes = server.join().unwrap();
        assert_eq!(&bytes[56..58], b"\r\n");
        assert_eq!(&bytes[58..], b"\x01\x03\x0bexample.com\x01\xbb\r\n");
    }

    #[test]
    fn vision_padding_frame_matches_xray_layout() {
        // Deterministic RNG: `next(bound)` returns fixed values.
        let frame = super::vision_pad(
            b"hello",
            super::VISION_COMMAND_CONTINUE,
            Some(&[0xAA; 16]),
            true,
            |bound| if bound == 500 { 100 } else { 0 },
        )
        .unwrap();
        // Long padding (content < 900): padding = rand(500) + 900 - 5 = 995.
        // uuid(16) + command(1) + content len(2) + padding len(2) + 5 + 995.
        assert_eq!(frame.len(), 16 + 1 + 2 + 2 + 5 + 995);
        assert_eq!(&frame[..16], &[0xAA; 16]);
        assert_eq!(frame[16], super::VISION_COMMAND_CONTINUE);
        assert_eq!(&frame[17..19], &5u16.to_be_bytes());
        assert_eq!(&frame[19..21], &995u16.to_be_bytes());
        assert_eq!(&frame[21..26], b"hello");

        // Long padding: content < 900 uses `rand(500) + 900 - content_len`.
        let frame = super::vision_pad(
            b"small",
            super::VISION_COMMAND_CONTINUE,
            None,
            true,
            |bound| if bound == 500 { 100 } else { 0 },
        )
        .unwrap();
        let padding_len = u16::from_be_bytes([frame[3], frame[4]]);
        assert_eq!(padding_len as usize, 100 + 900 - 5);

        // Short padding for large content: `rand(256)`.
        let large = vec![0u8; 900];
        let frame = super::vision_pad(
            &large,
            super::VISION_COMMAND_CONTINUE,
            None,
            true,
            |bound| if bound == 256 { 42 } else { 0 },
        )
        .unwrap();
        let padding_len = u16::from_be_bytes([frame[3], frame[4]]);
        assert_eq!(padding_len, 42);
    }

    #[test]
    fn vless_vision_stream_round_trips_padded_data() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut stream =
                super::VlessVisionStream::new(super::RemoteStream::Tcp(socket), [0xBB; 16]);
            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            received
        });

        let client = std::net::TcpStream::connect(address).unwrap();
        let mut stream =
            super::VlessVisionStream::new(super::RemoteStream::Tcp(client), [0xBB; 16]);
        stream.write_all(b"first").unwrap();
        stream.write_all(b"second").unwrap();
        drop(stream);
        assert_eq!(server.join().unwrap(), b"firstsecond");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn vless_flow_validation_matches_xray_constraints() {
        // vision over raw+TLS is accepted.
        let vision = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "gateway.example",
                            "port": 443,
                            "users": [{
                                "id": "00112233-4455-6677-8899-aabbccddeeff",
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                            }]
                        }]
                    },
                    "streamSettings": {"method": "raw", "security": "tls"}
                }]
            }"#,
        )
        .unwrap();
        assert!(matches!(
            vision.outbound(),
            XrayOutbound::Vless(vless)
                if vless.flow == Some(super::VlessFlow::XtlsRprxVision)
        ));
        assert!(XrayCore::start(vision).is_ok());

        // vision requires TLS/REALITY; raw+none is rejected.
        let no_security = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "gateway.example",
                            "port": 443,
                            "users": [{
                                "id": "00112233-4455-6677-8899-aabbccddeeff",
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                            }]
                        }]
                    }
                }]
            }"#,
        )
        .unwrap();
        let Err(error) = XrayCore::start(no_security) else {
            panic!("vision without TLS/REALITY must be rejected");
        };
        assert!(error.to_string().contains("requires TLS or REALITY"));

        // unknown flows are rejected at parse.
        let unknown = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "gateway.example",
                            "port": 443,
                            "users": [{
                                "id": "00112233-4455-6677-8899-aabbccddeeff",
                                "encryption": "none",
                                "flow": "xtls-rprx-unknown"
                            }]
                        }]
                    }
                }]
            }"#,
        );
        assert!(
            unknown.is_err(),
            "unknown VLESS flow must be rejected, got {:?}",
            unknown.as_ref().map(XrayConfig::outbound)
        );

        // direct/splice are validated but explicitly rejected as not implemented.
        for flow in ["xtls-rprx-direct", "xtls-rprx-splice"] {
            let config = XrayConfig::from_json(&format!(
                r#"{{
                    "outbounds": [{{
                        "protocol": "vless",
                        "settings": {{
                            "vnext": [{{
                                "address": "gateway.example",
                                "port": 443,
                                "users": [{{
                                    "id": "00112233-4455-6677-8899-aabbccddeeff",
                                    "encryption": "none",
                                    "flow": "{flow}"
                                }}]
                            }}]
                        }},
                        "streamSettings": {{"method": "raw", "security": "tls"}}
                    }}]
                }}"#
            ))
            .unwrap();
            let Err(error) = XrayCore::start(config) else {
                panic!("flow {flow} must be rejected as not implemented");
            };
            assert!(
                error.to_string().contains("not implemented"),
                "unexpected error for {flow}: {error}"
            );
        }
    }

    #[test]
    fn explicit_freedom_outbound_connects_without_becoming_a_fallback() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let config = XrayConfig::from_json(
            r#"{"outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]}"#,
        )
        .unwrap();
        assert!(matches!(
            config.outbound(),
            XrayOutbound::Freedom(freedom)
                if freedom.domain_strategy == FreedomDomainStrategy::UseIpv4
        ));
        let core = XrayCore::start(config).unwrap();
        let mut client =
            TcpStream::connect((core.endpoint().host(), core.endpoint().port())).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, &[0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&address.port().to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0x00);
        client.write_all(b"ping").unwrap();
        let mut body = [0u8; 4];
        client.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"pong");
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn dns_query_round_trips_through_configured_server() {
        let listener = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (length, peer) = listener.recv_from(&mut request).unwrap();
            let query = &request[..length];
            assert_eq!(&query[12..], b"\x07example\x04test\x00\x00\x01\x00\x01");
            let mut response = Vec::with_capacity(length + 16);
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&[0x81, 0x80]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&query[12..]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[127, 0, 0, 1]);
            listener.send_to(&response, peer).unwrap();
        });

        let resolver = super::XrayDnsResolver::new(super::DnsConfig {
            network: Some(super::DnsNetwork::Udp),
            address: Some(address.ip().to_string()),
            port: Some(address.port()),
        });
        let addresses = super::dns_resolve(&resolver, "example.test", super::DNS_QTYPE_A).unwrap();
        assert_eq!(addresses, vec![std::net::IpAddr::V4([127, 0, 0, 1].into())]);
        server.join().unwrap();
    }

    #[test]
    fn freedom_domain_strategy_routes_dns_packets_through_secondary_outbound() {
        let echo = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_server = thread::spawn(move || {
            let (mut stream, _) = echo.accept().unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let dns = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let dns_address = dns.local_addr().unwrap();
        let dns_server = thread::spawn(move || {
            for _ in 0..2 {
                let mut request = [0u8; 512];
                let (length, peer) = dns.recv_from(&mut request).unwrap();
                let query = &request[..length];
                let qtype = u16::from_be_bytes([query[length - 4], query[length - 3]]);
                let mut response = Vec::with_capacity(length + 16);
                response.extend_from_slice(&query[..2]);
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&1u16.to_be_bytes());
                let answer_count = u16::from(qtype == super::DNS_QTYPE_A);
                response.extend_from_slice(&answer_count.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&query[12..]);
                if qtype == super::DNS_QTYPE_A {
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&60u32.to_be_bytes());
                    response.extend_from_slice(&4u16.to_be_bytes());
                    response.extend_from_slice(&[127, 0, 0, 1]);
                }
                dns.send_to(&response, peer).unwrap();
            }
        });

        let config = XrayConfig::from_json(&format!(
            r#"{{
                "outbounds": [
                    {{"protocol": "freedom", "settings": {{"domainStrategy": "UseIP"}}}},
                    {{
                        "protocol": "dns",
                        "tag": "dns-out",
                        "settings": {{
                            "network": "udp",
                            "address": "{}",
                            "port": {}
                        }}
                    }}
                ]
            }}"#,
            dns_address.ip(),
            dns_address.port(),
        ))
        .unwrap();
        assert!(config.dns_resolver_config().is_some());

        let core = XrayCore::start(config).unwrap();
        let mut client =
            TcpStream::connect((core.endpoint().host(), core.endpoint().port())).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, &[0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00, 0x03];
        request.extend_from_slice(&[12]);
        request.extend_from_slice(b"echo.example");
        request.extend_from_slice(&echo_address.port().to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0x00);
        client.write_all(b"ping").unwrap();
        let mut body = [0u8; 4];
        client.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"pong");
        drop(client);
        echo_server.join().unwrap();
        dns_server.join().unwrap();
    }

    #[test]
    fn selected_blackhole_rejects_connections_without_direct_fallback() {
        let config =
            XrayConfig::from_json(r#"{"outbounds":[{"protocol":"blackhole","settings":{}}]}"#)
                .unwrap();
        let core = XrayCore::start(config).unwrap();
        let mut client =
            TcpStream::connect((core.endpoint().host(), core.endpoint().port())).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, &[0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&80_u16.to_be_bytes());
        client.write_all(&request).unwrap();
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0x02);
    }

    #[test]
    fn parses_blackhole_response_mode_and_starts_local_blocker() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "blackhole",
                    "settings": {"response": {"type": "http"}}
                }]
            }"#,
        )
        .unwrap();

        assert!(matches!(
            config.outbound(),
            XrayOutbound::Blackhole {
                response: super::BlackholeResponse::Http
            }
        ));
        assert!(XrayCore::start(config).is_ok());
    }

    #[test]
    fn parses_dns_outbound_rewrite_settings_without_accepting_stream_layers() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "dns",
                    "settings": {
                        "network": "tcp",
                        "address": "1.1.1.1",
                        "port": 5353
                    }
                }]
            }"#,
        )
        .unwrap();

        assert!(
            matches!(config.outbound(), XrayOutbound::Dns(dns) if dns.network == Some(super::DnsNetwork::Tcp)
            && dns.address.as_deref() == Some("1.1.1.1")
            && dns.port == Some(5353))
        );
        let Err(error) = XrayCore::start(config) else {
            panic!("DNS outbound must not start on the TCP-only core")
        };
        assert!(error
            .to_string()
            .contains("DNS outbound requires DNS packet routing"));
    }

    #[test]
    fn dns_resolver_forwards_complete_udp_wire_packets() {
        let listener = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (length, peer) = listener.recv_from(&mut request).unwrap();
            assert_eq!(&request[..length], b"dns-query");
            listener.send_to(b"dns-response", peer).unwrap();
        });
        let resolver = super::XrayDnsResolver::new(super::DnsConfig {
            network: Some(super::DnsNetwork::Udp),
            address: Some(address.ip().to_string()),
            port: Some(address.port()),
        });
        assert_eq!(resolver.query(b"dns-query").unwrap(), b"dns-response");
        server.join().unwrap();
    }

    #[test]
    fn dns_resolver_rejects_hostname_endpoints_to_prevent_local_resolution() {
        let resolver = super::XrayDnsResolver::new(super::DnsConfig {
            network: Some(super::DnsNetwork::Udp),
            address: Some("dns.example".to_owned()),
            port: Some(53),
        });

        let error = resolver.query(b"dns-query").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("numeric IP"));
    }

    #[test]
    fn parses_loopback_inbound_tag_and_rejects_unknown_reentry() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "loopback",
                    "settings": {"inboundTag": "reroute-web"}
                }]
            }"#,
        )
        .unwrap();

        assert!(
            matches!(config.outbound(), XrayOutbound::Loopback(loopback) if loopback.inbound_tag == "reroute-web")
        );
        let Err(error) = XrayCore::start(config) else {
            panic!("Loopback must not start without a routing graph")
        };
        assert!(error
            .to_string()
            .contains("Loopback requires an in-process routing graph"));
    }

    #[test]
    fn loopback_starts_when_an_in_process_connector_is_supplied() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "loopback",
                    "settings": {"inboundTag": "reroute-web"}
                }]
            }"#,
        )
        .unwrap();
        let connector: super::XrayLoopbackConnector = std::sync::Arc::new(|tag, host, port| {
            assert_eq!(tag, "reroute-web");
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "test connector",
            ))
        });
        assert!(XrayCore::start_with_loopback(config, connector).is_ok());
    }

    #[test]
    fn parses_shadowsocks_legacy_aead_configuration() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "shadowsocks",
                    "settings": {
                        "address": "gateway.example",
                        "port": 8388,
                        "method": "chacha20-poly1305",
                        "password": "secret"
                    }
                }]
            }"#,
        )
        .unwrap();

        assert!(
            matches!(config.outbound(), XrayOutbound::Shadowsocks(shadowsocks)
            if shadowsocks.method == super::ShadowsocksMethod::ChaCha20Poly1305)
        );
    }

    #[test]
    fn shadowsocks_legacy_aead_frames_round_trip_with_directional_nonce() {
        let salt = [0x42; 32];
        let frame = super::encode_shadowsocks_frame(
            super::ShadowsocksMethod::ChaCha20Poly1305,
            "secret",
            &salt,
            7,
            b"nomad payload",
        )
        .unwrap();
        assert_ne!(&frame[18..], b"nomad payload");
        assert_eq!(
            super::decode_shadowsocks_frame(
                super::ShadowsocksMethod::ChaCha20Poly1305,
                "secret",
                &salt,
                7,
                &frame,
            )
            .unwrap(),
            b"nomad payload"
        );
    }

    #[test]
    fn shadowsocks_xchacha_frames_round_trip_with_24_byte_nonce() {
        let salt = [0x42; 32];
        let frame = super::encode_shadowsocks_frame(
            super::ShadowsocksMethod::XChaCha20Poly1305,
            "secret",
            &salt,
            7,
            b"nomad payload",
        )
        .unwrap();
        assert_ne!(&frame[18..], b"nomad payload");
        assert_eq!(
            super::decode_shadowsocks_frame(
                super::ShadowsocksMethod::XChaCha20Poly1305,
                "secret",
                &salt,
                7,
                &frame,
            )
            .unwrap(),
            b"nomad payload"
        );
    }

    #[test]
    fn shadowsocks_2022_frames_round_trip_for_all_supported_ciphers() {
        let key = [0x37; 32];
        let salt = [0x42; 32];
        let header = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0d];

        for method in [
            super::ShadowsocksMethod::Blake3Aes128Gcm,
            super::ShadowsocksMethod::Blake3Aes256Gcm,
            super::ShadowsocksMethod::Blake3ChaCha20Poly1305,
        ] {
            let mut cipher =
                super::Shadowsocks2022Cipher::new(method, &key[..method.key_len()], &salt).unwrap();
            let encrypted = cipher.seal(&header).unwrap();
            assert_ne!(encrypted, header);

            let mut opened_cipher =
                super::Shadowsocks2022Cipher::new(method, &key[..method.key_len()], &salt).unwrap();
            assert_eq!(opened_cipher.open(&encrypted).unwrap(), header);
        }
    }

    #[test]
    fn shadowsocks_stream_exchanges_encrypted_payloads_with_server_salt() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut salt = [0u8; 32];
            stream.read_exact(&mut salt).unwrap();
            let mut frame = vec![0u8; 18 + 5 + 16];
            stream.read_exact(&mut frame).unwrap();
            assert_eq!(
                super::decode_shadowsocks_frame(
                    super::ShadowsocksMethod::ChaCha20Poly1305,
                    "secret",
                    &salt,
                    0,
                    &frame,
                )
                .unwrap(),
                b"hello"
            );
            let response_salt = [0x24; 32];
            stream.write_all(&response_salt).unwrap();
            let response = super::encode_shadowsocks_frame(
                super::ShadowsocksMethod::ChaCha20Poly1305,
                "secret",
                &response_salt,
                0,
                b"world",
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        });

        let stream = std::net::TcpStream::connect(address).unwrap();
        let mut stream = super::ShadowsocksStream::new(
            stream,
            super::ShadowsocksMethod::ChaCha20Poly1305,
            "secret",
        )
        .unwrap();
        stream.write_all(b"hello").unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"world");
        server.join().unwrap();
    }

    #[test]
    fn shadowsocks_2022_stream_exchanges_authenticated_headers_and_data() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let method = super::ShadowsocksMethod::Blake3ChaCha20Poly1305;
        let master_key = [0x37; 32];
        let password = base64::engine::general_purpose::STANDARD.encode(master_key);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut client_salt = [0u8; 32];
            stream.read_exact(&mut client_salt).unwrap();
            let mut client_cipher =
                super::Shadowsocks2022Cipher::new(method, &master_key, &client_salt).unwrap();
            let mut encrypted_header = vec![0u8; 1 + 8 + 2 + super::SHADOWSOCKS_TAG_LEN];
            stream.read_exact(&mut encrypted_header).unwrap();
            let header = client_cipher.open(&encrypted_header).unwrap();
            assert_eq!(header[0], 0);
            let payload_length = usize::from(u16::from_be_bytes([header[9], header[10]]));
            let mut encrypted_payload = vec![0u8; payload_length + super::SHADOWSOCKS_TAG_LEN];
            stream.read_exact(&mut encrypted_payload).unwrap();
            let payload = client_cipher.open(&encrypted_payload).unwrap();
            assert_eq!(&payload[payload.len() - 2..], &[0, 0]);

            let response_salt = [0x24; 32];
            let mut response_cipher =
                super::Shadowsocks2022Cipher::new(method, &master_key, &response_salt).unwrap();
            let mut response_header = Vec::with_capacity(1 + 8 + 32 + 2);
            response_header.push(1);
            response_header.extend_from_slice(
                &super::Shadowsocks2022Stream::timestamp()
                    .unwrap()
                    .to_be_bytes(),
            );
            response_header.extend_from_slice(&client_salt);
            response_header.extend_from_slice(&5u16.to_be_bytes());
            let encrypted_response_header = response_cipher.seal(&response_header).unwrap();
            let encrypted_response_payload = response_cipher.seal(b"world").unwrap();
            stream.write_all(&response_salt).unwrap();
            stream.write_all(&encrypted_response_header).unwrap();
            stream.write_all(&encrypted_response_payload).unwrap();
        });

        let stream = std::net::TcpStream::connect(address).unwrap();
        stream.set_nonblocking(false).unwrap();
        let mut target_address = Vec::new();
        super::append_shadowsocks_address(&mut target_address, "example.com").unwrap();
        target_address.extend_from_slice(&443u16.to_be_bytes());
        let mut stream =
            super::Shadowsocks2022Stream::new(stream, method, &password, target_address).unwrap();
        stream.start().unwrap();
        let mut response = [0u8; 5];
        let mut offset = 0;
        while offset < response.len() {
            match stream.read(&mut response[offset..]) {
                Ok(length) => offset += length,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::yield_now();
                }
                Err(error) => panic!("failed to read Shadowsocks 2022 response: {error}"),
            }
        }
        assert_eq!(&response, b"world");
        server.join().unwrap();
    }

    #[test]
    fn hysteria_tcp_control_frames_round_trip_with_quic_varints() {
        let request = super::encode_hysteria_tcp_request("example.com:443", &[b'x'; 64]).unwrap();
        let (address, padding) = super::decode_hysteria_tcp_request(&request).unwrap();
        assert_eq!(address, "example.com:443");
        assert_eq!(padding, 64);

        let response = super::encode_hysteria_tcp_response(true, "", &[b'y'; 128]).unwrap();
        let (ok, message, padding) = super::decode_hysteria_tcp_response(&response).unwrap();
        assert!(ok);
        assert!(message.is_empty());
        assert_eq!(padding, 128);
    }

    #[test]
    fn parses_hysteria_v2_http3_settings_and_keeps_tls_verification_strict() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "hysteria",
                    "settings": {"version": 2, "address": "gateway.example", "port": 443},
                    "streamSettings": {
                        "method": "hysteria",
                        "security": "tls",
                        "hysteriaSettings": {"version": 2, "auth": "secret"}
                    }
                }]
            }"#,
        )
        .unwrap();

        assert!(matches!(config.outbound(), XrayOutbound::Hysteria(_)));
        assert_eq!(config.hysteria_settings().version, 2);
        assert_eq!(config.hysteria_settings().auth, "secret");
        assert!(!config.hysteria_settings().allow_insecure);
        assert!(XrayCore::start(config).is_ok());
    }

    #[test]
    fn grpc_messages_use_uncompressed_five_byte_frames() {
        let frame = super::encode_grpc_message(b"nomad").unwrap();
        assert_eq!(&frame[..5], &[0, 0, 0, 0, 5]);
        let mut pending = frame;
        assert_eq!(super::decode_grpc_messages(&mut pending).unwrap(), b"nomad");
        assert!(pending.is_empty());
    }

    #[test]
    fn grpc_stream_bridges_vless_bytes_over_http2() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(stream).await.unwrap();
                let (mut request, mut respond) = connection.accept().await.unwrap().unwrap();
                let driver = tokio::spawn(async move {
                    while let Some(result) = connection.accept().await {
                        if result.is_err() {
                            break;
                        }
                    }
                });
                let data = request.body_mut().data().await.unwrap().unwrap();
                request
                    .body_mut()
                    .flow_control()
                    .release_capacity(data.len())
                    .unwrap();
                let mut framed = data.to_vec();
                assert_eq!(super::decode_grpc_messages(&mut framed).unwrap(), b"hello");
                let mut response = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                response
                    .send_data(
                        bytes::Bytes::from(super::encode_grpc_message(b"world").unwrap()),
                        true,
                    )
                    .unwrap();
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), driver).await;
            });
        });

        let mut stream = super::GrpcStream::connect(
            "127.0.0.1",
            address.port(),
            super::XraySecurity::None,
            "127.0.0.1",
            &super::XrayGrpcSettings::default(),
        )
        .unwrap();
        stream.write_all(b"hello").unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"world");
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn xhttp_stream_one_bridges_chunked_http11_bytes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"POST /x HTTP/1.1"));
            assert!(request
                .windows(b"Transfer-Encoding: chunked".len())
                .any(|window| window.eq_ignore_ascii_case(b"Transfer-Encoding: chunked")));
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                stream.read_exact(&mut byte).unwrap();
                line.push(byte[0]);
            }
            assert_eq!(line, b"5\r\n");
            let mut payload = [0u8; 5];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"hello");
            let mut separator = [0u8; 2];
            stream.read_exact(&mut separator).unwrap();
            assert_eq!(&separator, b"\r\n");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
                .unwrap();
            stream.write_all(b"5\r\nworld\r\n").unwrap();
        });

        let mut stream = super::XhttpStream::connect(
            "127.0.0.1",
            address.port(),
            super::XraySecurity::None,
            "127.0.0.1",
            &super::XrayXhttpSettings {
                path: "/x".to_owned(),
                host: None,
                mode: "stream-one".to_owned(),
            },
            &super::XhttpRequestOptions::default(),
            None,
        )
        .unwrap();
        stream.write_all(b"hello").unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"world");
        server.join().unwrap();
    }

    #[test]
    fn xhttp_stream_up_uses_shared_session_for_split_http11_connections() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut upload, _) = listener.accept().unwrap();
            let upload_request = read_test_http_headers(&mut upload);
            let upload_line = upload_request
                .split(|byte| *byte == b'\n')
                .next()
                .and_then(|line| line.strip_suffix(b"\r"))
                .unwrap();
            let upload_path = String::from_utf8_lossy(upload_line)
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_owned();
            assert!(upload_line.starts_with(b"POST /x/"));
            assert!(upload_request
                .windows(b"Transfer-Encoding: chunked".len())
                .any(|window| window.eq_ignore_ascii_case(b"Transfer-Encoding: chunked")));
            upload
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                )
                .unwrap();

            let (mut download, _) = listener.accept().unwrap();
            let download_request = read_test_http_headers(&mut download);
            let download_line = download_request
                .split(|byte| *byte == b'\n')
                .next()
                .and_then(|line| line.strip_suffix(b"\r"))
                .unwrap();
            assert!(download_line.starts_with(b"GET /x/"));
            assert_eq!(
                String::from_utf8_lossy(download_line)
                    .split_whitespace()
                    .nth(1)
                    .unwrap(),
                upload_path
            );
            download
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nworld\r\n")
                .unwrap();

            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while !line.ends_with(b"\r\n") {
                upload.read_exact(&mut byte).unwrap();
                line.push(byte[0]);
            }
            assert_eq!(line, b"5\r\n");
            let mut payload = [0u8; 5];
            upload.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"hello");
            let mut separator = [0u8; 2];
            upload.read_exact(&mut separator).unwrap();
            assert_eq!(&separator, b"\r\n");
        });

        let mut stream = super::connect_transport(
            "127.0.0.1",
            address.port(),
            super::XrayTransportConfig {
                method: super::XrayTransport::Xhttp,
                security: super::XraySecurity::None,
            },
            None,
            &super::XrayHttpSettings::default(),
            &super::XrayGrpcSettings::default(),
            &super::XrayXhttpSettings {
                path: "/x".to_owned(),
                host: None,
                mode: "stream-up".to_owned(),
            },
            &super::XhttpRequestOptions::default(),
            &super::XrayMkcpSettings::default(),
            None,
        )
        .unwrap();
        stream.write_all(b"hello").unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"world");
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn xhttp_packet_up_posts_sequenced_bodies_and_reads_shared_downlink() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut download, _) = listener.accept().unwrap();
            let download_request = read_test_http_headers(&mut download);
            let download_line = download_request
                .split(|byte| *byte == b'\n')
                .next()
                .and_then(|line| line.strip_suffix(b"\r"))
                .unwrap();
            assert_eq!(download_line, b"GET /x HTTP/1.1");
            let session_id = test_http_header(&download_request, "X-Session").unwrap();
            download
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
                )
                .unwrap();

            let (mut upload, _) = listener.accept().unwrap();
            let upload_request = read_test_http_headers(&mut upload);
            assert_packet_upload(&upload_request, &session_id, 0, b"hello");
            upload
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            let (mut second_upload, _) = listener.accept().unwrap();
            let second_request = read_test_http_headers(&mut second_upload);
            assert_packet_upload(&second_request, &session_id, 1, b"!");
            second_upload
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            download.write_all(b"5\r\nworld\r\n").unwrap();
        });

        let mut stream = super::connect_transport(
            "127.0.0.1",
            address.port(),
            super::XrayTransportConfig {
                method: super::XrayTransport::Xhttp,
                security: super::XraySecurity::None,
            },
            None,
            &super::XrayHttpSettings::default(),
            &super::XrayGrpcSettings::default(),
            &super::XrayXhttpSettings {
                path: "/x".to_owned(),
                host: None,
                mode: "packet-up".to_owned(),
            },
            &super::XhttpRequestOptions {
                session_placement: super::XhttpMetadataPlacement::Header,
                session_key: "X-Session".to_owned(),
                sequence_placement: super::XhttpMetadataPlacement::Query,
                sequence_key: "x_seq".to_owned(),
                uplink_data_placement: super::XhttpDataPlacement::Header,
                uplink_data_key: "X-Data".to_owned(),
                uplink_http_method: "POST".to_owned(),
            },
            &super::XrayMkcpSettings::default(),
            None,
        )
        .unwrap();
        stream.write_all(b"hello").unwrap();
        stream.write_all(b"!").unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"world");
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn xhttp_packet_cookie_metadata_is_combined_into_one_cookie_header() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_test_http_headers(&mut stream);
            let cookie_lines = request
                .split(|byte| *byte == b'\n')
                .filter(|line| line.starts_with(b"Cookie:"))
                .count();
            assert_eq!(cookie_lines, 1, "XHTTP must combine cookie metadata");
            assert!(request
                .windows(b"Cookie: ".len())
                .any(|window| { window.eq_ignore_ascii_case(b"Cookie: ") }));
            let text = String::from_utf8_lossy(&request);
            assert!(text.contains("session=abc"));
            assert!(text.contains("seq=7"));
            assert!(text.contains("data_0=Ynl0ZXM"));
            assert!(text.contains("Content-Length: 0"));
        });

        let mut stream = super::XhttpIo::Tcp(TcpStream::connect(address).unwrap());
        let options = super::XhttpRequestOptions {
            session_placement: super::XhttpMetadataPlacement::Cookie,
            session_key: "session".to_owned(),
            sequence_placement: super::XhttpMetadataPlacement::Cookie,
            sequence_key: "seq".to_owned(),
            uplink_data_placement: super::XhttpDataPlacement::Cookie,
            uplink_data_key: "data".to_owned(),
            uplink_http_method: "POST".to_owned(),
        };
        assert!(!super::xhttp_write_packet_request(
            &mut stream,
            "/x",
            "127.0.0.1",
            Some("abc"),
            Some(7),
            &options,
            b"bytes",
        )
        .unwrap());
        server.join().unwrap();
    }

    #[test]
    fn xhttp_rejects_invalid_upload_methods_for_the_selected_mode() {
        let stream = r#"{
            "method": "xhttp",
            "security": "none",
            "xhttpSettings": {"mode": "stream-one", "uplinkHTTPMethod": "GET"}
        }"#;
        let config = XrayConfig::from_json(&format!(
            r#"{{"outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"gateway.example","port":80,"users":[{{"id":"00112233-4455-6677-8899-aabbccddeeff","encryption":"none"}}]}}]}},"streamSettings":{stream}}}]}}"#
        ))
        .unwrap();
        let error = match XrayCore::start(config) {
            Ok(core) => {
                drop(core);
                panic!("invalid XHTTP upload method was accepted")
            }
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("XHTTP GET uplink is only valid for packet-up"));

        let stream = r#"{
            "method": "xhttp",
            "security": "none",
            "xhttpSettings": {"mode": "packet-up", "uplinkHTTPMethod": "PUT"}
        }"#;
        let config = XrayConfig::from_json(&format!(
            r#"{{"outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"gateway.example","port":80,"users":[{{"id":"00112233-4455-6677-8899-aabbccddeeff","encryption":"none"}}]}}]}},"streamSettings":{stream}}}]}}"#
        ))
        .unwrap();
        let error = match XrayCore::start(config) {
            Ok(core) => {
                drop(core);
                panic!("invalid XHTTP upload method was accepted")
            }
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("XHTTP uplink HTTP method must be GET or POST"));
    }

    #[test]
    fn vmess_aead_body_round_trips_for_supported_ciphers() {
        let key = [0x31; 16];
        let nonce = [0x42; 12];
        for security in [
            super::VmessSecurity::Aes128Gcm,
            super::VmessSecurity::ChaCha20Poly1305,
        ] {
            let encrypted = super::vmess_seal(security, &key, nonce, b"nomad vmess").unwrap();
            assert_ne!(encrypted, b"nomad vmess");
            assert_eq!(
                super::vmess_open(security, &key, nonce, &encrypted).unwrap(),
                b"nomad vmess"
            );
        }
    }

    #[test]
    fn vmess_security_none_passes_plaintext_body_with_authenticated_header() {
        // Xray's SecurityType_NONE (code 5) keeps the authenticated AEAD request
        // header but streams the body without encryption.
        let key = [0x31; 16];
        let nonce = [0x42; 12];
        let plaintext = b"nomad vmess none";
        let sealed = super::vmess_seal(super::VmessSecurity::None, &key, nonce, plaintext).unwrap();
        assert_eq!(sealed, plaintext);
        assert_eq!(
            super::vmess_open(super::VmessSecurity::None, &key, nonce, &sealed).unwrap(),
            plaintext
        );

        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vmess",
                    "settings": {
                        "address": "gateway.example",
                        "port": 443,
                        "id": "00112233-4455-6677-8899-aabbccddeeff",
                        "security": "none"
                    }
                }]
            }"#,
        )
        .unwrap();
        assert!(matches!(config.outbound(), XrayOutbound::Vmess(vmess)
            if vmess.security == super::VmessSecurity::None));

        // The request header encoder now accepts the none mode.
        assert!(super::encode_vmess_request(
            [0x12; 16],
            super::VmessSecurity::None,
            &super::Target {
                host: "example.com".to_owned(),
                port: 443,
            },
        )
        .is_ok());

        // The body frames carry the plaintext length-prefixed payload with no
        // AEAD tag, and the core accepts a vmess "none" profile at startup.
        let plaintext = b"plaintext body";
        assert!(XrayCore::start(config).is_ok());

        // A vmess none stream must round-trip its own frames over a connected
        // pair without any encryption or tag.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut server_stream = super::VmessStream::new(
                super::RemoteStream::Tcp(socket),
                super::VmessSecurity::None,
                key,
                key,
                key,
                key,
            );
            let mut received = vec![0u8; plaintext.len()];
            server_stream.read_exact(&mut received).unwrap();
            received
        });
        let client = std::net::TcpStream::connect(address).unwrap();
        let mut client_stream = super::VmessStream::new(
            super::RemoteStream::Tcp(client),
            super::VmessSecurity::None,
            key,
            key,
            key,
            key,
        );
        client_stream.write_all(plaintext).unwrap();
        assert_eq!(server_thread.join().unwrap(), plaintext);
    }

    #[test]
    fn parses_vmess_security_and_uuid() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vmess",
                    "settings": {
                        "address": "gateway.example",
                        "port": 443,
                        "id": "00112233-4455-6677-8899-aabbccddeeff",
                        "security": "aes-128-gcm"
                    }
                }]
            }"#,
        )
        .unwrap();

        assert!(matches!(config.outbound(), XrayOutbound::Vmess(vmess)
            if vmess.security == super::VmessSecurity::Aes128Gcm));
    }

    #[test]
    fn parses_hysteria_v2_and_wireguard_keys() {
        let hysteria = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "hysteria",
                    "settings": {"version": 2, "address": "gateway.example", "port": 443},
                    "streamSettings": {"method": "hysteria", "security": "tls"}
                }]
            }"#,
        )
        .unwrap();
        assert!(
            matches!(hysteria.outbound(), XrayOutbound::Hysteria(hysteria) if hysteria.version == 2)
        );

        let wireguard = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "wireguard",
                    "settings": {
                        "secretKey": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                        "address": ["10.0.0.2/32"],
                        "dns": ["10.0.0.1"],
                        "peers": [{
                            "endpoint": "198.51.100.1:51820",
                            "publicKey": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                            "keepAlive": 25
                        }]
                    }
                }]
            }"#,
        )
        .unwrap();
        assert!(
            matches!(wireguard.outbound(), XrayOutbound::WireGuard(wireguard)
            if wireguard.addresses == ["10.0.0.2/32"]
                && wireguard.dns == ["10.0.0.1"])
        );
        assert_eq!(
            match wireguard.outbound() {
                XrayOutbound::WireGuard(wireguard) => wireguard.peers[0].persistent_keepalive,
                _ => None,
            },
            Some(25)
        );
        assert!(XrayCore::start(wireguard).is_ok());
    }

    #[test]
    fn loads_xray_json_profile_from_path() {
        let path = std::env::temp_dir().join(format!(
            "nomad-xray-profile-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(
            &path,
            r#"{"outbounds":[{"protocol":"blackhole","settings":{}}]}"#,
        )
        .unwrap();

        let config = XrayConfig::from_path(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(matches!(config.outbound(), XrayOutbound::Blackhole { .. }));
    }

    #[test]
    fn retains_grpc_xhttp_mkcp_and_reality_transport_settings() {
        let grpc = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {
                        "method": "grpc",
                        "security": "tls",
                        "grpcSettings": {"serviceName": "nomad", "authority": "front.example", "multiMode": true}
                    }
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(grpc.grpc_settings().service_name, "nomad");
        assert_eq!(
            grpc.grpc_settings().authority.as_deref(),
            Some("front.example")
        );
        assert!(grpc.grpc_settings().multi_mode);

        let xhttp = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {"method": "xhttp", "xhttpSettings": {"path": "/x", "mode": "stream-up"}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(xhttp.xhttp_settings().path, "/x");
        assert_eq!(xhttp.xhttp_settings().mode, "stream-up");
        assert!(XrayCore::start(xhttp).is_ok());

        let mkcp = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {"method": "mkcp", "kcpSettings": {"mtu": 1200, "tti": 20, "congestion": true}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(mkcp.mkcp_settings().mtu, 1200);
        assert_eq!(mkcp.mkcp_settings().tti, 20);
        assert!(mkcp.mkcp_settings().congestion);

        let reality = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {
                        "method": "raw",
                        "security": "reality",
                        "realitySettings": {
                            "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                            "shortId": "0123456789abcdef",
                            "fingerprint": "chrome",
                            "serverName": "www.example.com"
                        }
                    }
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(reality.reality_settings().unwrap().fingerprint, "chrome");
        assert_eq!(
            reality.reality_settings().unwrap().short_id,
            vec![1, 35, 69, 103, 137, 171, 205, 239]
        );

        let reality_xhttp = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {
                        "method": "xhttp",
                        "security": "reality",
                        "xhttpSettings": {"path": "/x", "mode": "stream-one"},
                        "realitySettings": {
                            "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                            "shortId": "0123456789abcdef",
                            "fingerprint": "chrome",
                            "serverName": "www.example.com"
                        }
                    }
                }]
            }"#,
        )
        .unwrap();
        assert!(XrayCore::start(reality_xhttp).is_ok());
    }

    #[test]
    fn accepts_xhttp_packet_up_at_core_startup() {
        let packet_up = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {"method": "xhttp", "xhttpSettings": {"path": "/x", "mode": "packet-up"}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(packet_up.xhttp_settings().mode, "packet-up");
        assert!(XrayCore::start(packet_up).is_ok());
    }

    #[test]
    fn parses_xhttp_metadata_and_uplink_placement_options() {
        let config = XrayConfig::from_json(
            r#"{
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "gateway.example", "port": 443, "users": [{"id": "00112233-4455-6677-8899-aabbccddeeff", "encryption": "none"}]}]},
                    "streamSettings": {
                        "method": "xhttp",
                        "xhttpSettings": {
                            "path": "/x",
                            "mode": "packet-up",
                            "sessionPlacement": "header",
                            "sessionKey": "X-Session",
                            "seqPlacement": "query",
                            "seqKey": "x_seq",
                            "uplinkDataPlacement": "header",
                            "uplinkDataKey": "X-Data",
                            "uplinkHTTPMethod": "POST"
                        }
                    }
                }]
            }"#,
        )
        .unwrap();
        let options = config.xhttp_options();
        assert_eq!(
            options.session_placement,
            super::XhttpMetadataPlacement::Header
        );
        assert_eq!(
            options.sequence_placement,
            super::XhttpMetadataPlacement::Query
        );
        assert_eq!(
            options.uplink_data_placement,
            super::XhttpDataPlacement::Header
        );
        assert_eq!(options.session_key, "X-Session");
        assert_eq!(options.sequence_key, "x_seq");
        assert_eq!(options.uplink_data_key, "X-Data");
        assert_eq!(options.uplink_http_method, "POST");
    }

    #[test]
    fn requested_xray_families_have_startup_validation_paths() {
        let profiles = [
            r#"{"outbounds":[{"protocol":"blackhole","settings":{}}]}"#,
            r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"gateway.example","port":443,"users":[{"id":"00112233-4455-6677-8899-aabbccddeeff","encryption":"none"}]}]},"streamSettings":{"method":"raw","security":"reality","realitySettings":{"publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","shortId":"0123456789abcdef","fingerprint":"chrome","serverName":"www.example.com"}}}]}"#,
            r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"gateway.example","port":443,"users":[{"id":"00112233-4455-6677-8899-aabbccddeeff","encryption":"none"}]}]},"streamSettings":{"method":"xhttp","security":"reality","xhttpSettings":{"path":"/x","mode":"stream-one"},"realitySettings":{"publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","shortId":"0123456789abcdef","fingerprint":"chrome","serverName":"www.example.com"}}}]}"#,
            r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"gateway.example","port":443,"users":[{"id":"00112233-4455-6677-8899-aabbccddeeff","encryption":"none"}]}]},"streamSettings":{"method":"grpc","security":"tls"}}]}"#,
            r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"gateway.example","port":443,"users":[{"id":"00112233-4455-6677-8899-aabbccddeeff","encryption":"none"}]}]},"streamSettings":{"method":"mkcp","security":"none"}}]}"#,
            r#"{"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"gateway.example","port":443},"streamSettings":{"method":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"secret"}}}]}"#,
            r#"{"outbounds":[{"protocol":"shadowsocks","settings":{"address":"gateway.example","port":8388,"method":"chacha20-poly1305","password":"secret"}}]}"#,
            r#"{"outbounds":[{"protocol":"vmess","settings":{"address":"gateway.example","port":443,"id":"00112233-4455-6677-8899-aabbccddeeff","security":"aes-128-gcm"}}]}"#,
            r#"{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":["10.0.0.2/32"],"dns":["10.0.0.1"],"peers":[{"endpoint":"198.51.100.1:51820","publicKey":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}]}}]}"#,
        ];

        for profile in profiles {
            let config = XrayConfig::from_json(profile).unwrap();
            assert!(
                XrayCore::start(config).is_ok(),
                "profile must pass startup validation: {profile}"
            );
        }
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn fuzz_surface_rejects_oversized_transport_input() {
        let oversized = vec![0u8; super::FUZZ_INPUT_LIMIT + 1];
        assert!(super::fuzzing::decode_grpc_messages(&oversized).is_err());
        assert!(super::fuzzing::parse_reality_client_hello(&oversized).is_err());
        assert!(super::fuzzing::parse_reality_server_hello(&oversized).is_err());
    }
}
