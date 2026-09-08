use interprocess::local_socket::{prelude::*, GenericFilePath, Stream as LocalSocketStream};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use url::Url;

const MAX_ENVELOPE: usize = 4 * 1024 * 1024;
const MAX_FIELDS: usize = 8_192;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmcIdentityKind {
    Explicit,
    Alias,
}

impl UmcIdentityKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Explicit => "Explicit endpoint identity",
            Self::Alias => "Human-readable alias",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmcTrustState {
    IdentityAddressed,
    AliasRequiresVerification,
}

impl UmcTrustState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::IdentityAddressed => "Identity-addressed",
            Self::AliasRequiresVerification => "Alias; gateway verification required",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmcPathKind {
    DirectIdentitySession,
    GatewayApplication,
}

impl UmcPathKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DirectIdentitySession => "Direct identity session",
            Self::GatewayApplication => "Authorized gateway application",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmcSessionSecurity {
    AuthenticatedEncrypted,
}

impl UmcSessionSecurity {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AuthenticatedEncrypted => "Authenticated and encrypted UMC session",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmcPeerTrustState {
    Unknown,
    Observed,
    Introduced,
    Trusted,
    Restricted,
    Blocked,
    Revoked,
}

impl UmcPeerTrustState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Observed => "Observed",
            Self::Introduced => "Introduced",
            Self::Trusted => "Trusted",
            Self::Restricted => "Restricted",
            Self::Blocked => "Blocked",
            Self::Revoked => "Revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmcSessionState {
    Unknown,
    Handshaking,
    Active,
    Draining,
    Closed,
    Failed,
}

impl UmcSessionState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Handshaking => "Handshaking",
            Self::Active => "Active",
            Self::Draining => "Draining",
            Self::Closed => "Closed",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcPathDiagnostics {
    path_id: u64,
    state: String,
    carrier_type_id: String,
    estimated_rtt_ms: u64,
    current_mtu: u32,
    primary: bool,
}

impl UmcPathDiagnostics {
    #[must_use]
    pub const fn path_id(&self) -> u64 {
        self.path_id
    }

    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    #[must_use]
    pub fn carrier_type_id(&self) -> &str {
        &self.carrier_type_id
    }

    #[must_use]
    pub const fn estimated_rtt_ms(&self) -> u64 {
        self.estimated_rtt_ms
    }

    #[must_use]
    pub const fn current_mtu(&self) -> u32 {
        self.current_mtu
    }

    #[must_use]
    pub const fn primary(&self) -> bool {
        self.primary
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcSessionPrivacy {
    requested_profile: String,
    effective_profile: String,
    direct_path_allowed: bool,
    traffic_padding_active: bool,
    hop_count: u32,
    anonymous_authorization_active: bool,
    privacy_reason: String,
}

impl UmcSessionPrivacy {
    #[must_use]
    pub fn requested_profile(&self) -> &str {
        &self.requested_profile
    }

    #[must_use]
    pub fn effective_profile(&self) -> &str {
        &self.effective_profile
    }

    #[must_use]
    pub const fn direct_path_allowed(&self) -> bool {
        self.direct_path_allowed
    }

    #[must_use]
    pub const fn traffic_padding_active(&self) -> bool {
        self.traffic_padding_active
    }

    #[must_use]
    pub const fn hop_count(&self) -> u32 {
        self.hop_count
    }

    #[must_use]
    pub const fn anonymous_authorization_active(&self) -> bool {
        self.anonymous_authorization_active
    }

    #[must_use]
    pub fn privacy_reason(&self) -> &str {
        &self.privacy_reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcSessionDiagnostics {
    state: UmcSessionState,
    protocol_id: String,
    active_streams: u32,
    active_paths: u32,
    relayed: bool,
    peer_trust_state: Option<UmcPeerTrustState>,
    paths: Vec<UmcPathDiagnostics>,
    privacy: Option<UmcSessionPrivacy>,
}

impl UmcSessionDiagnostics {
    #[must_use]
    pub const fn state(&self) -> UmcSessionState {
        self.state
    }

    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    #[must_use]
    pub const fn active_streams(&self) -> u32 {
        self.active_streams
    }

    #[must_use]
    pub const fn active_paths(&self) -> u32 {
        self.active_paths
    }

    #[must_use]
    pub const fn relayed(&self) -> bool {
        self.relayed
    }

    #[must_use]
    pub const fn peer_trust_state(&self) -> Option<UmcPeerTrustState> {
        self.peer_trust_state
    }

    #[must_use]
    pub fn paths(&self) -> &[UmcPathDiagnostics] {
        &self.paths
    }

    #[must_use]
    pub const fn privacy(&self) -> Option<&UmcSessionPrivacy> {
        self.privacy.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcDiagnostics {
    protocol_id: String,
    gateway_configured: bool,
    active_streams: u32,
    active_application_sessions: usize,
    last_session: Option<UmcSessionDiagnostics>,
    last_error: Option<String>,
}

impl UmcDiagnostics {
    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    #[must_use]
    pub const fn gateway_configured(&self) -> bool {
        self.gateway_configured
    }

    #[must_use]
    pub const fn active_streams(&self) -> u32 {
        self.active_streams
    }

    #[must_use]
    pub const fn active_application_sessions(&self) -> usize {
        self.active_application_sessions
    }

    #[must_use]
    pub const fn last_session(&self) -> Option<&UmcSessionDiagnostics> {
        self.last_session.as_ref()
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

/// Snapshot of one browser-owned UMC application session.
#[cfg(any(unix, windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcApplicationSnapshot {
    tab_id: u64,
    protocol_id: String,
    state: UmcSessionState,
    active_streams: usize,
    active_paths: u32,
    relayed: bool,
    peer_trust_state: Option<UmcPeerTrustState>,
}

#[cfg(any(unix, windows))]
impl UmcApplicationSnapshot {
    #[must_use]
    pub const fn tab_id(&self) -> u64 {
        self.tab_id
    }

    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    #[must_use]
    pub const fn state(&self) -> UmcSessionState {
        self.state
    }

    #[must_use]
    pub const fn active_streams(&self) -> usize {
        self.active_streams
    }

    #[must_use]
    pub const fn active_paths(&self) -> u32 {
        self.active_paths
    }

    #[must_use]
    pub const fn relayed(&self) -> bool {
        self.relayed
    }

    #[must_use]
    pub const fn peer_trust_state(&self) -> Option<UmcPeerTrustState> {
        self.peer_trust_state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UmcSecurityInfo {
    identity_kind: UmcIdentityKind,
    trust_state: UmcTrustState,
    path_kind: UmcPathKind,
    session_security: UmcSessionSecurity,
}

impl UmcSecurityInfo {
    #[must_use]
    pub const fn identity_kind(self) -> UmcIdentityKind {
        self.identity_kind
    }

    #[must_use]
    pub const fn trust_state(self) -> UmcTrustState {
        self.trust_state
    }

    #[must_use]
    pub const fn path_kind(self) -> UmcPathKind {
        self.path_kind
    }

    #[must_use]
    pub const fn session_security(self) -> UmcSessionSecurity {
        self.session_security
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcResourceInfo {
    service_identity: String,
    path: String,
    port: u16,
    endpoint_id: Option<[u8; 32]>,
}

impl UmcResourceInfo {
    /// Parses an identity-addressed UMC resource URL.
    ///
    /// UMC service identities are kept as URL host text so aliases remain
    /// usable, while a 64-character hexadecimal host is recognized as an
    /// explicit 32-byte identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not a UMC URL or has no service host.
    pub fn from_url(url: &Url) -> Result<Self, UmcUrlError> {
        if url.scheme() != "umc" {
            return Err(UmcUrlError::UnsupportedScheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(UmcUrlError::CredentialsNotAllowed);
        }
        let service_identity = url
            .host_str()
            .ok_or(UmcUrlError::MissingServiceIdentity)?
            .to_owned();
        let endpoint_id = endpoint_id_from_identity(&service_identity);
        Ok(Self {
            service_identity,
            path: url.path().to_owned(),
            port: url.port().unwrap_or(80),
            endpoint_id,
        })
    }

    #[must_use]
    pub fn service_identity(&self) -> &str {
        &self.service_identity
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn has_explicit_identity(&self) -> bool {
        self.endpoint_id.is_some()
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Option<&[u8; 32]> {
        self.endpoint_id.as_ref()
    }

    #[must_use]
    pub const fn identity_kind(&self) -> UmcIdentityKind {
        if self.endpoint_id.is_some() {
            UmcIdentityKind::Explicit
        } else {
            UmcIdentityKind::Alias
        }
    }

    #[must_use]
    pub const fn trust_state(&self) -> UmcTrustState {
        if self.endpoint_id.is_some() {
            UmcTrustState::IdentityAddressed
        } else {
            UmcTrustState::AliasRequiresVerification
        }
    }

    #[must_use]
    pub const fn path_kind(&self) -> UmcPathKind {
        if self.endpoint_id.is_some() {
            UmcPathKind::DirectIdentitySession
        } else {
            UmcPathKind::GatewayApplication
        }
    }

    #[must_use]
    pub const fn security_info(&self) -> UmcSecurityInfo {
        UmcSecurityInfo {
            identity_kind: self.identity_kind(),
            trust_state: self.trust_state(),
            path_kind: self.path_kind(),
            session_security: UmcSessionSecurity::AuthenticatedEncrypted,
        }
    }

    #[must_use]
    pub fn stream_target(&self) -> String {
        if self.service_identity.contains(':') {
            format!("[{}]:{}", self.service_identity, self.port)
        } else {
            format!("{}:{}", self.service_identity, self.port)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmcUrlError {
    UnsupportedScheme,
    MissingServiceIdentity,
    CredentialsNotAllowed,
}

impl std::fmt::Display for UmcUrlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedScheme => formatter.write_str("URL is not a UMC resource"),
            Self::MissingServiceIdentity => formatter.write_str("UMC URL has no service identity"),
            Self::CredentialsNotAllowed => {
                formatter.write_str("UMC resource URLs cannot contain credentials")
            }
        }
    }
}

impl std::error::Error for UmcUrlError {}

/// Converts an identity-addressed UMC URL into the HTTP resource carried by
/// the authenticated UMC application stream.
///
/// # Errors
///
/// Returns [`UmcUrlError`] when the URL is not a valid UMC resource.
pub fn transport_url(url: &Url) -> Result<Url, UmcUrlError> {
    let _info = UmcResourceInfo::from_url(url)?;
    let suffix = url
        .as_str()
        .strip_prefix("umc")
        .ok_or(UmcUrlError::UnsupportedScheme)?;
    Url::parse(&format!("http{suffix}")).map_err(|_| UmcUrlError::UnsupportedScheme)
}

fn endpoint_id_from_identity(identity: &str) -> Option<[u8; 32]> {
    if identity.len() != 64 {
        return None;
    }
    let mut endpoint_id = [0u8; 32];
    for (index, pair) in identity.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        endpoint_id[index] = (high << 4) | low;
    }
    Some(endpoint_id)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct Field {
    number: u32,
    wire: u8,
    bytes: Vec<u8>,
    value: u64,
}

fn varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push(u8::try_from(value & 0x7f).expect("varint chunk fits") | 0x80);
        value >>= 7;
    }
    output.push(u8::try_from(value).expect("final varint chunk fits"));
}

fn field_key(number: u32, wire: u8, output: &mut Vec<u8>) {
    varint((u64::from(number) << 3) | u64::from(wire), output);
}

fn field_varint(number: u32, value: u64, output: &mut Vec<u8>) {
    field_key(number, 0, output);
    varint(value, output);
}

fn field_bytes(number: u32, bytes: &[u8], output: &mut Vec<u8>) {
    field_key(number, 2, output);
    varint(bytes.len() as u64, output);
    output.extend_from_slice(bytes);
}

fn field_string(number: u32, value: &str, output: &mut Vec<u8>) {
    field_bytes(number, value.as_bytes(), output);
}

fn field_message(number: u32, message: &[u8], output: &mut Vec<u8>) {
    field_bytes(number, message, output);
}

fn read_varint(input: &[u8], offset: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *input
            .get(*offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf varint"))?;
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "protobuf varint",
    ))
}

fn fields(input: &[u8]) -> io::Result<Vec<Field>> {
    let mut offset = 0;
    let mut output = Vec::new();
    while offset < input.len() {
        let key = read_varint(input, &mut offset)?;
        let number = u32::try_from(key >> 3)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "protobuf field"))?;
        let wire = u8::try_from(key & 0x07).unwrap_or(u8::MAX);
        let (bytes, value) = match wire {
            0 => {
                let start = offset;
                let value = read_varint(input, &mut offset)?;
                (input[start..offset].to_vec(), value)
            }
            1 => {
                let end = offset
                    .checked_add(8)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "protobuf field"))?;
                let bytes = input
                    .get(offset..end)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf fixed64")
                    })?
                    .to_vec();
                offset = end;
                (bytes, 0)
            }
            2 => {
                let length = usize::try_from(read_varint(input, &mut offset)?)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "protobuf length"))?;
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "protobuf field"))?;
                let bytes = input
                    .get(offset..end)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf bytes"))?
                    .to_vec();
                offset = end;
                (bytes, 0)
            }
            5 => {
                let end = offset
                    .checked_add(4)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "protobuf field"))?;
                let bytes = input
                    .get(offset..end)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf fixed32")
                    })?
                    .to_vec();
                offset = end;
                (bytes, 0)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf wire type",
                ));
            }
        };
        if output.len() >= MAX_FIELDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protobuf field count",
            ));
        }
        output.push(Field {
            number,
            wire,
            bytes,
            value,
        });
    }
    Ok(output)
}

fn message_field(input: &[u8], number: u32) -> io::Result<Option<Vec<u8>>> {
    Ok(fields(input)?
        .into_iter()
        .find(|field| field.number == number && field.wire == 2)
        .map(|field| field.bytes))
}

fn varint_field(input: &[u8], number: u32) -> io::Result<Option<u64>> {
    Ok(fields(input)?
        .into_iter()
        .find(|field| field.number == number && field.wire == 0)
        .map(|field| field.value))
}

fn parse_session_summary(input: &[u8]) -> io::Result<UmcSessionDiagnostics> {
    let state = match varint_field(input, 4)?.unwrap_or(0) {
        1 => UmcSessionState::Handshaking,
        2 => UmcSessionState::Active,
        3 => UmcSessionState::Draining,
        4 => UmcSessionState::Closed,
        5 => UmcSessionState::Failed,
        _ => UmcSessionState::Unknown,
    };
    let protocol_id = message_field(input, 5)?
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "UMC session protocol"))?
        .unwrap_or_default();
    Ok(UmcSessionDiagnostics {
        state,
        protocol_id,
        active_streams: u32::try_from(varint_field(input, 6)?.unwrap_or(0)).unwrap_or(u32::MAX),
        active_paths: u32::try_from(varint_field(input, 7)?.unwrap_or(0)).unwrap_or(u32::MAX),
        relayed: varint_field(input, 10)?.unwrap_or(0) != 0,
        peer_trust_state: None,
        paths: Vec::new(),
        privacy: None,
    })
}

fn parse_session_response(input: &[u8]) -> io::Result<UmcSessionDiagnostics> {
    let summary = message_field(input, 1)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UMC session summary missing"))?;
    let mut parsed = parse_session_summary(&summary)?;
    let paths = fields(input)?
        .into_iter()
        .filter(|field| field.number == 2 && field.wire == 2)
        .map(|field| parse_path_summary(&field.bytes))
        .collect::<io::Result<Vec<_>>>()?;
    let path_count = paths.len();
    if parsed.active_paths < u32::try_from(path_count).unwrap_or(u32::MAX) {
        parsed.active_paths = u32::try_from(path_count).unwrap_or(u32::MAX);
    }
    parsed.paths = paths;
    parsed.privacy = message_field(input, 3)?
        .map(|message| parse_session_privacy(&message))
        .transpose()?;
    Ok(parsed)
}

fn parse_path_summary(input: &[u8]) -> io::Result<UmcPathDiagnostics> {
    Ok(UmcPathDiagnostics {
        path_id: varint_field(input, 1)?.unwrap_or(0),
        state: string_field(input, 2, "UMC path state")?,
        carrier_type_id: string_field(input, 3, "UMC path carrier")?,
        estimated_rtt_ms: varint_field(input, 4)?.unwrap_or(0),
        current_mtu: u32::try_from(varint_field(input, 5)?.unwrap_or(0)).unwrap_or(u32::MAX),
        primary: varint_field(input, 6)?.unwrap_or(0) != 0,
    })
}

fn parse_session_privacy(input: &[u8]) -> io::Result<UmcSessionPrivacy> {
    Ok(UmcSessionPrivacy {
        requested_profile: string_field(input, 1, "UMC requested privacy profile")?,
        effective_profile: string_field(input, 2, "UMC effective privacy profile")?,
        direct_path_allowed: varint_field(input, 3)?.unwrap_or(0) != 0,
        traffic_padding_active: varint_field(input, 4)?.unwrap_or(0) != 0,
        hop_count: u32::try_from(varint_field(input, 5)?.unwrap_or(0)).unwrap_or(u32::MAX),
        anonymous_authorization_active: varint_field(input, 8)?.unwrap_or(0) != 0,
        privacy_reason: string_field(input, 9, "UMC privacy reason")?,
    })
}

fn string_field(input: &[u8], number: u32, label: &'static str) -> io::Result<String> {
    message_field(input, number)?
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, label))
        .map(Option::unwrap_or_default)
}

fn send_datagram_request(
    session_handle: &[u8],
    context_id: u64,
    data: &[u8],
    lifetime_ms: u64,
    request_ack: bool,
) -> Vec<u8> {
    let mut request = Vec::new();
    handle_field(1, session_handle, &mut request);
    field_varint(2, context_id, &mut request);
    field_bytes(3, data, &mut request);
    field_varint(4, lifetime_ms, &mut request);
    if request_ack {
        field_varint(5, 1, &mut request);
    }
    request
}

const fn peer_trust_state(value: u64) -> Option<UmcPeerTrustState> {
    match value {
        1 => Some(UmcPeerTrustState::Unknown),
        2 => Some(UmcPeerTrustState::Observed),
        3 => Some(UmcPeerTrustState::Introduced),
        4 => Some(UmcPeerTrustState::Trusted),
        5 => Some(UmcPeerTrustState::Restricted),
        6 => Some(UmcPeerTrustState::Blocked),
        7 => Some(UmcPeerTrustState::Revoked),
        _ => None,
    }
}

fn envelope(version: &[u8], sequence: u64, body_number: u32, body: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    field_message(1, version, &mut output);
    field_varint(2, sequence, &mut output);
    field_message(body_number, body, &mut output);
    output
}

fn api_version() -> Vec<u8> {
    let mut output = Vec::new();
    field_varint(1, 1, &mut output);
    field_varint(2, 0, &mut output);
    output
}

/// A small exact-wire Control API envelope used for the UMC integration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEnvelope(Vec<u8>);

/// Errors returned when attacker-controlled UMC protobuf bytes are decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlEnvelopeError {
    Empty,
    TooLarge,
    Malformed,
}

impl ControlEnvelope {
    /// Create the OS-peer-authenticated UMC client hello.
    #[must_use]
    pub fn client_hello(client_name: &str) -> Self {
        let mut hello = Vec::new();
        field_message(1, &api_version(), &mut hello);
        field_string(2, client_name, &mut hello);
        field_varint(4, 2, &mut hello);
        let mut auth = Vec::new();
        field_message(1, &[], &mut auth);
        field_message(5, &auth, &mut hello);
        field_varint(6, MAX_ENVELOPE as u64, &mut hello);
        Self(envelope(&api_version(), 1, 10, &hello))
    }

    /// Return the protobuf bytes without the local transport frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Validates and retains a bounded UMC Control API envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or malformed protobuf
    /// envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ControlEnvelopeError> {
        if bytes.is_empty() {
            return Err(ControlEnvelopeError::Empty);
        }
        if bytes.len() > MAX_ENVELOPE {
            return Err(ControlEnvelopeError::TooLarge);
        }
        fields(bytes).map_err(|_| ControlEnvelopeError::Malformed)?;
        Ok(Self(bytes.to_vec()))
    }
}

#[derive(Debug)]
enum ControlError {
    Io(io::Error),
    Status(i32),
    Protocol(&'static str),
}

impl From<io::Error> for ControlError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Status(code) => write!(formatter, "UMC Control API status {code}"),
            Self::Protocol(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ControlError {}

/// Errors produced by the embedded UMC application-stream adapter.
#[derive(Debug)]
pub enum UmcError {
    /// The UMC route configuration is incomplete or malformed.
    InvalidConfig(String),
    /// A local listener or Control API operation failed.
    Io(io::Error),
    /// The UMC daemon rejected or could not complete a Control API operation.
    Control(String),
}

impl From<io::Error> for UmcError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for UmcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) | Self::Control(error) => formatter.write_str(error),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for UmcError {}

#[cfg(any(unix, windows))]
struct UmcControlClient {
    stream: LocalSocketStream,
    sequence: u64,
    request_id: u64,
    envelope_max: usize,
    application_handle: Vec<u8>,
    protocol_id: String,
}

#[cfg(any(unix, windows))]
impl UmcControlClient {
    fn connect(
        socket: &Path,
        protocol_id: &str,
        allow_datagrams: bool,
    ) -> Result<Self, ControlError> {
        let socket_path = socket.to_string_lossy();
        let socket_name = socket_path
            .as_ref()
            .to_fs_name::<GenericFilePath>()
            .map_err(|error| {
                ControlError::Io(io::Error::new(io::ErrorKind::InvalidInput, error))
            })?;
        let stream = LocalSocketStream::connect(socket_name)?;
        stream.set_recv_timeout(Some(CONTROL_IO_TIMEOUT))?;
        stream.set_send_timeout(Some(CONTROL_IO_TIMEOUT))?;
        let mut client = Self {
            stream,
            sequence: 1,
            request_id: 0,
            envelope_max: MAX_ENVELOPE,
            application_handle: Vec::new(),
            protocol_id: protocol_id.to_owned(),
        };
        client.hello()?;
        client.register_application(allow_datagrams)?;
        Ok(client)
    }

    fn hello(&mut self) -> Result<(), ControlError> {
        let hello = ControlEnvelope::client_hello("nomad-browser");
        self.send(&hello.encode())?;
        let body = self.receive_body(11)?;
        let selected = message_field(&body, 1)?.ok_or(ControlError::Protocol("UMC version"))?;
        if varint_field(&selected, 1)? != Some(1) || varint_field(&selected, 2)? != Some(0) {
            return Err(ControlError::Protocol("UMC API version mismatch"));
        }
        if let Some(max) = varint_field(&body, 7)? {
            self.envelope_max = usize::try_from(max)
                .map_err(|_| ControlError::Protocol("UMC envelope limit"))?
                .min(MAX_ENVELOPE);
        }
        Ok(())
    }

    fn register_application(&mut self, allow_datagrams: bool) -> Result<(), ControlError> {
        let mut request = Vec::new();
        field_string(1, "Nomad Browser", &mut request);
        field_string(4, &self.protocol_id, &mut request);
        field_varint(5, 30, &mut request);
        field_varint(5, 50, &mut request);
        field_varint(5, 80, &mut request);
        field_varint(5, 81, &mut request);
        field_varint(5, 83, &mut request);
        if allow_datagrams {
            field_varint(5, 84, &mut request);
        }
        let body = self.request("ApplicationService", "RegisterApplication", &request)?;
        let handle = message_field(&body, 1)?
            .and_then(|message| message_field(&message, 1).ok().flatten())
            .ok_or(ControlError::Protocol("UMC application handle"))?;
        self.application_handle = handle;
        Ok(())
    }

    fn connect_session(
        &mut self,
        destination_hint: &[u8],
        allow_datagrams: bool,
    ) -> Result<(Vec<u8>, UmcSessionDiagnostics), ControlError> {
        let mut connect = Vec::new();
        handle_field(1, &self.application_handle, &mut connect);
        field_bytes(3, destination_hint, &mut connect);
        field_string(4, &self.protocol_id, &mut connect);
        let mut route = Vec::new();
        field_varint(1, 4, &mut route);
        field_varint(4, 1, &mut route);
        field_varint(7, 2, &mut route);
        let mut policy = Vec::new();
        field_message(1, &route, &mut policy);
        field_varint(2, 1, &mut policy);
        if allow_datagrams {
            field_varint(4, 1, &mut policy);
        }
        field_message(5, &policy, &mut connect);
        let response = self.request("ApplicationService", "Connect", &connect)?;
        let session = message_field(&response, 1)?
            .and_then(|message| message_field(&message, 1).ok().flatten())
            .ok_or(ControlError::Protocol("UMC session handle"))?;
        let session_summary = message_field(&response, 3)?
            .map(|message| parse_session_summary(&message))
            .transpose()?
            .unwrap_or_else(|| UmcSessionDiagnostics {
                state: UmcSessionState::Unknown,
                protocol_id: self.protocol_id.clone(),
                active_streams: 0,
                active_paths: 0,
                relayed: false,
                peer_trust_state: None,
                paths: Vec::new(),
                privacy: None,
            });
        Ok((session, session_summary))
    }

    fn open_stream(
        &mut self,
        destination_hint: &[u8],
        target: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, UmcSessionDiagnostics), ControlError> {
        let (session, session_summary) = self.connect_session(destination_hint, false)?;

        let mut open = Vec::new();
        handle_field(1, &self.application_handle, &mut open);
        handle_field(2, &session, &mut open);
        field_bytes(4, target.as_bytes(), &mut open);
        let response = self.request("ApplicationService", "OpenStream", &open)?;
        let stream = message_field(&response, 1)?
            .and_then(|message| message_field(&message, 1).ok().flatten())
            .ok_or(ControlError::Protocol("UMC stream handle"))?;
        Ok((stream, session, session_summary))
    }

    fn open_application_stream(
        &mut self,
        session: &[u8],
        initial_metadata: &[u8],
    ) -> Result<Vec<u8>, ControlError> {
        let mut open = Vec::new();
        handle_field(1, &self.application_handle, &mut open);
        handle_field(2, session, &mut open);
        field_bytes(4, initial_metadata, &mut open);
        let response = self.request("ApplicationService", "OpenStream", &open)?;
        message_field(&response, 1)?
            .and_then(|message| message_field(&message, 1).ok().flatten())
            .ok_or(ControlError::Protocol("UMC stream handle"))
    }

    fn get_session(&mut self, session: &[u8]) -> Result<UmcSessionDiagnostics, ControlError> {
        let mut request = Vec::new();
        handle_field(1, session, &mut request);
        let response = self.request("SessionService", "GetSession", &request)?;
        parse_session_response(&response).map_err(ControlError::Io)
    }

    fn send_datagram(
        &mut self,
        session: &[u8],
        context_id: u64,
        data: &[u8],
        lifetime_ms: u64,
        request_ack: bool,
    ) -> Result<u64, ControlError> {
        let request = send_datagram_request(session, context_id, data, lifetime_ms, request_ack);
        let response = self.request("ApplicationService", "SendDatagram", &request)?;
        Ok(varint_field(&response, 1)?.unwrap_or(0))
    }

    fn receive_datagram(
        &mut self,
        session: &[u8],
        maximum_bytes: usize,
        wait_for_data: bool,
    ) -> Result<Option<UmcDatagram>, ControlError> {
        let mut request = Vec::new();
        handle_field(1, &self.application_handle, &mut request);
        handle_field(2, session, &mut request);
        field_varint(
            3,
            u64::try_from(maximum_bytes.min(32 * 1024)).unwrap_or(u64::MAX),
            &mut request,
        );
        if wait_for_data {
            field_varint(4, 1, &mut request);
        }
        let response = match self.request("ApplicationService", "ReceiveDatagram", &request) {
            Ok(response) => response,
            Err(ControlError::Status(15)) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(UmcDatagram {
            context_id: varint_field(&response, 2)?.unwrap_or(0),
            data: message_field(&response, 3)?.unwrap_or_default(),
            expired: varint_field(&response, 4)?.unwrap_or(0) != 0,
        }))
    }

    fn peer_trust_state(
        &mut self,
        endpoint_id: &[u8; 32],
    ) -> Result<Option<UmcPeerTrustState>, ControlError> {
        let mut request = Vec::new();
        field_bytes(1, endpoint_id, &mut request);
        let response = self.request("PeerService", "GetPeer", &request)?;
        let peer = message_field(&response, 1)?.ok_or(ControlError::Protocol("UMC peer"))?;
        let value = varint_field(&peer, 3)?.unwrap_or(0);
        Ok(peer_trust_state(value))
    }

    fn write_stream(
        &mut self,
        stream: &[u8],
        data: &[u8],
        fin: bool,
    ) -> Result<usize, ControlError> {
        let mut request = Vec::new();
        handle_field(1, stream, &mut request);
        field_bytes(2, data, &mut request);
        if fin {
            field_varint(3, 1, &mut request);
        }
        let response = self.request("ApplicationService", "WriteStream", &request)?;
        Ok(usize::try_from(varint_field(&response, 1)?.unwrap_or(0)).unwrap_or(usize::MAX))
    }

    fn read_stream(
        &mut self,
        stream: &[u8],
        maximum_bytes: usize,
    ) -> Result<ReadResult, ControlError> {
        let mut request = Vec::new();
        handle_field(1, stream, &mut request);
        field_varint(2, maximum_bytes.min(32 * 1024) as u64, &mut request);
        let response = match self.request("ApplicationService", "ReadStream", &request) {
            Ok(response) => response,
            Err(ControlError::Status(15)) => return Ok(ReadResult::NoData),
            Err(error) => return Err(error),
        };
        Ok(ReadResult::Data {
            bytes: message_field(&response, 1)?.unwrap_or_default(),
            eof: varint_field(&response, 2)?.unwrap_or(0) != 0,
            reset: varint_field(&response, 3)?.unwrap_or(0) != 0,
        })
    }

    fn close_stream(&mut self, stream: &[u8]) -> Result<(), ControlError> {
        let mut request = Vec::new();
        handle_field(1, stream, &mut request);
        let _ = self.request("ApplicationService", "CloseStreamSend", &request)?;
        Ok(())
    }

    fn request(
        &mut self,
        service: &str,
        method: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, ControlError> {
        self.request_id = self.request_id.saturating_add(1);
        let mut request = Vec::new();
        field_varint(1, self.request_id, &mut request);
        field_string(2, service, &mut request);
        field_string(3, method, &mut request);
        field_bytes(6, payload, &mut request);
        let mut bytes = Vec::new();
        field_message(1, &api_version(), &mut bytes);
        field_varint(2, self.next_sequence(), &mut bytes);
        field_message(12, &request, &mut bytes);
        self.send(&bytes)?;
        let response = self.receive_body(13)?;
        let response_id = varint_field(&response, 1)?.unwrap_or(0);
        if response_id != self.request_id {
            return Err(ControlError::Protocol("UMC response correlation"));
        }
        let status = message_field(&response, 2)?
            .map(|status| varint_field(&status, 1))
            .transpose()?
            .flatten()
            .unwrap_or(0);
        if status != 0 {
            return Err(ControlError::Status(
                i32::try_from(status).unwrap_or(i32::MAX),
            ));
        }
        Ok(message_field(&response, 3)?.unwrap_or_default())
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), ControlError> {
        let framed = Self::frame_with_max(bytes, self.envelope_max)?;
        self.stream.write_all(&framed)?;
        self.stream.flush()?;
        Ok(())
    }

    fn receive_body(&mut self, expected_number: u32) -> Result<Vec<u8>, ControlError> {
        let mut length = [0u8; 4];
        self.stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > self.envelope_max {
            return Err(ControlError::Protocol("UMC envelope size"));
        }
        let mut bytes = vec![0u8; length];
        self.stream.read_exact(&mut bytes)?;
        message_field(&bytes, expected_number)?.ok_or(ControlError::Protocol("UMC response body"))
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        sequence
    }

    #[cfg(test)]
    fn frame(bytes: &[u8]) -> io::Result<Vec<u8>> {
        Self::frame_with_max(bytes, MAX_ENVELOPE)
    }

    fn frame_with_max(bytes: &[u8], maximum: usize) -> io::Result<Vec<u8>> {
        if bytes.is_empty() || bytes.len() > maximum || bytes.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UMC envelope size",
            ));
        }
        let mut output = Vec::with_capacity(bytes.len() + 4);
        let length = u32::try_from(bytes.len()).expect("envelope size is bounded");
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(bytes);
        Ok(output)
    }
}

impl From<ControlError> for UmcError {
    fn from(error: ControlError) -> Self {
        Self::Control(error.to_string())
    }
}

/// A generic UMC application session for stream and datagram protocols.
#[cfg(any(unix, windows))]
pub struct UmcApplicationSession {
    client: UmcControlClient,
    session_handle: Vec<u8>,
    diagnostics: UmcSessionDiagnostics,
}

#[cfg(any(unix, windows))]
impl UmcApplicationSession {
    /// Connect an application session with stream and datagram capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error when the local Control API cannot be reached, rejects
    /// the requested capabilities, or cannot establish the session.
    pub fn connect(
        socket: impl AsRef<Path>,
        protocol_id: impl Into<String>,
        destination_hint: &[u8],
    ) -> Result<Self, UmcError> {
        let protocol_id = protocol_id.into();
        let mut client = UmcControlClient::connect(socket.as_ref(), &protocol_id, true)?;
        let (session_handle, diagnostics) = client.connect_session(destination_hint, true)?;
        Ok(Self {
            client,
            session_handle,
            diagnostics,
        })
    }

    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.client.protocol_id
    }

    /// Return the most recently received session diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> &UmcSessionDiagnostics {
        &self.diagnostics
    }

    #[must_use]
    pub fn session_handle(&self) -> &[u8] {
        &self.session_handle
    }

    /// Refresh the daemon-reported session and path summary.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon rejects the session query or the
    /// response is malformed.
    pub fn refresh_diagnostics(&mut self) -> Result<&UmcSessionDiagnostics, UmcError> {
        self.diagnostics = self.client.get_session(&self.session_handle)?;
        Ok(&self.diagnostics)
    }

    /// Open a bidirectional application stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon rejects the stream or the response is
    /// malformed.
    pub fn open_stream(
        &mut self,
        initial_metadata: &[u8],
    ) -> Result<UmcApplicationStream, UmcError> {
        let handle = self
            .client
            .open_application_stream(&self.session_handle, initial_metadata)?;
        Ok(UmcApplicationStream { handle })
    }

    /// Write bytes to an application stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon rejects the write or the response is
    /// malformed.
    pub fn write_stream(
        &mut self,
        stream: &UmcApplicationStream,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, UmcError> {
        Ok(self.client.write_stream(stream.handle(), data, fin)?)
    }

    /// Read bytes from an application stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon rejects the read or the response is
    /// malformed.
    pub fn read_stream(
        &mut self,
        stream: &UmcApplicationStream,
        maximum_bytes: usize,
    ) -> Result<Option<UmcStreamRead>, UmcError> {
        match self.client.read_stream(stream.handle(), maximum_bytes)? {
            ReadResult::Data { bytes, eof, reset } => Ok(Some(UmcStreamRead { bytes, eof, reset })),
            ReadResult::NoData => Ok(None),
        }
    }

    /// Close the sending side of an application stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon rejects the close request.
    pub fn close_stream(&mut self, stream: &UmcApplicationStream) -> Result<(), UmcError> {
        Ok(self.client.close_stream(stream.handle())?)
    }

    /// Send one application datagram.
    ///
    /// # Errors
    ///
    /// Returns an error when datagrams were not granted or the daemon rejects
    /// the datagram.
    pub fn send_datagram(
        &mut self,
        context_id: u64,
        data: &[u8],
        lifetime_ms: u64,
        request_ack: bool,
    ) -> Result<u64, UmcError> {
        Ok(self.client.send_datagram(
            &self.session_handle,
            context_id,
            data,
            lifetime_ms,
            request_ack,
        )?)
    }

    /// Receive one application datagram, optionally waiting for data.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon rejects the receive request or the
    /// response is malformed.
    pub fn receive_datagram(
        &mut self,
        maximum_bytes: usize,
        wait_for_data: bool,
    ) -> Result<Option<UmcDatagram>, UmcError> {
        Ok(self
            .client
            .receive_datagram(&self.session_handle, maximum_bytes, wait_for_data)?)
    }

    fn close_session(&mut self) -> Result<(), ControlError> {
        let mut request = Vec::new();
        handle_field(1, &self.session_handle, &mut request);
        let _ = self
            .client
            .request("SessionService", "CloseSession", &request)?;
        Ok(())
    }
}

#[cfg(any(unix, windows))]
impl Drop for UmcApplicationSession {
    fn drop(&mut self) {
        let _ = self.close_session();
    }
}

fn handle_field(number: u32, value: &[u8], output: &mut Vec<u8>) {
    let mut handle = Vec::new();
    field_bytes(1, value, &mut handle);
    field_message(number, &handle, output);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcDatagram {
    context_id: u64,
    data: Vec<u8>,
    expired: bool,
}

impl UmcDatagram {
    #[must_use]
    pub const fn context_id(&self) -> u64 {
        self.context_id
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub const fn expired(&self) -> bool {
        self.expired
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcApplicationStream {
    handle: Vec<u8>,
}

impl UmcApplicationStream {
    #[must_use]
    pub fn handle(&self) -> &[u8] {
        &self.handle
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmcStreamRead {
    bytes: Vec<u8>,
    eof: bool,
    reset: bool,
}

impl UmcStreamRead {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn eof(&self) -> bool {
        self.eof
    }

    #[must_use]
    pub const fn reset(&self) -> bool {
        self.reset
    }
}

#[cfg(any(unix, windows))]
struct UmcApplicationSlot {
    session: UmcApplicationSession,
    streams: HashMap<u64, UmcApplicationStream>,
    destination_hint: Vec<u8>,
}

/// Browser-owned UMC application sessions, keyed by Nomad tab identity.
///
/// Web navigation uses [`UmcCore`] as a local SOCKS route. This bridge is the
/// complementary native application surface: it gives a tab an authenticated
/// UMC session with bidirectional streams and datagrams without exposing the
/// daemon socket or private credentials to page content.
#[cfg(any(unix, windows))]
pub struct UmcApplicationBridge {
    socket: PathBuf,
    protocol_id: String,
    default_destination_hint: Vec<u8>,
    sessions: HashMap<u64, UmcApplicationSlot>,
    next_stream_id: u64,
}

#[cfg(any(unix, windows))]
impl UmcApplicationBridge {
    /// Create an empty application bridge for one local UMC Control API.
    ///
    /// # Errors
    ///
    /// Returns an error when the protocol identifier is empty.
    pub fn new(
        socket: impl Into<PathBuf>,
        protocol_id: impl Into<String>,
        default_destination_hint: Vec<u8>,
    ) -> Result<Self, UmcError> {
        let protocol_id = protocol_id.into();
        if protocol_id.is_empty() {
            return Err(UmcError::InvalidConfig(
                "UMC application protocol id is empty".to_owned(),
            ));
        }
        Ok(Self {
            socket: socket.into(),
            protocol_id,
            default_destination_hint,
            sessions: HashMap::new(),
            next_stream_id: 1,
        })
    }

    /// Connect or reuse the application session associated with a tab.
    ///
    /// An empty destination uses the configured gateway hint. Explicit UMC
    /// identities should pass their endpoint bytes here so aliases never
    /// silently replace identity-addressed routing. A stale, failed, or
    /// differently addressed session is replaced.
    ///
    /// # Errors
    ///
    /// Returns an error when the Control API rejects the session or the
    /// response is malformed.
    pub fn connect(
        &mut self,
        tab_id: u64,
        destination_hint: &[u8],
    ) -> Result<UmcApplicationSnapshot, UmcError> {
        let destination_hint = if destination_hint.is_empty() {
            self.default_destination_hint.clone()
        } else {
            destination_hint.to_vec()
        };
        if self.sessions.get(&tab_id).is_some_and(|slot| {
            slot.destination_hint == destination_hint
                && !matches!(
                    slot.session.diagnostics().state(),
                    UmcSessionState::Closed | UmcSessionState::Failed
                )
        }) {
            return self.snapshot(tab_id).ok_or_else(|| {
                UmcError::InvalidConfig("UMC application session was not retained".to_owned())
            });
        }
        self.sessions.remove(&tab_id);
        let session = UmcApplicationSession::connect(
            &self.socket,
            self.protocol_id.clone(),
            &destination_hint,
        )?;
        self.sessions.insert(
            tab_id,
            UmcApplicationSlot {
                session,
                streams: HashMap::new(),
                destination_hint,
            },
        );
        self.snapshot(tab_id).ok_or_else(|| {
            UmcError::InvalidConfig("UMC application session was not retained".to_owned())
        })
    }

    /// Close and forget the application session associated with a tab.
    pub fn close(&mut self, tab_id: u64) {
        self.sessions.remove(&tab_id);
    }

    /// Return the current local snapshot for a tab.
    #[must_use]
    pub fn snapshot(&self, tab_id: u64) -> Option<UmcApplicationSnapshot> {
        self.sessions
            .get(&tab_id)
            .map(|slot| snapshot_application_slot(tab_id, slot))
    }

    /// Return snapshots for all tabs with native UMC application sessions.
    #[must_use]
    pub fn snapshots(&self) -> Vec<UmcApplicationSnapshot> {
        self.sessions
            .iter()
            .map(|(&tab_id, slot)| snapshot_application_slot(tab_id, slot))
            .collect()
    }

    /// Refresh daemon-backed diagnostics for one tab's application session.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no application session or the Control
    /// API rejects the session query.
    pub fn refresh(&mut self, tab_id: u64) -> Result<UmcApplicationSnapshot, UmcError> {
        let slot = self.slot_mut(tab_id)?;
        slot.session.refresh_diagnostics()?;
        Ok(snapshot_application_slot(tab_id, slot))
    }

    /// Open a stream inside a tab's application session and return its local id.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no application session or the Control
    /// API rejects the stream.
    pub fn open_stream(&mut self, tab_id: u64, initial_metadata: &[u8]) -> Result<u64, UmcError> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.saturating_add(1);
        let slot = self.slot_mut(tab_id)?;
        let stream = slot.session.open_stream(initial_metadata)?;
        slot.streams.insert(stream_id, stream);
        Ok(stream_id)
    }

    /// Write application bytes for a tab-owned stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab or stream is unknown, or when the Control
    /// API rejects the write.
    pub fn write_stream(
        &mut self,
        tab_id: u64,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, UmcError> {
        let slot = self.slot_mut(tab_id)?;
        let stream = slot.streams.get(&stream_id).ok_or_else(|| {
            UmcError::InvalidConfig(format!("UMC stream {stream_id} is not open"))
        })?;
        slot.session.write_stream(stream, data, fin)
    }

    /// Read application bytes for a tab-owned stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab or stream is unknown, or when the Control
    /// API rejects the read.
    pub fn read_stream(
        &mut self,
        tab_id: u64,
        stream_id: u64,
        maximum_bytes: usize,
    ) -> Result<Option<UmcStreamRead>, UmcError> {
        let slot = self.slot_mut(tab_id)?;
        let stream = slot.streams.get(&stream_id).ok_or_else(|| {
            UmcError::InvalidConfig(format!("UMC stream {stream_id} is not open"))
        })?;
        slot.session.read_stream(stream, maximum_bytes)
    }

    /// Close one tab-owned application stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab or stream is unknown, or when the Control
    /// API rejects the close request.
    pub fn close_stream(&mut self, tab_id: u64, stream_id: u64) -> Result<(), UmcError> {
        let slot = self.slot_mut(tab_id)?;
        let stream = slot.streams.remove(&stream_id).ok_or_else(|| {
            UmcError::InvalidConfig(format!("UMC stream {stream_id} is not open"))
        })?;
        slot.session.close_stream(&stream)
    }

    /// Send one application datagram from a tab-owned session.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no application session, datagrams
    /// were not granted, or the Control API rejects the datagram.
    pub fn send_datagram(
        &mut self,
        tab_id: u64,
        context_id: u64,
        data: &[u8],
        lifetime_ms: u64,
        request_ack: bool,
    ) -> Result<u64, UmcError> {
        self.slot_mut(tab_id)?
            .session
            .send_datagram(context_id, data, lifetime_ms, request_ack)
    }

    /// Receive one application datagram for a tab-owned session.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no application session or the Control
    /// API rejects the receive request.
    pub fn receive_datagram(
        &mut self,
        tab_id: u64,
        maximum_bytes: usize,
        wait_for_data: bool,
    ) -> Result<Option<UmcDatagram>, UmcError> {
        self.slot_mut(tab_id)?
            .session
            .receive_datagram(maximum_bytes, wait_for_data)
    }

    fn slot_mut(&mut self, tab_id: u64) -> Result<&mut UmcApplicationSlot, UmcError> {
        self.sessions.get_mut(&tab_id).ok_or_else(|| {
            UmcError::InvalidConfig(format!("UMC application for tab {tab_id} is not open"))
        })
    }
}

#[cfg(any(unix, windows))]
fn snapshot_application_slot(tab_id: u64, slot: &UmcApplicationSlot) -> UmcApplicationSnapshot {
    let diagnostics = slot.session.diagnostics();
    UmcApplicationSnapshot {
        tab_id,
        protocol_id: slot.session.protocol_id().to_owned(),
        state: diagnostics.state(),
        active_streams: slot.streams.len(),
        active_paths: diagnostics.active_paths(),
        relayed: diagnostics.relayed(),
        peer_trust_state: diagnostics.peer_trust_state(),
    }
}

#[cfg(any(unix, windows))]
enum ReadResult {
    Data {
        bytes: Vec<u8>,
        eof: bool,
        reset: bool,
    },
    NoData,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Default)]
struct UmcStatusState {
    active_streams: u32,
    last_session: Option<UmcSessionDiagnostics>,
    last_error: Option<String>,
}

/// Embedded UMC application-stream adapter exposed as a local SOCKS5 route.
#[cfg(any(unix, windows))]
pub struct UmcCore {
    endpoint: crate::network::ProxyEndpoint,
    protocol_id: String,
    gateway_configured: bool,
    application_bridge: UmcApplicationBridge,
    status: Arc<Mutex<UmcStatusState>>,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

#[cfg(any(unix, windows))]
impl UmcCore {
    /// Start an adapter using the UMC local Control API socket and protocol id.
    ///
    /// `destination_hint` is the authorized gateway/application endpoint used
    /// for ordinary web and alias resources. It may be empty when the browser
    /// will only open explicit identity-addressed resources; those resources
    /// supply their own endpoint hint from the SOCKS target.
    ///
    /// # Errors
    ///
    /// Returns an error when the loopback listener cannot be opened.
    pub fn start(
        socket: impl Into<PathBuf>,
        protocol_id: impl Into<String>,
        destination_hint: Vec<u8>,
    ) -> Result<Self, UmcError> {
        let socket = socket.into();
        let protocol_id = protocol_id.into();
        if protocol_id.is_empty() {
            return Err(UmcError::InvalidConfig(
                "UMC protocol id is empty".to_owned(),
            ));
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(UmcError::Io)?;
        listener.set_nonblocking(true).map_err(UmcError::Io)?;
        let port = listener.local_addr().map_err(UmcError::Io)?.port();
        let endpoint = crate::network::ProxyEndpoint::new(
            crate::network::ProxyScheme::Socks5,
            "127.0.0.1",
            port,
        );
        let gateway_configured = !destination_hint.is_empty();
        let application_bridge = UmcApplicationBridge::new(
            socket.clone(),
            protocol_id.clone(),
            destination_hint.clone(),
        )?;
        let status = Arc::new(Mutex::new(UmcStatusState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_status = Arc::clone(&status);
        let thread_protocol_id = protocol_id.clone();
        let accept_thread = thread::Builder::new()
            .name("nomad-umc-listener".to_owned())
            .spawn(move || {
                umc_accept_loop(
                    listener,
                    socket,
                    thread_protocol_id,
                    destination_hint,
                    thread_status,
                    thread_stop,
                );
            })
            .map_err(UmcError::Io)?;
        Ok(Self {
            endpoint,
            protocol_id,
            gateway_configured,
            application_bridge,
            status,
            stop,
            accept_thread: Some(accept_thread),
        })
    }

    /// Return the loopback endpoint consumed by Servo.
    #[must_use]
    pub const fn endpoint(&self) -> &crate::network::ProxyEndpoint {
        &self.endpoint
    }

    /// Return daemon-backed application/session observations for the UI.
    #[must_use]
    pub fn diagnostics(&self) -> UmcDiagnostics {
        let status = self
            .status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default();
        UmcDiagnostics {
            protocol_id: self.protocol_id.clone(),
            gateway_configured: self.gateway_configured,
            active_streams: status.active_streams,
            active_application_sessions: self.application_bridge.snapshots().len(),
            last_session: status.last_session,
            last_error: status.last_error,
        }
    }

    /// Attach a native UMC application session to a browser tab.
    ///
    /// Explicit identity URLs pass their endpoint identity. Alias URLs use
    /// the gateway destination configured when the core was started.
    ///
    /// # Errors
    ///
    /// Returns an error when the Control API rejects the application session
    /// or the resource cannot be routed with the configured UMC destination.
    pub fn open_application(
        &mut self,
        tab_id: u64,
        resource: &UmcResourceInfo,
    ) -> Result<UmcApplicationSnapshot, UmcError> {
        let destination_hint = resource
            .endpoint_id()
            .map_or(&[][..], |endpoint| endpoint.as_slice());
        self.application_bridge.connect(tab_id, destination_hint)
    }

    /// Close the native UMC application session associated with a browser tab.
    pub fn close_application(&mut self, tab_id: u64) {
        self.application_bridge.close(tab_id);
    }

    /// Return native UMC application sessions currently attached to tabs.
    #[must_use]
    pub fn application_snapshots(&self) -> Vec<UmcApplicationSnapshot> {
        self.application_bridge.snapshots()
    }

    /// Access the tab-scoped application API for native integrations.
    pub fn application_bridge_mut(&mut self) -> &mut UmcApplicationBridge {
        &mut self.application_bridge
    }
}

#[cfg(any(unix, windows))]
impl Drop for UmcCore {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(any(unix, windows))]
#[allow(clippy::needless_pass_by_value)]
fn umc_accept_loop(
    listener: TcpListener,
    socket: PathBuf,
    protocol_id: String,
    destination_hint: Vec<u8>,
    status: Arc<Mutex<UmcStatusState>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let socket = socket.clone();
                let protocol_id = protocol_id.clone();
                let destination_hint = destination_hint.clone();
                let status = Arc::clone(&status);
                let _ = thread::Builder::new()
                    .name("nomad-umc-connection".to_owned())
                    .spawn(move || {
                        handle_umc_connection(
                            stream,
                            &socket,
                            &protocol_id,
                            &destination_hint,
                            &status,
                        );
                    });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

#[cfg(any(unix, windows))]
fn handle_umc_connection(
    mut client: TcpStream,
    socket: &Path,
    protocol_id: &str,
    destination_hint: &[u8],
    status: &Arc<Mutex<UmcStatusState>>,
) {
    let Ok(target) = read_socks_target(&mut client) else {
        return;
    };
    let Some(destination_hint) = destination_hint_for_target(&target.host, destination_hint) else {
        record_umc_error(status, "no authorized UMC destination for target");
        let _ = write_socks_reply(&mut client, 0x01);
        return;
    };
    let mut control = match UmcControlClient::connect(socket, protocol_id, false) {
        Ok(control) => control,
        Err(error) => {
            record_umc_error(status, &error.to_string());
            let _ = write_socks_reply(&mut client, 0x01);
            return;
        }
    };
    let destination = if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let peer_trust_state = endpoint_id_from_identity(&target.host)
        .and_then(|endpoint_id| control.peer_trust_state(&endpoint_id).unwrap_or_default());
    let (stream, session_handle, mut session) =
        match control.open_stream(&destination_hint, &destination) {
            Ok(opened) => opened,
            Err(error) => {
                record_umc_error(status, &error.to_string());
                let _ = write_socks_reply(&mut client, 0x05);
                return;
            }
        };
    session.peer_trust_state = peer_trust_state;
    record_umc_session_opened(status, session.clone());
    if write_socks_reply(&mut client, 0x00).is_err() {
        record_umc_session_closed(status);
        return;
    }
    let _ = client.set_read_timeout(Some(Duration::from_millis(5)));
    let mut local_closed = false;
    let mut buffer = vec![0u8; 32 * 1024];
    let mut last_session_refresh = Instant::now();
    loop {
        if !local_closed {
            match client.read(&mut buffer) {
                Ok(0) => {
                    local_closed = true;
                    let _ = control.write_stream(&stream, &[], true);
                }
                Ok(count) => {
                    if control
                        .write_stream(&stream, &buffer[..count], false)
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
        match control.read_stream(&stream, buffer.len()) {
            Ok(ReadResult::Data { bytes, eof, reset }) => {
                if client.write_all(&bytes).is_err() {
                    break;
                }
                if eof || reset {
                    break;
                }
            }
            Ok(ReadResult::NoData) => {}
            Err(_) => break,
        }
        if last_session_refresh.elapsed() >= Duration::from_millis(250) {
            if let Ok(mut refreshed) = control.get_session(&session_handle) {
                refreshed.peer_trust_state = session.peer_trust_state();
                session = refreshed;
                record_umc_session_updated(status, &session);
            }
            last_session_refresh = Instant::now();
        }
        thread::sleep(Duration::from_millis(2));
    }
    let _ = control.close_stream(&stream);
    record_umc_session_closed(status);
}

#[cfg(any(unix, windows))]
fn record_umc_error(status: &Arc<Mutex<UmcStatusState>>, error: &str) {
    if let Ok(mut status) = status.lock() {
        status.last_error = Some(error.to_owned());
    }
}

#[cfg(any(unix, windows))]
fn record_umc_session_opened(status: &Arc<Mutex<UmcStatusState>>, session: UmcSessionDiagnostics) {
    if let Ok(mut status) = status.lock() {
        status.active_streams = status.active_streams.saturating_add(1);
        status.last_session = Some(session);
        status.last_error = None;
    }
}

#[cfg(any(unix, windows))]
fn record_umc_session_updated(
    status: &Arc<Mutex<UmcStatusState>>,
    session: &UmcSessionDiagnostics,
) {
    if let Ok(mut status) = status.lock() {
        status.last_session = Some(session.clone());
        status.last_error = None;
    }
}

#[cfg(any(unix, windows))]
fn record_umc_session_closed(status: &Arc<Mutex<UmcStatusState>>) {
    if let Ok(mut status) = status.lock() {
        status.active_streams = status.active_streams.saturating_sub(1);
        let active_streams = status.active_streams;
        if let Some(session) = &mut status.last_session {
            session.state = UmcSessionState::Closed;
            session.active_streams = active_streams;
        }
    }
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug)]
struct SocksTarget {
    host: String,
    port: u16,
}

fn destination_hint_for_target(host: &str, gateway_hint: &[u8]) -> Option<Vec<u8>> {
    endpoint_id_from_identity(host)
        .map(|id| id.to_vec())
        .or_else(|| (!gateway_hint.is_empty()).then(|| gateway_hint.to_vec()))
}

#[cfg(any(unix, windows))]
fn read_socks_target(stream: &mut TcpStream) -> io::Result<SocksTarget> {
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
    Ok(SocksTarget {
        host,
        port: u16::from_be_bytes(port),
    })
}

#[cfg(any(unix, windows))]
fn write_socks_reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    #[cfg(unix)]
    use std::thread;

    use super::{
        endpoint_id_from_identity, transport_url, ControlEnvelope, ControlEnvelopeError,
        UmcApplicationBridge, UmcApplicationSession, UmcControlClient, UmcResourceInfo,
        UmcUrlError, MAX_FIELDS,
    };

    #[test]
    fn control_envelope_decoder_is_bounded_and_rejects_malformed_wire_data() {
        let hello = ControlEnvelope::client_hello("nomad-test");
        assert_eq!(ControlEnvelope::from_bytes(&hello.encode()).unwrap(), hello);
        assert_eq!(
            ControlEnvelope::from_bytes(&[]),
            Err(ControlEnvelopeError::Empty)
        );
        assert_eq!(
            ControlEnvelope::from_bytes(&[0x80]),
            Err(ControlEnvelopeError::Malformed)
        );
        assert_eq!(
            ControlEnvelope::from_bytes(&vec![0; 4 * 1024 * 1024 + 1]),
            Err(ControlEnvelopeError::TooLarge)
        );
        let mut too_many_fields = Vec::with_capacity(MAX_FIELDS * 2 + 2);
        for _ in 0..=MAX_FIELDS {
            too_many_fields.extend_from_slice(&[0x10, 0]);
        }
        assert_eq!(
            ControlEnvelope::from_bytes(&too_many_fields),
            Err(ControlEnvelopeError::Malformed)
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn application_bridge_starts_empty_and_rejects_empty_protocol() {
        let bridge = UmcApplicationBridge::new(
            "/tmp/nomad-test-umc.sock",
            "org.nomad.browser.app/1",
            Vec::new(),
        )
        .unwrap();

        assert!(bridge.snapshots().is_empty());
        assert!(bridge.snapshot(7).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn core_accepts_empty_gateway_hint_for_identity_resources() {
        let core = super::UmcCore::start(
            "/tmp/nomad-test-umc.sock",
            "org.nomad.browser.tcp/1",
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            core.endpoint().scheme(),
            super::super::network::ProxyScheme::Socks5
        );
        let diagnostics = core.diagnostics();
        assert_eq!(diagnostics.protocol_id(), "org.nomad.browser.tcp/1");
        assert!(!diagnostics.gateway_configured());
        assert_eq!(diagnostics.active_streams(), 0);
        assert!(diagnostics.last_session().is_none());
    }

    #[test]
    fn explicit_identity_exposes_typed_security_and_destination_metadata() {
        let url = url::Url::parse(
            "umc://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/app",
        )
        .unwrap();

        let info = UmcResourceInfo::from_url(&url).unwrap();
        let security = info.security_info();

        assert_eq!(info.identity_kind(), super::UmcIdentityKind::Explicit);
        assert_eq!(info.trust_state(), super::UmcTrustState::IdentityAddressed);
        assert_eq!(info.path_kind(), super::UmcPathKind::DirectIdentitySession);
        assert_eq!(
            security.session_security(),
            super::UmcSessionSecurity::AuthenticatedEncrypted
        );
        assert_eq!(info.endpoint_id().unwrap().len(), 32);
    }

    #[test]
    fn alias_resource_requires_gateway_resolution() {
        let url = url::Url::parse("umc://service-alias/app").unwrap();

        let info = UmcResourceInfo::from_url(&url).unwrap();

        assert_eq!(info.identity_kind(), super::UmcIdentityKind::Alias);
        assert_eq!(
            info.trust_state(),
            super::UmcTrustState::AliasRequiresVerification
        );
        assert_eq!(info.path_kind(), super::UmcPathKind::GatewayApplication);
        assert!(info.endpoint_id().is_none());
    }

    #[test]
    fn explicit_socks_target_selects_identity_destination_over_gateway() {
        let target = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let gateway = vec![0xaa; 32];

        assert_eq!(
            super::destination_hint_for_target(target, &gateway),
            Some(vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef
            ])
        );
    }

    #[test]
    fn alias_socks_target_keeps_configured_gateway_destination() {
        let target = "service-alias";
        let gateway = vec![0xaa; 32];

        assert_eq!(
            super::destination_hint_for_target(target, &gateway),
            Some(gateway)
        );
    }

    #[test]
    fn alias_socks_target_without_gateway_fails_closed() {
        assert_eq!(
            super::destination_hint_for_target("service-alias", &[]),
            None
        );
    }

    #[test]
    fn parses_daemon_session_summary_for_security_inspection() {
        let mut wire = Vec::new();
        super::field_varint(4, 2, &mut wire);
        super::field_string(5, "org.nomad.browser.tcp/1", &mut wire);
        super::field_varint(6, 3, &mut wire);
        super::field_varint(7, 2, &mut wire);
        super::field_varint(10, 1, &mut wire);

        let summary = super::parse_session_summary(&wire).unwrap();

        assert_eq!(summary.state(), super::UmcSessionState::Active);
        assert_eq!(summary.protocol_id(), "org.nomad.browser.tcp/1");
        assert_eq!(summary.active_streams(), 3);
        assert_eq!(summary.active_paths(), 2);
        assert!(summary.relayed());
    }

    #[test]
    fn parses_live_session_response_with_path_count_and_updated_state() {
        let mut summary = Vec::new();
        super::field_varint(4, 3, &mut summary);
        super::field_string(5, "org.nomad.browser.datagram/1", &mut summary);
        super::field_varint(6, 2, &mut summary);
        super::field_varint(7, 4, &mut summary);
        super::field_varint(10, 1, &mut summary);
        let mut path = Vec::new();
        super::field_varint(1, 9, &mut path);
        super::field_string(2, "active", &mut path);
        super::field_string(3, "quic", &mut path);
        super::field_varint(4, 31, &mut path);
        super::field_varint(5, 1400, &mut path);
        super::field_varint(6, 1, &mut path);
        let mut privacy = Vec::new();
        super::field_string(1, "hardened", &mut privacy);
        super::field_string(2, "anonymous", &mut privacy);
        super::field_varint(3, 0, &mut privacy);
        super::field_varint(4, 1, &mut privacy);
        super::field_varint(5, 3, &mut privacy);
        super::field_varint(8, 1, &mut privacy);
        super::field_string(9, "relay enforced", &mut privacy);
        let mut response = Vec::new();
        super::field_message(1, &summary, &mut response);
        super::field_message(2, &path, &mut response);
        super::field_message(3, &privacy, &mut response);

        let parsed = super::parse_session_response(&response).unwrap();

        assert_eq!(parsed.state(), super::UmcSessionState::Draining);
        assert_eq!(parsed.protocol_id(), "org.nomad.browser.datagram/1");
        assert_eq!(parsed.active_streams(), 2);
        assert_eq!(parsed.active_paths(), 4);
        assert!(parsed.relayed());
        assert_eq!(parsed.paths().len(), 1);
        assert_eq!(parsed.paths()[0].carrier_type_id(), "quic");
        assert_eq!(parsed.paths()[0].estimated_rtt_ms(), 31);
        let privacy = parsed.privacy().unwrap();
        assert_eq!(privacy.effective_profile(), "anonymous");
        assert_eq!(privacy.hop_count(), 3);
        assert!(privacy.traffic_padding_active());
    }

    #[test]
    fn builds_datagram_request_with_context_lifetime_and_ack() {
        let request = super::send_datagram_request(b"session", 17, b"hello", 250, true);

        let session_handle = super::message_field(&request, 1).unwrap().unwrap();
        assert_eq!(
            super::message_field(&session_handle, 1).unwrap(),
            Some(b"session".to_vec())
        );
        assert_eq!(super::varint_field(&request, 2).unwrap(), Some(17));
        assert_eq!(
            super::message_field(&request, 3).unwrap(),
            Some(b"hello".to_vec())
        );
        assert_eq!(super::varint_field(&request, 4).unwrap(), Some(250));
        assert_eq!(super::varint_field(&request, 5).unwrap(), Some(1));
    }

    #[test]
    fn maps_daemon_peer_trust_states_without_guessing_unknown_values() {
        assert_eq!(
            super::peer_trust_state(4),
            Some(super::UmcPeerTrustState::Trusted)
        );
        assert_eq!(
            super::peer_trust_state(7),
            Some(super::UmcPeerTrustState::Revoked)
        );
        assert_eq!(super::peer_trust_state(99), None);
    }

    #[cfg(any(unix, windows))]
    #[test]
    #[ignore = "requires a running UMC daemon and explicit test credentials"]
    fn live_control_api_interoperates_with_configured_umc_daemon() {
        let socket = std::env::var("NOMAD_UMC_SOCKET").expect("NOMAD_UMC_SOCKET");
        let destination = std::env::var("NOMAD_UMC_DESTINATION").expect("NOMAD_UMC_DESTINATION");
        let destination =
            endpoint_id_from_identity(&destination).expect("64-character endpoint id");
        let protocol = std::env::var("NOMAD_UMC_PROTOCOL")
            .unwrap_or_else(|_| "org.nomad.browser.tcp/1".to_owned());
        let expected_protocol = protocol.clone();
        let mut session = UmcApplicationSession::connect(socket, protocol, &destination).unwrap();

        let diagnostics = session.refresh_diagnostics().unwrap();
        assert_eq!(diagnostics.protocol_id(), expected_protocol);
    }

    #[cfg(unix)]
    #[test]
    fn browser_application_bridge_supports_live_refresh_and_datagrams() {
        let socket_path = std::env::temp_dir().join(format!(
            "nomad-umc-application-test-{}-{}.sock",
            std::process::id(),
            3_u64
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            let _hello = read_frame(&mut stream);
            let mut hello = Vec::new();
            super::field_message(1, &super::api_version(), &mut hello);
            super::field_varint(7, super::MAX_ENVELOPE as u64, &mut hello);
            write_frame(&mut stream, 11, &hello);

            let register = read_frame(&mut stream);
            let register_request = super::message_field(&register, 12).unwrap().unwrap();
            write_response(
                &mut stream,
                &register_request,
                &opaque_response(b"application"),
            );

            let connect = read_frame(&mut stream);
            let connect_request = super::message_field(&connect, 12).unwrap().unwrap();
            let mut summary = Vec::new();
            super::field_varint(4, 2, &mut summary);
            super::field_string(5, "org.nomad.browser.datagram/1", &mut summary);
            super::field_varint(6, 0, &mut summary);
            super::field_varint(7, 1, &mut summary);
            let mut connect_payload = Vec::new();
            opaque_field(1, b"session", &mut connect_payload);
            super::field_message(3, &summary, &mut connect_payload);
            write_response(&mut stream, &connect_request, &connect_payload);

            let refresh = read_frame(&mut stream);
            let refresh_request = super::message_field(&refresh, 12).unwrap().unwrap();
            let mut path = Vec::new();
            super::field_varint(1, 4, &mut path);
            super::field_string(2, "active", &mut path);
            super::field_string(3, "quic", &mut path);
            let mut refresh_payload = Vec::new();
            super::field_message(1, &summary, &mut refresh_payload);
            super::field_message(2, &path, &mut refresh_payload);
            write_response(&mut stream, &refresh_request, &refresh_payload);

            let send = read_frame(&mut stream);
            let send_request = super::message_field(&send, 12).unwrap().unwrap();
            let mut send_payload = Vec::new();
            super::field_varint(1, 99, &mut send_payload);
            write_response(&mut stream, &send_request, &send_payload);

            let receive = read_frame(&mut stream);
            let receive_request = super::message_field(&receive, 12).unwrap().unwrap();
            let mut receive_payload = Vec::new();
            super::field_varint(2, 17, &mut receive_payload);
            super::field_bytes(3, b"reply", &mut receive_payload);
            write_response(&mut stream, &receive_request, &receive_payload);

            let close = read_frame(&mut stream);
            let close_request = super::message_field(&close, 12).unwrap().unwrap();
            write_response(&mut stream, &close_request, &[]);
        });

        let mut bridge =
            UmcApplicationBridge::new(&socket_path, "org.nomad.browser.datagram/1", Vec::new())
                .unwrap();
        let initial = bridge.connect(7, &[]).unwrap();
        assert_eq!(initial.tab_id(), 7);
        let reused = bridge.connect(7, &[]).unwrap();
        assert_eq!(reused, initial);
        let diagnostics = bridge.refresh(7).unwrap();
        assert_eq!(diagnostics.active_paths(), 1);
        assert_eq!(bridge.send_datagram(7, 7, b"hello", 250, true).unwrap(), 99);
        let datagram = bridge.receive_datagram(7, 1024, false).unwrap().unwrap();
        assert_eq!(datagram.context_id(), 17);
        assert_eq!(datagram.data(), b"reply");
        assert!(!datagram.expired());
        bridge.close(7);

        server.join().unwrap();
        let _ = std::fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    #[test]
    fn local_control_api_and_socks_route_complete_identity_navigation() {
        let socket_path = std::env::temp_dir().join(format!(
            "nomad-umc-test-{}-{}.sock",
            std::process::id(),
            1_u64
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();

            let _hello = read_frame(&mut stream);
            let mut hello = Vec::new();
            super::field_message(1, &super::api_version(), &mut hello);
            super::field_varint(7, super::MAX_ENVELOPE as u64, &mut hello);
            write_frame(&mut stream, 11, &hello);

            let register = read_frame(&mut stream);
            let register_request = super::message_field(&register, 12).unwrap().unwrap();
            write_response(
                &mut stream,
                &register_request,
                &opaque_response(b"application"),
            );

            let peer = read_frame(&mut stream);
            let peer_request = super::message_field(&peer, 12).unwrap().unwrap();
            let mut peer_summary = Vec::new();
            super::field_bytes(1, &[0x11; 32], &mut peer_summary);
            super::field_varint(3, 4, &mut peer_summary);
            let mut peer_payload = Vec::new();
            super::field_message(1, &peer_summary, &mut peer_payload);
            write_response(&mut stream, &peer_request, &peer_payload);

            let connect = read_frame(&mut stream);
            let connect_request = super::message_field(&connect, 12).unwrap().unwrap();
            let mut summary = Vec::new();
            super::field_varint(4, 2, &mut summary);
            super::field_string(5, "org.nomad.browser.tcp/1", &mut summary);
            super::field_varint(6, 1, &mut summary);
            super::field_varint(7, 1, &mut summary);
            let mut connect_payload = Vec::new();
            opaque_field(1, b"session", &mut connect_payload);
            super::field_message(3, &summary, &mut connect_payload);
            write_response(&mut stream, &connect_request, &connect_payload);

            let open = read_frame(&mut stream);
            let open_request = super::message_field(&open, 12).unwrap().unwrap();
            write_response(&mut stream, &open_request, &opaque_response(b"stream"));

            let write = read_frame(&mut stream);
            let write_request = super::message_field(&write, 12).unwrap().unwrap();
            write_response(&mut stream, &write_request, &[]);
        });

        let core =
            super::UmcCore::start(&socket_path, "org.nomad.browser.tcp/1", Vec::new()).unwrap();
        let mut client =
            std::net::TcpStream::connect(core.endpoint().uri().replace("socks5h://", "")).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);

        let identity = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let identity_length = u8::try_from(identity.len()).unwrap();
        let mut request = vec![0x05, 0x01, 0x00, 0x03, identity_length];
        request.extend_from_slice(identity);
        request.extend_from_slice(&80_u16.to_be_bytes());
        client.write_all(&request).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut reply = [0u8; 10];
        if let Err(error) = client.read_exact(&mut reply) {
            drop(client);
            let server_result = server.join();
            assert!(server_result.is_ok(), "mock UMC server failed");
            panic!("SOCKS route did not open: {error}");
        }
        assert_eq!(reply[1], 0x00);
        drop(client);

        server.join().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let diagnostics = loop {
            let diagnostics = core.diagnostics();
            if diagnostics.active_streams() == 0 || std::time::Instant::now() >= deadline {
                break diagnostics;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        let session = diagnostics.last_session().unwrap();
        assert_eq!(session.state(), super::UmcSessionState::Closed);
        assert_eq!(
            session.peer_trust_state(),
            Some(super::UmcPeerTrustState::Trusted)
        );
        assert_eq!(session.active_paths(), 1);
        let _ = std::fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).unwrap();
        let mut bytes = vec![0u8; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut bytes).unwrap();
        bytes
    }

    #[cfg(unix)]
    fn write_frame(stream: &mut std::os::unix::net::UnixStream, number: u32, body: &[u8]) {
        let mut envelope = Vec::new();
        super::field_message(1, &super::api_version(), &mut envelope);
        super::field_varint(2, 1, &mut envelope);
        super::field_message(number, body, &mut envelope);
        let envelope_length = u32::try_from(envelope.len()).unwrap();
        stream.write_all(&envelope_length.to_be_bytes()).unwrap();
        stream.write_all(&envelope).unwrap();
    }

    #[cfg(unix)]
    fn write_response(stream: &mut std::os::unix::net::UnixStream, request: &[u8], payload: &[u8]) {
        let request_id = super::varint_field(request, 1).unwrap().unwrap();
        let mut response = Vec::new();
        super::field_varint(1, request_id, &mut response);
        super::field_message(3, payload, &mut response);
        write_frame(stream, 13, &response);
    }

    #[cfg(unix)]
    fn opaque_field(number: u32, value: &[u8], output: &mut Vec<u8>) {
        let mut handle = Vec::new();
        super::field_bytes(1, value, &mut handle);
        super::field_message(number, &handle, output);
    }

    #[cfg(unix)]
    fn opaque_response(value: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        opaque_field(1, value, &mut response);
        response
    }

    #[test]
    fn parses_umc_identity_path_and_stream_target() {
        let url = url::Url::parse(
            "umc://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/app/index",
        )
        .unwrap();

        let info = UmcResourceInfo::from_url(&url).unwrap();

        assert_eq!(info.service_identity().len(), 64);
        assert!(info.has_explicit_identity());
        assert_eq!(info.path(), "/app/index");
        assert_eq!(info.port(), 80);
        assert_eq!(
            info.stream_target(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:80"
        );
    }

    #[test]
    fn converts_umc_resource_to_http_transport_without_changing_identity() {
        let url = url::Url::parse("umc://service-alias:8080/app").unwrap();

        assert_eq!(
            transport_url(&url).unwrap().as_str(),
            "http://service-alias:8080/app"
        );
    }

    #[test]
    fn rejects_non_umc_urls_in_resource_inspection() {
        let url = url::Url::parse("https://example.com").unwrap();

        assert_eq!(
            UmcResourceInfo::from_url(&url),
            Err(UmcUrlError::UnsupportedScheme)
        );
    }

    #[test]
    fn rejects_credentials_in_umc_resource_identity() {
        let url = url::Url::parse("umc://user:secret@service-alias/app").unwrap();

        assert_eq!(
            UmcResourceInfo::from_url(&url),
            Err(UmcUrlError::CredentialsNotAllowed)
        );
    }

    #[test]
    fn request_envelope_uses_versioned_framed_control_api() {
        let envelope = ControlEnvelope::client_hello("nomad-browser");
        let bytes = envelope.encode();

        assert_eq!(bytes[0], 0x0a);
        assert!(bytes.contains(&0x52), "ClientHello oneof field is present");
        assert!(bytes.windows(2).any(|window| window == [0x20, 0x02]));
        let length = u8::try_from(bytes.len()).expect("test envelope fits");
        assert_eq!(
            UmcControlClient::frame(&bytes).unwrap()[..4],
            [0, 0, 0, length]
        );
    }
}
