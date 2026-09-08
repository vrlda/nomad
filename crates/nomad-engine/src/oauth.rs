//! Provider-backed OAuth 2.0 plumbing for `WebExtensions` identity.
//!
//! Implements the Chromium `identity` contract for extensions that declare an
//! `oauth2` manifest section: authorization-code flow with PKCE against the
//! provider's authorize and token endpoints, refresh-token rotation, and the
//! extension-scoped redirect (`https://<extension-id>.chromiumapp.org/`).
//! Token records are never logged: [`OAuthTokenRecord::Debug`] redacts every
//! secret field.

use std::fmt::{self, Write as _};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

/// Real provider endpoints used when a manifest declares `oauth2` without
/// custom endpoints. These are Chromium's built-in Google provider paths.
pub const GOOGLE_OAUTH_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_OAUTH_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Chromium's web origin redirect for `chrome.identity` flows.
pub const EXTENSION_REDIRECT_SUFFIX: &str = ".chromiumapp.org/";

const DEFAULT_TOKEN_TTL_SECONDS: u64 = 3_600;
const TOKEN_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Failure modes of an OAuth provider flow, mapped to the messages Chromium
/// surfaces through `runtime.lastError`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OAuthFlowError {
    /// The extension has no usable `oauth2` manifest section.
    NoProviderConfig,
    /// `getAuthToken` without a cached token and without `interactive`.
    UserInteractionRequired,
    /// The user (or provider) denied authorization at the consent step.
    AccessDenied,
    /// The token endpoint rejected the client credentials.
    InvalidClient,
    /// The refresh or authorization grant was rejected (expired, revoked).
    InvalidGrant,
    /// The provider endpoint could not be reached or answered unusably.
    Transport(String),
    /// The provider answered with an unparseable body or unknown error code.
    MalformedResponse(String),
}

impl OAuthFlowError {
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NoProviderConfig => {
                "Missing OAuth client ID in the extension manifest".to_owned()
            }
            Self::UserInteractionRequired => "user interaction required".to_owned(),
            Self::AccessDenied => {
                "Authorization failed: access_denied (user denied access)".to_owned()
            }
            Self::InvalidClient => {
                "Authorization failed: invalid_client (invalid OAuth client)".to_owned()
            }
            Self::InvalidGrant => {
                "Authorization failed: invalid_grant (expired or revoked grant)".to_owned()
            }
            Self::Transport(detail) => format!("Authorization failed: transport error ({detail})"),
            Self::MalformedResponse(detail) => {
                format!("Authorization failed: unexpected provider response ({detail})")
            }
        }
    }
}

impl fmt::Display for OAuthFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for OAuthFlowError {}

/// The `oauth2` manifest configuration of one extension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    #[serde(default)]
    pub auth_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl OAuthProviderConfig {
    #[must_use]
    pub fn resolved_auth_endpoint(&self) -> &str {
        self.auth_endpoint
            .as_deref()
            .unwrap_or(GOOGLE_OAUTH_AUTH_ENDPOINT)
    }

    #[must_use]
    pub fn resolved_token_endpoint(&self) -> &str {
        self.token_endpoint
            .as_deref()
            .unwrap_or(GOOGLE_OAUTH_TOKEN_ENDPOINT)
    }
}

/// A stored provider-backed token for one extension identity grant.
///
/// `Debug` is implemented manually so tokens never reach logs: every secret
/// renders as `[REDACTED]`.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OAuthTokenRecord {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Milliseconds since the Unix epoch at which the access token expires.
    pub expires_at_ms: u64,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Milliseconds since the Unix epoch when the record was stored.
    pub stored_at_ms: u64,
}

impl fmt::Debug for OAuthTokenRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenRecord")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at_ms", &self.expires_at_ms)
            .field("scopes", &self.scopes)
            .field("account_id", &self.account_id)
            .field("stored_at_ms", &self.stored_at_ms)
            .finish()
    }
}

impl OAuthTokenRecord {
    #[must_use]
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

/// Stable storage key for one extension's provider token grant.
#[must_use]
pub fn token_key(extension_id: &str, client_id: &str, scopes: &[String]) -> String {
    let mut ordered = scopes.to_vec();
    ordered.sort_unstable();
    format!("{extension_id}\u{0}{client_id}\u{0}{}", ordered.join(" "))
}

/// PKCE verifier/challenge pair per RFC 7636 (S256 method).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// Derives the S256 challenge for a given verifier (pure, testable).
#[must_use]
pub fn challenge_from_verifier(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Generates a fresh PKCE verifier/challenge pair from OS randomness.
///
/// # Errors
///
/// Returns [`OAuthFlowError::Transport`] when the operating system randomness
/// source is unavailable.
pub fn generate_pkce_pair() -> Result<PkcePair, OAuthFlowError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OAuthFlowError::Transport("randomness unavailable".to_owned()))?;
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    Ok(PkcePair {
        challenge: challenge_from_verifier(&verifier),
        verifier,
    })
}

/// Builds the authorization-code URL for a provider sign-in flow.
///
/// # Errors
///
/// Returns [`OAuthFlowError::Transport`] when the configured authorize
/// endpoint is not a valid http(s) URL.
pub fn build_authorize_url(
    provider: &OAuthProviderConfig,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String, OAuthFlowError> {
    let mut url = Url::parse(provider.resolved_auth_endpoint())
        .map_err(|_| OAuthFlowError::Transport("authorize endpoint is not a URL".to_owned()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(OAuthFlowError::Transport(
            "authorize endpoint must be http(s)".to_owned(),
        ));
    }
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &provider.scopes.join(" "))
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.into())
}

/// `application/x-www-form-urlencoded` body for a code exchange request.
#[must_use]
pub fn exchange_request_body(
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: &str,
) -> String {
    format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        urlencoded(code),
        urlencoded(redirect_uri),
        urlencoded(client_id),
        urlencoded(code_verifier),
    )
}

/// `application/x-www-form-urlencoded` body for a refresh-token request.
#[must_use]
pub fn refresh_request_body(refresh_token: &str, client_id: &str) -> String {
    format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        urlencoded(refresh_token),
        urlencoded(client_id),
    )
}

fn urlencoded(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail"),
        }
    }
    encoded
}

/// One pending token-endpoint request handed to a [`TokenExchange`] client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenExchangeRequest {
    pub token_endpoint: Url,
    /// Form-encoded request body; already percent-encoded.
    pub body: String,
}

impl TokenExchangeRequest {
    /// Creates a validated token-endpoint request.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthFlowError::Transport`] when the endpoint is not a valid
    /// HTTP(S) URL.
    pub fn new(token_endpoint: &str, body: &str) -> Result<Self, OAuthFlowError> {
        let url = Url::parse(token_endpoint)
            .map_err(|_| OAuthFlowError::Transport("token endpoint is not a URL".to_owned()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(OAuthFlowError::Transport(
                "token endpoint must be http(s)".to_owned(),
            ));
        }
        Ok(Self {
            token_endpoint: url,
            body: body.to_owned(),
        })
    }

    #[must_use]
    pub fn http_bytes(&self) -> Vec<u8> {
        let host = self.token_endpoint.host_str().unwrap_or_default();
        let target = {
            let mut target = self.token_endpoint.path().to_owned();
            if target.is_empty() {
                target.push('/');
            }
            if let Some(query) = self.token_endpoint.query() {
                target.push('?');
                target.push_str(query);
            }
            target
        };
        format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.body.len(),
            self.body,
        )
        .into_bytes()
    }
}

/// Blocking token-endpoint transport. The default implementation performs a
/// real HTTPS POST; tests inject a mock to exercise error paths without
/// network access.
pub trait TokenExchange: Send + Sync {
    /// Exchanges a code or refresh grant for a provider token record.
    ///
    /// # Errors
    ///
    /// Returns the provider or transport failure that prevented a token
    /// record from being produced.
    fn exchange(&self, request: &TokenExchangeRequest) -> Result<OAuthTokenRecord, OAuthFlowError>;
}

/// Real HTTPS transport for OAuth token endpoints (HTTP/1.1, TLS via rustls).
#[derive(Debug, Default)]
pub struct HttpsTokenClient;

/// HTTP/1.1 transport over either a plain socket or a TLS session.
enum TokenStream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncWrite for TokenStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl tokio::io::AsyncRead for TokenStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl TokenExchange for HttpsTokenClient {
    fn exchange(&self, request: &TokenExchangeRequest) -> Result<OAuthTokenRecord, OAuthFlowError> {
        let request_bytes = request.http_bytes();
        let host = request
            .token_endpoint
            .host_str()
            .ok_or_else(|| OAuthFlowError::Transport("token endpoint has no host".to_owned()))?
            .to_owned();
        let port = request
            .token_endpoint
            .port_or_known_default()
            .ok_or_else(|| OAuthFlowError::Transport("token endpoint has no port".to_owned()))?;
        let https = matches!(request.token_endpoint.scheme(), "https");
        let timeout = TOKEN_EXCHANGE_TIMEOUT;
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| OAuthFlowError::Transport(error.to_string()))?
            .block_on(async move {
                let host = host.clone();
                let stream = tokio::time::timeout(
                    timeout,
                    tokio::net::TcpStream::connect((host.as_str(), port)),
                )
                .await
                .map_err(|_| OAuthFlowError::Transport("connect timed out".to_owned()))?
                .map_err(|error| OAuthFlowError::Transport(error.to_string()))?;
                let mut stream = if https {
                    let roots: RootCertStore =
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
                    let config = ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
                    let server_name = ServerName::try_from(host.clone()).map_err(|_| {
                        OAuthFlowError::Transport("invalid TLS host name".to_owned())
                    })?;
                    let tls_stream =
                        tokio::time::timeout(timeout, connector.connect(server_name, stream))
                            .await
                            .map_err(|_| {
                                OAuthFlowError::Transport("TLS handshake timed out".to_owned())
                            })?
                            .map_err(|error| OAuthFlowError::Transport(error.to_string()))?;
                    TokenStream::Tls(Box::new(tls_stream))
                } else {
                    TokenStream::Plain(stream)
                };
                tokio::time::timeout(timeout, stream.write_all(&request_bytes))
                    .await
                    .map_err(|_| OAuthFlowError::Transport("write timed out".to_owned()))?
                    .map_err(|error| OAuthFlowError::Transport(error.to_string()))?;
                let mut response = Vec::new();
                tokio::time::timeout(timeout, stream.read_to_end(&mut response))
                    .await
                    .map_err(|_| OAuthFlowError::Transport("read timed out".to_owned()))?
                    .map_err(|error| OAuthFlowError::Transport(error.to_string()))?;
                let (status, body) = parse_http_status_and_body(&response)?;
                parse_token_response(status, &body, unix_now_ms())
            })
    }
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn parse_http_status_and_body(response: &[u8]) -> Result<(u16, Vec<u8>), OAuthFlowError> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| OAuthFlowError::Transport("missing HTTP headers".to_owned()))?;
    let headers = std::str::from_utf8(&response[..separator])
        .map_err(|error| OAuthFlowError::Transport(format!("non-UTF-8 headers: {error}")))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| OAuthFlowError::Transport("invalid HTTP status".to_owned()))?;
    Ok((status, response[separator + 4..].to_vec()))
}

/// Parses a token-endpoint HTTP exchange result into a stored record.
///
/// 2xx responses must carry a JSON `access_token`; provider error responses
/// (RFC 6749 §5.2) map to dedicated error variants so callers can distinguish
/// `invalid_client`, `invalid_grant`, and user denial.
///
/// # Errors
///
/// Returns the mapped [`OAuthFlowError`] for provider errors and
/// [`OAuthFlowError::MalformedResponse`] for unusable bodies.
pub fn parse_token_response(
    status: u16,
    body: &[u8],
    request_time_ms: u64,
) -> Result<OAuthTokenRecord, OAuthFlowError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| OAuthFlowError::MalformedResponse("non-UTF-8 body".to_owned()))?;
    let json: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| OAuthFlowError::MalformedResponse("body is not JSON".to_owned()))?;
    if !(200..300).contains(&status) {
        return Err(token_error(&json));
    }
    let access_token = json
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| OAuthFlowError::MalformedResponse("missing access_token".to_owned()))?;
    let expires_in = json
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_TOKEN_TTL_SECONDS);
    let scopes = json
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .map(|scope| {
            scope
                .split(' ')
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let refresh_token = json
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned);
    let account_id = json
        .get("id_token")
        .and_then(serde_json::Value::as_str)
        .and_then(account_id_from_id_token);
    Ok(OAuthTokenRecord {
        access_token: access_token.to_owned(),
        expires_at_ms: request_time_ms.saturating_add(expires_in.saturating_mul(1_000)),
        scopes,
        account_id,
        stored_at_ms: request_time_ms,
        refresh_token,
    })
}

fn token_error(json: &serde_json::Value) -> OAuthFlowError {
    let code = json
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match code {
        "invalid_client" => OAuthFlowError::InvalidClient,
        "invalid_grant" => OAuthFlowError::InvalidGrant,
        "access_denied" => OAuthFlowError::AccessDenied,
        "" => OAuthFlowError::MalformedResponse("missing error code".to_owned()),
        other => OAuthFlowError::MalformedResponse(format!("provider error {other:?}")),
    }
}

/// Extracts the `OpenID` Connect `sub` claim from an unverified ID token.
///
/// The value is only used as a display identifier for `onSignInChanged`;
/// no trust decision depends on it.
#[must_use]
pub fn account_id_from_id_token(id_token: &str) -> Option<String> {
    let mut segments = id_token.split('.');
    let payload = segments.nth(1)?;
    let json = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&json).ok()?;
    value
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|sub| !sub.is_empty())
        .map(str::to_owned)
}

/// Chromium's extension-owned redirect origin for `identity` flows.
#[must_use]
pub fn redirect_uri_for_extension(extension_id: &str) -> String {
    format!("https://{extension_id}{EXTENSION_REDIRECT_SUFFIX}")
}

/// Whether `url` lands on `redirect_uri`.
///
/// Loopback redirects (RFC 8252 §7.3) match any port; other origins require
/// an exact scheme/host/port/path match.
#[must_use]
pub fn redirect_matches_redirect_uri(url: &Url, redirect_uri: &str) -> bool {
    let Ok(target) = Url::parse(redirect_uri) else {
        return false;
    };
    if url.scheme() != target.scheme() {
        return false;
    }
    if url.host_str() != target.host_str() || url.path() != target.path() {
        return false;
    }
    if is_loopback(&target) {
        return true;
    }
    url.port() == target.port()
}

fn is_loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
}

/// Reads the authorization completion of a redirect URL.
///
/// `Ok(None)` means the URL carries neither `code` nor `error` and is not a
/// completion; `Err(AccessDenied)` is the user-denial path.
///
/// # Errors
///
/// Returns the mapped error variant for provider-declared `error` parameters.
pub fn authorization_completion(url: &Url) -> Result<Option<String>, OAuthFlowError> {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let code = pairs
        .iter()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.clone())
        .filter(|code| !code.is_empty());
    if let Some(code) = code {
        return Ok(Some(code));
    }
    let Some(error) = pairs.iter().find(|(name, _)| name == "error") else {
        return Ok(None);
    };
    Err(match error.1.as_str() {
        "access_denied" => OAuthFlowError::AccessDenied,
        "invalid_client" => OAuthFlowError::InvalidClient,
        "invalid_grant" => OAuthFlowError::InvalidGrant,
        other => OAuthFlowError::MalformedResponse(format!("provider error {other:?}")),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        account_id_from_id_token, authorization_completion, build_authorize_url,
        challenge_from_verifier, exchange_request_body, generate_pkce_pair, parse_token_response,
        redirect_matches_redirect_uri, redirect_uri_for_extension, refresh_request_body, token_key,
        OAuthFlowError, OAuthProviderConfig, OAuthTokenRecord, PkcePair, TokenExchangeRequest,
        GOOGLE_OAUTH_TOKEN_ENDPOINT,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use url::Url;

    fn provider() -> OAuthProviderConfig {
        OAuthProviderConfig {
            client_id: "client-123".to_owned(),
            auth_endpoint: None,
            token_endpoint: None,
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        }
    }

    fn record(expires_at_ms: u64) -> OAuthTokenRecord {
        OAuthTokenRecord {
            access_token: "secret-access-token".to_owned(),
            refresh_token: Some("secret-refresh-token".to_owned()),
            expires_at_ms,
            scopes: vec!["openid".to_owned()],
            account_id: Some("acct".to_owned()),
            stored_at_ms: 0,
        }
    }

    #[test]
    fn build_authorize_url_carries_pkce_and_provider_defaults() {
        let pair = PkcePair {
            verifier: "verifier-abc".to_owned(),
            challenge: challenge_from_verifier("verifier-abc"),
        };
        let url = build_authorize_url(
            &provider(),
            "https://ext.chromiumapp.org/",
            "state-1",
            &pair.challenge,
        )
        .unwrap();
        let parsed = Url::parse(&url).unwrap();
        assert_eq!(
            parsed.origin().ascii_serialization(),
            "https://accounts.google.com"
        );
        assert_eq!(parsed.path(), "/o/oauth2/v2/auth");
        let query: std::collections::HashMap<String, String> = parsed
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("client-123")
        );
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some("https://ext.chromiumapp.org/")
        );
        assert_eq!(query.get("scope").map(String::as_str), Some("openid email"));
        assert_eq!(query.get("state").map(String::as_str), Some("state-1"));
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some(pair.challenge.as_str())
        );
    }

    #[test]
    fn build_authorize_url_honors_custom_endpoints() {
        let mut custom = provider();
        custom.auth_endpoint = Some("https://auth.example.com/authorize".to_owned());
        custom.token_endpoint = Some("https://auth.example.com/token".to_owned());
        let url = build_authorize_url(&custom, "https://ext.chromiumapp.org/", "s", "c").unwrap();
        assert!(url.starts_with("https://auth.example.com/authorize?"));
    }

    #[test]
    fn build_authorize_url_rejects_bad_endpoints() {
        let mut bad = provider();
        bad.auth_endpoint = Some(":://nope".to_owned());
        assert!(matches!(
            build_authorize_url(&bad, "https://e.chromiumapp.org/", "s", "c"),
            Err(OAuthFlowError::Transport(_))
        ));
        bad.auth_endpoint = Some("ftp://auth.example.com".to_owned());
        assert!(matches!(
            build_authorize_url(&bad, "https://e.chromiumapp.org/", "s", "c"),
            Err(OAuthFlowError::Transport(_))
        ));
    }

    #[test]
    fn pkce_pairs_derive_challenges_from_verifiers() {
        let pair = generate_pkce_pair().unwrap();
        assert_eq!(pair.challenge, challenge_from_verifier(&pair.verifier));
        assert!(pair.verifier.len() >= 43);
        assert_ne!(pair.verifier, generate_pkce_pair().unwrap().verifier);
    }

    #[test]
    fn exchange_bodies_are_form_encoded() {
        assert_eq!(
            exchange_request_body("c o+de", "https://e.chromiumapp.org/", "cid", "v~er"),
            "grant_type=authorization_code&code=c%20o%2Bde&redirect_uri=https%3A%2F%2Fe.chromiumapp.org%2F&client_id=cid&code_verifier=v~er"
        );
        assert_eq!(
            refresh_request_body("r t", "cid"),
            "grant_type=refresh_token&refresh_token=r%20t&client_id=cid"
        );
    }

    #[test]
    fn exchange_requests_build_real_http_posts() {
        let request = TokenExchangeRequest::new(
            GOOGLE_OAUTH_TOKEN_ENDPOINT,
            &refresh_request_body("rt", "cid"),
        )
        .unwrap();
        let bytes = String::from_utf8(request.http_bytes()).unwrap();
        assert!(bytes.starts_with("POST /token HTTP/1.1\r\n"));
        assert!(bytes.contains("Host: oauth2.googleapis.com\r\n"));
        assert!(bytes.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(bytes.contains("grant_type=refresh_token"));
        assert!(matches!(
            TokenExchangeRequest::new("ftp://x/token", "a=b"),
            Err(OAuthFlowError::Transport(_))
        ));
    }

    #[test]
    fn token_responses_parse_into_records() {
        let record = parse_token_response(
            200,
            br#"{"access_token":"at-1","token_type":"Bearer","expires_in":1800,"refresh_token":"rt-1","scope":"openid email","id_token":"a.eyJzdWIiOiJhY2NvdW50LTcifQ.b"}"#,
            1_000,
        )
        .unwrap();
        assert_eq!(record.access_token, "at-1");
        assert_eq!(record.refresh_token.as_deref(), Some("rt-1"));
        assert_eq!(record.expires_at_ms, 1_000 + 1_800 * 1_000);
        assert_eq!(record.scopes, vec!["openid", "email"]);
        assert_eq!(record.account_id.as_deref(), Some("account-7"));
        let default = parse_token_response(200, br#"{"access_token":"at-2"}"#, 5_000).unwrap();
        assert_eq!(default.expires_at_ms, 5_000 + 3_600 * 1_000);
        assert!(default.refresh_token.is_none());
    }

    #[test]
    fn token_errors_map_to_flow_error_variants() {
        for (body, expected) in [
            (
                &br#"{"error":"invalid_client"}"#[..],
                OAuthFlowError::InvalidClient,
            ),
            (
                &br#"{"error":"invalid_grant"}"#[..],
                OAuthFlowError::InvalidGrant,
            ),
            (
                &br#"{"error":"access_denied"}"#[..],
                OAuthFlowError::AccessDenied,
            ),
            (
                &br#"{"error":"unsupported_grant_type"}"#[..],
                OAuthFlowError::MalformedResponse(
                    "provider error \"unsupported_grant_type\"".to_owned(),
                ),
            ),
            (
                &br"{}"[..],
                OAuthFlowError::MalformedResponse("missing error code".to_owned()),
            ),
        ] {
            assert_eq!(
                parse_token_response(400, body, 0).unwrap_err(),
                expected,
                "body {body:?}"
            );
        }
        assert!(matches!(
            parse_token_response(200, br#"{"token_type":"Bearer"}"#, 0),
            Err(OAuthFlowError::MalformedResponse(_))
        ));
        assert!(matches!(
            parse_token_response(200, b"not json", 0),
            Err(OAuthFlowError::MalformedResponse(_))
        ));
    }

    #[test]
    fn token_records_never_debug_leak_secrets() {
        let rendered = format!("{:?}", record(10));
        assert!(!rendered.contains("secret-access-token"));
        assert!(!rendered.contains("secret-refresh-token"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn token_expiration_is_wall_clock() {
        assert!(!record(10).is_expired_at(9));
        assert!(record(10).is_expired_at(10));
        assert!(record(10).is_expired_at(11));
    }

    #[test]
    fn token_keys_are_scope_ordered_per_client() {
        let first = token_key("ext", "cid", &["b".to_owned(), "a".to_owned()]);
        assert_eq!(
            first,
            token_key("ext", "cid", &["a".to_owned(), "b".to_owned()])
        );
        assert_ne!(
            first,
            token_key(
                "ext",
                "cid",
                &["a".to_owned(), "b".to_owned(), "c".to_owned()]
            )
        );
        assert_ne!(
            first,
            token_key("other", "cid", &["a".to_owned(), "b".to_owned()])
        );
        assert_ne!(
            first,
            token_key("ext", "cid2", &["a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn id_tokens_reveal_account_subjects_without_verification() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"subject-9"}"#);
        let id_token = format!("header.{payload}.signature");
        assert_eq!(
            account_id_from_id_token(&id_token).as_deref(),
            Some("subject-9")
        );
        assert_eq!(account_id_from_id_token("garbage"), None);
        let empty = URL_SAFE_NO_PAD.encode(br#"{"sub":""}"#);
        assert_eq!(account_id_from_id_token(&format!("h.{empty}.s")), None);
    }

    #[test]
    fn extension_redirects_use_the_chromiumapp_origin() {
        assert_eq!(
            redirect_uri_for_extension("wallet"),
            "https://wallet.chromiumapp.org/"
        );
        let url = Url::parse("https://wallet.chromiumapp.org/?code=c").unwrap();
        assert!(redirect_matches_redirect_uri(
            &url,
            &redirect_uri_for_extension("wallet")
        ));
        assert!(redirect_matches_redirect_uri(
            &Url::parse("https://wallet.chromiumapp.org/callback").unwrap(),
            "https://wallet.chromiumapp.org/callback"
        ));
        assert!(!redirect_matches_redirect_uri(
            &Url::parse("https://wallet.chromiumapp.org/other").unwrap(),
            "https://wallet.chromiumapp.org/"
        ));
        assert!(!redirect_matches_redirect_uri(
            &Url::parse("https://wallet.evil.org/?code=c").unwrap(),
            "https://wallet.chromiumapp.org/"
        ));
        assert!(!redirect_matches_redirect_uri(
            &Url::parse("http://wallet.chromiumapp.org/?code=c").unwrap(),
            "https://wallet.chromiumapp.org/"
        ));
        assert!(redirect_matches_redirect_uri(
            &Url::parse("http://127.0.0.1:8123/callback?code=c").unwrap(),
            "http://127.0.0.1:443/callback"
        ));
        assert!(redirect_matches_redirect_uri(
            &Url::parse("http://localhost:9000/?code=c").unwrap(),
            "http://localhost:443/"
        ));
        assert!(!redirect_matches_redirect_uri(
            &Url::parse("https://example.com:8443/?code=c").unwrap(),
            "https://example.com/?code=c"
        ));
        assert!(!redirect_matches_redirect_uri(
            &Url::parse("https://example.com/?code=c").unwrap(),
            "not a url"
        ));
    }

    #[test]
    fn completions_extract_codes_and_deny_paths() {
        assert_eq!(
            authorization_completion(&Url::parse("https://e.chromiumapp.org/?code=xyz").unwrap())
                .unwrap()
                .as_deref(),
            Some("xyz")
        );
        assert_eq!(
            authorization_completion(&Url::parse("https://e.chromiumapp.org/page").unwrap())
                .unwrap(),
            None
        );
        assert_eq!(
            authorization_completion(
                &Url::parse("https://e.chromiumapp.org/?error=access_denied").unwrap()
            )
            .unwrap_err(),
            OAuthFlowError::AccessDenied
        );
        assert_eq!(
            authorization_completion(
                &Url::parse("https://e.chromiumapp.org/?error=server_error").unwrap()
            )
            .unwrap_err(),
            OAuthFlowError::MalformedResponse("provider error \"server_error\"".to_owned())
        );
        assert_eq!(
            authorization_completion(&Url::parse("https://e.chromiumapp.org/?code=").unwrap())
                .unwrap(),
            None
        );
    }
}
