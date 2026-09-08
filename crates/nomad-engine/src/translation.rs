#![allow(clippy::missing_errors_doc)]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Builder;
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TranslationLanguage {
    Auto,
    English,
    Russian,
    German,
    French,
    Spanish,
    Arabic,
    Chinese,
    Japanese,
    Korean,
}

impl TranslationLanguage {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::English => "en",
            Self::Russian => "ru",
            Self::German => "de",
            Self::French => "fr",
            Self::Spanish => "es",
            Self::Arabic => "ar",
            Self::Chinese => "zh",
            Self::Japanese => "ja",
            Self::Korean => "ko",
        }
    }

    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code.trim().to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "en" | "eng" => Self::English,
            "ru" | "rus" => Self::Russian,
            "de" | "deu" => Self::German,
            "fr" | "fra" => Self::French,
            "es" | "spa" => Self::Spanish,
            "ar" | "ara" => Self::Arabic,
            "zh" | "zho" => Self::Chinese,
            "ja" | "jpn" => Self::Japanese,
            "ko" | "kor" => Self::Korean,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslationProvider {
    Local,
    Endpoint(Url),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslationRequest {
    pub source: TranslationLanguage,
    pub target: TranslationLanguage,
    pub text: String,
    pub provider: TranslationProvider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslationError {
    EmptyText,
    InvalidTarget,
    LocalBackendUnavailable,
    UnsupportedEndpointScheme(String),
    InvalidEndpoint(String),
    Transport(String),
    InvalidResponse(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslationResult {
    pub source: TranslationLanguage,
    pub target: TranslationLanguage,
    pub text: String,
}

/// Executes an explicit user-selected translation endpoint.
///
/// The endpoint receives a GET request with `source`, `target`, and `text`
/// query parameters. Responses may be plain text or JSON containing one of
/// `translation`, `translatedText`, `text`, or
/// `data.translations[0].translatedText`.
pub struct EndpointTranslationExecutor {
    timeout: std::time::Duration,
}

impl Default for EndpointTranslationExecutor {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(20),
        }
    }
}

impl EndpointTranslationExecutor {
    #[must_use]
    pub const fn new(timeout: std::time::Duration) -> Self {
        Self { timeout }
    }

    pub fn execute(
        &self,
        request: &TranslationRequest,
    ) -> Result<TranslationResult, TranslationError> {
        let endpoint = match &request.provider {
            TranslationProvider::Endpoint(endpoint) => endpoint,
            TranslationProvider::Local => return Err(TranslationError::LocalBackendUnavailable),
        };
        let body = match endpoint.scheme() {
            "http" => self.execute_http(request, endpoint)?,
            "https" => self.execute_https(request, endpoint)?,
            scheme => {
                return Err(TranslationError::UnsupportedEndpointScheme(
                    scheme.to_owned(),
                ));
            }
        };
        let text = parse_translation_response(&body)?;
        Ok(TranslationResult {
            source: request.source,
            target: request.target,
            text,
        })
    }

    fn execute_http(
        &self,
        request: &TranslationRequest,
        endpoint: &Url,
    ) -> Result<String, TranslationError> {
        let host = endpoint
            .host_str()
            .ok_or_else(|| TranslationError::InvalidEndpoint(endpoint.to_string()))?;
        let port = endpoint
            .port_or_known_default()
            .ok_or_else(|| TranslationError::InvalidEndpoint(endpoint.to_string()))?;
        let address = (host, port)
            .to_socket_addrs()
            .map_err(|error| TranslationError::Transport(error.to_string()))?
            .next()
            .ok_or_else(|| TranslationError::Transport("endpoint has no address".to_owned()))?;
        let mut stream = TcpStream::connect_timeout(&address, self.timeout)
            .map_err(|error| TranslationError::Transport(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|error| TranslationError::Transport(error.to_string()))?;
        let url = request
            .endpoint_url()
            .ok_or_else(|| TranslationError::InvalidEndpoint(endpoint.to_string()))?;
        let path = request_target(&url);
        let host_header = endpoint.host_str().unwrap_or_default();
        let request_bytes = format!(
            "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json, text/plain\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request_bytes.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|error| TranslationError::Transport(error.to_string()))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| TranslationError::Transport(error.to_string()))?;
        parse_http_response(&response)
    }

    fn execute_https(
        &self,
        request: &TranslationRequest,
        endpoint: &Url,
    ) -> Result<String, TranslationError> {
        let endpoint = endpoint.clone();
        let request = request.clone();
        let timeout = self.timeout;
        Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| TranslationError::Transport(error.to_string()))?
            .block_on(async move {
                let host = endpoint.host_str().ok_or_else(|| {
                    TranslationError::InvalidEndpoint(endpoint.to_string())
                })?;
                let port = endpoint.port_or_known_default().ok_or_else(|| {
                    TranslationError::InvalidEndpoint(endpoint.to_string())
                })?;
                let stream = tokio::time::timeout(
                    timeout,
                    TokioTcpStream::connect((host.to_owned(), port)),
                )
                .await
                .map_err(|error| TranslationError::Transport(error.to_string()))?
                .map_err(|error| TranslationError::Transport(error.to_string()))?;
                let roots: rustls::RootCertStore =
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let connector = TlsConnector::from(Arc::new(config));
                let server_name = ServerName::try_from(host.to_owned())
                    .map_err(|_| TranslationError::InvalidEndpoint(endpoint.to_string()))?;
                let mut stream = tokio::time::timeout(
                    timeout,
                    connector.connect(server_name, stream),
                )
                .await
                .map_err(|error| TranslationError::Transport(error.to_string()))?
                .map_err(|error| TranslationError::Transport(error.to_string()))?;
                let url = request.endpoint_url().ok_or_else(|| {
                    TranslationError::InvalidEndpoint(endpoint.to_string())
                })?;
                let path = request_target(&url);
                let request_bytes = format!(
                    "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json, text/plain\r\nConnection: close\r\n\r\n"
                );
                tokio::time::timeout(timeout, stream.write_all(request_bytes.as_bytes()))
                    .await
                    .map_err(|error| TranslationError::Transport(error.to_string()))?
                    .map_err(|error| TranslationError::Transport(error.to_string()))?;
                let mut response = Vec::new();
                tokio::time::timeout(timeout, stream.read_to_end(&mut response))
                    .await
                    .map_err(|error| TranslationError::Transport(error.to_string()))?
                    .map_err(|error| TranslationError::Transport(error.to_string()))?;
                parse_http_response(&response)
            })
    }
}

impl TranslationRequest {
    pub fn new(
        source: TranslationLanguage,
        target: TranslationLanguage,
        text: impl Into<String>,
        provider: TranslationProvider,
    ) -> Result<Self, TranslationError> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(TranslationError::EmptyText);
        }
        if target == TranslationLanguage::Auto || source == target {
            return Err(TranslationError::InvalidTarget);
        }
        Ok(Self {
            source,
            target,
            text,
            provider,
        })
    }

    #[must_use]
    pub fn endpoint_url(&self) -> Option<Url> {
        let TranslationProvider::Endpoint(endpoint) = &self.provider else {
            return None;
        };
        let mut endpoint = endpoint.clone();
        endpoint
            .query_pairs_mut()
            .append_pair("source", self.source.code())
            .append_pair("target", self.target.code())
            .append_pair("text", &self.text);
        Some(endpoint)
    }

    pub fn require_local_backend(
        &self,
        local_backend_available: bool,
    ) -> Result<(), TranslationError> {
        if matches!(self.provider, TranslationProvider::Local) && !local_backend_available {
            return Err(TranslationError::LocalBackendUnavailable);
        }
        Ok(())
    }
}

fn request_target(url: &Url) -> String {
    let mut target = url.path().to_owned();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

fn parse_http_response(response: &[u8]) -> Result<String, TranslationError> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| TranslationError::InvalidResponse("missing HTTP headers".to_owned()))?;
    let headers = std::str::from_utf8(&response[..separator])
        .map_err(|error| TranslationError::InvalidResponse(error.to_string()))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| TranslationError::InvalidResponse("invalid HTTP status".to_owned()))?;
    if !(200..300).contains(&status) {
        return Err(TranslationError::InvalidResponse(format!(
            "translation endpoint returned HTTP {status}"
        )));
    }
    let body = &response[separator + 4..];
    String::from_utf8(body.to_vec())
        .map_err(|error| TranslationError::InvalidResponse(error.to_string()))
}

fn parse_translation_response(body: &str) -> Result<String, TranslationError> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        let candidates = [
            value.get("translation"),
            value.get("translatedText"),
            value.get("text"),
            value
                .get("data")
                .and_then(|data| data.get("translations"))
                .and_then(|translations| translations.get(0))
                .and_then(|translation| translation.get("translatedText")),
        ];
        if let Some(text) = candidates
            .into_iter()
            .flatten()
            .find_map(serde_json::Value::as_str)
        {
            if !text.trim().is_empty() {
                return Ok(text.to_owned());
            }
        }
        return Err(TranslationError::InvalidResponse(
            "JSON response has no translation field".to_owned(),
        ));
    }
    let text = body.trim();
    (!text.is_empty())
        .then_some(text.to_owned())
        .ok_or_else(|| TranslationError::InvalidResponse("empty translation response".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_translation_response, EndpointTranslationExecutor, TranslationLanguage,
        TranslationProvider, TranslationRequest,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;
    use url::Url;

    #[test]
    fn language_codes_support_interactive_selection() {
        assert_eq!(
            TranslationLanguage::from_code("RU"),
            Some(TranslationLanguage::Russian)
        );
        assert_eq!(TranslationLanguage::Japanese.code(), "ja");
    }

    #[test]
    fn endpoint_request_is_explicit_and_url_encoded() {
        let request = TranslationRequest::new(
            TranslationLanguage::English,
            TranslationLanguage::German,
            "hello world",
            TranslationProvider::Endpoint(Url::parse("https://translator.example/v1").unwrap()),
        )
        .unwrap();
        assert_eq!(
            request.endpoint_url().unwrap().as_str(),
            "https://translator.example/v1?source=en&target=de&text=hello+world"
        );
    }

    #[test]
    fn translation_response_accepts_common_provider_shapes() {
        assert_eq!(
            parse_translation_response(r#"{"translatedText":"Hallo"}"#).unwrap(),
            "Hallo"
        );
        assert_eq!(
            parse_translation_response(
                r#"{"data":{"translations":[{"translatedText":"Привет"}]}}"#
            )
            .unwrap(),
            "Привет"
        );
        assert_eq!(parse_translation_response("Bonjour").unwrap(), "Bonjour");
    }

    #[test]
    fn endpoint_executor_performs_real_explicit_http_request() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8(request[..length].to_vec()).unwrap();
            assert!(request.contains("source=en"));
            assert!(request.contains("target=de"));
            assert!(request.contains("text=hello+world"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"translation\":\"Hallo Welt\"}",
                )
                .unwrap();
        });
        let request = TranslationRequest::new(
            TranslationLanguage::English,
            TranslationLanguage::German,
            "hello world",
            TranslationProvider::Endpoint(
                Url::parse(&format!("http://{address}/translate")).unwrap(),
            ),
        )
        .unwrap();
        let result = EndpointTranslationExecutor::new(Duration::from_secs(2))
            .execute(&request)
            .unwrap();
        assert_eq!(result.text, "Hallo Welt");
        server.join().unwrap();
    }
}
