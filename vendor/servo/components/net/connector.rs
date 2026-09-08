/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::hash_map::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use std::{fmt, io};

use futures::task::{Context, Poll};
use futures::{Future, TryFutureExt};
use http::uri::{Authority, Uri as Destination};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::rt::Executor;
use hyper_rustls::{HttpsConnector as HyperRustlsHttpsConnector, MaybeHttpsStream};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::proxy::Tunnel;
use hyper_util::client::legacy::connect::{
    Connected, Connection, HttpConnector as HyperHttpConnector,
};
use hyper_util::rt::TokioIo;
use log::warn;
use parking_lot::Mutex;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::{ClientConnection, EchStatus};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::{ClientConfig, ProtocolVersion};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use servo_config::pref;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower::Service;

use crate::async_runtime::spawn_task;
use crate::hosts::replace_host;

pub const BUF_SIZE: usize = 32768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsResolutionRoute {
    System,
    Proxy,
}

#[derive(Clone, Debug)]
pub enum NetworkConnectionEvent {
    Connecting {
        destination: String,
        proxy: Option<String>,
        dns_route: DnsResolutionRoute,
    },
    Connected {
        destination: String,
        proxy: Option<String>,
        dns_route: DnsResolutionRoute,
        tls_protocol: Option<String>,
        tls_cipher_suite: Option<String>,
        alpn_protocol: Option<String>,
        used_ech: bool,
    },
    Failed {
        destination: String,
        proxy: Option<String>,
        dns_route: DnsResolutionRoute,
        error: String,
    },
}

pub type NetworkObserver = Arc<dyn Fn(NetworkConnectionEvent) + Send + Sync>;

static NETWORK_OBSERVER: LazyLock<Mutex<Option<NetworkObserver>>> =
    LazyLock::new(|| Mutex::new(None));

pub fn set_network_observer(observer: Option<NetworkObserver>) {
    *NETWORK_OBSERVER.lock() = observer;
}

fn report_network_event(event: NetworkConnectionEvent) {
    if let Some(observer) = NETWORK_OBSERVER.lock().as_ref() {
        observer(event);
    }
}

/// ALPN identifier for HTTP/2 (RFC 7540 §3.1).
pub const ALPN_H2: &str = "h2";

#[derive(Clone)]
pub struct ServoHttpConnector {
    inner: HyperHttpConnector,
}

impl ServoHttpConnector {
    fn new() -> ServoHttpConnector {
        let mut inner = HyperHttpConnector::new();
        inner.enforce_http(false);
        inner.set_happy_eyeballs_timeout(None);
        inner.set_connect_timeout(Some(Duration::from_secs(pref!(network_connection_timeout))));
        ServoHttpConnector { inner }
    }
}

impl Service<Destination> for ServoHttpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = ConnectionError;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<TokioIo<TcpStream>, ConnectionError>> + Send>>;

    fn call(&mut self, dest: Destination) -> Self::Future {
        // Perform host replacement when making the actual TCP connection.
        let mut new_dest = dest.clone();
        let mut parts = dest.into_parts();

        if let Some(auth) = parts.authority {
            let host = auth.host();
            let host = replace_host(host);

            let authority = if let Some(port) = auth.port() {
                format!("{}:{}", host, port.as_str())
            } else {
                (*host).to_string()
            };

            if let Ok(authority) = Authority::from_maybe_shared(authority) {
                parts.authority = Some(authority);
                if let Ok(dest) = Destination::from_parts(parts) {
                    new_dest = dest
                }
            }
        }

        Box::pin(
            self.inner
                .call(new_dest)
                .map_err(|e| ConnectionError::HttpError(format!("{e}"))),
        )
    }

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct InstrumentedConnector<T> {
    inner: HyperRustlsHttpsConnector<T>,
}

impl<T> InstrumentedConnector<T> {
    fn new(inner: HyperRustlsHttpsConnector<T>) -> Self {
        Self { inner }
    }
}

impl<T> From<HyperRustlsHttpsConnector<T>> for InstrumentedConnector<T> {
    fn from(inner: HyperRustlsHttpsConnector<T>) -> Self {
        Self::new(inner)
    }
}

pub struct InstrumentedStream<T> {
    inner: MaybeHttpsStream<T>,
    tls_info: Option<TlsHandshakeInfo>,
}

impl<T: Unpin> Unpin for InstrumentedStream<T> {}

impl<T> fmt::Debug for InstrumentedStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstrumentedStream")
            .field("tls_info", &self.tls_info)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct TlsHandshakeInfo {
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub kea_group_name: Option<String>,
    pub signature_scheme_name: Option<String>,
    pub alpn_protocol: Option<String>,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub used_ech: bool,
}

impl TlsHandshakeInfo {
    fn from_connection(conn: &ClientConnection) -> Self {
        let protocol_version = conn.protocol_version().map(protocol_version_to_string);
        let cipher_suite = conn
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite()));
        let kea_group_name = conn
            .negotiated_key_exchange_group()
            .map(|group| format!("{:?}", group.name()));
        let certificate_chain_der = conn
            .peer_certificates()
            .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
            .unwrap_or_default();
        let alpn_protocol = conn
            .alpn_protocol()
            .map(|proto| String::from_utf8_lossy(proto).into_owned());
        let used_ech = matches!(conn.ech_status(), EchStatus::Accepted);

        Self {
            protocol_version,
            cipher_suite,
            kea_group_name,
            signature_scheme_name: None,
            alpn_protocol,
            certificate_chain_der,
            used_ech,
        }
    }
}

fn protocol_version_to_string(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        ProtocolVersion::TLSv1_1 => "TLS 1.1".to_string(),
        ProtocolVersion::TLSv1_0 => "TLS 1.0".to_string(),
        ProtocolVersion::SSLv2 => "SSL 2.0".to_string(),
        ProtocolVersion::SSLv3 => "SSL 3.0".to_string(),
        ProtocolVersion::DTLSv1_0 => "DTLS 1.0".to_string(),
        ProtocolVersion::DTLSv1_2 => "DTLS 1.2".to_string(),
        ProtocolVersion::DTLSv1_3 => "DTLS 1.3".to_string(),
        ProtocolVersion::Unknown(v) => format!("Unknown(0x{v:04x})"),
        _ => format!("{version:?}"),
    }
}

impl<T> InstrumentedStream<T>
where
    T: Connection + hyper::rt::Read + hyper::rt::Write + Unpin,
{
    fn from_maybe_https_stream(stream: MaybeHttpsStream<T>) -> Self {
        match stream {
            MaybeHttpsStream::Http(inner) => Self {
                inner: MaybeHttpsStream::Http(inner),
                tls_info: None,
            },
            MaybeHttpsStream::Https(tls_stream) => {
                let (_tcp, tls) = tls_stream.inner().get_ref();
                let tls_info = TlsHandshakeInfo::from_connection(tls);

                Self {
                    inner: MaybeHttpsStream::Https(tls_stream),
                    tls_info: Some(tls_info),
                }
            },
        }
    }
}

impl<T> Connection for InstrumentedStream<T>
where
    T: Connection + hyper::rt::Read + hyper::rt::Write + Unpin,
{
    fn connected(&self) -> Connected {
        let connected = match &self.inner {
            MaybeHttpsStream::Http(stream) => stream.connected(),
            MaybeHttpsStream::Https(stream) => {
                let (tcp, tls) = stream.inner().get_ref();
                if tls.alpn_protocol() == Some(ALPN_H2.as_bytes()) {
                    tcp.inner().connected().negotiated_h2()
                } else {
                    tcp.inner().connected()
                }
            },
        };
        if let Some(info) = &self.tls_info {
            connected.extra(info.clone())
        } else {
            connected
        }
    }
}

impl<T> hyper::rt::Read for InstrumentedStream<T>
where
    T: Connection + hyper::rt::Read + hyper::rt::Write + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T> hyper::rt::Write for InstrumentedStream<T>
where
    T: Connection + hyper::rt::Read + hyper::rt::Write + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}

impl<T> Service<Destination> for InstrumentedConnector<T>
where
    T: Service<Destination>,
    T::Response: Connection + hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    T::Future: Send + 'static,
    T::Error: Into<BoxError>,
{
    type Response = InstrumentedStream<T::Response>;
    type Error = BoxError;
    type Future = std::pin::Pin<
        Box<dyn Future<Output = Result<InstrumentedStream<T::Response>, BoxError>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Destination) -> Self::Future {
        let (proxy, dns_route) = proxy_metadata(&dst);
        let destination = dst.to_string();
        let future = self.inner.call(dst);
        Box::pin(async move {
            let stream = match future.await {
                Ok(stream) => stream,
                Err(error) => {
                    report_network_event(NetworkConnectionEvent::Failed {
                        destination,
                        proxy,
                        dns_route,
                        error: error.to_string(),
                    });
                    return Err::<InstrumentedStream<T::Response>, BoxError>(error.into());
                },
            };
            let stream = InstrumentedStream::from_maybe_https_stream(stream);
            let (tls_protocol, tls_cipher_suite, alpn_protocol, used_ech) = stream
                .tls_info
                .as_ref()
                .map_or((None, None, None, false), |info| {
                    (
                        info.protocol_version.clone(),
                        info.cipher_suite.clone(),
                        info.alpn_protocol.clone(),
                        info.used_ech,
                    )
                });
            report_network_event(NetworkConnectionEvent::Connected {
                destination,
                proxy,
                dns_route,
                tls_protocol,
                tls_cipher_suite,
                alpn_protocol,
                used_ech,
            });
            Ok(stream)
        })
    }
}

pub type Connector = InstrumentedConnector<ServoHttpConnector>;
pub type TlsConfig = ClientConfig;

#[derive(Clone, Debug, Default)]
struct CertificateErrorOverrideManagerInternal {
    /// A mapping of certificates and their hosts, which have seen certificate errors.
    /// This is used to later create an override in this [CertificateErrorOverrideManager].
    certificates_failing_to_verify: HashMap<ServerName<'static>, CertificateDer<'static>>,
    /// A list of certificates that should be accepted despite encountering verification
    /// errors.
    overrides: Vec<CertificateDer<'static>>,
}

/// This data structure is used to track certificate verification errors and overrides.
/// It tracks:
///  - A list of [Certificate]s with verification errors mapped by their [ServerName]
///  - A list of [Certificate]s for which to ignore verification errors.
#[derive(Clone, Debug, Default)]
pub struct CertificateErrorOverrideManager(Arc<Mutex<CertificateErrorOverrideManagerInternal>>);

impl CertificateErrorOverrideManager {
    pub fn new() -> Self {
        Self(Default::default())
    }

    /// Add a certificate to this manager's list of certificates for which to ignore
    /// validation errors.
    pub fn add_override(&self, certificate: &CertificateDer<'static>) {
        self.0.lock().overrides.push(certificate.clone());
    }

    /// Given the a string representation of a sever host name, remove information about
    /// a [Certificate] with verification errors. If a certificate with
    /// verification errors was found, return it, otherwise None.
    pub(crate) fn remove_certificate_failing_verification(
        &self,
        host: &str,
    ) -> Option<CertificateDer<'static>> {
        let server_name = match ServerName::try_from(host) {
            Ok(name) => name.to_owned(),
            Err(error) => {
                warn!("Could not convert host string into RustTLS ServerName: {error:?}");
                return None;
            },
        };
        self.0
            .lock()
            .certificates_failing_to_verify
            .remove(&server_name)
    }
}

#[derive(Clone, Debug, Default)]
pub enum CACertificates<'de> {
    #[default]
    Default,
    Override(Vec<CertificateDer<'de>>),
}

/// Create a [TlsConfig] to use for managing a HTTP connection. This currently creates
/// a rustls [ClientConfig].
///
/// FIXME: The `ignore_certificate_errors` argument ignores all certificate errors. This
/// is used when running the WPT tests, because rustls currently rejects the WPT certificiate.
/// See <https://github.com/servo/servo/issues/30080>
#[servo_tracing::instrument(skip_all)]
pub fn create_tls_config(
    ca_certificates: CACertificates<'static>,
    ignore_certificate_errors: bool,
    override_manager: CertificateErrorOverrideManager,
) -> TlsConfig {
    let verifier = CertificateVerificationOverrideVerifier::new(
        ca_certificates,
        ignore_certificate_errors,
        override_manager,
    );
    // TODO: After <https://github.com/rustls/rustls-platform-verifier/pull/204> is merged,
    // `dangerous` can be removed.
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}

#[derive(Clone)]
struct TokioExecutor {}

impl<F> Executor<F> for TokioExecutor
where
    F: Future<Output = ()> + 'static + std::marker::Send,
{
    fn execute(&self, fut: F) {
        spawn_task(fut);
    }
}

static CRYPTO_PROVIDER_CACHE: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| {
    CryptoProvider::get_default()
        .cloned()
        // The embedder should have initialized the default crypto provider before
        // initializing servo, so this should never fail.
        .unwrap_or_else(|| {
            warn!("Default crypto provider not initialized before first access in connector.");
            Arc::new(aws_lc_rs::default_provider())
        })
});

/// A cache for the default rustls platform verifier.
///
/// Instantiating a new verifier can be expensive, since it can read through all certificates:
/// <https://github.com/rustls/rustls-platform-verifier/blob/996b1c903491641b17b3c9afb65d1352f6fc6b76/rustls-platform-verifier/src/verification/others.rs#L92>
static RUSTLS_PLATFORM_VERIFIER_CACHE: LazyLock<Arc<rustls_platform_verifier::Verifier>> =
    LazyLock::new(|| {
        Arc::new(
            rustls_platform_verifier::Verifier::new(CRYPTO_PROVIDER_CACHE.clone())
                .expect("Could not initialize platform certificate verifier"),
        )
    });

/// Prewarm the TLS stack to speed up the first connection
///
/// Currently, this force-seeds the crypto provider (from aws_lc_rs),
/// which on my system takes around 30-50ms according to samply, spent in
/// `tree_jitter_initialize_once`. If we don't call this function, then
/// the initialization will happen much later, on a tokio runtime thread.
#[inline]
pub fn prewarm_tls() {
    #[servo_tracing::instrument]
    fn prewarm_tls_impl() {
        let mut sink = [0u8; 32];
        // The first access can be slow, if the provider needs to gather entropy.
        let _ = CRYPTO_PROVIDER_CACHE.secure_random.fill(&mut sink);
        // Note: We don't need to explicitly force initialize RUSTLS_PLATFORM_VERIFIER_CACHE,
        // since the resource manager thread will do that during startup.
    }

    if let Err(error) = std::thread::Builder::new()
        .name("Net-TLS-prewarm".into())
        .spawn(prewarm_tls_impl)
    {
        warn!("Failed to spawn thread to prewarm TLS: {error:?}");
    }
}

#[derive(Debug)]
struct CertificateVerificationOverrideVerifier {
    main_verifier: Arc<dyn ServerCertVerifier>,
    ignore_certificate_errors: bool,
    override_manager: CertificateErrorOverrideManager,
}

impl CertificateVerificationOverrideVerifier {
    fn new(
        ca_certficates: CACertificates<'static>,
        ignore_certificate_errors: bool,
        override_manager: CertificateErrorOverrideManager,
    ) -> Self {
        // From <https://github.com/rustls/rustls-platform-verifier/blob/main/README.md>:
        // > Some manual setup is required, outside of cargo, to use this crate on
        // > Android. In order to use Android's certificate verifier, the crate needs to
        // > call into the JVM. A small Kotlin component must be included in your app's
        // > build to support rustls-platform-verifier.
        //
        // Since we cannot count on embedders to do this setup, just stick with webpki roots
        // on Android.
        let use_webpki_roots = cfg!(target_os = "android") || pref!(network_use_webpki_roots);
        let main_verifier = if !use_webpki_roots {
            let verifier = match ca_certficates {
                CACertificates::Default => RUSTLS_PLATFORM_VERIFIER_CACHE.clone(),
                // Android doesn't support `Verifier::new_with_extra_roots`, but currently Android
                // never uses the platform verifier at all.
                CACertificates::Override(_certificates) => {
                    #[cfg(target_os = "android")]
                    unreachable!("Android should always use the WebPKI verifier.");
                    #[cfg(not(target_os = "android"))]
                    {
                        let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
                            _certificates,
                            CRYPTO_PROVIDER_CACHE.clone(),
                        )
                        .expect("Could not initialize platform certificate verifier");
                        Arc::new(verifier)
                    }
                },
            };
            verifier as Arc<dyn ServerCertVerifier>
        } else {
            let mut root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            match ca_certficates {
                CACertificates::Default => {},
                CACertificates::Override(certificates) => {
                    for certificate in certificates {
                        if root_store.add(certificate).is_err() {
                            log::error!("Could not add an override certificate.");
                        }
                    }
                },
            }
            rustls::client::WebPkiServerVerifier::builder(root_store.into())
                .build()
                .expect("Could not initialize platform certificate verifier.")
                as Arc<dyn ServerCertVerifier>
        };

        Self {
            main_verifier,
            ignore_certificate_errors,
            override_manager,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for CertificateVerificationOverrideVerifier {
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.main_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.main_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.main_verifier.supported_verify_schemes()
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let error = match self.main_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(result) => return Ok(result),
            Err(error) => error,
        };

        if self.ignore_certificate_errors {
            warn!("Ignoring certficate error: {error:?}");
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // If there's an override for this certificate, just accept it.
        for cert_with_exception in &*self.override_manager.0.lock().overrides {
            if *end_entity == *cert_with_exception {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        self.override_manager
            .0
            .lock()
            .certificates_failing_to_verify
            .insert(server_name.to_owned(), end_entity.clone().into_owned());
        Err(error)
    }
}

pub type BoxedBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug)]
/// The error type for the MaybeProxyConnector
pub enum ConnectionError {
    HttpError(String),
    // It looks like currently the type is not exported.
    ProxyError(String),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ConnectionError {}

#[derive(Clone)]
/// A proxy connector. This will automatically open a proxy connection if the uri matches the proxy uri.
/// Also respects 'no_proxy'.
pub struct ProxyConnector {
    client: ServoHttpConnector,
}

impl ProxyConnector {
    fn new() -> Self {
        ProxyConnector {
            client: ServoHttpConnector::new(),
        }
    }
}

fn parse_socks5_proxy(raw: &str) -> Option<Authority> {
    let uri = raw.parse::<Destination>().ok()?;
    if !matches!(uri.scheme_str(), Some("socks5") | Some("socks5h")) {
        return None;
    }
    uri.authority().cloned()
}

fn proxy_metadata(destination: &Destination) -> (Option<String>, DnsResolutionRoute) {
    let http_proxy_uri = pref!(network_http_proxy_uri).to_owned();
    let https_proxy_uri = pref!(network_https_proxy_uri).to_owned();
    if parse_socks5_proxy(&https_proxy_uri).is_some() {
        return (Some(https_proxy_uri), DnsResolutionRoute::Proxy);
    }
    if parse_socks5_proxy(&http_proxy_uri).is_some() {
        return (Some(http_proxy_uri), DnsResolutionRoute::Proxy);
    }
    let matcher = hyper_util::client::proxy::matcher::Matcher::builder()
        .http(http_proxy_uri)
        .https(https_proxy_uri)
        .no(pref!(network_http_no_proxy))
        .build();
    matcher
        .intercept(destination)
        .map_or((None, DnsResolutionRoute::System), |intercept| {
            (Some(intercept.uri().to_string()), DnsResolutionRoute::Proxy)
        })
}

async fn connect_socks5(
    proxy: Authority,
    destination: Destination,
) -> Result<TokioIo<TcpStream>, ConnectionError> {
    let proxy_host = proxy.host().to_owned();
    let proxy_port = proxy
        .port_u16()
        .ok_or_else(|| ConnectionError::ProxyError("SOCKS5 proxy has no port".to_owned()))?;
    let destination_authority = destination
        .authority()
        .ok_or_else(|| ConnectionError::ProxyError("destination has no authority".to_owned()))?;
    let destination_host = destination_authority.host();
    let destination_port = destination_authority
        .port_u16()
        .or_else(|| match destination.scheme_str() {
            Some("http") => Some(80),
            Some("https") => Some(443),
            _ => None,
        })
        .ok_or_else(|| ConnectionError::ProxyError("destination has no port".to_owned()))?;
    let destination_host_bytes = destination_host.as_bytes();
    let host_length = u8::try_from(destination_host_bytes.len())
        .map_err(|_| ConnectionError::ProxyError("SOCKS5 hostname is too long".to_owned()))?;

    let mut stream = TcpStream::connect((proxy_host.as_str(), proxy_port))
        .await
        .map_err(|error| ConnectionError::ProxyError(format!("SOCKS5 proxy connect: {error}")))?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|error| ConnectionError::ProxyError(format!("SOCKS5 greeting: {error}")))?;

    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.map_err(|error| {
        ConnectionError::ProxyError(format!("SOCKS5 greeting response: {error}"))
    })?;
    if greeting != [0x05, 0x00] {
        return Err(ConnectionError::ProxyError(
            "SOCKS5 proxy does not allow unauthenticated connections".to_owned(),
        ));
    }

    let mut request = Vec::with_capacity(7 + destination_host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_length]);
    request.extend_from_slice(destination_host_bytes);
    request.extend_from_slice(&destination_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| ConnectionError::ProxyError(format!("SOCKS5 connect request: {error}")))?;

    let mut response = [0; 4];
    stream.read_exact(&mut response).await.map_err(|error| {
        ConnectionError::ProxyError(format!("SOCKS5 connect response: {error}"))
    })?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(ConnectionError::ProxyError(format!(
            "SOCKS5 proxy rejected connection with code 0x{:02x}",
            response[1]
        )));
    }
    match response[3] {
        0x01 => read_socks5_bytes(&mut stream, 4).await?,
        0x03 => {
            let mut length = [0; 1];
            stream.read_exact(&mut length).await.map_err(|error| {
                ConnectionError::ProxyError(format!("SOCKS5 bound address: {error}"))
            })?;
            read_socks5_bytes(&mut stream, usize::from(length[0])).await?;
        },
        0x04 => read_socks5_bytes(&mut stream, 16).await?,
        atyp => {
            return Err(ConnectionError::ProxyError(format!(
                "SOCKS5 proxy returned unknown address type 0x{atyp:02x}"
            )));
        },
    }
    read_socks5_bytes(&mut stream, 2).await?;

    Ok(TokioIo::new(stream))
}

async fn read_socks5_bytes(stream: &mut TcpStream, length: usize) -> Result<(), ConnectionError> {
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| ConnectionError::ProxyError(format!("SOCKS5 bound address: {error}")))?;
    Ok(())
}

// Just forward everything to the inner type except that we modify the errors returned.
impl Service<Destination> for ProxyConnector {
    type Response = TokioIo<TcpStream>;
    type Error = ConnectionError;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<TokioIo<TcpStream>, ConnectionError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.client
            .poll_ready(cx)
            .map_err(|e| ConnectionError::ProxyError(format!("{e}")))
    }

    fn call(&mut self, req: Destination) -> Self::Future {
        let destination = req.to_string();
        let (proxy, dns_route) = proxy_metadata(&req);
        report_network_event(NetworkConnectionEvent::Connecting {
            destination,
            proxy,
            dns_route,
        });
        let http_proxy_uri = pref!(network_http_proxy_uri).to_owned();
        let https_proxy_uri = pref!(network_https_proxy_uri).to_owned();
        let socks5_proxy =
            parse_socks5_proxy(&https_proxy_uri).or_else(|| parse_socks5_proxy(&http_proxy_uri));
        if let Some(proxy) = socks5_proxy {
            return Box::pin(connect_socks5(proxy, req));
        }
        let matcher = hyper_util::client::proxy::matcher::Matcher::builder()
            .http(http_proxy_uri)
            .https(https_proxy_uri)
            .no(pref!(network_http_no_proxy))
            .build();
        match matcher.intercept(&req) {
            Some(intercept) => {
                let mut tunnel = Tunnel::new(intercept.uri().clone(), self.client.clone());
                let final_tunnel = if let Some(auth) = intercept.basic_auth() {
                    tunnel.with_auth(auth.clone())
                } else {
                    tunnel
                }
                .call(req)
                .map_err(|e| ConnectionError::ProxyError(format!("{e}")));
                Box::pin(final_tunnel)
            },
            None => Box::pin(
                self.client
                    .call(req)
                    .map_err(|e| ConnectionError::ProxyError(format!("{e}"))),
            ),
        }
    }
}

pub type ServoClient = Client<InstrumentedConnector<ProxyConnector>, BoxedBody>;

pub fn create_http_client(tls_config: TlsConfig) -> ServoClient {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(ProxyConnector::new());

    Client::builder(TokioExecutor {})
        .http1_title_case_headers(true)
        .build(InstrumentedConnector::from(connector))
}
