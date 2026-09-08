use nomad_core::RouteMode;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyScheme {
    HttpConnect,
    Socks5,
}

impl ProxyScheme {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpConnect => "http",
            Self::Socks5 => "socks5h",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEndpoint {
    scheme: ProxyScheme,
    host: String,
    port: u16,
}

impl ProxyEndpoint {
    #[must_use]
    pub fn new(scheme: ProxyScheme, host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme,
            host: host.into(),
            port,
        }
    }

    #[must_use]
    pub const fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn uri(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{}://{}:{}", self.scheme.as_str(), host, self.port)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SiteRouteAction {
    Selected,
    Direct,
    Block,
}

impl SiteRouteAction {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Selected => "Selected route",
            Self::Direct => "Direct",
            Self::Block => "Blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteRoutePolicyError {
    InvalidSitePattern,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SiteRouteRule {
    site: String,
    action: SiteRouteAction,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SiteRoutePolicy {
    rules: Vec<SiteRouteRule>,
}

impl SiteRoutePolicy {
    /// Adds or replaces a suffix-matching site rule.
    ///
    /// A rule for `example.com` matches the apex domain and its subdomains.
    /// Rules are evaluated by most-specific suffix first.
    ///
    /// # Errors
    ///
    /// Returns an error when the pattern is empty or contains URL syntax.
    pub fn add_rule(
        &mut self,
        site: &str,
        action: SiteRouteAction,
    ) -> Result<(), SiteRoutePolicyError> {
        let site = normalize_site_pattern(site)?;
        if let Some(rule) = self.rules.iter_mut().find(|rule| rule.site == site) {
            rule.action = action;
        } else {
            self.rules.push(SiteRouteRule { site, action });
        }
        Ok(())
    }

    fn rule_for(&self, url: &Url) -> Option<&SiteRouteRule> {
        let host = url.host_str()?.to_ascii_lowercase();
        self.rules
            .iter()
            .filter(|rule| host_matches_site(&host, &rule.site))
            .max_by_key(|rule| rule.site.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    mode: RouteMode,
    dns_route: DnsRoute,
    action: SiteRouteAction,
    matched_site: Option<String>,
}

impl RouteDecision {
    #[must_use]
    pub const fn mode(&self) -> RouteMode {
        self.mode
    }

    #[must_use]
    pub const fn dns_route(&self) -> DnsRoute {
        self.dns_route
    }

    #[must_use]
    pub const fn action(&self) -> SiteRouteAction {
        self.action
    }

    #[must_use]
    pub fn matched_site(&self) -> Option<&str> {
        self.matched_site.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyEndpointError {
    InvalidUrl,
    UnsupportedScheme,
    CredentialsNotAllowed,
    MissingHost,
    MissingPort,
}

/// Parses a user-provided proxy endpoint without accepting embedded credentials.
///
/// # Errors
///
/// Returns an error when the endpoint is malformed, uses an unsupported scheme,
/// contains credentials, or has no host or explicit port.
pub fn parse_proxy_endpoint(raw: &str) -> Result<ProxyEndpoint, ProxyEndpointError> {
    let url = Url::parse(raw).map_err(|_| ProxyEndpointError::InvalidUrl)?;
    let scheme = match url.scheme() {
        "http" | "https" => ProxyScheme::HttpConnect,
        "socks5" | "socks5h" => ProxyScheme::Socks5,
        _ => return Err(ProxyEndpointError::UnsupportedScheme),
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ProxyEndpointError::CredentialsNotAllowed);
    }
    let host = url
        .host_str()
        .ok_or(ProxyEndpointError::MissingHost)?
        .to_owned();
    let port = url.port().ok_or(ProxyEndpointError::MissingPort)?;
    Ok(ProxyEndpoint::new(scheme, host, port))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRoute {
    System,
    ViaProxy,
}

impl DnsRoute {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::System => "System resolver",
            Self::ViaProxy => "Proxy-side resolver",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Failed,
}

impl ConnectionState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkTelemetryEvent {
    Connecting {
        destination: String,
        proxy: Option<String>,
        dns_route: DnsRoute,
    },
    Connected {
        destination: String,
        proxy: Option<String>,
        dns_route: DnsRoute,
        tls_protocol: Option<String>,
        tls_cipher_suite: Option<String>,
        alpn_protocol: Option<String>,
        used_ech: bool,
    },
    Failed {
        destination: String,
        proxy: Option<String>,
        dns_route: DnsRoute,
        error: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkDiagnostics {
    state: ConnectionState,
    destination: Option<String>,
    proxy: Option<String>,
    dns_route: DnsRoute,
    tls_protocol: Option<String>,
    tls_cipher_suite: Option<String>,
    alpn_protocol: Option<String>,
    used_ech: bool,
    last_error: Option<String>,
    successful_connections: u64,
    failed_connections: u64,
}

impl NetworkDiagnostics {
    #[must_use]
    pub const fn new(dns_route: DnsRoute) -> Self {
        Self {
            state: ConnectionState::Idle,
            destination: None,
            proxy: None,
            dns_route,
            tls_protocol: None,
            tls_cipher_suite: None,
            alpn_protocol: None,
            used_ech: false,
            last_error: None,
            successful_connections: 0,
            failed_connections: 0,
        }
    }

    pub fn observe(&mut self, event: NetworkTelemetryEvent) {
        match event {
            NetworkTelemetryEvent::Connecting {
                destination,
                proxy,
                dns_route,
            } => {
                self.state = ConnectionState::Connecting;
                self.destination = Some(destination);
                self.proxy = proxy;
                self.dns_route = dns_route;
                self.tls_protocol = None;
                self.tls_cipher_suite = None;
                self.alpn_protocol = None;
                self.used_ech = false;
                self.last_error = None;
            }
            NetworkTelemetryEvent::Connected {
                destination,
                proxy,
                dns_route,
                tls_protocol,
                tls_cipher_suite,
                alpn_protocol,
                used_ech,
            } => {
                self.state = ConnectionState::Connected;
                self.destination = Some(destination);
                self.proxy = proxy;
                self.dns_route = dns_route;
                self.tls_protocol = tls_protocol;
                self.tls_cipher_suite = tls_cipher_suite;
                self.alpn_protocol = alpn_protocol;
                self.used_ech = used_ech;
                self.last_error = None;
                self.successful_connections = self.successful_connections.saturating_add(1);
            }
            NetworkTelemetryEvent::Failed {
                destination,
                proxy,
                dns_route,
                error,
            } => {
                self.state = ConnectionState::Failed;
                self.destination = Some(destination);
                self.proxy = proxy;
                self.dns_route = dns_route;
                self.last_error = Some(error);
                self.failed_connections = self.failed_connections.saturating_add(1);
            }
        }
    }

    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    #[must_use]
    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }

    #[must_use]
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }

    #[must_use]
    pub const fn dns_route(&self) -> DnsRoute {
        self.dns_route
    }

    pub const fn set_dns_route(&mut self, dns_route: DnsRoute) {
        self.dns_route = dns_route;
    }

    #[must_use]
    pub fn tls_protocol(&self) -> Option<&str> {
        self.tls_protocol.as_deref()
    }

    #[must_use]
    pub fn tls_cipher_suite(&self) -> Option<&str> {
        self.tls_cipher_suite.as_deref()
    }

    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&str> {
        self.alpn_protocol.as_deref()
    }

    #[must_use]
    pub const fn used_ech(&self) -> bool {
        self.used_ech
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    #[must_use]
    pub const fn successful_connections(&self) -> u64 {
        self.successful_connections
    }

    #[must_use]
    pub const fn failed_connections(&self) -> u64 {
        self.failed_connections
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkRoute {
    mode: RouteMode,
    proxy: Option<ProxyEndpoint>,
    dns_route: DnsRoute,
    policy: SiteRoutePolicy,
}

impl NetworkRoute {
    #[must_use]
    pub fn direct() -> Self {
        Self::new(RouteMode::Direct, None, DnsRoute::System)
    }

    #[must_use]
    pub fn new(mode: RouteMode, proxy: Option<ProxyEndpoint>, dns_route: DnsRoute) -> Self {
        Self {
            mode,
            proxy,
            dns_route,
            policy: SiteRoutePolicy::default(),
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: SiteRoutePolicy) -> Self {
        self.policy = policy;
        self
    }

    #[must_use]
    pub const fn policy(&self) -> &SiteRoutePolicy {
        &self.policy
    }

    #[must_use]
    pub fn decision_for(&self, url: &Url) -> RouteDecision {
        let rule = self.policy.rule_for(url);
        RouteDecision {
            mode: self.mode,
            dns_route: self.dns_route,
            action: rule.map_or(SiteRouteAction::Selected, |rule| rule.action),
            matched_site: rule.map(|rule| rule.site.clone()),
        }
    }

    #[must_use]
    pub const fn mode(&self) -> RouteMode {
        self.mode
    }

    #[must_use]
    pub const fn mode_label(&self) -> &'static str {
        match self.mode {
            RouteMode::Direct => "Direct",
            RouteMode::Umc => "UMC",
            RouteMode::Xray => "Xray",
        }
    }

    #[must_use]
    pub const fn proxy(&self) -> Option<&ProxyEndpoint> {
        self.proxy.as_ref()
    }

    #[must_use]
    pub const fn dns_route(&self) -> DnsRoute {
        self.dns_route
    }

    #[must_use]
    pub const fn dns_route_label(&self) -> &'static str {
        self.dns_route.label()
    }

    /// Validates that an enabled privacy route cannot silently leak through direct DNS.
    ///
    /// # Errors
    ///
    /// Returns an error when a routed mode has no proxy, uses system DNS, or
    /// when direct mode has a proxy or routed DNS configured.
    pub fn validate(&self) -> Result<(), RouteConfigError> {
        if self.mode != RouteMode::Direct
            && self
                .policy
                .rules
                .iter()
                .any(|rule| rule.action == SiteRouteAction::Direct)
        {
            return Err(RouteConfigError::DirectBypassNotAllowed(self.mode));
        }
        match self.mode {
            RouteMode::Direct => {
                if self.proxy.is_some() {
                    return Err(RouteConfigError::ProxyNotAllowed);
                }
                if self.dns_route != DnsRoute::System {
                    return Err(RouteConfigError::MissingProxyEndpoint(RouteMode::Direct));
                }
            }
            RouteMode::Umc | RouteMode::Xray => {
                if self.proxy.is_none() {
                    return Err(RouteConfigError::MissingProxyEndpoint(self.mode));
                }
                if self.dns_route != DnsRoute::ViaProxy {
                    return Err(RouteConfigError::DnsLeak(self.mode));
                }
            }
        }
        Ok(())
    }
}

/// A named, validated route configuration loaded from a local profile file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkProfile {
    name: String,
    route: NetworkRoute,
}

impl NetworkProfile {
    /// Loads one named network profile from JSON.
    ///
    /// The accepted shape is:
    ///
    /// ```json
    /// {
    ///   "name": "work",
    ///   "mode": "xray",
    ///   "proxy": "socks5h://127.0.0.1:1080",
    ///   "dns": "proxy",
    ///   "sites": [{"site": "example.com", "action": "block"}]
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is malformed, a proxy or site rule is
    /// invalid, or the resulting route would violate the fail-closed route
    /// contract.
    pub fn from_json(raw: &str) -> Result<Self, NetworkProfileError> {
        let input: ProfileInput = serde_json::from_str(raw)
            .map_err(|error| NetworkProfileError::InvalidJson(error.to_string()))?;
        Self::from_input(input)
    }

    /// Loads one named network profile from a local JSON file.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkProfileError::Io`] when the file cannot be read or
    /// [`NetworkProfileError::InvalidJson`] when it is not valid profile JSON.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, NetworkProfileError> {
        let raw =
            fs::read_to_string(path).map_err(|error| NetworkProfileError::Io(error.to_string()))?;
        Self::from_json(&raw)
    }

    fn from_input(input: ProfileInput) -> Result<Self, NetworkProfileError> {
        let name = normalize_profile_name(&input.name)?;
        let mode = parse_profile_mode(&input.mode)?;
        let proxy = input
            .proxy
            .as_deref()
            .map(parse_proxy_endpoint)
            .transpose()
            .map_err(NetworkProfileError::InvalidProxy)?;
        let dns_route = parse_dns_route(input.dns.as_deref().unwrap_or("system"))?;
        let mut policy = SiteRoutePolicy::default();
        for site in input.sites {
            let action = parse_site_route_action(&site.action)?;
            policy.add_rule(&site.site, action).map_err(|source| {
                NetworkProfileError::InvalidSiteRule {
                    site: site.site,
                    source,
                }
            })?;
        }
        let route = NetworkRoute::new(mode, proxy, dns_route).with_policy(policy);
        route
            .validate()
            .map_err(NetworkProfileError::InvalidRoute)?;
        Ok(Self { name, route })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn route(&self) -> &NetworkRoute {
        &self.route
    }

    #[must_use]
    pub fn into_route(self) -> NetworkRoute {
        self.route
    }
}

/// A named collection of local network profiles with one validated default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkProfileStore {
    profiles: Vec<NetworkProfile>,
    default_index: usize,
}

impl NetworkProfileStore {
    /// Loads a profile collection from JSON.
    ///
    /// The accepted shape is:
    ///
    /// ```json
    /// {
    ///   "default": "direct",
    ///   "profiles": [{"name": "direct", "mode": "direct"}]
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when a profile is malformed, duplicated, or the
    /// configured default does not exist.
    pub fn from_json(raw: &str) -> Result<Self, NetworkProfileError> {
        let document: ProfileDocument = serde_json::from_str(raw)
            .map_err(|error| NetworkProfileError::InvalidJson(error.to_string()))?;
        if document.profiles.is_empty() {
            return Err(NetworkProfileError::EmptyProfiles);
        }
        let mut profiles = Vec::with_capacity(document.profiles.len());
        for input in document.profiles {
            let profile = NetworkProfile::from_input(input)?;
            if profiles
                .iter()
                .any(|existing: &NetworkProfile| existing.name() == profile.name())
            {
                return Err(NetworkProfileError::DuplicateProfile(
                    profile.name().to_owned(),
                ));
            }
            profiles.push(profile);
        }
        let default_name = document
            .default
            .as_deref()
            .unwrap_or_else(|| profiles[0].name());
        let default_index = profiles
            .iter()
            .position(|profile| profile.name() == default_name)
            .ok_or_else(|| NetworkProfileError::UnknownDefault(default_name.to_owned()))?;
        Ok(Self {
            profiles,
            default_index,
        })
    }

    /// Loads a profile collection from a local JSON file.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkProfileError::Io`] when the file cannot be read or a
    /// profile parsing error when its contents are invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, NetworkProfileError> {
        let raw =
            fs::read_to_string(path).map_err(|error| NetworkProfileError::Io(error.to_string()))?;
        Self::from_json(&raw)
    }

    #[must_use]
    pub fn profiles(&self) -> &[NetworkProfile] {
        &self.profiles
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&NetworkProfile> {
        self.profiles.iter().find(|profile| profile.name() == name)
    }

    #[must_use]
    pub fn default_profile(&self) -> &NetworkProfile {
        &self.profiles[self.default_index]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileInput {
    name: String,
    mode: String,
    #[serde(default)]
    proxy: Option<String>,
    #[serde(default)]
    dns: Option<String>,
    #[serde(default)]
    sites: Vec<SiteRuleInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteRuleInput {
    site: String,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    #[serde(default)]
    default: Option<String>,
    profiles: Vec<ProfileInput>,
}

fn normalize_profile_name(raw: &str) -> Result<String, NetworkProfileError> {
    let name = raw.trim();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(NetworkProfileError::InvalidName);
    }
    Ok(name.to_owned())
}

fn parse_profile_mode(raw: &str) -> Result<RouteMode, NetworkProfileError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(RouteMode::Direct),
        "umc" => Ok(RouteMode::Umc),
        "xray" => Ok(RouteMode::Xray),
        _ => Err(NetworkProfileError::UnknownMode(raw.to_owned())),
    }
}

fn parse_dns_route(raw: &str) -> Result<DnsRoute, NetworkProfileError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "system" => Ok(DnsRoute::System),
        "proxy" | "via_proxy" | "via-proxy" => Ok(DnsRoute::ViaProxy),
        _ => Err(NetworkProfileError::UnknownDnsRoute(raw.to_owned())),
    }
}

fn parse_site_route_action(raw: &str) -> Result<SiteRouteAction, NetworkProfileError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "selected" => Ok(SiteRouteAction::Selected),
        "direct" => Ok(SiteRouteAction::Direct),
        "block" | "blocked" => Ok(SiteRouteAction::Block),
        _ => Err(NetworkProfileError::UnknownSiteAction(raw.to_owned())),
    }
}

#[derive(Debug)]
pub enum NetworkProfileError {
    InvalidJson(String),
    Io(String),
    InvalidName,
    UnknownMode(String),
    UnknownDnsRoute(String),
    UnknownSiteAction(String),
    InvalidProxy(ProxyEndpointError),
    InvalidSiteRule {
        site: String,
        source: SiteRoutePolicyError,
    },
    InvalidRoute(RouteConfigError),
    EmptyProfiles,
    DuplicateProfile(String),
    UnknownDefault(String),
}

impl Display for NetworkProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(error) => write!(formatter, "invalid network profile JSON: {error}"),
            Self::Io(error) => write!(formatter, "cannot read network profile: {error}"),
            Self::InvalidName => {
                formatter.write_str("network profile name is empty or contains control characters")
            }
            Self::UnknownMode(mode) => write!(formatter, "unknown network profile mode: {mode}"),
            Self::UnknownDnsRoute(route) => {
                write!(formatter, "unknown network profile DNS route: {route}")
            }
            Self::UnknownSiteAction(action) => {
                write!(formatter, "unknown network profile site action: {action}")
            }
            Self::InvalidProxy(error) => {
                write!(formatter, "invalid network profile proxy: {error:?}")
            }
            Self::InvalidSiteRule { site, source } => {
                write!(
                    formatter,
                    "invalid network profile site rule {site:?}: {source:?}"
                )
            }
            Self::InvalidRoute(error) => {
                write!(formatter, "invalid network profile route: {error:?}")
            }
            Self::EmptyProfiles => formatter.write_str("network profile collection is empty"),
            Self::DuplicateProfile(name) => write!(formatter, "duplicate network profile: {name}"),
            Self::UnknownDefault(name) => {
                write!(formatter, "network profile default does not exist: {name}")
            }
        }
    }
}

impl std::error::Error for NetworkProfileError {}

fn normalize_site_pattern(raw: &str) -> Result<String, SiteRoutePolicyError> {
    let site = raw.trim().trim_start_matches("*.").trim_start_matches('.');
    if site.is_empty()
        || site.chars().any(char::is_whitespace)
        || (site.parse::<IpAddr>().is_err()
            && site
                .chars()
                .any(|character| matches!(character, '/' | ':' | '@')))
    {
        return Err(SiteRoutePolicyError::InvalidSitePattern);
    }
    Ok(site.to_ascii_lowercase())
}

fn host_matches_site(host: &str, site: &str) -> bool {
    host == site
        || host
            .strip_suffix(site)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteConfigError {
    MissingProxyEndpoint(RouteMode),
    DnsLeak(RouteMode),
    ProxyNotAllowed,
    DirectBypassNotAllowed(RouteMode),
}

#[cfg(test)]
mod tests {
    use nomad_core::RouteMode;

    use super::{
        parse_proxy_endpoint, ConnectionState, DnsRoute, NetworkDiagnostics, NetworkProfile,
        NetworkProfileError, NetworkProfileStore, NetworkRoute, NetworkTelemetryEvent,
        ProxyEndpoint, ProxyEndpointError, ProxyScheme, RouteConfigError, SiteRouteAction,
        SiteRoutePolicy, SiteRoutePolicyError,
    };

    #[test]
    fn test_network_profile_loads_route_and_site_rules() {
        let profile = NetworkProfile::from_json(
            r#"{
                "name": "work",
                "mode": "xray",
                "proxy": "socks5h://127.0.0.1:1080",
                "dns": "proxy",
                "sites": [
                    {"site": "internal.example", "action": "block"}
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(profile.name(), "work");
        assert_eq!(profile.route().mode(), RouteMode::Xray);
        assert_eq!(profile.route().dns_route(), DnsRoute::ViaProxy);
        let decision = profile
            .route()
            .decision_for(&url::Url::parse("https://internal.example/app").unwrap());
        assert_eq!(decision.action(), SiteRouteAction::Block);
        assert_eq!(decision.matched_site(), Some("internal.example"));
    }

    #[test]
    fn test_network_profile_rejects_direct_bypass_in_privacy_mode() {
        let error = NetworkProfile::from_json(
            r#"{
                "name": "private",
                "mode": "xray",
                "proxy": "socks5h://127.0.0.1:1080",
                "dns": "proxy",
                "sites": [
                    {"site": "bank.example", "action": "direct"}
                ]
            }"#,
        )
        .unwrap_err();

        assert!(matches!(error, NetworkProfileError::InvalidRoute(_)));
    }

    #[test]
    fn test_network_profile_store_selects_named_default_profile() {
        let store = NetworkProfileStore::from_json(
            r#"{
                "default": "direct",
                "profiles": [
                    {"name": "direct", "mode": "direct", "dns": "system"},
                    {
                        "name": "work",
                        "mode": "xray",
                        "proxy": "http://127.0.0.1:8080",
                        "dns": "proxy"
                    }
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(store.default_profile().name(), "direct");
        assert_eq!(store.get("work").unwrap().route().mode(), RouteMode::Xray);
    }

    #[test]
    fn test_network_diagnostics_tracks_live_connection_events() {
        let mut diagnostics = NetworkDiagnostics::new(DnsRoute::ViaProxy);
        diagnostics.observe(NetworkTelemetryEvent::Connecting {
            destination: "https://example.com:443".into(),
            proxy: Some("socks5h://127.0.0.1:1080".into()),
            dns_route: DnsRoute::ViaProxy,
        });
        assert_eq!(diagnostics.state(), ConnectionState::Connecting);
        assert_eq!(diagnostics.destination(), Some("https://example.com:443"));
        assert_eq!(diagnostics.dns_route(), DnsRoute::ViaProxy);

        diagnostics.observe(NetworkTelemetryEvent::Connected {
            destination: "https://example.com:443".into(),
            proxy: Some("socks5h://127.0.0.1:1080".into()),
            dns_route: DnsRoute::ViaProxy,
            tls_protocol: Some("TLS 1.3".into()),
            tls_cipher_suite: Some("TLS13_AES_128_GCM_SHA256".into()),
            alpn_protocol: Some("h2".into()),
            used_ech: true,
        });
        assert_eq!(diagnostics.state(), ConnectionState::Connected);
        assert_eq!(diagnostics.successful_connections(), 1);
        assert_eq!(diagnostics.tls_protocol(), Some("TLS 1.3"));
        assert!(diagnostics.used_ech());

        diagnostics.observe(NetworkTelemetryEvent::Failed {
            destination: "https://example.com:443".into(),
            proxy: Some("socks5h://127.0.0.1:1080".into()),
            dns_route: DnsRoute::ViaProxy,
            error: "connection refused".into(),
        });
        assert_eq!(diagnostics.state(), ConnectionState::Failed);
        assert_eq!(diagnostics.failed_connections(), 1);
        assert_eq!(diagnostics.last_error(), Some("connection refused"));
    }

    #[test]
    fn test_direct_route_uses_system_dns_without_proxy() {
        let route = NetworkRoute::direct();

        assert_eq!(route.mode(), RouteMode::Direct);
        assert_eq!(route.dns_route(), DnsRoute::System);
        assert!(route.proxy().is_none());
        assert_eq!(route.validate(), Ok(()));
    }

    #[test]
    fn test_privacy_route_requires_proxy_endpoint() {
        let route = NetworkRoute::new(RouteMode::Xray, None, DnsRoute::ViaProxy);

        assert_eq!(
            route.validate(),
            Err(RouteConfigError::MissingProxyEndpoint(RouteMode::Xray))
        );
    }

    #[test]
    fn test_privacy_route_rejects_system_dns() {
        let proxy = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", 1080);
        let route = NetworkRoute::new(RouteMode::Umc, Some(proxy), DnsRoute::System);

        assert_eq!(
            route.validate(),
            Err(RouteConfigError::DnsLeak(RouteMode::Umc))
        );
    }

    #[test]
    fn test_proxy_uri_preserves_scheme_host_and_port() {
        let proxy = ProxyEndpoint::new(ProxyScheme::HttpConnect, "127.0.0.1", 8080);

        assert_eq!(proxy.uri(), "http://127.0.0.1:8080");
    }

    #[test]
    fn test_parse_proxy_endpoint_supports_http_connect_and_socks5() {
        let http = parse_proxy_endpoint("http://127.0.0.1:8080").unwrap();
        let socks = parse_proxy_endpoint("socks5h://127.0.0.1:1080").unwrap();

        assert_eq!(http.scheme(), ProxyScheme::HttpConnect);
        assert_eq!(socks.scheme(), ProxyScheme::Socks5);
        assert_eq!(socks.uri(), "socks5h://127.0.0.1:1080");
    }

    #[test]
    fn test_parse_proxy_endpoint_rejects_credentials_and_unknown_schemes() {
        assert_eq!(
            parse_proxy_endpoint("http://user:password@127.0.0.1:8080"),
            Err(ProxyEndpointError::CredentialsNotAllowed)
        );
        assert_eq!(
            parse_proxy_endpoint("ftp://127.0.0.1:21"),
            Err(ProxyEndpointError::UnsupportedScheme)
        );
    }

    #[test]
    fn test_site_route_policy_uses_the_longest_matching_suffix() {
        let mut policy = SiteRoutePolicy::default();
        policy
            .add_rule("example.com", SiteRouteAction::Block)
            .unwrap();
        policy
            .add_rule("private.example.com", SiteRouteAction::Selected)
            .unwrap();
        let route = NetworkRoute::direct().with_policy(policy);

        let private =
            route.decision_for(&url::Url::parse("https://private.example.com/account").unwrap());
        let public = route.decision_for(&url::Url::parse("https://www.example.com").unwrap());
        let unrelated = route.decision_for(&url::Url::parse("https://example.net").unwrap());

        assert_eq!(private.action(), SiteRouteAction::Selected);
        assert_eq!(private.matched_site(), Some("private.example.com"));
        assert_eq!(public.action(), SiteRouteAction::Block);
        assert_eq!(public.matched_site(), Some("example.com"));
        assert_eq!(unrelated.action(), SiteRouteAction::Selected);
        assert_eq!(unrelated.matched_site(), None);
    }

    #[test]
    fn test_privacy_route_rejects_direct_site_bypass_rules() {
        let mut policy = SiteRoutePolicy::default();
        policy
            .add_rule("example.com", SiteRouteAction::Direct)
            .unwrap();
        let route = NetworkRoute::new(
            RouteMode::Xray,
            Some(ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", 1080)),
            DnsRoute::ViaProxy,
        )
        .with_policy(policy);

        assert_eq!(
            route.validate(),
            Err(RouteConfigError::DirectBypassNotAllowed(RouteMode::Xray))
        );
    }

    #[test]
    fn test_site_route_policy_rejects_url_like_patterns() {
        let mut policy = SiteRoutePolicy::default();

        assert_eq!(
            policy.add_rule("https://example.com", SiteRouteAction::Block),
            Err(SiteRoutePolicyError::InvalidSitePattern)
        );
    }
}
