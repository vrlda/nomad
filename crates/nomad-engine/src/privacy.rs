use std::net::IpAddr;

use crate::permissions::PermissionKind;
use serde::{Deserialize, Serialize};
use url::Url;

/// Browser-wide privacy posture.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum PrivacyMode {
    #[default]
    Standard,
    Hardened,
    Private,
}

impl PrivacyMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Hardened => "Hardened",
            Self::Private => "Private",
        }
    }
}

/// Runtime policy consumed by the browser shell and the embedded Servo fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PrivacyPolicy {
    mode: PrivacyMode,
    tracking_protection: bool,
    storage_partitioning: bool,
    anti_fingerprinting: bool,
    advanced_fingerprinting: bool,
    block_webrtc: bool,
    dns_leak_protection: bool,
    third_party_cookie_blocking: bool,
    reduced_cross_site_referrers: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PrivacyDiagnostics {
    pub mode: PrivacyMode,
    pub blocked_resources: u64,
    pub blocked_ads: u64,
    pub blocked_trackers: u64,
    pub tracking_protection: bool,
    pub storage_partitioning: bool,
    pub anti_fingerprinting: bool,
    pub advanced_fingerprinting: bool,
    pub block_webrtc: bool,
    pub dns_leak_protection: bool,
    pub third_party_cookie_blocking: bool,
    pub reduced_cross_site_referrers: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceBlockReason {
    Ad,
    Tracker,
}

impl PrivacyPolicy {
    #[must_use]
    pub const fn for_mode(mode: PrivacyMode) -> Self {
        Self {
            mode,
            tracking_protection: true,
            storage_partitioning: true,
            anti_fingerprinting: true,
            advanced_fingerprinting: matches!(mode, PrivacyMode::Hardened | PrivacyMode::Private),
            block_webrtc: matches!(mode, PrivacyMode::Hardened | PrivacyMode::Private),
            dns_leak_protection: true,
            third_party_cookie_blocking: true,
            reduced_cross_site_referrers: true,
        }
    }

    #[must_use]
    pub const fn mode(self) -> PrivacyMode {
        self.mode
    }

    #[must_use]
    pub const fn tracking_protection(self) -> bool {
        self.tracking_protection
    }

    #[must_use]
    pub const fn storage_partitioning(self) -> bool {
        self.storage_partitioning
    }

    #[must_use]
    pub const fn anti_fingerprinting(self) -> bool {
        self.anti_fingerprinting
    }

    #[must_use]
    pub const fn advanced_fingerprinting(self) -> bool {
        self.advanced_fingerprinting
    }

    #[must_use]
    pub const fn block_webrtc(self) -> bool {
        self.block_webrtc
    }

    #[must_use]
    pub const fn dns_leak_protection(self) -> bool {
        self.dns_leak_protection
    }

    #[must_use]
    pub const fn third_party_cookie_blocking(self) -> bool {
        self.third_party_cookie_blocking
    }

    #[must_use]
    pub const fn reduced_cross_site_referrers(self) -> bool {
        self.reduced_cross_site_referrers
    }

    /// Returns whether cookies may accompany a network request.
    #[must_use]
    pub fn should_send_cookies(
        self,
        top_level_url: &Url,
        request_url: &Url,
        is_main_frame: bool,
    ) -> bool {
        !self.third_party_cookie_blocking
            || is_main_frame
            || !is_third_party(top_level_url, request_url)
    }

    /// Reduces a cross-site referrer to an origin and drops HTTPS-to-HTTP referrers.
    #[must_use]
    pub fn sanitize_referrer(self, referrer_url: &Url, request_url: &Url) -> Option<Url> {
        if !self.reduced_cross_site_referrers || site_key(referrer_url) == site_key(request_url) {
            return Some(referrer_url.clone());
        }
        if referrer_url.scheme() == "https" && request_url.scheme() == "http" {
            return None;
        }
        let mut origin = referrer_url.clone();
        origin.set_path("/");
        origin.set_query(None);
        origin.set_fragment(None);
        origin.set_username("").ok();
        origin.set_password(None).ok();
        Some(origin)
    }

    /// Returns whether a resource should be blocked before network I/O.
    #[must_use]
    pub fn should_block_resource(
        self,
        top_level_url: &Url,
        resource_url: &Url,
        is_main_frame: bool,
    ) -> bool {
        self.block_reason(top_level_url, resource_url, is_main_frame)
            .is_some()
    }

    /// Classifies a resource that the privacy policy will block.
    #[must_use]
    pub fn block_reason(
        self,
        top_level_url: &Url,
        resource_url: &Url,
        is_main_frame: bool,
    ) -> Option<ResourceBlockReason> {
        if !self.tracking_protection
            || is_main_frame
            || !matches!(resource_url.scheme(), "http" | "https")
            || !is_third_party(top_level_url, resource_url)
        {
            return None;
        }

        if is_known_ad(resource_url) {
            Some(ResourceBlockReason::Ad)
        } else if is_known_tracker(resource_url) {
            Some(ResourceBlockReason::Tracker)
        } else {
            None
        }
    }

    /// Returns the storage partition key for a top-level site.
    #[must_use]
    pub fn storage_partition_key(self, top_level_url: &Url) -> Option<String> {
        self.storage_partitioning
            .then(|| site_key(top_level_url))
            .flatten()
    }

    /// Private mode denies sensitive capability requests without a persisted grant.
    #[must_use]
    pub const fn deny_sensitive_permissions(self) -> bool {
        matches!(self.mode, PrivacyMode::Private)
    }

    /// Returns whether a page may request a browser capability.
    ///
    /// Servo performs the web-platform permission checks that are specific to
    /// a feature. Nomad adds the browser-level gate here so every embedder
    /// path applies the same rule: sensitive capabilities require a secure
    /// context, and Private mode denies them regardless of stored decisions.
    #[must_use]
    pub fn allows_permission_request(self, url: &Url, _kind: PermissionKind) -> bool {
        !self.deny_sensitive_permissions() && is_secure_permission_origin(url)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityLevel {
    Secure,
    Insecure,
    Local,
    Internal,
    Unknown,
}

impl SecurityLevel {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Local => "Local/private",
            Self::Internal => "Internal",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityInfo {
    pub level: SecurityLevel,
    pub origin: String,
    pub explanation: &'static str,
}

#[must_use]
pub fn security_info(url: Option<&Url>) -> SecurityInfo {
    let Some(url) = url else {
        return SecurityInfo {
            level: SecurityLevel::Unknown,
            origin: "No page".to_owned(),
            explanation: "No page is loaded",
        };
    };

    let origin = url.origin().ascii_serialization();
    let local_host = is_local_host(url);
    let (level, explanation) = match (url.scheme(), local_host) {
        ("https", true) => (
            SecurityLevel::Local,
            "Local/private-network service over encrypted HTTPS",
        ),
        ("http", true) => (
            SecurityLevel::Local,
            "Local/private-network service over unencrypted HTTP",
        ),
        ("https", false) => (SecurityLevel::Secure, "Encrypted HTTPS connection"),
        ("http", false) => (SecurityLevel::Insecure, "Unencrypted HTTP connection"),
        ("file", _) => (SecurityLevel::Local, "Local resource"),
        ("about" | "data" | "blob", _) => (SecurityLevel::Internal, "Browser-managed resource"),
        ("umc", _) => (
            SecurityLevel::Secure,
            "UMC resource; inspect its route and identity",
        ),
        _ => (SecurityLevel::Unknown, "Security state is not established"),
    };

    SecurityInfo {
        level,
        origin,
        explanation,
    }
}

fn is_local_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        Ok(IpAddr::V6(address)) => {
            address.is_loopback() || address.segments()[0] & 0xfe00 == 0xfc00
        }
        Err(_) => false,
    }
}

fn is_secure_permission_origin(url: &Url) -> bool {
    if matches!(url.scheme(), "https" | "umc" | "file") {
        return true;
    }
    if url.scheme() != "http" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn is_third_party(top_level_url: &Url, resource_url: &Url) -> bool {
    site_key(top_level_url) != site_key(resource_url)
}

fn is_known_tracker(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    [
        "doubleclick.net",
        "googlesyndication.com",
        "google-analytics.com",
        "googletagmanager.com",
        "facebook.net",
        "connect.facebook.net",
        "analytics.twitter.com",
        "adsrvr.org",
        "adnxs.com",
        "scorecardresearch.com",
        "quantserve.com",
        "hotjar.com",
        "mixpanel.com",
        "segment.io",
        "clarity.ms",
        "fullstory.com",
    ]
    .iter()
    .any(|suffix| host_matches_suffix(&host, suffix))
}

fn is_known_ad(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    [
        "adform.net",
        "adsrvr.org",
        "amazon-adsystem.com",
        "criteo.com",
        "googlesyndication.com",
        "openx.net",
        "pagead2.googlesyndication.com",
        "pubmatic.com",
        "rubiconproject.com",
        "taboola.com",
        "outbrain.com",
        "yieldmo.com",
    ]
    .iter()
    .any(|suffix| host_matches_suffix(&host, suffix))
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn site_key(url: &Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return Some(host);
    }
    let labels: Vec<_> = host.split('.').filter(|label| !label.is_empty()).collect();
    match labels.as_slice() {
        [] => None,
        [single] => Some((*single).to_owned()),
        [.., parent, child] => Some(format!("{parent}.{child}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{security_info, PrivacyMode, PrivacyPolicy, SecurityLevel};
    use crate::PermissionKind;

    fn url(raw: &str) -> url::Url {
        url::Url::parse(raw).unwrap()
    }

    #[test]
    fn test_known_third_party_tracker_is_blocked() {
        let policy = PrivacyPolicy::for_mode(PrivacyMode::Standard);

        assert!(policy.should_block_resource(
            &url("https://news.example/article"),
            &url("https://www.google-analytics.com/collect"),
            false,
        ));
    }

    #[test]
    fn test_webrtc_is_blocked_in_hardened_and_private_modes_only() {
        assert!(!PrivacyPolicy::for_mode(PrivacyMode::Standard).block_webrtc());
        assert!(PrivacyPolicy::for_mode(PrivacyMode::Hardened).block_webrtc());
        assert!(PrivacyPolicy::for_mode(PrivacyMode::Private).block_webrtc());
    }

    #[test]
    fn test_webrtc_leak_controls_are_always_on_with_dns_leak_protection() {
        // WebRTC leaks (local IPs, STUN/TURN endpoints) are mitigated by
        // disabling the API entirely in hardened/private modes and by DNS leak
        // protection in every mode.
        for mode in [
            PrivacyMode::Standard,
            PrivacyMode::Hardened,
            PrivacyMode::Private,
        ] {
            let policy = PrivacyPolicy::for_mode(mode);
            assert!(
                policy.dns_leak_protection(),
                "DNS leak protection must be on"
            );
            assert!(policy.block_webrtc() || mode == PrivacyMode::Standard);
        }
    }

    #[test]
    fn test_known_third_party_ad_is_blocked() {
        let policy = PrivacyPolicy::for_mode(PrivacyMode::Standard);

        assert!(policy.should_block_resource(
            &url("https://news.example/article"),
            &url("https://pagead2.googlesyndication.com/impression"),
            false,
        ));
    }

    #[test]
    fn test_block_reason_distinguishes_ads_from_trackers() {
        let policy = PrivacyPolicy::for_mode(PrivacyMode::Standard);

        assert_eq!(
            policy.block_reason(
                &url("https://news.example/article"),
                &url("https://pagead2.googlesyndication.com/impression"),
                false,
            ),
            Some(super::ResourceBlockReason::Ad)
        );
        assert_eq!(
            policy.block_reason(
                &url("https://news.example/article"),
                &url("https://www.google-analytics.com/collect"),
                false,
            ),
            Some(super::ResourceBlockReason::Tracker)
        );
    }

    #[test]
    fn test_first_party_tracker_domain_is_allowed() {
        let policy = PrivacyPolicy::for_mode(PrivacyMode::Standard);

        assert!(!policy.should_block_resource(
            &url("https://analytics.example/article"),
            &url("https://analytics.example/pixel"),
            false,
        ));
    }

    #[test]
    fn test_partition_key_is_site_scoped() {
        let policy = PrivacyPolicy::for_mode(PrivacyMode::Hardened);

        assert_eq!(
            policy.storage_partition_key(&url("https://www.example.com/path")),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn test_private_mode_denies_sensitive_permissions() {
        assert!(PrivacyPolicy::for_mode(PrivacyMode::Private).deny_sensitive_permissions());
        assert!(!PrivacyPolicy::for_mode(PrivacyMode::Standard).deny_sensitive_permissions());
    }

    #[test]
    fn test_sensitive_permissions_require_secure_origins() {
        let standard = PrivacyPolicy::for_mode(PrivacyMode::Standard);
        assert!(standard
            .allows_permission_request(&url("https://example.com"), PermissionKind::Camera,));
        assert!(standard
            .allows_permission_request(&url("http://localhost:3000"), PermissionKind::Microphone,));
        assert!(!standard
            .allows_permission_request(&url("http://example.com"), PermissionKind::Geolocation,));
        assert!(!PrivacyPolicy::for_mode(PrivacyMode::Private)
            .allows_permission_request(&url("https://example.com"), PermissionKind::Camera,));
    }

    #[test]
    fn test_hardened_and_private_modes_enable_advanced_fingerprint_protection() {
        let standard = PrivacyPolicy::for_mode(PrivacyMode::Standard);
        let hardened = PrivacyPolicy::for_mode(PrivacyMode::Hardened);
        let private = PrivacyPolicy::for_mode(PrivacyMode::Private);

        assert!(!standard.advanced_fingerprinting());
        assert!(hardened.advanced_fingerprinting());
        assert!(private.advanced_fingerprinting());
    }

    #[test]
    fn test_third_party_cookies_are_blocked_but_first_party_cookies_are_allowed() {
        let policy = PrivacyPolicy::for_mode(PrivacyMode::Standard);
        assert!(!policy.should_send_cookies(
            &url("https://news.example/article"),
            &url("https://tracker.example/pixel"),
            false,
        ));
        assert!(policy.should_send_cookies(
            &url("https://news.example/article"),
            &url("https://cdn.news.example/script.js"),
            false,
        ));
        assert!(policy.should_send_cookies(
            &url("https://news.example/article"),
            &url("https://tracker.example/"),
            true,
        ));
    }

    #[test]
    fn test_cross_site_referrer_is_reduced_to_origin() {
        let policy = PrivacyPolicy::for_mode(PrivacyMode::Hardened);
        assert_eq!(
            policy
                .sanitize_referrer(
                    &url("https://news.example/path?secret=1"),
                    &url("https://tracker.example/pixel"),
                )
                .unwrap()
                .as_str(),
            "https://news.example/"
        );
        assert!(policy
            .sanitize_referrer(
                &url("https://news.example/path"),
                &url("http://tracker.example/pixel"),
            )
            .is_none());
    }

    #[test]
    fn test_security_info_distinguishes_https_and_http() {
        assert_eq!(
            security_info(Some(&url("https://example.com"))).level,
            SecurityLevel::Secure
        );
        assert_eq!(
            security_info(Some(&url("http://example.com"))).level,
            SecurityLevel::Insecure
        );
    }

    #[test]
    fn test_security_info_marks_loopback_and_private_network_services_local() {
        assert_eq!(
            security_info(Some(&url("http://localhost:3000"))).level,
            SecurityLevel::Local
        );
        assert_eq!(
            security_info(Some(&url("https://192.168.1.20"))).level,
            SecurityLevel::Local
        );
        assert_eq!(SecurityLevel::Local.label(), "Local/private");
    }
}
