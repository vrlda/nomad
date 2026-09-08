use nomad_engine::{
    parse_proxy_endpoint, ExtensionManifest, NetworkProfile, PermissionKind, PrivacyMode,
    PrivacyPolicy, ProxyEndpointError, ResourceBlockReason,
};
use url::Url;

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

#[test]
fn privacy_blocklist_does_not_match_deceptive_suffixes() {
    let policy = PrivacyPolicy::for_mode(PrivacyMode::Hardened);
    assert_eq!(
        policy.block_reason(
            &url("https://news.example/article"),
            &url("https://not-google-analytics.com/collect"),
            false,
        ),
        None
    );
    assert_eq!(
        policy.block_reason(
            &url("https://news.example/article"),
            &url("https://cdn.google-analytics.com/collect"),
            false,
        ),
        Some(ResourceBlockReason::Tracker)
    );
}

#[test]
fn privacy_regression_preserves_partition_and_referrer_boundaries() {
    let policy = PrivacyPolicy::for_mode(PrivacyMode::Hardened);
    assert_eq!(
        policy.storage_partition_key(&url("https://a.example.test/page")),
        Some("example.test".to_owned())
    );
    assert_eq!(
        policy
            .sanitize_referrer(
                &url("https://a.example.test/private?token=redacted"),
                &url("https://tracker.test/pixel"),
            )
            .unwrap()
            .as_str(),
        "https://a.example.test/"
    );
}

#[test]
fn sensitive_permissions_fail_closed_on_insecure_origins() {
    let policy = PrivacyPolicy::for_mode(PrivacyMode::Standard);
    assert!(!policy.allows_permission_request(&url("http://example.test"), PermissionKind::Camera,));
    assert!(policy
        .allows_permission_request(&url("http://127.0.0.1:3000"), PermissionKind::Microphone,));
}

#[test]
fn route_inputs_fail_closed_on_credentials_and_direct_privacy_bypass() {
    assert_eq!(
        parse_proxy_endpoint("socks5://user:secret@127.0.0.1:1080"),
        Err(ProxyEndpointError::CredentialsNotAllowed)
    );
    assert!(NetworkProfile::from_json(
        r#"{"name":"private","mode":"xray","proxy":"socks5h://127.0.0.1:1080","dns":"system"}"#
    )
    .is_err());
}

#[test]
fn extension_manifests_reject_missing_identity() {
    assert!(ExtensionManifest::from_json(r#"{"id":"","name":"Wallet","version":"1"}"#).is_err());
}
