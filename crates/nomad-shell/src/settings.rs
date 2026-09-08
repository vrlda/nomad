use std::path::PathBuf;

use nomad_engine::{PrivacyMode, ResolverSettings, SiteRoutePolicy, UpdatePolicy};
use serde::{Deserialize, Serialize};

fn default_search_url() -> String {
    "https://duckduckgo.com/?q={query}".to_owned()
}

fn default_sync_collections() -> Vec<String> {
    vec!["settings".into(), "bookmarks".into(), "history".into()]
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncSettings {
    pub enabled: bool,
    pub provider: String,
    pub endpoint: String,
    #[serde(default = "default_sync_collections")]
    pub collections: Vec<String>,
    pub key_configured: bool,
    pub recovery_configured: bool,
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "file".into(),
            endpoint: String::new(),
            collections: default_sync_collections(),
            key_configured: false,
            recovery_configured: false,
            key_fingerprint: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct BrowserSettings {
    pub privacy_mode: PrivacyMode,
    #[serde(default)]
    pub route_policy: SiteRoutePolicy,
    pub persist_session: bool,
    pub persist_history: bool,
    pub persist_bookmarks: bool,
    pub persist_permissions: bool,
    pub download_directory: PathBuf,
    #[serde(default = "default_search_url")]
    pub search_url: String,
    #[serde(default)]
    pub update_policy: UpdatePolicy,
    #[serde(default)]
    pub sync: SyncSettings,
    #[serde(default)]
    pub resolver: ResolverSettings,
}

impl Default for BrowserSettings {
    fn default() -> Self {
        Self {
            privacy_mode: PrivacyMode::Standard,
            route_policy: SiteRoutePolicy::default(),
            persist_session: true,
            persist_history: true,
            persist_bookmarks: true,
            persist_permissions: true,
            download_directory: PathBuf::from("downloads"),
            search_url: default_search_url(),
            update_policy: UpdatePolicy::default(),
            sync: SyncSettings::default(),
            resolver: ResolverSettings::default(),
        }
    }
}

impl BrowserSettings {
    #[must_use]
    pub const fn session_persistence_enabled(&self) -> bool {
        self.persist_session && !matches!(self.privacy_mode, PrivacyMode::Private)
    }

    #[must_use]
    pub const fn history_enabled(&self) -> bool {
        self.persist_history && !matches!(self.privacy_mode, PrivacyMode::Private)
    }

    #[must_use]
    pub const fn bookmarks_persistence_enabled(&self) -> bool {
        self.persist_bookmarks && !matches!(self.privacy_mode, PrivacyMode::Private)
    }

    #[must_use]
    pub const fn permissions_persistence_enabled(&self) -> bool {
        self.persist_permissions && !matches!(self.privacy_mode, PrivacyMode::Private)
    }
}

#[cfg(test)]
mod tests {
    use nomad_engine::{SiteRouteAction, SiteRoutePolicy, UpdatePolicy};

    use super::{BrowserSettings, PrivacyMode};

    #[test]
    fn test_default_settings_are_persistent_and_standard() {
        let settings = BrowserSettings::default();

        assert_eq!(settings.privacy_mode, PrivacyMode::Standard);
        assert!(settings.persist_session);
        assert!(settings.persist_history);
        assert!(settings.persist_bookmarks);
        assert!(settings.persist_permissions);
        assert_eq!(
            settings.download_directory,
            std::path::Path::new("downloads")
        );
        assert_eq!(settings.search_url, "https://duckduckgo.com/?q={query}");
        assert_eq!(settings.route_policy, SiteRoutePolicy::default());
        assert_eq!(settings.update_policy, UpdatePolicy::default());
        assert_eq!(settings.sync, super::SyncSettings::default());
    }

    #[test]
    fn test_private_mode_disables_persistence_effectively() {
        let settings = BrowserSettings {
            privacy_mode: PrivacyMode::Private,
            ..BrowserSettings::default()
        };

        assert!(!settings.session_persistence_enabled());
        assert!(!settings.history_enabled());
        assert!(!settings.bookmarks_persistence_enabled());
    }

    #[test]
    fn test_route_policy_is_persistable_with_settings() {
        let mut settings = BrowserSettings::default();
        settings
            .route_policy
            .add_rule("example.com", SiteRouteAction::Block)
            .unwrap();
        let json = serde_json::to_string(&settings).unwrap();
        let restored: BrowserSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, settings);
    }

    #[test]
    fn test_resolver_settings_are_backward_compatible_and_persistable() {
        let mut settings = BrowserSettings::default();
        settings.resolver.mode = nomad_engine::ResolverMode::Doh;
        settings.resolver.server_url = "https://dns.example/dns-query".to_owned();

        let json = serde_json::to_string(&settings).unwrap();
        let restored: BrowserSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.resolver, settings.resolver);

        let legacy = r#"{
            "privacy_mode":"Standard",
            "persist_session":true,
            "persist_history":true,
            "persist_bookmarks":true,
            "persist_permissions":true,
            "download_directory":"downloads",
            "search_url":"https://duckduckgo.com/?q={query}"
        }"#;
        let restored: BrowserSettings = serde_json::from_str(legacy).unwrap();
        assert_eq!(restored.resolver, nomad_engine::ResolverSettings::default());
        assert_eq!(restored.resolver.mode, nomad_engine::ResolverMode::System);
    }

    #[test]
    fn test_update_policy_is_backward_compatible_and_persistable() {
        let mut settings = BrowserSettings::default();
        settings.update_policy.channel = nomad_engine::UpdateChannel::Beta;
        settings.update_policy.automatic_checks = false;

        let json = serde_json::to_string(&settings).unwrap();
        let restored: BrowserSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.update_policy, settings.update_policy);

        let legacy = r#"{
            "privacy_mode":"Standard",
            "persist_session":true,
            "persist_history":true,
            "persist_bookmarks":true,
            "persist_permissions":true,
            "download_directory":"downloads",
            "search_url":"https://duckduckgo.com/?q={query}"
        }"#;
        let restored: BrowserSettings = serde_json::from_str(legacy).unwrap();
        assert_eq!(restored.update_policy, UpdatePolicy::default());
        assert_eq!(restored.sync, super::SyncSettings::default());
    }
}
