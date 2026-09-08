#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PermissionPromptId(u64);

impl PermissionPromptId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PermissionKind {
    Geolocation,
    Notifications,
    Push,
    Midi,
    Camera,
    Microphone,
    Speaker,
    DeviceInfo,
    BackgroundSync,
    Bluetooth,
    PersistentStorage,
    ScreenWakeLock,
    Gamepad,
}

impl PermissionKind {
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Geolocation => "geolocation",
            Self::Notifications => "notifications",
            Self::Push => "push",
            Self::Midi => "midi",
            Self::Camera => "camera",
            Self::Microphone => "microphone",
            Self::Speaker => "speaker",
            Self::DeviceInfo => "device_info",
            Self::BackgroundSync => "background_sync",
            Self::Bluetooth => "bluetooth",
            Self::PersistentStorage => "persistent_storage",
            Self::ScreenWakeLock => "screen_wake_lock",
            Self::Gamepad => "gamepad",
        }
    }

    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Some(match key {
            "geolocation" => Self::Geolocation,
            "notifications" => Self::Notifications,
            "push" => Self::Push,
            "midi" => Self::Midi,
            "camera" => Self::Camera,
            "microphone" => Self::Microphone,
            "speaker" => Self::Speaker,
            "device_info" => Self::DeviceInfo,
            "background_sync" => Self::BackgroundSync,
            "bluetooth" => Self::Bluetooth,
            "persistent_storage" => Self::PersistentStorage,
            "screen_wake_lock" => Self::ScreenWakeLock,
            "gamepad" => Self::Gamepad,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Geolocation => "Location",
            Self::Notifications => "Notifications",
            Self::Push => "Push messaging",
            Self::Midi => "MIDI devices",
            Self::Camera => "Camera",
            Self::Microphone => "Microphone",
            Self::Speaker => "Speaker",
            Self::DeviceInfo => "Device information",
            Self::BackgroundSync => "Background activity",
            Self::Bluetooth => "Bluetooth",
            Self::PersistentStorage => "Persistent storage",
            Self::ScreenWakeLock => "Screen wake lock",
            Self::Gamepad => "Gamepad",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionDecision {
    Ask,
    Allow,
    Block,
    AllowOnce,
}

impl PermissionDecision {
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Allow => "allow",
            Self::Block => "block",
            Self::AllowOnce => "allow_once",
        }
    }

    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Some(match key {
            "ask" => Self::Ask,
            "allow" => Self::Allow,
            "block" => Self::Block,
            "allow_once" => Self::AllowOnce,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRule {
    pub site: String,
    pub kind: PermissionKind,
    pub decision: PermissionDecision,
}

#[derive(Default)]
pub struct PermissionManager {
    rules: Vec<PermissionRule>,
    allow_once: Vec<(String, PermissionKind)>,
}

impl PermissionManager {
    #[must_use]
    pub fn rules(&self) -> &[PermissionRule] {
        &self.rules
    }

    #[must_use]
    pub fn decision(&self, site: &str, kind: PermissionKind) -> PermissionDecision {
        if self
            .allow_once
            .iter()
            .any(|(rule_site, rule_kind)| rule_site == site && *rule_kind == kind)
        {
            return PermissionDecision::AllowOnce;
        }
        self.rules
            .iter()
            .rev()
            .find(|rule| rule.site == site && rule.kind == kind)
            .map_or(PermissionDecision::Ask, |rule| rule.decision)
    }

    pub fn set_decision(
        &mut self,
        site: impl Into<String>,
        kind: PermissionKind,
        decision: PermissionDecision,
    ) {
        let site = site.into();
        self.allow_once
            .retain(|(rule_site, rule_kind)| !(rule_site == &site && *rule_kind == kind));
        if decision == PermissionDecision::AllowOnce {
            self.allow_once.push((site, kind));
            return;
        }
        if let Some(rule) = self
            .rules
            .iter_mut()
            .find(|rule| rule.site == site && rule.kind == kind)
        {
            rule.decision = decision;
        } else {
            self.rules.push(PermissionRule {
                site,
                kind,
                decision,
            });
        }
    }

    pub fn consume_allow_once(&mut self, site: &str, kind: PermissionKind) -> bool {
        let Some(index) = self
            .allow_once
            .iter()
            .position(|(rule_site, rule_kind)| rule_site == site && *rule_kind == kind)
        else {
            return false;
        };
        self.allow_once.remove(index);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{PermissionDecision, PermissionKind, PermissionManager};

    #[test]
    fn test_unknown_site_permission_defaults_to_ask() {
        let manager = PermissionManager::default();

        assert_eq!(
            manager.decision("https://example.com", PermissionKind::Camera),
            PermissionDecision::Ask
        );
    }

    #[test]
    fn test_persistent_decisions_are_site_and_feature_scoped() {
        let mut manager = PermissionManager::default();
        manager.set_decision(
            "https://example.com",
            PermissionKind::Camera,
            PermissionDecision::Block,
        );

        assert_eq!(
            manager.decision("https://example.com", PermissionKind::Camera),
            PermissionDecision::Block
        );
        assert_eq!(
            manager.decision("https://example.com", PermissionKind::Microphone),
            PermissionDecision::Ask
        );
        assert_eq!(
            manager.decision("https://other.example", PermissionKind::Camera),
            PermissionDecision::Ask
        );
    }

    #[test]
    fn test_allow_once_is_consumed_after_one_use() {
        let mut manager = PermissionManager::default();
        manager.set_decision(
            "https://example.com",
            PermissionKind::Geolocation,
            PermissionDecision::AllowOnce,
        );

        assert_eq!(
            manager.decision("https://example.com", PermissionKind::Geolocation),
            PermissionDecision::AllowOnce
        );
        assert!(manager.consume_allow_once("https://example.com", PermissionKind::Geolocation));
        assert_eq!(
            manager.decision("https://example.com", PermissionKind::Geolocation),
            PermissionDecision::Ask
        );
    }
}
