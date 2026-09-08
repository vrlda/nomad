use std::cmp::Reverse;

use crate::{TabId, TabLifecycle, TabSnapshot};

const BASE_BROWSER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const MEGABYTE: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryMode {
    #[default]
    Automatic,
    LowMemory,
    Balanced,
    MaximumPerformance,
}

impl MemoryMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Automatic => "Automatic",
            Self::LowMemory => "Low memory",
            Self::Balanced => "Balanced",
            Self::MaximumPerformance => "Maximum performance",
        }
    }

    const fn budget_ratio(self) -> (u64, u64) {
        match self {
            Self::Automatic => (2, 5),
            Self::LowMemory => (1, 5),
            Self::Balanced => (1, 3),
            Self::MaximumPerformance => (3, 5),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryPressure {
    #[default]
    Normal,
    Warning,
    Critical,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryObservationSource {
    #[default]
    Estimated,
    Observed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TabMemorySource {
    #[default]
    Estimated,
    Servo,
}

/// Runtime activity that affects whether a tab can safely lose residency.
///
/// This is deliberately kept out of the persisted session format. Activity is
/// reconstructed from the live renderer and browser subsystems after restore.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TabActivity {
    pub playing_audio: bool,
    pub playing_video: bool,
    pub active_webrtc: bool,
    pub active_upload: bool,
    pub active_download: bool,
    pub unsaved_form: bool,
    pub devtools_open: bool,
    pub active_worker: bool,
}

impl TabActivity {
    #[must_use]
    pub fn priority_bonus(self) -> i64 {
        i64::from(self.playing_audio) * 3_000
            + i64::from(self.playing_video) * 3_000
            + i64::from(self.active_webrtc) * 5_000
            + i64::from(self.active_upload) * 6_000
            + i64::from(self.active_download) * 6_000
            + i64::from(self.unsaved_form) * 2_000
            + i64::from(self.devtools_open) * 1_500
            + i64::from(self.active_worker) * 1_500
    }

    #[must_use]
    pub const fn protects_from_suspend(self) -> bool {
        self.active_webrtc || self.active_upload || self.active_download || self.unsaved_form
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TabPriorityScore {
    pub tab_id: TabId,
    pub score: i64,
    pub protected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TabMemoryUsage {
    pub tab_id: TabId,
    pub bytes: u64,
    pub source: TabMemorySource,
    pub lifecycle: TabLifecycle,
    pub priority: TabPriorityScore,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryDiagnostics {
    pub available_bytes: u64,
    pub budget_bytes: u64,
    pub browser_bytes: u64,
    pub pressure: MemoryPressure,
    pub observation_source: MemoryObservationSource,
    pub measured_tabs: usize,
    pub estimated_tabs: usize,
    pub active_tabs: usize,
    pub warm_tabs: usize,
    pub sleeping_tabs: usize,
    pub suspended_tabs: usize,
    pub archived_tabs: usize,
    pub largest_tabs: Vec<TabMemoryUsage>,
}

pub struct MemoryManager {
    mode: MemoryMode,
    available_bytes: u64,
    pressure: MemoryPressure,
    observation_source: MemoryObservationSource,
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new(8 * 1024 * 1024 * 1024)
    }
}

impl MemoryManager {
    #[must_use]
    pub const fn new(available_bytes: u64) -> Self {
        Self {
            mode: MemoryMode::Automatic,
            available_bytes,
            pressure: MemoryPressure::Normal,
            observation_source: MemoryObservationSource::Estimated,
        }
    }

    #[must_use]
    pub const fn mode(&self) -> MemoryMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: MemoryMode) {
        self.mode = mode;
    }

    #[must_use]
    pub const fn available_bytes(&self) -> u64 {
        self.available_bytes
    }

    #[must_use]
    pub const fn budget_bytes(&self) -> u64 {
        let (numerator, denominator) = self.mode.budget_ratio();
        self.available_bytes.saturating_mul(numerator) / denominator
    }

    #[must_use]
    pub const fn pressure(&self) -> MemoryPressure {
        self.pressure
    }

    #[must_use]
    pub const fn observation_source(&self) -> MemoryObservationSource {
        self.observation_source
    }

    /// Observes available memory and current tab residency.
    pub fn observe(&mut self, available_bytes: u64, tabs: &[TabSnapshot]) {
        self.available_bytes = available_bytes;
        self.observation_source = MemoryObservationSource::Observed;
        self.refresh(tabs);
    }

    /// Recomputes pressure from the latest available-memory observation.
    pub fn refresh(&mut self, tabs: &[TabSnapshot]) {
        let browser_bytes = browser_memory_bytes(tabs);
        self.pressure = if browser_bytes > self.budget_bytes()
            || (self.available_bytes > 0 && self.available_bytes < self.budget_bytes() / 2)
        {
            MemoryPressure::Critical
        } else if browser_bytes.saturating_mul(100) > self.budget_bytes().saturating_mul(85)
            || (self.available_bytes > 0 && self.available_bytes < self.budget_bytes())
        {
            MemoryPressure::Warning
        } else {
            MemoryPressure::Normal
        };
    }

    #[must_use]
    pub fn diagnostics(&self, tabs: &[TabSnapshot]) -> MemoryDiagnostics {
        let mut largest_tabs: Vec<_> = tabs
            .iter()
            .map(|tab| TabMemoryUsage {
                tab_id: tab.id,
                bytes: tab.memory_bytes,
                source: tab.memory_source,
                lifecycle: tab.lifecycle,
                priority: priority_score(tab, tabs),
            })
            .collect();
        largest_tabs.sort_by_key(|tab| Reverse(tab.bytes));
        largest_tabs.truncate(8);

        MemoryDiagnostics {
            available_bytes: self.available_bytes,
            budget_bytes: self.budget_bytes(),
            browser_bytes: browser_memory_bytes(tabs),
            pressure: self.pressure,
            observation_source: self.observation_source,
            measured_tabs: tabs
                .iter()
                .filter(|tab| tab.memory_source == TabMemorySource::Servo)
                .count(),
            estimated_tabs: tabs
                .iter()
                .filter(|tab| tab.memory_source == TabMemorySource::Estimated)
                .count(),
            active_tabs: count_lifecycle(tabs, TabLifecycle::Active),
            warm_tabs: count_lifecycle(tabs, TabLifecycle::Warm),
            sleeping_tabs: count_lifecycle(tabs, TabLifecycle::Sleeping),
            suspended_tabs: count_lifecycle(tabs, TabLifecycle::Suspended),
            archived_tabs: count_lifecycle(tabs, TabLifecycle::Archived),
            largest_tabs,
        }
    }

    #[must_use]
    pub fn should_reclaim(&self, tabs: &[TabSnapshot]) -> bool {
        self.pressure != MemoryPressure::Normal || browser_memory_bytes(tabs) > self.budget_bytes()
    }

    #[must_use]
    pub fn suspension_candidates(&self, tabs: &[TabSnapshot]) -> Vec<TabPriorityScore> {
        let mut candidates: Vec<_> = tabs
            .iter()
            .filter(|tab| {
                matches!(tab.lifecycle, TabLifecycle::Warm | TabLifecycle::Sleeping)
                    && !priority_score(tab, tabs).protected
            })
            .map(|tab| priority_score(tab, tabs))
            .collect();
        candidates.sort_by_key(|candidate| candidate.score);
        candidates
    }
}

#[must_use]
pub fn browser_memory_bytes(tabs: &[TabSnapshot]) -> u64 {
    BASE_BROWSER_MEMORY_BYTES.saturating_add(
        tabs.iter()
            .filter(|tab| {
                !matches!(
                    tab.lifecycle,
                    TabLifecycle::Suspended | TabLifecycle::Archived
                )
            })
            .map(|tab| tab.memory_bytes)
            .sum::<u64>(),
    )
}

fn count_lifecycle(tabs: &[TabSnapshot], lifecycle: TabLifecycle) -> usize {
    tabs.iter().filter(|tab| tab.lifecycle == lifecycle).count()
}

fn priority_score(tab: &TabSnapshot, tabs: &[TabSnapshot]) -> TabPriorityScore {
    let max_tick = tabs
        .iter()
        .map(|candidate| candidate.last_used_tick)
        .max()
        .unwrap_or_default();
    let lifecycle_score = match tab.lifecycle {
        TabLifecycle::Active => 10_000,
        TabLifecycle::Warm => 4_000,
        TabLifecycle::Sleeping => 2_000,
        TabLifecycle::Suspended => 0,
        TabLifecycle::Archived => -1_000,
        TabLifecycle::New => 1_000,
    };
    let recency_score =
        i64::try_from(max_tick.saturating_sub(tab.last_used_tick).min(1_000)).unwrap_or(i64::MAX);
    let memory_penalty =
        i64::try_from((tab.memory_bytes / MEGABYTE).min(4_000)).unwrap_or(i64::MAX);
    let score = lifecycle_score
        + i64::from(tab.user_priority) * 100
        + i64::from(tab.pinned) * 8_000
        + i64::from(tab.keep_alive) * 9_000
        + i64::from(tab.restoration_cost) * 10
        + tab.activity.priority_bonus()
        - recency_score
        - memory_penalty;
    TabPriorityScore {
        tab_id: tab.id,
        score,
        protected: tab.pinned || tab.keep_alive || tab.activity.protects_from_suspend(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryManager, MemoryMode, MemoryObservationSource, MemoryPressure, TabMemorySource,
        MEGABYTE,
    };
    use crate::{TabActivity, TabId, TabLifecycle, TabSnapshot};

    fn tab(id: u64, lifecycle: TabLifecycle, bytes: u64) -> TabSnapshot {
        TabSnapshot {
            id: TabId::new(id),
            url: None,
            state: crate::TabState::Active,
            error: None,
            lifecycle,
            pinned: false,
            keep_alive: false,
            user_priority: 0,
            last_used_tick: id,
            memory_bytes: bytes,
            memory_source: TabMemorySource::Estimated,
            restoration_cost: 1,
            activity: TabActivity::default(),
        }
    }

    #[test]
    fn test_budget_modes_scale_available_memory() {
        let mut manager = MemoryManager::new(1_000);

        assert_eq!(manager.budget_bytes(), 400);
        manager.set_mode(MemoryMode::LowMemory);
        assert_eq!(manager.budget_bytes(), 200);
        manager.set_mode(MemoryMode::MaximumPerformance);
        assert_eq!(manager.budget_bytes(), 600);
    }

    #[test]
    fn test_observation_detects_pressure_and_excludes_protected_tabs() {
        let mut manager = MemoryManager::new(1_000);
        let mut protected = tab(1, TabLifecycle::Warm, 500);
        protected.keep_alive = true;
        let tabs = vec![protected, tab(2, TabLifecycle::Sleeping, 500)];

        manager.observe(1_000, &tabs);

        assert_eq!(manager.pressure(), MemoryPressure::Critical);
        assert_eq!(
            manager.observation_source(),
            MemoryObservationSource::Observed
        );
        assert_eq!(
            manager.suspension_candidates(&tabs)[0].tab_id,
            TabId::new(2)
        );
        assert!(manager.suspension_candidates(&tabs)[0].score < 9_000);
    }

    #[test]
    fn test_diagnostics_count_residency_and_sort_largest_tabs() {
        let manager = MemoryManager::new(10_000);
        let tabs = vec![
            tab(1, TabLifecycle::Active, 300),
            tab(2, TabLifecycle::Suspended, 900),
            tab(3, TabLifecycle::Warm, 700),
        ];

        let diagnostics = manager.diagnostics(&tabs);

        assert_eq!(diagnostics.active_tabs, 1);
        assert_eq!(diagnostics.suspended_tabs, 1);
        assert_eq!(diagnostics.warm_tabs, 1);
        assert_eq!(diagnostics.largest_tabs[0].tab_id, TabId::new(2));
    }

    #[test]
    fn test_diagnostics_distinguish_servo_measurements() {
        let manager = MemoryManager::new(4 * 1024 * 1024 * 1024);
        let mut tabs = vec![tab(1, TabLifecycle::Active, 96 * MEGABYTE)];
        tabs[0].memory_source = TabMemorySource::Servo;

        let diagnostics = manager.diagnostics(&tabs);

        assert_eq!(diagnostics.measured_tabs, 1);
        assert_eq!(diagnostics.estimated_tabs, 0);
        assert_eq!(diagnostics.largest_tabs[0].source, TabMemorySource::Servo);
    }

    #[test]
    fn test_live_activity_changes_priority_and_protects_critical_work() {
        let mut streaming = tab(1, TabLifecycle::Warm, 100 * MEGABYTE);
        streaming.activity.playing_video = true;
        let mut downloading = tab(2, TabLifecycle::Warm, 100 * MEGABYTE);
        downloading.activity.active_download = true;
        let ordinary = tab(3, TabLifecycle::Warm, 100 * MEGABYTE);
        let tabs = vec![streaming, downloading, ordinary];

        let candidates = MemoryManager::new(8 * 1024 * MEGABYTE).suspension_candidates(&tabs);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].tab_id, TabId::new(3));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.tab_id != TabId::new(2)));
        assert!(candidates[1].score > candidates[0].score);
    }
}
