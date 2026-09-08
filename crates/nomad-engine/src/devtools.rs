use std::collections::VecDeque;

const DEVTOOLS_HISTORY_LIMIT: usize = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleLevel {
    Log,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleEntry {
    pub level: ConsoleLevel,
    pub message: String,
    pub source: Option<String>,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevToolsEvaluation {
    pub expression: String,
    pub result: Result<String, String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DevToolsDomNode {
    pub node_type: u16,
    pub node_name: String,
    pub node_value: Option<String>,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Self>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DevToolsStyleSheet {
    pub href: String,
    pub rules: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DevToolsSource {
    pub url: String,
    pub content: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DevToolsDomSnapshot {
    pub root: DevToolsDomNode,
    pub stylesheets: Vec<DevToolsStyleSheet>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkRequestRecord {
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub failed: bool,
    /// Request headers exposed by Servo's network interception boundary.
    pub request_headers: Vec<(String, String)>,
    /// Response headers captured at completion. Values are bounded by the
    /// interception layer and are never logged as raw bodies.
    pub response_headers: Vec<(String, String)>,
    pub request_body_size: Option<usize>,
    pub request_body_unavailable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DevToolsPageSnapshot {
    pub url: String,
    pub title: String,
    pub ready_state: String,
    pub visible_text: String,
    pub metadata: Vec<(String, String)>,
    pub stylesheets: Vec<String>,
    pub local_storage_keys: Vec<String>,
    pub session_storage_keys: Vec<String>,
    pub local_storage: Vec<(String, String)>,
    pub session_storage: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub sources: Vec<DevToolsSource>,
    pub navigation_duration_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DevToolsSnapshot {
    pub console: Vec<ConsoleEntry>,
    pub network: Vec<NetworkRequestRecord>,
    pub dom: Option<DevToolsDomSnapshot>,
    pub page_inspection: Option<DevToolsPageSnapshot>,
}

#[derive(Default)]
pub struct DevToolsStore {
    console: VecDeque<ConsoleEntry>,
    network: VecDeque<NetworkRequestRecord>,
    dom: Option<DevToolsDomSnapshot>,
    page_inspection: Option<DevToolsPageSnapshot>,
}

impl DevToolsStore {
    pub fn record_console(&mut self, entry: ConsoleEntry) {
        push_bounded(&mut self.console, entry);
    }
    pub fn record_network(&mut self, request: NetworkRequestRecord) {
        push_bounded(&mut self.network, request);
    }
    pub fn record_dom(&mut self, dom: DevToolsDomSnapshot) {
        self.dom = Some(dom);
    }
    pub fn record_page_inspection(&mut self, snapshot: DevToolsPageSnapshot) {
        self.page_inspection = Some(snapshot);
    }
    pub fn clear(&mut self) {
        self.console.clear();
        self.network.clear();
        self.dom = None;
        self.page_inspection = None;
    }
    #[must_use]
    pub fn snapshot(&self) -> DevToolsSnapshot {
        DevToolsSnapshot {
            console: self.console.iter().cloned().collect(),
            network: self.network.iter().cloned().collect(),
            dom: self.dom.clone(),
            page_inspection: self.page_inspection.clone(),
        }
    }
}

fn push_bounded<T>(queue: &mut VecDeque<T>, value: T) {
    if queue.len() >= DEVTOOLS_HISTORY_LIMIT {
        queue.pop_front();
    }
    queue.push_back(value);
}

#[must_use]
pub fn filter_console_entries(
    entries: &[ConsoleEntry],
    enabled_levels: &[ConsoleLevel],
) -> Vec<ConsoleEntry> {
    entries
        .iter()
        .filter(|entry| enabled_levels.contains(&entry.level))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ConsoleEntry, ConsoleLevel, DevToolsPageSnapshot, DevToolsSource, DevToolsStore,
        NetworkRequestRecord, DEVTOOLS_HISTORY_LIMIT,
    };

    #[test]
    fn devtools_store_keeps_console_and_network_streams_separate() {
        let mut store = DevToolsStore::default();
        store.record_console(ConsoleEntry {
            level: ConsoleLevel::Error,
            message: "boom".into(),
            source: Some("app.js".into()),
            line: Some(7),
        });
        store.record_network(NetworkRequestRecord {
            method: "GET".into(),
            url: "https://example.com".into(),
            status: Some(200),
            duration_ms: Some(12),
            failed: false,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body_size: None,
            request_body_unavailable: false,
        });
        let snapshot = store.snapshot();
        assert_eq!(snapshot.console.len(), 1);
        assert_eq!(snapshot.network.len(), 1);
    }

    #[test]
    fn devtools_store_keeps_structured_page_inspection() {
        let mut store = DevToolsStore::default();
        store.record_page_inspection(DevToolsPageSnapshot {
            url: "https://example.com".into(),
            title: "Example".into(),
            ready_state: "complete".into(),
            visible_text: "hello".into(),
            metadata: vec![("description".into(), "demo".into())],
            stylesheets: vec!["https://example.com/app.css".into()],
            local_storage_keys: vec!["theme".into()],
            session_storage_keys: vec!["draft".into()],
            local_storage: vec![("theme".into(), "dark".into())],
            session_storage: vec![("draft".into(), "pending".into())],
            cookies: vec![("session".into(), "abc".into())],
            sources: vec![DevToolsSource {
                url: "https://example.com/app.js".into(),
                content: Some("console.log('ready');".into()),
            }],
            navigation_duration_ms: Some(42),
        });
        let snapshot = store.snapshot();
        let page = snapshot.page_inspection.unwrap();
        assert_eq!(page.title, "Example");
        assert_eq!(page.local_storage[0], ("theme".into(), "dark".into()));
        assert_eq!(page.cookies[0], ("session".into(), "abc".into()));
        assert_eq!(page.sources[0].url, "https://example.com/app.js");
    }

    #[test]
    fn devtools_store_keeps_structured_dom_and_stylesheets() {
        let mut store = DevToolsStore::default();
        store.record_dom(super::DevToolsDomSnapshot {
            root: super::DevToolsDomNode {
                node_type: 1,
                node_name: "HTML".into(),
                node_value: None,
                attributes: vec![("lang".into(), "en".into())],
                children: vec![],
            },
            stylesheets: vec![super::DevToolsStyleSheet {
                href: "inline".into(),
                rules: vec!["body { color: red; }".into()],
            }],
        });

        let snapshot = store.snapshot();
        assert_eq!(snapshot.dom.unwrap().stylesheets[0].rules.len(), 1);
    }

    #[test]
    fn devtools_store_applies_bounded_backpressure() {
        let mut store = DevToolsStore::default();
        for index in 0..(DEVTOOLS_HISTORY_LIMIT + 25) {
            store.record_console(ConsoleEntry {
                level: ConsoleLevel::Log,
                message: index.to_string(),
                source: None,
                line: None,
            });
        }

        let snapshot = store.snapshot();
        assert_eq!(snapshot.console.len(), DEVTOOLS_HISTORY_LIMIT);
        assert_eq!(snapshot.console.first().unwrap().message, "25");
        assert_eq!(snapshot.console.last().unwrap().message, "1024");
    }

    #[test]
    fn filter_console_entries_keeps_only_enabled_levels() {
        let entries = vec![
            ConsoleEntry {
                level: ConsoleLevel::Log,
                message: "log".into(),
                source: None,
                line: None,
            },
            ConsoleEntry {
                level: ConsoleLevel::Error,
                message: "error".into(),
                source: None,
                line: None,
            },
        ];

        let filtered = super::filter_console_entries(&entries, &[ConsoleLevel::Error]);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].message, "error");
    }
}
