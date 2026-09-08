use serde::{Deserialize, Serialize};
use url::Url;

use super::BrowserSettings;
use nomad_engine::{Container, ExtensionRegistrySnapshot, Workspace};

pub const SESSION_VERSION: u8 = 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionTab {
    pub url: Option<String>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub keep_alive: bool,
    #[serde(default)]
    pub user_priority: i8,
    #[serde(default)]
    pub workspace_id: Option<u64>,
    #[serde(default)]
    pub container_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionBookmark {
    pub url: String,
    pub title: String,
    #[serde(default)]
    pub folder: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionHistoryVisit {
    pub tab_index: usize,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionPermissionRule {
    pub site: String,
    pub kind: String,
    pub decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionTabGroup {
    pub title: Option<String>,
    pub color: String,
    pub collapsed: bool,
    /// Member tabs by session tab index; ids are not stable across restore.
    pub tab_indices: Vec<usize>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionSnapshot {
    pub version: u8,
    pub active_tab: usize,
    pub tabs: Vec<SessionTab>,
    pub bookmarks: Vec<SessionBookmark>,
    #[serde(default)]
    pub bookmark_folders: Vec<String>,
    #[serde(default)]
    pub settings: BrowserSettings,
    #[serde(default)]
    pub history: Vec<SessionHistoryVisit>,
    #[serde(default)]
    pub permissions: Vec<SessionPermissionRule>,
    #[serde(default)]
    pub workspaces: Vec<Workspace>,
    #[serde(default)]
    pub containers: Vec<Container>,
    #[serde(default)]
    pub active_workspace: Option<u64>,
    #[serde(default)]
    pub groups: Vec<SessionTabGroup>,
    #[serde(default)]
    pub extensions: ExtensionRegistrySnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidJson(String),
    UnsupportedVersion(u8),
    InvalidUrl(String),
    EmptySession,
    InvalidHistoryTab(usize),
}

impl SessionSnapshot {
    #[must_use]
    pub fn new(active_tab: usize, tabs: Vec<SessionTab>, bookmarks: Vec<SessionBookmark>) -> Self {
        Self {
            version: SESSION_VERSION,
            active_tab,
            tabs,
            bookmarks,
            bookmark_folders: Vec::new(),
            settings: BrowserSettings::default(),
            history: Vec::new(),
            permissions: Vec::new(),
            workspaces: Vec::new(),
            containers: Vec::new(),
            active_workspace: None,
            groups: Vec::new(),
            extensions: ExtensionRegistrySnapshot::default(),
        }
    }

    /// Parses and validates a locally stored session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] when the JSON, version, tab set, or URL data
    /// is invalid.
    pub fn from_json(raw: &str) -> Result<Self, SessionError> {
        let snapshot: Self = serde_json::from_str(raw)
            .map_err(|error| SessionError::InvalidJson(error.to_string()))?;
        if snapshot.version != 1 && snapshot.version != SESSION_VERSION {
            return Err(SessionError::UnsupportedVersion(snapshot.version));
        }
        if snapshot.tabs.is_empty() {
            return Err(SessionError::EmptySession);
        }
        for tab in &snapshot.tabs {
            validate_url(tab.url.as_deref())?;
        }
        for bookmark in &snapshot.bookmarks {
            validate_url(Some(&bookmark.url))?;
        }
        for visit in &snapshot.history {
            if visit.tab_index >= snapshot.tabs.len() {
                return Err(SessionError::InvalidHistoryTab(visit.tab_index));
            }
            validate_url(Some(&visit.url))?;
        }
        Ok(snapshot)
    }

    /// Serializes this session snapshot to local JSON.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidJson`] when serialization fails.
    pub fn to_json(&self) -> Result<String, SessionError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| SessionError::InvalidJson(error.to_string()))
    }
}

fn validate_url(raw_url: Option<&str>) -> Result<(), SessionError> {
    let Some(raw_url) = raw_url else {
        return Ok(());
    };
    let url = Url::parse(raw_url).map_err(|_| SessionError::InvalidUrl(raw_url.to_owned()))?;
    if !matches!(url.scheme(), "about" | "file" | "http" | "https" | "umc")
        || (url.scheme() == "file"
            && url
                .host_str()
                .is_some_and(|host| !host.eq_ignore_ascii_case("localhost")))
    {
        return Err(SessionError::InvalidUrl(raw_url.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SessionBookmark, SessionError, SessionHistoryVisit, SessionSnapshot, SessionTab};

    fn snapshot() -> SessionSnapshot {
        SessionSnapshot::new(
            1,
            vec![
                SessionTab {
                    url: None,
                    pinned: false,
                    keep_alive: false,
                    user_priority: 0,
                    workspace_id: None,
                    container_id: None,
                },
                SessionTab {
                    url: Some("https://example.com/".into()),
                    pinned: false,
                    keep_alive: false,
                    user_priority: 0,
                    workspace_id: None,
                    container_id: None,
                },
            ],
            vec![SessionBookmark {
                url: "https://example.com/".into(),
                title: "Example".into(),
                folder: None,
            }],
        )
    }

    #[test]
    fn test_session_round_trip_json() {
        let restored = SessionSnapshot::from_json(&snapshot().to_json().unwrap()).unwrap();

        assert_eq!(restored, snapshot());
    }

    #[test]
    fn test_session_rejects_unsupported_urls() {
        let mut snapshot = snapshot();
        snapshot.tabs[1].url = Some("javascript:alert(1)".into());

        assert_eq!(
            SessionSnapshot::from_json(&snapshot.to_json().unwrap()),
            Err(SessionError::InvalidUrl("javascript:alert(1)".into()))
        );
    }

    #[test]
    fn test_session_accepts_local_file_tabs() {
        let mut snapshot = snapshot();
        snapshot.tabs[1].url = Some("file:///tmp/nomad.html".into());

        let restored = SessionSnapshot::from_json(&snapshot.to_json().unwrap()).unwrap();

        assert_eq!(
            restored.tabs[1].url.as_deref(),
            Some("file:///tmp/nomad.html")
        );
    }

    #[test]
    fn test_session_rejects_remote_file_authorities() {
        let mut snapshot = snapshot();
        snapshot.tabs[1].url = Some("file://remote-host/share/nomad.html".into());

        assert_eq!(
            SessionSnapshot::from_json(&snapshot.to_json().unwrap()),
            Err(SessionError::InvalidUrl(
                "file://remote-host/share/nomad.html".into()
            ))
        );
    }

    #[test]
    fn test_session_validates_history_tab_indices() {
        let mut snapshot = snapshot();
        snapshot.history = vec![SessionHistoryVisit {
            tab_index: 3,
            url: "https://example.com/".into(),
        }];

        assert_eq!(
            SessionSnapshot::from_json(&snapshot.to_json().unwrap()),
            Err(SessionError::InvalidHistoryTab(3))
        );
    }
}
