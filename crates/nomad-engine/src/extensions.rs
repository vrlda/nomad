#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use base64::Engine;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::oauth::{
    redirect_matches_redirect_uri, unix_now_ms, OAuthProviderConfig, OAuthTokenRecord,
};

const MAX_EXTENSION_VALUE_BYTES: usize = 1024 * 1024;
const MAX_EXTENSION_STORAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_EXTENSION_MESSAGE_COUNT: usize = 4096;
const MAX_EXTENSION_COUNT: usize = 256;
const MAX_EXTENSION_RESOURCE_COUNT: usize = 4096;
/// Bound on the total size of an installed extension's resources. The bound
/// is intentionally finite to prevent unbounded resource exhaustion, but must
/// fit real distribution packages: ``MetaMask``'s release ships roughly 73 MiB of
/// unpacked resources (vendor bundles, WASM, locale data), so the limit is
/// 128 MiB.
const MAX_EXTENSION_RESOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_DECLARATIVE_RULE_COUNT: usize = 5000;
const MAX_CONTEXT_MENU_ITEMS: usize = 1024;
const EXTENSION_STATE_VERSION: u8 = 1;
/// Upper bound on stored provider token grants across all extensions.
pub const MAX_OAUTH_TOKEN_RECORDS: usize = 64;
/// Upper bound on concurrently pending authorization flows.
pub const MAX_PENDING_AUTH_FLOWS: usize = 8;
/// Pending flows older than this are dropped on the next redirect probe.
pub const PENDING_AUTH_FLOW_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ExtensionPermission {
    ReadPage,
    ModifyPage,
    Scripting,
    ActiveTab,
    Storage,
    Clipboard,
    Downloads,
    Tabs,
    History,
    Bookmarks,
    Network,
    WebRequest,
    WebRequestBlocking,
    Cookies,
    Alarms,
    Notifications,
    NativeMessaging,
    WebNavigation,
    ContextMenus,
    Offscreen,
    Management,
    Identity,
    Windows,
    TabGroups,
    Sessions,
    Permissions,
    Proxy,
    Privacy,
    Idle,
    DeclarativeNetRequest,
    UserScripts,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionManifest {
    #[serde(default = "default_manifest_version")]
    pub manifest_version: u8,
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub permissions: Vec<ExtensionPermission>,
    #[serde(default)]
    pub host_permissions: Vec<String>,
    #[serde(default)]
    pub optional_permissions: Vec<ExtensionPermission>,
    #[serde(default)]
    pub optional_host_permissions: Vec<String>,
    #[serde(default)]
    pub unsupported_permissions: Vec<String>,
    #[serde(default)]
    pub unsupported_optional_permissions: Vec<String>,
    #[serde(default)]
    pub content_scripts: Vec<ExtensionContentScript>,
    #[serde(default)]
    pub background: Option<ExtensionBackground>,
    #[serde(default)]
    pub action: Option<ExtensionAction>,
    #[serde(default)]
    pub web_accessible_resources: Vec<ExtensionWebAccessibleResource>,
    #[serde(default)]
    pub externally_connectable_ids: Vec<String>,
    /// Nomad's declarative blocking surface. Request cancellation must be
    /// decided before Servo's network thread proceeds, so it is kept separate
    /// from callback-based `webRequest` events.
    #[serde(default)]
    pub blocked_host_patterns: Vec<String>,
    /// MV3 static Declarative Net Request rulesets declared by the package.
    #[serde(default)]
    pub declarative_net_request: Vec<ExtensionRuleset>,
    #[serde(default)]
    pub commands: HashMap<String, ExtensionCommandSettings>,
    /// Options page surface declared by the package.
    #[serde(default)]
    pub options_ui: Option<ExtensionOptionsUi>,
    /// Chromium-standard `oauth2` provider configuration backing `identity`.
    #[serde(default)]
    pub oauth2: Option<OAuthProviderConfig>,
    /// MV2 options page location.
    #[serde(default)]
    pub options_page: Option<String>,
    #[serde(skip)]
    content_scripts_require_explicit_page_permissions: bool,
}

/// A manifest-declared static Declarative Net Request ruleset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionRuleset {
    pub id: String,
    pub path: String,
    #[serde(default = "default_ruleset_enabled")]
    pub enabled: bool,
}

/// `options_ui` declaration from the manifest.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionOptionsUi {
    pub page: String,
    #[serde(default)]
    pub open_in_tab: bool,
}

/// Settings for one manifest-declared keyboard command.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionCommandSettings {
    #[serde(default)]
    pub description: String,
    /// `suggested_key` accepts either a bare string or Chromium's
    /// `{"default": ..., "mac": ..., ...}` object shape.
    #[serde(default)]
    pub suggested_key: Value,
}

impl ExtensionCommandSettings {
    /// Resolve the suggested key for the current platform with a `default`
    /// fallback, matching Chromium's command shortcut resolution.
    fn resolved_suggested_key(&self) -> String {
        let platform = match std::env::consts::OS {
            "macos" => "mac",
            "windows" => "windows",
            "linux" => "linux",
            other => other,
        };
        self.suggested_key
            .get(platform)
            .or_else(|| self.suggested_key.get("default"))
            .and_then(Value::as_str)
            .or_else(|| self.suggested_key.as_str())
            .unwrap_or_default()
            .to_owned()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionWebAccessibleResource {
    pub resources: Vec<String>,
    #[serde(default)]
    pub matches: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionBackground {
    #[serde(default)]
    pub scripts: Vec<String>,
    #[serde(default)]
    pub service_worker: Option<String>,
    #[serde(default)]
    pub module: bool,
    #[serde(default = "default_background_persistent")]
    pub persistent: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionAction {
    #[serde(default)]
    pub default_title: Option<String>,
    #[serde(default)]
    pub default_popup: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionBackgroundKind {
    PersistentPage,
    ServiceWorker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionBackgroundInfo {
    pub kind: ExtensionBackgroundKind,
    pub persistent: bool,
    pub running: bool,
}
const MAX_WEB_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Converts buffered uploads into bounded `WebExtensions` requestBody data.
/// Streaming and oversized uploads are explicitly redacted.
#[must_use]
pub fn bounded_web_request_body(method: &str, content_type: Option<&str>, body: &[u8]) -> Value {
    if !matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    ) {
        return Value::Null;
    }
    if body.len() > MAX_WEB_REQUEST_BODY_BYTES {
        return serde_json::json!({"redacted": true, "reason": "size"});
    }
    if content_type.is_some_and(|value| value.starts_with("application/x-www-form-urlencoded")) {
        if let Ok(text) = std::str::from_utf8(body) {
            let form_data = text
                .split('&')
                .filter_map(|pair| {
                    let (name, value) = pair.split_once('=')?;
                    Some(serde_json::json!({"name": name, "value": value}))
                })
                .collect::<Vec<_>>();
            return serde_json::json!({"formData": form_data});
        }
    }
    serde_json::json!({"raw": [{"bytes": base64::engine::general_purpose::STANDARD.encode(body)}]})
}

const FORBIDDEN_WEB_REQUEST_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Applies a blocking listener's request-header edits. Header names are
/// case-insensitive and empty values remove headers. Transport framing and
/// authority headers are rejected.
pub fn apply_web_request_header_mutations(
    headers: &mut HeaderMap,
    response: &Value,
) -> Result<(), ExtensionError> {
    let Some(entries) = response.get("requestHeaders").and_then(Value::as_array) else {
        return Ok(());
    };

    for entry in entries {
        let Some(raw_name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let name = HeaderName::from_bytes(raw_name.as_bytes()).map_err(|_| {
            ExtensionError::InvalidManifest(format!("invalid webRequest header name {raw_name:?}"))
        })?;
        if FORBIDDEN_WEB_REQUEST_HEADERS.contains(&name.as_str()) {
            return Err(ExtensionError::PermissionDenied(format!(
                "webRequest cannot mutate forbidden header {name}"
            )));
        }
        let value = entry
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        headers.remove(&name);
        if !value.is_empty() {
            headers.insert(
                name,
                HeaderValue::from_str(value).map_err(|_| {
                    ExtensionError::InvalidManifest("invalid webRequest header value".into())
                })?,
            );
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebRequestBlockingRequest {
    pub webview_id: Option<u64>,
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub request_body_size: Option<usize>,
    pub request_body_unavailable: bool,
    pub is_for_main_frame: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WebRequestBlockingDecision {
    pub cancel: bool,
    pub redirect_url: Option<String>,
    pub request_headers: Option<Vec<(String, String)>>,
    pub response_headers: Option<Vec<(String, String)>>,
}

pub trait WebRequestBlockingHandler: Send + Sync {
    fn decide(&self, request: &WebRequestBlockingRequest) -> WebRequestBlockingDecision;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionEventKind {
    Startup,
    Installed {
        reason: String,
    },
    RuntimeMessage {
        sender_extension_id: Option<String>,
        tab_id: Option<u64>,
        request_id: Option<String>,
        payload: Value,
    },
    RuntimePortConnected {
        tab_id: u64,
        port_id: String,
        name: String,
    },
    RuntimePortMessage {
        tab_id: u64,
        port_id: String,
        payload: Value,
    },
    RuntimePortDisconnected {
        tab_id: u64,
        port_id: String,
    },
    RuntimeExternalPortConnected {
        sender_extension_id: String,
        port_id: String,
        name: String,
    },
    RuntimeExternalPortMessage {
        sender_extension_id: String,
        port_id: String,
        payload: Value,
    },
    RuntimeExternalPortDisconnected {
        sender_extension_id: String,
        port_id: String,
    },
    WebNavigation {
        event: String,
        details: Value,
    },
    StorageChanged {
        changes: Value,
    },
    NotificationClosed {
        id: String,
    },
    NotificationClicked {
        id: String,
    },
    NotificationButtonClicked {
        id: String,
        button_index: u64,
    },
    ContextMenuClicked {
        info: Value,
        tab: Option<ExtensionTabInfo>,
    },
    ContextMenuShown {
        info: Value,
        tab: Option<ExtensionTabInfo>,
    },
    ContextMenuHidden,
    PermissionAdded {
        details: Value,
    },
    PermissionRemoved {
        details: Value,
    },
    CookieChanged {
        cookie: Value,
        cause: Value,
        removed: bool,
    },
    RuntimeSuspend,
    RuntimeUpdateAvailable {
        version: String,
    },
    ManagementInstalled {
        info: Value,
    },
    ManagementUninstalled {
        info: Value,
    },
    ManagementEnabled {
        info: Value,
    },
    ManagementDisabled {
        info: Value,
    },
    HistoryVisited {
        details: Value,
    },
    HistoryTitleChanged {
        details: Value,
    },
    HistoryVisitRemoved {
        details: Value,
    },
    BookmarkCreated {
        bookmark: Value,
    },
    BookmarkRemoved {
        id: String,
        parent_id: String,
        index: u64,
    },
    BookmarkChanged {
        id: String,
        title: String,
        url: Option<String>,
    },
    BookmarkMoved {
        id: String,
        old_parent_id: String,
        old_index: u64,
        parent_id: String,
        index: u64,
    },
    DownloadCreated {
        details: Value,
    },
    DownloadChanged {
        details: Value,
    },
    DownloadErased {
        id: String,
    },
    Alarm {
        name: String,
        scheduled_time_ms: u64,
    },
    WebRequest {
        request: Value,
        event: &'static str,
    },
    RuleMatched {
        details: Value,
    },
    ActionClicked {
        tab: ExtensionTabInfo,
    },
    Command {
        command: String,
    },
    TabCreated {
        tab: Value,
    },
    TabUpdated {
        tab_id: u64,
        change_info: Value,
        tab: Value,
    },
    TabRemoved {
        tab_id: u64,
        window_id: u64,
    },
    TabActivated {
        tab_id: u64,
        window_id: u64,
    },
    WindowCreated {
        window: Value,
    },
    WindowRemoved {
        window_id: u64,
    },
    WindowFocusChanged {
        window_id: u64,
    },
    /// `identity.onSignInChanged`: the account behind an extension's provider
    /// grant (or the browser profile token) changed sign-in state.
    IdentitySignInChanged {
        signed_in: bool,
        account: Value,
    },
    RuntimeResponse {
        request_id: String,
        result: Result<Value, String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionEvent {
    pub extension_id: String,
    pub kind: ExtensionEventKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionContentScript {
    #[serde(default)]
    pub matches: Vec<String>,
    #[serde(default)]
    pub js: String,
    #[serde(default)]
    pub js_files: Vec<String>,
    #[serde(default)]
    pub css: String,
    #[serde(default)]
    pub css_files: Vec<String>,
    #[serde(default = "default_script_world")]
    pub world: ExtensionScriptWorld,
}

/// A content script registered at runtime via `chrome.scripting`.
///
/// Registered scripts persist across restarts and are injected exactly like
/// manifest-declared content scripts, subject to the same host-permission and
/// pattern checks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionRegisteredContentScript {
    /// Unique registration id within the extension.
    pub id: String,
    /// Host patterns this script matches.
    #[serde(default)]
    pub matches: Vec<String>,
    /// JavaScript file paths within the extension package.
    #[serde(default)]
    pub js: Vec<String>,
    /// CSS file paths within the extension package.
    #[serde(default)]
    pub css: Vec<String>,
    /// Whether the script runs in all frames of a matching page.
    #[serde(default)]
    pub all_frames: bool,
    /// `"document_start"`, `"document_end"`, or `"document_idle"`.
    #[serde(default = "default_registered_run_at")]
    pub run_at: String,
    #[serde(default)]
    pub world: ExtensionScriptWorld,
    /// Host patterns the script must not run on.
    #[serde(default)]
    pub exclude_matches: Vec<String>,
}

fn default_registered_run_at() -> String {
    "document_idle".into()
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum ExtensionScriptWorld {
    #[default]
    Isolated,
    Main,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionInjection {
    pub extension_id: String,
    pub manifest: ExtensionManifest,
    pub script: String,
    pub style: Option<String>,
    pub matches: Vec<String>,
    pub storage: Option<ExtensionStorage>,
    pub tab: Option<ExtensionTabInfo>,
    pub world: ExtensionScriptWorld,
}

/// The `WebExtensions` [`storage`](https://developer.chrome.com/docs/extensions/reference/api/storage) areas, kept as distinct namespaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtensionStorage {
    /// `storage.local` — persisted across restarts, extension-scoped.
    pub local: HashMap<String, Value>,
    /// `storage.sync` — persisted across restarts in its own namespace.
    pub sync: HashMap<String, Value>,
    /// `storage.session` — in-memory only, cleared when the browser restarts.
    pub session: HashMap<String, Value>,
}

/// A `WebExtensions` storage area name (`"local"`, `"sync"`, `"session"`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionStorageArea {
    Local,
    Sync,
    Session,
}

impl ExtensionStorageArea {
    fn from_str(name: &str) -> Option<Self> {
        match name {
            "local" => Some(Self::Local),
            "sync" => Some(Self::Sync),
            "session" => Some(Self::Session),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Sync => "sync",
            Self::Session => "session",
        }
    }
}

impl std::fmt::Display for ExtensionStorageArea {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionTabInfo {
    pub id: u64,
    pub url: Option<Url>,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionMessage {
    pub extension_id: String,
    pub tab_id: Option<u64>,
    pub payload: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionResource {
    pub extension_id: String,
    pub path: String,
    pub source: String,
    pub bytes: Vec<u8>,
    pub mime_type: String,
    pub web_accessible: bool,
    pub web_accessible_matches: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionApiRequest {
    pub request_id: String,
    pub method: String,
    pub arguments: Value,
}

#[must_use]
pub fn extension_api_request(payload: &Value) -> Option<ExtensionApiRequest> {
    let request = payload.get("__nomad_api_request")?.as_object()?;
    let request_id = request.get("id")?.as_str()?.to_owned();
    let method = request.get("method")?.as_str()?.to_owned();
    let arguments = request.get("arguments").cloned().unwrap_or(Value::Null);
    if request_id.is_empty() || request_id.len() > 128 || method.is_empty() || method.len() > 128 {
        return None;
    }
    Some(ExtensionApiRequest {
        request_id,
        method,
        arguments,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionPackage {
    manifest: ExtensionManifest,
    resources: HashMap<String, String>,
    binary_resources: HashMap<String, Vec<u8>>,
}

/// Target metadata for frame-aware extension scripting and navigation APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionFrameTarget {
    pub tab_id: u64,
    pub frame_ids: Option<Vec<i64>>,
    pub all_frames: bool,
}

impl ExtensionFrameTarget {
    /// Parses Chrome-compatible target selectors.
    ///
    /// # Errors
    ///
    /// Returns an extension error for malformed or conflicting selectors.
    pub fn parse(value: &Value) -> Result<Self, ExtensionError> {
        let object = value.as_object().ok_or_else(|| {
            ExtensionError::InvalidManifest("scripting target must be an object".into())
        })?;
        let tab_id = object.get("tabId").and_then(Value::as_u64).ok_or_else(|| {
            ExtensionError::InvalidManifest("scripting target requires tabId".into())
        })?;
        let all_frames = object
            .get("allFrames")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let frame_ids = object
            .get("frameIds")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| {
                        ExtensionError::InvalidManifest("frameIds must be an array".into())
                    })?
                    .iter()
                    .map(|frame| {
                        let id = frame.as_i64().ok_or_else(|| {
                            ExtensionError::InvalidManifest("frameIds must contain integers".into())
                        })?;
                        if id < 0 {
                            return Err(ExtensionError::InvalidManifest(
                                "frameIds must contain non-negative integers".into(),
                            ));
                        }
                        Ok(id)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        if frame_ids.as_ref().is_some_and(Vec::is_empty) {
            return Err(ExtensionError::InvalidManifest(
                "frameIds must not be empty".into(),
            ));
        }
        if all_frames && frame_ids.is_some() {
            return Err(ExtensionError::InvalidManifest(
                "allFrames and frameIds are mutually exclusive".into(),
            ));
        }
        Ok(Self {
            tab_id,
            frame_ids,
            all_frames,
        })
    }
}

/// Live frame metadata for one active tab document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionFrame {
    pub id: i64,
    pub parent_frame_id: Option<i64>,
    pub url: Url,
    pub navigation_generation: u64,
    /// Opaque renderer target, never serialized to extension code.
    pub renderer_handle: Option<u64>,
}

impl ExtensionFrame {
    #[must_use]
    pub fn top(url: Url, navigation_generation: u64) -> Self {
        Self {
            id: 0,
            parent_frame_id: Some(-1),
            url,
            navigation_generation,
            renderer_handle: None,
        }
    }

    #[must_use]
    pub fn child(id: i64, parent_frame_id: i64, url: Url, navigation_generation: u64) -> Self {
        Self::child_with_handle(id, Some(parent_frame_id), url, navigation_generation, None)
    }

    #[must_use]
    pub fn child_with_handle(
        id: i64,
        parent_frame_id: Option<i64>,
        url: Url,
        navigation_generation: u64,
        renderer_handle: Option<u64>,
    ) -> Self {
        Self {
            id,
            parent_frame_id,
            url,
            navigation_generation,
            renderer_handle,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionAlarm {
    pub extension_id: String,
    pub name: String,
    pub scheduled_time_ms: u64,
    pub period_ms: Option<u64>,
}

/// A manifest-declared keyboard command (`manifest.commands`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtensionCommand {
    pub name: String,
    pub description: String,
    pub suggested_key: String,
}

/// A command triggered by the user (keyboard shortcut), delivered to the
/// background context's `commands.onCommand` listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandEvent {
    pub command: String,
}

#[derive(Clone, Debug, Default)]
pub struct ExtensionFrameRegistry {
    tabs: HashMap<u64, (u64, Vec<ExtensionFrame>)>,
    order: VecDeque<u64>,
}

impl ExtensionFrameRegistry {
    const MAX_TABS: usize = 256;

    pub fn replace_tab(&mut self, tab_id: u64, generation: u64, frames: Vec<ExtensionFrame>) {
        self.tabs.insert(tab_id, (generation, frames));
        self.order.retain(|id| *id != tab_id);
        self.order.push_back(tab_id);
        while self.order.len() > Self::MAX_TABS {
            if let Some(evicted) = self.order.pop_front() {
                self.tabs.remove(&evicted);
            }
        }
    }

    pub fn remove_tab(&mut self, tab_id: u64) {
        self.tabs.remove(&tab_id);
        self.order.retain(|id| *id != tab_id);
    }

    /// Selects live frames, preserving explicit request order.
    ///
    /// # Errors
    ///
    /// Returns an extension error when tab/frame selectors do not resolve.
    pub fn select(
        &self,
        target: &ExtensionFrameTarget,
    ) -> Result<Vec<ExtensionFrame>, ExtensionError> {
        let (_, frames) = self
            .tabs
            .get(&target.tab_id)
            .ok_or_else(|| ExtensionError::Missing(format!("tab {}", target.tab_id)))?;
        if let Some(ids) = &target.frame_ids {
            let mut selected = Vec::with_capacity(ids.len());
            for id in ids {
                let frame = frames
                    .iter()
                    .find(|frame| frame.id == *id)
                    .ok_or_else(|| ExtensionError::Missing(format!("frame {id}")))?;
                selected.push(frame.clone());
            }

            return Ok(selected);
        }
        if target.all_frames {
            return Ok(frames.clone());
        }
        frames
            .iter()
            .find(|frame| frame.id == 0)
            .cloned()
            .map(|frame| vec![frame])
            .ok_or_else(|| ExtensionError::Missing("top frame".into()))
    }
    #[allow(clippy::needless_pass_by_value)]
    pub fn update_renderer_snapshot(
        &mut self,
        tab_id: u64,
        generation: u64,
        snapshot: Vec<(u64, Option<u64>, Url)>,
    ) {
        let previous = self.tabs.get(&tab_id).map(|(_, frames)| frames);
        let mut next_id = previous
            .into_iter()
            .flatten()
            .map(|frame| frame.id)
            .max()
            .unwrap_or(0)
            + 1;
        let mut frames: Vec<ExtensionFrame> = snapshot
            .iter()
            .enumerate()
            .map(|(index, (handle, _, url))| {
                let id = if index == 0 {
                    0
                } else {
                    previous
                        .into_iter()
                        .flatten()
                        .find(|frame| frame.renderer_handle == Some(*handle))
                        .map_or_else(
                            || {
                                let id = next_id;
                                next_id += 1;
                                id
                            },
                            |frame| frame.id,
                        )
                };
                ExtensionFrame {
                    id,
                    parent_frame_id: None,
                    url: url.clone(),
                    navigation_generation: generation,
                    renderer_handle: (index != 0).then_some(*handle),
                }
            })
            .collect();
        let handles = frames
            .iter()
            .zip(snapshot.iter())
            .map(|(frame, (handle, _, _))| (*handle, frame.id))
            .collect::<HashMap<_, _>>();
        for (frame, (_, parent_handle, _)) in frames.iter_mut().zip(snapshot.iter()) {
            frame.parent_frame_id = parent_handle.and_then(|handle| handles.get(&handle).copied());
        }
        self.replace_tab(tab_id, generation, frames);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionRegistrySnapshot {
    #[serde(default = "default_extension_state_version")]
    pub version: u8,
    #[serde(default)]
    pub extensions: Vec<ExtensionSnapshot>,
}

impl Default for ExtensionRegistrySnapshot {
    fn default() -> Self {
        Self {
            version: EXTENSION_STATE_VERSION,
            extensions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtensionSnapshot {
    pub manifest: ExtensionManifest,
    #[serde(default = "default_extension_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub permissions: Vec<ExtensionPermission>,
    #[serde(default)]
    pub host_permissions: Vec<String>,
    #[serde(default)]
    pub resources: HashMap<String, String>,
    #[serde(default)]
    pub binary_resources: HashMap<String, String>,
    #[serde(default)]
    pub storage: HashMap<String, Value>,
    #[serde(default)]
    pub storage_sync: HashMap<String, Value>,
    #[serde(default)]
    pub storage_session: HashMap<String, Value>,
    #[serde(default)]
    pub dynamic_rules: Vec<Value>,
    #[serde(default)]
    pub enabled_rulesets: Vec<String>,
    #[serde(default)]
    pub registered_content_scripts: Vec<ExtensionRegisteredContentScript>,
    /// Provider-backed identity token grants, persisted with storage keys.
    #[serde(default)]
    pub oauth_tokens: Vec<(String, OAuthTokenRecord)>,
    pub uninstall_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionError {
    InvalidManifest(String),
    DuplicateId(String),
    Missing(String),
    PermissionDenied(String),
    ResourceLimitExceeded(String),
}

#[derive(Clone, Debug)]
pub struct ActionState {
    pub badge_text: Option<String>,
    pub badge_background_color: Option<String>,
    pub badge_text_color: Option<String>,
    pub icon: Option<Value>,
    pub title: Option<String>,
    pub popup: Option<String>,
    pub enabled: bool,
    pub dnr_action_count_as_badge: bool,
}

impl Default for ActionState {
    fn default() -> Self {
        Self {
            badge_text: None,
            badge_background_color: None,
            badge_text_color: None,
            icon: None,
            title: None,
            popup: None,
            enabled: true,
            dnr_action_count_as_badge: false,
        }
    }
}

/// What an in-flight authorization flow is for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingAuthFlowKind {
    /// `identity.getAuthToken` interactive sign-in; resolves to a stored
    /// provider token plus an `onSignInChanged` transition.
    ProviderSignIn,
    /// `identity.launchWebAuthFlow`; resolves to the redirect URL string.
    LaunchWebAuthFlow,
}

/// An authorization-code flow awaiting its redirect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAuthFlow {
    pub flow_id: String,
    pub extension_id: String,
    pub request_id: String,
    pub kind: PendingAuthFlowKind,
    /// Where the flow tab navigates first (the provider authorize URL).
    pub auth_url: String,
    /// Loopback or `chromiumapp.org` completion target.
    pub redirect_uri: String,
    pub state: Option<String>,
    /// PKCE verifier for the token exchange (`ProviderSignIn` only).
    pub code_verifier: Option<String>,
    /// Storage key the exchanged token is persisted under.
    pub token_key: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Default)]
pub struct ExtensionRegistry {
    installed: HashMap<String, ExtensionManifest>,
    granted: HashMap<String, Vec<ExtensionPermission>>,
    granted_hosts: HashMap<String, Vec<String>>,
    resources: HashMap<String, HashMap<String, String>>,
    binary_resources: HashMap<String, HashMap<String, Vec<u8>>>,
    storage: HashMap<String, HashMap<String, Value>>,
    storage_sync: HashMap<String, HashMap<String, Value>>,
    storage_session: HashMap<String, HashMap<String, Value>>,
    messages: VecDeque<ExtensionMessage>,
    backgrounds: HashMap<String, ExtensionBackgroundInfo>,
    background_events: VecDeque<ExtensionEvent>,
    active_tab_grants: HashMap<String, HashSet<u64>>,
    alarms: Vec<ExtensionAlarm>,
    dynamic_rules: HashMap<String, Vec<Value>>,
    session_rules: HashMap<String, Vec<Value>>,
    static_rules: HashMap<String, HashMap<String, Vec<Value>>>,
    enabled_rulesets: HashMap<String, Vec<String>>,
    disabled: HashSet<String>,
    context_menus: HashMap<String, HashMap<String, Value>>,
    next_context_menu_id: u64,
    registered_content_scripts: HashMap<String, Vec<ExtensionRegisteredContentScript>>,
    uninstall_urls: HashMap<String, String>,
    action_states: HashMap<String, ActionState>,
    dnr_action_counts: HashMap<String, u64>,
    oauth_tokens: HashMap<String, OAuthTokenRecord>,
    pending_auth_flows: BTreeMap<String, PendingAuthFlow>,
    sign_in_accounts: HashMap<String, Option<String>>,
}

impl ExtensionManifest {
    #[allow(clippy::too_many_lines)]
    pub fn from_json(raw: &str) -> Result<Self, ExtensionError> {
        let input: RawManifest = serde_json::from_str(raw)
            .map_err(|error| ExtensionError::InvalidManifest(error.to_string()))?;
        let content_scripts_require_explicit_page_permissions =
            input.permissions.iter().any(|permission| {
                matches!(
                    permission.trim().to_ascii_lowercase().as_str(),
                    "readpage" | "modifypage"
                )
            });
        let id = input
            .id
            .clone()
            .or_else(|| {
                input
                    .browser_specific_settings
                    .as_ref()
                    .and_then(|settings| settings.gecko.as_ref())
                    .and_then(|gecko| gecko.id.clone())
            })
            .or_else(|| {
                input
                    .applications
                    .as_ref()
                    .and_then(|settings| settings.gecko.as_ref())
                    .and_then(|gecko| gecko.id.clone())
            })
            .map_or_else(
                || derive_extension_id(input.key.as_deref(), &input.name, &input.version),
                Ok,
            )?;
        let mut permissions = Vec::new();
        let mut unsupported_permissions = Vec::new();
        let mut host_permissions = input.host_permissions;
        for permission in input.permissions {
            if is_match_pattern(&permission) {
                host_permissions.push(permission);
                continue;
            }
            match standard_permissions(&permission) {
                Ok(mapped_permissions) => {
                    for mapped in mapped_permissions {
                        if !permissions.contains(&mapped) {
                            permissions.push(mapped);
                        }
                    }
                }
                Err(ExtensionError::InvalidManifest(_)) => {
                    unsupported_permissions.push(normalize_unknown_permission(&permission)?);
                }
                Err(error) => return Err(error),
            }
        }
        let mut optional_permissions = Vec::new();
        let mut unsupported_optional_permissions = Vec::new();
        let mut optional_host_permissions = input.optional_host_permissions;
        for permission in input.optional_permissions {
            if is_match_pattern(&permission) {
                optional_host_permissions.push(permission);
                continue;
            }
            match standard_permissions(&permission) {
                Ok(mapped_permissions) => {
                    for mapped in mapped_permissions {
                        if !optional_permissions.contains(&mapped) {
                            optional_permissions.push(mapped);
                        }
                    }
                }
                Err(ExtensionError::InvalidManifest(_)) => unsupported_optional_permissions
                    .push(normalize_unknown_permission(&permission)?),
                Err(error) => return Err(error),
            }
        }
        let content_scripts = input
            .content_scripts
            .into_iter()
            .map(RawContentScript::try_into_manifest)
            .collect::<Result<Vec<_>, _>>()?;
        let background = input
            .background
            .map(RawBackground::try_into_manifest)
            .transpose()?;
        let action = input
            .action
            .or(input.browser_action)
            .map(RawAction::try_into_manifest);
        let web_accessible_resources =
            parse_web_accessible_resources(&input.web_accessible_resources)?;
        let externally_connectable_ids = input
            .externally_connectable
            .map(|value| value.ids)
            .unwrap_or_default();
        let blocked_host_patterns = input.nomad_blocked_hosts;
        let declarative_net_request = input
            .declarative_net_request
            .map(|value| value.rule_resources)
            .unwrap_or_default();
        if let Some(config) = &input.oauth2 {
            if config.client_id.trim().is_empty() {
                return Err(ExtensionError::InvalidManifest(
                    "oauth2.client_id must not be empty".into(),
                ));
            }
            if config
                .scopes
                .iter()
                .any(|scope| scope.trim().is_empty() || scope.len() > 64)
            {
                return Err(ExtensionError::InvalidManifest(
                    "oauth2.scopes entries must be non-empty and at most 64 characters".into(),
                ));
            }
        }
        let manifest = Self {
            manifest_version: input.manifest_version,
            id,
            name: input.name,
            version: input.version,
            permissions,
            host_permissions,
            optional_permissions,
            optional_host_permissions,
            unsupported_permissions,
            unsupported_optional_permissions,
            content_scripts,
            background,
            action,
            web_accessible_resources,
            externally_connectable_ids,
            options_ui: input.options_ui,
            options_page: input.options_page,
            oauth2: input.oauth2,
            blocked_host_patterns,
            declarative_net_request,
            commands: input.commands,
            content_scripts_require_explicit_page_permissions,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if !matches!(self.manifest_version, 2 | 3) {
            return Err(ExtensionError::InvalidManifest(format!(
                "unsupported manifest version {}",
                self.manifest_version
            )));
        }
        validate_text_field("id", &self.id, 128)?;
        validate_text_field("name", &self.name, 256)?;
        validate_text_field("version", &self.version, 128)?;
        if self
            .host_permissions
            .iter()
            .any(|pattern| !is_match_pattern(pattern))
        {
            return Err(ExtensionError::InvalidManifest(
                "invalid host permission pattern".into(),
            ));
        }
        if self
            .optional_host_permissions
            .iter()
            .any(|pattern| !is_match_pattern(pattern))
        {
            return Err(ExtensionError::InvalidManifest(
                "invalid optional host permission pattern".into(),
            ));
        }
        for permission in self
            .unsupported_permissions
            .iter()
            .chain(&self.unsupported_optional_permissions)
        {
            normalize_unknown_permission(permission)?;
        }
        for script in &self.content_scripts {
            if script.matches.is_empty() {
                return Err(ExtensionError::InvalidManifest(
                    "content script requires at least one match pattern".into(),
                ));
            }
            if script
                .matches
                .iter()
                .any(|pattern| !is_match_pattern(pattern))
            {
                return Err(ExtensionError::InvalidManifest(
                    "invalid content script match pattern".into(),
                ));
            }
            if script.js.trim().is_empty()
                && script.js_files.is_empty()
                && script.css.trim().is_empty()
                && script.css_files.is_empty()
            {
                return Err(ExtensionError::InvalidManifest(
                    "content script requires JavaScript or CSS resources".into(),
                ));
            }
            if !script.js.trim().is_empty() && !script.js_files.is_empty() {
                return Err(ExtensionError::InvalidManifest(
                    "content script cannot mix inline JavaScript and resource files".into(),
                ));
            }
            if script.js.len() > MAX_EXTENSION_RESOURCE_BYTES {
                return Err(ExtensionError::ResourceLimitExceeded(
                    "inline content script is too large".into(),
                ));
            }
            for file in &script.js_files {
                validate_resource_name(file)?;
            }
            if script.css.len() > MAX_EXTENSION_RESOURCE_BYTES {
                return Err(ExtensionError::ResourceLimitExceeded(
                    "inline content stylesheet is too large".into(),
                ));
            }
            for file in &script.css_files {
                validate_resource_name(file)?;
            }
        }
        if let Some(background) = &self.background {
            if background.scripts.is_empty() == background.service_worker.is_none() {
                return Err(ExtensionError::InvalidManifest(
                    "background must declare scripts or one service worker".into(),
                ));
            }
            for script in &background.scripts {
                validate_resource_name(script)?;
            }
            if let Some(service_worker) = &background.service_worker {
                validate_resource_name(service_worker)?;
            }
        }
        if let Some(action) = &self.action {
            if let Some(title) = &action.default_title {
                validate_text_field("action.default_title", title, 256)?;
            }
            if let Some(popup) = &action.default_popup {
                validate_resource_name(popup)?;
            }
        }
        for entry in &self.web_accessible_resources {
            for resource in &entry.resources {
                validate_resource_name(resource)?;
            }
            if entry
                .matches
                .iter()
                .any(|pattern| !is_match_pattern(pattern))
            {
                return Err(ExtensionError::InvalidManifest(
                    "invalid web accessible resource match pattern".into(),
                ));
            }
        }
        for id in &self.externally_connectable_ids {
            validate_text_field("externally_connectable.ids", id, 128)?;
        }
        if self
            .blocked_host_patterns
            .iter()
            .any(|pattern| !is_match_pattern(pattern))
        {
            return Err(ExtensionError::InvalidManifest(
                "invalid Nomad blocking host pattern".into(),
            ));
        }
        let mut ruleset_ids = HashSet::new();
        for ruleset in &self.declarative_net_request {
            validate_text_field("declarative_net_request.id", &ruleset.id, 64)?;
            if ruleset.id.chars().any(|character| {
                !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
            }) || !ruleset_ids.insert(&ruleset.id)
            {
                return Err(ExtensionError::InvalidManifest(
                    "declarative ruleset IDs must be unique ASCII names".into(),
                ));
            }
            validate_resource_name(&ruleset.path)?;
        }
        Ok(())
    }
}

impl ExtensionPackage {
    pub fn from_manifest_json(
        raw_manifest: &str,
        resources: HashMap<String, String>,
    ) -> Result<Self, ExtensionError> {
        let manifest = ExtensionManifest::from_json(raw_manifest)?;
        Self::from_parts(manifest, resources, HashMap::new())
    }

    pub fn from_directory(path: impl AsRef<Path>) -> Result<Self, ExtensionError> {
        let root = path.as_ref();
        let metadata = fs::symlink_metadata(root).map_err(|error| {
            ExtensionError::InvalidManifest(format!("cannot inspect extension directory: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ExtensionError::InvalidManifest(
                "extension package must be a real directory".into(),
            ));
        }
        let manifest_path = root.join("manifest.json");
        let manifest = fs::read_to_string(&manifest_path).map_err(|error| {
            ExtensionError::InvalidManifest(format!("cannot read manifest.json: {error}"))
        })?;
        ExtensionManifest::from_json(&manifest)?;
        let mut names = Vec::new();
        collect_directory_resources(root, root, &mut names)?;
        let mut resources = HashMap::new();
        let mut binary_resources = HashMap::new();
        let mut total_bytes = 0_usize;
        for name in names {
            let resource_path = safe_resource_path(root, &name)?;
            let bytes = fs::read(&resource_path).map_err(|error| {
                ExtensionError::InvalidManifest(format!(
                    "cannot read extension resource {name:?}: {error}"
                ))
            })?;
            total_bytes = total_bytes.saturating_add(bytes.len());
            if total_bytes > MAX_EXTENSION_RESOURCE_BYTES {
                return Err(ExtensionError::ResourceLimitExceeded(
                    "extension resources are too large".into(),
                ));
            }
            match String::from_utf8(bytes) {
                Ok(source) => {
                    resources.insert(name, source);
                }
                Err(error) => {
                    binary_resources.insert(name, error.into_bytes());
                }
            }
        }
        Self::from_parts(
            ExtensionManifest::from_json(&manifest)?,
            resources,
            binary_resources,
        )
    }

    pub fn from_archive_bytes(bytes: &[u8]) -> Result<Self, ExtensionError> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|error| {
            ExtensionError::InvalidManifest(format!("cannot read extension archive: {error}"))
        })?;
        if archive.len() > MAX_EXTENSION_RESOURCE_COUNT {
            return Err(ExtensionError::ResourceLimitExceeded(
                "extension archive contains too many files".into(),
            ));
        }

        let manifest_raw = {
            let mut raw = None;
            for index in 0..archive.len() {
                let mut file = archive.by_index(index).map_err(|error| {
                    ExtensionError::InvalidManifest(format!(
                        "cannot read extension archive entry: {error}"
                    ))
                })?;
                let path = file.enclosed_name().ok_or_else(|| {
                    ExtensionError::InvalidManifest(
                        "extension archive contains a traversal path".into(),
                    )
                })?;
                if file.is_dir() || path != Path::new("manifest.json") {
                    continue;
                }
                if file.size() > MAX_EXTENSION_RESOURCE_BYTES as u64 {
                    return Err(ExtensionError::ResourceLimitExceeded(
                        "extension manifest is too large".into(),
                    ));
                }
                let mut contents = String::new();
                file.read_to_string(&mut contents).map_err(|error| {
                    ExtensionError::InvalidManifest(format!(
                        "extension manifest is not valid UTF-8: {error}"
                    ))
                })?;
                raw = Some(contents);
                break;
            }
            raw.ok_or_else(|| {
                ExtensionError::InvalidManifest("extension archive has no manifest.json".into())
            })?
        };
        let manifest = ExtensionManifest::from_json(&manifest_raw)?;
        let mut resources = HashMap::new();
        let mut binary_resources = HashMap::new();
        let mut total_bytes = 0_u64;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).map_err(|error| {
                ExtensionError::InvalidManifest(format!(
                    "cannot read extension archive entry: {error}"
                ))
            })?;
            let path = file.enclosed_name().ok_or_else(|| {
                ExtensionError::InvalidManifest(
                    "extension archive contains a traversal path".into(),
                )
            })?;
            if file.is_dir() {
                continue;
            }
            let name = path.to_str().ok_or_else(|| {
                ExtensionError::InvalidManifest("extension archive path is not UTF-8".into())
            })?;
            validate_resource_name(name)?;
            if name == "manifest.json" {
                continue;
            }
            total_bytes = total_bytes.saturating_add(file.size());
            if total_bytes > MAX_EXTENSION_RESOURCE_BYTES as u64 {
                return Err(ExtensionError::ResourceLimitExceeded(
                    "extension script resources are too large".into(),
                ));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|error| {
                ExtensionError::InvalidManifest(format!(
                    "cannot read extension resource {name:?}: {error}"
                ))
            })?;
            match String::from_utf8(bytes) {
                Ok(source) => {
                    resources.insert(name.to_owned(), source);
                }
                Err(error) => {
                    binary_resources.insert(name.to_owned(), error.into_bytes());
                }
            }
        }
        Self::from_parts(manifest, resources, binary_resources)
    }

    fn from_parts(
        manifest: ExtensionManifest,
        resources: HashMap<String, String>,
        binary_resources: HashMap<String, Vec<u8>>,
    ) -> Result<Self, ExtensionError> {
        validate_resources(&manifest, &resources, &binary_resources)?;
        Ok(Self {
            manifest,
            resources,
            binary_resources,
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &ExtensionManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn resources(&self) -> &HashMap<String, String> {
        &self.resources
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ExtensionManifest,
        HashMap<String, String>,
        HashMap<String, Vec<u8>>,
    ) {
        (self.manifest, self.resources, self.binary_resources)
    }
}

fn safe_resource_path(root: &Path, name: &str) -> Result<PathBuf, ExtensionError> {
    validate_resource_name(name)?;
    let path = root.join(name);
    let mut current = root.to_path_buf();
    for component in name.split('/') {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            ExtensionError::InvalidManifest(format!("cannot inspect resource {name:?}: {error}"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ExtensionError::InvalidManifest(format!(
                "extension resource {name:?} contains a symlink"
            )));
        }
    }
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        ExtensionError::InvalidManifest(format!("cannot inspect resource {name:?}: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ExtensionError::InvalidManifest(format!(
            "extension resource {name:?} must be a regular file"
        )));
    }
    Ok(path)
}

fn collect_directory_resources(
    root: &Path,
    directory: &Path,
    names: &mut Vec<String>,
) -> Result<(), ExtensionError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        ExtensionError::InvalidManifest(format!("cannot read extension directory: {error}"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ExtensionError::InvalidManifest(format!("cannot inspect extension resource: {error}"))
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            ExtensionError::InvalidManifest(format!("cannot inspect extension resource: {error}"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ExtensionError::InvalidManifest(
                "extension package contains a symlink".into(),
            ));
        }
        if metadata.is_dir() {
            collect_directory_resources(root, &path, names)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ExtensionError::InvalidManifest(
                "extension package contains a non-file resource".into(),
            ));
        }
        let relative = path.strip_prefix(root).map_err(|error| {
            ExtensionError::InvalidManifest(format!("extension resource path: {error}"))
        })?;
        let name = relative
            .components()
            .map(|component| component.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                ExtensionError::InvalidManifest("extension resource path is not UTF-8".into())
            })?
            .join("/");
        validate_resource_name(&name)?;
        if name != "manifest.json" {
            names.push(name);
        }
    }
    Ok(())
}

impl ExtensionRegistrySnapshot {
    pub fn to_json(&self) -> Result<String, ExtensionError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| ExtensionError::InvalidManifest(error.to_string()))
    }

    pub fn from_json(raw: &str) -> Result<Self, ExtensionError> {
        serde_json::from_str(raw)
            .map_err(|error| ExtensionError::InvalidManifest(error.to_string()))
    }
}

impl ExtensionRegistry {
    pub fn install(&mut self, manifest: ExtensionManifest) -> Result<(), ExtensionError> {
        self.install_with_resources(manifest, HashMap::new())
    }

    pub fn install_package(&mut self, package: ExtensionPackage) -> Result<(), ExtensionError> {
        let (manifest, resources, binary_resources) = package.into_parts();
        self.install_with_package_resources(manifest, resources, binary_resources)
    }

    /// Installs a newer package while preserving user-granted capabilities,
    /// host grants, storage, and dynamic rules that remain valid for the new
    /// manifest.
    pub fn update_package(&mut self, package: ExtensionPackage) -> Result<(), ExtensionError> {
        let (manifest, resources, binary_resources) = package.into_parts();
        manifest.validate()?;
        validate_resources(&manifest, &resources, &binary_resources)?;
        let static_rules = load_static_rulesets(&manifest, &resources, &binary_resources)?;
        let id = manifest.id.clone();
        let current = self
            .installed
            .get(&id)
            .cloned()
            .ok_or_else(|| ExtensionError::Missing(id.clone()))?;
        if !extension_version_is_newer(&manifest.version, &current.version) {
            return Err(ExtensionError::InvalidManifest(format!(
                "extension update version {} is not newer than {}",
                manifest.version, current.version
            )));
        }
        let enabled_rulesets = self.enabled_rulesets.get(&id).map_or_else(
            || {
                manifest
                    .declarative_net_request
                    .iter()
                    .filter(|ruleset| ruleset.enabled)
                    .map(|ruleset| ruleset.id.clone())
                    .collect()
            },
            |enabled| {
                let known = static_rules.keys().collect::<HashSet<_>>();
                enabled
                    .iter()
                    .filter(|ruleset| known.contains(ruleset))
                    .cloned()
                    .collect::<Vec<_>>()
            },
        );

        if let Some(granted) = self.granted.get_mut(&id) {
            granted.retain(|permission| {
                manifest.permissions.contains(permission)
                    || manifest.optional_permissions.contains(permission)
            });
        }
        if let Some(granted_hosts) = self.granted_hosts.get_mut(&id) {
            granted_hosts.retain(|pattern| manifest.host_permissions.contains(pattern));
        }
        let enabled = self.is_enabled(&id);
        self.resources.insert(id.clone(), resources);
        self.binary_resources.insert(id.clone(), binary_resources);
        self.static_rules.insert(id.clone(), static_rules);
        self.enabled_rulesets.insert(id.clone(), enabled_rulesets);
        self.installed.insert(id.clone(), manifest.clone());
        self.backgrounds.remove(&id);
        self.context_menus.remove(&id);
        self.active_tab_grants.remove(&id);
        self.background_events
            .retain(|event| event.extension_id != id);

        if enabled && manifest.background.is_some() {
            let background = ExtensionBackgroundInfo {
                kind: if manifest
                    .background
                    .as_ref()
                    .is_some_and(|background| background.service_worker.is_some())
                {
                    ExtensionBackgroundKind::ServiceWorker
                } else {
                    ExtensionBackgroundKind::PersistentPage
                },
                persistent: manifest
                    .background
                    .as_ref()
                    .is_some_and(|background| background.persistent),
                running: false,
            };
            self.backgrounds.insert(id.clone(), background);
            self.start_background(&id)?;
            self.background_events.push_back(ExtensionEvent {
                extension_id: id.clone(),
                kind: ExtensionEventKind::Installed {
                    reason: "update".into(),
                },
            });
        }
        Ok(())
    }

    pub fn install_with_resources(
        &mut self,
        manifest: ExtensionManifest,
        resources: HashMap<String, String>,
    ) -> Result<(), ExtensionError> {
        self.install_with_package_resources(manifest, resources, HashMap::new())
    }

    fn install_with_package_resources(
        &mut self,
        manifest: ExtensionManifest,
        resources: HashMap<String, String>,
        binary_resources: HashMap<String, Vec<u8>>,
    ) -> Result<(), ExtensionError> {
        if self.installed.contains_key(&manifest.id) {
            return Err(ExtensionError::DuplicateId(manifest.id));
        }
        manifest.validate()?;
        validate_resources(&manifest, &resources, &binary_resources)?;
        let static_rules = load_static_rulesets(&manifest, &resources, &binary_resources)?;
        let enabled_rulesets = manifest
            .declarative_net_request
            .iter()
            .filter(|ruleset| ruleset.enabled)
            .map(|ruleset| ruleset.id.clone())
            .collect::<Vec<_>>();
        if self.installed.len() >= MAX_EXTENSION_COUNT {
            return Err(ExtensionError::ResourceLimitExceeded(
                "maximum installed extension count reached".into(),
            ));
        }
        let background = manifest
            .background
            .as_ref()
            .map(|background| ExtensionBackgroundInfo {
                kind: if background.service_worker.is_some() {
                    ExtensionBackgroundKind::ServiceWorker
                } else {
                    ExtensionBackgroundKind::PersistentPage
                },
                persistent: background.persistent,
                running: false,
            });
        let id = manifest.id.clone();
        self.resources.insert(manifest.id.clone(), resources);
        self.binary_resources
            .insert(manifest.id.clone(), binary_resources);
        self.static_rules.insert(id.clone(), static_rules);
        self.enabled_rulesets.insert(id.clone(), enabled_rulesets);
        self.storage.insert(manifest.id.clone(), HashMap::new());
        self.installed.insert(id.clone(), manifest);
        if let Some(background) = background {
            self.backgrounds.insert(id.clone(), background);
            self.start_background(&id)?;
            self.background_events.push_back(ExtensionEvent {
                extension_id: id.clone(),
                kind: ExtensionEventKind::Installed {
                    reason: "install".into(),
                },
            });
        }
        Ok(())
    }

    /// The `oauth2` provider configuration declared by an extension.
    #[must_use]
    pub fn oauth_provider(&self, id: &str) -> Option<&OAuthProviderConfig> {
        self.installed
            .get(id)
            .and_then(|manifest| manifest.oauth2.as_ref())
    }

    /// The stored provider token under one grant key.
    #[must_use]
    pub fn oauth_token_for_key(&self, key: &str) -> Option<&OAuthTokenRecord> {
        self.oauth_tokens.get(key)
    }

    /// Stores (or replaces) one provider token grant, evicting expired-then-
    /// oldest entries once [`MAX_OAUTH_TOKEN_RECORDS`] is exceeded.
    pub fn store_oauth_token(&mut self, key: String, record: OAuthTokenRecord) {
        self.oauth_tokens.insert(key, record);
        while self.oauth_tokens.len() > MAX_OAUTH_TOKEN_RECORDS {
            let victim = self
                .oauth_tokens
                .iter()
                .min_by_key(|(_, record)| {
                    (record.is_expired_at(unix_now_ms()), record.stored_at_ms)
                })
                .map(|(key, _)| key.clone());
            let Some(victim) = victim else {
                break;
            };
            self.oauth_tokens.remove(&victim);
        }
    }

    /// Takes the stored provider token under one grant key.
    pub fn take_oauth_token(&mut self, key: &str) -> Option<OAuthTokenRecord> {
        self.oauth_tokens.remove(key)
    }

    /// Removes every token grant belonging to one extension.
    pub fn remove_oauth_tokens(&mut self, extension_id: &str) {
        let prefix = format!("{extension_id}\u{0}");
        self.oauth_tokens.retain(|key, _| !key.starts_with(&prefix));
    }

    /// The account an extension is currently signed in to, if any.
    #[must_use]
    pub fn oauth_account(&self, extension_id: &str) -> Option<&str> {
        self.sign_in_accounts
            .get(extension_id)
            .and_then(Option::as_deref)
    }

    /// Updates the sign-in account and returns the `onSignInChanged`
    /// transition (`(account_id, signed_in)`) when the account actually
    /// changed. Setting the same account again is a no-op.
    pub fn set_oauth_account(
        &mut self,
        extension_id: &str,
        account_id: Option<String>,
    ) -> Option<(String, bool)> {
        let previous = self.sign_in_accounts.get(extension_id).cloned().flatten();
        if previous == account_id {
            return None;
        }
        let transition = match &account_id {
            Some(account) => Some((account.clone(), true)),
            None => previous.map(|account| (account, false)),
        };
        self.sign_in_accounts
            .insert(extension_id.to_owned(), account_id);
        transition
    }

    /// Registers a pending authorization flow, bounded by
    /// [`MAX_PENDING_AUTH_FLOWS`].
    pub fn set_pending_auth_flow(&mut self, flow: PendingAuthFlow) -> Result<(), ExtensionError> {
        if self.pending_auth_flows.contains_key(&flow.flow_id) {
            return Err(ExtensionError::InvalidManifest(
                "duplicate authorization flow id".into(),
            ));
        }
        self.pending_auth_flows.insert(flow.flow_id.clone(), flow);
        while self.pending_auth_flows.len() > MAX_PENDING_AUTH_FLOWS {
            let Some(flow_id) = self.pending_auth_flows.keys().next().cloned() else {
                break;
            };
            self.pending_auth_flows.remove(&flow_id);
        }
        Ok(())
    }

    /// Takes one pending flow by id.
    pub fn take_pending_auth_flow(&mut self, flow_id: &str) -> Option<PendingAuthFlow> {
        self.pending_auth_flows.remove(flow_id)
    }

    /// Expires stale flows, then returns the pending flow whose redirect
    /// target matches `url` (scheme/host/path per RFC 8252, port ignored).
    pub fn pending_auth_flow_for_redirect(
        &mut self,
        url: &Url,
        now_ms: u64,
    ) -> Option<(String, PendingAuthFlow)> {
        let expired: Vec<String> = self
            .pending_auth_flows
            .iter()
            .filter(|(_, flow)| {
                now_ms.saturating_sub(flow.created_at_ms) > PENDING_AUTH_FLOW_TTL_MS
            })
            .map(|(flow_id, _)| flow_id.clone())
            .collect();
        for flow_id in expired {
            self.pending_auth_flows.remove(&flow_id);
        }
        let flow_id = self
            .pending_auth_flows
            .iter()
            .find(|(_, flow)| redirect_matches_redirect_uri(url, &flow.redirect_uri))
            .map(|(flow_id, _)| flow_id.clone())?;
        let flow = self.pending_auth_flows.remove(&flow_id)?;
        Some((flow_id, flow))
    }

    /// Removes every pending flow belonging to one extension.
    pub fn remove_pending_auth_flows(&mut self, extension_id: &str) {
        self.pending_auth_flows
            .retain(|_, flow| flow.extension_id != extension_id);
    }

    #[must_use]
    pub fn snapshot(&self) -> ExtensionRegistrySnapshot {
        let mut ids: Vec<_> = self.installed.keys().cloned().collect();
        ids.sort_unstable();
        let extensions = ids
            .into_iter()
            .filter_map(|id| {
                let manifest = self.installed.get(&id)?.clone();
                Some(ExtensionSnapshot {
                    manifest,
                    enabled: !self.disabled.contains(&id),
                    permissions: self.granted.get(&id).cloned().unwrap_or_default(),
                    host_permissions: self.granted_hosts.get(&id).cloned().unwrap_or_default(),
                    resources: self.resources.get(&id).cloned().unwrap_or_default(),
                    binary_resources: self
                        .binary_resources
                        .get(&id)
                        .map(|resources| {
                            resources
                                .iter()
                                .map(|(path, bytes)| {
                                    (
                                        path.clone(),
                                        base64::engine::general_purpose::STANDARD.encode(bytes),
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    storage: self.storage.get(&id).cloned().unwrap_or_default(),
                    storage_sync: self.storage_sync.get(&id).cloned().unwrap_or_default(),
                    // storage.session is in-memory only and intentionally not
                    // snapshotted: it is cleared on restart, matching Chromium.
                    storage_session: HashMap::new(),
                    dynamic_rules: self.dynamic_rules.get(&id).cloned().unwrap_or_default(),
                    enabled_rulesets: self.enabled_rulesets.get(&id).cloned().unwrap_or_default(),
                    registered_content_scripts: self
                        .registered_content_scripts
                        .get(&id)
                        .cloned()
                        .unwrap_or_default(),
                    uninstall_url: self.uninstall_urls.get(&id).cloned(),
                    oauth_tokens: {
                        let prefix = format!("{id}\u{0}");
                        let mut grants: Vec<(String, OAuthTokenRecord)> = self
                            .oauth_tokens
                            .iter()
                            .filter(|(key, _)| key.starts_with(&prefix))
                            .map(|(key, record)| (key.clone(), record.clone()))
                            .collect();
                        grants.sort_by(|left, right| left.0.cmp(&right.0));
                        grants
                    },
                })
            })
            .collect();
        ExtensionRegistrySnapshot {
            version: EXTENSION_STATE_VERSION,
            extensions,
        }
    }

    pub fn restore(&mut self, snapshot: ExtensionRegistrySnapshot) -> Result<(), ExtensionError> {
        if snapshot.version != EXTENSION_STATE_VERSION {
            return Err(ExtensionError::InvalidManifest(format!(
                "unsupported extension state version {}",
                snapshot.version
            )));
        }
        if snapshot.extensions.len() > MAX_EXTENSION_COUNT {
            return Err(ExtensionError::ResourceLimitExceeded(
                "extension state contains too many extensions".into(),
            ));
        }
        let mut restored = Self::default();
        for extension in snapshot.extensions {
            let id = extension.manifest.id.clone();
            let binary_resources = extension
                .binary_resources
                .into_iter()
                .map(|(path, encoded)| {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map(|bytes| (path, bytes))
                        .map_err(|error| {
                            ExtensionError::InvalidManifest(format!(
                                "invalid binary extension resource: {error}"
                            ))
                        })
                })
                .collect::<Result<HashMap<_, _>, _>>()?;
            restored.install_with_package_resources(
                extension.manifest,
                extension.resources,
                binary_resources,
            )?;
            for permission in extension.permissions {
                restored.grant(&id, permission)?;
            }
            for pattern in extension.host_permissions {
                restored.grant_host_permission(&id, &pattern)?;
            }
            restored.replace_storage_values(&id, &extension.storage)?;
            restored.replace_storage_values_area(
                &id,
                ExtensionStorageArea::Sync,
                &extension.storage_sync,
            )?;
            restored.replace_declarative_rules(&id, extension.dynamic_rules, false)?;
            restored.set_enabled_rulesets(&id, &extension.enabled_rulesets)?;
            restored
                .registered_content_scripts
                .insert(id.clone(), extension.registered_content_scripts);
            if let Some(url) = &extension.uninstall_url {
                restored.uninstall_urls.insert(id.clone(), url.clone());
            }
            for (key, record) in extension.oauth_tokens {
                restored.oauth_tokens.insert(key, record);
            }
            if !extension.enabled {
                restored.set_enabled(&id, false)?;
            }
        }
        *self = restored;
        Ok(())
    }

    pub fn uninstall(&mut self, id: &str) -> Result<ExtensionManifest, ExtensionError> {
        self.granted.remove(id);
        self.granted_hosts.remove(id);
        self.resources.remove(id);
        self.binary_resources.remove(id);
        self.storage.remove(id);
        self.storage_sync.remove(id);
        self.dnr_action_counts.remove(id);
        self.remove_oauth_tokens(id);
        self.remove_pending_auth_flows(id);
        self.sign_in_accounts.remove(id);
        self.messages.retain(|message| message.extension_id != id);
        self.backgrounds.remove(id);
        self.active_tab_grants.remove(id);
        self.alarms.retain(|alarm| alarm.extension_id != id);
        self.dynamic_rules.remove(id);
        self.session_rules.remove(id);
        self.static_rules.remove(id);
        self.enabled_rulesets.remove(id);
        self.registered_content_scripts.remove(id);
        self.disabled.remove(id);
        self.background_events
            .retain(|event| event.extension_id != id);
        self.uninstall_urls.remove(id);
        self.action_states.remove(id);
        self.dnr_action_counts.remove(id);
        self.installed
            .remove(id)
            .ok_or_else(|| ExtensionError::Missing(id.to_owned()))
    }

    pub fn installed(&self) -> impl Iterator<Item = &ExtensionManifest> {
        self.installed.values()
    }

    #[must_use]
    pub fn optional_permissions(&self, id: &str) -> Vec<ExtensionPermission> {
        self.installed
            .get(id)
            .map(|manifest| manifest.optional_permissions.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn optional_host_permissions(&self, id: &str) -> Vec<String> {
        self.installed
            .get(id)
            .map(|manifest| manifest.optional_host_permissions.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn manifest(&self, id: &str) -> Option<ExtensionManifest> {
        self.installed.get(id).cloned()
    }

    #[must_use]
    pub fn is_enabled(&self, id: &str) -> bool {
        self.installed.contains_key(id) && !self.disabled.contains(id)
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), ExtensionError> {
        self.require_installed(id)?;
        if enabled {
            self.disabled.remove(id);
            if self.backgrounds.contains_key(id) {
                self.start_background(id)?;
            }
        } else {
            self.disabled.insert(id.to_owned());
            if let Some(background) = self.backgrounds.get_mut(id) {
                background.running = false;
            }
            self.alarms.retain(|alarm| alarm.extension_id != id);
            self.background_events
                .retain(|event| event.extension_id != id);
        }
        Ok(())
    }

    #[must_use]
    pub fn background_info(&self, id: &str) -> Option<ExtensionBackgroundInfo> {
        self.backgrounds.get(id).cloned()
    }

    pub fn set_uninstall_url(&mut self, id: &str, url: &str) -> Result<(), ExtensionError> {
        self.require_installed(id)?;
        let parsed = url
            .parse::<Url>()
            .map_err(|_| ExtensionError::InvalidManifest("uninstall URL is invalid".into()))?;
        if !matches!(parsed.scheme(), "http" | "https") || url.len() > 1024 {
            return Err(ExtensionError::InvalidManifest(
                "uninstall URL must be an http(s) URL".into(),
            ));
        }
        self.uninstall_urls.insert(id.to_owned(), url.to_owned());
        Ok(())
    }

    #[must_use]
    pub fn uninstall_url(&self, id: &str) -> Option<String> {
        self.uninstall_urls.get(id).cloned()
    }

    #[must_use]
    pub fn background_script(&self, id: &str) -> Option<String> {
        let manifest = self.installed.get(id)?;
        let resources = self.resources.get(id)?;
        let background = manifest.background.as_ref()?;
        if let Some(service_worker) = &background.service_worker {
            return resources.get(service_worker).cloned();
        }
        Some(
            background
                .scripts
                .iter()
                .filter_map(|script| resources.get(script))
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    #[must_use]
    pub fn background_script_paths(&self, id: &str) -> Vec<String> {
        let Some(background) = self
            .installed
            .get(id)
            .and_then(|manifest| manifest.background.as_ref())
        else {
            return Vec::new();
        };
        background
            .service_worker
            .iter()
            .cloned()
            .chain(background.scripts.iter().cloned())
            .collect()
    }

    /// Returns the static ruleset IDs declared by an installed extension.
    #[must_use]
    pub fn static_ruleset_ids(&self, id: &str) -> Vec<String> {
        self.static_rules
            .get(id)
            .map(|rulesets| {
                let mut ids = rulesets.keys().cloned().collect::<Vec<_>>();
                ids.sort_unstable();
                ids
            })
            .unwrap_or_default()
    }

    /// Returns the currently enabled static ruleset IDs for an extension.
    #[must_use]
    pub fn enabled_ruleset_ids(&self, id: &str) -> Vec<String> {
        self.enabled_rulesets.get(id).cloned().unwrap_or_default()
    }

    /// Enables and disables manifest-declared static rulesets atomically.
    pub fn update_enabled_rulesets(
        &mut self,
        id: &str,
        enable: &[String],
        disable: &[String],
    ) -> Result<Vec<String>, ExtensionError> {
        self.require_permission(id, ExtensionPermission::DeclarativeNetRequest)?;
        if enable.iter().any(|ruleset| disable.contains(ruleset)) {
            return Err(ExtensionError::InvalidManifest(
                "a static ruleset cannot be enabled and disabled in one update".into(),
            ));
        }
        let known = self.static_ruleset_ids(id);
        if enable
            .iter()
            .chain(disable)
            .any(|ruleset| !known.contains(ruleset))
        {
            return Err(ExtensionError::Missing(
                "unknown static declarative ruleset".into(),
            ));
        }
        let mut enabled = self.enabled_rulesets.get(id).cloned().unwrap_or_default();
        enabled.retain(|ruleset| !disable.contains(ruleset));
        for ruleset in enable {
            if !enabled.contains(ruleset) {
                enabled.push(ruleset.clone());
            }
        }
        enabled.sort_unstable();
        self.enabled_rulesets.insert(id.to_owned(), enabled.clone());
        Ok(enabled)
    }

    fn set_enabled_rulesets(
        &mut self,
        id: &str,
        requested: &[String],
    ) -> Result<(), ExtensionError> {
        let known = self.static_ruleset_ids(id);
        if requested.iter().any(|ruleset| !known.contains(ruleset)) {
            return Err(ExtensionError::InvalidManifest(
                "extension state references an unknown static ruleset".into(),
            ));
        }
        let mut requested = requested.to_vec();
        requested.sort_unstable();
        requested.dedup();
        self.enabled_rulesets.insert(id.to_owned(), requested);
        Ok(())
    }

    #[must_use]
    pub fn resource_source(&self, id: &str, name: &str) -> Option<String> {
        self.resources.get(id)?.get(name).cloned()
    }

    #[must_use]
    pub fn resources_for(&self, id: &str) -> Vec<ExtensionResource> {
        let Some(resources) = self.resources.get(id) else {
            return Vec::new();
        };
        let binary_resources = self.binary_resources.get(id);
        let mut paths: Vec<_> = resources.keys().cloned().collect();
        if let Some(binary_resources) = binary_resources {
            paths.extend(
                binary_resources
                    .keys()
                    .filter(|path| !resources.contains_key(*path))
                    .cloned(),
            );
        }
        paths.sort_unstable();
        paths
            .into_iter()
            .map(|path| {
                let source = resources.get(&path).cloned().unwrap_or_default();
                let bytes = binary_resources
                    .and_then(|resources| resources.get(&path).cloned())
                    .unwrap_or_else(|| source.as_bytes().to_vec());
                let web_accessible = self.installed.get(id).is_some_and(|manifest| {
                    manifest.web_accessible_resources.iter().any(|entry| {
                        entry
                            .resources
                            .iter()
                            .any(|pattern| wildcard_matches(pattern, &path))
                    })
                });
                let web_accessible_matches = self
                    .installed
                    .get(id)
                    .into_iter()
                    .flat_map(|manifest| manifest.web_accessible_resources.iter())
                    .filter(|entry| {
                        entry
                            .resources
                            .iter()
                            .any(|pattern| wildcard_matches(pattern, &path))
                    })
                    .flat_map(|entry| entry.matches.iter().cloned())
                    .collect();
                ExtensionResource {
                    extension_id: id.to_owned(),
                    mime_type: extension_mime_type(&path).to_owned(),
                    source,
                    bytes,
                    path,
                    web_accessible,
                    web_accessible_matches,
                }
            })
            .collect()
    }

    #[must_use]
    pub fn action_popup_source(&self, id: &str) -> Option<String> {
        let popup = self
            .installed
            .get(id)?
            .action
            .as_ref()?
            .default_popup
            .as_ref()?;
        self.resources.get(id)?.get(popup).cloned()
    }

    #[must_use]
    pub fn action_popup_resource_path(&self, id: &str) -> Option<String> {
        self.installed
            .get(id)?
            .action
            .as_ref()?
            .default_popup
            .clone()
    }

    #[must_use]
    pub fn action_default_title(&self, id: &str) -> Option<String> {
        self.installed
            .get(id)
            .and_then(|manifest| manifest.action.as_ref()?.default_title.clone())
    }

    #[must_use]
    pub fn storage_snapshot(&self, id: &str) -> Option<HashMap<String, Value>> {
        self.storage.get(id).cloned()
    }

    pub fn action_set_badge_text(&mut self, id: &str, text: Option<String>) {
        self.action_states
            .entry(id.to_owned())
            .or_default()
            .badge_text = text;
    }

    pub fn action_set_badge_background_color(&mut self, id: &str, color: Option<String>) {
        self.action_states
            .entry(id.to_owned())
            .or_default()
            .badge_background_color = color;
    }

    pub fn action_set_badge_text_color(&mut self, id: &str, color: Option<String>) {
        self.action_states
            .entry(id.to_owned())
            .or_default()
            .badge_text_color = color;
    }

    pub fn action_set_icon(&mut self, id: &str, icon: Option<Value>) {
        self.action_states.entry(id.to_owned()).or_default().icon = icon;
    }

    pub fn action_set_title(&mut self, id: &str, title: Option<String>) {
        self.action_states.entry(id.to_owned()).or_default().title = title;
    }

    pub fn action_set_popup(&mut self, id: &str, popup: Option<String>) {
        self.action_states.entry(id.to_owned()).or_default().popup = popup;
    }

    pub fn action_set_enabled(&mut self, id: &str, enabled: bool) {
        self.action_states.entry(id.to_owned()).or_default().enabled = enabled;
    }

    pub fn set_dnr_action_options(
        &mut self,
        id: &str,
        display_action_count_as_badge_text: bool,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::DeclarativeNetRequest)?;
        self.action_states
            .entry(id.to_owned())
            .or_default()
            .dnr_action_count_as_badge = display_action_count_as_badge_text;
        Ok(())
    }

    pub fn record_dnr_match(&mut self, id: &str) {
        let count = self.dnr_action_counts.entry(id.to_owned()).or_default();
        *count = count.saturating_add(1);
    }

    #[must_use]
    pub fn action_get_badge_text(&self, id: &str) -> String {
        self.action_states
            .get(id)
            .and_then(|state| state.badge_text.clone())
            .or_else(|| {
                self.action_states
                    .get(id)
                    .is_some_and(|state| state.dnr_action_count_as_badge)
                    .then(|| {
                        self.dnr_action_counts
                            .get(id)
                            .copied()
                            .unwrap_or_default()
                            .to_string()
                    })
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn action_get_badge_background_color(&self, id: &str) -> Option<String> {
        self.action_states
            .get(id)
            .and_then(|state| state.badge_background_color.clone())
    }

    #[must_use]
    pub fn action_get_badge_text_color(&self, id: &str) -> String {
        self.action_states
            .get(id)
            .and_then(|state| state.badge_text_color.clone())
            .unwrap_or_else(|| "#ffffff".to_owned())
    }

    #[must_use]
    pub fn action_get_title(&self, id: &str) -> Option<String> {
        self.action_states
            .get(id)
            .and_then(|state| state.title.clone())
            .or_else(|| self.action_default_title(id))
    }

    #[must_use]
    pub fn action_get_popup(&self, id: &str) -> Option<String> {
        self.action_states
            .get(id)
            .and_then(|state| state.popup.clone())
            .or_else(|| self.action_popup_resource_path(id))
    }

    #[must_use]
    pub fn action_is_enabled(&self, id: &str) -> bool {
        self.action_states.get(id).is_none_or(|state| state.enabled)
    }

    pub fn trigger_action(
        &mut self,
        id: &str,
        tab: &ExtensionTabInfo,
    ) -> Result<(), ExtensionError> {
        let visible_tab = self.activate_action(id, tab)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: id.to_owned(),
            kind: ExtensionEventKind::ActionClicked { tab: visible_tab },
        });
        Ok(())
    }

    /// Return the extension's manifest-declared commands, sorted by name for
    /// deterministic `commands.getAll` output.
    #[must_use]
    pub fn commands(&self, id: &str) -> Vec<ExtensionCommand> {
        let mut commands = self
            .installed
            .get(id)
            .map(|manifest| {
                manifest
                    .commands
                    .iter()
                    .map(|(name, settings)| ExtensionCommand {
                        name: name.clone(),
                        description: settings.description.clone(),
                        suggested_key: settings.resolved_suggested_key(),
                    })
                    .collect::<Vec<ExtensionCommand>>()
            })
            .unwrap_or_default();
        commands.sort_by(|left, right| left.name.cmp(&right.name));
        commands
    }

    /// Queue a `commands.onCommand` event for a triggered keyboard command.
    pub fn trigger_command(&mut self, id: &str, command: &str) -> Result<(), ExtensionError> {
        if !self.is_enabled(id) {
            return Err(ExtensionError::PermissionDenied(format!(
                "extension {id} is disabled"
            )));
        }
        if !self.commands(id).iter().any(|entry| entry.name == command) {
            return Err(ExtensionError::PermissionDenied(format!(
                "command {command:?} is not declared in the extension manifest"
            )));
        }
        self.background_events.push_back(ExtensionEvent {
            extension_id: id.to_owned(),
            kind: ExtensionEventKind::Command {
                command: command.to_owned(),
            },
        });
        Ok(())
    }

    pub fn activate_action(
        &mut self,
        id: &str,
        tab: &ExtensionTabInfo,
    ) -> Result<ExtensionTabInfo, ExtensionError> {
        let manifest = self
            .installed
            .get(id)
            .ok_or_else(|| ExtensionError::Missing(id.to_owned()))?;
        if manifest.action.is_none() {
            return Err(ExtensionError::PermissionDenied(
                "extension has no action".into(),
            ));
        }
        if !self.is_granted(id, ExtensionPermission::Tabs)
            && !self.is_granted(id, ExtensionPermission::ActiveTab)
        {
            return Err(ExtensionError::PermissionDenied(
                "action clicks require tabs or activeTab permission".into(),
            ));
        }
        let mut visible_tab = tab.clone();
        if !self.is_granted(id, ExtensionPermission::ActiveTab)
            && !visible_tab
                .url
                .as_ref()
                .is_some_and(|url| self.is_host_granted(id, url))
        {
            visible_tab.url = None;
        }
        if self.is_granted(id, ExtensionPermission::ActiveTab) {
            self.active_tab_grants
                .entry(id.to_owned())
                .or_default()
                .insert(tab.id);
        }
        self.start_background(id)?;
        Ok(visible_tab)
    }

    pub fn dispatch_background_message(
        &mut self,
        id: &str,
        tab_id: Option<u64>,
        request_id: Option<String>,
        payload: Value,
        target_url: Option<&Url>,
    ) -> Result<(), ExtensionError> {
        self.validate_message(id, target_url)?;
        self.start_background(id)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: id.to_owned(),
            kind: ExtensionEventKind::RuntimeMessage {
                sender_extension_id: None,
                tab_id,
                request_id,
                payload,
            },
        });
        Ok(())
    }

    pub fn dispatch_external_message(
        &mut self,
        sender_id: &str,
        target_id: &str,
        payload: Value,
    ) -> Result<(), ExtensionError> {
        self.require_installed(sender_id)?;
        let target = self
            .installed
            .get(target_id)
            .ok_or_else(|| ExtensionError::Missing(target_id.to_owned()))?;
        if !target.externally_connectable_ids.is_empty()
            && !target
                .externally_connectable_ids
                .iter()
                .any(|id| id == sender_id || id == "*")
        {
            return Err(ExtensionError::PermissionDenied(format!(
                "extension {target_id} does not accept messages from {sender_id}"
            )));
        }
        self.start_background(target_id)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: target_id.to_owned(),
            kind: ExtensionEventKind::RuntimeMessage {
                sender_extension_id: Some(sender_id.to_owned()),
                tab_id: None,
                request_id: None,
                payload,
            },
        });
        Ok(())
    }

    fn validate_external_connection(
        &self,
        sender_id: &str,
        target_id: &str,
    ) -> Result<(), ExtensionError> {
        self.require_installed(sender_id)?;
        let target = self
            .installed
            .get(target_id)
            .ok_or_else(|| ExtensionError::Missing(target_id.to_owned()))?;
        if !target.externally_connectable_ids.is_empty()
            && !target
                .externally_connectable_ids
                .iter()
                .any(|id| id == sender_id || id == "*")
        {
            return Err(ExtensionError::PermissionDenied(format!(
                "extension {target_id} does not accept connections from {sender_id}"
            )));
        }
        Ok(())
    }

    pub fn dispatch_external_port_connect(
        &mut self,
        sender_id: &str,
        target_id: &str,
        port_id: String,
        name: String,
    ) -> Result<(), ExtensionError> {
        self.validate_external_connection(sender_id, target_id)?;
        self.start_background(target_id)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: target_id.to_owned(),
            kind: ExtensionEventKind::RuntimeExternalPortConnected {
                sender_extension_id: sender_id.to_owned(),
                port_id,
                name,
            },
        });
        Ok(())
    }

    pub fn dispatch_external_port_message(
        &mut self,
        sender_id: &str,
        target_id: &str,
        port_id: String,
        payload: Value,
    ) -> Result<(), ExtensionError> {
        self.require_installed(sender_id)?;
        self.require_installed(target_id)?;
        self.start_background(target_id)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: target_id.to_owned(),
            kind: ExtensionEventKind::RuntimeExternalPortMessage {
                sender_extension_id: sender_id.to_owned(),
                port_id,
                payload,
            },
        });
        Ok(())
    }

    pub fn dispatch_external_port_disconnect(
        &mut self,
        sender_id: &str,
        target_id: &str,
        port_id: String,
    ) -> Result<(), ExtensionError> {
        self.require_installed(sender_id)?;
        self.require_installed(target_id)?;
        self.start_background(target_id)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: target_id.to_owned(),
            kind: ExtensionEventKind::RuntimeExternalPortDisconnected {
                sender_extension_id: sender_id.to_owned(),
                port_id,
            },
        });
        Ok(())
    }

    pub fn dispatch_web_request(
        &mut self,
        id: &str,
        event: &'static str,
        request: Value,
        target_url: Option<&Url>,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::WebRequest)?;
        if let Some(url) = target_url {
            if !self.is_host_granted(id, url) {
                return Err(ExtensionError::PermissionDenied(format!(
                    "extension has no host permission for {url}"
                )));
            }
        }
        self.start_background(id)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: id.to_owned(),
            kind: ExtensionEventKind::WebRequest { request, event },
        });
        Ok(())
    }

    pub fn dispatch_dnr_rule_matched(
        &mut self,
        id: &str,
        details: Value,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::DeclarativeNetRequest)?;
        self.start_background(id)?;
        self.background_events.push_back(ExtensionEvent {
            extension_id: id.to_owned(),
            kind: ExtensionEventKind::RuleMatched { details },
        });
        Ok(())
    }

    #[must_use]
    pub fn matching_dnr_rules(&self, url: &Url, method: &str) -> Vec<(String, Value)> {
        let mut matched = Vec::new();
        for id in self.installed.keys() {
            if !self.is_enabled(id)
                || !self.is_granted(id, ExtensionPermission::DeclarativeNetRequest)
            {
                continue;
            }
            for rule in self.dnr_rules(id) {
                let Some(pattern) = declarative_block_pattern(&rule) else {
                    continue;
                };
                let Some((_, rest)) = pattern.split_once("://") else {
                    continue;
                };
                let Some((domain, _)) = rest.split_once('/') else {
                    continue;
                };
                if url.host_str() == Some(domain) {
                    matched.push((
                        id.clone(),
                        serde_json::json!({
                            "request": {
                                "url": url.to_string(),
                                "method": method,
                                "tabId": serde_json::Value::Null,
                            },
                            "rule": {
                                "ruleId": rule
                                    .get("id")
                                    .and_then(serde_json::Value::as_u64)
                                    .unwrap_or(0),
                            },
                        }),
                    ));
                }
            }
        }
        matched
    }

    #[must_use]
    pub fn web_request_extension_ids(&self) -> Vec<String> {
        self.installed
            .values()
            .filter(|manifest| {
                self.is_enabled(&manifest.id)
                    && (manifest
                        .permissions
                        .contains(&ExtensionPermission::WebRequest)
                        || manifest
                            .optional_permissions
                            .contains(&ExtensionPermission::WebRequest))
            })
            .map(|manifest| manifest.id.clone())
            .collect()
    }

    #[must_use]
    pub fn web_request_blocking_extension_ids(&self) -> Vec<String> {
        self.installed
            .values()
            .filter(|manifest| {
                self.is_enabled(&manifest.id)
                    && self.is_granted(&manifest.id, ExtensionPermission::WebRequestBlocking)
            })
            .map(|manifest| manifest.id.clone())
            .collect()
    }

    #[must_use]
    pub fn blocking_host_patterns(&self) -> Vec<String> {
        let mut patterns = self
            .installed
            .values()
            .filter(|manifest| {
                self.is_enabled(&manifest.id)
                    && self.is_granted(&manifest.id, ExtensionPermission::WebRequestBlocking)
            })
            .flat_map(|manifest| manifest.blocked_host_patterns.iter().cloned())
            .collect::<Vec<_>>();
        for id in self.installed.keys() {
            if !self.is_enabled(id)
                || !self.is_granted(id, ExtensionPermission::DeclarativeNetRequest)
            {
                continue;
            }
            for rule in self.dnr_rules(id) {
                if let Some(pattern) = declarative_block_pattern(&rule) {
                    patterns.push(pattern);
                }
            }
        }
        patterns
    }

    fn dnr_rules(&self, id: &str) -> Vec<Value> {
        let static_rules = self
            .enabled_rulesets
            .get(id)
            .into_iter()
            .flat_map(|enabled| enabled.iter())
            .filter_map(|ruleset| self.static_rules.get(id)?.get(ruleset))
            .flat_map(|rules| rules.iter().cloned());
        static_rules
            .chain(self.dynamic_rules(id))
            .chain(self.session_rules(id))
            .collect()
    }

    pub fn context_menu_create(
        &mut self,
        id: &str,
        properties: &Value,
    ) -> Result<Value, ExtensionError> {
        self.require_permission(id, ExtensionPermission::ContextMenus)?;
        let mut properties = properties.as_object().cloned().ok_or_else(|| {
            ExtensionError::InvalidManifest("contextMenus.create expects an object".into())
        })?;
        let menu_id = match properties.remove("id") {
            Some(value) => match value.as_str() {
                Some(id) => id.to_owned(),
                None => value.to_string(),
            },
            None => loop {
                let candidate = self.next_context_menu_id.to_string();
                self.next_context_menu_id = self.next_context_menu_id.saturating_add(1).max(1);
                let menus = self.context_menus.get(id);
                if !menus.is_some_and(|menus| menus.contains_key(&candidate)) {
                    break candidate;
                }
            },
        };
        if menu_id.is_empty() || menu_id.len() > 256 || menu_id.chars().any(char::is_control) {
            return Err(ExtensionError::InvalidManifest(
                "context menu id is invalid".into(),
            ));
        }
        if properties
            .get("title")
            .and_then(Value::as_str)
            .is_some_and(|title| title.len() > 4096 || title.chars().any(char::is_control))
        {
            return Err(ExtensionError::InvalidManifest(
                "context menu title is invalid".into(),
            ));
        }
        let menus = self.context_menus.entry(id.to_owned()).or_default();
        if menus.len() >= MAX_CONTEXT_MENU_ITEMS && !menus.contains_key(&menu_id) {
            return Err(ExtensionError::ResourceLimitExceeded(
                "extension context menu limit reached".into(),
            ));
        }
        if menus.contains_key(&menu_id) {
            return Err(ExtensionError::InvalidManifest(
                "context menu id already exists".into(),
            ));
        }
        properties.insert("id".into(), Value::String(menu_id.clone()));
        menus.insert(menu_id.clone(), Value::Object(properties));
        Ok(Value::String(menu_id))
    }

    pub fn context_menu_update(
        &mut self,
        id: &str,
        menu_id: &str,
        updates: &Value,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::ContextMenus)?;
        let updates = updates.as_object().ok_or_else(|| {
            ExtensionError::InvalidManifest("contextMenus.update expects an object".into())
        })?;
        let menu = self
            .context_menus
            .get_mut(id)
            .and_then(|menus| menus.get_mut(menu_id))
            .ok_or_else(|| ExtensionError::Missing(format!("context menu {menu_id}")))?;
        let menu = menu.as_object_mut().ok_or_else(|| {
            ExtensionError::InvalidManifest("stored context menu is not an object".into())
        })?;
        for (key, value) in updates {
            if key != "id" {
                menu.insert(key.clone(), value.clone());
            }
        }
        Ok(())
    }

    pub fn context_menu_remove(&mut self, id: &str, menu_id: &str) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::ContextMenus)?;
        let menus = self
            .context_menus
            .get_mut(id)
            .ok_or_else(|| ExtensionError::Missing(format!("context menu {menu_id}")))?;
        if menus.remove(menu_id).is_none() {
            return Err(ExtensionError::Missing(format!("context menu {menu_id}")));
        }
        Ok(())
    }

    pub fn context_menu_remove_all(&mut self, id: &str) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::ContextMenus)?;
        self.context_menus.remove(id);
        Ok(())
    }

    #[allow(clippy::double_must_use)]
    #[must_use]
    pub fn require_context_menus(&self, id: &str) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::ContextMenus)
    }

    #[must_use]
    pub fn context_menu_items(&self, id: &str) -> Vec<Value> {
        self.context_menus
            .get(id)
            .map(|menus| menus.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn schedule_alarm(
        &mut self,
        id: &str,
        name: &str,
        scheduled_time_ms: u64,
        period_ms: Option<u64>,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Alarms)?;
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(ExtensionError::InvalidManifest(
                "alarm name is invalid".into(),
            ));
        }
        if period_ms.is_some_and(|period| period == 0) {
            return Err(ExtensionError::InvalidManifest(
                "alarm period must be greater than zero".into(),
            ));
        }
        self.alarms
            .retain(|alarm| !(alarm.extension_id == id && alarm.name == name));
        self.alarms.push(ExtensionAlarm {
            extension_id: id.to_owned(),
            name: name.to_owned(),
            scheduled_time_ms,
            period_ms,
        });
        self.start_background(id)
    }

    pub fn clear_alarm(&mut self, id: &str, name: &str) -> Result<bool, ExtensionError> {
        self.require_permission(id, ExtensionPermission::Alarms)?;
        let before = self.alarms.len();
        self.alarms
            .retain(|alarm| !(alarm.extension_id == id && alarm.name == name));
        Ok(before != self.alarms.len())
    }

    pub fn clear_all_alarms(&mut self, id: &str) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Alarms)?;
        self.alarms.retain(|alarm| alarm.extension_id != id);
        Ok(())
    }

    pub fn get_alarm(
        &self,
        id: &str,
        name: &str,
    ) -> Result<Option<ExtensionAlarm>, ExtensionError> {
        self.require_permission(id, ExtensionPermission::Alarms)?;
        Ok(self
            .alarms
            .iter()
            .find(|alarm| alarm.extension_id == id && alarm.name == name)
            .cloned())
    }

    pub fn get_all_alarms(&self, id: &str) -> Result<Vec<ExtensionAlarm>, ExtensionError> {
        self.require_permission(id, ExtensionPermission::Alarms)?;
        Ok(self
            .alarms
            .iter()
            .filter(|alarm| alarm.extension_id == id)
            .cloned()
            .collect())
    }

    /// Replaces selected MV3 dynamic declarative rules and returns the stored
    /// rule set. Matching is applied at the renderer request boundary.
    pub fn update_dynamic_rules(
        &mut self,
        id: &str,
        remove_ids: &[u64],
        add_rules: &[Value],
    ) -> Result<Vec<Value>, ExtensionError> {
        self.update_declarative_rules(id, remove_ids, add_rules, false)
    }

    /// Replaces selected MV3 session declarative rules. Session rules are not
    /// persisted across a registry snapshot restore.
    pub fn update_session_rules(
        &mut self,
        id: &str,
        remove_ids: &[u64],
        add_rules: &[Value],
    ) -> Result<Vec<Value>, ExtensionError> {
        self.update_declarative_rules(id, remove_ids, add_rules, true)
    }

    #[must_use]
    pub fn dynamic_rules(&self, id: &str) -> Vec<Value> {
        self.dynamic_rules.get(id).cloned().unwrap_or_default()
    }

    #[must_use]
    pub fn session_rules(&self, id: &str) -> Vec<Value> {
        self.session_rules.get(id).cloned().unwrap_or_default()
    }

    fn update_declarative_rules(
        &mut self,
        id: &str,
        remove_ids: &[u64],
        add_rules: &[Value],
        session: bool,
    ) -> Result<Vec<Value>, ExtensionError> {
        self.require_permission(id, ExtensionPermission::DeclarativeNetRequest)?;
        for rule in add_rules {
            validate_declarative_rule(rule)?;
        }
        let current = if session {
            self.session_rules.get(id).cloned().unwrap_or_default()
        } else {
            self.dynamic_rules.get(id).cloned().unwrap_or_default()
        };
        let mut rules = current
            .into_iter()
            .filter(|rule| {
                !rule
                    .get("id")
                    .and_then(Value::as_u64)
                    .is_some_and(|rule_id| remove_ids.contains(&rule_id))
            })
            .collect::<Vec<_>>();
        let existing_ids = rules
            .iter()
            .filter_map(|rule| rule.get("id").and_then(Value::as_u64))
            .collect::<HashSet<_>>();
        let mut added_ids = HashSet::new();
        for rule in add_rules {
            let rule_id = rule.get("id").and_then(Value::as_u64).ok_or_else(|| {
                ExtensionError::InvalidManifest("declarative rule requires numeric id".into())
            })?;
            if existing_ids.contains(&rule_id) || !added_ids.insert(rule_id) {
                return Err(ExtensionError::InvalidManifest(format!(
                    "declarative rule id {rule_id} is already present"
                )));
            }
            rules.push(rule.clone());
        }
        if rules.len() > MAX_DECLARATIVE_RULE_COUNT {
            return Err(ExtensionError::ResourceLimitExceeded(
                "declarative rule quota exceeded".into(),
            ));
        }
        if session {
            self.session_rules.insert(id.to_owned(), rules.clone());
        } else {
            self.dynamic_rules.insert(id.to_owned(), rules.clone());
        }
        Ok(rules.clone())
    }

    fn replace_declarative_rules(
        &mut self,
        id: &str,
        rules: Vec<Value>,
        session: bool,
    ) -> Result<(), ExtensionError> {
        if rules.len() > MAX_DECLARATIVE_RULE_COUNT {
            return Err(ExtensionError::ResourceLimitExceeded(
                "declarative rule quota exceeded".into(),
            ));
        }
        let mut ids = HashSet::new();
        for rule in &rules {
            validate_declarative_rule(rule)?;
            let rule_id = rule.get("id").and_then(Value::as_u64).ok_or_else(|| {
                ExtensionError::InvalidManifest("declarative rule requires numeric id".into())
            })?;
            if !ids.insert(rule_id) {
                return Err(ExtensionError::InvalidManifest(
                    "declarative rule ids must be unique".into(),
                ));
            }
        }
        if session {
            self.session_rules.insert(id.to_owned(), rules);
        } else {
            self.dynamic_rules.insert(id.to_owned(), rules);
        }
        Ok(())
    }

    pub fn poll_due_alarms(&mut self, now_ms: u64) -> Vec<ExtensionEvent> {
        let mut due = Vec::new();
        for alarm in &mut self.alarms {
            if alarm.scheduled_time_ms > now_ms {
                continue;
            }
            due.push(ExtensionEvent {
                extension_id: alarm.extension_id.clone(),
                kind: ExtensionEventKind::Alarm {
                    name: alarm.name.clone(),
                    scheduled_time_ms: alarm.scheduled_time_ms,
                },
            });
            if let Some(period_ms) = alarm.period_ms {
                let elapsed = now_ms.saturating_sub(alarm.scheduled_time_ms);
                let periods = elapsed / period_ms + 1;
                alarm.scheduled_time_ms = alarm
                    .scheduled_time_ms
                    .saturating_add(periods.saturating_mul(period_ms));
            } else {
                alarm.scheduled_time_ms = u64::MAX;
            }
        }
        self.alarms
            .retain(|alarm| alarm.scheduled_time_ms != u64::MAX);
        due
    }

    pub fn drain_background_events(&mut self, id: &str) -> Vec<ExtensionEvent> {
        let mut events = Vec::new();
        let mut retained = VecDeque::with_capacity(self.background_events.len());
        while let Some(event) = self.background_events.pop_front() {
            if event.extension_id == id {
                events.push(event);
            } else {
                retained.push_back(event);
            }
        }
        self.background_events = retained;
        events
    }

    fn start_background(&mut self, id: &str) -> Result<(), ExtensionError> {
        let Some(background) = self.backgrounds.get_mut(id) else {
            return Err(ExtensionError::PermissionDenied(
                "extension has no background context".into(),
            ));
        };
        if !background.running {
            background.running = true;
            self.background_events.push_back(ExtensionEvent {
                extension_id: id.to_owned(),
                kind: ExtensionEventKind::Startup,
            });
        }
        Ok(())
    }

    pub fn grant(
        &mut self,
        id: &str,
        permission: ExtensionPermission,
    ) -> Result<(), ExtensionError> {
        let manifest = self
            .installed
            .get(id)
            .ok_or_else(|| ExtensionError::Missing(id.to_owned()))?;
        if !manifest.permissions.contains(&permission)
            && !manifest.optional_permissions.contains(&permission)
        {
            return Err(ExtensionError::InvalidManifest(format!(
                "extension does not request {permission:?}"
            )));
        }
        let granted = self.granted.entry(id.to_owned()).or_default();
        if !granted.contains(&permission) {
            granted.push(permission);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        id: &str,
        permission: ExtensionPermission,
    ) -> Result<(), ExtensionError> {
        if !self.installed.contains_key(id) {
            return Err(ExtensionError::Missing(id.to_owned()));
        }
        if let Some(granted) = self.granted.get_mut(id) {
            granted.retain(|current| *current != permission);
        }
        Ok(())
    }

    pub fn grant_host_permission(&mut self, id: &str, pattern: &str) -> Result<(), ExtensionError> {
        let manifest = self
            .installed
            .get(id)
            .ok_or_else(|| ExtensionError::Missing(id.to_owned()))?;
        if !manifest
            .host_permissions
            .iter()
            .any(|requested| requested == pattern)
            && !manifest
                .optional_host_permissions
                .iter()
                .any(|requested| requested == pattern)
        {
            return Err(ExtensionError::PermissionDenied(format!(
                "extension did not request host permission {pattern:?}"
            )));
        }
        let granted = self.granted_hosts.entry(id.to_owned()).or_default();
        if !granted
            .iter()
            .any(|granted_pattern| granted_pattern == pattern)
        {
            granted.push(pattern.to_owned());
        }
        Ok(())
    }

    pub fn revoke_host_permission(
        &mut self,
        id: &str,
        pattern: &str,
    ) -> Result<(), ExtensionError> {
        if !self.installed.contains_key(id) {
            return Err(ExtensionError::Missing(id.to_owned()));
        }
        if let Some(granted) = self.granted_hosts.get_mut(id) {
            granted.retain(|granted_pattern| granted_pattern != pattern);
        }
        Ok(())
    }

    pub fn clear_active_tab_grant(&mut self, tab_id: u64) {
        for tabs in self.active_tab_grants.values_mut() {
            tabs.remove(&tab_id);
        }
    }

    #[must_use]
    pub fn is_active_tab_granted(&self, id: &str, tab_id: u64) -> bool {
        self.active_tab_grants
            .get(id)
            .is_some_and(|tabs| tabs.contains(&tab_id))
    }

    #[must_use]
    pub fn granted_permissions(&self, id: &str) -> Vec<ExtensionPermission> {
        self.granted.get(id).cloned().unwrap_or_default()
    }

    #[must_use]
    pub fn granted_host_permissions(&self, id: &str) -> Vec<String> {
        self.granted_hosts.get(id).cloned().unwrap_or_default()
    }

    #[must_use]
    pub fn is_granted(&self, id: &str, permission: ExtensionPermission) -> bool {
        self.granted
            .get(id)
            .is_some_and(|permissions| permissions.contains(&permission))
    }

    #[must_use]
    pub fn is_host_granted(&self, id: &str, url: &Url) -> bool {
        self.granted_hosts
            .get(id)
            .is_some_and(|patterns| patterns.iter().any(|pattern| pattern_matches(pattern, url)))
    }

    #[must_use]
    pub fn is_host_permission_granted(&self, id: &str, pattern: &str) -> bool {
        self.granted_hosts
            .get(id)
            .is_some_and(|patterns| patterns.iter().any(|granted| granted == pattern))
    }

    pub fn storage_set(&mut self, id: &str, key: &str, value: Value) -> Result<(), ExtensionError> {
        self.storage_set_area(id, ExtensionStorageArea::Local, key, value)
    }

    pub fn storage_set_area(
        &mut self,
        id: &str,
        area: ExtensionStorageArea,
        key: &str,
        value: Value,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Storage)?;
        let updates = HashMap::from([(key.to_owned(), value)]);
        self.replace_storage_values_area(id, area, &updates)
    }

    pub fn storage_get(&self, id: &str, key: &str) -> Result<Option<Value>, ExtensionError> {
        self.storage_get_area(id, ExtensionStorageArea::Local, key)
    }

    pub fn storage_get_area(
        &self,
        id: &str,
        area: ExtensionStorageArea,
        key: &str,
    ) -> Result<Option<Value>, ExtensionError> {
        self.require_permission(id, ExtensionPermission::Storage)?;
        Ok(self
            .storage_area_map(area)
            .get(id)
            .and_then(|values| values.get(key).cloned()))
    }

    pub fn storage_get_all(&self, id: &str) -> Result<HashMap<String, Value>, ExtensionError> {
        self.storage_get_area_all(id, ExtensionStorageArea::Local)
    }

    pub fn storage_get_area_all(
        &self,
        id: &str,
        area: ExtensionStorageArea,
    ) -> Result<HashMap<String, Value>, ExtensionError> {
        self.require_permission(id, ExtensionPermission::Storage)?;
        Ok(self
            .storage_area_map(area)
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    pub fn storage_remove(&mut self, id: &str, key: &str) -> Result<(), ExtensionError> {
        self.storage_remove_area(id, ExtensionStorageArea::Local, key)
    }

    pub fn storage_remove_area(
        &mut self,
        id: &str,
        area: ExtensionStorageArea,
        key: &str,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Storage)?;
        if let Some(values) = self.storage_area_map_mut(area).get_mut(id) {
            values.remove(key);
        }
        Ok(())
    }

    pub fn storage_clear(&mut self, id: &str) -> Result<(), ExtensionError> {
        self.storage_clear_area(id, ExtensionStorageArea::Local)
    }

    pub fn storage_clear_area(
        &mut self,
        id: &str,
        area: ExtensionStorageArea,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Storage)?;
        if let Some(values) = self.storage_area_map_mut(area).get_mut(id) {
            values.clear();
        }
        Ok(())
    }

    /// All three storage areas for one extension, used to seed renderer shims.
    #[must_use]
    pub fn storage_areas_snapshot(&self, id: &str) -> Option<ExtensionStorage> {
        Some(ExtensionStorage {
            local: self.storage.get(id).cloned().unwrap_or_default(),
            sync: self.storage_sync.get(id).cloned().unwrap_or_default(),
            session: self.storage_session.get(id).cloned().unwrap_or_default(),
        })
    }

    fn storage_area_map(
        &self,
        area: ExtensionStorageArea,
    ) -> &HashMap<String, HashMap<String, Value>> {
        match area {
            ExtensionStorageArea::Local => &self.storage,
            ExtensionStorageArea::Sync => &self.storage_sync,
            ExtensionStorageArea::Session => &self.storage_session,
        }
    }

    fn storage_area_map_mut(
        &mut self,
        area: ExtensionStorageArea,
    ) -> &mut HashMap<String, HashMap<String, Value>> {
        match area {
            ExtensionStorageArea::Local => &mut self.storage,
            ExtensionStorageArea::Sync => &mut self.storage_sync,
            ExtensionStorageArea::Session => &mut self.storage_session,
        }
    }

    pub fn query_tabs(
        &self,
        id: &str,
        tabs: &[ExtensionTabInfo],
    ) -> Result<Vec<ExtensionTabInfo>, ExtensionError> {
        self.require_permission(id, ExtensionPermission::Tabs)?;
        Ok(tabs
            .iter()
            .cloned()
            .map(|mut tab| {
                if !tab
                    .url
                    .as_ref()
                    .is_some_and(|url| self.is_host_granted(id, url))
                {
                    tab.url = None;
                }
                tab
            })
            .collect())
    }

    pub fn send_message(
        &mut self,
        id: &str,
        tab_id: Option<u64>,
        payload: Value,
        target_url: Option<&Url>,
    ) -> Result<(), ExtensionError> {
        self.validate_message(id, target_url)?;
        self.enqueue_message(id, tab_id, payload)
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate_api_request(
        &self,
        id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<(), ExtensionError> {
        self.require_installed(id)?;
        if matches!(
            request.method.as_str(),
            "runtime.getURL"
                | "runtime.getManifest"
                | "runtime.getPlatformInfo"
                | "runtime.getBrowserInfo"
                | "runtime.connect"
                | "runtime.getContexts"
                | "runtime.openOptionsPage"
                | "i18n.getUILanguage"
                | "i18n.getMessage"
                | "i18n.getAcceptLanguages"
                | "i18n.detectLanguage"
                | "commands.getAll"
                | "permissions.contains"
                | "permissions.request"
                | "permissions.remove"
                | "permissions.getAll"
                | "runtime.setUninstallURL"
        ) {
            if request.method == "permissions.contains" {
                return self.require_permission(id, ExtensionPermission::Permissions);
            }
            return Ok(());
        }
        let permission = match request.method.as_str() {
            "tabs.query"
            | "tabs.get"
            | "tabs.create"
            | "tabs.update"
            | "tabs.remove"
            | "tabs.reload"
            | "tabs.duplicate"
            | "tabs.discard"
            | "tabs.goBack"
            | "tabs.goForward"
            | "tabs.getCurrent"
            | "tabs.sendMessage"
            | "tabs.captureVisibleTab" => ExtensionPermission::Tabs,
            "tabs.group" | "tabs.ungroup" | "tabGroups.get" | "tabGroups.query"
            | "tabGroups.update" => ExtensionPermission::TabGroups,
            "history.search"
            | "history.getVisits"
            | "history.addUrl"
            | "history.deleteUrl"
            | "history.deleteRange"
            | "history.deleteAll" => ExtensionPermission::History,
            "bookmarks.search"
            | "bookmarks.get"
            | "bookmarks.getChildren"
            | "bookmarks.getTree"
            | "bookmarks.getSubTree"
            | "bookmarks.create"
            | "bookmarks.move"
            | "bookmarks.update"
            | "bookmarks.remove"
            | "bookmarks.removeTree" => ExtensionPermission::Bookmarks,
            "downloads.search" | "downloads.list" | "downloads.download" | "downloads.pause"
            | "downloads.resume" | "downloads.cancel" | "downloads.remove" | "downloads.erase"
            | "downloads.open" | "downloads.show" => ExtensionPermission::Downloads,
            "alarms.create" | "alarms.clear" | "alarms.clearAll" | "alarms.get"
            | "alarms.getAll" => ExtensionPermission::Alarms,
            "notifications.create" | "notifications.clear" | "notifications.getAll" => {
                ExtensionPermission::Notifications
            }
            "runtime.sendNativeMessage" => ExtensionPermission::NativeMessaging,
            "contextMenus.create"
            | "contextMenus.remove"
            | "contextMenus.removeAll"
            | "contextMenus.update" => ExtensionPermission::ContextMenus,
            "offscreen.createDocument" | "offscreen.closeDocument" | "offscreen.hasDocument" => {
                ExtensionPermission::Offscreen
            }
            "management.getAll"
            | "management.get"
            | "management.getPermissionWarningsById"
            | "management.setEnabled"
            | "management.getSelf"
            | "management.uninstallSelf" => ExtensionPermission::Management,
            "windows.get" | "windows.getCurrent" | "windows.getAll" | "windows.create"
            | "windows.update" | "windows.remove" => ExtensionPermission::Windows,
            "webNavigation.getAllFrames" | "webNavigation.getFrame" => {
                ExtensionPermission::WebNavigation
            }
            "declarativeNetRequest.updateDynamicRules"
            | "declarativeNetRequest.getDynamicRules"
            | "declarativeNetRequest.getSessionRules"
            | "declarativeNetRequest.updateSessionRules"
            | "declarativeNetRequest.isSessionEnabled"
            | "declarativeNetRequest.getEnabledRulesets"
            | "declarativeNetRequest.updateEnabledRulesets"
            | "declarativeNetRequest.isRegexSupported"
            | "declarativeNetRequest.setExtensionActionOptions" => {
                ExtensionPermission::DeclarativeNetRequest
            }
            "cookies.get" | "cookies.getAll" | "cookies.set" | "cookies.remove" => {
                ExtensionPermission::Cookies
            }
            "identity.getAuthToken" | "identity.launchWebAuthFlow" => ExtensionPermission::Identity,
            "webRequest.resolveBlocking" | "webRequest.handlerBehaviorChanged" => {
                ExtensionPermission::WebRequest
            }
            "scripting.executeScript"
            | "scripting.registerContentScripts"
            | "scripting.unregisterContentScripts"
            | "scripting.updateContentScripts"
            | "scripting.getRegisteredContentScripts"
            | "scripting.insertCSS"
            | "scripting.removeCSS" => ExtensionPermission::Scripting,
            method if method.starts_with("action.") => {
                return Ok(());
            }
            method => {
                return Err(ExtensionError::PermissionDenied(format!(
                    "unsupported extension API {method:?}"
                )));
            }
        };
        self.require_permission(id, permission)
    }

    pub fn validate_scripting_target(
        &self,
        id: &str,
        tab_id: u64,
        target_url: Option<&Url>,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Scripting)?;
        let active_tab = self
            .active_tab_grants
            .get(id)
            .is_some_and(|tabs| tabs.contains(&tab_id));
        if !active_tab && !target_url.is_some_and(|url| self.is_host_granted(id, url)) {
            return Err(ExtensionError::PermissionDenied(
                "scripting target has no host permission".into(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn parse_registered_content_script(
        &self,
        extension_id: &str,
        value: &Value,
    ) -> Result<ExtensionRegisteredContentScript, ExtensionError> {
        let entry = value.as_object().ok_or_else(|| {
            ExtensionError::InvalidManifest("registered content scripts must be objects".into())
        })?;
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 128)
            .ok_or_else(|| {
                ExtensionError::InvalidManifest(
                    "registered content script requires a non-empty id of at most 128 chars".into(),
                )
            })?
            .to_owned();
        let matches = entry
            .get("matches")
            .and_then(Value::as_array)
            .filter(|matches| !matches.is_empty())
            .ok_or_else(|| {
                ExtensionError::InvalidManifest(
                    "registered content script requires at least one match pattern".into(),
                )
            })?
            .iter()
            .map(|pattern| {
                let pattern = pattern.as_str().ok_or_else(|| {
                    ExtensionError::InvalidManifest(
                        "registered content script match patterns must be strings".into(),
                    )
                })?;
                if !is_match_pattern(pattern) {
                    return Err(ExtensionError::InvalidManifest(format!(
                        "registered content script has invalid match pattern {pattern:?}"
                    )));
                }
                Ok(pattern.to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let files = |key: &str| -> Result<Vec<String>, ExtensionError> {
            let Some(list) = entry.get(key).and_then(Value::as_array) else {
                return Ok(Vec::new());
            };
            let mut files = Vec::new();
            for file in list {
                let name = file.as_str().ok_or_else(|| {
                    ExtensionError::InvalidManifest(format!(
                        "registered content script {key} entries must be strings"
                    ))
                })?;
                if !self
                    .resources
                    .get(extension_id)
                    .is_some_and(|map| map.contains_key(name))
                {
                    return Err(ExtensionError::Missing(format!(
                        "registered content script references missing resource {name:?}"
                    )));
                }
                files.push(name.to_owned());
            }
            Ok(files)
        };
        let js = files("js")?;
        let css = files("css")?;
        if js.is_empty() && css.is_empty() {
            return Err(ExtensionError::InvalidManifest(
                "registered content script requires js or css files".into(),
            ));
        }
        let world = match entry
            .get("world")
            .and_then(Value::as_str)
            .unwrap_or("ISOLATED")
        {
            "ISOLATED" => ExtensionScriptWorld::Isolated,
            "MAIN" => ExtensionScriptWorld::Main,
            other => {
                return Err(ExtensionError::InvalidManifest(format!(
                    "registered content script has invalid world {other:?}"
                )));
            }
        };
        let run_at = match entry
            .get("runAt")
            .and_then(Value::as_str)
            .unwrap_or("document_idle")
        {
            "document_start" | "document_end" | "document_idle" => entry
                .get("runAt")
                .and_then(Value::as_str)
                .unwrap_or("document_idle")
                .to_owned(),
            other => {
                return Err(ExtensionError::InvalidManifest(format!(
                    "registered content script has invalid runAt {other:?}"
                )));
            }
        };
        let exclude_matches = entry
            .get("excludeMatches")
            .and_then(Value::as_array)
            .map(|patterns| {
                patterns
                    .iter()
                    .map(|pattern| {
                        let pattern = pattern.as_str().ok_or_else(|| {
                            ExtensionError::InvalidManifest(
                                "registered content script excludeMatches must be strings".into(),
                            )
                        })?;
                        if !is_match_pattern(pattern) {
                            return Err(ExtensionError::InvalidManifest(format!(
                                "registered content script has invalid excludeMatches pattern {pattern:?}"
                            )));
                        }
                        Ok(pattern.to_owned())
                    })
                    .collect::<Result<Vec<_>, ExtensionError>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(ExtensionRegisteredContentScript {
            id,
            matches,
            js,
            css,
            all_frames: entry
                .get("allFrames")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            run_at,
            world,
            exclude_matches,
        })
    }

    pub fn register_content_scripts(
        &mut self,
        id: &str,
        scripts: &[Value],
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Scripting)?;
        let existing = self
            .registered_content_scripts
            .get(id)
            .cloned()
            .unwrap_or_default();
        let mut parsed = Vec::new();
        for value in scripts {
            let script = self.parse_registered_content_script(id, value)?;
            if existing
                .iter()
                .chain(parsed.iter())
                .any(|registered: &ExtensionRegisteredContentScript| registered.id == script.id)
            {
                return Err(ExtensionError::InvalidManifest(format!(
                    "registered content script id {:?} is already registered",
                    script.id
                )));
            }
            parsed.push(script);
        }
        let mut registered = existing;
        registered.extend(parsed);
        self.registered_content_scripts
            .insert(id.to_owned(), registered);
        Ok(())
    }

    pub fn unregister_content_scripts(
        &mut self,
        id: &str,
        ids: Option<&[String]>,
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Scripting)?;
        let Some(mut registered) = self.registered_content_scripts.remove(id) else {
            return Ok(());
        };
        if let Some(ids) = ids {
            let removed = |script: &ExtensionRegisteredContentScript| {
                !ids.iter().any(|target| target == &script.id)
            };
            registered.retain(removed);
        } else {
            registered.clear();
        }
        self.registered_content_scripts
            .insert(id.to_owned(), registered);
        Ok(())
    }

    pub fn update_content_scripts(
        &mut self,
        id: &str,
        scripts: &[Value],
    ) -> Result<(), ExtensionError> {
        self.require_permission(id, ExtensionPermission::Scripting)?;
        let mut registered = self
            .registered_content_scripts
            .get(id)
            .cloned()
            .unwrap_or_default();
        for value in scripts {
            let script = self.parse_registered_content_script(id, value)?;
            let position = registered
                .iter()
                .position(|existing| existing.id == script.id)
                .ok_or_else(|| {
                    ExtensionError::InvalidManifest(format!(
                        "registered content script id {:?} is not registered",
                        script.id
                    ))
                })?;
            registered[position] = script;
        }
        self.registered_content_scripts
            .insert(id.to_owned(), registered);
        Ok(())
    }

    #[must_use]
    pub fn registered_content_scripts(&self, id: &str) -> Vec<ExtensionRegisteredContentScript> {
        self.registered_content_scripts
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn receive_background_message(
        &mut self,
        id: &str,
        payload: Value,
    ) -> Result<(), ExtensionError> {
        self.require_installed(id)?;
        if self.apply_storage_message(id, &payload)? {
            return Ok(());
        }
        self.enqueue_message(id, None, payload)
    }

    pub fn validate_background_page_message(
        &self,
        id: &str,
        target_url: Option<&Url>,
    ) -> Result<(), ExtensionError> {
        self.validate_message(id, target_url)
    }

    pub fn receive_page_message(
        &mut self,
        id: &str,
        tab_id: Option<u64>,
        payload: Value,
        target_url: Option<&Url>,
    ) -> Result<(), ExtensionError> {
        self.validate_message(id, target_url)?;
        if self.apply_storage_message(id, &payload)? {
            return Ok(());
        }
        self.enqueue_message(id, tab_id, payload)
    }

    fn validate_message(&self, id: &str, target_url: Option<&Url>) -> Result<(), ExtensionError> {
        self.require_installed(id)?;
        let has_message_access = self.is_granted(id, ExtensionPermission::Tabs)
            || self.is_granted(id, ExtensionPermission::ReadPage)
            || target_url.is_some_and(|url| self.is_host_granted(id, url));
        if !has_message_access {
            return Err(ExtensionError::PermissionDenied(
                "runtime messaging requires tabs or page access".into(),
            ));
        }
        if let Some(url) = target_url {
            if !self.is_host_granted(id, url) {
                return Err(ExtensionError::PermissionDenied(format!(
                    "extension has no host permission for {url}"
                )));
            }
        }
        Ok(())
    }

    fn enqueue_message(
        &mut self,
        id: &str,
        tab_id: Option<u64>,
        payload: Value,
    ) -> Result<(), ExtensionError> {
        if self.messages.len() >= MAX_EXTENSION_MESSAGE_COUNT {
            return Err(ExtensionError::ResourceLimitExceeded(
                "extension message queue is full".into(),
            ));
        }
        let encoded = serde_json::to_vec(&payload)
            .map_err(|error| ExtensionError::InvalidManifest(error.to_string()))?;
        if encoded.len() > MAX_EXTENSION_VALUE_BYTES {
            return Err(ExtensionError::ResourceLimitExceeded(format!(
                "extension message exceeds {MAX_EXTENSION_VALUE_BYTES} bytes"
            )));
        }
        self.messages.push_back(ExtensionMessage {
            extension_id: id.to_owned(),
            tab_id,
            payload,
        });
        Ok(())
    }

    fn replace_storage_values<'a, I>(&mut self, id: &str, updates: I) -> Result<(), ExtensionError>
    where
        I: IntoIterator<Item = (&'a String, &'a Value)>,
    {
        self.replace_storage_values_area(id, ExtensionStorageArea::Local, updates)
    }

    fn replace_storage_values_area<'a, I>(
        &mut self,
        id: &str,
        area: ExtensionStorageArea,
        updates: I,
    ) -> Result<(), ExtensionError>
    where
        I: IntoIterator<Item = (&'a String, &'a Value)>,
    {
        let mut values = self
            .storage_area_map_mut(area)
            .get(id)
            .cloned()
            .unwrap_or_default();
        for (key, value) in updates {
            validate_storage_value(&values, key, value)?;
            values.insert(key.clone(), value.clone());
        }
        self.storage_area_map_mut(area)
            .insert(id.to_owned(), values);
        Ok(())
    }

    pub fn apply_storage_message(
        &mut self,
        id: &str,
        payload: &Value,
    ) -> Result<bool, ExtensionError> {
        let Some(object) = payload.as_object() else {
            return Ok(false);
        };
        let area = object
            .get("__nomad_storage_area")
            .and_then(Value::as_str)
            .and_then(ExtensionStorageArea::from_str)
            .unwrap_or(ExtensionStorageArea::Local);
        if let Some(values) = object.get("__nomad_storage_set").and_then(Value::as_object) {
            self.require_permission(id, ExtensionPermission::Storage)?;
            self.replace_storage_values_area(id, area, values)?;
            return Ok(true);
        }
        if let Some(keys) = object.get("__nomad_storage_remove") {
            let keys = keys.as_array().ok_or_else(|| {
                ExtensionError::InvalidManifest(
                    "extension storage remove payload must be an array".into(),
                )
            })?;
            self.require_permission(id, ExtensionPermission::Storage)?;
            for key in keys {
                let key = key.as_str().ok_or_else(|| {
                    ExtensionError::InvalidManifest(
                        "extension storage remove keys must be strings".into(),
                    )
                })?;
                self.storage_remove_area(id, area, key)?;
            }
            return Ok(true);
        }
        if object.get("__nomad_storage_clear").and_then(Value::as_bool) == Some(true) {
            self.storage_clear_area(id, area)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn drain_messages(&mut self, id: &str) -> Vec<ExtensionMessage> {
        let mut messages = Vec::new();
        let mut retained = VecDeque::with_capacity(self.messages.len());
        while let Some(message) = self.messages.pop_front() {
            if message.extension_id == id {
                messages.push(message);
            } else {
                retained.push_back(message);
            }
        }
        self.messages = retained;
        messages
    }

    fn require_installed(&self, id: &str) -> Result<(), ExtensionError> {
        if self.installed.contains_key(id) {
            Ok(())
        } else {
            Err(ExtensionError::Missing(id.to_owned()))
        }
    }

    fn require_permission(
        &self,
        id: &str,
        permission: ExtensionPermission,
    ) -> Result<(), ExtensionError> {
        self.require_installed(id)?;
        if self.is_granted(id, permission) {
            Ok(())
        } else {
            Err(ExtensionError::PermissionDenied(format!(
                "extension lacks {permission:?} permission"
            )))
        }
    }

    /// Returns content scripts that may execute for `url`.
    ///
    /// Injection is denied unless the user granted both page read and page
    /// modification capabilities. Host permissions and manifest match
    /// patterns are checked independently.
    #[must_use]
    pub fn scripts_for_url(&self, url: &Url) -> Vec<ExtensionInjection> {
        self.scripts_for_url_with_tab(url, None)
    }

    #[must_use]
    pub fn scripts_for_tab(&self, tab: &ExtensionTabInfo) -> Vec<ExtensionInjection> {
        let Some(url) = tab.url.as_ref() else {
            return Vec::new();
        };
        self.scripts_for_url_with_tab(url, Some(tab))
    }

    #[allow(clippy::too_many_lines)]
    fn scripts_for_url_with_tab(
        &self,
        url: &Url,
        tab: Option<&ExtensionTabInfo>,
    ) -> Vec<ExtensionInjection> {
        self.installed
            .values()
            .filter(|manifest| {
                self.is_enabled(&manifest.id) && {
                    let explicit_page_access = self
                        .is_granted(&manifest.id, ExtensionPermission::ReadPage)
                        && self.is_granted(&manifest.id, ExtensionPermission::ModifyPage);
                    let legacy_content_script_access = manifest.manifest_version == 2;
                    let active_tab_access = tab.is_some_and(|tab| {
                        self.active_tab_grants
                            .get(&manifest.id)
                            .is_some_and(|tabs| tabs.contains(&tab.id))
                    });
                    let declared_content_script_access =
                        !manifest.content_scripts_require_explicit_page_permissions;
                    (explicit_page_access
                        || declared_content_script_access
                        || legacy_content_script_access
                        || active_tab_access)
                        && !manifest.content_scripts.is_empty()
                }
            })
            .flat_map(|manifest| {
                manifest
                    .content_scripts
                    .iter()
                    .filter(|script| {
                        script
                            .matches
                            .iter()
                            .any(|pattern| pattern_matches(pattern, url))
                            && (self.is_host_granted(&manifest.id, url)
                                || tab.is_some_and(|tab| {
                                    self.active_tab_grants
                                        .get(&manifest.id)
                                        .is_some_and(|tabs| tabs.contains(&tab.id))
                                }))
                    })
                    .filter_map(|script| {
                        let resources = self.resources.get(&manifest.id);
                        let source = script_sources(script, resources).unwrap_or_default();
                        let style = style_sources(script, resources);
                        if source.trim().is_empty() && style.is_none() {
                            return None;
                        }
                        Some(ExtensionInjection {
                            extension_id: manifest.id.clone(),
                            manifest: manifest.clone(),
                            script: source,
                            style,
                            matches: script.matches.clone(),
                            storage: self
                                .is_granted(&manifest.id, ExtensionPermission::Storage)
                                .then(|| self.storage_areas_snapshot(&manifest.id))
                                .flatten(),
                            tab: self
                                .is_granted(&manifest.id, ExtensionPermission::Tabs)
                                .then(|| tab.cloned())
                                .flatten(),
                            world: script.world,
                        })
                    })
            })
            .chain(
                self.installed
                    .values()
                    .filter(|manifest| {
                        self.is_enabled(&manifest.id)
                            && self
                                .registered_content_scripts
                                .get(&manifest.id)
                                .is_some_and(|scripts| !scripts.is_empty())
                    })
                    .flat_map(|manifest| {
                        let Some(registered) = self.registered_content_scripts.get(&manifest.id)
                        else {
                            return Vec::new();
                        };
                        let resources = self.resources.get(&manifest.id);
                        registered
                            .iter()
                            .filter(|script| {
                                script
                                    .matches
                                    .iter()
                                    .any(|pattern| pattern_matches(pattern, url))
                                    && !script
                                        .exclude_matches
                                        .iter()
                                        .any(|pattern| pattern_matches(pattern, url))
                                    && (self.is_host_granted(&manifest.id, url)
                                        || tab.is_some_and(|tab| {
                                            self.active_tab_grants
                                                .get(&manifest.id)
                                                .is_some_and(|tabs| tabs.contains(&tab.id))
                                        }))
                            })
                            .filter_map(|script| {
                                let source = script
                                    .js
                                    .iter()
                                    .map(|file| resources.and_then(|map| map.get(file)).cloned())
                                    .collect::<Option<Vec<_>>>()
                                    .map(|sources| {
                                        sources.join(
                                            "
",
                                        )
                                    })
                                    .unwrap_or_default();
                                let style = (!script.css.is_empty())
                                    .then(|| {
                                        script
                                            .css
                                            .iter()
                                            .map(|file| {
                                                resources.and_then(|map| map.get(file)).cloned()
                                            })
                                            .collect::<Option<Vec<_>>>()
                                            .map(|sources| {
                                                sources.join(
                                                    "
",
                                                )
                                            })
                                    })
                                    .flatten();
                                if source.trim().is_empty() && style.is_none() {
                                    return None;
                                }
                                Some(ExtensionInjection {
                                    extension_id: manifest.id.clone(),
                                    manifest: manifest.clone(),
                                    script: source,
                                    style,
                                    matches: script.matches.clone(),
                                    storage: self
                                        .is_granted(&manifest.id, ExtensionPermission::Storage)
                                        .then(|| self.storage_areas_snapshot(&manifest.id))
                                        .flatten(),
                                    tab: self
                                        .is_granted(&manifest.id, ExtensionPermission::Tabs)
                                        .then(|| tab.cloned())
                                        .flatten(),
                                    world: script.world,
                                })
                            })
                            .collect::<Vec<_>>()
                    }),
            )
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct RawManifest {
    #[serde(default = "default_manifest_version")]
    manifest_version: u8,
    #[serde(default)]
    id: Option<String>,
    name: String,
    version: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    host_permissions: Vec<String>,
    #[serde(default)]
    optional_permissions: Vec<String>,
    #[serde(default)]
    optional_host_permissions: Vec<String>,
    #[serde(default)]
    content_scripts: Vec<RawContentScript>,
    #[serde(default)]
    background: Option<RawBackground>,
    #[serde(default)]
    action: Option<RawAction>,
    #[serde(default)]
    browser_action: Option<RawAction>,
    #[serde(default)]
    web_accessible_resources: serde_json::Value,
    #[serde(default)]
    externally_connectable: Option<RawExternallyConnectable>,
    #[serde(default)]
    browser_specific_settings: Option<RawBrowserSpecificSettings>,
    #[serde(default)]
    commands: HashMap<String, ExtensionCommandSettings>,
    #[serde(default)]
    applications: Option<RawBrowserSpecificSettings>,
    #[serde(default)]
    nomad_blocked_hosts: Vec<String>,
    #[serde(default)]
    declarative_net_request: Option<RawDeclarativeNetRequest>,
    #[serde(default)]
    options_ui: Option<ExtensionOptionsUi>,
    #[serde(default)]
    options_page: Option<String>,
    #[serde(default)]
    oauth2: Option<OAuthProviderConfig>,
}

#[derive(Debug, Deserialize)]
struct RawDeclarativeNetRequest {
    #[serde(default)]
    rule_resources: Vec<ExtensionRuleset>,
}

fn parse_web_accessible_resources(
    value: &serde_json::Value,
) -> Result<Vec<ExtensionWebAccessibleResource>, ExtensionError> {
    let Some(entries) = value.as_array() else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err(ExtensionError::InvalidManifest(
            "web_accessible_resources must be an array".into(),
        ));
    };
    let mut resources = Vec::new();
    for entry in entries {
        match entry {
            serde_json::Value::String(path) => resources.push(ExtensionWebAccessibleResource {
                resources: vec![path.clone()],
                matches: Vec::new(),
            }),
            serde_json::Value::Object(object) => {
                let Some(paths) = object
                    .get("resources")
                    .and_then(serde_json::Value::as_array)
                else {
                    return Err(ExtensionError::InvalidManifest(
                        "web_accessible_resources entries require resources".into(),
                    ));
                };
                let resources_for_entry = paths
                    .iter()
                    .map(|path| {
                        path.as_str().map(str::to_owned).ok_or_else(|| {
                            ExtensionError::InvalidManifest(
                                "web_accessible_resources paths must be strings".into(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let matches = object
                    .get("matches")
                    .and_then(serde_json::Value::as_array)
                    .map(|matches| {
                        matches
                            .iter()
                            .map(|pattern| {
                                pattern.as_str().map(str::to_owned).ok_or_else(|| {
                                    ExtensionError::InvalidManifest(
                                        "web_accessible_resources matches must be strings".into(),
                                    )
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                resources.push(ExtensionWebAccessibleResource {
                    resources: resources_for_entry,
                    matches,
                });
            }
            _ => {
                return Err(ExtensionError::InvalidManifest(
                    "web_accessible_resources entries must be strings or objects".into(),
                ));
            }
        }
    }
    Ok(resources)
}

#[derive(Debug, Deserialize)]
struct RawBrowserSpecificSettings {
    #[serde(default)]
    gecko: Option<RawGeckoSettings>,
}

#[derive(Debug, Deserialize)]
struct RawGeckoSettings {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawExternallyConnectable {
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawBackground {
    #[serde(default)]
    scripts: Vec<String>,
    #[serde(default)]
    service_worker: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default = "default_background_persistent")]
    persistent: bool,
}

impl RawBackground {
    fn try_into_manifest(self) -> Result<ExtensionBackground, ExtensionError> {
        if let Some(kind) = &self.kind {
            if kind != "module" {
                return Err(ExtensionError::InvalidManifest(format!(
                    "unsupported background type {kind:?}"
                )));
            }
        }
        let persistent = self.service_worker.is_none() && self.persistent;
        Ok(ExtensionBackground {
            scripts: self.scripts,
            service_worker: self.service_worker,
            module: self.kind.is_some_and(|kind| kind == "module"),
            persistent,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawAction {
    #[serde(default)]
    default_title: Option<String>,
    #[serde(default)]
    default_popup: Option<String>,
}

impl RawAction {
    fn try_into_manifest(self) -> ExtensionAction {
        ExtensionAction {
            default_title: self.default_title,
            default_popup: self.default_popup,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawContentScript {
    #[serde(default)]
    matches: Vec<String>,
    #[serde(default)]
    js: serde_json::Value,
    #[serde(default)]
    css: serde_json::Value,
    #[serde(default)]
    world: Option<String>,
}

impl RawContentScript {
    fn try_into_manifest(self) -> Result<ExtensionContentScript, ExtensionError> {
        let (js, js_files) = match self.js {
            serde_json::Value::Null => (String::new(), Vec::new()),
            serde_json::Value::String(js) => (js, Vec::new()),
            serde_json::Value::Array(files) => {
                let js_files = files
                    .into_iter()
                    .map(|file| {
                        file.as_str().map(str::to_owned).ok_or_else(|| {
                            ExtensionError::InvalidManifest(
                                "content script js entries must be strings".into(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if js_files.is_empty() {
                    return Err(ExtensionError::InvalidManifest(
                        "content script js cannot be empty".into(),
                    ));
                }
                (String::new(), js_files)
            }
            _ => Err(ExtensionError::InvalidManifest(
                "content script js must be a string or array".into(),
            ))?,
        };
        let (css, css_files) = match self.css {
            serde_json::Value::Null => (String::new(), Vec::new()),
            serde_json::Value::String(css) => (css, Vec::new()),
            serde_json::Value::Array(files) => {
                let css_files = files
                    .into_iter()
                    .map(|file| {
                        file.as_str().map(str::to_owned).ok_or_else(|| {
                            ExtensionError::InvalidManifest(
                                "content script css entries must be strings".into(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if css_files.is_empty() {
                    return Err(ExtensionError::InvalidManifest(
                        "content script css cannot be empty".into(),
                    ));
                }
                (String::new(), css_files)
            }
            _ => {
                return Err(ExtensionError::InvalidManifest(
                    "content script css must be a string or array".into(),
                ));
            }
        };
        Ok(ExtensionContentScript {
            matches: self.matches,
            js,
            js_files,
            css,
            css_files,
            world: match self.world.as_deref().unwrap_or("ISOLATED") {
                "ISOLATED" => ExtensionScriptWorld::Isolated,
                "MAIN" => ExtensionScriptWorld::Main,
                world => {
                    return Err(ExtensionError::InvalidManifest(format!(
                        "unsupported content script world {world:?}"
                    )));
                }
            },
        })
    }
}

fn default_manifest_version() -> u8 {
    2
}

fn default_extension_enabled() -> bool {
    true
}

fn default_ruleset_enabled() -> bool {
    true
}

fn derive_extension_id(
    key: Option<&str>,
    name: &str,
    version: &str,
) -> Result<String, ExtensionError> {
    let digest = if let Some(key) = key {
        let key = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|error| {
                ExtensionError::InvalidManifest(format!("extension key is not base64: {error}"))
            })?;
        Sha256::digest(key)
    } else {
        Sha256::digest(format!("nomad-extension\0{name}\0{version}"))
    };
    Ok(digest[..16]
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(b'a' + nibble))
        .collect())
}

fn default_background_persistent() -> bool {
    true
}

fn default_script_world() -> ExtensionScriptWorld {
    ExtensionScriptWorld::Isolated
}

fn normalize_unknown_permission(permission: &str) -> Result<String, ExtensionError> {
    let normalized = permission.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 128 || normalized.chars().any(char::is_control) {
        return Err(ExtensionError::InvalidManifest(
            "extension permission name is invalid".into(),
        ));
    }
    Ok(normalized)
}

fn default_extension_state_version() -> u8 {
    EXTENSION_STATE_VERSION
}

fn extension_version_is_newer(candidate: &str, current: &str) -> bool {
    let parse = |version: &str| {
        version
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
    };
    match (parse(candidate), parse(current)) {
        (Ok(mut candidate), Ok(mut current)) => {
            let length = candidate.len().max(current.len());
            candidate.resize(length, 0);
            current.resize(length, 0);
            candidate > current
        }
        _ => candidate > current,
    }
}

fn validate_text_field(field: &str, value: &str, max_bytes: usize) -> Result<(), ExtensionError> {
    if value.trim().is_empty() {
        return Err(ExtensionError::InvalidManifest(format!(
            "{field} is required"
        )));
    }
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ExtensionError::InvalidManifest(format!(
            "{field} is invalid or too large"
        )));
    }
    Ok(())
}

fn validate_resource_name(name: &str) -> Result<(), ExtensionError> {
    if name.is_empty()
        || name.len() > 512
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ExtensionError::InvalidManifest(format!(
            "invalid extension resource path {name:?}"
        )));
    }
    Ok(())
}

pub fn extension_resource_uri(id: &str, name: &str) -> Result<Url, ExtensionError> {
    validate_text_field("extension id", id, 128)?;
    if id.contains('/') || id.contains('\\') || id.contains(':') {
        return Err(ExtensionError::InvalidManifest(
            "extension id cannot be used as a resource authority".into(),
        ));
    }
    validate_resource_name(name)?;
    Url::parse(&format!("nomad-extension://{id}/{name}")).map_err(|error| {
        ExtensionError::InvalidManifest(format!("extension resource URL is invalid: {error}"))
    })
}

fn extension_mime_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html" | "htm") => "text/html",
        Some("js" | "mjs") => "text/javascript",
        Some("css") => "text/css",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn validate_resources(
    manifest: &ExtensionManifest,
    resources: &HashMap<String, String>,
    binary_resources: &HashMap<String, Vec<u8>>,
) -> Result<(), ExtensionError> {
    if resources.len().saturating_add(binary_resources.len()) > MAX_EXTENSION_RESOURCE_COUNT {
        return Err(ExtensionError::ResourceLimitExceeded(
            "extension contains too many resources".into(),
        ));
    }
    let mut total_bytes = 0_usize;
    for (name, source) in resources {
        validate_resource_name(name)?;
        total_bytes = total_bytes.saturating_add(source.len());
        if total_bytes > MAX_EXTENSION_RESOURCE_BYTES {
            return Err(ExtensionError::ResourceLimitExceeded(
                "extension resources are too large".into(),
            ));
        }
    }
    for (name, bytes) in binary_resources {
        validate_resource_name(name)?;
        total_bytes = total_bytes.saturating_add(bytes.len());
        if total_bytes > MAX_EXTENSION_RESOURCE_BYTES {
            return Err(ExtensionError::ResourceLimitExceeded(
                "extension resources are too large".into(),
            ));
        }
    }
    for file in extension_resource_names(manifest) {
        if !resources.contains_key(&file) && !binary_resources.contains_key(&file) {
            return Err(ExtensionError::InvalidManifest(format!(
                "extension resource {file:?} is missing"
            )));
        }
    }
    Ok(())
}

fn extension_resource_names(manifest: &ExtensionManifest) -> HashSet<String> {
    let mut names = manifest
        .content_scripts
        .iter()
        .flat_map(|script| script.js_files.iter().cloned())
        .collect::<HashSet<_>>();
    names.extend(
        manifest
            .content_scripts
            .iter()
            .flat_map(|script| script.css_files.iter().cloned()),
    );
    if let Some(background) = &manifest.background {
        names.extend(background.scripts.iter().cloned());
        if let Some(service_worker) = &background.service_worker {
            names.insert(service_worker.clone());
        }
    }
    if let Some(action) = &manifest.action {
        if let Some(popup) = &action.default_popup {
            names.insert(popup.clone());
        }
    }
    names.extend(
        manifest
            .declarative_net_request
            .iter()
            .map(|ruleset| ruleset.path.clone()),
    );
    names
}

fn load_static_rulesets(
    manifest: &ExtensionManifest,
    resources: &HashMap<String, String>,
    binary_resources: &HashMap<String, Vec<u8>>,
) -> Result<HashMap<String, Vec<Value>>, ExtensionError> {
    let mut loaded = HashMap::new();
    for ruleset in &manifest.declarative_net_request {
        let bytes = binary_resources
            .get(&ruleset.path)
            .cloned()
            .or_else(|| {
                resources
                    .get(&ruleset.path)
                    .map(|source| source.as_bytes().to_vec())
            })
            .ok_or_else(|| {
                ExtensionError::InvalidManifest(format!(
                    "static ruleset resource {:?} is missing",
                    ruleset.path
                ))
            })?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
            ExtensionError::InvalidManifest(format!(
                "static ruleset {:?} is not valid JSON: {error}",
                ruleset.id
            ))
        })?;
        let rules = value.as_array().ok_or_else(|| {
            ExtensionError::InvalidManifest(format!(
                "static ruleset {:?} must contain an array",
                ruleset.id
            ))
        })?;
        if rules.len() > MAX_DECLARATIVE_RULE_COUNT {
            return Err(ExtensionError::ResourceLimitExceeded(
                "static declarative ruleset quota exceeded".into(),
            ));
        }
        let mut ids = HashSet::new();
        for rule in rules {
            validate_declarative_rule(rule)?;
            let rule_id = rule.get("id").and_then(Value::as_u64).ok_or_else(|| {
                ExtensionError::InvalidManifest(
                    "static declarative rule requires numeric id".into(),
                )
            })?;
            if !ids.insert(rule_id) {
                return Err(ExtensionError::InvalidManifest(format!(
                    "static ruleset {:?} contains duplicate rule ID {rule_id}",
                    ruleset.id
                )));
            }
        }
        loaded.insert(ruleset.id.clone(), rules.clone());
    }
    Ok(loaded)
}

fn validate_storage_value(
    current: &HashMap<String, Value>,
    key: &str,
    value: &Value,
) -> Result<(), ExtensionError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| ExtensionError::InvalidManifest(error.to_string()))?;
    if encoded.len() > MAX_EXTENSION_VALUE_BYTES {
        return Err(ExtensionError::ResourceLimitExceeded(format!(
            "extension storage value exceeds {MAX_EXTENSION_VALUE_BYTES} bytes"
        )));
    }
    if key.is_empty() || key.len() > 512 || key.chars().any(char::is_control) {
        return Err(ExtensionError::InvalidManifest(
            "extension storage key is invalid".into(),
        ));
    }
    let current_bytes = current
        .iter()
        .filter(|(current_key, _)| current_key.as_str() != key)
        .map(|(current_key, current_value)| {
            current_key.len()
                + serde_json::to_vec(current_value).map_or(0, |serialized| serialized.len())
        })
        .sum::<usize>();
    if current_bytes
        .saturating_add(key.len())
        .saturating_add(encoded.len())
        > MAX_EXTENSION_STORAGE_BYTES
    {
        return Err(ExtensionError::ResourceLimitExceeded(
            "extension storage quota exceeded".into(),
        ));
    }
    Ok(())
}

fn validate_declarative_rule(rule: &Value) -> Result<(), ExtensionError> {
    let object = rule.as_object().ok_or_else(|| {
        ExtensionError::InvalidManifest("declarative rule must be an object".into())
    })?;
    let id = object.get("id").and_then(Value::as_u64).ok_or_else(|| {
        ExtensionError::InvalidManifest("declarative rule requires numeric id".into())
    })?;
    if id == 0 {
        return Err(ExtensionError::InvalidManifest(
            "declarative rule id must be greater than zero".into(),
        ));
    }
    let action_type = object
        .get("action")
        .and_then(Value::as_object)
        .and_then(|action| action.get("type"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ExtensionError::InvalidManifest("declarative rule requires an action type".into())
        })?;
    if !matches!(
        action_type,
        "block" | "allow" | "allowAllRequests" | "redirect"
    ) {
        return Err(ExtensionError::InvalidManifest(format!(
            "unsupported declarative action {action_type:?}"
        )));
    }
    let condition = object
        .get("condition")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ExtensionError::InvalidManifest("declarative rule requires a condition".into())
        })?;
    for key in ["urlFilter", "regexFilter"] {
        if let Some(filter) = condition.get(key) {
            let filter = filter.as_str().ok_or_else(|| {
                ExtensionError::InvalidManifest(format!("declarative {key} must be a string"))
            })?;
            if filter.is_empty() || filter.len() > 2048 || filter.chars().any(char::is_control) {
                return Err(ExtensionError::InvalidManifest(format!(
                    "declarative {key} is invalid"
                )));
            }
        }
    }
    for key in ["requestDomains", "excludedRequestDomains", "resourceTypes"] {
        if let Some(values) = condition.get(key) {
            let values = values.as_array().ok_or_else(|| {
                ExtensionError::InvalidManifest(format!("declarative {key} must be an array"))
            })?;
            if values.len() > 128
                || values.iter().any(|value| {
                    value.as_str().is_none_or(|value| {
                        value.is_empty() || value.len() > 255 || value.chars().any(char::is_control)
                    })
                })
            {
                return Err(ExtensionError::InvalidManifest(format!(
                    "declarative {key} contains an invalid value"
                )));
            }
        }
    }
    Ok(())
}

fn declarative_block_pattern(rule: &Value) -> Option<String> {
    let object = rule.as_object()?;
    let action = object.get("action")?.as_object()?;
    if action.get("type")?.as_str()? != "block" {
        return None;
    }
    let condition = object.get("condition")?.as_object()?;
    if condition.contains_key("excludedRequestDomains") {
        return None;
    }
    let domains = condition.get("requestDomains")?.as_array()?;
    let domain = domains.first()?.as_str()?;
    if domains.len() != 1 || domain.is_empty() || domain.contains(['/', '?', '#', '@']) {
        return None;
    }
    Some(format!("*://{domain}/*"))
}

fn is_match_pattern(pattern: &str) -> bool {
    if pattern == "<all_urls>" {
        return true;
    }
    let Some((scheme, rest)) = pattern.split_once("://") else {
        return false;
    };
    // `ws`/`wss` are not in the WebExtensions match-pattern grammar, but
    // real packages (MetaMask) ship them and Chromium accepts them; Nomad
    // mirrors that leniency so genuine packages install.
    if !matches!(
        scheme,
        "*" | "http" | "https" | "file" | "ftp" | "ws" | "wss"
    ) {
        return false;
    }
    let Some((host, _path)) = rest.split_once('/') else {
        return false;
    };
    // An empty path (e.g. `http://host/`) matches every path on the host,
    // matching Chromium's lenient parsing; only the host is required to be
    // non-empty (except for file: which permits the wildcard host).
    (scheme == "file" || !host.is_empty()) && !host.chars().any(char::is_whitespace)
}

fn standard_permissions(permission: &str) -> Result<Vec<ExtensionPermission>, ExtensionError> {
    let normalized = permission.trim().to_ascii_lowercase();
    let mapped = match normalized.as_str() {
        "readpage" => vec![ExtensionPermission::ReadPage],
        "activetab" => vec![ExtensionPermission::ActiveTab],
        "modifypage" => vec![ExtensionPermission::ModifyPage],
        "scripting" => vec![
            ExtensionPermission::ReadPage,
            ExtensionPermission::ModifyPage,
            ExtensionPermission::Scripting,
        ],
        "storage" | "unlimitedstorage" => vec![ExtensionPermission::Storage],
        "clipboard" | "clipboardread" | "clipboardwrite" => {
            vec![ExtensionPermission::Clipboard]
        }
        "downloads" => vec![ExtensionPermission::Downloads],
        "tabs" => vec![ExtensionPermission::Tabs],
        "history" => vec![ExtensionPermission::History],
        "bookmarks" => vec![ExtensionPermission::Bookmarks],
        "network" => vec![ExtensionPermission::Network],
        "webrequest" => vec![ExtensionPermission::WebRequest],
        "webrequestblocking" => vec![
            ExtensionPermission::WebRequest,
            ExtensionPermission::WebRequestBlocking,
        ],
        "cookies" => vec![ExtensionPermission::Cookies],
        "alarms" => vec![ExtensionPermission::Alarms],
        "notifications" => vec![ExtensionPermission::Notifications],
        "nativemessaging" => vec![ExtensionPermission::NativeMessaging],
        "webnavigation" => vec![ExtensionPermission::WebNavigation],
        "contextmenus" => vec![ExtensionPermission::ContextMenus],
        "offscreen" => vec![ExtensionPermission::Offscreen],
        "management" => vec![ExtensionPermission::Management],
        "identity" => vec![ExtensionPermission::Identity],
        "windows" => vec![ExtensionPermission::Windows],
        "tabgroups" => vec![ExtensionPermission::TabGroups],
        "sessions" => vec![ExtensionPermission::Sessions],
        "permissions" => vec![ExtensionPermission::Permissions],
        "proxy" => vec![ExtensionPermission::Proxy],
        "privacy" => vec![ExtensionPermission::Privacy],
        "idle" => vec![ExtensionPermission::Idle],
        "declarativenetrequest"
        | "declarativenetrequestwithhostaccess"
        | "declarativenetrequestfeedback" => vec![ExtensionPermission::DeclarativeNetRequest],
        "userscripts" => vec![ExtensionPermission::UserScripts],
        _ => {
            return Err(ExtensionError::InvalidManifest(format!(
                "unsupported WebExtension permission {permission:?}"
            )));
        }
    };
    Ok(mapped)
}

#[must_use]
pub fn permission_name(permission: ExtensionPermission) -> &'static str {
    match permission {
        ExtensionPermission::ReadPage => "readpage",
        ExtensionPermission::ModifyPage => "modifypage",
        ExtensionPermission::Scripting => "scripting",
        ExtensionPermission::ActiveTab => "activetab",
        ExtensionPermission::Storage => "storage",
        ExtensionPermission::Clipboard => "clipboard",
        ExtensionPermission::Downloads => "downloads",
        ExtensionPermission::Tabs => "tabs",
        ExtensionPermission::History => "history",
        ExtensionPermission::Bookmarks => "bookmarks",
        ExtensionPermission::Network => "network",
        ExtensionPermission::WebRequest => "webrequest",
        ExtensionPermission::WebRequestBlocking => "webrequestblocking",
        ExtensionPermission::Cookies => "cookies",
        ExtensionPermission::Alarms => "alarms",
        ExtensionPermission::Notifications => "notifications",
        ExtensionPermission::NativeMessaging => "nativemessaging",
        ExtensionPermission::WebNavigation => "webnavigation",
        ExtensionPermission::ContextMenus => "contextmenus",
        ExtensionPermission::Offscreen => "offscreen",
        ExtensionPermission::Management => "management",
        ExtensionPermission::Identity => "identity",
        ExtensionPermission::Windows => "windows",
        ExtensionPermission::TabGroups => "tabgroups",
        ExtensionPermission::Sessions => "sessions",
        ExtensionPermission::Permissions => "permissions",
        ExtensionPermission::Proxy => "proxy",
        ExtensionPermission::Privacy => "privacy",
        ExtensionPermission::Idle => "idle",
        ExtensionPermission::DeclarativeNetRequest => "declarativenetrequest",
        ExtensionPermission::UserScripts => "userscripts",
    }
}

fn script_sources(
    script: &ExtensionContentScript,
    resources: Option<&HashMap<String, String>>,
) -> Option<String> {
    if !script.js.is_empty() {
        return Some(script.js.clone());
    }
    let resources = resources?;
    let sources = script
        .js_files
        .iter()
        .map(|file| resources.get(file).cloned())
        .collect::<Option<Vec<_>>>()?;
    Some(sources.join("\n"))
}

fn style_sources(
    script: &ExtensionContentScript,
    resources: Option<&HashMap<String, String>>,
) -> Option<String> {
    if !script.css.is_empty() {
        return Some(script.css.clone());
    }
    if script.css_files.is_empty() {
        return None;
    }
    let resources = resources?;
    let sources = script
        .css_files
        .iter()
        .map(|file| resources.get(file).cloned())
        .collect::<Option<Vec<_>>>()?;
    Some(sources.join("\n"))
}

fn pattern_matches(pattern: &str, url: &Url) -> bool {
    if pattern == "<all_urls>" {
        return matches!(url.scheme(), "http" | "https" | "file");
    }
    let Some((scheme, rest)) = pattern.split_once("://") else {
        return false;
    };
    if scheme == "*" && !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    if scheme != "*" && scheme != url.scheme() {
        return false;
    }
    let Some((host_pattern, path_pattern)) = rest.split_once('/') else {
        return false;
    };
    let host = url.host_str().unwrap_or_default();
    wildcard_matches(host_pattern, host) && wildcard_matches(path_pattern, url.path())
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let mut remaining = value;
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return true;
    };
    if !remaining.starts_with(first) {
        return false;
    }
    remaining = &remaining[first.len()..];
    let fragments: Vec<_> = parts.collect();
    for (index, fragment) in fragments.iter().enumerate() {
        if fragment.is_empty() {
            continue;
        }
        let Some(offset) = remaining.find(fragment) else {
            return false;
        };
        if index == fragments.len() - 1 && !remaining[offset + fragment.len()..].is_empty() {
            return false;
        }
        remaining = &remaining[offset + fragment.len()..];
    }
    true
}

#[cfg(test)]
mod frame_target_tests {
    use super::{ExtensionError, ExtensionFrame, ExtensionFrameRegistry, ExtensionFrameTarget};
    use serde_json::json;
    use url::Url;

    #[test]
    fn frame_target_rejects_conflicting_selectors_and_selects_requested_frames_in_order() {
        assert!(ExtensionFrameTarget::parse(&json!({
            "tabId": 7,
            "frameIds": [2],
            "allFrames": true
        }))
        .is_err());

        let target = ExtensionFrameTarget::parse(&json!({"tabId": 7, "frameIds": [2, 0]})).unwrap();
        let mut frames = ExtensionFrameRegistry::default();
        frames.replace_tab(
            7,
            3,
            vec![
                ExtensionFrame::top(Url::parse("https://example.test/").unwrap(), 3),
                ExtensionFrame::child(2, 0, Url::parse("https://child.test/").unwrap(), 3),
            ],
        );
        assert_eq!(
            frames
                .select(&target)
                .unwrap()
                .iter()
                .map(|frame| frame.id)
                .collect::<Vec<_>>(),
            vec![2, 0]
        );
    }

    #[test]
    fn frame_navigation_generation_replaces_stale_frame_history() {
        let mut frames = ExtensionFrameRegistry::default();
        frames.replace_tab(
            7,
            1,
            vec![ExtensionFrame::top(
                Url::parse("https://old.test/").unwrap(),
                1,
            )],
        );
        frames.replace_tab(
            7,
            2,
            vec![ExtensionFrame::top(
                Url::parse("https://new.test/").unwrap(),
                2,
            )],
        );
        let target = ExtensionFrameTarget::parse(&json!({"tabId": 7, "allFrames": true})).unwrap();
        let selected = frames.select(&target).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].url.as_str(), "https://new.test/");
        assert_eq!(selected[0].navigation_generation, 2);
        assert!(matches!(
            frames.select(&ExtensionFrameTarget::parse(&json!({"tabId": 99})).unwrap()),
            Err(ExtensionError::Missing(_))
        ));
    }

    #[test]
    fn renderer_snapshot_preserves_child_ids_and_parent_links() {
        let mut frames = ExtensionFrameRegistry::default();
        frames.update_renderer_snapshot(
            7,
            1,
            vec![
                (10, None, Url::parse("https://top.test/").unwrap()),
                (11, Some(10), Url::parse("https://child.test/").unwrap()),
            ],
        );
        let target = ExtensionFrameTarget::parse(&json!({"tabId": 7, "allFrames": true})).unwrap();
        let first = frames.select(&target).unwrap();
        assert_eq!(first[1].parent_frame_id, Some(0));
        let child_id = first[1].id;
        frames.update_renderer_snapshot(
            7,
            2,
            vec![
                (10, None, Url::parse("https://top.test/next").unwrap()),
                (11, Some(10), Url::parse("https://child.test/next").unwrap()),
            ],
        );
        let second = frames.select(&target).unwrap();
        assert_eq!(second[1].id, child_id);
        assert_eq!(second[1].parent_frame_id, Some(0));
        assert_eq!(second[1].renderer_handle, Some(11));
    }

    #[test]
    fn frame_registry_evicts_old_tabs_at_bound() {
        let mut frames = ExtensionFrameRegistry::default();
        for tab_id in 0..257 {
            frames.replace_tab(
                tab_id,
                1,
                vec![ExtensionFrame::top(
                    Url::parse("https://example.test/").unwrap(),
                    1,
                )],
            );
        }
        let evicted = ExtensionFrameTarget::parse(&json!({"tabId": 0})).unwrap();
        assert!(frames.select(&evicted).is_err());
        let retained = ExtensionFrameTarget::parse(&json!({"tabId": 256})).unwrap();
        assert!(frames.select(&retained).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{Cursor, Write};

    use super::{
        apply_web_request_header_mutations, ExtensionError, ExtensionEvent, ExtensionEventKind,
        ExtensionManifest, ExtensionMessage, ExtensionPackage, ExtensionPermission,
        ExtensionRegistry, ExtensionRegistrySnapshot, ExtensionScriptWorld, ExtensionStorageArea,
        ExtensionTabInfo, PendingAuthFlow, PendingAuthFlowKind, MAX_PENDING_AUTH_FLOWS,
    };
    use crate::oauth::{generate_pkce_pair, OAuthTokenRecord, PkcePair};
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use serde_json::json;
    use url::Url;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    #[test]
    fn extension_permissions_are_explicitly_granted() {
        let manifest = ExtensionManifest::from_json(
            r#"{"id":"wallet","name":"Wallet","version":"1","permissions":["ReadPage"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        assert!(!registry.is_granted("wallet", ExtensionPermission::ReadPage));
        registry
            .grant("wallet", ExtensionPermission::ReadPage)
            .unwrap();
        assert!(registry.is_granted("wallet", ExtensionPermission::ReadPage));
    }

    #[test]
    fn unsupported_permissions_are_preserved_without_becoming_grants() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["cookies","history","webRequest","notifications"],"optional_permissions":["bookmarks"]}"#,
        )
        .unwrap();
        assert!(manifest.unsupported_permissions.is_empty());
        assert!(manifest.unsupported_optional_permissions.is_empty());
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        assert!(!registry.is_granted("tool", ExtensionPermission::Storage));
        registry
            .grant("tool", ExtensionPermission::WebRequest)
            .unwrap();
    }

    #[test]
    fn declarative_net_request_rules_are_permission_checked_persisted_and_blocking() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"rules","name":"Rules","version":"1","permissions":["declarativeNetRequest"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        let rule = json!({
            "id": 7,
            "action": {"type": "block"},
            "condition": {"requestDomains": ["ads.example"]}
        });
        assert!(registry
            .update_dynamic_rules("rules", &[], std::slice::from_ref(&rule))
            .is_err());
        registry
            .grant("rules", ExtensionPermission::DeclarativeNetRequest)
            .unwrap();
        registry
            .update_dynamic_rules("rules", &[], std::slice::from_ref(&rule))
            .unwrap();
        assert_eq!(registry.dynamic_rules("rules"), vec![rule.clone()]);
        assert_eq!(
            registry.blocking_host_patterns(),
            vec!["*://ads.example/*".to_owned()]
        );
        registry
            .update_session_rules("rules", &[], std::slice::from_ref(&rule))
            .unwrap();
        assert_eq!(registry.session_rules("rules"), vec![rule.clone()]);
        registry.set_dnr_action_options("rules", true).unwrap();
        registry.record_dnr_match("rules");
        assert_eq!(registry.action_get_badge_text("rules"), "1");
        registry.action_set_badge_text("rules", Some("manual".into()));
        assert_eq!(registry.action_get_badge_text("rules"), "manual");

        let invalid = json!({
            "id": 8,
            "action": {"type": "block"},
            "condition": {"requestDomains": "not-an-array"}
        });
        assert!(registry
            .update_dynamic_rules("rules", &[7], std::slice::from_ref(&invalid))
            .is_err());
        assert_eq!(registry.dynamic_rules("rules"), vec![rule.clone()]);

        let snapshot = registry.snapshot();
        let mut restored = ExtensionRegistry::default();
        restored.restore(snapshot).unwrap();
        assert_eq!(restored.dynamic_rules("rules"), vec![rule]);
        assert!(restored.session_rules("rules").is_empty());

        restored.update_dynamic_rules("rules", &[7], &[]).unwrap();
        assert!(restored.dynamic_rules("rules").is_empty());
    }

    #[test]
    fn static_declarative_rulesets_load_match_toggle_and_restore() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"static-rules","name":"Static rules","version":"1","permissions":["declarativeNetRequest"],"declarative_net_request":{"rule_resources":[{"id":"ads","enabled":true,"path":"rules.json"},{"id":"optional","enabled":false,"path":"optional.json"}]}}"#,
            [
                (
                    "rules.json".into(),
                    r#"[{"id":101,"action":{"type":"block"},"condition":{"requestDomains":["ads.example"]}}]"#.into(),
                ),
                (
                    "optional.json".into(),
                    r#"[{"id":102,"action":{"type":"block"},"condition":{"requestDomains":["optional.example"]}}]"#.into(),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();
        registry
            .grant("static-rules", ExtensionPermission::DeclarativeNetRequest)
            .unwrap();

        assert_eq!(
            registry.static_ruleset_ids("static-rules"),
            vec!["ads".to_owned(), "optional".to_owned()]
        );
        assert_eq!(registry.enabled_ruleset_ids("static-rules"), vec!["ads"]);
        assert_eq!(
            registry.blocking_host_patterns(),
            vec!["*://ads.example/*".to_owned()]
        );

        registry
            .update_enabled_rulesets(
                "static-rules",
                &["optional".to_owned()],
                &["ads".to_owned()],
            )
            .unwrap();
        assert_eq!(
            registry.blocking_host_patterns(),
            vec!["*://optional.example/*".to_owned()]
        );

        let updated = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"static-rules","name":"Static rules","version":"2","permissions":["declarativeNetRequest"],"declarative_net_request":{"rule_resources":[{"id":"ads","enabled":true,"path":"rules.json"},{"id":"optional","enabled":true,"path":"optional.json"}]}}"#,
            [
                (
                    "rules.json".into(),
                    r#"[{"id":101,"action":{"type":"block"},"condition":{"requestDomains":["ads.example"]}}]"#.into(),
                ),
                (
                    "optional.json".into(),
                    r#"[{"id":102,"action":{"type":"block"},"condition":{"requestDomains":["optional.example"]}}]"#.into(),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        registry.update_package(updated).unwrap();
        assert_eq!(
            registry.enabled_ruleset_ids("static-rules"),
            vec!["optional".to_owned()]
        );

        let snapshot = registry.snapshot();
        let mut restored = ExtensionRegistry::default();
        restored.restore(snapshot).unwrap();
        assert_eq!(
            restored.enabled_ruleset_ids("static-rules"),
            vec!["optional".to_owned()]
        );
        assert_eq!(
            restored.blocking_host_patterns(),
            vec!["*://optional.example/*".to_owned()]
        );
    }

    #[test]
    fn disabled_extensions_stop_injection_and_persist_across_restore() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["ReadPage","ModifyPage"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":"document.title='Nomad';"}]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        registry
            .grant("tool", ExtensionPermission::ReadPage)
            .unwrap();
        registry
            .grant("tool", ExtensionPermission::ModifyPage)
            .unwrap();
        registry
            .grant_host_permission("tool", "https://example.com/*")
            .unwrap();
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(registry.scripts_for_url(&url).len(), 1);

        registry.set_enabled("tool", false).unwrap();
        assert!(!registry.is_enabled("tool"));
        assert!(registry.scripts_for_url(&url).is_empty());
        let snapshot = registry.snapshot();
        assert!(!snapshot.extensions[0].enabled);

        let mut restored = ExtensionRegistry::default();
        restored.restore(snapshot).unwrap();
        assert!(!restored.is_enabled("tool"));
        assert!(restored.scripts_for_url(&url).is_empty());
        restored.set_enabled("tool", true).unwrap();
        assert_eq!(restored.scripts_for_url(&url).len(), 1);
    }

    #[test]
    fn context_menus_are_permission_checked_and_mutable() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"menus","name":"Menus","version":"1","permissions":["contextMenus"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        let first_properties = json!({"title": "Inspect"});
        assert!(registry
            .context_menu_create("menus", &first_properties)
            .is_err());
        registry
            .grant("menus", ExtensionPermission::ContextMenus)
            .unwrap();
        let properties = json!({"title": "Inspect", "contexts": ["page"]});
        let id = registry.context_menu_create("menus", &properties).unwrap();
        let id = id.as_str().unwrap().to_owned();
        assert_eq!(registry.context_menu_items("menus").len(), 1);
        let updates = json!({"title": "Inspect page"});
        registry
            .context_menu_update("menus", &id, &updates)
            .unwrap();
        assert_eq!(
            registry.context_menu_items("menus")[0]["title"],
            "Inspect page"
        );
        registry.context_menu_remove("menus", &id).unwrap();
        assert!(registry.context_menu_items("menus").is_empty());
    }

    #[test]
    fn generated_context_menu_ids_skip_explicit_ids() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"menu","name":"Menu","version":"1","permissions":["contextMenus"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        registry
            .grant("menu", ExtensionPermission::ContextMenus)
            .unwrap();

        assert_eq!(
            registry
                .context_menu_create("menu", &json!({"id": "0", "title": "Explicit"}))
                .unwrap(),
            json!("0")
        );
        assert_eq!(
            registry
                .context_menu_create("menu", &json!({"title": "Generated"}))
                .unwrap(),
            json!("1")
        );
    }

    #[test]
    fn content_scripts_require_permissions_and_match_hosts() {
        let manifest = ExtensionManifest::from_json(
            r#"{"id":"tool","name":"Tool","version":"1","permissions":["ReadPage","ModifyPage"],"host_permissions":["https://*.example.com/*"],"content_scripts":[{"matches":["https://*.example.com/*"],"js":"document.body.dataset.nomad='1';"}]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        let example = Url::parse("https://app.example.com/page").unwrap();
        assert!(registry.scripts_for_url(&example).is_empty());
        registry
            .grant("tool", ExtensionPermission::ReadPage)
            .unwrap();
        registry
            .grant("tool", ExtensionPermission::ModifyPage)
            .unwrap();
        registry
            .grant_host_permission("tool", "https://*.example.com/*")
            .unwrap();
        assert_eq!(registry.scripts_for_url(&example).len(), 1);
        assert!(registry
            .scripts_for_url(&Url::parse("https://other.invalid/").unwrap())
            .is_empty());
    }

    #[test]
    fn active_tab_action_temporarily_allows_content_script_injection() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["activeTab"],"content_scripts":[{"matches":["https://example.com/*"],"js":"document.title='Nomad';"}],"background":{"service_worker":"background.js"},"action":{}}"#,
            [("background.js".into(), String::new())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();
        registry
            .grant("tool", ExtensionPermission::ActiveTab)
            .unwrap();
        let tab = ExtensionTabInfo {
            id: 7,
            url: Some(Url::parse("https://example.com/").unwrap()),
            active: true,
        };
        assert!(registry.scripts_for_tab(&tab).is_empty());
        registry.trigger_action("tool", &tab).unwrap();
        assert_eq!(registry.scripts_for_tab(&tab).len(), 1);
        registry.clear_active_tab_grant(tab.id);
        assert!(registry.scripts_for_tab(&tab).is_empty());
    }

    #[test]
    fn standard_webextension_manifest_and_script_resources_are_supported() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1.0","permissions":["scripting","storage"],"host_permissions":["https://*.example.com/*"],"content_scripts":[{"matches":["https://*.example.com/*"],"js":["content.js"]}]}"#,
        )
        .unwrap();
        assert_eq!(manifest.manifest_version, 3);
        assert!(manifest
            .permissions
            .contains(&ExtensionPermission::ModifyPage));
        assert_eq!(manifest.content_scripts[0].js_files, ["content.js"]);

        let mut registry = ExtensionRegistry::default();
        registry
            .install_with_resources(
                manifest,
                [(
                    "content.js".into(),
                    "document.body.dataset.nomad='1';".into(),
                )]
                .into_iter()
                .collect(),
            )
            .unwrap();
        registry
            .grant("tool", ExtensionPermission::ReadPage)
            .unwrap();
        registry
            .grant("tool", ExtensionPermission::ModifyPage)
            .unwrap();
        registry
            .grant("tool", ExtensionPermission::Storage)
            .unwrap();
        registry
            .grant_host_permission("tool", "https://*.example.com/*")
            .unwrap();
        let injections =
            registry.scripts_for_url(&Url::parse("https://app.example.com/page").unwrap());
        assert_eq!(injections.len(), 1);
        assert!(injections[0].script.contains("dataset.nomad"));
    }

    #[test]
    fn extension_archive_keeps_unlisted_runtime_resources() {
        let mut archive = ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file("manifest.json", SimpleFileOptions::default())
            .unwrap();
        archive
            .write_all(
                br#"{"manifest_version":3,"id":"resource-test","name":"Resource Test","version":"1"}"#,
            )
            .unwrap();
        archive
            .start_file("chunks/runtime.js", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"export const value = 42;").unwrap();
        archive
            .start_file("_locales/en/messages.json", SimpleFileOptions::default())
            .unwrap();
        archive
            .write_all(br#"{"hello":{"message":"Hello"}}"#)
            .unwrap();
        archive
            .start_file("icons/icon.png", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(&[0, 159, 250, 1]).unwrap();
        let bytes = archive.finish().unwrap().into_inner();

        let package = ExtensionPackage::from_archive_bytes(&bytes).unwrap();

        assert_eq!(
            package
                .resources()
                .get("chunks/runtime.js")
                .map(String::as_str),
            Some("export const value = 42;")
        );
        assert!(package
            .resources()
            .contains_key("_locales/en/messages.json"));

        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();
        assert!(registry
            .resources_for("resource-test")
            .iter()
            .any(|resource| {
                resource.path == "icons/icon.png" && resource.bytes == [0, 159, 250, 1]
            }));
    }

    #[test]
    fn registry_exposes_extension_origin_resources_with_content_types() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"resource-test","name":"Resource Test","version":"1"}"#,
            [
                ("background.js".into(), "export const value = 42;".into()),
                ("popup.html".into(), "<main>Nomad</main>".into()),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();

        let resources = registry.resources_for("resource-test");

        assert_eq!(resources.len(), 2);
        assert!(resources.iter().any(|resource| {
            resource.path == "background.js"
                && resource.mime_type == "text/javascript"
                && resource.source == "export const value = 42;"
        }));
        assert!(resources.iter().any(|resource| {
            resource.path == "popup.html" && resource.mime_type == "text/html"
        }));
    }

    #[test]
    fn background_script_paths_preserve_manifest_execution_order() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":2,"id":"background-test","name":"Background Test","version":"1","background":{"scripts":["first.js","second.js"]}}"#,
            [
                ("first.js".into(), "window.first = true;".into()),
                ("second.js".into(), "window.second = true;".into()),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();

        assert_eq!(
            registry.background_script_paths("background-test"),
            vec!["first.js".to_owned(), "second.js".to_owned()]
        );
    }

    #[test]
    fn standard_manifest_derives_identity_when_custom_id_is_absent() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"name":"Identity Test","version":"1.0","key":"AQIDBAU="}"#,
        )
        .unwrap();

        assert_eq!(manifest.id.len(), 32);
        assert!(manifest
            .id
            .chars()
            .all(|character| ('a'..='p').contains(&character)));
    }

    #[test]
    fn standard_content_script_can_be_css_only() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"style-test","name":"Style Test","version":"1","permissions":["scripting"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"css":["content.css"]}]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry
            .install_with_resources(
                manifest,
                [("content.css".into(), "body { color: red; }".into())]
                    .into_iter()
                    .collect(),
            )
            .unwrap();
        registry
            .grant("style-test", ExtensionPermission::ReadPage)
            .unwrap();
        registry
            .grant("style-test", ExtensionPermission::ModifyPage)
            .unwrap();
        registry
            .grant_host_permission("style-test", "https://example.com/*")
            .unwrap();

        let injections = registry.scripts_for_url(&Url::parse("https://example.com/").unwrap());

        assert_eq!(injections.len(), 1);
        assert_eq!(injections[0].style.as_deref(), Some("body { color: red; }"));
    }

    #[test]
    fn main_world_content_script_is_explicitly_supported() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"wallet","name":"Wallet","version":"1","host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":["inpage.js"],"world":"MAIN"}]}"#,
        )
        .unwrap();
        assert_eq!(
            manifest.content_scripts[0].world,
            super::ExtensionScriptWorld::Main
        );
    }

    #[test]
    fn declared_content_scripts_use_granted_host_access_without_tabs_permission() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"wallet","name":"Wallet","version":"1","host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":"window.postMessage({ready:true}, '*');"}]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        registry
            .grant_host_permission("wallet", "https://example.com/*")
            .unwrap();
        assert_eq!(
            registry
                .scripts_for_url(&Url::parse("https://example.com/").unwrap())
                .len(),
            1
        );
    }

    #[test]
    fn extension_resource_uri_rejects_traversal_and_encodes_identity() {
        assert_eq!(
            super::extension_resource_uri("wallet", "background.js")
                .unwrap()
                .as_str(),
            "nomad-extension://wallet/background.js"
        );
        assert!(super::extension_resource_uri("wallet", "../secret").is_err());
        assert!(super::extension_resource_uri("wallet/id", "background.js").is_err());
    }

    #[test]
    fn manifest_parses_background_and_action_resources() {
        let raw = r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1.0","background":{"service_worker":"background.js","type":"module"},"action":{"default_title":"Tool","default_popup":"popup.html"}}"#;
        let manifest = ExtensionManifest::from_json(raw).unwrap();

        assert_eq!(
            manifest
                .background
                .as_ref()
                .unwrap()
                .service_worker
                .as_deref(),
            Some("background.js")
        );
        assert_eq!(
            manifest.action.as_ref().unwrap().default_popup.as_deref(),
            Some("popup.html")
        );
        assert!(ExtensionPackage::from_manifest_json(
            raw,
            [
                ("background.js".into(), "browser.runtime.onMessage;".into()),
                ("popup.html".into(), "<button>Nomad</button>".into()),
            ]
            .into_iter()
            .collect(),
        )
        .is_ok());
        assert!(ExtensionPackage::from_manifest_json(raw, HashMap::new()).is_err());

        let legacy = ExtensionManifest::from_json(
            r#"{"manifest_version":2,"id":"legacy","name":"Legacy","version":"1","browser_action":{"default_title":"Legacy","default_popup":"popup.html"}}"#,
        )
        .unwrap();
        assert_eq!(
            legacy.action.as_ref().unwrap().default_title.as_deref(),
            Some("Legacy")
        );
    }

    #[test]
    fn background_lifecycle_and_action_events_are_capability_checked() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1.0","permissions":["tabs","storage"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"},"action":{"default_title":"Tool","default_popup":"popup.html"}}"#,
            [
                ("background.js".into(), "browser.runtime.onMessage;".into()),
                ("popup.html".into(), "<button>Nomad</button>".into()),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();
        assert_eq!(
            registry.background_script("tool").as_deref(),
            Some("browser.runtime.onMessage;")
        );
        assert!(registry.background_info("tool").unwrap().running);

        let tab = ExtensionTabInfo {
            id: 9,
            url: Some(Url::parse("https://example.com/").unwrap()),
            active: true,
        };
        assert!(registry.trigger_action("tool", &tab).is_err());
        registry.grant("tool", ExtensionPermission::Tabs).unwrap();
        registry
            .grant("tool", ExtensionPermission::Storage)
            .unwrap();
        registry
            .grant_host_permission("tool", "https://example.com/*")
            .unwrap();
        registry
            .receive_background_message("tool", json!({"__nomad_storage_set": {"mode": "compact"}}))
            .unwrap();
        assert_eq!(
            registry.storage_get("tool", "mode").unwrap(),
            Some(json!("compact"))
        );
        registry.trigger_action("tool", &tab).unwrap();
        assert!(registry.background_info("tool").unwrap().running);
        assert!(matches!(
            registry.drain_background_events("tool").as_slice(),
            [
                ExtensionEvent {
                    kind: ExtensionEventKind::Startup,
                    ..
                },
                ExtensionEvent {
                    kind: ExtensionEventKind::Installed { .. },
                    ..
                },
                ExtensionEvent {
                    kind: ExtensionEventKind::ActionClicked { .. },
                    ..
                }
            ]
        ));
    }

    #[test]
    fn extension_update_replaces_resources_and_preserves_user_state() {
        let first = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"updatable","name":"Updatable","version":"1.0","permissions":["storage"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
            [("background.js".into(), "globalThis.version = 1;".into())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let second = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"updatable","name":"Updatable","version":"2.0","permissions":["storage"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
            [("background.js".into(), "globalThis.version = 2;".into())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(first).unwrap();
        registry
            .grant("updatable", ExtensionPermission::Storage)
            .unwrap();
        registry
            .grant_host_permission("updatable", "https://example.com/*")
            .unwrap();
        registry
            .storage_set("updatable", "userChoice", json!("keep"))
            .unwrap();
        registry.update_package(second).unwrap();

        assert_eq!(registry.manifest("updatable").unwrap().version, "2.0");
        assert_eq!(
            registry.resource_source("updatable", "background.js"),
            Some("globalThis.version = 2;".into())
        );
        assert_eq!(
            registry.storage_get("updatable", "userChoice").unwrap(),
            Some(json!("keep"))
        );
        assert!(registry.is_granted("updatable", ExtensionPermission::Storage));
        assert!(registry.is_host_granted("updatable", &Url::parse("https://example.com/").unwrap()));
        assert!(matches!(
            registry.drain_background_events("updatable").last(),
            Some(ExtensionEvent {
                kind: ExtensionEventKind::Installed { reason },
                ..
            }) if reason == "update"
        ));
    }

    #[test]
    fn web_request_events_require_permission_and_host_access() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["webRequest"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
            [("background.js".into(), "browser.webRequest.onBeforeRequest.addListener(() => {});".into())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();
        let url = Url::parse("https://example.com/resource").unwrap();
        assert!(registry
            .dispatch_web_request(
                "tool",
                "web_request",
                json!({"url": url.as_str()}),
                Some(&url)
            )
            .is_err());
        registry
            .grant("tool", ExtensionPermission::WebRequest)
            .unwrap();
        registry
            .grant_host_permission("tool", "https://example.com/*")
            .unwrap();
        registry
            .dispatch_web_request(
                "tool",
                "web_request",
                json!({"url": url.as_str()}),
                Some(&url),
            )
            .unwrap();
        assert!(matches!(
            registry.drain_background_events("tool").as_slice(),
            [
                ExtensionEvent {
                    kind: ExtensionEventKind::Startup,
                    ..
                },
                ExtensionEvent {
                    kind: ExtensionEventKind::Installed { .. },
                    ..
                },
                ExtensionEvent {
                    kind: ExtensionEventKind::WebRequest { .. },
                    ..
                }
            ]
        ));
    }

    #[test]
    fn host_permissions_storage_tabs_and_messages_are_capability_checked() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1.0","permissions":["storage","tabs"],"host_permissions":["https://*.example.com/*"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        registry
            .grant("tool", ExtensionPermission::Storage)
            .unwrap();
        registry.grant("tool", ExtensionPermission::Tabs).unwrap();

        let example = Url::parse("https://app.example.com/page").unwrap();
        let private = Url::parse("https://private.invalid/").unwrap();
        let tabs = vec![
            ExtensionTabInfo {
                id: 1,
                url: Some(example.clone()),
                active: true,
            },
            ExtensionTabInfo {
                id: 2,
                url: Some(private.clone()),
                active: false,
            },
        ];
        assert!(registry.query_tabs("tool", &tabs).is_ok());
        assert!(registry
            .query_tabs("tool", &tabs)
            .unwrap()
            .iter()
            .all(|tab| tab.url.is_none()));
        assert!(registry
            .send_message("tool", Some(1), json!({"ready": true}), Some(&example))
            .is_err());

        registry
            .grant_host_permission("tool", "https://*.example.com/*")
            .unwrap();
        assert_eq!(
            registry
                .storage_set("tool", "mode", json!("compact"))
                .unwrap(),
            ()
        );
        assert_eq!(
            registry.storage_get("tool", "mode").unwrap(),
            Some(json!("compact"))
        );
        registry
            .receive_page_message(
                "tool",
                Some(1),
                json!({"__nomad_storage_set": {"theme": "dark"}}),
                Some(&example),
            )
            .unwrap();
        assert_eq!(
            registry.storage_get("tool", "theme").unwrap(),
            Some(json!("dark"))
        );
        registry
            .receive_page_message(
                "tool",
                Some(1),
                json!({"__nomad_storage_remove": ["theme"]}),
                Some(&example),
            )
            .unwrap();
        assert_eq!(registry.storage_get("tool", "theme").unwrap(), None);
        let visible = registry.query_tabs("tool", &tabs).unwrap();
        assert_eq!(visible[0].url, Some(example.clone()));
        assert_eq!(visible[1].url, None);

        registry
            .send_message("tool", Some(1), json!({"ready": true}), Some(&example))
            .unwrap();
        assert_eq!(
            registry.drain_messages("tool"),
            vec![ExtensionMessage {
                extension_id: "tool".into(),
                tab_id: Some(1),
                payload: json!({"ready": true}),
            }]
        );
        registry
            .revoke("tool", ExtensionPermission::Storage)
            .unwrap();
        assert!(registry
            .receive_page_message(
                "tool",
                Some(1),
                json!({"__nomad_storage_set": {"blocked": true}}),
                Some(&example),
            )
            .is_err());
        registry.uninstall("tool").unwrap();
        assert!(registry.storage_get("tool", "mode").is_err());
    }

    #[test]
    fn package_validation_rejects_unsafe_resources_and_empty_scripts() {
        let raw = r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["scripting"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":["../content.js"]}]}"#;
        let result = ExtensionPackage::from_manifest_json(
            raw,
            [("../content.js".into(), "alert(1)".into())]
                .into_iter()
                .collect(),
        );
        assert!(matches!(
            result,
            Err(super::ExtensionError::InvalidManifest(_))
        ));

        let raw = r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["scripting"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":""}]}"#;
        assert!(ExtensionManifest::from_json(raw).is_err());
    }

    #[test]
    fn registry_snapshot_round_trips_grants_resources_and_storage() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["scripting","storage"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":["content.js"]}]}"#,
            [("content.js".into(), "document.body.dataset.ready='1';".into())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();
        registry
            .grant("tool", ExtensionPermission::ReadPage)
            .unwrap();
        registry
            .grant("tool", ExtensionPermission::ModifyPage)
            .unwrap();
        registry
            .grant("tool", ExtensionPermission::Storage)
            .unwrap();
        registry
            .grant_host_permission("tool", "https://example.com/*")
            .unwrap();
        registry
            .storage_set("tool", "theme", json!("dark"))
            .unwrap();

        let snapshot = registry.snapshot();
        let encoded = snapshot.to_json().unwrap();
        let decoded = ExtensionRegistrySnapshot::from_json(&encoded).unwrap();
        let mut restored = ExtensionRegistry::default();
        restored.restore(decoded).unwrap();

        assert_eq!(
            restored.storage_get("tool", "theme").unwrap(),
            Some(json!("dark"))
        );
        assert_eq!(
            restored
                .scripts_for_url(&Url::parse("https://example.com/").unwrap())
                .len(),
            1
        );
    }

    #[test]
    fn storage_areas_are_separate_and_session_is_cleared_on_restore() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"store","name":"Store","version":"1","permissions":["storage"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        registry
            .grant("store", ExtensionPermission::Storage)
            .unwrap();

        registry
            .storage_set_area(
                "store",
                ExtensionStorageArea::Local,
                "local-key",
                json!("l"),
            )
            .unwrap();
        registry
            .storage_set_area("store", ExtensionStorageArea::Sync, "sync-key", json!("s"))
            .unwrap();
        registry
            .storage_set_area(
                "store",
                ExtensionStorageArea::Session,
                "session-key",
                json!("x"),
            )
            .unwrap();

        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Local, "local-key")
                .unwrap(),
            Some(json!("l"))
        );
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Sync, "sync-key")
                .unwrap(),
            Some(json!("s"))
        );
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Session, "session-key")
                .unwrap(),
            Some(json!("x"))
        );
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Local, "sync-key")
                .unwrap(),
            None,
            "areas must not leak into each other"
        );

        let snapshot = registry.snapshot();
        let encoded = snapshot.to_json().unwrap();
        let decoded = ExtensionRegistrySnapshot::from_json(&encoded).unwrap();
        let mut restored = ExtensionRegistry::default();
        restored.restore(decoded).unwrap();

        assert_eq!(
            restored
                .storage_get_area("store", ExtensionStorageArea::Local, "local-key")
                .unwrap(),
            Some(json!("l")),
            "local storage must survive restart"
        );
        assert_eq!(
            restored
                .storage_get_area("store", ExtensionStorageArea::Sync, "sync-key")
                .unwrap(),
            Some(json!("s")),
            "sync storage must survive restart"
        );
        assert_eq!(
            restored
                .storage_get_area("store", ExtensionStorageArea::Session, "session-key")
                .unwrap(),
            None,
            "session storage is in-memory only and must be cleared on restart"
        );
    }

    #[test]
    fn storage_message_payloads_route_to_their_area() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"store","name":"Store","version":"1","permissions":["storage"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        registry
            .grant("store", ExtensionPermission::Storage)
            .unwrap();

        assert!(registry
            .apply_storage_message(
                "store",
                &json!({"__nomad_storage_area": "sync", "__nomad_storage_set": {"k": 1}})
            )
            .unwrap());
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Sync, "k")
                .unwrap(),
            Some(json!(1))
        );
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Local, "k")
                .unwrap(),
            None
        );

        assert!(registry
            .apply_storage_message(
                "store",
                &json!({"__nomad_storage_area": "session", "__nomad_storage_set": {"k": 2}})
            )
            .unwrap());
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Session, "k")
                .unwrap(),
            Some(json!(2))
        );
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Sync, "k")
                .unwrap(),
            Some(json!(1)),
            "areas must not clobber each other"
        );

        assert!(registry
            .apply_storage_message(
                "store",
                &json!({"__nomad_storage_area": "session", "__nomad_storage_remove": ["k"]})
            )
            .unwrap());
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Session, "k")
                .unwrap(),
            None
        );
        assert_eq!(
            registry
                .storage_get_area("store", ExtensionStorageArea::Sync, "k")
                .unwrap(),
            Some(json!(1)),
            "removing from one area must not touch another"
        );

        assert!(registry
            .apply_storage_message(
                "store",
                &json!({"__nomad_storage_area": "session", "__nomad_storage_clear": true})
            )
            .unwrap());
        assert!(registry
            .storage_get_area_all("store", ExtensionStorageArea::Session)
            .unwrap()
            .is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn registered_content_scripts_register_update_unregister_and_persist() {
        let package = ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"dyn","name":"Dyn","version":"1","permissions":["scripting"],"host_permissions":["https://example.com/*"]}"#,
            [
                ("a.js".into(), "const a = 1;".into()),
                ("b.js".into(), "const b = 2;".into()),
                ("style.css".into(), "body { color: red; }".into()),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install_package(package).unwrap();
        registry
            .grant("dyn", ExtensionPermission::Scripting)
            .unwrap();
        registry
            .grant_host_permission("dyn", "https://example.com/*")
            .unwrap();

        registry
            .register_content_scripts(
                "dyn",
                &[serde_json::json!({
                    "id": "first",
                    "matches": ["https://example.com/*"],
                    "js": ["a.js"],
                    "css": ["style.css"],
                    "world": "MAIN",
                    "runAt": "document_start",
                    "allFrames": true,
                })],
            )
            .unwrap();
        assert_eq!(registry.registered_content_scripts("dyn").len(), 1);

        assert_eq!(
            registry
                .register_content_scripts(
                    "dyn",
                    &[serde_json::json!({"id": "first", "matches": ["https://example.com/*"], "js": ["b.js"]})]
                )
                .unwrap_err(),
            ExtensionError::InvalidManifest(
                "registered content script id \"first\" is already registered".into()
            )
        );
        assert_eq!(
            registry
                .register_content_scripts(
                    "dyn",
                    &[serde_json::json!({"id": "bad", "matches": ["not-a-pattern"], "js": ["a.js"]})]
                )
                .unwrap_err(),
            ExtensionError::InvalidManifest(
                "registered content script has invalid match pattern \"not-a-pattern\"".into()
            )
        );
        assert!(matches!(
            registry.register_content_scripts(
                "dyn",
                &[serde_json::json!({"id": "missing", "matches": ["https://example.com/*"], "js": ["nope.js"]})]
            ),
            Err(ExtensionError::Missing(_))
        ));
        assert!(matches!(
            registry.register_content_scripts(
                "dyn",
                &[serde_json::json!({"id": "noworld", "matches": ["https://example.com/*"], "js": ["a.js"], "world": "PAGE"})]
            ),
            Err(ExtensionError::InvalidManifest(_))
        ));

        let injections = registry.scripts_for_url(&Url::parse("https://example.com/").unwrap());
        assert_eq!(injections.len(), 1);
        assert_eq!(injections[0].extension_id, "dyn");
        assert!(injections[0].script.contains("const a = 1"));
        assert!(injections[0]
            .style
            .as_deref()
            .is_some_and(|style| style.contains("color: red")));
        assert_eq!(injections[0].world, ExtensionScriptWorld::Main);
        assert!(registry
            .scripts_for_url(&Url::parse("https://other.example/").unwrap())
            .is_empty());

        let snapshot = registry.snapshot();
        let mut restored = ExtensionRegistry::default();
        restored.restore(snapshot).unwrap();
        assert_eq!(restored.registered_content_scripts("dyn").len(), 1);
        assert_eq!(restored.registered_content_scripts("dyn")[0].id, "first");

        registry
            .update_content_scripts(
                "dyn",
                &[serde_json::json!({
                    "id": "first",
                    "matches": ["https://example.com/*"],
                    "js": ["b.js"],
                })],
            )
            .unwrap();
        let injections = registry.scripts_for_url(&Url::parse("https://example.com/").unwrap());
        assert!(injections[0].script.contains("const b = 2"));
        assert!(injections[0].style.is_none(), "css dropped by update");

        registry
            .unregister_content_scripts("dyn", Some(&["first".into()]))
            .unwrap();
        assert!(registry.registered_content_scripts("dyn").is_empty());
        assert!(registry
            .scripts_for_url(&Url::parse("https://example.com/").unwrap())
            .is_empty());

        registry.unregister_content_scripts("dyn", None).unwrap();
        registry
            .unregister_content_scripts("missing", None)
            .unwrap_err();
    }

    #[test]
    fn registry_snapshot_retains_storage_when_permission_is_revoked() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1.0","permissions":["storage"]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry.install(manifest).unwrap();
        registry
            .grant("tool", ExtensionPermission::Storage)
            .unwrap();
        registry
            .storage_set("tool", "theme", json!("dark"))
            .unwrap();
        registry
            .revoke("tool", ExtensionPermission::Storage)
            .unwrap();

        let mut restored = ExtensionRegistry::default();
        restored.restore(registry.snapshot()).unwrap();
        restored
            .grant("tool", ExtensionPermission::Storage)
            .unwrap();
        assert_eq!(
            restored.storage_get("tool", "theme").unwrap(),
            Some(json!("dark"))
        );
    }

    #[test]
    fn directory_package_loads_all_safe_resources() {
        let root = std::env::temp_dir().join(format!("nomad-extension-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("scripts")).unwrap();
        std::fs::write(
            root.join("manifest.json"),
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["scripting"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":["scripts/content.js"]}]}"#,
        )
        .unwrap();
        std::fs::write(root.join("scripts/content.js"), "document.title='Nomad';").unwrap();
        std::fs::write(root.join("ignored.txt"), "not loaded").unwrap();

        let package = ExtensionPackage::from_directory(&root).unwrap();
        assert_eq!(package.resources().len(), 2);
        assert!(package.resources().contains_key("scripts/content.js"));
        assert!(package.resources().contains_key("ignored.txt"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn archive_package_loads_all_safe_resources() {
        let mut archive = ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file("manifest.json", SimpleFileOptions::default())
            .unwrap();
        archive
            .write_all(
                br#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["scripting"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":["scripts/content.js"]}]}"#,
            )
            .unwrap();
        archive
            .start_file("scripts/content.js", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"document.title='Nomad';").unwrap();
        archive
            .start_file("ignored.txt", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"not loaded").unwrap();
        let bytes = archive.finish().unwrap().into_inner();

        let package = ExtensionPackage::from_archive_bytes(&bytes).unwrap();

        assert_eq!(package.manifest().id, "tool");
        assert_eq!(package.resources().len(), 2);
        assert!(package.resources().contains_key("scripts/content.js"));
        assert!(package.resources().contains_key("ignored.txt"));
    }

    #[test]
    fn modern_permissions_and_declarative_blocking_rules_are_parsed() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"blocker","name":"Blocker","version":"1","permissions":["scripting","cookies","alarms","notifications","webRequestBlocking"],"nomad_blocked_hosts":["https://ads.example/*"]}"#,
        )
        .unwrap();
        assert!(manifest
            .permissions
            .contains(&ExtensionPermission::Scripting));
        assert!(manifest.permissions.contains(&ExtensionPermission::Cookies));
        assert!(manifest
            .permissions
            .contains(&ExtensionPermission::WebRequestBlocking));
        assert_eq!(
            manifest.blocked_host_patterns,
            vec!["https://ads.example/*"]
        );
    }

    #[test]
    fn web_accessible_resources_support_mv2_and_mv3_shapes() {
        let legacy = ExtensionManifest::from_json(
            r#"{"manifest_version":2,"id":"legacy","name":"Legacy","version":"1","web_accessible_resources":["inpage.js","images/*"]}"#,
        )
        .unwrap();
        assert_eq!(
            legacy.web_accessible_resources[0].resources,
            vec!["inpage.js"]
        );
        assert_eq!(
            legacy.web_accessible_resources[1].resources,
            vec!["images/*"]
        );

        let modern = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"modern","name":"Modern","version":"1","web_accessible_resources":[{"resources":["inpage.js","images/*"],"matches":["https://*.example/*"]}]}"#,
        )
        .unwrap();
        assert_eq!(
            modern.web_accessible_resources[0].resources,
            vec!["inpage.js", "images/*"]
        );
        assert_eq!(
            modern.web_accessible_resources[0].matches,
            vec!["https://*.example/*"]
        );
    }

    #[test]
    fn resources_report_web_accessibility_for_page_world_injection() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"wallet","name":"Wallet","version":"1","web_accessible_resources":[{"resources":["inpage.js"]}]}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry
            .install_with_resources(
                manifest,
                HashMap::from([
                    ("inpage.js".into(), "window.ethereum = {};".into()),
                    ("private.js".into(), "secret();".into()),
                ]),
            )
            .unwrap();
        let resources = registry.resources_for("wallet");
        assert!(
            resources
                .iter()
                .find(|resource| resource.path == "inpage.js")
                .unwrap()
                .web_accessible
        );
        assert!(
            !resources
                .iter()
                .find(|resource| resource.path == "private.js")
                .unwrap()
                .web_accessible
        );
    }

    #[test]
    fn external_messages_are_permission_and_target_scoped() {
        let sender = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"sender","name":"Sender","version":"1","permissions":["tabs"],"background":{"service_worker":"background.js"}}"#,
        )
        .unwrap();
        let receiver = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"receiver","name":"Receiver","version":"1","externally_connectable":{"ids":["sender"]},"background":{"service_worker":"background.js"}}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry
            .install_with_resources(
                sender,
                HashMap::from([(String::from("background.js"), String::new())]),
            )
            .unwrap();
        registry
            .install_with_resources(
                receiver,
                HashMap::from([(String::from("background.js"), String::new())]),
            )
            .unwrap();
        registry
            .dispatch_external_message("sender", "receiver", json!({"ok": true}))
            .unwrap();
        let events = registry.drain_background_events("receiver");
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            ExtensionEventKind::RuntimeMessage {
                sender_extension_id: Some(sender),
                payload,
                ..
            } if sender == "sender" && payload == &json!({"ok": true})
        )));
    }

    #[test]
    fn external_ports_preserve_sender_and_target_lifecycle() {
        let sender = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"sender","name":"Sender","version":"1","background":{"service_worker":"background.js"}}"#,
        )
        .unwrap();
        let receiver = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"receiver","name":"Receiver","version":"1","externally_connectable":{"ids":["sender"]},"background":{"service_worker":"background.js"}}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry
            .install_with_resources(
                sender,
                HashMap::from([(String::from("background.js"), String::new())]),
            )
            .unwrap();
        registry
            .install_with_resources(
                receiver,
                HashMap::from([(String::from("background.js"), String::new())]),
            )
            .unwrap();

        registry
            .dispatch_external_port_connect("sender", "receiver", "port-1".into(), "wallet".into())
            .unwrap();
        let events = registry.drain_background_events("receiver");
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            ExtensionEventKind::RuntimeExternalPortConnected {
                sender_extension_id,
                port_id,
                name,
            } if sender_extension_id == "sender" && port_id == "port-1" && name == "wallet"
        )));

        registry
            .dispatch_external_port_message(
                "receiver",
                "sender",
                "port-1".into(),
                json!({"ready": true}),
            )
            .unwrap();
        let events = registry.drain_background_events("sender");
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            ExtensionEventKind::RuntimeExternalPortMessage {
                sender_extension_id,
                port_id,
                payload,
            } if sender_extension_id == "receiver"
                && port_id == "port-1"
                && payload == &json!({"ready": true})
        )));

        registry
            .dispatch_external_port_disconnect("receiver", "sender", "port-1".into())
            .unwrap();
        let events = registry.drain_background_events("sender");
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            ExtensionEventKind::RuntimeExternalPortDisconnected {
                sender_extension_id,
                port_id,
            } if sender_extension_id == "receiver" && port_id == "port-1"
        )));
    }

    #[test]
    fn alarms_fire_once_and_periodic_alarms_reschedule() {
        let manifest = ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"clock","name":"Clock","version":"1","permissions":["alarms"],"background":{"service_worker":"background.js"}}"#,
        )
        .unwrap();
        let mut registry = ExtensionRegistry::default();
        registry
            .install_with_resources(
                manifest,
                HashMap::from([(String::from("background.js"), String::new())]),
            )
            .unwrap();
        registry
            .grant("clock", ExtensionPermission::Alarms)
            .unwrap();
        registry.schedule_alarm("clock", "once", 10, None).unwrap();
        registry
            .schedule_alarm("clock", "repeat", 10, Some(10))
            .unwrap();
        assert_eq!(registry.poll_due_alarms(9).len(), 0);
        assert_eq!(registry.poll_due_alarms(10).len(), 2);
        assert_eq!(registry.poll_due_alarms(10).len(), 0);
        assert_eq!(registry.poll_due_alarms(20).len(), 1);
    }
    #[test]
    fn web_request_header_mutations_fold_case_and_reject_framing() {
        let mut headers = HeaderMap::from_iter([
            (
                HeaderName::from_static("x-test"),
                HeaderValue::from_static("old"),
            ),
            (
                HeaderName::from_static("x-remove"),
                HeaderValue::from_static("yes"),
            ),
        ]);
        apply_web_request_header_mutations(
            &mut headers,
            &json!({"requestHeaders": [
                {"name": "X-TEST", "value": "new"},
                {"name": "x-remove", "value": ""}
            ]}),
        )
        .unwrap();
        assert_eq!(headers.get("x-test").unwrap(), "new");
        assert!(!headers.contains_key("x-remove"));
        assert!(apply_web_request_header_mutations(
            &mut headers,
            &json!({"requestHeaders": [{"name": "Host", "value": "evil"}]})
        )
        .is_err());
    }

    fn oauth_manifest() -> ExtensionManifest {
        ExtensionManifest::from_json(
            r#"{"id":"ext","name":"Ext","version":"1","permissions":["identity"],
                "oauth2":{"client_id":"client-1","scopes":["openid","email"]}}"#,
        )
        .unwrap()
    }

    fn token_record(stored_at_ms: u64) -> OAuthTokenRecord {
        OAuthTokenRecord {
            access_token: "secret-access".to_owned(),
            refresh_token: Some("secret-refresh".to_owned()),
            expires_at_ms: stored_at_ms + 1_800_000,
            scopes: vec!["openid".to_owned()],
            account_id: Some("acct".to_owned()),
            stored_at_ms,
        }
    }

    fn pending_flow(extension_id: &str, redirect_uri: &str, created_at_ms: u64) -> PendingAuthFlow {
        PendingAuthFlow {
            flow_id: format!("flow-{redirect_uri}"),
            extension_id: extension_id.to_owned(),
            request_id: "request-1".to_owned(),
            kind: PendingAuthFlowKind::LaunchWebAuthFlow,
            auth_url: "https://provider.test/authorize".to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            state: None,
            code_verifier: None,
            token_key: None,
            created_at_ms,
        }
    }

    #[test]
    fn manifests_parse_and_validate_oauth2_provider_config() {
        let manifest = oauth_manifest();
        let config = manifest.oauth2.as_ref().unwrap();
        assert_eq!(config.client_id, "client-1");
        assert_eq!(config.scopes, vec!["openid", "email"]);
        assert!(manifest
            .permissions
            .contains(&super::ExtensionPermission::Identity));
    }

    #[test]
    fn sign_in_transitions_only_fire_on_real_changes() {
        let mut registry = ExtensionRegistry::default();
        assert_eq!(
            registry.set_oauth_account("ext", Some("acct-1".to_owned())),
            Some(("acct-1".to_owned(), true))
        );
        assert!(registry
            .set_oauth_account("ext", Some("acct-1".to_owned()))
            .is_none());
        assert_eq!(
            registry.set_oauth_account("ext", None),
            Some(("acct-1".to_owned(), false))
        );
        assert!(registry.set_oauth_account("ext", None).is_none());
        assert!(registry.oauth_account("ext").is_none());
    }

    #[test]
    fn oauth2_without_client_id_is_rejected() {
        let result = ExtensionManifest::from_json(
            r#"{"id":"ext","name":"Ext","version":"1",
                "oauth2":{"client_id":"  ","scopes":["openid"]}}"#,
        );
        assert!(matches!(result, Err(ExtensionError::InvalidManifest(_))));
    }

    #[test]
    fn oauth2_with_oversized_scopes_is_rejected() {
        let result = ExtensionManifest::from_json(
            r#"{"id":"ext","name":"Ext","version":"1",
                "oauth2":{"client_id":"c","scopes":["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]}}"#,
        );
        assert!(matches!(result, Err(ExtensionError::InvalidManifest(_))));
    }

    #[test]
    fn provider_configs_resolve_default_google_endpoints() {
        let manifest = oauth_manifest();
        let config = manifest.oauth2.as_ref().unwrap();
        assert_eq!(
            config.resolved_auth_endpoint(),
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(
            config.resolved_token_endpoint(),
            "https://oauth2.googleapis.com/token"
        );
    }

    #[test]
    fn oauth_token_store_is_bounded_and_keyed_per_grant() {
        let mut registry = ExtensionRegistry::default();
        let first = crate::oauth::token_key("ext", "client-1", &["openid".to_owned()]);
        let second = crate::oauth::token_key("ext", "client-1", &["email".to_owned()]);
        registry.store_oauth_token(first.clone(), token_record(1));
        assert!(registry.oauth_token_for_key(&first).is_some());
        for index in 0..80u64 {
            registry.store_oauth_token(format!("ext\u{0}client-{index}\u{0}"), token_record(index));
        }
        assert!(registry.oauth_token_for_key(&second).is_none());
        assert!(registry.oauth_token_for_key(&first).is_none());
        assert!(registry
            .oauth_token_for_key("ext\u{0}client-79\u{0}")
            .is_some());
        assert!(registry
            .take_oauth_token("ext\u{0}client-79\u{0}")
            .is_some());
        assert!(registry
            .oauth_token_for_key("ext\u{0}client-79\u{0}")
            .is_none());
    }

    #[test]
    fn pending_flows_match_redirects_and_expire() {
        let mut registry = ExtensionRegistry::default();
        registry
            .set_pending_auth_flow(pending_flow("ext", "https://ext.chromiumapp.org/", 1_000))
            .unwrap();
        let url = Url::parse("https://ext.chromiumapp.org/?code=abc&state=s").unwrap();
        let (flow_id, flow) = registry
            .pending_auth_flow_for_redirect(&url, 2_000)
            .unwrap();
        assert_eq!(flow_id, "flow-https://ext.chromiumapp.org/");
        assert_eq!(flow.extension_id, "ext");
        assert!(registry
            .pending_auth_flow_for_redirect(&url, 2_000)
            .is_none());

        registry
            .set_pending_auth_flow(pending_flow("ext", "https://ext.chromiumapp.org/", 1_000))
            .unwrap();
        let wrong_host = Url::parse("https://evil.example/?code=abc").unwrap();
        assert!(registry
            .pending_auth_flow_for_redirect(&wrong_host, 2_000)
            .is_none());
        let expired = registry.pending_auth_flow_for_redirect(&url, 1_000 + 6 * 60 * 1_000);
        assert!(expired.is_none(), "flows expire after the TTL");
    }

    #[test]
    fn pending_flows_are_bounded() {
        let mut registry = ExtensionRegistry::default();
        for index in 0..20u64 {
            registry
                .set_pending_auth_flow(pending_flow(
                    "ext",
                    &format!("https://redirect-{index}.chromiumapp.org/"),
                    index,
                ))
                .unwrap();
        }
        assert!(registry
            .pending_auth_flow_for_redirect(
                &Url::parse("https://redirect-0.chromiumapp.org/?code=1").unwrap(),
                0
            )
            .is_none());
        assert!(registry
            .pending_auth_flow_for_redirect(
                &Url::parse("https://redirect-9.chromiumapp.org/?code=1").unwrap(),
                9
            )
            .is_some());
        let _ = MAX_PENDING_AUTH_FLOWS;
    }

    #[test]
    fn uninstall_clears_identity_state() {
        let mut registry = ExtensionRegistry::default();
        registry.install(oauth_manifest()).unwrap();
        let key = crate::oauth::token_key("ext", "client-1", &["openid".to_owned()]);
        registry.store_oauth_token(key, token_record(1));
        registry
            .set_oauth_account("ext", Some("acct-1".to_owned()))
            .unwrap();
        registry
            .set_pending_auth_flow(pending_flow("ext", "https://ext.chromiumapp.org/", 1))
            .unwrap();
        registry.uninstall("ext").unwrap();
        assert!(registry.set_oauth_account("ext", None).is_none());
        assert!(registry
            .pending_auth_flow_for_redirect(
                &Url::parse("https://ext.chromiumapp.org/?code=1").unwrap(),
                2
            )
            .is_none());
    }

    #[test]
    fn snapshots_round_trip_provider_tokens() {
        let mut registry = ExtensionRegistry::default();
        registry.install(oauth_manifest()).unwrap();
        let key = crate::oauth::token_key("ext", "client-1", &["openid".to_owned()]);
        registry.store_oauth_token(key.clone(), token_record(7));
        let snapshot = registry.snapshot();
        let snapshot_json = snapshot.to_json().unwrap();
        let mut restored = ExtensionRegistry::default();
        restored
            .restore(ExtensionRegistrySnapshot::from_json(&snapshot_json).unwrap())
            .unwrap();
        let record = restored.oauth_token_for_key(&key).unwrap();
        assert_eq!(record.access_token, "secret-access");
        assert_eq!(record.account_id.as_deref(), Some("acct"));
        let _ = PkcePair {
            verifier: String::new(),
            challenge: String::new(),
        };
        let _ = generate_pkce_pair();
    }
}
