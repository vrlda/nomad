#![allow(clippy::missing_errors_doc)]

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use nomad_engine::extensions::{
    WebRequestBlockingDecision, WebRequestBlockingHandler, WebRequestBlockingRequest,
};
use nomad_engine::{
    extension_api_request, extension_resource_uri, Bookmark, BookmarkError, BookmarkFolder,
    BookmarkFolderId, BookmarkId, BookmarkManager, BrowserRuntime, Container, ContainerId,
    DevToolsSnapshot, DevToolsStore, DownloadError, DownloadId, DownloadManager, DownloadRequest,
    DownloadSnapshot, DownloadState, EncryptedSyncCodec, EncryptedSyncStore, ExtensionApiRequest,
    ExtensionError, ExtensionEventKind, ExtensionFrame, ExtensionFrameRegistry,
    ExtensionFrameTarget, ExtensionManifest, ExtensionPermission, ExtensionRegistry,
    FileSyncTransport, HistoryVisit, MemoryDiagnostics, MemoryManager, MemoryMode, NavigationError,
    NetworkRequestRecord, OAuthTokenRecord, OsCredentialStore, PageRenderer, PermissionDecision,
    PermissionKind, PermissionManager, PermissionPromptId, ReaderDocument, ReaderMode, RenderError,
    ResolverEngine, ResolverSettings, SplitError, SplitLayout, SplitOrientation, SplitPaneId,
    SyncConflict, SyncConflictChoice, SyncCryptoError, SyncKeyMaterial, TabActivity, TabContext,
    TabError, TabId, TabLifecycle, TabMemorySource, TabSnapshot, TabState, Workspace,
    WorkspaceError, WorkspaceId, WorkspaceManager,
};
use serde::{Deserialize, Serialize};
use url::Url;

mod address;
mod session;
mod settings;

pub use address::{
    normalize_address_input, AddressInputError, BrowserCommand, UniversalSuggestion,
    UniversalSuggestionKind, UniversalTarget,
};
pub use nomad_engine::{
    ExtensionBackgroundInfo, ExtensionEvent, ExtensionMessage, ExtensionTabInfo, PrivacyMode,
};
pub use session::{
    SessionBookmark, SessionError, SessionHistoryVisit, SessionPermissionRule, SessionSnapshot,
    SessionTab, SessionTabGroup,
};
pub use settings::BrowserSettings;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddressBarState {
    input: String,
}

impl AddressBarState {
    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn set_input(&mut self, input: &str) {
        input.clone_into(&mut self.input);
    }

    pub fn clear(&mut self) {
        self.input.clear();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerticalTabSidebarState {
    visible: bool,
    collapsed: bool,
    tab_ids: Vec<TabId>,
    active_tab: Option<TabId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TabSearchResult {
    pub id: TabId,
    pub url: Option<url::Url>,
    pub state: TabState,
    pub lifecycle: TabLifecycle,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionPrompt {
    pub id: PermissionPromptId,
    pub site: String,
    pub kind: PermissionKind,
}

impl Default for VerticalTabSidebarState {
    fn default() -> Self {
        Self {
            visible: true,
            collapsed: false,
            tab_ids: Vec::new(),
            active_tab: None,
        }
    }
}

impl VerticalTabSidebarState {
    #[must_use]
    pub const fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    #[must_use]
    pub const fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    pub fn set_collapsed(&mut self, collapsed: bool) {
        self.collapsed = collapsed;
    }

    #[must_use]
    pub fn tab_ids(&self) -> &[TabId] {
        &self.tab_ids
    }

    #[must_use]
    pub const fn active_tab(&self) -> Option<TabId> {
        self.active_tab
    }

    fn sync_from_runtime(&mut self, runtime: &BrowserRuntime) {
        self.tab_ids = runtime.tabs().iter().map(|tab| tab.id).collect();
        self.active_tab = runtime.active_tab();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShellError {
    NoActiveTab,
    MissingTab(TabId),
    Navigation(NavigationError),
    Download(DownloadError),
    Bookmark(BookmarkError),
    Session(SessionError),
    Permission(PermissionPromptId),
    Renderer(String),
    ActiveTabCannotBeSuspended(TabId),
    Workspace(WorkspaceError),
    Split(SplitError),
    MissingTabGroup(u64),
    Sync(SyncCryptoError),
    Credential(String),
    Extension(ExtensionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    pub enabled: bool,
    pub provider: String,
    pub endpoint: String,
    pub key_fingerprint: Option<String>,
    pub pending_uploads: usize,
    pub conflicts: usize,
    pub pending_conflicts: Vec<SyncConflict>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SyncPayload {
    settings: Option<BrowserSettings>,
    bookmarks: Option<Vec<SessionBookmark>>,
    bookmark_folders: Option<Vec<String>>,
    history: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionNotification {
    pub id: String,
    pub extension_id: String,
    pub title: String,
    pub message: String,
}
pub struct BlockingDecision {
    pub url: String,
    pub method: String,
    pub cancel: bool,
    pub redirect_url: Option<String>,
    pub request_headers: Option<Vec<(String, String)>>,
    pub response_headers: Option<Vec<(String, String)>>,
}

struct WebRequestBlockingAdapter {
    registry: Arc<Mutex<ExtensionRegistry>>,
    decisions: Arc<Mutex<Vec<BlockingDecision>>>,
}

impl WebRequestBlockingHandler for WebRequestBlockingAdapter {
    fn decide(&self, request: &WebRequestBlockingRequest) -> WebRequestBlockingDecision {
        let Ok(url) = Url::parse(&request.url) else {
            return WebRequestBlockingDecision::default();
        };
        let ids = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .web_request_blocking_extension_ids();
        for id in ids {
            let _ = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .dispatch_web_request(
                    &id,
                    "web_request",
                    serde_json::json!({
                        "url": request.url,
                        "method": request.method,
                        "requestHeaders": request.headers,
                        "requestBody": if request.request_body_unavailable {
                            serde_json::json!({"redacted": true, "reason": "unavailable"})
                        } else if request.request_body_size.is_some_and(|size| size > 64 * 1024) {
                            serde_json::json!({"redacted": true, "reason": "size"})
                        } else {
                            serde_json::Value::Null
                        },
                        "isMainFrame": request.is_for_main_frame,
                    }),
                    Some(&url),
                );
        }
        let mut decisions = self
            .decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = decisions.iter().position(|decision| {
            decision.url == request.url && decision.method.eq_ignore_ascii_case(&request.method)
        }) else {
            return WebRequestBlockingDecision::default();
        };
        let decision = decisions.remove(index);
        WebRequestBlockingDecision {
            cancel: decision.cancel,
            redirect_url: decision.redirect_url,
            request_headers: decision.request_headers,
            response_headers: decision.response_headers,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TabGroup {
    pub id: u64,
    pub title: Option<String>,
    pub color: String,
    pub collapsed: bool,
    pub tab_ids: Vec<TabId>,
}

/// Read-only group snapshot for the chrome sidebar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TabGroupInfo {
    pub id: u64,
    pub title: Option<String>,
    pub color: String,
    pub collapsed: bool,
    pub tab_ids: Vec<TabId>,
}

struct PendingExtensionScreenshot {
    extension_id: String,
    request_id: String,
}

struct ProviderGrantRequest<'a> {
    extension_id: &'a str,
    provider: &'a nomad_engine::OAuthProviderConfig,
    key: &'a str,
    expired: Option<OAuthTokenRecord>,
    interactive: bool,
    request_id: &'a str,
}

pub struct ShellState {
    identity_account_token: Option<String>,
    /// Authorization flows awaiting their provider redirect, by flow tab.
    pending_auth_flow_tabs: HashMap<TabId, String>,
    /// Token-endpoint transport for provider-backed `identity` flows.
    oauth_token_exchange: Arc<dyn nomad_engine::TokenExchange>,
    web_request_blocking_decisions: Arc<Mutex<Vec<BlockingDecision>>>,
    runtime: BrowserRuntime,
    address_bar: AddressBarState,
    sidebar: VerticalTabSidebarState,
    downloads: DownloadManager,
    bookmarks: BookmarkManager,
    settings: BrowserSettings,
    permissions: PermissionManager,
    pending_permissions: Vec<PermissionPrompt>,
    memory: MemoryManager,
    workspaces: WorkspaceManager,
    /// The active resolver engine: the active workspace's pinned override
    /// when present, otherwise the global settings. Hot-swapped in place.
    resolver: ResolverEngine,
    split_layout: SplitLayout,
    reader_modes: std::collections::HashMap<TabId, ReaderMode>,
    reader_documents: std::collections::HashMap<TabId, ReaderDocument>,
    devtools: std::collections::HashMap<TabId, DevToolsStore>,
    extensions: Arc<Mutex<ExtensionRegistry>>,
    extension_frames: ExtensionFrameRegistry,
    extension_notifications: Vec<ExtensionNotification>,
    next_extension_notification_id: u64,
    native_hosts: HashMap<String, PathBuf>,
    extension_ports: HashSet<(String, u64, String)>,
    external_extension_ports: HashSet<(String, String, String)>,
    tab_groups: HashMap<u64, TabGroup>,
    next_tab_group_id: u64,
    pending_extension_screenshots: HashMap<TabId, PendingExtensionScreenshot>,
    sync_key_material: Option<SyncKeyMaterial>,
    sync_store: Option<EncryptedSyncStore<FileSyncTransport>>,
    sync_conflicts: Vec<SyncConflict>,
    sync_device_id: String,
}

impl ShellState {
    /// Sidebar group color palette, rotated by group id. Values match the
    /// extension `tabGroups` color vocabulary.
    const GROUP_COLORS: [&'static str; 8] = [
        "blue", "cyan", "green", "yellow", "orange", "red", "pink", "purple",
    ];

    /// Bounds for event-grown Vecs on `ShellState`. Each drops its oldest
    /// entries so a long session or a blocked consumer cannot grow them
    /// without limit.
    const MAX_BLOCKING_DECISIONS: usize = 256;
    const MAX_EXTENSION_NOTIFICATIONS: usize = 64;
    const MAX_SYNC_CONFLICTS: usize = 128;
    const SYNC_KEY_ORIGIN: &'static str = "https://sync.nomad.invalid";
    const SYNC_KEY_SERVICE: &'static str = "org.nomad.browser.sync";

    #[must_use]
    pub fn new(runtime: BrowserRuntime) -> Self {
        Self::from_parts(
            runtime,
            BrowserSettings::default(),
            PathBuf::from("downloads"),
        )
    }

    #[must_use]
    pub fn with_download_directory(runtime: BrowserRuntime, directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        let settings = BrowserSettings {
            download_directory: directory.clone(),
            ..BrowserSettings::default()
        };
        Self::from_parts(runtime, settings, directory)
    }

    #[must_use]
    pub fn with_settings(runtime: BrowserRuntime, settings: BrowserSettings) -> Self {
        Self::from_parts(runtime, settings.clone(), settings.download_directory)
    }

    fn from_parts(
        mut runtime: BrowserRuntime,
        settings: BrowserSettings,
        download_directory: PathBuf,
    ) -> Self {
        let first_tab = runtime.new_tab();
        runtime.set_history_enabled(settings.history_enabled());
        let mut workspaces = WorkspaceManager::new();
        let default_workspace = workspaces.active_workspace();
        let default_container = workspaces.containers()[0].id;
        let _ = workspaces.assign_tab(first_tab, default_workspace, default_container);
        let resolver = Self::resolver_engine_for(&settings, &workspaces);
        let mut shell = Self {
            identity_account_token: None,
            pending_auth_flow_tabs: HashMap::new(),
            oauth_token_exchange: Arc::new(nomad_engine::HttpsTokenClient),
            web_request_blocking_decisions: Arc::new(Mutex::new(Vec::new())),
            runtime,
            address_bar: AddressBarState::default(),
            sidebar: VerticalTabSidebarState::default(),
            downloads: DownloadManager::new(download_directory),
            bookmarks: BookmarkManager::default(),
            settings,
            permissions: PermissionManager::default(),
            pending_permissions: Vec::new(),
            memory: MemoryManager::default(),
            workspaces,
            resolver,
            split_layout: SplitLayout::single(first_tab),
            reader_modes: std::collections::HashMap::new(),
            reader_documents: std::collections::HashMap::new(),
            devtools: std::collections::HashMap::new(),
            extensions: Arc::new(Mutex::new(ExtensionRegistry::default())),
            extension_frames: ExtensionFrameRegistry::default(),
            extension_notifications: Vec::new(),
            next_extension_notification_id: 1,
            native_hosts: HashMap::new(),
            extension_ports: HashSet::new(),
            external_extension_ports: HashSet::new(),
            tab_groups: HashMap::new(),
            next_tab_group_id: 1,
            pending_extension_screenshots: HashMap::new(),
            sync_key_material: None,
            sync_store: None,
            sync_conflicts: Vec::new(),
            sync_device_id: format!("desktop-{}", std::process::id()),
        };
        shell.sync_sidebar();
        shell
    }

    #[must_use]
    pub fn tabs(&self) -> &[TabSnapshot] {
        self.runtime.tabs()
    }

    #[must_use]
    pub const fn active_tab(&self) -> Option<TabId> {
        self.runtime.active_tab()
    }

    #[must_use]
    pub fn active_url(&self) -> Option<&Url> {
        self.active_tab()
            .and_then(|tab_id| self.tab(tab_id))
            .and_then(|tab| tab.url.as_ref())
    }

    fn active_credential_origin(&self) -> Result<String, ShellError> {
        let url = self
            .active_url()
            .ok_or_else(|| ShellError::Credential("the active page has no site origin".into()))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(ShellError::Credential(
                "saved credentials are limited to HTTP(S) site origins".into(),
            ));
        }
        Ok(url.origin().ascii_serialization())
    }

    pub fn save_active_credential(&self, username: &str, password: &str) -> Result<(), ShellError> {
        let origin = self.active_credential_origin()?;
        OsCredentialStore::default()
            .save(&origin, username, password)
            .map_err(|error| ShellError::Credential(error.to_string()))
    }

    pub fn load_active_credential(&self, username: &str) -> Result<String, ShellError> {
        let origin = self.active_credential_origin()?;
        OsCredentialStore::default()
            .load(&origin, username)
            .map_err(|error| ShellError::Credential(error.to_string()))?
            .ok_or_else(|| {
                ShellError::Credential("no saved credential matches this username".into())
            })
    }

    #[must_use]
    pub fn workspaces(&self) -> &[Workspace] {
        self.workspaces.workspaces()
    }

    #[must_use]
    pub fn workspace(&self, id: WorkspaceId) -> Option<&Workspace> {
        self.workspaces.workspace(id)
    }

    #[must_use]
    pub fn containers(&self) -> &[Container] {
        self.workspaces.containers()
    }

    #[must_use]
    pub const fn active_workspace(&self) -> WorkspaceId {
        self.workspaces.active_workspace()
    }

    /// The active resolver engine. Its configuration is the active
    /// workspace's pinned override when present, otherwise the global
    /// browser resolver settings.
    #[must_use]
    pub fn resolver(&self) -> &ResolverEngine {
        &self.resolver
    }

    /// The resolver configuration currently governing resolution: the
    /// active workspace's pinned override when present, otherwise the
    /// global settings.
    #[must_use]
    pub fn effective_resolver_settings(&self) -> ResolverSettings {
        let global = &self.settings.resolver;
        self.workspace(self.active_workspace()).map_or_else(
            || global.clone(),
            |workspace| workspace.effective_resolver(global).clone(),
        )
    }

    /// Whether the active workspace pins a resolver override. Surfaced
    /// so the UI can show which configuration actually governs
    /// resolution.
    #[must_use]
    pub fn resolver_override_active(&self) -> bool {
        self.workspace(self.active_workspace())
            .is_some_and(|workspace| workspace.resolver.is_some())
    }

    /// Rebuilds the engine configuration from the current settings and
    /// active workspace without dropping the engine.
    ///
    /// The fallback chain here is config-validation only: it fires when a
    /// configuration is unusable (`ResolverError::InvalidConfig`), trying
    /// the global settings and finally the platform resolver so a broken
    /// override never leaves the engine without a working transport.
    /// Runtime transport failures never reach this path — an explicit-mode
    /// resolver that fails at query time fails closed instead (see the
    /// `nomad_engine::dns` module docs), so a navigation fails rather
    /// than leaking the hostname to the system resolver.
    fn sync_resolver(&mut self) {
        let effective = self.effective_resolver_settings();
        if self.resolver.apply_settings(&effective).is_ok() {
            return;
        }
        if self
            .resolver
            .apply_settings(&self.settings.resolver)
            .is_ok()
        {
            eprintln!("Nomad workspace DNS override rejected; using the global resolver");
            return;
        }
        eprintln!("Nomad global DNS resolver invalid; using the platform resolver");
        self.resolver = ResolverEngine::default();
    }

    /// Builds the engine for `settings` as seen from `workspaces`. An
    /// unusable configuration (e.g. a persisted invalid server) falls
    /// back to the platform resolver rather than failing shell
    /// construction. This is config-validation only: runtime transport
    /// failures fail closed and never substitute the platform resolver.
    fn resolver_engine_for(
        settings: &BrowserSettings,
        workspaces: &WorkspaceManager,
    ) -> ResolverEngine {
        let global = &settings.resolver;
        let effective = workspaces
            .workspace(workspaces.active_workspace())
            .map_or(global, |workspace| workspace.effective_resolver(global));
        ResolverEngine::from_settings(effective).unwrap_or_default()
    }

    /// Pins (or clears) a workspace resolver override. `None` makes the
    /// workspace inherit the global resolver settings. Changing the active
    /// workspace's override hot-swaps the engine immediately.
    pub fn set_workspace_resolver(
        &mut self,
        id: WorkspaceId,
        resolver: Option<ResolverSettings>,
    ) -> Result<(), ShellError> {
        self.workspaces
            .set_resolver(id, resolver)
            .map_err(ShellError::Workspace)?;
        if id == self.active_workspace() {
            self.sync_resolver();
        }
        Ok(())
    }

    #[must_use]
    pub fn tab_context(&self, tab_id: TabId) -> TabContext {
        self.workspaces.tab_context(tab_id)
    }

    #[must_use]
    pub fn workspace_tabs(&self, workspace_id: WorkspaceId) -> Vec<TabId> {
        self.tabs()
            .iter()
            .filter(|tab| self.workspaces.tab_belongs_to(tab.id, workspace_id))
            .map(|tab| tab.id)
            .collect()
    }

    /// Creates a workspace. New tabs inherit the active workspace and default
    /// storage container until explicitly moved.
    pub fn create_workspace(&mut self, name: impl Into<String>) -> Result<WorkspaceId, ShellError> {
        self.workspaces
            .create_workspace(name)
            .map_err(ShellError::Workspace)
    }

    pub fn select_workspace(&mut self, id: WorkspaceId) -> Result<(), ShellError> {
        self.workspaces
            .select_workspace(id)
            .map_err(ShellError::Workspace)?;
        if let Some(tab_id) = self.workspace_tabs(id).first().copied() {
            self.runtime.select_tab(tab_id).map_err(map_tab_error)?;
            self.sync_sidebar();
            self.sync_address_bar();
        }
        self.sync_resolver();
        Ok(())
    }

    pub fn select_workspace_with_renderer<R: PageRenderer>(
        &mut self,
        id: WorkspaceId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.workspaces
            .select_workspace(id)
            .map_err(ShellError::Workspace)?;
        if let Some(tab_id) = self.workspace_tabs(id).first().copied() {
            self.select_tab_with_renderer(tab_id, renderer)?;
        } else {
            let tab_id = self.new_tab();
            self.select_tab_with_renderer(tab_id, renderer)?;
        }
        self.sync_resolver();
        Ok(())
    }

    pub fn create_container(
        &mut self,
        name: impl Into<String>,
        ephemeral: bool,
    ) -> Result<ContainerId, ShellError> {
        self.workspaces
            .create_container(name, ephemeral)
            .map_err(ShellError::Workspace)
    }

    pub fn assign_tab_context(
        &mut self,
        tab_id: TabId,
        workspace_id: WorkspaceId,
        container_id: ContainerId,
    ) -> Result<(), ShellError> {
        if self.tab(tab_id).is_none() {
            return Err(ShellError::MissingTab(tab_id));
        }
        self.workspaces
            .assign_tab(tab_id, workspace_id, container_id)
            .map_err(ShellError::Workspace)
    }

    /// Moves the active tab into a different storage container and rebuilds
    /// its renderer context before reloading the current document.
    ///
    /// This is the user-facing container boundary: cookies, storage, cache,
    /// permissions, and extension content contexts must not survive a
    /// container switch by accident.
    pub fn assign_active_tab_to_container_with_renderer<R: PageRenderer>(
        &mut self,
        container_id: ContainerId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        let workspace_id = self.tab_context(tab_id).workspace_id;
        let container = self
            .workspaces
            .container(container_id)
            .ok_or(ShellError::Workspace(WorkspaceError::MissingContainer(
                container_id,
            )))?;
        renderer
            .configure_tab(tab_id, container_id, container.ephemeral)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        self.workspaces
            .assign_tab(tab_id, workspace_id, container_id)
            .map_err(ShellError::Workspace)?;
        if self.tab(tab_id).and_then(|tab| tab.url.as_ref()).is_some() {
            self.runtime
                .reload_tab_with_renderer(tab_id, renderer)
                .map_err(ShellError::Navigation)?;
        }
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    #[must_use]
    pub const fn split_layout(&self) -> &SplitLayout {
        &self.split_layout
    }

    pub fn split_tab(
        &mut self,
        tab_id: TabId,
        orientation: SplitOrientation,
    ) -> Result<SplitPaneId, ShellError> {
        self.split_layout
            .split(tab_id, orientation)
            .map_err(ShellError::Split)
    }

    pub fn activate_split_pane<R: PageRenderer>(
        &mut self,
        pane_id: SplitPaneId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let tab_id = self
            .split_layout
            .activate(pane_id)
            .map_err(ShellError::Split)?;
        self.select_tab_with_renderer(tab_id, renderer)
    }

    pub fn close_split_pane(&mut self, pane_id: SplitPaneId) -> Result<TabId, ShellError> {
        self.split_layout.close(pane_id).map_err(ShellError::Split)
    }

    /// Splits the pane currently holding `pane_id`, inserting `tab_id` as a
    /// new pane beside it. Splitting individual panes is what allows
    /// mixed-orientation arrangements (rows inside a column and vice versa).
    pub fn split_pane(
        &mut self,
        pane_id: SplitPaneId,
        tab_id: TabId,
        orientation: SplitOrientation,
    ) -> Result<SplitPaneId, ShellError> {
        self.split_layout
            .split_pane(pane_id, tab_id, orientation)
            .map_err(ShellError::Split)
    }

    #[must_use]
    pub fn tab_groups(&self) -> Vec<TabGroupInfo> {
        self.tab_groups
            .values()
            .map(|group| TabGroupInfo {
                id: group.id,
                title: group.title.clone(),
                color: group.color.clone(),
                collapsed: group.collapsed,
                tab_ids: group.tab_ids.clone(),
            })
            .collect()
    }

    #[must_use]
    pub fn tab_group_of(&self, tab_id: TabId) -> Option<u64> {
        self.tab_groups
            .values()
            .find(|group| group.tab_ids.contains(&tab_id))
            .map(|group| group.id)
    }

    /// Creates a user-facing tab group containing `tab_id` and returns its
    /// id. Groups holding no tabs are pruned, so the number of groups is
    /// bounded by the number of open tabs.
    pub fn create_tab_group(&mut self, tab_id: TabId) -> Result<u64, ShellError> {
        if self.tab(tab_id).is_none() {
            return Err(ShellError::MissingTab(tab_id));
        }
        let group_id = self.next_tab_group_id;
        self.next_tab_group_id = self.next_tab_group_id.saturating_add(1).max(1);
        self.tab_groups.insert(
            group_id,
            TabGroup {
                id: group_id,
                title: Some(format!("Group {group_id}")),
                color: Self::GROUP_COLORS[usize::try_from(group_id.saturating_sub(1)).unwrap_or(0)
                    % Self::GROUP_COLORS.len()]
                .to_owned(),
                collapsed: false,
                tab_ids: vec![tab_id],
            },
        );
        Self::remove_tabs_from_other_groups(&mut self.tab_groups, group_id, &[tab_id]);
        Ok(group_id)
    }

    pub fn add_tab_to_group(&mut self, group_id: u64, tab_id: TabId) -> Result<(), ShellError> {
        if self.tab(tab_id).is_none() {
            return Err(ShellError::MissingTab(tab_id));
        }
        if !self.tab_groups.contains_key(&group_id) {
            return Err(ShellError::MissingTabGroup(group_id));
        }
        Self::remove_tabs_from_other_groups(&mut self.tab_groups, group_id, &[tab_id]);
        if let Some(group) = self.tab_groups.get_mut(&group_id) {
            if !group.tab_ids.contains(&tab_id) {
                group.tab_ids.push(tab_id);
            }
        }
        Ok(())
    }

    /// Removes a tab from whichever group holds it. Missing membership is
    /// not an error so close paths can call this unconditionally.
    pub fn remove_tab_from_group(&mut self, tab_id: TabId) -> Result<(), ShellError> {
        if self.tab(tab_id).is_none() {
            return Err(ShellError::MissingTab(tab_id));
        }
        Self::remove_tabs_from_other_groups(&mut self.tab_groups, 0, &[tab_id]);
        self.tab_groups.retain(|_, group| !group.tab_ids.is_empty());
        Ok(())
    }

    pub fn set_tab_group_collapsed(
        &mut self,
        group_id: u64,
        collapsed: bool,
    ) -> Result<(), ShellError> {
        let group = self
            .tab_groups
            .get_mut(&group_id)
            .ok_or(ShellError::MissingTabGroup(group_id))?;
        group.collapsed = collapsed;
        Ok(())
    }

    /// Dissolves a group; its tabs remain open and ungrouped.
    pub fn ungroup_tab_group(&mut self, group_id: u64) -> Result<(), ShellError> {
        self.tab_groups
            .remove(&group_id)
            .ok_or(ShellError::MissingTabGroup(group_id))?;
        Ok(())
    }

    /// Moves `tab_id` to the sidebar position currently occupied by
    /// `anchor`, persisting the order in the runtime tab list.
    pub fn reorder_tab(&mut self, tab_id: TabId, anchor: TabId) -> Result<(), ShellError> {
        self.runtime
            .move_tab(tab_id, anchor)
            .map_err(map_tab_error)?;
        self.sync_sidebar();
        Ok(())
    }

    #[must_use]
    pub fn reader_mode(&self, tab_id: TabId) -> ReaderMode {
        self.reader_modes
            .get(&tab_id)
            .copied()
            .unwrap_or(ReaderMode::Original)
    }

    #[must_use]
    pub fn reader_document(&self, tab_id: TabId) -> Option<&ReaderDocument> {
        self.reader_documents.get(&tab_id)
    }

    pub fn set_reader_document(
        &mut self,
        tab_id: TabId,
        document: ReaderDocument,
    ) -> Result<(), ShellError> {
        if self.tab(tab_id).is_none() {
            return Err(ShellError::MissingTab(tab_id));
        }
        self.reader_documents.insert(tab_id, document);
        Ok(())
    }

    pub fn toggle_reader_mode(&mut self, tab_id: TabId) -> Result<ReaderMode, ShellError> {
        if self.tab(tab_id).is_none() {
            return Err(ShellError::MissingTab(tab_id));
        }
        let next = match self.reader_mode(tab_id) {
            ReaderMode::Original => ReaderMode::Reader,
            ReaderMode::Reader => ReaderMode::Original,
        };
        self.reader_modes.insert(tab_id, next);
        Ok(next)
    }

    #[must_use]
    pub fn devtools_snapshot(&self, tab_id: TabId) -> Option<DevToolsSnapshot> {
        self.devtools.get(&tab_id).map(DevToolsStore::snapshot)
    }

    pub fn devtools_store_mut(&mut self, tab_id: TabId) -> Result<&mut DevToolsStore, ShellError> {
        if self.tab(tab_id).is_none() {
            return Err(ShellError::MissingTab(tab_id));
        }
        Ok(self.devtools.entry(tab_id).or_default())
    }

    pub fn clear_devtools(&mut self, tab_id: TabId) -> Result<(), ShellError> {
        self.devtools_store_mut(tab_id)?.clear();
        Ok(())
    }

    pub fn extensions(&self) -> MutexGuard<'_, ExtensionRegistry> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn extension_notifications(&self) -> &[ExtensionNotification] {
        &self.extension_notifications
    }

    pub fn clear_extension_notification(&mut self, id: &str) {
        self.extension_notifications
            .retain(|notification| notification.id != id);
    }

    /// Registers an explicitly allowlisted native messaging host. Nomad never
    /// resolves host names from extension input into arbitrary executables.
    pub fn register_native_host(
        &mut self,
        name: impl Into<String>,
        executable: impl Into<PathBuf>,
    ) -> Result<(), ShellError> {
        let name = name.into();
        let executable = executable.into();
        if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            return Err(ShellError::Renderer("native host name is invalid".into()));
        }
        let metadata = std::fs::metadata(&executable).map_err(|error| {
            ShellError::Renderer(format!("native host is unavailable: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(ShellError::Renderer("native host is not a file".into()));
        }
        self.native_hosts.insert(name, executable);
        Ok(())
    }

    pub fn install_extension(&mut self, manifest: ExtensionManifest) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install(manifest)
            .map_err(ShellError::Extension)
    }

    pub fn install_extension_with_resources(
        &mut self,
        manifest: ExtensionManifest,
        resources: HashMap<String, String>,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install_with_resources(manifest, resources)
            .map_err(ShellError::Extension)
    }

    pub fn install_extension_package(
        &mut self,
        manifest_json: &str,
        resources: HashMap<String, String>,
    ) -> Result<(), ShellError> {
        let package = nomad_engine::ExtensionPackage::from_manifest_json(manifest_json, resources)
            .map_err(ShellError::Extension)?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install_package(package)
            .map_err(ShellError::Extension)
    }

    pub fn install_extension_directory(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<(), ShellError> {
        let package =
            nomad_engine::ExtensionPackage::from_directory(path).map_err(ShellError::Extension)?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install_package(package)
            .map_err(ShellError::Extension)
    }

    pub fn install_extension_with_renderer<R: PageRenderer>(
        &mut self,
        manifest: ExtensionManifest,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let id = manifest.id.clone();
        self.install_extension(manifest)?;
        if let Err(error) = self
            .install_extension_resources_with_renderer(&id, renderer)
            .and_then(|()| self.install_background_with_renderer(&id, renderer))
            .and_then(|()| self.refresh_extension_scripts_with_renderer(renderer))
        {
            let _ = renderer.uninstall_extension(&id);
            let _ = self.uninstall_extension(&id);
            return Err(error);
        }
        Ok(())
    }

    pub fn install_extension_package_with_renderer<R: PageRenderer>(
        &mut self,
        manifest_json: &str,
        resources: HashMap<String, String>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let package = nomad_engine::ExtensionPackage::from_manifest_json(manifest_json, resources)
            .map_err(ShellError::Extension)?;
        let id = package.manifest().id.clone();
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install_package(package)
            .map_err(ShellError::Extension)?;
        if let Err(error) = self
            .install_extension_resources_with_renderer(&id, renderer)
            .and_then(|()| self.install_background_with_renderer(&id, renderer))
            .and_then(|()| self.refresh_extension_scripts_with_renderer(renderer))
        {
            let _ = renderer.uninstall_extension(&id);
            let _ = self.uninstall_extension(&id);
            return Err(error);
        }
        self.dispatch_management_event("installed", &id, renderer)?;
        Ok(())
    }

    pub fn update_extension_package_with_renderer<R: PageRenderer>(
        &mut self,
        package: nomad_engine::ExtensionPackage,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let id = package.manifest().id.clone();
        let previous = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot();
        let was_enabled = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_enabled(&id);
        let new_version = package.manifest().version.clone();
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .update_package(package)
            .map_err(ShellError::Extension)?;

        if was_enabled {
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id: id.clone(),
                    kind: nomad_engine::ExtensionEventKind::RuntimeUpdateAvailable {
                        version: new_version,
                    },
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id: id.clone(),
                    kind: nomad_engine::ExtensionEventKind::RuntimeSuspend,
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }

        let renderer_result = (|| {
            renderer
                .uninstall_extension(&id)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            if was_enabled {
                self.install_background_with_renderer(&id, renderer)?;
            } else {
                self.install_extension_resources_with_renderer(&id, renderer)?;
            }
            self.refresh_extension_scripts_with_renderer(renderer)
        })();
        if let Err(error) = renderer_result {
            let _ = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .restore(previous);
            let _ = renderer.uninstall_extension(&id);
            if was_enabled {
                let _ = self.install_background_with_renderer(&id, renderer);
            } else {
                let _ = self.install_extension_resources_with_renderer(&id, renderer);
            }
            let _ = self.refresh_extension_scripts_with_renderer(renderer);
            return Err(error);
        }
        self.dispatch_management_event("installed", &id, renderer)?;
        Ok(())
    }

    pub fn install_extension_archive_with_renderer<R: PageRenderer>(
        &mut self,
        bytes: &[u8],
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let package = nomad_engine::ExtensionPackage::from_archive_bytes(bytes)
            .map_err(ShellError::Extension)?;
        let id = package.manifest().id.clone();
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install_package(package)
            .map_err(ShellError::Extension)?;
        if let Err(error) = self
            .install_extension_resources_with_renderer(&id, renderer)
            .and_then(|()| self.install_background_with_renderer(&id, renderer))
            .and_then(|()| self.refresh_extension_scripts_with_renderer(renderer))
        {
            let _ = renderer.uninstall_extension(&id);
            let _ = self.uninstall_extension(&id);
            return Err(error);
        }
        self.dispatch_management_event("installed", &id, renderer)?;
        Ok(())
    }

    /// Installs an archive for an explicitly trusted browser-owned preload,
    /// granting its manifest-declared required permissions and host patterns.
    ///
    /// Ordinary extension installation remains permission-prompted through the
    /// normal install path. This variant is reserved for native test launches
    /// and other embedder-controlled package provisioning where the caller has
    /// already made that trust decision.
    pub fn install_extension_archive_with_renderer_and_grants<R: PageRenderer>(
        &mut self,
        bytes: &[u8],
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let package = nomad_engine::ExtensionPackage::from_archive_bytes(bytes)
            .map_err(ShellError::Extension)?;
        let manifest = package.manifest().clone();
        let id = manifest.id.clone();
        self.install_extension_package_with_renderer_from_package(package, renderer)?;
        for permission in manifest.permissions {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .grant(&id, permission)
                .map_err(ShellError::Extension)?;
        }
        for pattern in manifest.host_permissions {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .grant_host_permission(&id, &pattern)
                .map_err(ShellError::Extension)?;
        }
        self.refresh_extension_scripts_with_renderer(renderer)
    }

    fn install_extension_package_with_renderer_from_package<R: PageRenderer>(
        &mut self,
        package: nomad_engine::ExtensionPackage,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let id = package.manifest().id.clone();
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install_package(package)
            .map_err(ShellError::Extension)?;
        if let Err(error) = self
            .install_extension_resources_with_renderer(&id, renderer)
            .and_then(|()| self.install_background_with_renderer(&id, renderer))
            .and_then(|()| self.refresh_extension_scripts_with_renderer(renderer))
        {
            let _ = renderer.uninstall_extension(&id);
            let _ = self.uninstall_extension(&id);
            return Err(error);
        }
        self.dispatch_management_event("installed", &id, renderer)?;
        Ok(())
    }

    fn install_background_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.install_extension_resources_with_renderer(id, renderer)?;
        let background = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .background_script(id)
                .zip(registry.background_info(id))
        };
        if let Some((script, info)) = background {
            let (manifest, script_paths, storage) = {
                let registry = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    registry.manifest(id).ok_or_else(|| {
                        ShellError::Extension(ExtensionError::Missing(id.to_owned()))
                    })?,
                    registry.background_script_paths(id),
                    registry.storage_areas_snapshot(id).unwrap_or_default(),
                )
            };
            renderer
                .install_extension_background(
                    id,
                    &manifest,
                    &script,
                    info.kind == nomad_engine::ExtensionBackgroundKind::ServiceWorker,
                    &script_paths,
                    &storage,
                )
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            for event in self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain_background_events(id)
            {
                renderer
                    .dispatch_extension_event(&event)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
        }
        Ok(())
    }

    fn install_extension_resources_with_renderer<R: PageRenderer>(
        &self,
        id: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let resources = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resources_for(id);
        renderer
            .install_extension_resources(&resources)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))
    }

    pub fn refresh_extension_scripts_with_renderer<R: PageRenderer>(
        &self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        for tab in self.tabs().iter().filter(|tab| {
            tab.url.is_some()
                && !matches!(
                    tab.lifecycle,
                    nomad_engine::TabLifecycle::Suspended | nomad_engine::TabLifecycle::Archived
                )
        }) {
            let scripts = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .scripts_for_tab(&ExtensionTabInfo {
                    id: tab.id.get(),
                    url: tab.url.clone(),
                    active: self.active_tab() == Some(tab.id),
                });
            renderer
                .install_extension_scripts_for_tab(tab.id, &scripts)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    pub fn install_extension_archive(&mut self, bytes: &[u8]) -> Result<(), ShellError> {
        let package = nomad_engine::ExtensionPackage::from_archive_bytes(bytes)
            .map_err(ShellError::Extension)?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .install_package(package)
            .map_err(ShellError::Extension)
    }

    pub fn install_extension_archive_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<(), ShellError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|error| {
            ShellError::Extension(ExtensionError::InvalidManifest(format!(
                "cannot read extension archive: {error}"
            )))
        })?;
        self.install_extension_archive(&bytes)
    }

    pub fn update_extension_archive_with_renderer<R: PageRenderer>(
        &mut self,
        bytes: &[u8],
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let package = nomad_engine::ExtensionPackage::from_archive_bytes(bytes)
            .map_err(ShellError::Extension)?;
        self.update_extension_package_with_renderer(package, renderer)
    }

    pub fn update_extension_archive_file_with_renderer<R: PageRenderer>(
        &mut self,
        path: impl AsRef<Path>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|error| {
            ShellError::Extension(ExtensionError::InvalidManifest(format!(
                "cannot read extension update archive: {error}"
            )))
        })?;
        self.update_extension_archive_with_renderer(&bytes, renderer)
    }

    pub fn grant_extension_permission(
        &mut self,
        id: &str,
        permission: ExtensionPermission,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .grant(id, permission)
            .map_err(ShellError::Extension)
    }

    pub fn grant_extension_permission_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        permission: ExtensionPermission,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.grant_extension_permission(id, permission)?;
        self.refresh_extension_scripts_with_renderer(renderer)
    }

    pub fn grant_extension_host_permission(
        &mut self,
        id: &str,
        pattern: &str,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .grant_host_permission(id, pattern)
            .map_err(ShellError::Extension)
    }

    pub fn grant_extension_host_permission_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        pattern: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.grant_extension_host_permission(id, pattern)?;
        self.refresh_extension_scripts_with_renderer(renderer)
    }

    pub fn revoke_extension_permission(
        &mut self,
        id: &str,
        permission: ExtensionPermission,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revoke(id, permission)
            .map_err(ShellError::Extension)
    }

    pub fn revoke_extension_permission_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        permission: ExtensionPermission,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.revoke_extension_permission(id, permission)?;
        self.refresh_extension_scripts_with_renderer(renderer)
    }

    pub fn revoke_extension_host_permission(
        &mut self,
        id: &str,
        pattern: &str,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revoke_host_permission(id, pattern)
            .map_err(ShellError::Extension)
    }

    pub fn revoke_extension_host_permission_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        pattern: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.revoke_extension_host_permission(id, pattern)?;
        self.refresh_extension_scripts_with_renderer(renderer)
    }

    pub fn uninstall_extension(&mut self, id: &str) -> Result<ExtensionManifest, ShellError> {
        self.extension_ports
            .retain(|(extension_id, _, _)| extension_id != id);
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .uninstall(id)
            .map_err(ShellError::Extension)
    }

    pub fn uninstall_extension_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        renderer: &mut R,
    ) -> Result<ExtensionManifest, ShellError> {
        self.dispatch_management_event("uninstalled", id, renderer)?;
        if self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_enabled(id)
        {
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id: id.to_owned(),
                    kind: nomad_engine::ExtensionEventKind::RuntimeSuspend,
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        renderer
            .uninstall_extension(id)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        self.uninstall_extension(id)
    }

    #[must_use]
    pub fn extension_uninstall_url(&self, id: &str) -> Option<String> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .uninstall_url(id)
    }

    pub fn extension_storage_set(
        &mut self,
        id: &str,
        key: &str,
        value: serde_json::Value,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .storage_set(id, key, value)
            .map_err(ShellError::Extension)
    }

    pub fn extension_storage_get(
        &self,
        id: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .storage_get(id, key)
            .map_err(ShellError::Extension)
    }

    pub fn extension_storage_get_all(
        &self,
        id: &str,
    ) -> Result<HashMap<String, serde_json::Value>, ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .storage_get_all(id)
            .map_err(ShellError::Extension)
    }

    pub fn extension_storage_remove(&mut self, id: &str, key: &str) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .storage_remove(id, key)
            .map_err(ShellError::Extension)
    }

    pub fn extension_storage_clear(&mut self, id: &str) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .storage_clear(id)
            .map_err(ShellError::Extension)
    }

    pub fn extension_query_tabs(&self, id: &str) -> Result<Vec<ExtensionTabInfo>, ShellError> {
        let tabs = self
            .tabs()
            .iter()
            .map(|tab| ExtensionTabInfo {
                id: tab.id.get(),
                url: tab.url.clone(),
                active: self.active_tab() == Some(tab.id),
            })
            .collect::<Vec<_>>();
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .query_tabs(id, &tabs)
            .map_err(ShellError::Extension)
    }

    pub fn send_extension_message(
        &mut self,
        id: &str,
        tab_id: Option<TabId>,
        payload: serde_json::Value,
    ) -> Result<(), ShellError> {
        let target_url = tab_id
            .and_then(|id| self.tab(id))
            .and_then(|tab| tab.url.clone());
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send_message(id, tab_id.map(TabId::get), payload, target_url.as_ref())
            .map_err(ShellError::Extension)
    }

    pub fn receive_extension_message(
        &mut self,
        message: ExtensionMessage,
    ) -> Result<(), ShellError> {
        let tab_id = message.tab_id.map(TabId::new);
        let target_url = tab_id
            .and_then(|id| self.tab(id))
            .and_then(|tab| tab.url.clone());
        if message.tab_id.is_none() {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .receive_background_message(&message.extension_id, message.payload)
                .map_err(ShellError::Extension)
        } else {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .receive_page_message(
                    &message.extension_id,
                    message.tab_id,
                    message.payload,
                    target_url.as_ref(),
                )
                .map_err(ShellError::Extension)
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn receive_extension_message_with_renderer<R: PageRenderer>(
        &mut self,
        message: ExtensionMessage,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let extension_id = message.extension_id.clone();
        let tab_id = message.tab_id;
        let payload = message.payload.clone();
        if let Some(relay) = payload
            .get("__nomad_isolated_queue_message")
            .and_then(serde_json::Value::as_object)
        {
            let message_payload = relay.get("payload").cloned().ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "isolated-world queue relay requires a payload".into(),
                ))
            })?;
            return self.receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id,
                    tab_id,
                    payload: message_payload,
                },
                renderer,
            );
        }
        if let Some(error) = payload
            .get("__nomad_background_error")
            .and_then(serde_json::Value::as_str)
        {
            eprintln!("Nomad extension background script error ({extension_id}): {error}");
            return Ok(());
        }
        if let Some(relay) = payload
            .get("__nomad_isolated_world_message")
            .and_then(serde_json::Value::as_object)
        {
            let target_id = tab_id.ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "isolated-world message relay requires a tab id".into(),
                ))
            })?;
            let message_payload = relay.get("payload").cloned().ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "isolated-world message relay requires a payload".into(),
                ))
            })?;
            let target_origin = relay
                .get("target_origin")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("*");
            renderer
                .dispatch_extension_message(
                    TabId::new(target_id),
                    &extension_id,
                    &serde_json::json!({
                        "__nomad_page_dom_message_to_page": {
                            "payload": message_payload,
                            "target_origin": target_origin,
                        },
                    }),
                )
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            return Ok(());
        }
        if let Some(relay) = payload
            .get("__nomad_main_world_message")
            .and_then(serde_json::Value::as_object)
        {
            let target_id = relay
                .get("tab_id")
                .and_then(serde_json::Value::as_u64)
                .or(tab_id)
                .ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "main-world message relay requires a tab id".into(),
                    ))
                })?;
            let message_payload = relay.get("payload").cloned().ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "main-world message relay requires a payload".into(),
                ))
            })?;
            renderer
                .dispatch_extension_message(
                    TabId::new(target_id),
                    &extension_id,
                    &serde_json::json!({
                        "__nomad_page_dom_message_to_content": {
                            "payload": message_payload,
                        },
                    }),
                )
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            return Ok(());
        }
        let is_extension_port_message = payload
            .get("__nomad_extension_port_connect")
            .is_some_and(serde_json::Value::is_object)
            || payload
                .get("__nomad_extension_port_message")
                .is_some_and(serde_json::Value::is_object)
            || payload
                .get("__nomad_extension_port_disconnect")
                .is_some_and(serde_json::Value::is_object);
        if tab_id.is_none()
            || payload.get("__nomad_page_response").is_some()
            || is_extension_port_message
        {
            if let Some(port) = payload
                .get("__nomad_extension_port_connect")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = port
                    .get("target_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "runtime.connect requires a valid target extension id".into(),
                        ))
                    })?;
                let port_id = port
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "runtime.connect requires a valid port id".into(),
                        ))
                    })?;
                let name = port
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if name.len() > 128 || name.chars().any(char::is_control) {
                    return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                        "runtime.connect port name is invalid".into(),
                    )));
                }
                if target_id == extension_id {
                    if let Some(tab_id) = tab_id {
                        let target_url =
                            self.tab(TabId::new(tab_id)).and_then(|tab| tab.url.clone());
                        self.extensions
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .validate_background_page_message(&extension_id, target_url.as_ref())
                            .map_err(ShellError::Extension)?;
                        let key = (extension_id.clone(), tab_id, port_id.to_owned());
                        if self.extension_ports.insert(key) {
                            renderer
                                .dispatch_extension_event(&ExtensionEvent {
                                    extension_id: extension_id.clone(),
                                    kind: ExtensionEventKind::RuntimePortConnected {
                                        tab_id,
                                        port_id: port_id.to_owned(),
                                        name: name.to_owned(),
                                    },
                                })
                                .map_err(|error| {
                                    ShellError::Navigation(NavigationError::Render(error))
                                })?;
                        }
                        return Ok(());
                    }
                }
                let key = (
                    extension_id.clone(),
                    target_id.to_owned(),
                    port_id.to_owned(),
                );
                if self.external_extension_ports.insert(key) {
                    self.extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .dispatch_external_port_connect(
                            &extension_id,
                            target_id,
                            port_id.to_owned(),
                            name.to_owned(),
                        )
                        .map_err(ShellError::Extension)?;
                    for event in self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .drain_background_events(target_id)
                    {
                        renderer.dispatch_extension_event(&event).map_err(|error| {
                            ShellError::Navigation(NavigationError::Render(error))
                        })?;
                    }
                }
                return Ok(());
            }
            if let Some(port) = payload
                .get("__nomad_extension_port_message")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = port
                    .get("target_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "runtime port message requires a valid target extension id".into(),
                        ))
                    })?;
                let port_id = port
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "runtime port message requires a valid port id".into(),
                        ))
                    })?;
                if target_id == extension_id {
                    if let Some(tab_id) = tab_id {
                        if !self.extension_ports.contains(&(
                            extension_id.clone(),
                            tab_id,
                            port_id.to_owned(),
                        )) {
                            return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                                "runtime port is not connected".into(),
                            )));
                        }
                        let target_url =
                            self.tab(TabId::new(tab_id)).and_then(|tab| tab.url.clone());
                        self.extensions
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .validate_background_page_message(&extension_id, target_url.as_ref())
                            .map_err(ShellError::Extension)?;
                        renderer
                            .dispatch_extension_event(&ExtensionEvent {
                                extension_id: extension_id.clone(),
                                kind: ExtensionEventKind::RuntimePortMessage {
                                    tab_id,
                                    port_id: port_id.to_owned(),
                                    payload: port
                                        .get("payload")
                                        .cloned()
                                        .unwrap_or(serde_json::Value::Null),
                                },
                            })
                            .map_err(|error| {
                                ShellError::Navigation(NavigationError::Render(error))
                            })?;
                        return Ok(());
                    }
                }
                if !self.external_extension_ports.contains(&(
                    extension_id.clone(),
                    target_id.to_owned(),
                    port_id.to_owned(),
                )) && !self.external_extension_ports.contains(&(
                    target_id.to_owned(),
                    extension_id.clone(),
                    port_id.to_owned(),
                )) {
                    return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                        "runtime port is not connected".into(),
                    )));
                }
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .dispatch_external_port_message(
                        &extension_id,
                        target_id,
                        port_id.to_owned(),
                        port.get("payload")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                    )
                    .map_err(ShellError::Extension)?;
                for event in self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .drain_background_events(target_id)
                {
                    renderer
                        .dispatch_extension_event(&event)
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                }
                return Ok(());
            }
            if let Some(port) = payload
                .get("__nomad_extension_port_disconnect")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = port
                    .get("target_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "runtime port disconnect requires a valid target extension id".into(),
                        ))
                    })?;
                let port_id = port
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "runtime port disconnect requires a valid port id".into(),
                        ))
                    })?;
                let forward_key = (
                    extension_id.clone(),
                    target_id.to_owned(),
                    port_id.to_owned(),
                );
                let reverse_key = (
                    target_id.to_owned(),
                    extension_id.clone(),
                    port_id.to_owned(),
                );
                if target_id == extension_id {
                    if let Some(tab_id) = tab_id {
                        if self.extension_ports.remove(&(
                            extension_id.clone(),
                            tab_id,
                            port_id.to_owned(),
                        )) {
                            renderer
                                .dispatch_extension_event(&ExtensionEvent {
                                    extension_id: extension_id.clone(),
                                    kind: ExtensionEventKind::RuntimePortDisconnected {
                                        tab_id,
                                        port_id: port_id.to_owned(),
                                    },
                                })
                                .map_err(|error| {
                                    ShellError::Navigation(NavigationError::Render(error))
                                })?;
                        }
                        return Ok(());
                    }
                }
                if self.external_extension_ports.remove(&forward_key)
                    || self.external_extension_ports.remove(&reverse_key)
                {
                    self.extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .dispatch_external_port_disconnect(
                            &extension_id,
                            target_id,
                            port_id.to_owned(),
                        )
                        .map_err(ShellError::Extension)?;
                    for event in self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .drain_background_events(target_id)
                    {
                        renderer.dispatch_extension_event(&event).map_err(|error| {
                            ShellError::Navigation(NavigationError::Render(error))
                        })?;
                    }
                }
                return Ok(());
            }
            if let Some(response) = payload
                .get("__nomad_page_response")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = response
                    .get("tab_id")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension response requires a tab id".into(),
                        ))
                    })?;
                let request_id = response
                    .get("request_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|request_id| !request_id.is_empty() && request_id.len() <= 128)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension response requires a valid request id".into(),
                        ))
                    })?;
                let mut response_value = serde_json::Map::new();
                response_value.insert(
                    "request_id".into(),
                    serde_json::Value::String(request_id.to_owned()),
                );
                if let Some(error) = response.get("error") {
                    response_value.insert("error".into(), error.clone());
                } else {
                    response_value.insert(
                        "result".into(),
                        response
                            .get("result")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                    );
                }
                if tab_id.is_some() {
                    let result = if let Some(error) = response.get("error") {
                        Err(error.to_string())
                    } else {
                        Ok(response
                            .get("result")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null))
                    };
                    renderer
                        .dispatch_extension_event(&ExtensionEvent {
                            extension_id: extension_id.clone(),
                            kind: ExtensionEventKind::RuntimeResponse {
                                request_id: request_id.to_owned(),
                                result,
                            },
                        })
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                } else {
                    let response_payload = serde_json::json!({
                        "__nomad_runtime_response": response_value,
                    });
                    renderer
                        .dispatch_extension_message(
                            TabId::new(target_id),
                            &extension_id,
                            &response_payload,
                        )
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                }
                return Ok(());
            }
            if let Some(response) = payload
                .get("__nomad_port_response")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = response
                    .get("tab_id")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension port response requires a tab id".into(),
                        ))
                    })?;
                let port_id = response
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|port_id| {
                        !port_id.is_empty()
                            && port_id.len() <= 128
                            && !port_id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension port response requires a valid port id".into(),
                        ))
                    })?;
                let response_payload = serde_json::json!({
                    "__nomad_port_response": {
                        "port_id": port_id,
                        "payload": response.get("payload").cloned().unwrap_or(serde_json::Value::Null),
                    }
                });
                renderer
                    .dispatch_extension_message(
                        TabId::new(target_id),
                        &extension_id,
                        &response_payload,
                    )
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                return Ok(());
            }
            if let Some(port) = payload
                .get("__nomad_port_disconnect")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = port
                    .get("tab_id")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "port disconnect requires tab_id".into(),
                        ))
                    })?;
                let port_id = port
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|port_id| !port_id.is_empty() && port_id.len() <= 128)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "port disconnect requires a valid port id".into(),
                        ))
                    })?;
                self.extension_ports
                    .remove(&(extension_id.clone(), target_id, port_id.to_owned()));
                renderer
                    .dispatch_extension_message(
                        TabId::new(target_id),
                        &extension_id,
                        &serde_json::json!({
                            "__nomad_port_disconnect": {"port_id": port_id}
                        }),
                    )
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                return Ok(());
            }
            if let Some(port) = payload
                .get("__nomad_tabs_port_connect")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = port
                    .get("tab_id")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "tabs.connect requires tab_id".into(),
                        ))
                    })?;
                let port_id = port
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|port_id| {
                        !port_id.is_empty()
                            && port_id.len() <= 128
                            && !port_id.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "tabs.connect requires a valid port id".into(),
                        ))
                    })?;
                let name = port
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if name.len() > 128 || name.chars().any(char::is_control) {
                    return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                        "tabs.connect port name is invalid".into(),
                    )));
                }
                if !self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_granted(&extension_id, ExtensionPermission::Tabs)
                {
                    return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                        "tabs.connect requires tabs permission".into(),
                    )));
                }
                let target_tab = TabId::new(target_id);
                let target_url = self.tab(target_tab).and_then(|tab| tab.url.as_ref());
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .validate_background_page_message(&extension_id, target_url)
                    .map_err(ShellError::Extension)?;
                let port_key = (extension_id.clone(), target_id, port_id.to_owned());
                if self.extension_ports.insert(port_key) {
                    renderer
                        .dispatch_extension_message(
                            target_tab,
                            &extension_id,
                            &serde_json::json!({
                                "__nomad_tabs_port_connected": {
                                    "port_id": port_id,
                                    "name": name,
                                }
                            }),
                        )
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                }
                return Ok(());
            }
            if let Some(port) = payload
                .get("__nomad_tabs_port_message")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = port
                    .get("tab_id")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "tabs port message requires tab_id".into(),
                        ))
                    })?;
                let port_id = port
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|port_id| !port_id.is_empty() && port_id.len() <= 128)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "tabs port message requires a valid port id".into(),
                        ))
                    })?;
                if !self.extension_ports.contains(&(
                    extension_id.clone(),
                    target_id,
                    port_id.to_owned(),
                )) {
                    return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                        "tabs port is not connected".into(),
                    )));
                }
                let target_tab = TabId::new(target_id);
                let target_url = self.tab(target_tab).and_then(|tab| tab.url.as_ref());
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .validate_background_page_message(&extension_id, target_url)
                    .map_err(ShellError::Extension)?;
                renderer
                    .dispatch_extension_message(
                        target_tab,
                        &extension_id,
                        &serde_json::json!({
                            "__nomad_tabs_port_message": {
                                "port_id": port_id,
                                "payload": port
                                    .get("payload")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null),
                            }
                        }),
                    )
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                return Ok(());
            }
            if let Some(port) = payload
                .get("__nomad_tabs_port_disconnect")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = port
                    .get("tab_id")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "tabs port disconnect requires tab_id".into(),
                        ))
                    })?;
                let port_id = port
                    .get("port_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|port_id| !port_id.is_empty() && port_id.len() <= 128)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "tabs port disconnect requires a valid port id".into(),
                        ))
                    })?;
                self.extension_ports
                    .remove(&(extension_id.clone(), target_id, port_id.to_owned()));
                renderer
                    .dispatch_extension_message(
                        TabId::new(target_id),
                        &extension_id,
                        &serde_json::json!({
                            "__nomad_tabs_port_disconnect": {"port_id": port_id}
                        }),
                    )
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                return Ok(());
            }
            if let Some(external) = payload
                .get("__nomad_extension_message")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = external
                    .get("target_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension message requires target_id".into(),
                        ))
                    })?;
                let message_payload = external.get("payload").cloned().ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "extension message requires payload".into(),
                    ))
                })?;
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .dispatch_external_message(&extension_id, target_id, message_payload)
                    .map_err(ShellError::Extension)?;
                for event in self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .drain_background_events(target_id)
                {
                    renderer
                        .dispatch_extension_event(&event)
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                }
                return Ok(());
            }
            if let Some(page_message) = payload
                .get("__nomad_page_message")
                .and_then(serde_json::Value::as_object)
            {
                let target_id = page_message
                    .get("tab_id")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension page message requires a tab id".into(),
                        ))
                    })?;
                let message_payload = page_message.get("payload").cloned().ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "extension page message requires a payload".into(),
                    ))
                })?;
                let target_tab = TabId::new(target_id);
                let target_url = self.tab(target_tab).and_then(|tab| tab.url.clone());
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .validate_background_page_message(&extension_id, target_url.as_ref())
                    .map_err(ShellError::Extension)?;
                renderer
                    .dispatch_extension_message(target_tab, &extension_id, &message_payload)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                return Ok(());
            }
            if let Some(request) = extension_api_request(&payload) {
                return self.handle_extension_api_request(&extension_id, request, tab_id, renderer);
            }
            if is_extension_storage_message(&payload) {
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .apply_storage_message(&extension_id, &payload)
                    .map_err(ShellError::Extension)?;
                renderer
                    .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                        extension_id: extension_id.clone(),
                        kind: nomad_engine::ExtensionEventKind::StorageChanged { changes: payload },
                    })
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                return Ok(());
            }
        }
        let runtime_request = tab_id
            .and_then(|_| {
                payload
                    .get("__nomad_runtime_request")
                    .and_then(serde_json::Value::as_object)
                    .map(|request| {
                        let request_id = request
                            .get("request_id")
                            .and_then(serde_json::Value::as_str)
                            .filter(|request_id| !request_id.is_empty() && request_id.len() <= 128)
                            .ok_or_else(|| {
                                ShellError::Extension(ExtensionError::InvalidManifest(
                                    "extension request requires a valid request id".into(),
                                ))
                            })?;
                        let payload = request.get("payload").cloned().ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "extension request requires a payload".into(),
                            ))
                        })?;
                        Ok((request_id.to_owned(), payload))
                    })
            })
            .transpose()?;
        let is_runtime_port = payload
            .get("__nomad_runtime_port")
            .is_some_and(serde_json::Value::is_object)
            || payload
                .get("__nomad_runtime_port_connect")
                .is_some_and(serde_json::Value::is_object)
            || payload
                .get("__nomad_tabs_port_message")
                .is_some_and(serde_json::Value::is_object)
            || payload
                .get("__nomad_tabs_port_disconnect")
                .is_some_and(serde_json::Value::is_object)
            || payload
                .get("__nomad_runtime_port_disconnect")
                .is_some_and(serde_json::Value::is_object);
        if runtime_request.is_none() && !is_runtime_port {
            self.receive_extension_message(message)?;
        }
        if tab_id.is_none()
            && runtime_request.is_none()
            && !is_runtime_port
            && self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .background_info(&extension_id)
                .is_some()
        {
            let target_tabs = self
                .tabs()
                .iter()
                .filter(|tab| tab.url.is_some())
                .map(|tab| (tab.id, tab.url.clone()))
                .collect::<Vec<_>>();
            for (target_tab, target_url) in target_tabs {
                if self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .validate_background_page_message(&extension_id, target_url.as_ref())
                    .is_err()
                {
                    continue;
                }
                renderer
                    .dispatch_extension_message(
                        target_tab,
                        &extension_id,
                        &serde_json::json!({
                            "__nomad_runtime_message": {
                                "payload": payload.clone(),
                                "sender": {"id": extension_id},
                            }
                        }),
                    )
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
            return Ok(());
        }
        if let Some(tab_id) = tab_id {
            if let Some(request) = extension_api_request(&payload) {
                return self.handle_extension_api_request(
                    &extension_id,
                    request,
                    Some(tab_id),
                    renderer,
                );
            }
            let target_url = self.tab(TabId::new(tab_id)).and_then(|tab| tab.url.clone());
            if self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .background_info(&extension_id)
                .is_some()
            {
                if let Some(port) = payload
                    .get("__nomad_runtime_port_connect")
                    .and_then(serde_json::Value::as_object)
                {
                    let port_id = port
                        .get("port_id")
                        .and_then(serde_json::Value::as_str)
                        .filter(|port_id| {
                            !port_id.is_empty()
                                && port_id.len() <= 128
                                && !port_id.chars().any(char::is_control)
                        })
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "extension port requires a valid port id".into(),
                            ))
                        })?;
                    let name = port
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    if name.len() > 128 || name.chars().any(char::is_control) {
                        return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension port name is invalid".into(),
                        )));
                    }
                    self.extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .validate_background_page_message(&extension_id, target_url.as_ref())
                        .map_err(ShellError::Extension)?;
                    let port_key = (extension_id.clone(), tab_id, port_id.to_owned());
                    if self.extension_ports.insert(port_key) {
                        renderer
                            .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                                extension_id: extension_id.clone(),
                                kind: nomad_engine::ExtensionEventKind::RuntimePortConnected {
                                    tab_id,
                                    port_id: port_id.to_owned(),
                                    name: name.to_owned(),
                                },
                            })
                            .map_err(|error| {
                                ShellError::Navigation(NavigationError::Render(error))
                            })?;
                    }
                    return Ok(());
                }
                if let Some(port) = payload
                    .get("__nomad_tabs_port_message")
                    .and_then(serde_json::Value::as_object)
                {
                    let port_id = port
                        .get("port_id")
                        .and_then(serde_json::Value::as_str)
                        .filter(|port_id| !port_id.is_empty() && port_id.len() <= 128)
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "tabs port message requires a valid port id".into(),
                            ))
                        })?;
                    if !self.extension_ports.contains(&(
                        extension_id.clone(),
                        tab_id,
                        port_id.to_owned(),
                    )) {
                        return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                            "tabs port is not connected".into(),
                        )));
                    }
                    self.extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .validate_background_page_message(&extension_id, target_url.as_ref())
                        .map_err(ShellError::Extension)?;
                    renderer
                        .dispatch_extension_event(&ExtensionEvent {
                            extension_id: extension_id.clone(),
                            kind: ExtensionEventKind::RuntimePortMessage {
                                tab_id,
                                port_id: port_id.to_owned(),
                                payload: port
                                    .get("payload")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null),
                            },
                        })
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                    return Ok(());
                }
                if let Some(port) = payload
                    .get("__nomad_tabs_port_disconnect")
                    .and_then(serde_json::Value::as_object)
                    .or_else(|| {
                        payload
                            .get("__nomad_runtime_port_disconnect")
                            .and_then(serde_json::Value::as_object)
                    })
                {
                    let port_id = port
                        .get("port_id")
                        .and_then(serde_json::Value::as_str)
                        .filter(|port_id| !port_id.is_empty() && port_id.len() <= 128)
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "port disconnect requires a valid port id".into(),
                            ))
                        })?;
                    if self.extension_ports.remove(&(
                        extension_id.clone(),
                        tab_id,
                        port_id.to_owned(),
                    )) {
                        renderer
                            .dispatch_extension_event(&ExtensionEvent {
                                extension_id: extension_id.clone(),
                                kind: ExtensionEventKind::RuntimePortDisconnected {
                                    tab_id,
                                    port_id: port_id.to_owned(),
                                },
                            })
                            .map_err(|error| {
                                ShellError::Navigation(NavigationError::Render(error))
                            })?;
                    }
                    return Ok(());
                }
                if let Some(port) = payload
                    .get("__nomad_runtime_port")
                    .and_then(serde_json::Value::as_object)
                {
                    let port_id = port
                        .get("port_id")
                        .and_then(serde_json::Value::as_str)
                        .filter(|port_id| {
                            !port_id.is_empty()
                                && port_id.len() <= 128
                                && !port_id.chars().any(char::is_control)
                        })
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "extension port requires a valid port id".into(),
                            ))
                        })?;
                    let name = port
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    if name.len() > 128 || name.chars().any(char::is_control) {
                        return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension port name is invalid".into(),
                        )));
                    }
                    let message_payload = port.get("payload").cloned().ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "extension port requires a payload".into(),
                        ))
                    })?;
                    self.extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .validate_background_page_message(&extension_id, target_url.as_ref())
                        .map_err(ShellError::Extension)?;
                    let port_key = (extension_id.clone(), tab_id, port_id.to_owned());
                    if self.extension_ports.insert(port_key) {
                        renderer
                            .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                                extension_id: extension_id.clone(),
                                kind: nomad_engine::ExtensionEventKind::RuntimePortConnected {
                                    tab_id,
                                    port_id: port_id.to_owned(),
                                    name: name.to_owned(),
                                },
                            })
                            .map_err(|error| {
                                ShellError::Navigation(NavigationError::Render(error))
                            })?;
                    }
                    renderer
                        .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                            extension_id: extension_id.clone(),
                            kind: nomad_engine::ExtensionEventKind::RuntimePortMessage {
                                tab_id,
                                port_id: port_id.to_owned(),
                                payload: message_payload,
                            },
                        })
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                    return Ok(());
                }
                let (message_payload, request_id) = runtime_request
                    .map_or((payload, None), |(request_id, payload)| {
                        (payload, Some(request_id))
                    });
                if is_extension_storage_message(&message_payload) {
                    renderer
                        .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                            extension_id: extension_id.clone(),
                            kind: nomad_engine::ExtensionEventKind::StorageChanged {
                                changes: message_payload,
                            },
                        })
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                    return Ok(());
                }
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .dispatch_background_message(
                        &extension_id,
                        Some(tab_id),
                        request_id,
                        message_payload,
                        target_url.as_ref(),
                    )
                    .map_err(ShellError::Extension)?;
            }
        }
        let events = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain_background_events(&extension_id);
        for event in events {
            renderer
                .dispatch_extension_event(&event)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn handle_extension_api_request<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: ExtensionApiRequest,
        sender_tab_id: Option<u64>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.poll_extension_frames(renderer)?;
        let validation = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .validate_api_request(extension_id, &request)
            .map_err(ShellError::Extension);
        let result = match validation {
            Ok(()) => {
                self.execute_extension_api_request(extension_id, &request, sender_tab_id, renderer)
            }
            Err(error) => Err(error),
        };
        if result.is_ok()
            && matches!(
                request.method.as_str(),
                "declarativeNetRequest.updateDynamicRules"
                    | "declarativeNetRequest.updateSessionRules"
            )
        {
            let patterns = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .blocking_host_patterns();
            renderer.set_extension_blocking_patterns(&patterns);
        }
        if matches!(
            request.method.as_str(),
            "tabs.sendMessage" | "tabs.captureVisibleTab"
        ) && result.is_ok()
        {
            return Ok(());
        }
        // Provider-backed identity flows answer their own request once the
        // redirect completes; a null result means the response is deferred.
        if matches!(
            request.method.as_str(),
            "identity.getAuthToken" | "identity.launchWebAuthFlow"
        ) && matches!(&result, Ok(value) if value.is_null())
        {
            return Ok(());
        }
        let result = result.map_err(|error| format!("{error:?}"));
        renderer
            .dispatch_extension_event(&ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: ExtensionEventKind::RuntimeResponse {
                    request_id: request.request_id,
                    result,
                },
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))
    }

    #[allow(clippy::too_many_lines)]
    fn execute_extension_api_request(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        sender_tab_id: Option<u64>,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        match request.method.as_str() {
            "tabs.query" => self.execute_extension_tabs_query(extension_id, request),
            "tabs.get" => self.execute_extension_tabs_get(extension_id, request),
            "tabs.create" => self.execute_extension_tabs_create(extension_id, request, renderer),
            "tabs.update" => self.execute_extension_tabs_update(extension_id, request, renderer),
            "tabs.remove" => self.execute_extension_tabs_remove(extension_id, request, renderer),
            "tabs.group" => self.execute_extension_tabs_group(extension_id, request),
            "tabs.ungroup" => self.execute_extension_tabs_ungroup(extension_id, request),
            "tabs.captureVisibleTab" => {
                self.execute_extension_tabs_capture_visible_tab(extension_id, request, renderer)
            }
            "tabs.reload" => self.execute_extension_tabs_reload(extension_id, request, renderer),
            "tabs.discard" => self.execute_extension_tabs_discard(extension_id, request, renderer),
            "tabs.duplicate" => {
                self.execute_extension_tabs_duplicate(extension_id, request, renderer)
            }
            "tabs.goBack" => self.execute_extension_tabs_history_move(
                extension_id,
                request,
                sender_tab_id,
                renderer,
                false,
            ),
            "tabs.goForward" => self.execute_extension_tabs_history_move(
                extension_id,
                request,
                sender_tab_id,
                renderer,
                true,
            ),
            "tabs.getCurrent" => {
                self.execute_extension_tabs_get_current(extension_id, sender_tab_id)
            }
            "tabs.sendMessage" => {
                self.execute_extension_tabs_send_message(extension_id, request, renderer)
            }
            "history.search" => Ok(self.execute_extension_history_search(request)),
            "history.getVisits" => Ok(self.execute_extension_history_get_visits(request)),
            "history.addUrl" => {
                self.execute_extension_history_add_url(extension_id, request, renderer)
            }
            "history.deleteUrl" => {
                self.execute_extension_history_delete_url(extension_id, request, renderer)
            }
            "history.deleteRange" => {
                self.execute_extension_history_delete_range(extension_id, request, renderer)
            }
            "history.deleteAll" => {
                self.execute_extension_history_delete_all(extension_id, renderer)
            }
            "identity.getAuthToken" => {
                self.execute_extension_identity_get_auth_token(extension_id, request, renderer)
            }
            "action.setBadgeText"
            | "action.setBadgeBackgroundColor"
            | "action.setBadgeTextColor"
            | "action.setIcon"
            | "action.setTitle"
            | "action.setPopup"
            | "action.enable"
            | "action.disable"
            | "action.getBadgeText"
            | "action.getBadgeBackgroundColor"
            | "action.getBadgeTextColor"
            | "action.getTitle"
            | "action.getPopup" => self.execute_extension_action(extension_id, request),
            "webRequest.resolveBlocking" => {
                self.execute_extension_web_request_resolve_blocking(extension_id, request)
            }
            "webRequest.handlerBehaviorChanged" => {
                self.execute_extension_web_request_handler_behavior_changed(extension_id, request)
            }
            "identity.launchWebAuthFlow" => self.execute_extension_identity_launch_web_auth_flow(
                extension_id,
                request,
                renderer,
            ),
            "bookmarks.search" => Ok(self.execute_extension_bookmarks_search(request)),
            "bookmarks.get" => self.execute_extension_bookmarks_get(request),
            "bookmarks.getChildren" => self.execute_extension_bookmarks_get_children(request),
            "bookmarks.getTree" => Ok(self.execute_extension_bookmarks_get_tree()),
            "bookmarks.getSubTree" => self.execute_extension_bookmarks_get_sub_tree(request),
            "bookmarks.create" => {
                self.execute_extension_bookmarks_create(extension_id, request, renderer)
            }
            "bookmarks.move" => {
                self.execute_extension_bookmarks_move(extension_id, request, renderer)
            }
            "bookmarks.update" => {
                self.execute_extension_bookmarks_update(extension_id, request, renderer)
            }
            "bookmarks.remove" => {
                self.execute_extension_bookmarks_remove(extension_id, request, renderer)
            }
            "bookmarks.removeTree" => {
                self.execute_extension_bookmarks_remove_tree(extension_id, request, renderer)
            }
            "downloads.list" | "downloads.search" => {
                Ok(self.execute_extension_downloads_search(request))
            }
            "downloads.download" => {
                self.execute_extension_download(extension_id, request, renderer)
            }
            "downloads.pause" => {
                self.execute_extension_downloads_pause(extension_id, request, renderer)
            }
            "downloads.resume" => {
                self.execute_extension_downloads_resume(extension_id, request, renderer)
            }
            "downloads.cancel" => {
                self.execute_extension_downloads_cancel(extension_id, request, renderer)
            }
            "downloads.remove" => {
                self.execute_extension_downloads_remove(extension_id, request, renderer)
            }
            "downloads.erase" => {
                self.execute_extension_downloads_erase(extension_id, request, renderer)
            }
            "downloads.open" => {
                self.execute_extension_downloads_open(extension_id, request, renderer)
            }
            "downloads.show" => {
                self.execute_extension_downloads_show(extension_id, request, renderer)
            }
            "alarms.create" => self.execute_extension_alarm_create(extension_id, request),
            "alarms.get" => self.execute_extension_alarm_get(extension_id, request),
            "alarms.getAll" => self.execute_extension_alarm_get_all(extension_id),
            "alarms.clear" => self.execute_extension_alarm_clear(extension_id, request),
            "alarms.clearAll" => {
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear_all_alarms(extension_id)
                    .map_err(ShellError::Extension)?;
                Ok(serde_json::json!(true))
            }
            "notifications.create" => {
                self.execute_extension_notification_create(extension_id, request)
            }
            "notifications.clear" => {
                self.execute_extension_notification_clear(extension_id, request, renderer)
            }
            "notifications.getAll" => Ok(self.execute_extension_notification_get_all(extension_id)),
            "contextMenus.create" => {
                self.execute_extension_context_menu_create(extension_id, request)
            }
            "contextMenus.update" => {
                self.execute_extension_context_menu_update(extension_id, request)
            }
            "contextMenus.remove" => {
                self.execute_extension_context_menu_remove(extension_id, request)
            }
            "contextMenus.removeAll" => {
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .context_menu_remove_all(extension_id)
                    .map_err(ShellError::Extension)?;
                Ok(serde_json::Value::Null)
            }
            "cookies.get" | "cookies.getAll" | "cookies.set" | "cookies.remove" => {
                self.execute_extension_cookie_operation(extension_id, request, renderer)
            }
            "scripting.executeScript" => {
                self.execute_extension_script(extension_id, request, renderer)
            }
            "scripting.registerContentScripts" => {
                self.execute_extension_register_content_scripts(extension_id, request, renderer)
            }
            "scripting.unregisterContentScripts" => {
                self.execute_extension_unregister_content_scripts(extension_id, request, renderer)
            }
            "scripting.updateContentScripts" => {
                self.execute_extension_update_content_scripts(extension_id, request, renderer)
            }
            "scripting.getRegisteredContentScripts" => {
                Ok(self.execute_extension_get_registered_content_scripts(extension_id, request))
            }
            "scripting.insertCSS" | "scripting.removeCSS" => self.execute_extension_scripting_css(
                extension_id,
                request,
                request.method == "scripting.removeCSS",
                renderer,
            ),
            "runtime.sendNativeMessage" => {
                self.execute_extension_native_message(extension_id, request)
            }
            "runtime.getURL" => Self::execute_extension_get_url(extension_id, request),
            "runtime.getManifest" => self.execute_extension_get_manifest(extension_id),
            "runtime.getContexts" => Ok(Self::execute_extension_runtime_get_contexts(
                extension_id,
                request,
            )),
            "runtime.connect" | "offscreen.createDocument" | "offscreen.closeDocument" => {
                Ok(serde_json::Value::Null)
            }
            "runtime.openOptionsPage" => {
                self.execute_extension_open_options_page(extension_id, renderer)
            }
            "runtime.setUninstallURL" => {
                self.execute_extension_set_uninstall_url(extension_id, request)
            }
            "windows.create" => {
                self.execute_extension_windows_create(extension_id, request, renderer)
            }
            "windows.update" => {
                self.execute_extension_windows_update(extension_id, request, renderer)
            }
            "windows.remove" => {
                self.execute_extension_windows_remove(extension_id, request, renderer)
            }
            "declarativeNetRequest.updateDynamicRules" => {
                self.execute_extension_declarative_update(extension_id, request, false)
            }
            "declarativeNetRequest.updateSessionRules" => {
                self.execute_extension_declarative_update(extension_id, request, true)
            }
            "runtime.getPlatformInfo" | "runtime.getBrowserInfo" => Ok(serde_json::json!({
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "browser": "nomad",
            })),
            "i18n.getUILanguage" => Ok(serde_json::json!("en-US")),
            "i18n.getAcceptLanguages" => Ok(serde_json::json!(["en-US", "en"])),
            "i18n.detectLanguage" => Ok(Self::execute_extension_i18n_detect_language(request)),
            "i18n.getMessage" => Ok(self.execute_extension_i18n_get_message(extension_id, request)),
            "commands.getAll" => Ok(serde_json::to_value(
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .commands(extension_id),
            )
            .unwrap_or(serde_json::Value::Array(Vec::new()))),
            "permissions.contains" => {
                self.execute_extension_permissions_contains(extension_id, request)
            }
            "permissions.request" => {
                self.execute_extension_permissions_request(extension_id, request, renderer)
            }
            "permissions.remove" => {
                self.execute_extension_permissions_remove(extension_id, request, renderer)
            }
            "permissions.getAll" => Ok(self.execute_extension_permissions_get_all(extension_id)),
            "offscreen.hasDocument" => Ok(serde_json::json!(false)),
            "management.getAll" => Ok(self.execute_extension_management_get_all()),
            "management.get" => self.execute_extension_management_get(request),
            "management.getPermissionWarningsById" => {
                self.execute_extension_management_warnings(request)
            }
            "management.setEnabled" => {
                self.execute_extension_management_set_enabled(request, renderer)
            }
            "management.getSelf" => Ok({
                let registry = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let manifest = registry.manifest(extension_id).ok_or_else(|| {
                    ShellError::Extension(ExtensionError::Missing(extension_id.to_owned()))
                })?;
                extension_management_value(&manifest, registry.is_enabled(extension_id))
            }),
            "management.uninstallSelf" => {
                self.execute_extension_uninstall_self(extension_id, renderer)
            }
            "windows.get" => self.execute_extension_window_get(extension_id, request),
            "windows.getCurrent" => Ok(self.execute_extension_window_value(extension_id, true)?),
            "windows.getAll" => self.execute_extension_windows_get_all(extension_id, request),
            "tabGroups.get" => self.execute_extension_tab_groups_get(extension_id, request),
            "tabGroups.query" => self.execute_extension_tab_groups_query(extension_id, request),
            "tabGroups.update" => self.execute_extension_tab_groups_update(extension_id, request),
            "webNavigation.getAllFrames" | "webNavigation.getFrame" => {
                self.execute_extension_web_navigation_request(extension_id, request)
            }
            "declarativeNetRequest.isSessionEnabled" => Ok(serde_json::json!(true)),
            "declarativeNetRequest.getEnabledRulesets" => Ok(serde_json::to_value(
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .enabled_ruleset_ids(extension_id),
            )
            .unwrap_or_else(|_| serde_json::Value::Array(Vec::new()))),
            "declarativeNetRequest.updateEnabledRulesets" => {
                self.execute_extension_dnr_update_enabled_rulesets(extension_id, request)
            }
            "declarativeNetRequest.isRegexSupported" => {
                Self::execute_extension_dnr_is_regex_supported(request)
            }
            "declarativeNetRequest.setExtensionActionOptions" => {
                self.execute_extension_dnr_set_extension_action_options(extension_id, request)
            }
            "declarativeNetRequest.getDynamicRules" => Ok(serde_json::Value::Array(
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .dynamic_rules(extension_id),
            )),
            "declarativeNetRequest.getSessionRules" => Ok(serde_json::Value::Array(
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .session_rules(extension_id),
            )),
            method => Err(ShellError::Extension(ExtensionError::PermissionDenied(
                format!("unsupported extension API {method:?}"),
            ))),
        }
    }

    fn execute_extension_get_url(
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let path = request
            .arguments
            .as_str()
            .unwrap_or_default()
            .trim_start_matches('/');
        let url = if path.is_empty() {
            format!("nomad-extension://{extension_id}/")
        } else {
            extension_resource_uri(extension_id, path)
                .map_err(ShellError::Extension)?
                .to_string()
        };
        Ok(serde_json::Value::String(url))
    }

    fn execute_extension_runtime_get_contexts(
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> serde_json::Value {
        let filter = request.arguments.as_object();
        let context = serde_json::json!({
            "contextId": format!("{extension_id}:background"),
            "contextType": "BACKGROUND",
            "documentUrl": format!("nomad-extension://{extension_id}/__nomad/background.html"),
            "incognito": false,
            "tabId": -1,
            "frameId": 0,
        });
        let matches_type = filter
            .and_then(|filter| filter.get("contextTypes"))
            .and_then(serde_json::Value::as_array)
            .is_none_or(|types| {
                types
                    .iter()
                    .any(|value| value.as_str() == Some("BACKGROUND"))
            });
        let matches_document = filter
            .and_then(|filter| filter.get("documentUrls"))
            .and_then(serde_json::Value::as_array)
            .is_none_or(|urls| {
                urls.iter().any(|value| {
                    value.as_str()
                        == Some(
                            format!("nomad-extension://{extension_id}/__nomad/background.html")
                                .as_str(),
                        )
                })
            });
        if matches_type && matches_document {
            serde_json::json!([context])
        } else {
            serde_json::json!([])
        }
    }

    /// Resolve `i18n.getMessage` against the extension's `_locales` catalog.
    ///
    /// `_locales/<lang>/messages.json` is loaded for the UI language (with an
    /// `<lang>_<region>` → `<lang>` fallback), the message body is returned,
    /// and `$1`, `$2`, ... and `$NAME$` placeholders are substituted from the
    /// caller-provided substitutions. Unknown keys return an empty string,
    /// matching Chromium's contract.
    fn execute_extension_i18n_get_message(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> serde_json::Value {
        let message_name = request
            .arguments
            .get("messageName")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let substitutions: Vec<String> = request
            .arguments
            .get("substitutions")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let catalog = self.extension_locale_catalog(extension_id, "en");
        let Some(message) = catalog
            .as_object()
            .and_then(|messages| messages.get(message_name))
            .and_then(|entry| entry.get("message"))
            .and_then(serde_json::Value::as_str)
        else {
            return serde_json::Value::String(String::new());
        };
        serde_json::Value::String(substitute_i18n_message(message, &substitutions))
    }

    fn execute_extension_i18n_detect_language(request: &ExtensionApiRequest) -> serde_json::Value {
        let text = request
            .arguments
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let (language, reliable) = if text
            .chars()
            .any(|character| ('\u{0400}'..='\u{04ff}').contains(&character))
        {
            ("ru", true)
        } else if text
            .chars()
            .any(|character| ('\u{3040}'..='\u{30ff}').contains(&character))
        {
            ("ja", true)
        } else if text
            .chars()
            .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character))
        {
            ("zh", true)
        } else if text
            .chars()
            .any(|character| ('\u{0600}'..='\u{06ff}').contains(&character))
        {
            ("ar", true)
        } else {
            ("en", !text.trim().is_empty())
        };
        serde_json::json!({
            "isReliable": reliable,
            "languages": [{"language": language, "percentage": if reliable { 100 } else { 0 }}],
        })
    }

    /// Load the extension's `_locales/<lang>/messages.json` catalog.
    fn extension_locale_catalog(&self, extension_id: &str, language: &str) -> serde_json::Value {
        for candidate in [format!("_locales/{language}/messages.json"), {
            let (base, _) = language.split_once('_').unwrap_or((language, ""));
            format!("_locales/{base}/messages.json")
        }] {
            if let Some(source) = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .resource_source(extension_id, &candidate)
            {
                if let Ok(value) = serde_json::from_str(&source) {
                    return value;
                }
            }
        }
        serde_json::Value::Null
    }

    fn execute_extension_get_manifest(
        &self,
        extension_id: &str,
    ) -> Result<serde_json::Value, ShellError> {
        let manifest = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .installed()
            .find(|manifest| manifest.id == extension_id)
            .cloned()
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::Missing(extension_id.to_owned()))
            })?;
        serde_json::to_value(manifest).map_err(|error| {
            ShellError::Renderer(format!("extension manifest encoding failed: {error}"))
        })
    }

    fn execute_extension_permissions_contains(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let permissions = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "permissions.contains expects an object".into(),
            ))
        })?;
        let requested = permissions
            .get("permissions")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .all(|permission| {
                ExtensionManifest::from_json(&format!(
                    "{{\"manifest_version\":3,\"id\":\"permission-check\",\"name\":\"Permission Check\",\"version\":\"1\",\"permissions\":[{permission:?}]}}"
                ))
                .ok()
                .and_then(|manifest| manifest.permissions.into_iter().next())
                .is_some_and(|permission| self.extensions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_granted(extension_id, permission))
            });
        let origins = permissions
            .get("origins")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .all(|pattern| {
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_host_permission_granted(extension_id, pattern)
            });
        Ok(serde_json::json!(requested && origins))
    }

    fn execute_extension_permissions_request<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let permissions = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "permissions.request expects an object".into(),
            ))
        })?;
        let manifest = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .manifest(extension_id)
            .ok_or_else(|| ShellError::Extension(ExtensionError::Missing(extension_id.into())))?;
        let mut granted = Vec::new();
        for name in permissions
            .get("permissions")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            let parsed = ExtensionManifest::from_json(&format!(
                "{{\"manifest_version\":3,\"id\":\"permission-request\",\"name\":\"Permission Request\",\"version\":\"1\",\"permissions\":[{name:?}]}}"
            ))
            .map_err(ShellError::Extension)?
            .permissions;
            if parsed.is_empty() || !manifest.optional_permissions.contains(&parsed[0]) {
                return Ok(serde_json::json!(false));
            }
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .grant(extension_id, parsed[0])
                .map_err(ShellError::Extension)?;
            granted.push(nomad_engine::permission_name(parsed[0]));
        }
        let mut granted_origins = Vec::new();
        for pattern in permissions
            .get("origins")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            if !manifest
                .optional_host_permissions
                .iter()
                .any(|candidate| candidate == pattern)
            {
                return Ok(serde_json::json!(false));
            }
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .grant_host_permission(extension_id, pattern)
                .map_err(ShellError::Extension)?;
            granted_origins.push(pattern.to_owned());
        }
        if !granted.is_empty() || !granted_origins.is_empty() {
            let details = serde_json::json!({
                "permissions": granted,
                "origins": granted_origins,
            });
            let installed = {
                let registry = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                registry
                    .installed()
                    .filter(|manifest| registry.is_enabled(&manifest.id))
                    .map(|manifest| manifest.id.clone())
                    .collect::<Vec<_>>()
            };
            for extension_id in installed {
                renderer
                    .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                        extension_id,
                        kind: nomad_engine::ExtensionEventKind::PermissionAdded {
                            details: details.clone(),
                        },
                    })
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
        }
        Ok(serde_json::json!(true))
    }

    fn execute_extension_permissions_remove<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let permissions = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "permissions.remove expects an object".into(),
            ))
        })?;
        let mut revoked = Vec::new();
        for name in permissions
            .get("permissions")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            let parsed = ExtensionManifest::from_json(&format!(
                "{{\"manifest_version\":3,\"id\":\"permission-request\",\"name\":\"Permission Request\",\"version\":\"1\",\"permissions\":[{name:?}]}}"
            ))
            .map_err(ShellError::Extension)?
            .permissions;
            if parsed.is_empty() {
                continue;
            }
            if self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .revoke(extension_id, parsed[0])
                .is_ok()
            {
                revoked.push(nomad_engine::permission_name(parsed[0]));
            }
        }
        let mut revoked_origins = Vec::new();
        for pattern in permissions
            .get("origins")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .revoke_host_permission(extension_id, pattern)
                .map_err(ShellError::Extension)?;
            revoked_origins.push(pattern.to_owned());
        }
        if !revoked.is_empty() || !revoked_origins.is_empty() {
            let details = serde_json::json!({
                "permissions": revoked,
                "origins": revoked_origins,
            });
            let installed = {
                let registry = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                registry
                    .installed()
                    .filter(|manifest| registry.is_enabled(&manifest.id))
                    .map(|manifest| manifest.id.clone())
                    .collect::<Vec<_>>()
            };
            for extension_id in installed {
                renderer
                    .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                        extension_id,
                        kind: nomad_engine::ExtensionEventKind::PermissionRemoved {
                            details: details.clone(),
                        },
                    })
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
        }
        Ok(serde_json::json!(true))
    }

    fn execute_extension_permissions_get_all(&self, extension_id: &str) -> serde_json::Value {
        let mut permissions = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .granted_permissions(extension_id)
            .into_iter()
            .map(nomad_engine::permission_name)
            .collect::<Vec<_>>();
        permissions.sort_unstable();
        let permissions = permissions
            .into_iter()
            .map(serde_json::Value::from)
            .collect::<Vec<_>>();
        let mut origins = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .granted_host_permissions(extension_id)
            .into_iter()
            .collect::<Vec<_>>();
        origins.sort();
        let origins = origins
            .into_iter()
            .map(serde_json::Value::from)
            .collect::<Vec<_>>();
        serde_json::json!({ "permissions": permissions, "origins": origins })
    }

    fn execute_extension_declarative_update(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        session: bool,
    ) -> Result<serde_json::Value, ShellError> {
        let arguments = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "declarative rule update expects an object".into(),
            ))
        })?;
        let remove_ids = arguments
            .get("removeRuleIds")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "removeRuleIds must be an array".into(),
                        ))
                    })?
                    .iter()
                    .map(|value| {
                        value.as_u64().ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "removeRuleIds must contain numeric IDs".into(),
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let add_rules = arguments
            .get("addRules")
            .map(|value| {
                value.as_array().cloned().ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "addRules must be an array".into(),
                    ))
                })
            })
            .transpose()?
            .unwrap_or_default();
        if session {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .update_session_rules(extension_id, &remove_ids, &add_rules)
        } else {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .update_dynamic_rules(extension_id, &remove_ids, &add_rules)
        }
        .map(|_| serde_json::Value::Null)
        .map_err(ShellError::Extension)
    }

    fn execute_extension_context_menu_create(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .context_menu_create(extension_id, &request.arguments)
            .map_err(ShellError::Extension)
    }

    fn execute_extension_context_menu_update(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let arguments = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "contextMenus.update expects an object".into(),
            ))
        })?;
        let menu_id = extension_menu_id(arguments.get("menuItemId"))?;
        let updates = arguments
            .get("updateProperties")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .context_menu_update(extension_id, &menu_id, &updates)
            .map_err(ShellError::Extension)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_context_menu_remove(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let arguments = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "contextMenus.remove expects an object".into(),
            ))
        })?;
        let menu_id = extension_menu_id(arguments.get("menuItemId"))?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .context_menu_remove(extension_id, &menu_id)
            .map_err(ShellError::Extension)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_management_get_all(&self) -> serde_json::Value {
        serde_json::Value::Array({
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .map(|manifest| {
                    extension_management_value(manifest, registry.is_enabled(&manifest.id))
                })
                .collect()
        })
    }

    fn execute_extension_management_get(
        &self,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "management.get requires an extension id".into(),
                ))
            })?;
        let registry = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let value = registry
            .manifest(id)
            .map(|manifest| {
                extension_management_value(&manifest, registry.is_enabled(&manifest.id))
            })
            .ok_or_else(|| ShellError::Extension(ExtensionError::Missing(id.to_owned())));
        drop(registry);
        value
    }

    fn execute_extension_management_warnings(
        &self,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "management.getPermissionWarningsById requires an extension id".into(),
                ))
            })?;
        if self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .manifest(id)
            .is_none()
        {
            return Err(ShellError::Extension(ExtensionError::Missing(
                id.to_owned(),
            )));
        }
        Ok(serde_json::json!([]))
    }

    fn execute_extension_management_set_enabled<R: PageRenderer>(
        &mut self,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let arguments = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "management.setEnabled expects an object".into(),
            ))
        })?;
        let id = arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "management.setEnabled requires an extension id".into(),
                ))
            })?;
        let enabled = arguments
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "management.setEnabled requires enabled".into(),
                ))
            })?;
        let was_enabled = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_enabled(id);
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_enabled(id, enabled)
            .map_err(ShellError::Extension)?;
        let renderer_result = if enabled {
            self.install_extension_resources_with_renderer(id, renderer)
                .and_then(|()| self.install_background_with_renderer(id, renderer))
                .and_then(|()| self.refresh_extension_scripts_with_renderer(renderer))
        } else {
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id: id.to_owned(),
                    kind: nomad_engine::ExtensionEventKind::RuntimeSuspend,
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            renderer
                .uninstall_extension(id)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))
                .and_then(|()| self.refresh_extension_scripts_with_renderer(renderer))
        };
        if let Err(error) = renderer_result {
            let _ = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .set_enabled(id, was_enabled);
            return Err(error);
        }
        self.dispatch_management_event(if enabled { "enabled" } else { "disabled" }, id, renderer)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_uninstall_self<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let _ = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .manifest(extension_id)
            .ok_or_else(|| ShellError::Extension(ExtensionError::Missing(extension_id.into())))?;
        let id = extension_id.to_owned();
        self.dispatch_management_event("uninstalled", &id, renderer)?;
        if self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_enabled(&id)
        {
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id: id.clone(),
                    kind: nomad_engine::ExtensionEventKind::RuntimeSuspend,
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        renderer
            .uninstall_extension(&id)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        self.uninstall_extension(&id)?;
        Ok(serde_json::Value::Null)
    }

    fn dispatch_management_event<R: PageRenderer>(
        &self,
        kind: &str,
        subject_id: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let info = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .manifest(subject_id)
                .map_or(serde_json::Value::Null, |manifest| {
                    extension_management_value(&manifest, registry.is_enabled(&manifest.id))
                })
        };
        let installed = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .installed()
            .cloned()
            .collect::<Vec<_>>();
        for manifest in installed {
            if manifest.id == subject_id
                || !self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_enabled(&manifest.id)
                || !self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_granted(&manifest.id, nomad_engine::ExtensionPermission::Management)
            {
                continue;
            }
            let event = match kind {
                "installed" => {
                    nomad_engine::ExtensionEventKind::ManagementInstalled { info: info.clone() }
                }
                "uninstalled" => {
                    nomad_engine::ExtensionEventKind::ManagementUninstalled { info: info.clone() }
                }
                "enabled" => {
                    nomad_engine::ExtensionEventKind::ManagementEnabled { info: info.clone() }
                }
                _ => nomad_engine::ExtensionEventKind::ManagementDisabled { info: info.clone() },
            };
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id: manifest.id.clone(),
                    kind: event,
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn execute_extension_window_get(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let window_id = request
            .arguments
            .get("windowId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "windows.get requires windowId".into(),
                ))
            })?;
        if window_id != 1 {
            return Err(ShellError::Extension(ExtensionError::Missing(format!(
                "window {window_id}"
            ))));
        }
        let populate = request
            .arguments
            .get("populate")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        self.execute_extension_window_value(extension_id, populate)
    }

    fn execute_extension_windows_get_all(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let populate = request
            .arguments
            .get("populate")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        Ok(serde_json::Value::Array(vec![
            self.execute_extension_window_value(extension_id, populate)?
        ]))
    }

    fn execute_extension_window_value(
        &self,
        extension_id: &str,
        populate: bool,
    ) -> Result<serde_json::Value, ShellError> {
        let tabs = if populate
            && self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_granted(extension_id, ExtensionPermission::Tabs)
        {
            self.extension_query_tabs(extension_id)?
                .into_iter()
                .map(|tab| {
                    let mut value = extension_tab_value(&tab);
                    if let Some(object) = value.as_object_mut() {
                        object.insert("windowId".into(), serde_json::json!(1));
                    }
                    value
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(serde_json::json!({
            "id": 1,
            "focused": true,
            "alwaysOnTop": false,
            "incognito": false,
            "type": "normal",
            "state": "normal",
            "tabs": tabs,
        }))
    }

    fn execute_extension_tabs_query(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let active_only = request
            .arguments
            .get("active")
            .and_then(serde_json::Value::as_bool);
        let window_id = request
            .arguments
            .get("windowId")
            .and_then(serde_json::Value::as_u64);
        let url_patterns = request.arguments.get("url").map(|value| {
            value
                .as_str()
                .map(|pattern| vec![pattern.to_owned()])
                .or_else(|| {
                    value.as_array().map(|patterns| {
                        patterns
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                })
                .unwrap_or_default()
        });
        let tabs = self.extension_query_tabs(extension_id)?;
        Ok(serde_json::Value::Array(
            tabs.into_iter()
                .filter(|tab| active_only.is_none_or(|active| tab.active == active))
                .filter(|_| window_id.is_none_or(|id| id == 1))
                .filter(|tab| {
                    url_patterns.as_ref().is_none_or(|patterns| {
                        tab.url.as_ref().is_some_and(|url| {
                            patterns
                                .iter()
                                .any(|pattern| extension_wildcard_matches(pattern, url.as_ref()))
                        })
                    })
                })
                .map(|tab| extension_tab_value(&tab))
                .collect(),
        ))
    }

    fn execute_extension_tabs_get(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.get requires tabId".into(),
                ))
            })?;
        let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        let visible = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .query_tabs(
                extension_id,
                &[ExtensionTabInfo {
                    id: tab.id.get(),
                    url: tab.url.clone(),
                    active: self.active_tab() == Some(tab.id),
                }],
            )
            .map_err(ShellError::Extension)?
            .into_iter()
            .next()
            .ok_or(ShellError::MissingTab(tab_id))?;
        Ok(extension_tab_value(&visible))
    }

    fn execute_extension_web_navigation_frames(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        all_frames: bool,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "webNavigation request requires tabId".into(),
                ))
            })?;
        self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;

        let frame_ids = if all_frames {
            None
        } else {
            Some(vec![request
                .arguments
                .get("frameId")
                .and_then(serde_json::Value::as_i64)
                .filter(|frame_id| *frame_id >= 0)
                .ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "webNavigation.getFrame requires a non-negative frameId".into(),
                    ))
                })?])
        };
        let frames = self
            .extension_frames
            .select(&ExtensionFrameTarget {
                tab_id: tab_id.get(),
                frame_ids,
                all_frames,
            })
            .map_err(ShellError::Extension)?;
        let mut values = Vec::with_capacity(frames.len());
        for frame in frames {
            if !self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_host_granted(extension_id, &frame.url)
            {
                return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                    "extension has no host permission for navigation details".into(),
                )));
            }
            values.push(serde_json::json!({
                "frameId": frame.id,
                "parentFrameId": frame.parent_frame_id.unwrap_or(-1),
                "tabId": tab_id.get(),
                "url": frame.url.as_str(),
            }));
        }
        if all_frames {
            Ok(values.into())
        } else {
            values.into_iter().next().ok_or_else(|| {
                ShellError::Extension(ExtensionError::Missing(
                    "requested frame is not live".into(),
                ))
            })
        }
    }

    fn execute_extension_web_navigation_request(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        self.execute_extension_web_navigation_frames(
            extension_id,
            request,
            request.method == "webNavigation.getAllFrames",
        )
    }

    fn execute_extension_tabs_create(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "tabs.create expects an object".into(),
            ))
        })?;
        let previous_tab = self.active_tab();
        let tab_id = self.new_tab();
        if let Some(url) = options.get("url").and_then(serde_json::Value::as_str) {
            self.configure_renderer_tab(tab_id, renderer)?;
            if let Ok(parsed_url) = Url::parse(url) {
                let injections = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .scripts_for_tab(&ExtensionTabInfo {
                        id: tab_id.get(),
                        url: Some(parsed_url),
                        active: true,
                    });
                renderer
                    .install_extension_scripts_for_tab(tab_id, &injections)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
            self.dispatch_web_navigation_before(tab_id, url, renderer)?;
            let nav_result = self.navigate_with_history_dispatch(tab_id, url, renderer);
            if let Err(error) = nav_result {
                let _ = self.dispatch_web_navigation_error(tab_id, url, renderer);
                let _ = self.close_tab_with_renderer(tab_id, renderer);
                return Err(ShellError::Navigation(error));
            }
            if let Some(navigated_url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
                self.dispatch_web_navigation_after(tab_id, &navigated_url, renderer, false)?;
            }
        }
        if options.get("active").and_then(serde_json::Value::as_bool) == Some(false) {
            if let Some(previous_tab) = previous_tab {
                self.select_tab_with_renderer(previous_tab, renderer)?;
            }
        }
        self.dispatch_extension_tab_event(
            tab_id,
            |_, tab| ExtensionEventKind::TabCreated {
                tab: tab.unwrap_or(serde_json::Value::Null),
            },
            renderer,
        )?;
        if let Some(url) = options.get("url").and_then(serde_json::Value::as_str) {
            self.dispatch_extension_tab_event(
                tab_id,
                |_, tab| ExtensionEventKind::TabUpdated {
                    tab_id: tab_id.get(),
                    change_info: serde_json::json!({ "url": url }),
                    tab: tab.unwrap_or(serde_json::Value::Null),
                },
                renderer,
            )?;
        }
        self.extension_tab_json(extension_id, tab_id)
    }

    fn execute_extension_tabs_update(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.update requires tabId".into(),
                ))
            })?;
        let update = request
            .arguments
            .get("updateProperties")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.update requires updateProperties".into(),
                ))
            })?;
        if let Some(url) = update.get("url").and_then(serde_json::Value::as_str) {
            self.configure_renderer_tab(tab_id, renderer)?;
            if let Ok(parsed_url) = Url::parse(url) {
                let injections = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .scripts_for_tab(&ExtensionTabInfo {
                        id: tab_id.get(),
                        url: Some(parsed_url),
                        active: self.active_tab() == Some(tab_id),
                    });
                renderer
                    .install_extension_scripts_for_tab(tab_id, &injections)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
            let previous_url = self.tab(tab_id).and_then(|tab| tab.url.clone());
            self.dispatch_web_navigation_before(tab_id, url, renderer)?;
            if let Err(error) = self.navigate_with_history_dispatch(tab_id, url, renderer) {
                let _ = self.dispatch_web_navigation_error(tab_id, url, renderer);
                self.fail_pending_auth_flows_for_tab(tab_id, &format!("{error:?}"), renderer)?;
                return Err(ShellError::Navigation(error));
            }
            if let Some(navigated_url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
                let history_state = previous_url.as_ref() == Some(&navigated_url);
                self.dispatch_web_navigation_after(
                    tab_id,
                    &navigated_url,
                    renderer,
                    history_state,
                )?;
            }
        }
        if update.get("active").and_then(serde_json::Value::as_bool) == Some(true) {
            self.select_tab_with_renderer(tab_id, renderer)?;
            self.dispatch_extension_tab_event(
                tab_id,
                |_, tab| ExtensionEventKind::TabUpdated {
                    tab_id: tab_id.get(),
                    change_info: serde_json::json!({ "active": true }),
                    tab: tab.unwrap_or(serde_json::Value::Null),
                },
                renderer,
            )?;
        }
        if let Some(url) = update.get("url").and_then(serde_json::Value::as_str) {
            self.dispatch_extension_tab_event(
                tab_id,
                |_, tab| ExtensionEventKind::TabUpdated {
                    tab_id: tab_id.get(),
                    change_info: serde_json::json!({ "url": url }),
                    tab: tab.unwrap_or(serde_json::Value::Null),
                },
                renderer,
            )?;
        }
        self.extension_tab_json(extension_id, tab_id)
    }

    fn execute_extension_tabs_remove(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_ids = request
            .arguments
            .get("tabIds")
            .and_then(serde_json::Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(serde_json::Value::as_u64)
                    .map(TabId::new)
                    .collect::<Vec<_>>()
            })
            .or_else(|| {
                request
                    .arguments
                    .get("tabId")
                    .and_then(serde_json::Value::as_u64)
                    .map(|id| vec![TabId::new(id)])
            })
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.remove requires tabIds".into(),
                ))
            })?;
        for tab_id in tab_ids {
            if self.tab(tab_id).is_some() {
                self.close_tab_with_renderer(tab_id, renderer)?;
            }
        }
        let _ = extension_id;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_tabs_reload<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.reload requires tabId".into(),
                ))
            })?;
        self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        self.configure_renderer_tab(tab_id, renderer)?;
        self.runtime
            .reload_tab_with_renderer(tab_id, renderer)
            .map_err(ShellError::Navigation)?;
        self.sync_address_bar();
        self.dispatch_extension_tab_event(
            tab_id,
            |_, tab| ExtensionEventKind::TabUpdated {
                tab_id: tab_id.get(),
                change_info: serde_json::json!({ "status": "loading" }),
                tab: tab.unwrap_or(serde_json::Value::Null),
            },
            renderer,
        )?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_tabs_discard<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.discard requires tabId".into(),
                ))
            })?;
        self.runtime
            .suspend_tab_with_renderer(tab_id, renderer)
            .map_err(map_tab_error)?;
        self.sync_sidebar();
        self.dispatch_extension_tab_event(
            tab_id,
            |_, tab| ExtensionEventKind::TabUpdated {
                tab_id: tab_id.get(),
                change_info: serde_json::json!({ "discarded": true, "status": "unloaded" }),
                tab: tab.unwrap_or(serde_json::Value::Null),
            },
            renderer,
        )?;
        let mut result = self.extension_tab_json(extension_id, tab_id)?;
        if let Some(object) = result.as_object_mut() {
            object.insert("discarded".into(), serde_json::Value::Bool(true));
            object.insert(
                "status".into(),
                serde_json::Value::String("unloaded".into()),
            );
        }
        Ok(result)
    }

    fn execute_extension_tabs_duplicate<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let source_tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.duplicate requires tabId".into(),
                ))
            })?;
        let source_url = self
            .tab(source_tab_id)
            .ok_or(ShellError::MissingTab(source_tab_id))?
            .url
            .clone();
        let tab_id = self.new_tab();
        if let Some(url) = source_url {
            self.configure_renderer_tab(tab_id, renderer)?;
            let injections = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .scripts_for_tab(&ExtensionTabInfo {
                    id: tab_id.get(),
                    url: Some(url.clone()),
                    active: true,
                });
            renderer
                .install_extension_scripts_for_tab(tab_id, &injections)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            self.dispatch_web_navigation_before(tab_id, url.as_str(), renderer)?;
            if let Err(error) = self.navigate_with_history_dispatch(tab_id, url.as_str(), renderer)
            {
                let _ = self.dispatch_web_navigation_error(tab_id, url.as_str(), renderer);
                let _ = self.close_tab_with_renderer(tab_id, renderer);
                return Err(ShellError::Navigation(error));
            }
            if let Some(navigated_url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
                self.dispatch_web_navigation_after(tab_id, &navigated_url, renderer, false)?;
            }
        }
        self.select_tab_with_renderer(tab_id, renderer)?;
        self.dispatch_extension_tab_event(
            tab_id,
            |_, _| ExtensionEventKind::TabActivated {
                tab_id: tab_id.get(),
                window_id: 1,
            },
            renderer,
        )?;
        self.dispatch_extension_tab_event(
            tab_id,
            |_, tab| ExtensionEventKind::TabCreated {
                tab: tab.unwrap_or(serde_json::Value::Null),
            },
            renderer,
        )?;
        self.extension_tab_json(extension_id, tab_id)
    }

    fn execute_extension_tabs_history_move<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        sender_tab_id: Option<u64>,
        renderer: &mut R,
        forward: bool,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .or(sender_tab_id)
            .map(TabId::new)
            .or_else(|| self.active_tab())
            .ok_or(ShellError::NoActiveTab)?;
        let history = self.runtime.tab_history(tab_id).map_err(map_tab_error)?;
        let current = history.current_index.ok_or_else(|| {
            ShellError::Navigation(NavigationError::InvalidUrl(
                "tab has no committed URL".to_owned(),
            ))
        })?;
        let target_index = if forward {
            current.saturating_add(1)
        } else {
            current.checked_sub(1).ok_or_else(|| {
                ShellError::Navigation(NavigationError::InvalidUrl(
                    "tab has no previous history entry".to_owned(),
                ))
            })?
        };
        let target_url = history.entries.get(target_index).ok_or_else(|| {
            ShellError::Navigation(NavigationError::InvalidUrl(
                "tab has no forward history entry".to_owned(),
            ))
        })?;
        let target_url_string = target_url.to_string();
        self.configure_renderer_tab(tab_id, renderer)?;
        self.dispatch_web_navigation_before(tab_id, &target_url_string, renderer)?;
        let result = if forward {
            self.runtime.go_forward_with_renderer(tab_id, renderer)
        } else {
            self.runtime.go_back_with_renderer(tab_id, renderer)
        };
        result.map_err(ShellError::Navigation)?;
        self.sync_address_bar();
        if let Some(navigated_url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
            self.dispatch_web_navigation_after(tab_id, &navigated_url, renderer, false)?;
        }
        self.dispatch_extension_tab_event(
            tab_id,
            |_, tab| ExtensionEventKind::TabUpdated {
                tab_id: tab_id.get(),
                change_info: serde_json::json!({
                    "status": "complete",
                    "url": target_url_string,
                }),
                tab: tab.unwrap_or(serde_json::Value::Null),
            },
            renderer,
        )?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_tabs_get_current(
        &self,
        extension_id: &str,
        sender_tab_id: Option<u64>,
    ) -> Result<serde_json::Value, ShellError> {
        match sender_tab_id {
            Some(tab_id) => self.extension_tab_json(extension_id, TabId::new(tab_id)),
            None => Ok(serde_json::Value::Null),
        }
    }

    fn execute_extension_tabs_group(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_ids = self.extension_tab_ids(request)?;
        let requested_group = request.arguments.get("groupId").and_then(|value| {
            value
                .as_i64()
                .and_then(|group_id| u64::try_from(group_id).ok())
        });
        let group_id = if let Some(group_id) = requested_group {
            if !self.tab_groups.contains_key(&group_id) {
                return Err(ShellError::Extension(ExtensionError::Missing(format!(
                    "tab group {group_id}"
                ))));
            }
            group_id
        } else {
            let group_id = self.next_tab_group_id;
            self.next_tab_group_id = self.next_tab_group_id.saturating_add(1).max(1);
            self.tab_groups.insert(
                group_id,
                TabGroup {
                    id: group_id,
                    title: None,
                    color: "grey".into(),
                    collapsed: false,
                    tab_ids: Vec::new(),
                },
            );
            group_id
        };
        for group in self.tab_groups.values_mut() {
            group.tab_ids.retain(|tab_id| !tab_ids.contains(tab_id));
        }
        if let Some(group) = self.tab_groups.get_mut(&group_id) {
            group.tab_ids.extend(tab_ids);
            group.tab_ids.sort_unstable_by_key(|tab_id| tab_id.get());
        }
        self.tab_groups.retain(|_, group| !group.tab_ids.is_empty());
        Ok(serde_json::json!(group_id))
    }

    fn execute_extension_tabs_ungroup(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_ids = self.extension_tab_ids(request)?;
        for group in self.tab_groups.values_mut() {
            group.tab_ids.retain(|tab_id| !tab_ids.contains(tab_id));
        }
        self.tab_groups.retain(|_, group| !group.tab_ids.is_empty());
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_tabs_capture_visible_tab<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        if request
            .arguments
            .get("windowId")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|window_id| window_id != 1)
        {
            return Err(ShellError::Extension(ExtensionError::Missing(
                "window 1".into(),
            )));
        }
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        let allowed = tab.url.as_ref().is_some_and(|url| {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_host_granted(extension_id, url)
                || self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_active_tab_granted(extension_id, tab_id.get())
        });
        if !allowed {
            return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                "tabs.captureVisibleTab requires host access or an activeTab grant".into(),
            )));
        }
        if self.pending_extension_screenshots.contains_key(&tab_id) {
            return Err(ShellError::Extension(
                ExtensionError::ResourceLimitExceeded(
                    "a screenshot is already pending for this tab".into(),
                ),
            ));
        }
        renderer
            .request_tab_screenshot(tab_id)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        self.pending_extension_screenshots.insert(
            tab_id,
            PendingExtensionScreenshot {
                extension_id: extension_id.to_owned(),
                request_id: request.request_id.clone(),
            },
        );
        Ok(serde_json::Value::Null)
    }

    fn extension_tab_ids(&self, request: &ExtensionApiRequest) -> Result<Vec<TabId>, ShellError> {
        let value = request.arguments.get("tabIds").ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest("tabIds is required".into()))
        })?;
        let values = value
            .as_array()
            .map_or_else(|| vec![value.clone()], Clone::clone);
        if values.is_empty() {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                "tabIds must not be empty".into(),
            )));
        }
        let mut tab_ids = Vec::with_capacity(values.len());
        for value in values {
            let tab_id = value.as_u64().map(TabId::new).ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabIds must contain numeric IDs".into(),
                ))
            })?;
            if self.tab(tab_id).is_none() {
                return Err(ShellError::MissingTab(tab_id));
            }
            if !tab_ids.contains(&tab_id) {
                tab_ids.push(tab_id);
            }
        }
        Ok(tab_ids)
    }

    fn execute_extension_tab_groups_get(
        &self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let group_id = request
            .arguments
            .get("groupId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabGroups.get requires groupId".into(),
                ))
            })?;
        self.tab_groups
            .get(&group_id)
            .map(Self::extension_tab_group_value)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::Missing(format!("tab group {group_id}")))
            })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn execute_extension_tab_groups_query(
        &self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let title = request
            .arguments
            .get("title")
            .and_then(|value| value.as_str());
        let collapsed = request
            .arguments
            .get("collapsed")
            .and_then(serde_json::Value::as_bool);
        let groups = self
            .tab_groups
            .values()
            .filter(|group| title.is_none_or(|title| group.title.as_deref() == Some(title)))
            .filter(|group| collapsed.is_none_or(|collapsed| group.collapsed == collapsed))
            .map(Self::extension_tab_group_value)
            .collect();
        Ok(serde_json::Value::Array(groups))
    }

    fn execute_extension_tab_groups_update(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let group_id = request
            .arguments
            .get("groupId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabGroups.update requires groupId".into(),
                ))
            })?;
        let update = request
            .arguments
            .get("updateProperties")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabGroups.update requires updateProperties".into(),
                ))
            })?;
        let group = self.tab_groups.get_mut(&group_id).ok_or_else(|| {
            ShellError::Extension(ExtensionError::Missing(format!("tab group {group_id}")))
        })?;
        if let Some(title) = update.get("title") {
            group.title = if title.is_null() {
                None
            } else {
                Some(
                    title
                        .as_str()
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "tab group title must be a string".into(),
                            ))
                        })?
                        .to_owned(),
                )
            };
        }
        if let Some(color) = update.get("color") {
            let color = color.as_str().ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tab group color must be a string".into(),
                ))
            })?;
            if !matches!(
                color,
                "grey" | "blue" | "red" | "yellow" | "green" | "pink" | "purple" | "cyan"
            ) {
                return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                    "tab group color is invalid".into(),
                )));
            }
            color.clone_into(&mut group.color);
        }
        if let Some(collapsed) = update.get("collapsed") {
            group.collapsed = collapsed.as_bool().ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tab group collapsed must be a boolean".into(),
                ))
            })?;
        }
        Ok(Self::extension_tab_group_value(group))
    }

    fn extension_tab_group_value(group: &TabGroup) -> serde_json::Value {
        serde_json::json!({
            "id": group.id,
            "windowId": 1,
            "title": group.title,
            "color": group.color,
            "collapsed": group.collapsed,
            "tabIds": group.tab_ids.iter().map(|tab_id| tab_id.get()).collect::<Vec<_>>(),
        })
    }

    fn execute_extension_windows_create<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "windows.create expects an object".into(),
            ))
        })?;
        let previous_active = self.active_tab();
        let tab_id = self.new_tab();
        if let Some(url) = options.get("url").and_then(serde_json::Value::as_str) {
            self.configure_renderer_tab(tab_id, renderer)?;
            if let Ok(parsed_url) = Url::parse(url) {
                let injections = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .scripts_for_tab(&ExtensionTabInfo {
                        id: tab_id.get(),
                        url: Some(parsed_url),
                        active: true,
                    });
                renderer
                    .install_extension_scripts_for_tab(tab_id, &injections)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
            self.dispatch_web_navigation_before(tab_id, url, renderer)?;
            if let Err(error) = self.navigate_with_history_dispatch(tab_id, url, renderer) {
                let _ = self.dispatch_web_navigation_error(tab_id, url, renderer);
                let _ = self.close_tab_with_renderer(tab_id, renderer);
                return Err(ShellError::Navigation(error));
            }
            if let Some(navigated_url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
                self.dispatch_web_navigation_after(tab_id, &navigated_url, renderer, false)?;
            }
        }
        let active = options
            .get("active")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        self.dispatch_extension_tab_event(
            tab_id,
            |_, tab| ExtensionEventKind::TabCreated {
                tab: tab.unwrap_or(serde_json::Value::Null),
            },
            renderer,
        )?;
        if active {
            self.select_tab_with_renderer(tab_id, renderer)?;
            self.dispatch_extension_tab_event(
                tab_id,
                |_, _| ExtensionEventKind::TabActivated {
                    tab_id: tab_id.get(),
                    window_id: 1,
                },
                renderer,
            )?;
        } else if let Some(previous_active) = previous_active {
            self.select_tab_with_renderer(previous_active, renderer)?;
        }
        let window = self.execute_extension_window_value(extension_id, true)?;
        self.dispatch_extension_window_event(
            |_| ExtensionEventKind::WindowCreated {
                window: window.clone(),
            },
            renderer,
        )?;
        Ok(window)
    }

    fn execute_extension_windows_update<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let window_id = request
            .arguments
            .get("windowId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "windows.update requires windowId".into(),
                ))
            })?;
        if window_id != 1 {
            return Err(ShellError::Extension(ExtensionError::Missing(format!(
                "window {window_id}"
            ))));
        }
        let update = request
            .arguments
            .get("updateInfo")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "windows.update requires updateInfo".into(),
                ))
            })?;
        if update.get("focused").and_then(serde_json::Value::as_bool) == Some(true) {
            if let Some(first_tab) = self.tabs().first() {
                self.select_tab_with_renderer(first_tab.id, renderer)?;
            }
            self.dispatch_extension_window_event(
                |_| ExtensionEventKind::WindowFocusChanged { window_id: 1 },
                renderer,
            )?;
        }
        self.execute_extension_window_value(extension_id, false)
    }

    fn execute_extension_windows_remove<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let window_id = request
            .arguments
            .get("windowId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "windows.remove requires windowId".into(),
                ))
            })?;
        if window_id != 1 {
            return Err(ShellError::Extension(ExtensionError::Missing(format!(
                "window {window_id}"
            ))));
        }
        let tab_ids = self.tabs().iter().map(|tab| tab.id).collect::<Vec<_>>();
        for tab_id in tab_ids {
            if self.tab(tab_id).is_some() {
                self.close_tab_with_renderer(tab_id, renderer)?;
            }
        }
        self.dispatch_extension_window_event(
            |_| ExtensionEventKind::WindowRemoved { window_id: 1 },
            renderer,
        )?;
        let _ = extension_id;
        Ok(serde_json::Value::Null)
    }

    /// Builds the permission-filtered tab payload used by tab lifecycle
    /// events. The URL is only exposed when the extension holds the `tabs`
    /// permission and a host grant for the tab's origin; all other fields are
    /// always visible, matching Chromium's contract.
    fn extension_event_tab_value(
        &self,
        extension_id: &str,
        tab_id: TabId,
    ) -> Option<serde_json::Value> {
        let tab = self.tab(tab_id)?;
        let url = if tab.url.as_ref().is_some_and(|url| {
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_granted(extension_id, ExtensionPermission::Tabs)
                && self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_host_granted(extension_id, url)
        }) {
            tab.url.clone()
        } else {
            None
        };
        Some(extension_tab_value(&ExtensionTabInfo {
            id: tab.id.get(),
            url,
            active: self.active_tab() == Some(tab.id),
        }))
    }

    fn dispatch_extension_tab_event<R: PageRenderer>(
        &self,
        tab_id: TabId,
        make_event: impl Fn(&str, Option<serde_json::Value>) -> ExtensionEventKind,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let extension_ids = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| registry.is_enabled(&manifest.id))
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in extension_ids {
            let tab = self.extension_event_tab_value(&extension_id, tab_id);
            renderer
                .dispatch_extension_event(&ExtensionEvent {
                    extension_id: extension_id.clone(),
                    kind: make_event(&extension_id, tab),
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn dispatch_extension_window_event<R: PageRenderer>(
        &self,
        make_event: impl Fn(&str) -> ExtensionEventKind,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let extension_ids = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| registry.is_enabled(&manifest.id))
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in extension_ids {
            let kind = make_event(&extension_id);
            renderer
                .dispatch_extension_event(&ExtensionEvent { extension_id, kind })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn execute_extension_tabs_send_message(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let tab_id = request
            .arguments
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "tabs.sendMessage requires tabId".into(),
                ))
            })?;
        let message = request
            .arguments
            .get("message")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .validate_background_page_message(extension_id, tab.url.as_ref())
            .map_err(ShellError::Extension)?;
        renderer
            .dispatch_extension_message(
                tab_id,
                extension_id,
                &serde_json::json!({
                    "__nomad_tabs_request": {
                        "request_id": request.request_id,
                        "payload": message,
                    }
                }),
            )
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        Ok(serde_json::Value::Null)
    }

    fn extension_tab_json(
        &self,
        extension_id: &str,
        tab_id: TabId,
    ) -> Result<serde_json::Value, ShellError> {
        let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        let visible = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .query_tabs(
                extension_id,
                &[ExtensionTabInfo {
                    id: tab.id.get(),
                    url: tab.url.clone(),
                    active: self.active_tab() == Some(tab.id),
                }],
            )
            .map_err(ShellError::Extension)?
            .into_iter()
            .next()
            .ok_or(ShellError::MissingTab(tab_id))?;
        Ok(extension_tab_value(&visible))
    }

    fn execute_extension_history_search(&self, request: &ExtensionApiRequest) -> serde_json::Value {
        let query = request
            .arguments
            .get("text")
            .or_else(|| request.arguments.get("query"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        serde_json::Value::Array(
            self.search_history(query)
                .into_iter()
                .map(|visit| {
                    serde_json::json!({
                        "id": visit.id,
                        "tabId": visit.tab_id.get(),
                        "url": visit.url.to_string(),
                    })
                })
                .collect(),
        )
    }

    fn execute_extension_bookmarks_search(
        &self,
        request: &ExtensionApiRequest,
    ) -> serde_json::Value {
        let query = request
            .arguments
            .get("query")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        serde_json::Value::Array(
            self.search_bookmarks(query)
                .into_iter()
                .map(|bookmark| {
                    serde_json::json!({
                        "id": bookmark.id.get(),
                        "title": bookmark.title,
                        "url": bookmark.url.to_string(),
                    })
                })
                .collect(),
        )
    }

    fn execute_extension_history_get_visits(
        &self,
        request: &ExtensionApiRequest,
    ) -> serde_json::Value {
        let url = request
            .arguments
            .get("url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default();
        serde_json::Value::Array(
            self.runtime
                .history()
                .iter()
                .filter(|visit| visit.url.as_str() == url)
                .map(|visit| {
                    serde_json::json!({
                        "visitTime": visit.visited_at,
                        "transitionType": "link",
                    })
                })
                .collect(),
        )
    }

    fn execute_extension_history_add_url<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let raw = request
            .arguments
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "history.addUrl requires url".into(),
                ))
            })?;
        let url = Url::parse(raw).map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "history.addUrl URL is invalid".into(),
            ))
        })?;
        if !matches!(url.scheme(), "file" | "http" | "https") {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                "history.addUrl only accepts http(s) or file URLs".into(),
            )));
        }
        let before = self.runtime.history().last().map_or(0, |visit| visit.id);
        self.runtime.record_visit_for_url(url);
        let added: Vec<HistoryVisit> = self
            .runtime
            .history()
            .iter()
            .filter(|visit| visit.id > before)
            .cloned()
            .collect();
        self.dispatch_history_visited(added, renderer)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_history_delete_url<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let raw = request
            .arguments
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "history.deleteUrl requires url".into(),
                ))
            })?;
        let url = Url::parse(raw).map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "history.deleteUrl URL is invalid".into(),
            ))
        })?;
        if self.runtime.delete_history_url(&url) {
            self.dispatch_history_event(
                "history_visit_removed",
                &serde_json::json!({
                    "allHistory": false,
                    "urls": [raw],
                }),
                renderer,
            )?;
        }
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_history_delete_all<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let _ = self.runtime.clear_history();
        self.dispatch_history_event(
            "history_visit_removed",
            &serde_json::json!({
                "allHistory": true,
                "urls": [],
            }),
            renderer,
        )?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_history_delete_range<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let start_time = request
            .arguments
            .get("startTime")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let end_time = request
            .arguments
            .get("endTime")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(u64::MAX);
        if start_time > end_time {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                "history.deleteRange startTime must not exceed endTime".into(),
            )));
        }

        let removed = self.runtime.delete_history_range(start_time, end_time);
        let mut urls = removed
            .into_iter()
            .map(|visit| visit.url.to_string())
            .collect::<Vec<_>>();
        urls.sort();
        urls.dedup();
        if !urls.is_empty() {
            self.dispatch_history_event(
                "history_visit_removed",
                &serde_json::json!({
                    "allHistory": false,
                    "urls": urls,
                }),
                renderer,
            )?;
        }
        Ok(serde_json::Value::Null)
    }

    fn dispatch_history_event<R: PageRenderer>(
        &self,
        kind: &str,
        details: &serde_json::Value,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let installed = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| {
                    registry.is_enabled(&manifest.id)
                        && registry
                            .is_granted(&manifest.id, nomad_engine::ExtensionPermission::History)
                })
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in installed {
            let event = if kind == "history_visited" {
                nomad_engine::ExtensionEventKind::HistoryVisited {
                    details: details.clone(),
                }
            } else if kind == "history_title_changed" {
                nomad_engine::ExtensionEventKind::HistoryTitleChanged {
                    details: details.clone(),
                }
            } else {
                nomad_engine::ExtensionEventKind::HistoryVisitRemoved {
                    details: details.clone(),
                }
            };
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id,
                    kind: event,
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    pub fn dispatch_history_title_changed<R: PageRenderer>(
        &self,
        tab_id: TabId,
        title: Option<String>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let Some(tab) = self.tab(tab_id) else {
            return Err(ShellError::MissingTab(tab_id));
        };
        let Some(url) = tab.url.as_ref() else {
            return Ok(());
        };
        self.dispatch_history_event(
            "history_title_changed",
            &serde_json::json!({
                "id": tab_id.get(),
                "url": url.to_string(),
                "title": title.unwrap_or_default(),
            }),
            renderer,
        )
    }

    fn dispatch_history_visited<R: PageRenderer>(
        &self,
        visits: Vec<HistoryVisit>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        for visit in visits {
            self.dispatch_history_event(
                "history_visited",
                &serde_json::json!({
                    "url": visit.url.to_string(),
                    "visitTime": visit.visited_at,
                    "visitId": visit.id,
                }),
                renderer,
            )?;
        }
        Ok(())
    }

    fn navigate_with_history_dispatch<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        raw_url: &str,
        renderer: &mut R,
    ) -> Result<(), NavigationError> {
        let target = match self.take_web_request_blocking_decision(raw_url, "GET") {
            Some(decision) if decision.cancel => {
                return Err(NavigationError::BlockedByWebRequest(raw_url.to_owned()));
            }
            Some(decision) => decision.redirect_url.unwrap_or_else(|| raw_url.to_owned()),
            None => raw_url.to_owned(),
        };
        let before = self.runtime.history().last().map_or(0, |visit| visit.id);
        if let Ok(url) = Url::parse(&target) {
            let matched = {
                let registry = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                registry.matching_dnr_rules(&url, "GET")
            };
            for (extension_id, details) in matched {
                let dispatched = {
                    let mut registry = self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    registry.record_dnr_match(&extension_id);
                    registry
                        .dispatch_dnr_rule_matched(&extension_id, details)
                        .is_ok()
                };
                if dispatched {
                    let events = self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .drain_background_events(&extension_id);
                    for event in events {
                        renderer
                            .dispatch_extension_event(&event)
                            .map_err(|_error| {
                                NavigationError::Render(RenderError::BackendUnavailable)
                            })?;
                    }
                }
            }
        }
        let result = self
            .runtime
            .navigate_with_renderer(tab_id, &target, renderer);
        if result.is_ok() {
            if let Some(url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
                let generation = self
                    .extension_frames
                    .select(&ExtensionFrameTarget {
                        tab_id: tab_id.get(),
                        frame_ids: None,
                        all_frames: true,
                    })
                    .ok()
                    .and_then(|frames| frames.first().map(|frame| frame.navigation_generation + 1))
                    .unwrap_or(1);
                self.extension_frames.replace_tab(
                    tab_id.get(),
                    generation,
                    vec![ExtensionFrame::top(url, generation)],
                );
            }
        }
        let new_visits: Vec<HistoryVisit> = self
            .runtime
            .history()
            .iter()
            .filter(|visit| visit.id > before)
            .cloned()
            .collect();
        self.dispatch_history_visited(new_visits, renderer)
            .map_err(|error| match error {
                ShellError::Navigation(error) => error,
                _other => NavigationError::Render(RenderError::BackendUnavailable),
            })?;
        result
    }

    fn take_web_request_blocking_decision(
        &mut self,
        url: &str,
        method: &str,
    ) -> Option<BlockingDecision> {
        let mut decisions = self
            .web_request_blocking_decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = decisions.iter().position(|decision| {
            decision.url == url && decision.method.eq_ignore_ascii_case(method)
        })?;
        Some(decisions.remove(index))
    }

    fn bookmark_node(&self, bookmark: &Bookmark) -> serde_json::Value {
        let index = self
            .bookmarks
            .bookmarks()
            .iter()
            .position(|candidate| candidate.id == bookmark.id)
            .unwrap_or(0);
        serde_json::json!({
            "id": bookmark.id.get().to_string(),
            "parentId": bookmark
                .folder_id.map_or_else(|| "0".to_owned(), |folder_id| folder_id.get().to_string()),
            "index": index,
            "title": bookmark.title,
            "url": bookmark.url.to_string(),
        })
    }

    fn bookmark_folder_node(&self, folder: &BookmarkFolder) -> serde_json::Value {
        let index = self
            .bookmarks
            .folders()
            .iter()
            .position(|candidate| candidate.id == folder.id)
            .unwrap_or(0);
        serde_json::json!({
            "id": folder.id.get().to_string(),
            "parentId": "0",
            "index": index,
            "title": folder.name,
        })
    }

    fn bookmark_children(&self, parent: &str) -> Vec<serde_json::Value> {
        let mut children = Vec::new();
        if parent == "0" {
            for folder in self.bookmarks.folders() {
                children.push(self.bookmark_folder_node(folder));
            }
            for bookmark in self.bookmarks.bookmarks() {
                if bookmark.folder_id.is_none() {
                    children.push(self.bookmark_node(bookmark));
                }
            }
        } else if let Ok(folder_id) = parent.parse::<u64>() {
            for bookmark in self.bookmarks.bookmarks() {
                if bookmark.folder_id == Some(BookmarkFolderId::new(folder_id)) {
                    children.push(self.bookmark_node(bookmark));
                }
            }
        }
        children
    }

    fn bookmark_subtree(&self, id: &str) -> Option<serde_json::Value> {
        if id == "0" {
            let mut children = Vec::new();
            for folder in self.bookmarks.folders() {
                children.push(self.bookmark_folder_node(folder));
            }
            for bookmark in self.bookmarks.bookmarks() {
                if bookmark.folder_id.is_none() {
                    children.push(self.bookmark_node(bookmark));
                }
            }
            let mut root = serde_json::json!({
                "id": "0",
                "parentId": "0",
                "index": 0,
                "title": "",
            });
            root["children"] = serde_json::Value::Array(children);
            return Some(root);
        }
        if let Ok(folder_id) = id.parse::<u64>() {
            if let Some(folder) = self.bookmarks.folder(BookmarkFolderId::new(folder_id)) {
                let mut node = self.bookmark_folder_node(folder);
                node["children"] = serde_json::Value::Array(self.bookmark_children(id));
                return Some(node);
            }
        }
        if let Ok(bookmark_id) = id.parse::<u64>() {
            self.bookmarks
                .get(BookmarkId::new(bookmark_id))
                .map(|bookmark| self.bookmark_node(bookmark))
        } else {
            None
        }
    }

    fn execute_extension_bookmarks_get(
        &self,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let ids = request
            .arguments
            .get("ids")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.get requires ids".into(),
                ))
            })?;
        let mut nodes = Vec::new();
        for id in ids.iter().filter_map(serde_json::Value::as_str) {
            let node = self.bookmark_subtree(id).ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(format!(
                    "no bookmark with id {id}"
                )))
            })?;
            let mut node = node;
            node.as_object_mut().map(|object| object.remove("children"));
            nodes.push(node);
        }
        Ok(serde_json::Value::Array(nodes))
    }

    fn execute_extension_bookmarks_get_children(
        &self,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.getChildren requires id".into(),
                ))
            })?;
        if id != "0"
            && !id.parse::<u64>().is_ok_and(|folder_id| {
                self.bookmarks
                    .folder(BookmarkFolderId::new(folder_id))
                    .is_some()
            })
        {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                format!("no folder with id {id}"),
            )));
        }
        Ok(serde_json::Value::Array(self.bookmark_children(id)))
    }

    fn execute_extension_bookmarks_get_tree(&self) -> serde_json::Value {
        serde_json::json!([self.bookmark_subtree("0").unwrap()])
    }

    fn execute_extension_bookmarks_get_sub_tree(
        &self,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.getSubTree requires id".into(),
                ))
            })?;
        self.bookmark_subtree(id)
            .map(|node| serde_json::json!([node]))
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(format!(
                    "no bookmark with id {id}"
                )))
            })
    }

    fn execute_extension_bookmarks_create<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "bookmarks.create expects an object".into(),
            ))
        })?;
        let parent_id = options
            .get("parentId")
            .and_then(serde_json::Value::as_str)
            .filter(|id| *id != "0")
            .map(|id| {
                id.parse::<u64>().map_err(|_| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "bookmarks.create parentId is invalid".into(),
                    ))
                })
            })
            .transpose()?;
        if let Some(url) = options.get("url").and_then(serde_json::Value::as_str) {
            let url = url::Url::parse(url).map_err(|_| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.create url is invalid".into(),
                ))
            })?;
            let title = options
                .get("title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let id = self
                .bookmarks
                .add_in_folder(url.clone(), title, parent_id.map(BookmarkFolderId::new))
                .map_err(ShellError::Bookmark)?;
            let bookmark = self.bookmarks.get(id).expect("bookmark exists");
            let node = self.bookmark_node(bookmark);
            self.dispatch_bookmark_event("created", &node, None, extension_id, renderer)?;
            return Ok(node);
        }
        let name = options
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let folder_id = self
            .bookmarks
            .create_folder(name)
            .map_err(ShellError::Bookmark)?;
        let folder = self.bookmarks.folder(folder_id).expect("folder exists");
        let node = self.bookmark_folder_node(folder);
        self.dispatch_bookmark_event("created", &node, None, extension_id, renderer)?;
        Ok(node)
    }

    fn execute_extension_bookmarks_move<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.move requires id".into(),
                ))
            })?;
        let bookmark_id = id.parse::<u64>().map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "bookmarks.move id is invalid".into(),
            ))
        })?;
        let old_node = self
            .bookmarks
            .get(BookmarkId::new(bookmark_id))
            .map(|bookmark| self.bookmark_node(bookmark))
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.move targets a missing bookmark".into(),
                ))
            })?;
        let destination = request
            .arguments
            .get("destination")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.move requires destination".into(),
                ))
            })?;
        let parent = destination
            .get("parentId")
            .and_then(serde_json::Value::as_str)
            .filter(|parent| *parent != "0")
            .map(|parent| {
                parent.parse::<u64>().map_err(|_| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "bookmarks.move parentId is invalid".into(),
                    ))
                })
            })
            .transpose()?;
        let target = parent.map(BookmarkFolderId::new);
        let old_parent = old_node["parentId"].as_str().unwrap_or("0").to_owned();
        let old_index = old_node["index"].as_u64().unwrap_or(0);
        self.bookmarks
            .move_to_folder(BookmarkId::new(bookmark_id), target)
            .map_err(ShellError::Bookmark)?;
        let new_node = self
            .bookmarks
            .get(BookmarkId::new(bookmark_id))
            .map(|bookmark| self.bookmark_node(bookmark))
            .expect("moved bookmark exists");
        let index = new_node["index"].as_u64().unwrap_or(0);
        let new_parent = new_node["parentId"].as_str().unwrap_or("0").to_owned();
        renderer
            .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: nomad_engine::ExtensionEventKind::BookmarkMoved {
                    id: id.to_owned(),
                    old_parent_id: old_parent,
                    old_index,
                    parent_id: new_parent,
                    index,
                },
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        Ok(new_node)
    }

    fn execute_extension_bookmarks_update<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.update requires id".into(),
                ))
            })?;
        let bookmark_id = id.parse::<u64>().map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "bookmarks.update id is invalid".into(),
            ))
        })?;
        if self.bookmarks.get(BookmarkId::new(bookmark_id)).is_none() {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                format!("no bookmark with id {id}"),
            )));
        }
        let changes = request
            .arguments
            .get("changes")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.update requires changes".into(),
                ))
            })?;
        if let Some(title) = changes.get("title").and_then(serde_json::Value::as_str) {
            self.bookmarks
                .rename(BookmarkId::new(bookmark_id), title)
                .map_err(ShellError::Bookmark)?;
        }
        if let Some(raw) = changes.get("url").and_then(serde_json::Value::as_str) {
            let url = url::Url::parse(raw).map_err(|_| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.update url is invalid".into(),
                ))
            })?;
            self.bookmarks
                .set_url(BookmarkId::new(bookmark_id), url)
                .map_err(ShellError::Bookmark)?;
        }
        let node = self
            .bookmarks
            .get(BookmarkId::new(bookmark_id))
            .map(|bookmark| self.bookmark_node(bookmark))
            .expect("bookmark exists");
        let title = node["title"].as_str().unwrap_or_default().to_owned();
        let url = node["url"].as_str().map(str::to_owned);
        renderer
            .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: nomad_engine::ExtensionEventKind::BookmarkChanged {
                    id: id.to_owned(),
                    title,
                    url,
                },
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        Ok(node)
    }

    fn execute_extension_bookmarks_remove<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.remove requires id".into(),
                ))
            })?;
        let bookmark_id = id.parse::<u64>().map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "bookmarks.remove id is invalid".into(),
            ))
        })?;
        if self
            .bookmarks
            .folder(BookmarkFolderId::new(bookmark_id))
            .is_some()
        {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                "bookmarks.remove cannot remove folders".into(),
            )));
        }
        let parent_id = self
            .bookmarks
            .get(BookmarkId::new(bookmark_id))
            .map(|bookmark| {
                bookmark
                    .folder_id
                    .map_or_else(|| "0".to_owned(), |folder_id| folder_id.get().to_string())
            })
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.remove targets a missing bookmark".into(),
                ))
            })?;
        let index = self
            .bookmarks
            .bookmarks()
            .iter()
            .position(|bookmark| bookmark.id == BookmarkId::new(bookmark_id))
            .unwrap_or(0);
        self.bookmarks
            .remove(BookmarkId::new(bookmark_id))
            .map_err(ShellError::Bookmark)?;
        self.dispatch_bookmark_event(
            "removed",
            &serde_json::json!({"id": id}),
            Some((parent_id, index as u64)),
            extension_id,
            renderer,
        )?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_bookmarks_remove_tree<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "bookmarks.removeTree requires id".into(),
                ))
            })?;
        let folder_id = id.parse::<u64>().map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "bookmarks.removeTree id is invalid".into(),
            ))
        })?;
        if self
            .bookmarks
            .folder(BookmarkFolderId::new(folder_id))
            .is_none()
        {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                format!("no folder with id {id}"),
            )));
        }
        let contained: Vec<BookmarkId> = self
            .bookmarks
            .bookmarks()
            .iter()
            .filter(|bookmark| bookmark.folder_id == Some(BookmarkFolderId::new(folder_id)))
            .map(|bookmark| bookmark.id)
            .collect();
        for bookmark_id in contained {
            let index = self
                .bookmarks
                .bookmarks()
                .iter()
                .position(|bookmark| bookmark.id == bookmark_id)
                .unwrap_or(0);
            self.bookmarks
                .remove(bookmark_id)
                .map_err(ShellError::Bookmark)?;
            self.dispatch_bookmark_event(
                "removed",
                &serde_json::json!({"id": bookmark_id.get().to_string()}),
                Some((id.to_owned(), index as u64)),
                extension_id,
                renderer,
            )?;
        }
        self.bookmarks
            .remove_folder(BookmarkFolderId::new(folder_id))
            .map_err(ShellError::Bookmark)?;
        self.dispatch_bookmark_event(
            "removed",
            &serde_json::json!({"id": id}),
            Some(("0".to_owned(), 0)),
            extension_id,
            renderer,
        )?;
        Ok(serde_json::Value::Null)
    }

    fn dispatch_bookmark_event<R: PageRenderer>(
        &self,
        kind: &str,
        node: &serde_json::Value,
        removed: Option<(String, u64)>,
        _extension_id: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let event = match kind {
            "created" => nomad_engine::ExtensionEventKind::BookmarkCreated {
                bookmark: node.clone(),
            },
            "removed" => {
                let (parent_id, index) = removed.expect("removed event requires parent");
                nomad_engine::ExtensionEventKind::BookmarkRemoved {
                    id: node["id"].as_str().unwrap_or_default().to_owned(),
                    parent_id,
                    index,
                }
            }
            _ => unreachable!("unknown bookmark event kind"),
        };
        let installed = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| {
                    registry.is_enabled(&manifest.id)
                        && registry
                            .is_granted(&manifest.id, nomad_engine::ExtensionPermission::Bookmarks)
                })
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in installed {
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id,
                    kind: event.clone(),
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn execute_extension_downloads_search(
        &self,
        request: &ExtensionApiRequest,
    ) -> serde_json::Value {
        let query = request
            .arguments
            .get("query")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        serde_json::Value::Array(
            self.downloads()
                .iter()
                .filter(|download| {
                    query.is_empty()
                        || download.url.as_str().to_ascii_lowercase().contains(&query)
                        || download
                            .suggested_filename
                            .to_ascii_lowercase()
                            .contains(&query)
                })
                .map(|download| {
                    serde_json::json!({
                        "id": download.id.get(),
                        "url": download.url.to_string(),
                        "filename": download.destination,
                        "bytesReceived": download.bytes_received,
                        "totalBytes": download.total_bytes,
                        "state": format!("{:?}", download.state).to_ascii_lowercase(),
                    })
                })
                .collect(),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn execute_extension_action(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        match request.method.as_str() {
            "action.setBadgeText" => {
                let text = request
                    .arguments
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_set_badge_text(extension_id, text);
            }
            "action.setBadgeBackgroundColor" => {
                let color = request
                    .arguments
                    .get("color")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_set_badge_background_color(extension_id, color);
            }
            "action.setBadgeTextColor" => {
                let color = request
                    .arguments
                    .get("color")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_set_badge_text_color(extension_id, color);
            }
            "action.setIcon" => {
                let details = request.arguments.as_object().ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "action.setIcon expects an object".into(),
                    ))
                })?;
                let icon = details
                    .get("path")
                    .or_else(|| details.get("imageData"))
                    .cloned()
                    .ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "action.setIcon requires path or imageData".into(),
                        ))
                    })?;
                if icon.is_null() {
                    return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                        "action.setIcon path or imageData cannot be null".into(),
                    )));
                }
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_set_icon(extension_id, Some(icon));
            }
            "action.setTitle" => {
                let title = request
                    .arguments
                    .get("title")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_set_title(extension_id, title);
            }
            "action.setPopup" => {
                let popup = request
                    .arguments
                    .get("popup")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_set_popup(extension_id, popup);
            }
            "action.enable" => self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .action_set_enabled(extension_id, true),
            "action.disable" => self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .action_set_enabled(extension_id, false),
            "action.getBadgeText" => {
                return Ok(serde_json::json!(self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_get_badge_text(extension_id)));
            }
            "action.getBadgeBackgroundColor" => {
                return Ok(serde_json::json!(self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_get_badge_background_color(extension_id)));
            }
            "action.getBadgeTextColor" => {
                return Ok(serde_json::json!(self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_get_badge_text_color(extension_id)));
            }
            "action.getTitle" => {
                return Ok(serde_json::json!(self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_get_title(extension_id)));
            }
            "action.getPopup" => {
                return Ok(serde_json::json!(self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .action_get_popup(extension_id)));
            }
            _ => {
                return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                    format!("unsupported extension API {:?}", request.method),
                )));
            }
        }
        Ok(serde_json::json!(null))
    }

    fn execute_extension_web_request_resolve_blocking(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        if !self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_granted(extension_id, ExtensionPermission::WebRequestBlocking)
        {
            return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                "webRequest blocking responses require the webRequestBlocking permission".into(),
            )));
        }
        let url = request
            .arguments
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "webRequest.resolveBlocking requires a url".into(),
                ))
            })?;
        Url::parse(url).map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "webRequest.resolveBlocking url is invalid".into(),
            ))
        })?;
        let cancel = request
            .arguments
            .get("cancel")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let redirect_url = request
            .arguments
            .get("redirectUrl")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        if !cancel && redirect_url.is_none() {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                "webRequest.resolveBlocking requires cancel or redirectUrl".into(),
            )));
        }
        let method = request
            .arguments
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("GET")
            .to_owned();
        let mut decisions = self
            .web_request_blocking_decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        decisions.push(BlockingDecision {
            url: url.to_owned(),
            method,
            cancel,
            redirect_url,
            request_headers: request
                .arguments
                .get("requestHeaders")
                .and_then(serde_json::Value::as_array)
                .map(|headers| {
                    headers
                        .iter()
                        .filter_map(|header| {
                            Some((
                                header.get("name")?.as_str()?.to_owned(),
                                header
                                    .get("value")
                                    .and_then(serde_json::Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ))
                        })
                        .collect()
                }),
            response_headers: request
                .arguments
                .get("responseHeaders")
                .and_then(serde_json::Value::as_array)
                .map(|headers| {
                    headers
                        .iter()
                        .filter_map(|header| {
                            Some((
                                header.get("name")?.as_str()?.to_owned(),
                                header
                                    .get("value")
                                    .and_then(serde_json::Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ))
                        })
                        .collect()
                }),
        });
        if decisions.len() > Self::MAX_BLOCKING_DECISIONS {
            let drop_count = decisions.len() - Self::MAX_BLOCKING_DECISIONS;
            decisions.drain(0..drop_count);
        }
        Ok(serde_json::json!(null))
    }

    fn execute_extension_web_request_handler_behavior_changed(
        &self,
        extension_id: &str,
        _request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        if !self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_granted(extension_id, ExtensionPermission::WebRequestBlocking)
        {
            return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                "webRequest.handlerBehaviorChanged requires the webRequestBlocking permission"
                    .into(),
            )));
        }
        Ok(serde_json::json!(null))
    }

    fn execute_extension_dnr_update_enabled_rulesets(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let arguments = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "updateEnabledRulesets expects an object".into(),
            ))
        })?;
        let ids = |name: &str| {
            arguments
                .get(name)
                .map(|value| {
                    value
                        .as_array()
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(format!(
                                "{name} must be an array"
                            )))
                        })?
                        .iter()
                        .map(|value| {
                            value.as_str().map(str::to_owned).ok_or_else(|| {
                                ShellError::Extension(ExtensionError::InvalidManifest(format!(
                                    "{name} must contain string IDs"
                                )))
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map(Option::unwrap_or_default)
        };
        let enable = ids("enableRulesetIds")?;
        let disable = ids("disableRulesetIds")?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .update_enabled_rulesets(extension_id, &enable, &disable)
            .map(|_| serde_json::Value::Null)
            .map_err(ShellError::Extension)
    }

    fn execute_extension_dnr_is_regex_supported(
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let pattern = request
            .arguments
            .get("regex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "declarativeNetRequest.isRegexSupported requires a regex".into(),
                ))
            })?;
        let unsupported = pattern.contains("(?=")
            || pattern.contains("(?<=")
            || pattern.contains("(?<")
            || pattern.contains("(?!")
            || pattern.contains("(?<!")
            || pattern.contains(r"\d")
            || pattern.contains(r"\k");
        let mut result = serde_json::json!({"isSupported": !unsupported});
        if unsupported {
            result["reason"] = serde_json::json!("syntaxError");
        }
        Ok(result)
    }

    fn execute_extension_dnr_set_extension_action_options(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request
            .arguments
            .get("options")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "declarativeNetRequest.setExtensionActionOptions requires an options object"
                        .into(),
                ))
            })?;
        if let Some(badge) = options.get("displayActionCountAsBadgeText") {
            let value = badge.as_bool().ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "displayActionCountAsBadgeText must be a boolean".into(),
                ))
            })?;
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .set_dnr_action_options(extension_id, value)
                .map_err(ShellError::Extension)?;
        }
        Ok(serde_json::json!(null))
    }

    fn execute_extension_identity_get_auth_token<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let interactive = request
            .arguments
            .get("interactive")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let provider = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .oauth_provider(extension_id)
            .cloned();
        let Some(provider) = provider else {
            // Without an `oauth2` manifest section the browser profile
            // account token remains the token source.
            return self
                .identity_account_token
                .clone()
                .map(serde_json::Value::String)
                .map(|token| serde_json::json!(token))
                .ok_or_else(|| {
                    ShellError::Extension(ExtensionError::PermissionDenied(
                        "Not authorized: no identity account token is available".into(),
                    ))
                });
        };
        let key = nomad_engine::token_key(extension_id, &provider.client_id, &provider.scopes);
        let record = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .oauth_token_for_key(&key)
            .cloned();
        let now_ms = unix_time_millis();
        match record {
            Some(record) if !record.is_expired_at(now_ms) => {
                Ok(serde_json::json!(record.access_token))
            }
            expired => self.serve_or_restart_provider_grant(
                ProviderGrantRequest {
                    extension_id,
                    provider: &provider,
                    key: &key,
                    expired,
                    interactive,
                    request_id: &request.request_id,
                },
                renderer,
            ),
        }
    }

    /// Serves a provider grant: refreshes an expired access token through the
    /// token endpoint, or - only when `interactive` - starts a fresh
    /// authorization flow whose response is deferred to the redirect.
    fn serve_or_restart_provider_grant<R: PageRenderer>(
        &mut self,
        grant: ProviderGrantRequest<'_>,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        if let Some(record) = grant.expired {
            match record.refresh_token.clone() {
                Some(refresh_token) => {
                    let exchange_request = nomad_engine::TokenExchangeRequest::new(
                        grant.provider.resolved_token_endpoint(),
                        &nomad_engine::refresh_request_body(
                            &refresh_token,
                            &grant.provider.client_id,
                        ),
                    )
                    .map_err(|error| {
                        ShellError::Extension(ExtensionError::PermissionDenied(format!("{error}")))
                    })?;
                    match self.oauth_token_exchange.exchange(&exchange_request) {
                        Ok(updated) => {
                            self.extensions
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .store_oauth_token(grant.key.to_owned(), updated.clone());
                            return Ok(serde_json::json!(updated.access_token));
                        }
                        Err(
                            nomad_engine::OAuthFlowError::InvalidGrant
                            | nomad_engine::OAuthFlowError::InvalidClient,
                        ) => self.drop_provider_grant(grant.extension_id, grant.key, renderer)?,
                        Err(error) => {
                            return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                                format!("{error}"),
                            )));
                        }
                    }
                }
                None => self.drop_provider_grant(grant.extension_id, grant.key, renderer)?,
            }
        }
        if grant.interactive {
            self.begin_provider_sign_in_flow(
                grant.extension_id,
                grant.provider,
                grant.request_id,
                renderer,
            )?;
            Ok(serde_json::Value::Null)
        } else {
            Err(ShellError::Extension(ExtensionError::PermissionDenied(
                "Not authorized: user interaction required to sign in".into(),
            )))
        }
    }

    /// Opens a flow tab on the provider's authorize endpoint and registers
    /// the pending flow; completion is wired to real navigation events.
    fn begin_provider_sign_in_flow<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        provider: &nomad_engine::OAuthProviderConfig,
        request_id: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let redirect_uri = nomad_engine::redirect_uri_for_extension(extension_id);
        let pair = nomad_engine::generate_pkce_pair().map_err(|error| {
            ShellError::Extension(ExtensionError::PermissionDenied(format!("{error}")))
        })?;
        let flow_id = self.next_flow_id();
        let token_key =
            nomad_engine::token_key(extension_id, &provider.client_id, &provider.scopes);
        let auth_url =
            nomad_engine::build_authorize_url(provider, &redirect_uri, &flow_id, &pair.challenge)
                .map_err(|error| {
                ShellError::Extension(ExtensionError::PermissionDenied(format!("{error}")))
            })?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_pending_auth_flow(nomad_engine::PendingAuthFlow {
                flow_id: flow_id.clone(),
                extension_id: extension_id.to_owned(),
                request_id: request_id.to_owned(),
                kind: nomad_engine::PendingAuthFlowKind::ProviderSignIn,
                auth_url: auth_url.clone(),
                redirect_uri,
                state: Some(flow_id.clone()),
                code_verifier: Some(pair.verifier),
                token_key: Some(token_key),
                created_at_ms: unix_time_millis(),
            })
            .map_err(ShellError::Extension)?;
        self.open_auth_flow_tab(&flow_id, &auth_url, renderer)?;
        Ok(())
    }

    fn execute_extension_identity_launch_web_auth_flow<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let raw = request
            .arguments
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "identity.launchWebAuthFlow requires a url".into(),
                ))
            })?;
        let url = Url::parse(raw).map_err(|_| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "identity.launchWebAuthFlow url is invalid".into(),
            ))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                "identity.launchWebAuthFlow only accepts http(s) urls".into(),
            )));
        }
        let redirect_uri = url
            .query_pairs()
            .find(|(name, _)| name == "redirect_uri")
            .map(|(_, value)| value.to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| nomad_engine::redirect_uri_for_extension(extension_id));
        let flow_id = self.next_flow_id();
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_pending_auth_flow(nomad_engine::PendingAuthFlow {
                flow_id: flow_id.clone(),
                extension_id: extension_id.to_owned(),
                request_id: request.request_id.clone(),
                kind: nomad_engine::PendingAuthFlowKind::LaunchWebAuthFlow,
                auth_url: raw.to_owned(),
                redirect_uri,
                state: None,
                code_verifier: None,
                token_key: None,
                created_at_ms: unix_time_millis(),
            })
            .map_err(ShellError::Extension)?;
        self.open_auth_flow_tab(&flow_id, raw, renderer)?;
        // The response is deferred until the provider redirect navigates the
        // flow tab back to its redirect target.
        Ok(serde_json::Value::Null)
    }

    fn next_flow_id(&self) -> String {
        format!(
            "flow-{}-{}",
            unix_time_millis(),
            self.pending_auth_flow_tabs.len()
        )
    }

    /// Creates the flow tab, binds it to `flow_id`, and navigates it to
    /// `url`. Failures resolve the deferred request with an error; success
    /// keeps the response pending until the redirect completes the flow.
    fn open_auth_flow_tab<R: PageRenderer>(
        &mut self,
        flow_id: &str,
        url: &str,
        renderer: &mut R,
    ) -> Result<TabId, ShellError> {
        let previous_tab = self.active_tab();
        let tab_id = self.new_tab();
        self.pending_auth_flow_tabs
            .insert(tab_id, flow_id.to_owned());
        self.configure_renderer_tab(tab_id, renderer)?;
        self.dispatch_web_navigation_before(tab_id, url, renderer)?;
        if let Err(error) = self.navigate_with_history_dispatch(tab_id, url, renderer) {
            let _ = self.dispatch_web_navigation_error(tab_id, url, renderer);
            self.fail_pending_auth_flows_for_tab(tab_id, &format!("{error:?}"), renderer)?;
            let _ = self.close_tab_with_renderer(tab_id, renderer);
            return Ok(tab_id);
        }
        self.dispatch_extension_tab_event(
            tab_id,
            |_, tab| ExtensionEventKind::TabCreated {
                tab: tab.unwrap_or(serde_json::Value::Null),
            },
            renderer,
        )?;
        if let Some(navigated_url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
            self.dispatch_web_navigation_after(tab_id, &navigated_url, renderer, false)?;
        }
        if let Some(previous_tab) = previous_tab {
            self.select_tab_with_renderer(previous_tab, renderer)?;
        }
        Ok(tab_id)
    }

    /// Resolves any pending flow bound to `tab_id` with an error (for
    /// example when the authorization page fails to load).
    fn fail_pending_auth_flows_for_tab<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        message: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let Some(flow_id) = self.pending_auth_flow_tabs.remove(&tab_id) else {
            return Ok(());
        };
        let owner = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take_pending_auth_flow(&flow_id)
            .map(|flow| (flow.extension_id, flow.request_id));
        if let Some((extension_id, request_id)) = owner {
            Self::respond_extension_request(
                &extension_id,
                &request_id,
                Err(message.to_owned()),
                renderer,
            )?;
        }
        Ok(())
    }

    /// Completes pending authorization flows whose redirect target matches a
    /// navigation. Wired into [`Self::dispatch_web_navigation_after`], so the
    /// provider's redirect - browser or page driven - resolves the deferred
    /// extension request.
    fn complete_pending_auth_flows<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        url: &Url,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let Some(flow_id) = self.pending_auth_flow_tabs.get(&tab_id).cloned() else {
            return Ok(());
        };
        let matched = {
            let mut registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match registry.take_pending_auth_flow(&flow_id) {
                Some(flow)
                    if nomad_engine::redirect_matches_redirect_uri(url, &flow.redirect_uri) =>
                {
                    Some(flow)
                }
                Some(flow) => {
                    // Intermediate navigation inside the provider; keep waiting.
                    let _ = registry.set_pending_auth_flow(flow);
                    None
                }
                None => {
                    self.pending_auth_flow_tabs.remove(&tab_id);
                    None
                }
            }
        };
        let Some(flow) = matched else {
            return Ok(());
        };
        self.pending_auth_flow_tabs.remove(&tab_id);
        match flow.kind {
            nomad_engine::PendingAuthFlowKind::LaunchWebAuthFlow => {
                let result = match nomad_engine::authorization_completion(url) {
                    Ok(_) => Ok(serde_json::json!({ "responseUrl": url.as_str() })),
                    Err(error) => Err(format!("{error}")),
                };
                Self::respond_extension_request(
                    &flow.extension_id,
                    &flow.request_id,
                    result,
                    renderer,
                )?;
                let _ = self.close_tab_with_renderer(tab_id, renderer);
            }
            nomad_engine::PendingAuthFlowKind::ProviderSignIn => {
                match nomad_engine::authorization_completion(url) {
                    Ok(Some(code)) => {
                        self.exchange_provider_code(&flow, &code, tab_id, renderer)?;
                    }
                    Ok(None) => {
                        Self::respond_extension_request(
                            &flow.extension_id,
                            &flow.request_id,
                            Err("Authorization redirect is missing the authorization code".into()),
                            renderer,
                        )?;
                        let _ = self.close_tab_with_renderer(tab_id, renderer);
                    }
                    Err(error) => {
                        Self::respond_extension_request(
                            &flow.extension_id,
                            &flow.request_id,
                            Err(format!("{error}")),
                            renderer,
                        )?;
                        let _ = self.close_tab_with_renderer(tab_id, renderer);
                    }
                }
            }
        }
        Ok(())
    }

    /// Exchanges the authorization code at the token endpoint, persists the
    /// grant under the extension's token key, and dispatches the
    /// `onSignInChanged` transition.
    fn exchange_provider_code<R: PageRenderer>(
        &mut self,
        flow: &nomad_engine::PendingAuthFlow,
        code: &str,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let provider = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .oauth_provider(&flow.extension_id)
            .cloned();
        let Some(provider) = provider else {
            Self::respond_extension_request(
                &flow.extension_id,
                &flow.request_id,
                Err("Extension provider configuration is unavailable".into()),
                renderer,
            )?;
            let _ = self.close_tab_with_renderer(tab_id, renderer);
            return Ok(());
        };
        let code_verifier = flow.code_verifier.clone().unwrap_or_default();
        let exchange_request = nomad_engine::TokenExchangeRequest::new(
            provider.resolved_token_endpoint(),
            &nomad_engine::exchange_request_body(
                code,
                &flow.redirect_uri,
                &provider.client_id,
                &code_verifier,
            ),
        )
        .map_err(|error| {
            ShellError::Extension(ExtensionError::PermissionDenied(format!("{error}")))
        })?;
        match self.oauth_token_exchange.exchange(&exchange_request) {
            Ok(record) => {
                let token = record.access_token.clone();
                let account = record.account_id.clone();
                let key = flow.token_key.clone().unwrap_or_else(|| {
                    nomad_engine::token_key(
                        &flow.extension_id,
                        &provider.client_id,
                        &provider.scopes,
                    )
                });
                self.extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .store_oauth_token(key, record);
                let transition = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_oauth_account(&flow.extension_id, account);
                if let Some((account_id, signed_in)) = transition {
                    Self::dispatch_identity_sign_in_changed(
                        &flow.extension_id,
                        Some(account_id),
                        signed_in,
                        renderer,
                    )?;
                }
                Self::respond_extension_request(
                    &flow.extension_id,
                    &flow.request_id,
                    Ok(serde_json::json!(token)),
                    renderer,
                )?;
                let _ = self.close_tab_with_renderer(tab_id, renderer);
            }
            Err(error) => {
                Self::respond_extension_request(
                    &flow.extension_id,
                    &flow.request_id,
                    Err(format!("{error}")),
                    renderer,
                )?;
                let _ = self.close_tab_with_renderer(tab_id, renderer);
            }
        }
        Ok(())
    }

    /// Removes a dead provider grant and reports the sign-out transition.
    fn drop_provider_grant<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        key: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let transition = {
            let mut registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.take_oauth_token(key);
            registry.set_oauth_account(extension_id, None)
        };
        if let Some((account_id, signed_in)) = transition {
            Self::dispatch_identity_sign_in_changed(
                extension_id,
                Some(account_id),
                signed_in,
                renderer,
            )?;
        }
        Ok(())
    }

    fn respond_extension_request<R: PageRenderer>(
        extension_id: &str,
        request_id: &str,
        result: Result<serde_json::Value, String>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        renderer
            .dispatch_extension_event(&ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: ExtensionEventKind::RuntimeResponse {
                    request_id: request_id.to_owned(),
                    result,
                },
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))
    }

    fn dispatch_identity_sign_in_changed<R: PageRenderer>(
        extension_id: &str,
        account_id: Option<String>,
        signed_in: bool,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        renderer
            .dispatch_extension_event(&ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: ExtensionEventKind::IdentitySignInChanged {
                    signed_in,
                    account: account_id.map_or(
                        serde_json::Value::Null,
                        |id| serde_json::json!({ "id": id }),
                    ),
                },
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))
    }

    fn download_item_json(download: &DownloadSnapshot) -> serde_json::Value {
        serde_json::json!({
            "id": download.id.get(),
            "url": download.url.to_string(),
            "filename": download.destination,
            "bytesReceived": download.bytes_received,
            "totalBytes": download.total_bytes,
            "state": format!("{:?}", download.state).to_ascii_lowercase(),
            "error": download.error,
        })
    }

    fn dispatch_download_event<R: PageRenderer>(
        &self,
        kind: &str,
        payload: &serde_json::Value,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let event = match kind {
            "created" => nomad_engine::ExtensionEventKind::DownloadCreated {
                details: payload.clone(),
            },
            "changed" => nomad_engine::ExtensionEventKind::DownloadChanged {
                details: payload.clone(),
            },
            "erased" => nomad_engine::ExtensionEventKind::DownloadErased {
                id: payload["id"].as_u64().unwrap_or_default().to_string(),
            },
            _ => unreachable!("unknown download event kind"),
        };
        let installed = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| {
                    registry.is_enabled(&manifest.id)
                        && registry
                            .is_granted(&manifest.id, nomad_engine::ExtensionPermission::Downloads)
                })
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in installed {
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id,
                    kind: event.clone(),
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn download_id_from_request(
        &self,
        method: &str,
        request: &ExtensionApiRequest,
    ) -> Result<DownloadId, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(format!(
                    "{method} requires a numeric id"
                )))
            })?;
        if self.downloads.get(DownloadId::new(id)).is_none() {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                format!("no download with id {id}"),
            )));
        }
        Ok(DownloadId::new(id))
    }

    fn execute_extension_downloads_pause<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = self.download_id_from_request("downloads.pause", request)?;
        let changed = self.downloads.pause(id).is_ok();
        if changed {
            self.dispatch_download_event(
                "changed",
                &serde_json::json!({"id": id.get(), "state": "paused"}),
                renderer,
            )?;
        }
        Ok(serde_json::json!(changed))
    }

    fn execute_extension_downloads_resume<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = self.download_id_from_request("downloads.resume", request)?;
        let changed = self.downloads.resume(id).is_ok();
        if changed {
            self.dispatch_download_event(
                "changed",
                &serde_json::json!({"id": id.get(), "state": "in_progress"}),
                renderer,
            )?;
        }
        Ok(serde_json::json!(changed))
    }

    fn execute_extension_downloads_cancel<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = self.download_id_from_request("downloads.cancel", request)?;
        let changed = self.downloads.cancel(id).is_ok();
        if changed {
            self.dispatch_download_event(
                "changed",
                &serde_json::json!({"id": id.get(), "state": "cancelled"}),
                renderer,
            )?;
        }
        Ok(serde_json::json!(changed))
    }

    fn execute_extension_downloads_remove<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = self.download_id_from_request("downloads.remove", request)?;
        let cancelled = self.downloads.cancel(id).is_ok();
        if cancelled {
            self.dispatch_download_event(
                "changed",
                &serde_json::json!({"id": id.get(), "state": "cancelled"}),
                renderer,
            )?;
        }
        self.downloads.erase(id).map_err(ShellError::Download)?;
        self.dispatch_download_event("erased", &serde_json::json!({"id": id.get()}), renderer)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_downloads_erase<R: PageRenderer>(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = self.download_id_from_request("downloads.erase", request)?;
        self.downloads.erase(id).map_err(ShellError::Download)?;
        self.dispatch_download_event("erased", &serde_json::json!({"id": id.get()}), renderer)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_downloads_open<R: PageRenderer>(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        self.reveal_download(extension_id, request, renderer, false)
    }

    fn execute_extension_downloads_show<R: PageRenderer>(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        self.reveal_download(extension_id, request, renderer, true)
    }

    fn reveal_download<R: PageRenderer>(
        &self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
        _renderer: &mut R,
        show_in_finder: bool,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "downloads.open/show requires a numeric id".into(),
                ))
            })?;
        let download = self.downloads.get(DownloadId::new(id)).ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(format!(
                "no download with id {id}"
            )))
        })?;
        if !matches!(download.state, nomad_engine::DownloadState::Completed) {
            return Err(ShellError::Download(DownloadError::InvalidState {
                id: DownloadId::new(id),
                state: download.state,
            }));
        }
        let destination = std::path::PathBuf::from(&download.destination);
        let program: Option<(&str, &str)> = if cfg!(target_os = "macos") {
            let flag = if show_in_finder { "-R" } else { "" };
            Some(("open", flag))
        } else {
            None
        };
        let Some((program, flag)) = program else {
            return Err(ShellError::Download(DownloadError::InvalidState {
                id: DownloadId::new(id),
                state: download.state,
            }));
        };
        let mut command = std::process::Command::new(program);
        if !flag.is_empty() {
            command.arg(flag);
        }
        command.arg(&destination).spawn().map_err(|_error| {
            ShellError::Download(DownloadError::InvalidState {
                id: DownloadId::new(id),
                state: download.state,
            })
        })?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_download<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::PermissionDenied(
                "downloads.download expects an options object".into(),
            ))
        })?;
        let url = options
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "downloads.download requires a URL".into(),
                ))
            })?
            .parse::<Url>()
            .map_err(|_| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "downloads.download URL is invalid".into(),
                ))
            })?;
        if matches!(url.scheme(), "http" | "https")
            && !self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_host_granted(extension_id, &url)
        {
            return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                format!("extension has no host permission for {url}"),
            )));
        }
        let tab_id = options
            .get("tabId")
            .and_then(serde_json::Value::as_u64)
            .map(TabId::new);
        let suggested_filename = options
            .get("filename")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                url.path_segments()
                    .and_then(|mut segments| segments.next_back())
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "download".into());
        let id = self.queue_download(DownloadRequest {
            tab_id,
            url,
            suggested_filename,
            total_bytes: None,
        })?;
        let download = self.downloads.get(id).expect("queued download exists");
        self.dispatch_download_event("created", &Self::download_item_json(download), renderer)?;
        Ok(serde_json::json!(id.get()))
    }

    #[allow(clippy::cast_precision_loss)]
    fn alarm_value(alarm: &nomad_engine::ExtensionAlarm) -> serde_json::Value {
        serde_json::json!({
            "name": alarm.name,
            "scheduledTime": alarm.scheduled_time_ms,
            "periodInMinutes": alarm
                .period_ms
                .map(|period| (period as f64) / 60_000.0),
        })
    }

    fn execute_extension_alarm_get(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let name = request
            .arguments
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("_nomad_default");
        let alarm = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_alarm(extension_id, name)
            .map_err(ShellError::Extension)?;
        Ok(alarm.map_or(serde_json::Value::Null, |alarm| Self::alarm_value(&alarm)))
    }

    fn execute_extension_alarm_get_all(
        &self,
        extension_id: &str,
    ) -> Result<serde_json::Value, ShellError> {
        let alarms = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_all_alarms(extension_id)
            .map_err(ShellError::Extension)?;
        Ok(serde_json::Value::Array(
            alarms.iter().map(Self::alarm_value).collect(),
        ))
    }

    fn execute_extension_alarm_create(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "alarms.create expects an object".into(),
            ))
        })?;
        let name = options
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("_nomad_default");
        let now = unix_time_millis();
        let when = options
            .get("when")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| {
                options
                    .get("delayInMinutes")
                    .and_then(serde_json::Value::as_f64)
                    .map_or(now, |minutes| {
                        now.saturating_add(minutes_to_millis(minutes))
                    })
            });
        let period_ms = options
            .get("periodInMinutes")
            .and_then(serde_json::Value::as_f64)
            .map(minutes_to_millis);
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .schedule_alarm(extension_id, name, when, period_ms)
            .map_err(ShellError::Extension)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_alarm_clear(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let name = request
            .arguments
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear_alarm(extension_id, name)
            .map(|cleared| serde_json::json!(cleared))
            .map_err(ShellError::Extension)
    }

    fn execute_extension_notification_create(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "notifications.create expects an object".into(),
            ))
        })?;
        let id = options
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map_or_else(
                || {
                    let id = format!("nomad-{}", self.next_extension_notification_id);
                    self.next_extension_notification_id =
                        self.next_extension_notification_id.saturating_add(1);
                    id
                },
                str::to_owned,
            );
        let title = options
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let message = options
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        self.extension_notifications
            .retain(|notification| notification.id != id);
        self.extension_notifications.push(ExtensionNotification {
            id: id.clone(),
            extension_id: extension_id.to_owned(),
            title,
            message,
        });
        if self.extension_notifications.len() > Self::MAX_EXTENSION_NOTIFICATIONS {
            let drop_count = self.extension_notifications.len() - Self::MAX_EXTENSION_NOTIFICATIONS;
            self.extension_notifications.drain(0..drop_count);
        }
        Ok(serde_json::Value::String(id))
    }

    fn execute_extension_notification_get_all(&self, extension_id: &str) -> serde_json::Value {
        serde_json::Value::Array(
            self.extension_notifications
                .iter()
                .filter(|notification| notification.extension_id == extension_id)
                .map(|notification| {
                    serde_json::json!({
                        "id": notification.id,
                        "title": notification.title,
                        "message": notification.message,
                    })
                })
                .collect(),
        )
    }

    fn execute_extension_notification_clear<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let id = request
            .arguments
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let before = self.extension_notifications.len();
        self.extension_notifications.retain(|notification| {
            !(notification.extension_id == extension_id && notification.id == id)
        });
        let cleared = before != self.extension_notifications.len();
        if cleared {
            self.dispatch_notification_event(
                "NotificationClosed",
                &serde_json::json!({"id": id}),
                renderer,
            )?;
        }
        Ok(serde_json::json!(cleared))
    }

    fn dispatch_notification_event<R: PageRenderer>(
        &self,
        kind: &str,
        details: &serde_json::Value,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let installed = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| {
                    registry.is_enabled(&manifest.id)
                        && registry.is_granted(
                            &manifest.id,
                            nomad_engine::ExtensionPermission::Notifications,
                        )
                })
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in installed {
            let event = match kind {
                "NotificationClosed" => nomad_engine::ExtensionEventKind::NotificationClosed {
                    id: details["id"].as_str().unwrap_or_default().to_owned(),
                },
                "NotificationClicked" => nomad_engine::ExtensionEventKind::NotificationClicked {
                    id: details["id"].as_str().unwrap_or_default().to_owned(),
                },
                "NotificationButtonClicked" => {
                    nomad_engine::ExtensionEventKind::NotificationButtonClicked {
                        id: details["id"].as_str().unwrap_or_default().to_owned(),
                        button_index: details["button_index"].as_u64().unwrap_or(0),
                    }
                }
                _ => unreachable!("unknown notification event kind"),
            };
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id,
                    kind: event,
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    pub fn notify_extension_context_menu_clicked<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        menu_item_id: &str,
        tab_id: Option<TabId>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .require_context_menus(extension_id)
            .map_err(ShellError::Extension)?;
        let menus = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .context_menu_items(extension_id);
        if !menus
            .iter()
            .any(|menu| menu.get("id").and_then(serde_json::Value::as_str) == Some(menu_item_id))
        {
            return Err(ShellError::Extension(ExtensionError::InvalidManifest(
                "context menu item does not exist".into(),
            )));
        }
        let page_url = tab_id
            .and_then(|id| self.tab(id))
            .and_then(|tab| tab.url.clone());
        let info = serde_json::json!({
            "menuItemId": menu_item_id,
            "editable": false,
            "frameId": 0,
            "pageUrl": page_url.map(|url| url.to_string()),
        });
        renderer
            .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: nomad_engine::ExtensionEventKind::ContextMenuClicked {
                    info,
                    tab: tab_id.and_then(|id| self.tab(id)).map(|tab| {
                        nomad_engine::ExtensionTabInfo {
                            id: tab.id.get(),
                            url: tab.url.clone(),
                            active: self.active_tab() == Some(tab.id),
                        }
                    }),
                },
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        Ok(())
    }

    pub fn notify_extension_context_menu_shown<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        tab_id: Option<TabId>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .require_context_menus(extension_id)
            .map_err(ShellError::Extension)?;
        let page_url = tab_id
            .and_then(|id| self.tab(id))
            .and_then(|tab| tab.url.clone());
        let info = serde_json::json!({
            "editable": false,
            "frameId": 0,
            "pageUrl": page_url.map(|url| url.to_string()),
        });
        renderer
            .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: nomad_engine::ExtensionEventKind::ContextMenuShown {
                    info,
                    tab: tab_id.and_then(|id| self.tab(id)).map(|tab| {
                        nomad_engine::ExtensionTabInfo {
                            id: tab.id.get(),
                            url: tab.url.clone(),
                            active: self.active_tab() == Some(tab.id),
                        }
                    }),
                },
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        Ok(())
    }

    pub fn notify_extension_context_menu_hidden<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .require_context_menus(extension_id)
            .map_err(ShellError::Extension)?;
        renderer
            .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                extension_id: extension_id.to_owned(),
                kind: nomad_engine::ExtensionEventKind::ContextMenuHidden,
            })
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        Ok(())
    }

    pub fn notify_extension_notification_clicked<R: PageRenderer>(
        &mut self,
        id: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.dispatch_notification_event(
            "NotificationClicked",
            &serde_json::json!({"id": id}),
            renderer,
        )
    }

    pub fn notify_extension_notification_button_clicked<R: PageRenderer>(
        &mut self,
        id: &str,
        button_index: u64,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.dispatch_notification_event(
            "NotificationButtonClicked",
            &serde_json::json!({"id": id, "button_index": button_index}),
            renderer,
        )
    }

    fn execute_extension_open_options_page<R: PageRenderer>(
        &mut self,
        extension_id: &str,
        renderer: &mut R,
    ) -> Result<serde_json::Value, ShellError> {
        let manifest = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .manifest(extension_id)
            .ok_or_else(|| ShellError::Extension(ExtensionError::Missing(extension_id.into())))?;
        let page = manifest
            .options_ui
            .as_ref()
            .map(|options| options.page.clone())
            .or_else(|| manifest.options_page.clone())
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "extension does not declare an options page".into(),
                ))
            })?;
        let url = nomad_engine::extension_resource_uri(extension_id, &page)
            .map_err(ShellError::Extension)?;
        let tab_id = self.active_tab().unwrap_or_else(|| self.new_tab());
        self.configure_renderer_tab(tab_id, renderer)?;
        let injections = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .scripts_for_tab(&nomad_engine::ExtensionTabInfo {
                id: tab_id.get(),
                url: Some(url.clone()),
                active: true,
            });
        renderer
            .install_extension_scripts_for_tab(tab_id, &injections)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        self.dispatch_web_navigation_before(tab_id, url.as_str(), renderer)?;
        if let Err(error) = self.navigate_with_history_dispatch(tab_id, url.as_str(), renderer) {
            let _ = self.dispatch_web_navigation_error(tab_id, url.as_str(), renderer);
            return Err(ShellError::Navigation(error));
        }
        if let Some(navigated_url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
            self.dispatch_web_navigation_after(tab_id, &navigated_url, renderer, false)?;
        }
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_set_uninstall_url(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let url = request
            .arguments
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "runtime.setUninstallURL expects url".into(),
                ))
            })?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_uninstall_url(extension_id, url)
            .map_err(ShellError::Extension)?;
        Ok(serde_json::Value::Null)
    }

    fn execute_extension_cookie_operation(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let url = request
            .arguments
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "cookie operation requires url".into(),
                ))
            })?
            .parse::<Url>()
            .map_err(|_| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "cookie URL is invalid".into(),
                ))
            })?;
        if matches!(url.scheme(), "http" | "https")
            && !self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_host_granted(extension_id, &url)
        {
            return Err(ShellError::Extension(ExtensionError::PermissionDenied(
                format!("extension has no host permission for {url}"),
            )));
        }
        let result = renderer
            .extension_cookie_operation(&request.method, &request.arguments)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        if matches!(request.method.as_str(), "cookies.set" | "cookies.remove") && result.is_object()
        {
            let mut cookie = result.clone();
            if cookie.get("storeId").is_none() {
                cookie["storeId"] = serde_json::json!("0");
            }
            self.dispatch_cookie_changed(&cookie, request.method.as_str(), renderer)?;
        }
        Ok(result)
    }

    fn dispatch_cookie_changed<R: PageRenderer>(
        &self,
        cookie: &serde_json::Value,
        method: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let installed = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| {
                    registry.is_enabled(&manifest.id)
                        && registry
                            .is_granted(&manifest.id, nomad_engine::ExtensionPermission::Cookies)
                })
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in installed {
            renderer
                .dispatch_extension_event(&nomad_engine::ExtensionEvent {
                    extension_id,
                    kind: nomad_engine::ExtensionEventKind::CookieChanged {
                        cookie: cookie.clone(),
                        cause: serde_json::json!("explicit"),
                        removed: method == "cookies.remove",
                    },
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn execute_extension_script(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let target_value = request.arguments.get("target").ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "scripting.executeScript requires target".into(),
            ))
        })?;
        let target = ExtensionFrameTarget::parse(target_value).map_err(ShellError::Extension)?;
        let tab_id = TabId::new(target.tab_id);
        if self.extension_frames.select(&target).is_err() {
            if let Some(url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
                self.extension_frames.replace_tab(
                    tab_id.get(),
                    1,
                    vec![ExtensionFrame::top(url, 1)],
                );
            }
        }
        let frames = self
            .extension_frames
            .select(&target)
            .map_err(ShellError::Extension)?;
        let source = if let Some(code) = request
            .arguments
            .get("code")
            .and_then(serde_json::Value::as_str)
        {
            code.to_owned()
        } else {
            let files = request
                .arguments
                .get("files")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "scripting.executeScript requires code or files".into(),
                    ))
                })?;
            files
                .iter()
                .map(|file| {
                    let name = file.as_str().ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "scripting files must be strings".into(),
                        ))
                    })?;
                    self.extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .resource_source(extension_id, name)
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::Missing(name.to_owned()))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("\n")
        };
        let target_url = self.tab(tab_id).and_then(|tab| tab.url.as_ref());
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .validate_scripting_target(extension_id, tab_id.get(), target_url)
            .map_err(ShellError::Extension)?;
        let mut results = Vec::with_capacity(frames.len());
        for frame in frames {
            renderer
                .execute_extension_script_target(
                    tab_id,
                    frame.renderer_handle,
                    extension_id,
                    &source,
                )
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            results.push(serde_json::json!({"frameId": frame.id, "result": null}));
        }
        Ok(serde_json::Value::Array(results))
    }

    fn execute_extension_register_content_scripts(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let scripts = request
            .arguments
            .get("scripts")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "scripting.registerContentScripts requires scripts".into(),
                ))
            })?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register_content_scripts(extension_id, scripts)
            .map_err(ShellError::Extension)?;
        self.refresh_extension_scripts_with_renderer(renderer)?;
        Ok(serde_json::json!([]))
    }

    fn execute_extension_unregister_content_scripts(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let ids = request
            .arguments
            .get("ids")
            .and_then(serde_json::Value::as_array)
            .map(|ids| {
                ids.iter()
                    .map(|id| {
                        id.as_str().map(str::to_owned).ok_or_else(|| {
                            ShellError::Extension(ExtensionError::InvalidManifest(
                                "scripting unregister ids must be strings".into(),
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unregister_content_scripts(extension_id, ids.as_deref())
            .map_err(ShellError::Extension)?;
        self.refresh_extension_scripts_with_renderer(renderer)?;
        Ok(serde_json::json!([]))
    }

    fn execute_extension_update_content_scripts(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let scripts = request
            .arguments
            .get("scripts")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "scripting.updateContentScripts requires scripts".into(),
                ))
            })?;
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .update_content_scripts(extension_id, scripts)
            .map_err(ShellError::Extension)?;
        self.refresh_extension_scripts_with_renderer(renderer)?;
        Ok(serde_json::json!([]))
    }

    fn execute_extension_get_registered_content_scripts(
        &self,
        extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> serde_json::Value {
        let scripts = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .registered_content_scripts(extension_id)
            .into_iter()
            .filter(|script| {
                request
                    .arguments
                    .get("ids")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(|ids| ids.iter().any(|id| id.as_str() == Some(script.id.as_str())))
            })
            .map(|script| {
                serde_json::json!({
                    "id": script.id,
                    "matches": script.matches,
                    "js": script.js,
                    "css": script.css,
                    "allFrames": script.all_frames,
                    "runAt": script.run_at,
                    "world": match script.world {
                        nomad_engine::ExtensionScriptWorld::Main => "MAIN",
                        nomad_engine::ExtensionScriptWorld::Isolated => "ISOLATED",
                    },
                    "excludeMatches": script.exclude_matches,
                })
            })
            .collect::<Vec<_>>();
        serde_json::Value::Array(scripts)
    }

    fn execute_extension_scripting_css(
        &mut self,
        extension_id: &str,
        request: &ExtensionApiRequest,
        remove: bool,
        renderer: &mut impl PageRenderer,
    ) -> Result<serde_json::Value, ShellError> {
        let target_value = request.arguments.get("target").ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "scripting CSS injection requires target".into(),
            ))
        })?;
        let target = ExtensionFrameTarget::parse(target_value).map_err(ShellError::Extension)?;
        let tab_id = TabId::new(target.tab_id);
        if self.extension_frames.select(&target).is_err() {
            if let Some(url) = self.tab(tab_id).and_then(|tab| tab.url.clone()) {
                self.extension_frames.replace_tab(
                    tab_id.get(),
                    1,
                    vec![ExtensionFrame::top(url, 1)],
                );
            }
        }
        let frames = self
            .extension_frames
            .select(&target)
            .map_err(ShellError::Extension)?;
        let target_url = self.tab(tab_id).and_then(|tab| tab.url.as_ref());
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .validate_scripting_target(extension_id, tab_id.get(), target_url)
            .map_err(ShellError::Extension)?;
        if remove {
            let mut results = Vec::with_capacity(frames.len());
            for frame in frames {
                renderer
                    .remove_extension_css_target(tab_id, frame.renderer_handle, extension_id)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                results.push(serde_json::json!({"frameId": frame.id}));
            }
            return Ok(serde_json::Value::Array(results));
        }
        let source = if let Some(css) = request
            .arguments
            .get("css")
            .and_then(serde_json::Value::as_str)
        {
            css.to_owned()
        } else {
            let files = request
                .arguments
                .get("files")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    ShellError::Extension(ExtensionError::InvalidManifest(
                        "scripting.insertCSS requires css or files".into(),
                    ))
                })?;
            files
                .iter()
                .map(|file| {
                    let name = file.as_str().ok_or_else(|| {
                        ShellError::Extension(ExtensionError::InvalidManifest(
                            "scripting files must be strings".into(),
                        ))
                    })?;
                    self.extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .resource_source(extension_id, name)
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::Missing(name.to_owned()))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("\n")
        };
        let mut results = Vec::with_capacity(frames.len());
        for frame in frames {
            renderer
                .insert_extension_css_target(tab_id, frame.renderer_handle, extension_id, &source)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            results.push(serde_json::json!({"frameId": frame.id}));
        }
        Ok(serde_json::Value::Array(results))
    }

    fn execute_extension_native_message(
        &mut self,
        _extension_id: &str,
        request: &ExtensionApiRequest,
    ) -> Result<serde_json::Value, ShellError> {
        let options = request.arguments.as_object().ok_or_else(|| {
            ShellError::Extension(ExtensionError::InvalidManifest(
                "runtime.sendNativeMessage expects an object".into(),
            ))
        })?;
        let host_name = options
            .get("hostName")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ShellError::Extension(ExtensionError::InvalidManifest(
                    "native message requires hostName".into(),
                ))
            })?;
        let executable = self.native_hosts.get(host_name).ok_or_else(|| {
            ShellError::Extension(ExtensionError::PermissionDenied(format!(
                "native host {host_name:?} is not allowlisted"
            )))
        })?;
        let message = options
            .get("message")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let mut child = Command::new(executable)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| ShellError::Renderer(format!("native host start failed: {error}")))?;
        let encoded = serde_json::to_vec(&message).map_err(|error| {
            ShellError::Renderer(format!("native message encoding failed: {error}"))
        })?;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| ShellError::Renderer("native host stdin is unavailable".into()))?;
        stdin
            .write_all(&encoded)
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|error| {
                ShellError::Renderer(format!("native message write failed: {error}"))
            })?;
        drop(child.stdin.take());
        let output = child
            .wait_with_output()
            .map_err(|error| ShellError::Renderer(format!("native host failed: {error}")))?;
        if output.stdout.len() > 1024 * 1024 {
            return Err(ShellError::Renderer(
                "native host response exceeds 1 MiB".into(),
            ));
        }
        let response = output
            .stdout
            .split(|byte| *byte == b'\n')
            .find(|line| !line.is_empty())
            .unwrap_or_default();
        serde_json::from_slice(response).map_err(|error| {
            ShellError::Renderer(format!("native host response is invalid: {error}"))
        })
    }

    pub fn drain_extension_messages(&mut self, id: &str) -> Vec<ExtensionMessage> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain_messages(id)
    }

    pub fn trigger_extension_action(&mut self, id: &str, tab_id: TabId) -> Result<(), ShellError> {
        let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        let info = ExtensionTabInfo {
            id: tab.id.get(),
            url: tab.url.clone(),
            active: self.active_tab() == Some(tab_id),
        };
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trigger_action(id, &info)
            .map_err(ShellError::Extension)
    }

    /// Trigger a manifest-declared keyboard command and deliver the resulting
    /// `commands.onCommand` event to the background context.
    pub fn trigger_extension_command_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        command: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trigger_command(id, command)
            .map_err(ShellError::Extension)?;
        for event in self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain_background_events(id)
        {
            renderer
                .dispatch_extension_event(&event)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    /// Enable or disable an extension through the `management.setEnabled`
    /// path, reinstalling or removing its renderer resources and background
    /// context accordingly.
    pub fn set_extension_enabled_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        enabled: bool,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.execute_extension_management_set_enabled(
            &ExtensionApiRequest {
                request_id: String::new(),
                method: "management.setEnabled".to_owned(),
                arguments: serde_json::json!({"id": id, "enabled": enabled}),
            },
            renderer,
        )?;
        Ok(())
    }

    pub fn trigger_extension_action_with_renderer<R: PageRenderer>(
        &mut self,
        id: &str,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        if let Some(source) = self.extension_action_popup_source(id) {
            let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
            let info = ExtensionTabInfo {
                id: tab.id.get(),
                url: tab.url.clone(),
                active: self.active_tab() == Some(tab_id),
            };
            self.extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .activate_action(id, &info)
                .map_err(ShellError::Extension)?;
            renderer
                .open_extension_popup(
                    id,
                    &self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .manifest(id)
                        .ok_or_else(|| {
                            ShellError::Extension(ExtensionError::Missing(id.to_owned()))
                        })?,
                    &source,
                    &self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .action_popup_resource_path(id)
                        .unwrap_or_default(),
                    &self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .storage_areas_snapshot(id)
                        .unwrap_or_default(),
                )
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            for event in self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain_background_events(id)
            {
                if !matches!(&event.kind, ExtensionEventKind::Startup) {
                    renderer
                        .dispatch_extension_event(&event)
                        .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                }
            }
        } else {
            self.trigger_extension_action(id, tab_id)?;
            for event in self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain_background_events(id)
            {
                renderer
                    .dispatch_extension_event(&event)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
            }
        }
        Ok(())
    }

    pub fn sync_extension_backgrounds_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let ids = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter_map(|manifest| {
                    registry
                        .background_info(&manifest.id)
                        .map(|_| manifest.id.clone())
                })
                .collect::<Vec<_>>()
        };
        for id in ids {
            self.install_background_with_renderer(&id, renderer)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn extension_background_info(&self, id: &str) -> Option<ExtensionBackgroundInfo> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .background_info(id)
    }

    #[must_use]
    pub fn extension_manifest(&self, id: &str) -> Option<ExtensionManifest> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .manifest(id)
    }

    #[must_use]
    pub fn extension_action_popup_source(&self, id: &str) -> Option<String> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .action_popup_source(id)
    }

    pub fn drain_extension_events(&mut self, id: &str) -> Vec<ExtensionEvent> {
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain_background_events(id)
    }

    pub fn poll_extension_alarms_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let events = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poll_due_alarms(unix_time_millis());
        for event in events {
            renderer
                .dispatch_extension_event(&event)
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    pub fn poll_extension_frames<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        for (tab_id, snapshot) in renderer.take_extension_frame_tree_events() {
            if snapshot.is_empty() {
                self.extension_frames.remove_tab(tab_id.get());
                continue;
            }
            let generation = self
                .extension_frames
                .select(&ExtensionFrameTarget {
                    tab_id: tab_id.get(),
                    frame_ids: None,
                    all_frames: true,
                })
                .ok()
                .and_then(|frames| frames.first().map(|frame| frame.navigation_generation + 1))
                .unwrap_or(1);
            let snapshot = snapshot
                .into_iter()
                .filter_map(|(handle, parent, url)| {
                    Url::parse(&url).ok().map(|url| (handle, parent, url))
                })
                .collect();
            self.extension_frames
                .update_renderer_snapshot(tab_id.get(), generation, snapshot);
        }
        Ok(())
    }

    pub fn poll_extension_screenshots<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.poll_extension_frames(renderer)?;
        for (tab_id, result) in renderer.take_tab_screenshots() {
            let Some(pending) = self.pending_extension_screenshots.remove(&tab_id) else {
                continue;
            };
            let result = result
                .map(|bytes| {
                    format!(
                        "data:image/png;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    )
                })
                .map(serde_json::Value::String)
                .map_err(|error| format!("{error:?}"));
            renderer
                .dispatch_extension_event(&ExtensionEvent {
                    extension_id: pending.extension_id,
                    kind: ExtensionEventKind::RuntimeResponse {
                        request_id: pending.request_id,
                        result,
                    },
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    pub fn dispatch_network_request_to_extensions<R: PageRenderer>(
        &mut self,
        request: &NetworkRequestRecord,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let target_url = Url::parse(&request.url).ok();
        let request_headers = request
            .request_headers
            .iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect::<Vec<_>>();
        let response_headers = request
            .response_headers
            .iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect::<Vec<_>>();
        let request_body = if request.request_body_unavailable {
            serde_json::json!({"unavailable": true, "redacted": true, "size": request.request_body_size})
        } else {
            request.request_body_size.map_or(
                serde_json::Value::Null,
                |size| serde_json::json!({"size": size}),
            )
        };
        let mut payloads = vec![(
            "web_request",
            serde_json::json!({
                "method": request.method,
                "url": request.url,
                "status": request.status,
                "duration_ms": request.duration_ms,
                "failed": request.failed,
                "requestHeaders": request_headers,
                "requestBody": request_body,
            }),
        )];
        if request.failed {
            payloads.push((
                "web_request_error",
                serde_json::json!({
                    "method": request.method,
                    "url": request.url,
                }),
            ));
        } else if request.status.is_some() {
            payloads.push((
                "web_request_headers_received",
                serde_json::json!({
                    "method": request.method,
                    "url": request.url,
                    "status": request.status,
                    "responseHeaders": response_headers,
                }),
            ));
            payloads.push((
                "web_request_completed",
                serde_json::json!({
                    "method": request.method,
                    "url": request.url,
                    "status": request.status,
                    "duration_ms": request.duration_ms,
                    "responseHeaders": response_headers,
                }),
            ));
        }
        let extension_ids = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .web_request_extension_ids();
        for id in extension_ids {
            for (event, payload) in &payloads {
                let _ = event;
                let dispatched = self
                    .extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .dispatch_web_request(&id, event, payload.clone(), target_url.as_ref())
                    .is_ok();
                if dispatched {
                    let events = self
                        .extensions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .drain_background_events(&id);
                    for event in events {
                        renderer.dispatch_extension_event(&event).map_err(|error| {
                            ShellError::Navigation(NavigationError::Render(error))
                        })?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn save_encrypted_session(&self, key: [u8; 32]) -> Result<Vec<u8>, ShellError> {
        let session = self.save_session()?;
        EncryptedSyncCodec::new(key)
            .encrypt(session.as_bytes())
            .map_err(ShellError::Sync)
    }

    pub fn restore_encrypted_session_with_renderer<R: PageRenderer>(
        &mut self,
        envelope: &[u8],
        key: [u8; 32],
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let session = EncryptedSyncCodec::new(key)
            .decrypt(envelope)
            .map_err(ShellError::Sync)?;
        let session = String::from_utf8(session)
            .map_err(|error| ShellError::Session(SessionError::InvalidJson(error.to_string())))?;
        self.restore_session_with_renderer(&session, renderer)
    }

    #[must_use]
    pub fn tab(&self, tab_id: TabId) -> Option<&TabSnapshot> {
        self.runtime.tab(tab_id)
    }

    #[must_use]
    pub fn search_tabs(&self, query: &str) -> Vec<TabSearchResult> {
        let query = query.trim().to_ascii_lowercase();
        self.tabs()
            .iter()
            .filter(|tab| {
                if query.is_empty() {
                    return true;
                }
                let id = tab.id.get().to_string();
                let url = tab.url.as_ref().map(url::Url::as_str).unwrap_or_default();
                id.contains(&query) || url.to_ascii_lowercase().contains(&query)
            })
            .map(|tab| TabSearchResult {
                id: tab.id,
                url: tab.url.clone(),
                state: tab.state,
                lifecycle: tab.lifecycle,
                active: self.active_tab() == Some(tab.id),
            })
            .collect()
    }

    #[must_use]
    pub fn command_suggestions(&self, input: &str) -> Vec<UniversalSuggestion> {
        let input = input.trim();
        let query = input.to_ascii_lowercase();
        BrowserCommand::all()
            .into_iter()
            .filter_map(|command| {
                let command_name = command.command();
                let label = command.label();
                let matches_command = input.is_empty()
                    || command_name.contains(&query)
                    || label.to_ascii_lowercase().contains(&query)
                    || (input.starts_with(':') && command_name.starts_with(&query));
                matches_command.then(|| UniversalSuggestion {
                    kind: UniversalSuggestionKind::Command,
                    title: label.to_owned(),
                    detail: command_name.to_owned(),
                    target: UniversalTarget::Command(command),
                })
            })
            .collect()
    }

    #[must_use]
    pub fn universal_suggestions(&self, input: &str) -> Vec<UniversalSuggestion> {
        let input = input.trim();
        let mut suggestions = Vec::new();
        suggestions.extend(self.command_suggestions(input));

        for tab in self.search_tabs(input).into_iter().take(4) {
            let title = tab
                .url
                .as_ref()
                .and_then(url::Url::host_str)
                .unwrap_or("New tab")
                .to_owned();
            let detail = tab
                .url
                .as_ref()
                .map_or_else(|| format!("Tab #{}", tab.id.get()), ToString::to_string);
            suggestions.push(UniversalSuggestion {
                kind: UniversalSuggestionKind::Tab,
                title,
                detail,
                target: UniversalTarget::SelectTab(tab.id),
            });
        }

        for bookmark in self.search_bookmarks(input).into_iter().take(3) {
            suggestions.push(UniversalSuggestion {
                kind: UniversalSuggestionKind::Bookmark,
                title: bookmark.title,
                detail: bookmark.url.to_string(),
                target: UniversalTarget::OpenBookmark(bookmark.id),
            });
        }

        let mut seen_history_urls = HashSet::new();
        for visit in self
            .search_history(input)
            .into_iter()
            .filter(|visit| seen_history_urls.insert(visit.url.clone()))
            .take(3)
        {
            suggestions.push(UniversalSuggestion {
                kind: UniversalSuggestionKind::History,
                title: visit.url.to_string(),
                detail: "History".to_owned(),
                target: UniversalTarget::Navigate(visit.url.to_string()),
            });
        }

        if !input.is_empty() {
            if let Ok(normalized) = normalize_address_input(input, &self.settings.search_url) {
                let is_address = address::looks_like_host(input) || Url::parse(input).is_ok();
                if suggestions.len() >= 7 {
                    suggestions.truncate(7);
                }
                suggestions.push(UniversalSuggestion {
                    kind: if is_address {
                        UniversalSuggestionKind::Address
                    } else {
                        UniversalSuggestionKind::Search
                    },
                    title: if is_address {
                        "Open address".to_owned()
                    } else {
                        "Search the web".to_owned()
                    },
                    detail: normalized.clone(),
                    target: UniversalTarget::Navigate(normalized),
                });
            }
        }

        suggestions.truncate(8);
        suggestions
    }

    #[must_use]
    pub const fn address_bar(&self) -> &AddressBarState {
        &self.address_bar
    }

    #[must_use]
    pub const fn sidebar(&self) -> &VerticalTabSidebarState {
        &self.sidebar
    }

    #[must_use]
    pub fn history(&self) -> &[HistoryVisit] {
        self.runtime.history()
    }

    #[must_use]
    pub fn recent_history(&self, limit: usize) -> Vec<HistoryVisit> {
        self.runtime.recent_history(limit)
    }

    #[must_use]
    pub fn search_history(&self, query: &str) -> Vec<HistoryVisit> {
        self.runtime.search_history(query)
    }

    #[must_use]
    pub const fn settings(&self) -> &BrowserSettings {
        &self.settings
    }

    pub fn apply_settings(&mut self, settings: BrowserSettings) {
        self.runtime.set_history_enabled(settings.history_enabled());
        self.downloads
            .set_directory(settings.download_directory.clone());
        self.settings = settings;
        self.sync_resolver();
        if !self.settings.sync.enabled || !self.settings.sync.key_configured {
            self.sync_store = None;
        } else if self.sync_key_material.is_some() {
            let _ = self.configure_sync_store();
        }
    }

    fn sync_error(message: impl Into<String>) -> ShellError {
        ShellError::Sync(SyncCryptoError::Transport(message.into()))
    }

    fn secure_storage_error(message: impl Into<String>) -> ShellError {
        ShellError::Sync(SyncCryptoError::SecureStorage(message.into()))
    }

    fn sync_key_store() -> OsCredentialStore {
        OsCredentialStore::new(Self::SYNC_KEY_SERVICE)
    }

    /// Saves only the recovery phrase in the platform credential manager.
    /// Session JSON stores the non-secret fingerprint, never key material.
    pub fn persist_sync_key(&self, recovery_phrase: &str) -> Result<(), ShellError> {
        let Some(key_material) = self.sync_key_material.as_ref() else {
            return Err(Self::secure_storage_error(
                "sync key setup or recovery is required before persistence",
            ));
        };
        let recovered = SyncKeyMaterial::recover(recovery_phrase).map_err(ShellError::Sync)?;
        if recovered.fingerprint() != key_material.fingerprint() {
            return Err(Self::secure_storage_error(
                "recovery phrase does not match the active sync key",
            ));
        }
        Self::sync_key_store()
            .save(
                Self::SYNC_KEY_ORIGIN,
                key_material.fingerprint(),
                recovery_phrase,
            )
            .map_err(|error| Self::secure_storage_error(error.to_string()))
    }

    /// Restores the configured key from the OS credential manager after a
    /// session restore. Returns `false` when no stored key is available.
    pub fn restore_persisted_sync_key(&mut self) -> Result<bool, ShellError> {
        let Some(fingerprint) = self.settings.sync.key_fingerprint.as_deref() else {
            return Ok(false);
        };
        let stored = Self::sync_key_store()
            .load(Self::SYNC_KEY_ORIGIN, fingerprint)
            .map_err(|error| Self::secure_storage_error(error.to_string()))?;
        let Some(recovery_phrase) = stored else {
            return Ok(false);
        };
        let key_material = SyncKeyMaterial::recover(&recovery_phrase).map_err(ShellError::Sync)?;
        if key_material.fingerprint() != fingerprint {
            return Err(Self::secure_storage_error(
                "stored sync key fingerprint does not match browser settings",
            ));
        }
        self.sync_key_material = Some(key_material);
        self.configure_sync_store()?;
        Ok(true)
    }

    fn configure_sync_store(&mut self) -> Result<(), ShellError> {
        if !self.settings.sync.enabled {
            self.sync_store = None;
            return Err(Self::sync_error("sync is disabled"));
        }
        if self.settings.sync.provider != "file" {
            self.sync_store = None;
            return Err(Self::sync_error(
                "only the user-owned file sync provider is available",
            ));
        }
        let endpoint = self.settings.sync.endpoint.trim();
        if endpoint.is_empty() {
            self.sync_store = None;
            return Err(Self::sync_error("sync requires a user-owned endpoint path"));
        }
        let Some(key_material) = self.sync_key_material.as_ref() else {
            self.sync_store = None;
            return Err(Self::sync_error(
                "sync key setup or recovery is required before syncing",
            ));
        };
        let same_transport = self
            .sync_store
            .as_ref()
            .is_some_and(|store| store.transport().path() == Path::new(endpoint));
        if !same_transport {
            self.sync_store = Some(EncryptedSyncStore::new(
                key_material.key(),
                self.sync_device_id.clone(),
                FileSyncTransport::new(endpoint),
            ));
        }
        Ok(())
    }

    pub fn setup_sync_key(&mut self) -> Result<String, ShellError> {
        let previous_settings = self.settings.sync.clone();
        let (key_material, recovery_phrase) =
            SyncKeyMaterial::generate().map_err(ShellError::Sync)?;
        self.sync_key_material = Some(key_material);
        self.settings.sync.enabled = true;
        self.settings.sync.key_configured = true;
        self.settings.sync.recovery_configured = true;
        self.settings.sync.key_fingerprint = self
            .sync_key_material
            .as_ref()
            .map(|key| key.fingerprint().to_owned());
        if let Err(error) = self.configure_sync_store() {
            self.sync_key_material = None;
            self.settings.sync = previous_settings;
            return Err(error);
        }
        Ok(recovery_phrase)
    }

    pub fn recover_sync_key(&mut self, recovery_phrase: &str) -> Result<(), ShellError> {
        let previous_settings = self.settings.sync.clone();
        let key_material = SyncKeyMaterial::recover(recovery_phrase).map_err(ShellError::Sync)?;
        self.sync_key_material = Some(key_material);
        self.settings.sync.enabled = true;
        self.settings.sync.key_configured = true;
        self.settings.sync.recovery_configured = true;
        self.settings.sync.key_fingerprint = self
            .sync_key_material
            .as_ref()
            .map(|key| key.fingerprint().to_owned());
        if let Err(error) = self.configure_sync_store() {
            self.sync_key_material = None;
            self.settings.sync = previous_settings;
            return Err(error);
        }
        Ok(())
    }

    #[must_use]
    pub fn sync_status(&self) -> SyncStatus {
        SyncStatus {
            enabled: self.settings.sync.enabled,
            provider: self.settings.sync.provider.clone(),
            endpoint: self.settings.sync.endpoint.clone(),
            key_fingerprint: self
                .sync_key_material
                .as_ref()
                .map(|key| key.fingerprint().to_owned()),
            pending_uploads: self
                .sync_store
                .as_ref()
                .map_or(0, EncryptedSyncStore::pending_upload_count),
            conflicts: self.sync_conflicts.len(),
            pending_conflicts: self
                .sync_store
                .as_ref()
                .map_or_else(Vec::new, EncryptedSyncStore::pending_conflicts),
        }
    }

    fn record_sync_conflicts(&mut self, conflicts: Vec<SyncConflict>) {
        for conflict in conflicts {
            if !self.sync_conflicts.contains(&conflict) {
                self.sync_conflicts.push(conflict);
                if self.sync_conflicts.len() > Self::MAX_SYNC_CONFLICTS {
                    self.sync_conflicts.remove(0);
                }
            }
        }
    }

    fn make_sync_payload(&self) -> SyncPayload {
        let snapshot = self.session_snapshot();
        let selected_collections = self.settings.sync.collections.clone();
        let selected =
            |collection: &str| selected_collections.iter().any(|value| value == collection);
        SyncPayload {
            settings: selected("settings").then_some(snapshot.settings),
            bookmarks: selected("bookmarks").then_some(snapshot.bookmarks),
            bookmark_folders: selected("bookmarks").then_some(snapshot.bookmark_folders),
            history: selected("history").then_some(
                snapshot
                    .history
                    .into_iter()
                    .map(|visit| visit.url)
                    .collect(),
            ),
        }
    }

    pub fn sync_now(&mut self) -> Result<SyncStatus, ShellError> {
        self.configure_sync_store()?;
        let payload = serde_json::to_vec(&self.make_sync_payload())
            .map_err(|error| Self::sync_error(format!("sync payload encoding failed: {error}")))?;
        let conflicts = {
            let store = self
                .sync_store
                .as_mut()
                .ok_or_else(|| Self::sync_error("sync transport is not configured"))?;
            store.pull().map_err(ShellError::Sync)?;
            store.take_conflicts()
        };
        self.record_sync_conflicts(conflicts);
        let store = self
            .sync_store
            .as_mut()
            .ok_or_else(|| Self::sync_error("sync transport is not configured"))?;
        store
            .publish("browser-state", &payload)
            .map_err(ShellError::Sync)?;
        store.retry_pending().map_err(ShellError::Sync)?;
        Ok(self.sync_status())
    }

    pub fn pull_sync(&mut self) -> Result<SyncStatus, ShellError> {
        self.configure_sync_store()?;
        let records = self
            .sync_store
            .as_mut()
            .ok_or_else(|| Self::sync_error("sync transport is not configured"))?
            .pull()
            .map_err(ShellError::Sync)?;
        let conflicts = self
            .sync_store
            .as_mut()
            .map_or_else(Vec::new, EncryptedSyncStore::take_conflicts);
        self.record_sync_conflicts(conflicts);
        let Some((_, raw)) = records.into_iter().find(|(key, _)| key == "browser-state") else {
            return Ok(self.sync_status());
        };
        let payload: SyncPayload = serde_json::from_slice(&raw)
            .map_err(|error| Self::sync_error(format!("sync payload is invalid: {error}")))?;
        let selected_collections = self.settings.sync.collections.clone();
        let selected =
            |collection: &str| selected_collections.iter().any(|value| value == collection);
        if selected("settings") {
            if let Some(mut settings) = payload.settings {
                settings.sync = self.settings.sync.clone();
                self.apply_settings(settings);
            }
        }
        if selected("bookmarks") {
            if let Some(folders) = payload.bookmark_folders {
                for folder in folders {
                    let _ = self.bookmarks.create_folder(folder);
                }
            }
            if let Some(bookmarks) = payload.bookmarks {
                for bookmark in bookmarks {
                    let Ok(url) = Url::parse(&bookmark.url) else {
                        continue;
                    };
                    let folder_id = bookmark.folder.as_deref().and_then(|folder| {
                        self.bookmarks
                            .folders()
                            .iter()
                            .find(|candidate| candidate.name == folder)
                            .map(|folder| folder.id)
                    });
                    let _ = self.bookmarks.add_in_folder(url, bookmark.title, folder_id);
                }
            }
        }
        if selected("history") {
            if let Some(history) = payload.history {
                for raw_url in history {
                    if let Ok(url) = Url::parse(&raw_url) {
                        self.runtime.record_visit_for_url(url);
                    }
                }
            }
        }
        Ok(self.sync_status())
    }

    pub fn resolve_sync_conflict(
        &mut self,
        key: &str,
        choice: SyncConflictChoice,
    ) -> Result<SyncStatus, ShellError> {
        self.configure_sync_store()?;
        let store = self
            .sync_store
            .as_mut()
            .ok_or_else(|| Self::sync_error("sync transport is not configured"))?;
        store
            .resolve_conflict(key, choice)
            .map_err(ShellError::Sync)?;
        Ok(self.sync_status())
    }

    /// Changes the browser's logical route after the native transport has
    /// accepted the same switch transition.
    ///
    /// # Errors
    ///
    /// Returns a renderer error when the selected backend is unavailable.
    pub fn set_switches(&mut self, switches: nomad_core::Switches) -> Result<(), ShellError> {
        self.runtime
            .set_switches(switches)
            .map_err(|error| ShellError::Renderer(format!("route switch rejected: {error:?}")))
    }

    #[must_use]
    pub fn memory_mode(&self) -> MemoryMode {
        self.memory.mode()
    }

    pub fn set_memory_mode(&mut self, mode: MemoryMode) {
        self.memory.set_mode(mode);
        let tabs = self.tabs().to_vec();
        self.memory.refresh(&tabs);
    }

    /// Updates memory pressure from an available-memory observation.
    pub fn observe_memory(&mut self, available_bytes: u64) {
        let tabs = self.tabs().to_vec();
        self.memory.observe(available_bytes, &tabs);
    }

    #[must_use]
    pub fn memory_diagnostics(&self) -> MemoryDiagnostics {
        self.memory.diagnostics(self.tabs())
    }

    /// Suspends the lowest-priority eligible tabs until the configured budget
    /// is satisfied or no more candidates remain.
    ///
    /// # Errors
    ///
    /// Returns an error when the renderer cannot release a selected tab.
    pub fn reclaim_memory_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<Vec<TabId>, ShellError> {
        let mut suspended = Vec::new();
        loop {
            let tabs = self.tabs().to_vec();
            self.memory.refresh(&tabs);
            if !self.memory.should_reclaim(&tabs) {
                break;
            }
            let Some(candidate) = self.memory.suspension_candidates(&tabs).into_iter().next()
            else {
                break;
            };
            let tab_id = candidate.tab_id;
            self.runtime
                .suspend_tab_with_renderer(tab_id, renderer)
                .map_err(map_tab_error)?;
            suspended.push(tab_id);
        }
        self.sync_sidebar();
        Ok(suspended)
    }

    /// Suspends one background tab on explicit user request.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is active, missing, or cannot be released.
    pub fn suspend_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.runtime
            .suspend_tab_with_renderer(tab_id, renderer)
            .map_err(map_tab_error)?;
        self.sync_sidebar();
        Ok(())
    }

    /// Puts a background tab into a low-activity sleeping state.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is active or missing.
    pub fn sleep_tab(&mut self, tab_id: TabId) -> Result<(), ShellError> {
        self.runtime.sleep_tab(tab_id).map_err(map_tab_error)?;
        self.sync_sidebar();
        Ok(())
    }

    /// Puts a background tab into a renderer-throttled sleeping state.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is active, missing, or the renderer
    /// cannot apply throttling.
    pub fn sleep_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.runtime
            .sleep_tab_with_renderer(tab_id, renderer)
            .map_err(map_tab_error)?;
        self.sync_sidebar();
        Ok(())
    }

    /// Wakes a sleeping tab and makes it active.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is missing or cannot be activated.
    pub fn wake_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.configure_renderer_tab(tab_id, renderer)?;
        self.runtime
            .wake_tab_with_renderer(tab_id, renderer)
            .map_err(map_tab_error)?;
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    /// Resumes a suspended tab and makes it active.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is missing or cannot be rendered.
    pub fn resume_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        self.configure_renderer_tab(tab_id, renderer)?;
        self.runtime
            .resume_tab_with_renderer(tab_id, renderer)
            .map_err(map_tab_error)?;
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    /// Pins or unpins a tab for resource policy decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::MissingTab`] when the tab does not exist.
    pub fn set_tab_pinned(&mut self, tab_id: TabId, pinned: bool) -> Result<(), ShellError> {
        self.runtime
            .set_tab_pinned(tab_id, pinned)
            .map_err(map_tab_error)
    }

    /// Updates a tab's estimated resident memory.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::MissingTab`] when the tab does not exist.
    pub fn set_tab_memory_estimate(
        &mut self,
        tab_id: TabId,
        estimated_memory_bytes: u64,
    ) -> Result<(), ShellError> {
        self.runtime
            .set_tab_memory_usage(tab_id, estimated_memory_bytes, TabMemorySource::Estimated)
            .map_err(map_tab_error)
    }

    /// Stores an exact memory sample reported by the embedded Servo engine.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::MissingTab`] when the tab does not exist.
    pub fn set_tab_memory_measurement(
        &mut self,
        tab_id: TabId,
        memory_bytes: u64,
    ) -> Result<(), ShellError> {
        self.runtime
            .set_tab_memory_measurement(tab_id, memory_bytes)
            .map_err(map_tab_error)
    }

    /// Enables or disables automatic suspension for a tab.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::MissingTab`] when the tab does not exist.
    pub fn set_tab_keep_alive(
        &mut self,
        tab_id: TabId,
        keep_alive: bool,
    ) -> Result<(), ShellError> {
        self.runtime
            .set_tab_keep_alive(tab_id, keep_alive)
            .map_err(map_tab_error)
    }

    /// Updates runtime activity used by automatic resource reclamation.
    ///
    /// The flags are intentionally not persisted; callers should refresh them
    /// from the live browser subsystems after session restore.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::MissingTab`] when the tab does not exist.
    pub fn set_tab_activity(
        &mut self,
        tab_id: TabId,
        activity: TabActivity,
    ) -> Result<(), ShellError> {
        self.runtime
            .set_tab_activity(tab_id, activity)
            .map_err(map_tab_error)
    }

    /// Marks whether a tab currently owns an actively playing media session.
    ///
    /// Servo's media-session event does not distinguish audio-only from video
    /// playback at this boundary, so both activity bits are updated
    /// conservatively to keep the renderer resident while media is playing.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::MissingTab`] when the tab does not exist.
    pub fn set_tab_media_playing(
        &mut self,
        tab_id: TabId,
        playing: bool,
    ) -> Result<(), ShellError> {
        let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        let mut activity = tab.activity;
        activity.playing_audio = playing;
        activity.playing_video = playing;
        self.set_tab_activity(tab_id, activity)
    }

    /// Rebuilds download activity flags from the authoritative download store.
    pub fn refresh_download_activity(&mut self) {
        let active_download_tabs: HashSet<_> = self
            .downloads
            .downloads()
            .iter()
            .filter(|download| download.state == DownloadState::InProgress)
            .filter_map(|download| download.tab_id)
            .collect();
        let tab_ids: Vec<_> = self.tabs().iter().map(|tab| tab.id).collect();
        for tab_id in tab_ids {
            let Some(tab) = self.tab(tab_id) else {
                continue;
            };
            let mut activity = tab.activity;
            activity.active_download = active_download_tabs.contains(&tab_id);
            let _ = self.set_tab_activity(tab_id, activity);
        }
    }

    #[must_use]
    pub fn permission_rules(&self) -> &[nomad_engine::PermissionRule] {
        self.permissions.rules()
    }

    #[must_use]
    pub fn pending_permissions(&self) -> &[PermissionPrompt] {
        &self.pending_permissions
    }

    #[must_use]
    pub fn permission_decision(&mut self, site: &str, kind: PermissionKind) -> PermissionDecision {
        let decision = self.permissions.decision(site, kind);
        if decision == PermissionDecision::AllowOnce {
            self.permissions.consume_allow_once(site, kind);
            PermissionDecision::Allow
        } else {
            decision
        }
    }

    pub fn queue_permission(&mut self, prompt: PermissionPrompt) {
        if !self
            .pending_permissions
            .iter()
            .any(|pending| pending.id == prompt.id)
        {
            self.pending_permissions.push(prompt);
        }
    }

    /// Resolves a pending site permission and records the selected policy.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Permission`] when the prompt no longer exists.
    pub fn resolve_permission(
        &mut self,
        id: PermissionPromptId,
        decision: PermissionDecision,
    ) -> Result<PermissionPrompt, ShellError> {
        let index = self
            .pending_permissions
            .iter()
            .position(|prompt| prompt.id == id)
            .ok_or(ShellError::Permission(id))?;
        let prompt = self.pending_permissions.remove(index);
        self.permissions
            .set_decision(prompt.site.clone(), prompt.kind, decision);
        if decision == PermissionDecision::AllowOnce {
            self.permissions
                .consume_allow_once(&prompt.site, prompt.kind);
        }
        Ok(prompt)
    }

    #[must_use]
    pub fn session_snapshot(&self) -> SessionSnapshot {
        let active_tab = self
            .active_tab()
            .and_then(|active_id| self.tabs().iter().position(|tab| tab.id == active_id))
            .unwrap_or_default();
        let tabs = self
            .tabs()
            .iter()
            .map(|tab| SessionTab {
                url: tab.url.as_ref().map(ToString::to_string),
                pinned: tab.pinned,
                keep_alive: tab.keep_alive,
                user_priority: tab.user_priority,
                workspace_id: Some(self.tab_context(tab.id).workspace_id.get()),
                container_id: Some(self.tab_context(tab.id).container_id.get()),
            })
            .collect();
        let bookmarks = if self.settings.bookmarks_persistence_enabled() {
            self.bookmarks()
                .iter()
                .map(|bookmark| SessionBookmark {
                    url: bookmark.url.to_string(),
                    title: bookmark.title.clone(),
                    folder: bookmark
                        .folder_id
                        .and_then(|folder_id| self.bookmarks.folder(folder_id))
                        .map(|folder| folder.name.clone()),
                })
                .collect()
        } else {
            Vec::new()
        };
        let bookmark_folders = if self.settings.bookmarks_persistence_enabled() {
            self.bookmark_folders()
                .iter()
                .map(|folder| folder.name.clone())
                .collect()
        } else {
            Vec::new()
        };
        let history = if self.settings.history_enabled() {
            self.history()
                .iter()
                .filter_map(|visit| {
                    let tab_index = self.tabs().iter().position(|tab| tab.id == visit.tab_id)?;
                    Some(SessionHistoryVisit {
                        tab_index,
                        url: visit.url.to_string(),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let permissions = if self.settings.permissions_persistence_enabled() {
            self.permission_rules()
                .iter()
                .filter(|rule| {
                    matches!(
                        rule.decision,
                        PermissionDecision::Allow | PermissionDecision::Block
                    )
                })
                .map(|rule| SessionPermissionRule {
                    site: rule.site.clone(),
                    kind: rule.kind.key().to_owned(),
                    decision: rule.decision.key().to_owned(),
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut snapshot = SessionSnapshot::new(active_tab, tabs, bookmarks);
        snapshot.bookmark_folders = bookmark_folders;
        snapshot.settings = self.settings.clone();
        snapshot.history = history;
        snapshot.permissions = permissions;
        snapshot.workspaces = self.workspaces.workspaces().to_vec();
        snapshot.containers = self.workspaces.containers().to_vec();
        snapshot.active_workspace = Some(self.active_workspace().get());
        snapshot.extensions = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot();
        snapshot.groups = self
            .tab_groups
            .values()
            .map(|group| SessionTabGroup {
                title: group.title.clone(),
                color: group.color.clone(),
                collapsed: group.collapsed,
                tab_indices: group
                    .tab_ids
                    .iter()
                    .filter_map(|tab_id| self.tabs().iter().position(|tab| tab.id == *tab_id))
                    .collect(),
            })
            .filter(|group| !group.tab_indices.is_empty())
            .collect();
        snapshot
    }

    /// Serializes the current tab and bookmark state for local session storage.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Session`] when serialization fails.
    pub fn save_session(&self) -> Result<String, ShellError> {
        self.session_snapshot()
            .to_json()
            .map_err(ShellError::Session)
    }

    /// Restores tabs and bookmarks through a page renderer.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is invalid, navigation fails, or the
    /// renderer cannot release or activate a tab.
    pub fn restore_session_with_renderer<R: PageRenderer>(
        &mut self,
        raw_session: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let snapshot = SessionSnapshot::from_json(raw_session).map_err(ShellError::Session)?;
        let session_settings = snapshot.settings.clone();
        self.apply_settings(session_settings);
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .restore(snapshot.extensions.clone())
            .map_err(ShellError::Extension)?;
        if !snapshot.workspaces.is_empty() && !snapshot.containers.is_empty() {
            let active_workspace = snapshot
                .active_workspace
                .unwrap_or_else(|| snapshot.workspaces[0].id.get());
            self.workspaces
                .restore_state(
                    snapshot.workspaces.clone(),
                    snapshot.containers.clone(),
                    WorkspaceId::new(active_workspace),
                )
                .map_err(ShellError::Workspace)?;
        }
        // The active workspace may carry a pinned resolver override that
        // only became visible once the snapshot's workspaces were restored.
        self.sync_resolver();

        self.clear_tabs_for_session_restore(renderer)?;

        let restored_tabs = self.restore_session_tabs(snapshot.tabs)?;
        if restored_tabs.is_empty() {
            let tab_id = self.new_tab();
            self.split_layout = SplitLayout::single(tab_id);
        } else {
            let active_index = snapshot
                .active_tab
                .min(restored_tabs.len().saturating_sub(1));
            self.select_tab_with_renderer(restored_tabs[active_index], renderer)?;
            self.split_layout = SplitLayout::single(restored_tabs[active_index]);
        }

        // Group membership is stored by session tab index because tab ids
        // are re-issued on restore. Groups without surviving tabs are
        // dropped, keeping the map bounded by the restored tab set.
        self.restore_tab_groups(&snapshot.groups, &restored_tabs);

        self.bookmarks = BookmarkManager::default();
        let mut restored_folders = Vec::with_capacity(snapshot.bookmark_folders.len());
        for folder in snapshot.bookmark_folders {
            let folder_id = self
                .bookmarks
                .create_folder(folder.clone())
                .map_err(ShellError::Bookmark)?;
            restored_folders.push((folder, folder_id));
        }
        for bookmark in snapshot.bookmarks {
            let url = url::Url::parse(&bookmark.url)
                .map_err(|_| ShellError::Session(SessionError::InvalidUrl(bookmark.url)))?;
            let folder_id = bookmark.folder.as_deref().and_then(|folder| {
                restored_folders
                    .iter()
                    .find(|(name, _)| name == folder)
                    .map(|(_, id)| *id)
            });
            self.bookmarks
                .add_in_folder(url, bookmark.title, folder_id)
                .map_err(ShellError::Bookmark)?;
        }

        let restored_history = snapshot
            .history
            .into_iter()
            .filter_map(|visit| {
                let tab_id = restored_tabs.get(visit.tab_index).copied()?;
                let url = url::Url::parse(&visit.url).ok()?;
                Some(HistoryVisit {
                    id: 0,
                    tab_id,
                    url,
                    visited_at: 0,
                })
            })
            .enumerate()
            .map(|(index, mut visit)| {
                visit.id = index.saturating_add(1) as u64;
                visit
            })
            .collect();
        self.runtime.replace_history(restored_history);
        self.permissions = PermissionManager::default();
        for rule in snapshot.permissions {
            let Some(kind) = PermissionKind::from_key(&rule.kind) else {
                continue;
            };
            let Some(decision) = PermissionDecision::from_key(&rule.decision) else {
                continue;
            };
            if matches!(
                decision,
                PermissionDecision::Allow | PermissionDecision::Block
            ) {
                self.permissions.set_decision(rule.site, kind, decision);
            }
        }
        self.sync_address_bar();
        Ok(())
    }

    /// Rebuilds user tab groups from a session snapshot. Group membership is
    /// stored by session tab index because tab ids are re-issued on restore.
    /// Groups without surviving tabs are dropped, keeping the map bounded by
    /// the restored tab set.
    fn restore_tab_groups(&mut self, groups: &[SessionTabGroup], restored_tabs: &[TabId]) {
        self.tab_groups = groups
            .iter()
            .enumerate()
            .filter_map(|(index, session_group)| {
                let tab_ids: Vec<TabId> = session_group
                    .tab_indices
                    .iter()
                    .filter_map(|tab_index| restored_tabs.get(*tab_index).copied())
                    .collect();
                if tab_ids.is_empty() {
                    return None;
                }
                let group_id = self.next_tab_group_id.saturating_add(index as u64).max(1);
                Some((
                    group_id,
                    TabGroup {
                        id: group_id,
                        title: session_group.title.clone(),
                        color: session_group.color.clone(),
                        collapsed: session_group.collapsed,
                        tab_ids,
                    },
                ))
            })
            .collect();
        self.next_tab_group_id = self
            .next_tab_group_id
            .saturating_add(groups.len() as u64)
            .max(1);
    }

    fn restore_session_tabs(
        &mut self,
        session_tabs: Vec<SessionTab>,
    ) -> Result<Vec<TabId>, ShellError> {
        let mut restored_tabs = Vec::with_capacity(session_tabs.len());
        for session_tab in session_tabs {
            let SessionTab {
                url,
                pinned,
                keep_alive,
                user_priority,
                workspace_id,
                container_id,
            } = session_tab;
            let tab_id = self.new_tab();
            let workspace_id =
                workspace_id.map_or_else(|| self.active_workspace(), WorkspaceId::new);
            let container_id =
                container_id.map_or_else(|| self.workspaces.containers()[0].id, ContainerId::new);
            self.workspaces
                .assign_tab(tab_id, workspace_id, container_id)
                .map_err(ShellError::Workspace)?;
            let parsed_url = url.as_ref().and_then(|raw| Url::parse(raw).ok());
            self.runtime
                .restore_tab_metadata(tab_id, parsed_url, TabLifecycle::Archived)
                .map_err(map_tab_error)?;
            self.runtime
                .set_tab_pinned(tab_id, pinned)
                .map_err(map_tab_error)?;
            self.runtime
                .set_tab_keep_alive(tab_id, keep_alive)
                .map_err(map_tab_error)?;
            self.runtime
                .set_tab_priority(tab_id, user_priority)
                .map_err(map_tab_error)?;
            restored_tabs.push(tab_id);
        }
        Ok(restored_tabs)
    }

    pub fn set_identity_account_token(&mut self, token: Option<String>) {
        self.identity_account_token = token;
    }

    /// Sets the browser profile account token and dispatches the
    /// `onSignInChanged` transition to every extension background page.
    ///
    /// # Errors
    ///
    /// Returns an error when the renderer rejects the event dispatch.
    pub fn set_identity_account_token_with_renderer<R: PageRenderer>(
        &mut self,
        token: Option<String>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let signed_in = token.is_some();
        let account = token
            .as_ref()
            .map(|_| serde_json::json!({ "id": "browser-profile" }));
        self.identity_account_token = token;
        self.dispatch_identity_sign_in_changed_all(signed_in, account.as_ref(), renderer)
    }

    /// Replaces the token-endpoint transport used by provider-backed
    /// `identity` flows (tests inject a mock here).
    pub fn set_oauth_token_exchange(&mut self, exchange: Arc<dyn nomad_engine::TokenExchange>) {
        self.oauth_token_exchange = exchange;
    }

    /// Dispatches `onSignInChanged` to every installed, enabled extension
    /// background page (used for browser profile account changes).
    fn dispatch_identity_sign_in_changed_all<R: PageRenderer>(
        &self,
        signed_in: bool,
        account: Option<&serde_json::Value>,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let extension_ids = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| registry.is_enabled(&manifest.id))
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        for extension_id in extension_ids {
            renderer
                .dispatch_extension_event(&ExtensionEvent {
                    extension_id,
                    kind: ExtensionEventKind::IdentitySignInChanged {
                        signed_in,
                        account: account.cloned().unwrap_or(serde_json::Value::Null),
                    },
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn downloads(&self) -> &[DownloadSnapshot] {
        self.downloads.downloads()
    }

    #[must_use]
    pub fn queued_download_requests(&self) -> Vec<(DownloadId, DownloadRequest)> {
        self.downloads
            .downloads()
            .iter()
            .filter(|download| download.state == DownloadState::Queued)
            .map(|download| {
                (
                    download.id,
                    DownloadRequest {
                        tab_id: download.tab_id,
                        url: download.url.clone(),
                        suggested_filename: download.suggested_filename.clone(),
                        total_bytes: download.total_bytes,
                    },
                )
            })
            .collect()
    }

    #[must_use]
    pub fn bookmarks(&self) -> &[Bookmark] {
        self.bookmarks.bookmarks()
    }

    #[must_use]
    pub fn bookmark_folders(&self) -> &[BookmarkFolder] {
        self.bookmarks.folders()
    }

    #[must_use]
    pub fn search_bookmarks(&self, query: &str) -> Vec<Bookmark> {
        self.bookmarks.search(query)
    }

    #[must_use]
    pub fn is_bookmarked(&self, url: &url::Url) -> bool {
        self.bookmarks.contains_url(url)
    }

    /// Toggles a bookmark for the active page.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab or the active tab has no
    /// committed URL yet.
    pub fn toggle_active_bookmark(&mut self) -> Result<(), ShellError> {
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        let tab = self.tab(tab_id).ok_or(ShellError::MissingTab(tab_id))?;
        let url = tab
            .url
            .clone()
            .ok_or(ShellError::Bookmark(BookmarkError::MissingUrl(tab_id)))?;
        if !self.bookmarks.remove_url(&url) {
            let title = url.host_str().unwrap_or(url.as_str()).to_owned();
            self.bookmarks.add(url, title);
        }
        Ok(())
    }

    /// Removes a bookmark from the browser library.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Bookmark`] when the id is not present.
    pub fn remove_bookmark(&mut self, id: BookmarkId) -> Result<(), ShellError> {
        self.bookmarks.remove(id).map_err(ShellError::Bookmark)
    }

    /// Renames a bookmark.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Bookmark`] when the id is not present.
    pub fn rename_bookmark(
        &mut self,
        id: BookmarkId,
        title: impl Into<String>,
    ) -> Result<(), ShellError> {
        self.bookmarks
            .rename(id, title)
            .map_err(ShellError::Bookmark)
    }

    /// Creates a bookmark folder.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Bookmark`] when the name is invalid.
    pub fn create_bookmark_folder(
        &mut self,
        name: impl Into<String>,
    ) -> Result<BookmarkFolderId, ShellError> {
        self.bookmarks
            .create_folder(name)
            .map_err(ShellError::Bookmark)
    }

    /// Renames a bookmark folder.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Bookmark`] when the folder is missing or the name is invalid.
    pub fn rename_bookmark_folder(
        &mut self,
        id: BookmarkFolderId,
        name: impl Into<String>,
    ) -> Result<(), ShellError> {
        self.bookmarks
            .rename_folder(id, name)
            .map_err(ShellError::Bookmark)
    }

    /// Removes a bookmark folder and unassigns its bookmarks.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Bookmark`] when the folder is missing.
    pub fn remove_bookmark_folder(&mut self, id: BookmarkFolderId) -> Result<(), ShellError> {
        self.bookmarks
            .remove_folder(id)
            .map_err(ShellError::Bookmark)
    }

    /// Moves a bookmark into a folder or the unassigned section.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Bookmark`] when the bookmark or folder is missing.
    pub fn move_bookmark(
        &mut self,
        id: BookmarkId,
        folder_id: Option<BookmarkFolderId>,
    ) -> Result<(), ShellError> {
        self.bookmarks
            .move_to_folder(id, folder_id)
            .map_err(ShellError::Bookmark)
    }

    /// Navigates the active tab to a saved bookmark.
    ///
    /// # Errors
    ///
    /// Returns an error when the bookmark, active tab, or renderer operation
    /// fails.
    pub fn open_bookmark_with_renderer<R: PageRenderer>(
        &mut self,
        id: BookmarkId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let url = self
            .bookmarks
            .get(id)
            .ok_or(ShellError::Bookmark(BookmarkError::MissingBookmark(id)))?
            .url
            .clone();
        self.set_address_input(url.as_str());
        self.submit_address_with_renderer(renderer)
    }

    /// Opens a saved bookmark in the reusable blank tab for the active
    /// workspace, creating that tab when necessary.
    ///
    /// # Errors
    ///
    /// Returns an error when the bookmark is missing or the tab/renderer
    /// operation fails.
    pub fn open_bookmark_in_new_tab_with_renderer<R: PageRenderer>(
        &mut self,
        id: BookmarkId,
        renderer: &mut R,
    ) -> Result<TabId, ShellError> {
        let url = self
            .bookmarks
            .get(id)
            .ok_or(ShellError::Bookmark(BookmarkError::MissingBookmark(id)))?
            .url
            .clone();
        self.open_address_in_new_tab_with_renderer(url.as_str(), renderer)
    }

    /// Queues a download request for the browser transport layer.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the URL or filename is rejected.
    pub fn queue_download(&mut self, request: DownloadRequest) -> Result<DownloadId, ShellError> {
        self.downloads.queue(request).map_err(ShellError::Download)
    }

    /// Marks a queued download as ready for transport.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing or not queued.
    pub fn begin_download(&mut self, id: DownloadId) -> Result<(), ShellError> {
        self.downloads.begin(id).map_err(ShellError::Download)
    }

    /// Records the response's advertised download size.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing or
    /// already terminal.
    pub fn set_download_total_bytes(
        &mut self,
        id: DownloadId,
        total_bytes: Option<u64>,
    ) -> Result<(), ShellError> {
        self.downloads
            .set_total_bytes(id, total_bytes)
            .map_err(ShellError::Download)
    }

    /// Records bytes received for an active download.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing or inactive.
    pub fn receive_download_bytes(&mut self, id: DownloadId, bytes: u64) -> Result<(), ShellError> {
        self.downloads
            .receive_bytes(id, bytes)
            .map_err(ShellError::Download)
    }

    /// Writes a response chunk and records its size.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing, inactive,
    /// or its destination cannot be written.
    pub fn receive_download_chunk(
        &mut self,
        id: DownloadId,
        chunk: &[u8],
    ) -> Result<(), ShellError> {
        self.downloads
            .receive_chunk(id, chunk)
            .map_err(ShellError::Download)
    }

    /// Marks an active download as complete.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing or not active.
    pub fn complete_download(&mut self, id: DownloadId) -> Result<(), ShellError> {
        self.downloads.complete(id).map_err(ShellError::Download)
    }

    /// Records a transport failure for a download.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing or terminal.
    pub fn fail_download(
        &mut self,
        id: DownloadId,
        error: impl Into<String>,
    ) -> Result<(), ShellError> {
        self.downloads.fail(id, error).map_err(ShellError::Download)
    }

    /// Cancels a queued or active download.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing or terminal.
    pub fn cancel_download(&mut self, id: DownloadId) -> Result<(), ShellError> {
        self.downloads.cancel(id).map_err(ShellError::Download)
    }

    /// Requeues a failed or cancelled download and returns its transport request.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError::Download`] when the download is missing or still
    /// active/completed.
    pub fn retry_download(&mut self, id: DownloadId) -> Result<DownloadRequest, ShellError> {
        self.downloads
            .retry_request(id)
            .map_err(ShellError::Download)
    }

    pub fn set_address_input(&mut self, input: &str) {
        self.address_bar.set_input(input);
    }

    /// Submits the current address-bar input to the active tab.
    ///
    /// The input is replaced with the URL's canonical form only after
    /// navigation succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab or the input is not a
    /// supported navigable URL.
    pub fn submit_address(&mut self) -> Result<(), ShellError> {
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        let input = self.address_bar.input.clone();
        let normalized = normalize_address_input(&input, &self.settings.search_url)
            .map_err(|_| ShellError::Navigation(NavigationError::InvalidUrl(input.clone())))?;
        self.runtime
            .navigate(tab_id, &normalized)
            .map_err(ShellError::Navigation)?;
        self.sync_address_bar();
        Ok(())
    }

    /// Submits the current address-bar input through a page renderer.
    ///
    /// The address bar and tab state are updated only after the renderer
    /// accepts the navigation.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab, the input is not a
    /// supported navigable URL, or the renderer rejects the load.
    pub fn submit_address_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        let input = self.address_bar.input.clone();
        self.configure_renderer_tab(tab_id, renderer)?;
        let normalized = normalize_address_input(&input, &self.settings.search_url)
            .map_err(|_| ShellError::Navigation(NavigationError::InvalidUrl(input.clone())))?;
        let normalized_url = Url::parse(&normalized)
            .map_err(|_| ShellError::Navigation(NavigationError::InvalidUrl(normalized.clone())))?;
        let scripts = self
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .scripts_for_tab(&ExtensionTabInfo {
                id: tab_id.get(),
                url: Some(normalized_url.clone()),
                active: self.active_tab() == Some(tab_id),
            });
        renderer
            .install_extension_scripts_for_tab(tab_id, &scripts)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        let previous_url = self.tab(tab_id).and_then(|tab| tab.url.clone());
        self.dispatch_web_navigation_before(tab_id, &normalized, renderer)?;
        if let Err(error) = self.navigate_with_history_dispatch(tab_id, &normalized, renderer) {
            let _ = self.dispatch_web_navigation_error(tab_id, &normalized, renderer);
            return Err(ShellError::Navigation(error));
        }
        let history_state = previous_url.as_ref() == Some(&normalized_url);
        self.dispatch_web_navigation_after(tab_id, &normalized_url, renderer, history_state)?;
        self.sync_address_bar();
        Ok(())
    }

    /// Opens address/search input in the reusable blank tab for the active
    /// workspace, creating that tab when necessary.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is invalid or the tab/renderer
    /// operation fails.
    pub fn open_address_in_new_tab_with_renderer<R: PageRenderer>(
        &mut self,
        input: &str,
        renderer: &mut R,
    ) -> Result<TabId, ShellError> {
        let normalized = normalize_address_input(input, &self.settings.search_url)
            .map_err(|_| ShellError::Navigation(NavigationError::InvalidUrl(input.to_owned())))?;
        let tab_id = self.focus_or_create_blank_tab_with_renderer(renderer)?;
        self.set_address_input(&normalized);
        self.submit_address_with_renderer(renderer)?;
        Ok(tab_id)
    }

    fn dispatch_web_navigation_event<R: PageRenderer>(
        &self,
        event_name: &str,
        tab_id: TabId,
        url: &Url,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let extension_ids = {
            let registry = self
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .installed()
                .filter(|manifest| {
                    registry.is_enabled(&manifest.id)
                        && registry.is_granted(&manifest.id, ExtensionPermission::WebNavigation)
                        && registry.is_host_granted(&manifest.id, url)
                })
                .map(|manifest| manifest.id.clone())
                .collect::<Vec<_>>()
        };
        let details = serde_json::json!({
            "tabId": tab_id.get(),
            "frameId": 0,
            "parentFrameId": -1,
            "url": url.as_str(),
            "timeStamp": unix_time_millis(),
        });
        for extension_id in extension_ids {
            renderer
                .dispatch_extension_event(&ExtensionEvent {
                    extension_id,
                    kind: ExtensionEventKind::WebNavigation {
                        event: event_name.to_owned(),
                        details: details.clone(),
                    },
                })
                .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        }
        Ok(())
    }

    fn dispatch_web_navigation_before<R: PageRenderer>(
        &self,
        tab_id: TabId,
        raw_url: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let Ok(url) = Url::parse(raw_url) else {
            return Ok(());
        };
        self.dispatch_web_navigation_event("onBeforeNavigate", tab_id, &url, renderer)
    }

    fn dispatch_web_navigation_error<R: PageRenderer>(
        &self,
        tab_id: TabId,
        raw_url: &str,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let Ok(url) = Url::parse(raw_url) else {
            return Ok(());
        };
        self.dispatch_web_navigation_event("onErrorOccurred", tab_id, &url, renderer)
    }

    fn dispatch_web_navigation_after<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        url: &Url,
        renderer: &mut R,
        history_state: bool,
    ) -> Result<(), ShellError> {
        self.dispatch_web_navigation_event("onCommitted", tab_id, url, renderer)?;
        if history_state {
            self.dispatch_web_navigation_event("onHistoryStateUpdated", tab_id, url, renderer)?;
        }
        self.dispatch_web_navigation_event("onDOMContentLoaded", tab_id, url, renderer)?;
        self.dispatch_web_navigation_event("onCompleted", tab_id, url, renderer)?;
        self.complete_pending_auth_flows(tab_id, url, renderer)
    }

    /// Reloads the active tab without adding a duplicate history entry.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab or the renderer rejects
    /// the reload.
    pub fn reload_active_tab_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        let has_url = self.tab(tab_id).and_then(|tab| tab.url.as_ref()).is_some();
        self.configure_renderer_tab(tab_id, renderer)?;
        if has_url {
            self.runtime
                .reload_tab_with_renderer(tab_id, renderer)
                .map_err(ShellError::Navigation)?;
        } else {
            self.runtime
                .select_tab_with_renderer(tab_id, renderer)
                .map_err(map_tab_error)?;
        }
        self.sync_address_bar();
        Ok(())
    }

    /// Commits a renderer-reported successful navigation.
    ///
    /// Servo reports navigation completion asynchronously. Keeping this
    /// transition separate from the load request prevents the shell from
    /// presenting a page as active before the document has finished loading.
    pub fn finish_navigation(&mut self, tab_id: TabId) -> Result<(), ShellError> {
        self.runtime
            .finish_navigation(tab_id)
            .map_err(map_tab_error)?;
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    /// Synchronizes browser-owned navigation state after a page-driven URL
    /// change, such as clicking a normal link or using `history.pushState`.
    /// Address-bar navigations already committed the same URL before the
    /// renderer notification arrives, so they are not recorded twice.
    pub fn sync_renderer_navigation(&mut self, tab_id: TabId, url: &Url) -> Result<(), ShellError> {
        let already_committed = self.tab(tab_id).and_then(|tab| tab.url.as_ref()) == Some(url);
        if !already_committed {
            self.runtime
                .navigate(tab_id, url.as_str())
                .map_err(ShellError::Navigation)?;
        }
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    #[must_use]
    pub fn can_go_back(&self) -> bool {
        self.active_tab()
            .and_then(|tab_id| self.runtime.can_go_back(tab_id).ok())
            .unwrap_or(false)
    }

    #[must_use]
    pub fn can_go_forward(&self) -> bool {
        self.active_tab()
            .and_then(|tab_id| self.runtime.can_go_forward(tab_id).ok())
            .unwrap_or(false)
    }

    /// Moves the active tab to its previous navigation entry.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab, no previous entry, or the
    /// renderer rejects the target.
    pub fn go_back_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        self.runtime
            .go_back_with_renderer(tab_id, renderer)
            .map_err(ShellError::Navigation)?;
        self.sync_address_bar();
        Ok(())
    }

    /// Moves the active tab to its next navigation entry.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab, no forward entry, or the
    /// renderer rejects the target.
    pub fn go_forward_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let tab_id = self.active_tab().ok_or(ShellError::NoActiveTab)?;
        self.runtime
            .go_forward_with_renderer(tab_id, renderer)
            .map_err(ShellError::Navigation)?;
        self.sync_address_bar();
        Ok(())
    }

    pub fn new_tab(&mut self) -> TabId {
        let tab_id = self.runtime.new_tab();
        let workspace_id = self.active_workspace();
        let container_id = self.workspaces.containers()[0].id;
        let _ = self
            .workspaces
            .assign_tab(tab_id, workspace_id, container_id);
        self.address_bar.clear();
        self.sync_sidebar();
        tab_id
    }

    /// Opens Settings as a normal tab, reusing the active workspace's
    /// existing Settings tab when possible.
    pub fn open_settings_tab_with_renderer<R: PageRenderer>(
        &mut self,
        _renderer: &mut R,
    ) -> Result<TabId, ShellError> {
        let existing = self
            .workspace_tabs(self.active_workspace())
            .into_iter()
            .find(|tab_id| {
                self.tab(*tab_id)
                    .and_then(|tab| tab.url.as_ref())
                    .is_some_and(|url| url.as_str() == "about:settings")
            });
        let tab_id = if let Some(tab_id) = existing {
            tab_id
        } else {
            let tab_id = self.new_tab();
            self.runtime
                .navigate(tab_id, "about:settings")
                .map_err(ShellError::Navigation)?;
            tab_id
        };
        // Settings is a browser-owned document represented by a normal tab.
        // Selecting it must not create a Servo `about:blank` WebView: that
        // surface would be composited over the native settings document.
        self.select_tab(tab_id)?;
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(tab_id)
    }

    /// Focuses an existing empty tab in the active workspace, or creates one
    /// when every tab in that workspace has navigated away from the blank page.
    ///
    /// This is the user-facing new-tab operation. Keeping it separate from
    /// [`Self::new_tab`] lets internal features such as split view create a
    /// distinct tab when they explicitly require one.
    ///
    /// # Errors
    ///
    /// Returns an error when the renderer cannot initialize or activate the
    /// selected tab.
    pub fn focus_or_create_blank_tab_with_renderer<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<TabId, ShellError> {
        let blank_tab = self
            .workspace_tabs(self.active_workspace())
            .into_iter()
            .find(|tab_id| {
                self.tab(*tab_id).is_some_and(|tab| match tab.url.as_ref() {
                    None => true,
                    Some(url) => url.as_str() == "about:blank",
                })
            });

        let tab_id = blank_tab.unwrap_or_else(|| self.new_tab());
        self.select_tab_with_renderer(tab_id, renderer)?;
        Ok(tab_id)
    }

    /// Selects the reusable blank tab without creating its renderer surface.
    /// This lets a subsequent first navigation become the `WebView`'s initial
    /// document instead of racing an `about:blank` browsing context.
    pub fn focus_or_create_blank_tab(&mut self) -> Result<TabId, ShellError> {
        let blank_tab = self
            .workspace_tabs(self.active_workspace())
            .into_iter()
            .find(|tab_id| {
                self.tab(*tab_id).is_some_and(|tab| match tab.url.as_ref() {
                    None => true,
                    Some(url) => url.as_str() == "about:blank",
                })
            });
        let tab_id = blank_tab.unwrap_or_else(|| self.new_tab());
        self.select_tab(tab_id)?;
        Ok(tab_id)
    }

    /// Selects a tab and synchronizes the sidebar and address bar.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist.
    pub fn select_tab(&mut self, tab_id: TabId) -> Result<(), ShellError> {
        self.runtime.select_tab(tab_id).map_err(map_tab_error)?;
        if !self.split_layout.contains_tab(tab_id) {
            self.split_layout = SplitLayout::single(tab_id);
        }
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    /// Selects a tab and activates its renderer surface.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist or the renderer rejects
    /// activation. Shell state remains unchanged on failure.
    pub fn select_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        if self
            .tab(tab_id)
            .and_then(|tab| tab.url.as_ref())
            .is_some_and(|url| url.as_str() == "about:settings")
        {
            return self.select_tab(tab_id);
        }
        let was_active = self.active_tab() == Some(tab_id);
        self.configure_renderer_tab(tab_id, renderer)?;
        self.runtime
            .select_tab_with_renderer(tab_id, renderer)
            .map_err(map_tab_error)?;
        // Selecting a tab that is not part of the split tree leaves split
        // view: the layout collapses to that tab so the rendered page always
        // matches the active tab. Pane activation keeps the tree because the
        // selected tab is already a pane.
        if !self.split_layout.contains_tab(tab_id) {
            self.split_layout = SplitLayout::single(tab_id);
        }
        self.sync_sidebar();
        self.sync_address_bar();
        if !was_active {
            self.dispatch_extension_tab_event(
                tab_id,
                |_, _| ExtensionEventKind::TabActivated {
                    tab_id: tab_id.get(),
                    window_id: 1,
                },
                renderer,
            )?;
        }
        Ok(())
    }

    /// Closes a tab and synchronizes the sidebar and address bar.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist.
    pub fn close_tab(&mut self, tab_id: TabId) -> Result<(), ShellError> {
        let was_active = self.active_tab() == Some(tab_id);
        self.runtime.close_tab(tab_id).map_err(map_tab_error)?;
        self.forget_closed_tab(tab_id);
        if self.tabs().is_empty() {
            let replacement = self.new_tab();
            self.split_layout = SplitLayout::single(replacement);
        } else if was_active {
            if let Some(active_tab) = self.active_tab() {
                self.split_layout = SplitLayout::single(active_tab);
            }
        }
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    /// Releases a tab's renderer surface, closes it, and activates the tab
    /// selected by the runtime when the active tab was closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist, renderer release fails,
    /// or the replacement tab cannot be activated.
    pub fn close_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let was_active = self.active_tab() == Some(tab_id);
        self.dispatch_extension_tab_event(
            tab_id,
            |_, _| ExtensionEventKind::TabRemoved {
                tab_id: tab_id.get(),
                window_id: 1,
            },
            renderer,
        )?;
        self.runtime
            .close_tab_with_renderer(tab_id, renderer)
            .map_err(map_tab_error)?;
        self.forget_closed_tab(tab_id);
        let replacement = if self.tabs().is_empty() {
            let replacement = self.new_tab();
            self.split_layout = SplitLayout::single(replacement);
            self.configure_renderer_tab(replacement, renderer)?;
            Some(replacement)
        } else {
            if was_active {
                if let Some(active_tab) = self.active_tab() {
                    self.split_layout = SplitLayout::single(active_tab);
                }
            }
            None
        };
        self.extension_frames.remove_tab(tab_id.get());
        self.sync_sidebar();
        self.sync_address_bar();

        if was_active {
            if let Some(active_tab) = self.active_tab() {
                renderer
                    .activate(active_tab)
                    .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
                self.dispatch_extension_tab_event(
                    active_tab,
                    |_, _| ExtensionEventKind::TabActivated {
                        tab_id: active_tab.get(),
                        window_id: 1,
                    },
                    renderer,
                )?;
            }
        }
        debug_assert!(replacement.is_none() || self.tabs().len() == 1);
        Ok(())
    }

    /// Removes the shell's startup tabs before restoring a saved session.
    ///
    /// This deliberately bypasses the public close operation's persistent
    /// blank-tab replacement. Otherwise restoring N saved tabs would leave
    /// that replacement alongside them and shift every restored tab index.
    fn clear_tabs_for_session_restore<R: PageRenderer>(
        &mut self,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let tab_ids = self.tabs().iter().map(|tab| tab.id).collect::<Vec<_>>();
        for tab_id in tab_ids {
            self.runtime
                .close_tab_with_renderer(tab_id, renderer)
                .map_err(map_tab_error)?;
            self.forget_closed_tab(tab_id);
        }
        self.sync_sidebar();
        self.sync_address_bar();
        Ok(())
    }

    fn sync_sidebar(&mut self) {
        self.sidebar.sync_from_runtime(&self.runtime);
    }

    fn forget_closed_tab(&mut self, tab_id: TabId) {
        self.workspaces.forget_tab(tab_id);
        self.reader_modes.remove(&tab_id);
        self.reader_documents.remove(&tab_id);
        self.devtools.remove(&tab_id);
        self.split_layout.remove_tab(tab_id);
        self.extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear_active_tab_grant(tab_id.get());
        self.extension_ports
            .retain(|(_, current_tab_id, _)| *current_tab_id != tab_id.get());
        for group in self.tab_groups.values_mut() {
            group.tab_ids.retain(|group_tab_id| *group_tab_id != tab_id);
        }
        self.tab_groups.retain(|_, group| !group.tab_ids.is_empty());
        self.pending_extension_screenshots.remove(&tab_id);
    }

    /// Removes `tab_ids` from every group except `keep_group_id` (use 0 to
    /// keep none). A tab lives in at most one group.
    fn remove_tabs_from_other_groups(
        groups: &mut HashMap<u64, TabGroup>,
        keep_group_id: u64,
        tab_ids: &[TabId],
    ) {
        for group in groups.values_mut() {
            if group.id != keep_group_id {
                group.tab_ids.retain(|tab_id| !tab_ids.contains(tab_id));
            }
        }
    }

    pub fn configure_renderer_tab<R: PageRenderer>(
        &self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), ShellError> {
        let context = self.tab_context(tab_id);
        let ephemeral = self
            .workspaces
            .container(context.container_id)
            .is_some_and(|container| container.ephemeral);
        renderer
            .configure_tab(tab_id, context.container_id, ephemeral)
            .map_err(|error| ShellError::Navigation(NavigationError::Render(error)))?;
        renderer.set_web_request_blocking_handler(Arc::new(WebRequestBlockingAdapter {
            registry: Arc::clone(&self.extensions),
            decisions: Arc::clone(&self.web_request_blocking_decisions),
        }));
        Ok(())
    }

    fn sync_address_bar(&mut self) {
        let input = self
            .active_tab()
            .and_then(|tab_id| self.tab(tab_id))
            .and_then(|tab| tab.url.as_ref())
            .map(ToString::to_string)
            .unwrap_or_default();
        self.address_bar.set_input(&input);
    }
}

/// Substitute `$1`, `$2`, ... positional substitutions into an i18n message
/// body. Named `$NAME$` placeholders that reference the message catalog's
/// `placeholders` block are resolved positionally from the substitution order
/// when present.
fn substitute_i18n_message(message: &str, substitutions: &[String]) -> String {
    let mut output = message.to_owned();
    for (index, substitution) in substitutions.iter().enumerate() {
        let index = index + 1;
        output = output.replace(&format!("${index}$"), substitution);
        output = output.replace(&format!("${index}"), substitution);
    }
    output.replace("$$", "$")
}

fn map_tab_error(error: TabError) -> ShellError {
    match error {
        TabError::MissingTab(tab_id) => ShellError::MissingTab(tab_id),
        TabError::Render(error) => ShellError::Navigation(NavigationError::Render(error)),
        TabError::ActiveTabCannotBeSuspended(tab_id) => {
            ShellError::ActiveTabCannotBeSuspended(tab_id)
        }
    }
}

fn is_extension_storage_message(payload: &serde_json::Value) -> bool {
    payload.as_object().is_some_and(|object| {
        object.contains_key("__nomad_storage_set")
            || object.contains_key("__nomad_storage_remove")
            || object.contains_key("__nomad_storage_clear")
    })
}

fn extension_tab_value(tab: &ExtensionTabInfo) -> serde_json::Value {
    serde_json::json!({
        "id": tab.id,
        "windowId": 1,
        "index": 0,
        "url": tab.url.as_ref().map(ToString::to_string),
        "active": tab.active,
        "highlighted": tab.active,
        "pinned": false,
        "incognito": false,
        "status": "complete",
        "discarded": false,
    })
}

fn extension_wildcard_matches(pattern: &str, value: &str) -> bool {
    if pattern == "<all_urls>" || pattern == "*" {
        return true;
    }
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
    fragments.is_empty() || remaining.is_empty() || pattern.ends_with('*')
}

fn extension_menu_id(value: Option<&serde_json::Value>) -> Result<String, ShellError> {
    let value = value.ok_or_else(|| {
        ShellError::Extension(ExtensionError::InvalidManifest(
            "context menu operation requires menuItemId".into(),
        ))
    })?;
    if let Some(id) = value.as_str() {
        return Ok(id.to_owned());
    }
    value.as_u64().map(|id| id.to_string()).ok_or_else(|| {
        ShellError::Extension(ExtensionError::InvalidManifest(
            "context menu id must be a string or number".into(),
        ))
    })
}

fn extension_management_value(manifest: &ExtensionManifest, enabled: bool) -> serde_json::Value {
    serde_json::json!({
        "id": &manifest.id,
        "name": &manifest.name,
        "version": &manifest.version,
        "shortName": &manifest.name,
        "description": "",
        "enabled": enabled,
        "type": "extension",
        "appDisabled": false,
        "installType": "development",
        "permissions": &manifest.permissions,
        "hostPermissions": &manifest.host_permissions,
    })
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn minutes_to_millis(minutes: f64) -> u64 {
    if !minutes.is_finite() || minutes <= 0.0 {
        return 0;
    }
    let millis = minutes * 60_000.0;
    if millis >= u64::MAX as f64 {
        u64::MAX
    } else {
        millis as u64
    }
}

#[cfg(test)]
mod tests {
    use nomad_core::{BackendAvailability, Switches};
    use nomad_engine::{
        BrowserRuntime, DownloadRequest, ExtensionEvent, ExtensionEventKind, ExtensionMessage,
        MemoryMode, NavigationError, NavigationRequest, OAuthFlowError, OAuthTokenRecord,
        PageRenderer, PermissionDecision, PermissionKind, ReaderMode, RenderError,
        SplitOrientation, TabId, TabLifecycle, TabState, TokenExchangeRequest,
    };
    use url::Url;

    use super::{
        AddressBarState, BrowserCommand, BrowserSettings, PermissionPrompt, PrivacyMode,
        ShellError, ShellState, UniversalSuggestionKind, UniversalTarget, VerticalTabSidebarState,
    };

    #[derive(Default)]
    struct RecordingRenderer {
        loaded: Vec<NavigationRequest>,
        activated: Vec<TabId>,
        released: Vec<TabId>,
        extension_events: Vec<ExtensionEvent>,
        page_messages: Vec<(TabId, String, serde_json::Value)>,
        blocking_patterns: Vec<String>,
        css_operations: Vec<(TabId, String, String)>,
        target_operations: Vec<(TabId, Option<u64>, String, String)>,
        #[allow(clippy::type_complexity)]
        frame_tree_events: Vec<(TabId, Vec<(u64, Option<u64>, String)>)>,
        screenshot_requests: Vec<TabId>,
        screenshot_results: Vec<(TabId, Result<Vec<u8>, RenderError>)>,
        cookie_operations: Vec<(String, serde_json::Value)>,
        fail: bool,
    }

    impl PageRenderer for RecordingRenderer {
        fn load(&mut self, request: &NavigationRequest) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.loaded.push(request.clone());
            Ok(())
        }

        fn execute_extension_script_target(
            &mut self,
            tab_id: TabId,
            frame_handle: Option<u64>,
            extension_id: &str,
            source: &str,
        ) -> Result<(), RenderError> {
            self.target_operations.push((
                tab_id,
                frame_handle,
                format!("script:{extension_id}"),
                source.to_owned(),
            ));
            Ok(())
        }

        fn insert_extension_css_target(
            &mut self,
            tab_id: TabId,
            frame_handle: Option<u64>,
            extension_id: &str,
            source: &str,
        ) -> Result<(), RenderError> {
            self.target_operations.push((
                tab_id,
                frame_handle,
                format!("insert:{extension_id}"),
                source.to_owned(),
            ));
            self.css_operations
                .push((tab_id, format!("insert:{extension_id}"), source.to_owned()));
            Ok(())
        }

        fn remove_extension_css_target(
            &mut self,
            tab_id: TabId,
            frame_handle: Option<u64>,
            extension_id: &str,
        ) -> Result<(), RenderError> {
            self.target_operations.push((
                tab_id,
                frame_handle,
                format!("remove:{extension_id}"),
                String::new(),
            ));
            self.css_operations
                .push((tab_id, format!("remove:{extension_id}"), String::new()));
            Ok(())
        }

        fn activate(&mut self, tab_id: TabId) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.activated.push(tab_id);
            Ok(())
        }

        fn dispatch_extension_event(&mut self, event: &ExtensionEvent) -> Result<(), RenderError> {
            self.extension_events.push(event.clone());
            Ok(())
        }

        fn dispatch_extension_message(
            &mut self,
            tab_id: TabId,
            extension_id: &str,
            payload: &serde_json::Value,
        ) -> Result<(), RenderError> {
            self.page_messages
                .push((tab_id, extension_id.to_owned(), payload.clone()));
            Ok(())
        }

        fn set_extension_blocking_patterns(&mut self, patterns: &[String]) {
            self.blocking_patterns = patterns.to_vec();
        }

        fn request_tab_screenshot(&mut self, tab_id: TabId) -> Result<(), RenderError> {
            self.screenshot_requests.push(tab_id);
            Ok(())
        }

        fn take_tab_screenshots(&mut self) -> Vec<(TabId, Result<Vec<u8>, RenderError>)> {
            std::mem::take(&mut self.screenshot_results)
        }

        fn insert_extension_css(
            &mut self,
            tab_id: TabId,
            extension_id: &str,
            source: &str,
        ) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.css_operations
                .push((tab_id, format!("insert:{extension_id}"), source.to_owned()));
            Ok(())
        }

        fn take_extension_frame_tree_events(
            &mut self,
        ) -> Vec<(TabId, Vec<(u64, Option<u64>, String)>)> {
            std::mem::take(&mut self.frame_tree_events)
        }

        fn extension_cookie_operation(
            &mut self,
            method: &str,
            arguments: &serde_json::Value,
        ) -> Result<serde_json::Value, RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            let name = arguments
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            self.cookie_operations
                .push((method.to_owned(), arguments.clone()));
            if name == "missing" {
                return Ok(serde_json::Value::Null);
            }
            Ok(serde_json::json!({
                "name": name,
                "value": "v1",
                "domain": "example.com",
                "path": "/",
                "secure": false,
                "httpOnly": false,
            }))
        }

        fn remove_extension_css(
            &mut self,
            tab_id: TabId,
            extension_id: &str,
        ) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.css_operations
                .push((tab_id, format!("remove:{extension_id}"), String::new()));
            Ok(())
        }

        fn release(&mut self, tab_id: TabId) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.released.push(tab_id);
            Ok(())
        }
    }

    fn runtime() -> BrowserRuntime {
        BrowserRuntime::new(Switches::default(), BackendAvailability::all_available())
            .expect("direct mode should always initialize")
    }

    #[test]
    fn test_address_bar_stores_user_input() {
        let mut address_bar = AddressBarState::default();

        address_bar.set_input("https://example.com");

        assert_eq!(address_bar.input(), "https://example.com");
    }

    #[test]
    fn test_shell_starts_with_one_blank_active_tab() {
        let shell = ShellState::new(runtime());

        assert_eq!(shell.tabs().len(), 1);
        assert_eq!(shell.active_tab(), Some(shell.tabs()[0].id));
        assert_eq!(shell.tabs()[0].state, TabState::New);
        assert_eq!(shell.address_bar().input(), "");
    }

    #[test]
    fn test_webextension_runtime_is_available_through_shell_capabilities() {
        let mut shell = ShellState::new(runtime());
        let manifest = nomad_engine::ExtensionManifest::from_json(
            r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["storage","tabs"],"host_permissions":["https://example.com/*"]}"#,
        )
        .unwrap();
        shell.install_extension(manifest).unwrap();
        shell
            .grant_extension_permission("tool", nomad_engine::ExtensionPermission::Storage)
            .unwrap();
        shell
            .grant_extension_permission("tool", nomad_engine::ExtensionPermission::Tabs)
            .unwrap();
        shell
            .grant_extension_host_permission("tool", "https://example.com/*")
            .unwrap();
        shell
            .extension_storage_set("tool", "theme", serde_json::json!("dark"))
            .unwrap();
        assert_eq!(
            shell.extension_storage_get("tool", "theme").unwrap(),
            Some(serde_json::json!("dark"))
        );

        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let active_tab = shell.active_tab().unwrap();
        let tabs = shell.extension_query_tabs("tool").unwrap();
        assert_eq!(tabs[0].id, active_tab.get());
        assert_eq!(
            tabs[0].url.as_ref().unwrap().as_str(),
            "https://example.com/"
        );
        shell
            .receive_extension_message(nomad_engine::ExtensionMessage {
                extension_id: "tool".into(),
                tab_id: Some(active_tab.get()),
                payload: serde_json::json!({"__nomad_storage_set": {"from_page": true}}),
            })
            .unwrap();
        assert_eq!(
            shell.extension_storage_get("tool", "from_page").unwrap(),
            Some(serde_json::json!(true))
        );
        shell
            .send_extension_message("tool", Some(active_tab), serde_json::json!({"ready": true}))
            .unwrap();
        assert_eq!(shell.drain_extension_messages("tool").len(), 1);
    }

    #[test]
    fn test_webextension_update_reloads_renderer_and_preserves_state() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"updatable","name":"Updatable","version":"1.0","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "globalThis.version = 1;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "updatable",
                nomad_engine::ExtensionPermission::Storage,
                &mut renderer,
            )
            .unwrap();
        shell
            .extension_storage_set("updatable", "keep", serde_json::json!(true))
            .unwrap();

        let package = nomad_engine::ExtensionPackage::from_manifest_json(
            r#"{"manifest_version":3,"id":"updatable","name":"Updatable","version":"2.0","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
            [("background.js".into(), "globalThis.version = 2;".into())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        shell
            .update_extension_package_with_renderer(package, &mut renderer)
            .unwrap();

        assert_eq!(
            shell.extension_manifest("updatable").unwrap().version,
            "2.0"
        );
        assert_eq!(
            shell.extension_storage_get("updatable", "keep").unwrap(),
            Some(serde_json::json!(true))
        );
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::Installed { reason } if reason == "update"
        )));
        assert!(
            renderer.extension_events.iter().any(|event| matches!(
                &event.kind,
                nomad_engine::ExtensionEventKind::RuntimeUpdateAvailable { version }
                    if version == "2.0"
            )),
            "an update must announce itself through runtime.onUpdateAvailable"
        );
        assert!(
            renderer.extension_events.iter().any(|event| matches!(
                &event.kind,
                nomad_engine::ExtensionEventKind::RuntimeSuspend
            )),
            "the old background worker must be suspended before reload"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_runtime_options_page_and_uninstall_url() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"options","name":"Options","version":"1","options_ui":{"page":"options.html"},"background":{"service_worker":"background.js"}}"#,
                [
                    ("background.js".into(), "1;".into()),
                    (
                        "options.html".into(),
                        "<!doctype html><p>settings</p>".into(),
                    ),
                ]
                .into_iter()
                .collect(),
                &mut renderer,
            )
            .unwrap();

        let api = |request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: "options".into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api("1", "runtime.openOptionsPage", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "1").unwrap(), serde_json::Value::Null);
        let options_tab = shell.active_tab().unwrap();
        assert_eq!(
            shell
                .tab(options_tab)
                .unwrap()
                .url
                .as_ref()
                .unwrap()
                .as_str(),
            "nomad-extension://options/options.html",
            "openOptionsPage must navigate a tab to the declared options page"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "2",
                    "runtime.setUninstallURL",
                    serde_json::json!({"url": "https://example.com/why"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "2").unwrap(), serde_json::Value::Null);
        assert_eq!(
            shell.extension_uninstall_url("options"),
            Some("https://example.com/why".to_owned()),
            "the uninstall URL must be stored for the uninstall survey"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "3",
                    "runtime.setUninstallURL",
                    serde_json::json!({"url": "file:///etc/passwd"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "3").is_err(),
            "non-http(s) uninstall URLs must be rejected"
        );

        let suspended = renderer
            .extension_events
            .iter()
            .filter(|event| matches!(event.kind, nomad_engine::ExtensionEventKind::RuntimeSuspend))
            .count();
        assert_eq!(
            suspended, 0,
            "no suspend may fire while the extension keeps running"
        );
        shell
            .uninstall_extension_with_renderer("options", &mut renderer)
            .unwrap();
        assert!(
            renderer.extension_events.iter().any(|event| matches!(
                &event.kind,
                nomad_engine::ExtensionEventKind::RuntimeSuspend
            )),
            "uninstalling an enabled extension must suspend its worker first"
        );
    }

    #[test]
    fn test_webextension_page_messages_reach_background_context() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["tabs"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "browser.runtime.onMessage.addListener(() => {});".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "tool",
                nomad_engine::ExtensionPermission::Tabs,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_host_permission_with_renderer(
                "tool",
                "https://example.com/*",
                &mut renderer,
            )
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let tab_id = shell.active_tab().unwrap();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "tool".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({"hello": "background"}),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(renderer.extension_events.len(), 3);

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "tool".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_page_message": {
                            "tab_id": tab_id.get(),
                            "payload": {"from": "background"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            renderer.page_messages,
            vec![(
                tab_id,
                "tool".into(),
                serde_json::json!({"from": "background"})
            )]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_external_runtime_ports_route_both_directions() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"sender","name":"Sender","version":"1","background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), String::new())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"receiver","name":"Receiver","version":"1","externally_connectable":{"ids":["sender"]},"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), String::new())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        let content_tab_id = shell.active_tab().unwrap().get();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "sender".into(),
                    tab_id: Some(content_tab_id),
                    payload: serde_json::json!({
                        "__nomad_extension_port_connect": {
                            "target_id": "receiver",
                            "port_id": "sender-content-runtime-1",
                            "name": "wallet-content"
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeExternalPortConnected {
                sender_extension_id,
                port_id,
                name,
            } if event.extension_id == "receiver"
                && sender_extension_id == "sender"
                && port_id == "sender-content-runtime-1"
                && name == "wallet-content"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "sender".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_extension_port_connect": {
                            "target_id": "receiver",
                            "port_id": "sender-runtime-1",
                            "name": "wallet"
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeExternalPortConnected {
                sender_extension_id,
                port_id,
                name,
            } if event.extension_id == "receiver"
                && sender_extension_id == "sender"
                && port_id == "sender-runtime-1"
                && name == "wallet"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "sender".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_extension_port_message": {
                            "target_id": "receiver",
                            "port_id": "sender-runtime-1",
                            "payload": {"request": "accounts"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeExternalPortMessage {
                sender_extension_id,
                port_id,
                payload,
            } if event.extension_id == "receiver"
                && sender_extension_id == "sender"
                && port_id == "sender-runtime-1"
                && payload == &serde_json::json!({"request": "accounts"})
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "receiver".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_extension_port_message": {
                            "target_id": "sender",
                            "port_id": "sender-runtime-1",
                            "payload": {"accounts": []}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeExternalPortMessage {
                sender_extension_id,
                port_id,
                payload,
            } if event.extension_id == "sender"
                && sender_extension_id == "receiver"
                && port_id == "sender-runtime-1"
                && payload == &serde_json::json!({"accounts": []})
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "receiver".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_extension_port_disconnect": {
                            "target_id": "sender",
                            "port_id": "sender-runtime-1"
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeExternalPortDisconnected {
                sender_extension_id,
                port_id,
            } if event.extension_id == "sender"
                && sender_extension_id == "receiver"
                && port_id == "sender-runtime-1"
        )));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_runtime_message_round_trip_preserves_request_id() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"wallet","name":"Wallet","version":"1","permissions":["tabs"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "browser.runtime.onMessage.addListener((message) => ({ok: message.ok}));".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "wallet",
                nomad_engine::ExtensionPermission::Tabs,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_host_permission_with_renderer(
                "wallet",
                "https://example.com/*",
                &mut renderer,
            )
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let tab_id = shell.active_tab().unwrap();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "wallet".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_extension_port_connect": {
                            "target_id": "wallet",
                            "port_id": "wallet-content-1",
                            "name": "metamask"
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimePortConnected {
                tab_id: event_tab,
                port_id,
                name,
            } if *event_tab == tab_id.get()
                && port_id == "wallet-content-1"
                && name == "metamask"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "wallet".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_extension_port_message": {
                            "target_id": "wallet",
                            "port_id": "wallet-content-1",
                            "payload": {"request": "accounts"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimePortMessage {
                tab_id: event_tab,
                port_id,
                payload,
            } if *event_tab == tab_id.get()
                && port_id == "wallet-content-1"
                && payload == &serde_json::json!({"request": "accounts"})
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "wallet".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_runtime_request": {
                            "request_id": "42",
                            "payload": {"ok": true}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeMessage {
                request_id: Some(request_id),
                payload,
                ..
            } if request_id == "42" && payload == &serde_json::json!({"ok": true})
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "wallet".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_page_response": {
                            "tab_id": tab_id.get(),
                            "request_id": "42",
                            "result": {"ok": true}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            renderer.page_messages.last().map(|(_, _, payload)| payload),
            Some(&serde_json::json!({
                "__nomad_runtime_response": {
                    "request_id": "42",
                    "result": {"ok": true}
                }
            }))
        );

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "wallet".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_runtime_port_connect": {
                            "port_id": "wallet-content-2",
                            "name": "metamask"
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimePortConnected {
                tab_id: event_tab,
                port_id,
                name,
            } if *event_tab == tab_id.get()
                && port_id == "wallet-content-2"
                && name == "metamask"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "wallet".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_runtime_port": {
                            "port_id": "wallet-1",
                            "name": "metamask",
                            "payload": {"hello": "port"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimePortConnected {
                tab_id: event_tab,
                port_id,
                name,
            } if *event_tab == tab_id.get() && port_id == "wallet-1" && name == "metamask"
        )));
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimePortMessage {
                tab_id: event_tab,
                port_id,
                payload,
            } if *event_tab == tab_id.get()
                && port_id == "wallet-1"
                && payload == &serde_json::json!({"hello": "port"})
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "wallet".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_port_response": {
                            "tab_id": tab_id.get(),
                            "port_id": "wallet-1",
                            "payload": {"reply": true}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            renderer.page_messages.last().map(|(_, _, payload)| payload),
            Some(&serde_json::json!({
                "__nomad_port_response": {
                    "port_id": "wallet-1",
                    "payload": {"reply": true}
                }
            }))
        );
    }

    #[test]
    fn test_webextension_tabs_send_message_round_trip_reaches_content_script() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"messenger","name":"Messenger","version":"1","permissions":["tabs"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":"browser.runtime.onMessage.addListener(() => {});"}],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), String::new())].into_iter().collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "messenger",
                nomad_engine::ExtensionPermission::Tabs,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_host_permission_with_renderer(
                "messenger",
                "https://example.com/*",
                &mut renderer,
            )
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let tab_id = shell.active_tab().unwrap();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "messenger".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "send-1",
                            "method": "tabs.sendMessage",
                            "arguments": {
                                "tabId": tab_id.get(),
                                "message": {"hello": "content"}
                            }
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            renderer.page_messages.last().map(|(_, _, payload)| payload),
            Some(&serde_json::json!({
                "__nomad_tabs_request": {
                    "request_id": "send-1",
                    "payload": {"hello": "content"}
                }
            }))
        );
        assert!(!renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse { request_id, .. }
                if request_id == "send-1"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "messenger".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_page_response": {
                            "tab_id": tab_id.get(),
                            "request_id": "send-1",
                            "result": {"received": true}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "send-1" && value == &serde_json::json!({"received": true})
        )));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_tabs_connect_routes_messages_and_disconnects() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"ports","name":"Ports","version":"1","permissions":["tabs"],"host_permissions":["https://example.com/*"],"content_scripts":[{"matches":["https://example.com/*"],"js":"browser.runtime.onConnect.addListener(() => {});"}],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), String::new())].into_iter().collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "ports",
                nomad_engine::ExtensionPermission::Tabs,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_host_permission_with_renderer(
                "ports",
                "https://example.com/*",
                &mut renderer,
            )
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let tab_id = shell.active_tab().unwrap();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "ports".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_tabs_port_connect": {
                            "tab_id": tab_id.get(),
                            "port_id": "ports-tabs-1",
                            "name": "devtools"
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            renderer.page_messages.last().map(|(_, _, payload)| payload),
            Some(&serde_json::json!({
                "__nomad_tabs_port_connected": {
                    "port_id": "ports-tabs-1",
                    "name": "devtools"
                }
            }))
        );

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "ports".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_tabs_port_message": {
                            "port_id": "ports-tabs-1",
                            "payload": {"from": "content"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimePortMessage {
                tab_id: event_tab,
                port_id,
                payload,
            } if *event_tab == tab_id.get()
                && port_id == "ports-tabs-1"
                && payload == &serde_json::json!({"from": "content"})
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "ports".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_tabs_port_message": {
                            "tab_id": tab_id.get(),
                            "port_id": "ports-tabs-1",
                            "payload": {"from": "background"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            renderer.page_messages.last().map(|(_, _, payload)| payload),
            Some(&serde_json::json!({
                "__nomad_tabs_port_message": {
                    "port_id": "ports-tabs-1",
                    "payload": {"from": "background"}
                }
            }))
        );

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "ports".into(),
                    tab_id: Some(tab_id.get()),
                    payload: serde_json::json!({
                        "__nomad_tabs_port_disconnect": {"port_id": "ports-tabs-1"}
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimePortDisconnected {
                tab_id: event_tab,
                port_id,
            } if *event_tab == tab_id.get() && port_id == "ports-tabs-1"
        )));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_tab_groups_round_trip() {
        let mut shell = ShellState::new(runtime());
        shell
            .install_extension(
                nomad_engine::ExtensionManifest::from_json(
                    r#"{"manifest_version":3,"id":"groups","name":"Groups","version":"1","permissions":["tabGroups"]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        shell
            .grant_extension_permission("groups", nomad_engine::ExtensionPermission::TabGroups)
            .unwrap();
        let first = shell.active_tab().unwrap();
        let second = shell.new_tab();
        let mut renderer = RecordingRenderer::default();
        let request = |id: &str, method: &str, arguments: serde_json::Value| ExtensionMessage {
            extension_id: "groups".into(),
            tab_id: None,
            payload: serde_json::json!({
                "__nomad_api_request": {"id": id, "method": method, "arguments": arguments}
            }),
        };

        shell
            .receive_extension_message_with_renderer(
                request(
                    "group",
                    "tabs.group",
                    serde_json::json!({"tabIds": [first.get(), second.get()]}),
                ),
                &mut renderer,
            )
            .unwrap();
        let group_id = renderer
            .extension_events
            .iter()
            .find_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::RuntimeResponse {
                    request_id,
                    result: Ok(value),
                } if request_id == "group" => value.as_u64(),
                _ => None,
            })
            .unwrap();
        assert_eq!(group_id, 1);

        shell
            .receive_extension_message_with_renderer(
                request(
                    "update",
                    "tabGroups.update",
                    serde_json::json!({
                        "groupId": group_id,
                        "updateProperties": {"title": "Work", "color": "blue", "collapsed": true}
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "update"
                && value["title"] == "Work"
                && value["color"] == "blue"
                && value["collapsed"] == true
        )));

        shell
            .receive_extension_message_with_renderer(
                request(
                    "query",
                    "tabGroups.query",
                    serde_json::json!({"title": "Work"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "query"
                && value.as_array().is_some_and(|groups| groups.len() == 1)
        )));

        shell
            .receive_extension_message_with_renderer(
                request(
                    "ungroup",
                    "tabs.ungroup",
                    serde_json::json!({"tabIds": [first.get(), second.get()]}),
                ),
                &mut renderer,
            )
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                request("empty", "tabGroups.query", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "empty" && value == &serde_json::json!([])
        )));
    }

    #[test]
    fn test_webextension_capture_visible_tab_responds_after_renderer_completion() {
        let mut shell = ShellState::new(runtime());
        shell
            .install_extension(
                nomad_engine::ExtensionManifest::from_json(
                    r#"{"manifest_version":3,"id":"capture","name":"Capture","version":"1","permissions":["tabs"],"host_permissions":["https://example.com/*"]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        shell
            .grant_extension_permission("capture", nomad_engine::ExtensionPermission::Tabs)
            .unwrap();
        shell
            .grant_extension_host_permission("capture", "https://example.com/*")
            .unwrap();
        shell.set_address_input("https://example.com/");
        shell.submit_address().unwrap();
        let tab_id = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();
        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "capture".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "shot",
                            "method": "tabs.captureVisibleTab",
                            "arguments": {"windowId": 1, "format": "png"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(renderer.screenshot_requests, vec![tab_id]);
        assert!(!renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse { request_id, .. }
                if request_id == "shot"
        )));

        renderer
            .screenshot_results
            .push((tab_id, Ok(vec![137, 80, 78, 71])));
        shell.poll_extension_screenshots(&mut renderer).unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "shot"
                && value.as_str().is_some_and(|value| value.starts_with("data:image/png;base64,"))
        )));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_tabs_and_windows_lifecycle_events() {
        let mut shell = ShellState::new(runtime());
        shell
            .install_extension(
                nomad_engine::ExtensionManifest::from_json(
                    r#"{"manifest_version":3,"id":"life","name":"Life","version":"1","permissions":["tabs","windows"],"host_permissions":["https://example.com/*"]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        for permission in [
            nomad_engine::ExtensionPermission::Tabs,
            nomad_engine::ExtensionPermission::Windows,
        ] {
            shell
                .grant_extension_permission("life", permission)
                .unwrap();
        }
        shell
            .grant_extension_host_permission("life", "https://example.com/*")
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let first_tab = shell.active_tab().unwrap();

        let mut renderer = RecordingRenderer::default();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "create",
                            "method": "windows.create",
                            "arguments": {"url": "https://example.com/", "active": false}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        let created = shell
            .tabs()
            .iter()
            .map(|tab| tab.id)
            .filter(|id| *id != first_tab)
            .collect::<Vec<_>>();
        assert_eq!(created.len(), 1);
        let created_tab = created[0];
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::WindowCreated { window }
                if window["tabs"].as_array().is_some_and(|tabs| {
                    tabs.iter().any(|tab| tab["id"] == serde_json::json!(created_tab.get()))
                })
        )));
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::TabCreated { tab }
                if tab["id"] == serde_json::json!(created_tab.get())
                    && tab["url"] == "https://example.com/"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "discard",
                            "method": "tabs.discard",
                            "arguments": {"tabId": created_tab.get()}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(matches!(
            shell.tab(created_tab).map(|tab| tab.lifecycle),
            Some(nomad_engine::TabLifecycle::Suspended)
        ));
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "discard"
                && value["discarded"] == serde_json::json!(true)
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "current",
                            "method": "tabs.getCurrent",
                            "arguments": {}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "current" && value == &serde_json::Value::Null
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: Some(first_tab.get()),
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "current-content",
                            "method": "tabs.getCurrent",
                            "arguments": {}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "current-content"
                && value["id"] == serde_json::json!(first_tab.get())
                && value["url"] == "https://example.com/"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "dup",
                            "method": "tabs.duplicate",
                            "arguments": {"tabId": first_tab.get()}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        let duplicated = shell
            .tabs()
            .iter()
            .map(|tab| tab.id)
            .filter(|id| *id != first_tab && *id != created_tab)
            .collect::<Vec<_>>();
        assert_eq!(duplicated.len(), 1);
        let duplicated_tab = duplicated[0];
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::TabCreated { tab }
                if tab["id"] == serde_json::json!(duplicated_tab.get())
        )));
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::TabActivated { tab_id, window_id }
                if *tab_id == duplicated_tab.get() && *window_id == 1
        )));
        assert_eq!(shell.active_tab(), Some(duplicated_tab));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "reload",
                            "method": "tabs.reload",
                            "arguments": {"tabId": duplicated_tab.get()}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::TabUpdated {
                tab_id,
                change_info,
                tab,
            } if *tab_id == duplicated_tab.get()
                && change_info["status"] == "loading"
                && tab["id"] == serde_json::json!(duplicated_tab.get())
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "update",
                            "method": "tabs.update",
                            "arguments": {
                                "tabId": duplicated_tab.get(),
                                "updateProperties": {"url": "https://example.com/docs"}
                            }
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::TabUpdated {
                tab_id,
                change_info,
                ..
            } if *tab_id == duplicated_tab.get()
                && change_info["url"] == "https://example.com/docs"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "back",
                            "method": "tabs.goBack",
                            "arguments": {"tabId": duplicated_tab.get()}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "back" && value == &serde_json::Value::Null
        )));
        assert_eq!(
            shell.tab(duplicated_tab).and_then(|tab| tab.url.as_ref()),
            Some(&url::Url::parse("https://example.com/").unwrap())
        );

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "forward",
                            "method": "tabs.goForward",
                            "arguments": {"tabId": duplicated_tab.get()}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "forward" && value == &serde_json::Value::Null
        )));
        assert_eq!(
            shell.tab(duplicated_tab).and_then(|tab| tab.url.as_ref()),
            Some(&url::Url::parse("https://example.com/docs").unwrap())
        );

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "focus",
                            "method": "windows.update",
                            "arguments": {
                                "windowId": 1,
                                "updateInfo": {"focused": true}
                            }
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::WindowFocusChanged { window_id }
                if *window_id == 1
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "remove",
                            "method": "tabs.remove",
                            "arguments": {"tabIds": [created_tab.get()]}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::TabRemoved { tab_id, window_id }
                if *tab_id == created_tab.get() && *window_id == 1
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "life".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "close-window",
                            "method": "windows.remove",
                            "arguments": {"windowId": 1}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::WindowRemoved { window_id }
                if *window_id == 1
        )));
        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::TabRemoved { tab_id, .. }
                if *tab_id == first_tab.get() || *tab_id == duplicated_tab.get()
        )));
        assert_eq!(shell.tabs().len(), 1);
        let replacement = &shell.tabs()[0];
        assert!(replacement.url.is_none());
        assert_ne!(replacement.id, first_tab);
        assert_ne!(replacement.id, duplicated_tab);
    }

    #[test]
    fn test_webextension_background_api_returns_permissioned_history() {
        let mut shell = ShellState::new(runtime());
        shell
            .install_extension(
                nomad_engine::ExtensionManifest::from_json(
                    r#"{"manifest_version":3,"id":"tool","name":"Tool","version":"1","permissions":["history"]}"#,
                )
            .unwrap(),
        )
        .unwrap();
        shell
            .grant_extension_permission("tool", nomad_engine::ExtensionPermission::History)
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();

        let mut renderer = RecordingRenderer::default();
        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "tool".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "1",
                            "method": "history.search",
                            "arguments": {"text": "example"}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(matches!(
            renderer.extension_events.as_slice(),
            [ExtensionEvent {
                kind: nomad_engine::ExtensionEventKind::RuntimeResponse {
                    request_id,
                    result: Ok(_),
                },
                ..
            }] if request_id == "1"
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_storage_areas_route_by_area_tag() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"store","name":"Store","version":"1","permissions":["storage","tabs"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "1;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "store",
                nomad_engine::ExtensionPermission::Storage,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "store",
                nomad_engine::ExtensionPermission::Tabs,
                &mut renderer,
            )
            .unwrap();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "store".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_storage_area": "sync",
                        "__nomad_storage_set": {"k": 1}
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "store".into(),
                    tab_id: Some(7),
                    payload: serde_json::json!({
                        "__nomad_storage_area": "session",
                        "__nomad_storage_set": {"k": 2}
                    }),
                },
                &mut renderer,
            )
            .unwrap();

        assert_eq!(
            shell
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .storage_get_area("store", nomad_engine::ExtensionStorageArea::Sync, "k")
                .unwrap(),
            Some(serde_json::json!(1))
        );
        assert_eq!(
            shell
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .storage_get_area("store", nomad_engine::ExtensionStorageArea::Session, "k")
                .unwrap(),
            Some(serde_json::json!(2))
        );
        assert_eq!(
            shell
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .storage_get_area("store", nomad_engine::ExtensionStorageArea::Local, "k")
                .unwrap(),
            None,
            "writes must land only in their tagged area"
        );

        let areas: Vec<String> = renderer
            .extension_events
            .iter()
            .filter_map(|event| {
                if let nomad_engine::ExtensionEventKind::StorageChanged { changes } = &event.kind {
                    changes
                        .get("__nomad_storage_area")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            areas,
            ["sync", "session"],
            "shims need the area tag to route"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_scripting_registers_updates_and_injects_css() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"scripting","name":"Scripting","version":"1","permissions":["scripting"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                [
                    ("background.js".into(), "1;".into()),
                    ("a.js".into(), "const a = 1;".into()),
                    ("theme.css".into(), "body { background: red; }".into()),
                ]
                .into_iter()
                .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "scripting",
                nomad_engine::ExtensionPermission::Scripting,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_host_permission_with_renderer(
                "scripting",
                "https://example.com/*",
                &mut renderer,
            )
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let tab_id = shell.active_tab().unwrap();
        renderer.frame_tree_events.push((
            tab_id,
            vec![
                (10, None, "https://example.com/".into()),
                (11, Some(10), "https://example.com/child-a".into()),
                (12, Some(10), "https://example.com/child-b".into()),
            ],
        ));

        let request =
            |method: &str, id: &str, arguments: serde_json::Value| nomad_engine::ExtensionMessage {
                extension_id: "scripting".into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {
                        "id": id,
                        "method": method,
                        "arguments": arguments,
                    }
                }),
            };
        let respond = |renderer: &RecordingRenderer, id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id,
                        result,
                    } = &event.kind
                    {
                        (request_id == id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                request(
                    "scripting.registerContentScripts",
                    "1",
                    serde_json::json!({"scripts": [
                        {"id": "first", "matches": ["https://example.com/*"], "js": ["a.js"], "css": ["theme.css"]}
                    ]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "1").is_ok());

        shell
            .receive_extension_message_with_renderer(
                request(
                    "scripting.getRegisteredContentScripts",
                    "2",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        let scripts = respond(&renderer, "2").unwrap();
        assert_eq!(scripts.as_array().unwrap().len(), 1);
        assert_eq!(scripts[0]["id"], serde_json::json!("first"));
        assert_eq!(
            scripts[0]["matches"][0],
            serde_json::json!("https://example.com/*")
        );
        assert_eq!(scripts[0]["js"][0], serde_json::json!("a.js"));
        assert_eq!(scripts[0]["css"][0], serde_json::json!("theme.css"));
        assert_eq!(scripts[0]["runAt"], serde_json::json!("document_idle"));
        assert_eq!(scripts[0]["world"], serde_json::json!("ISOLATED"));

        shell
            .receive_extension_message_with_renderer(
                request(
                    "scripting.updateContentScripts",
                    "3",
                    serde_json::json!({"scripts": [
                        {"id": "first", "matches": ["https://example.com/*"], "js": ["a.js"]}
                    ]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "3").is_ok());
        assert_eq!(
            shell
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .registered_content_scripts("scripting")[0]
                .css,
            Vec::<String>::new(),
            "update must replace the script wholesale"
        );

        shell
            .receive_extension_message_with_renderer(
                request(
                    "scripting.insertCSS",
                    "4",
                    serde_json::json!({"target": {"tabId": tab_id.get()}, "css": "body { color: blue; }"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "4").is_ok());
        shell
            .receive_extension_message_with_renderer(
                request(
                    "scripting.removeCSS",
                    "5",
                    serde_json::json!({"target": {"tabId": tab_id.get()}}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "5").is_ok());
        assert_eq!(
            renderer.css_operations,
            vec![
                (
                    tab_id,
                    "insert:scripting".into(),
                    "body { color: blue; }".into()
                ),
                (tab_id, "remove:scripting".into(), String::new())
            ]
        );

        shell
            .receive_extension_message_with_renderer(
                request(
                    "scripting.insertCSS",
                    "6",
                    serde_json::json!({"target": {"tabId": tab_id.get()}, "files": ["theme.css"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            renderer.css_operations.last().unwrap().2,
            "body { background: red; }",
            "files must resolve through extension resources"
        );

        for (method, id, arguments) in [
            (
                "scripting.executeScript",
                "8",
                serde_json::json!({"target": {"tabId": tab_id.get(), "frameIds": [2, 1]}, "code": "child();"}),
            ),
            (
                "scripting.insertCSS",
                "9",
                serde_json::json!({"target": {"tabId": tab_id.get(), "allFrames": true}, "css": "x{}"}),
            ),
            (
                "scripting.removeCSS",
                "10",
                serde_json::json!({"target": {"tabId": tab_id.get(), "frameIds": [2, 1]}, "css": "x{}"}),
            ),
        ] {
            shell
                .receive_extension_message_with_renderer(
                    request(method, id, arguments),
                    &mut renderer,
                )
                .unwrap();
            assert!(respond(&renderer, id).is_ok());
        }
        let targeted = &renderer.target_operations[renderer.target_operations.len() - 7..];
        assert_eq!(
            targeted
                .iter()
                .map(|(_, handle, _, _)| *handle)
                .collect::<Vec<_>>(),
            vec![
                Some(12),
                Some(11),
                None,
                Some(11),
                Some(12),
                Some(12),
                Some(11)
            ]
        );
        shell
            .receive_extension_message_with_renderer(
                request(
                    "scripting.unregisterContentScripts",
                    "7",
                    serde_json::json!({"ids": ["first"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "7").is_ok());
        assert!(shell
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .registered_content_scripts("scripting")
            .is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_notifications_get_all_and_events_dispatch() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, permissions) in [
            ("notifier", "notifications"),
            ("bystander", "notifications"),
            ("muted", "storage"),
        ] {
            shell
                .install_extension_package_with_renderer(
                    &format!(
                        r#"{{"manifest_version":3,"id":"{id}","name":"{id}","version":"1","permissions":["{permissions}"],"background":{{"service_worker":"background.js"}}}}"#
                    ),
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            shell
                .grant_extension_permission_with_renderer(
                    id,
                    nomad_engine::ExtensionPermission::Notifications,
                    &mut renderer,
                )
                .unwrap_or(());
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "notifier",
                    "1",
                    "notifications.create",
                    serde_json::json!({"id": "n1", "title": "Hello", "message": "World"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "1").unwrap(), serde_json::json!("n1"));

        shell
            .receive_extension_message_with_renderer(
                api(
                    "notifier",
                    "2",
                    "notifications.getAll",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        let all = respond(&renderer, "2").unwrap();
        assert_eq!(all.as_array().unwrap().len(), 1);
        assert_eq!(all[0]["id"], serde_json::json!("n1"));
        assert_eq!(all[0]["title"], serde_json::json!("Hello"));

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bystander",
                    "3",
                    "notifications.getAll",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "3").unwrap().as_array().unwrap().len(),
            0,
            "getAll must only list the calling extension's notifications"
        );

        shell
            .notify_extension_notification_clicked("n1", &mut renderer)
            .unwrap();
        shell
            .notify_extension_notification_button_clicked("n1", 1, &mut renderer)
            .unwrap();
        let clicked_ids: Vec<(&str, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::NotificationClicked { id }
                | nomad_engine::ExtensionEventKind::NotificationButtonClicked { id, .. } => {
                    Some((event.extension_id.as_str(), id.clone()))
                }
                _ => None,
            })
            .collect();
        let clicked_ids: Vec<(String, String)> = clicked_ids
            .into_iter()
            .map(|(extension_id, id)| (extension_id.to_owned(), id))
            .collect();
        let mut clicked_ids = clicked_ids;
        clicked_ids.sort();
        assert_eq!(
            clicked_ids,
            vec![
                ("bystander".to_owned(), "n1".to_owned()),
                ("bystander".to_owned(), "n1".to_owned()),
                ("notifier".to_owned(), "n1".to_owned()),
                ("notifier".to_owned(), "n1".to_owned())
            ],
            "click events must reach every enabled notifications extension, never muted ones"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "notifier",
                    "4",
                    "notifications.clear",
                    serde_json::json!({"id": "n1"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "4").unwrap(), serde_json::json!(true));
        let closed: Vec<(&str, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::NotificationClosed { id } => {
                    Some((event.extension_id.as_str(), id.clone()))
                }
                _ => None,
            })
            .collect();
        let closed: Vec<(String, String)> = closed
            .into_iter()
            .map(|(extension_id, id)| (extension_id.to_owned(), id))
            .collect();
        let mut closed = closed;
        closed.sort();
        assert_eq!(
            closed,
            vec![
                ("bystander".to_owned(), "n1".to_owned()),
                ("notifier".to_owned(), "n1".to_owned())
            ]
        );

        shell
            .receive_extension_message_with_renderer(
                api("muted", "5", "notifications.create", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "5").is_err(), "muted must be denied");
    }

    #[test]
    fn test_webextension_alarms_get_and_get_all() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"alarm","name":"Alarm","version":"1","permissions":["alarms"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "1;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "alarm",
                nomad_engine::ExtensionPermission::Alarms,
                &mut renderer,
            )
            .unwrap();
        let api = |request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: "alarm".into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        let default_before = shell
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_all_alarms("alarm")
            .unwrap()
            .len();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "1",
                    "alarms.create",
                    serde_json::json!({"name": "daily", "delayInMinutes": 60.0, "periodInMinutes": 60.0}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "1").unwrap(), serde_json::Value::Null);

        shell
            .receive_extension_message_with_renderer(
                api("2", "alarms.get", serde_json::json!({"name": "daily"})),
                &mut renderer,
            )
            .unwrap();
        let daily = respond(&renderer, "2").unwrap();
        assert_eq!(daily["name"], serde_json::json!("daily"));
        assert_eq!(daily["periodInMinutes"], serde_json::json!(60.0));
        assert!(daily["scheduledTime"].as_u64().unwrap() > 0);

        shell
            .receive_extension_message_with_renderer(
                api("3", "alarms.get", serde_json::json!({"name": "missing"})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "3").unwrap(), serde_json::Value::Null);

        shell
            .receive_extension_message_with_renderer(
                api("4", "alarms.getAll", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        let all = respond(&renderer, "4").unwrap();
        assert_eq!(all.as_array().unwrap().len(), default_before + 1);
        assert!(all
            .as_array()
            .unwrap()
            .iter()
            .any(|alarm| alarm["name"] == serde_json::json!("daily")));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_permissions_request_remove_and_events() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest) in [
            (
                "opt",
                r#"{"manifest_version":3,"id":"opt","name":"Opt","version":"1","permissions":["permissions"],"optional_permissions":["clipboard"],"optional_host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
            ),
            (
                "bystander",
                r#"{"manifest_version":3,"id":"bystander","name":"Bystander","version":"1","permissions":["permissions"],"background":{"service_worker":"background.js"}}"#,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            shell
                .grant_extension_permission_with_renderer(
                    id,
                    nomad_engine::ExtensionPermission::Permissions,
                    &mut renderer,
                )
                .unwrap();
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "opt",
                    "1",
                    "permissions.request",
                    serde_json::json!({"permissions": ["clipboard"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "1").unwrap(), serde_json::json!(true));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "opt",
                    "2",
                    "permissions.request",
                    serde_json::json!({"origins": ["https://example.com/*"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "2").unwrap(), serde_json::json!(true));
        shell
            .receive_extension_message_with_renderer(
                api("opt", "3", "permissions.getAll", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "3").unwrap(),
            serde_json::json!({
                "permissions": ["clipboard", "permissions"],
                "origins": ["https://example.com/*"]
            })
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "opt",
                    "4",
                    "permissions.contains",
                    serde_json::json!({"permissions": ["clipboard"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "4").unwrap(), serde_json::json!(true));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "opt",
                    "5",
                    "permissions.request",
                    serde_json::json!({"permissions": ["tabs"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "5").unwrap(),
            serde_json::json!(false),
            "non-optional permissions must be denied"
        );

        let added: Vec<(String, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::PermissionAdded { details } => {
                    Some((event.extension_id.clone(), details.to_string()))
                }
                _ => None,
            })
            .collect();
        let mut added = added;
        added.sort();
        let mut expected_added = vec![
            (
                "bystander".to_owned(),
                serde_json::json!({
                    "permissions": ["clipboard"],
                    "origins": []
                })
                .to_string(),
            ),
            (
                "bystander".to_owned(),
                serde_json::json!({
                    "permissions": [],
                    "origins": ["https://example.com/*"]
                })
                .to_string(),
            ),
            (
                "opt".to_owned(),
                serde_json::json!({
                    "permissions": ["clipboard"],
                    "origins": []
                })
                .to_string(),
            ),
            (
                "opt".to_owned(),
                serde_json::json!({
                    "permissions": [],
                    "origins": ["https://example.com/*"]
                })
                .to_string(),
            ),
        ];
        expected_added.sort();
        assert_eq!(
            added, expected_added,
            "onAdded must fire in every enabled extension with the granted details"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "opt",
                    "6",
                    "permissions.remove",
                    serde_json::json!({
                        "permissions": ["clipboard"],
                        "origins": ["https://example.com/*"]
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "6").unwrap(), serde_json::json!(true));
        shell
            .receive_extension_message_with_renderer(
                api("opt", "7", "permissions.getAll", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "7").unwrap(),
            serde_json::json!({"permissions": ["permissions"], "origins": []}),
            "removed permissions must no longer be granted"
        );
        let removed: Vec<(String, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::PermissionRemoved { details } => {
                    Some((event.extension_id.clone(), details.to_string()))
                }
                _ => None,
            })
            .collect();
        let mut removed = removed;
        removed.sort();
        let mut expected_removed = vec![
            (
                "bystander".to_owned(),
                serde_json::json!({
                    "permissions": ["clipboard"],
                    "origins": ["https://example.com/*"]
                })
                .to_string(),
            ),
            (
                "opt".to_owned(),
                serde_json::json!({
                    "permissions": ["clipboard"],
                    "origins": ["https://example.com/*"]
                })
                .to_string(),
            ),
        ];
        expected_removed.sort();
        assert_eq!(
            removed, expected_removed,
            "onRemoved must fire in every enabled extension with the revoked details"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_cookies_on_changed_dispatch() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest) in [
            (
                "cook",
                r#"{"manifest_version":3,"id":"cook","name":"Cook","version":"1","permissions":["cookies"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
            ),
            (
                "witness",
                r#"{"manifest_version":3,"id":"witness","name":"Witness","version":"1","permissions":["cookies"],"background":{"service_worker":"background.js"}}"#,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","background":{"service_worker":"background.js"}}"#,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            shell
                .grant_extension_permission_with_renderer(
                    id,
                    nomad_engine::ExtensionPermission::Cookies,
                    &mut renderer,
                )
                .unwrap_or(());
            shell
                .grant_extension_host_permission_with_renderer(
                    id,
                    "https://example.com/*",
                    &mut renderer,
                )
                .unwrap_or(());
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "cook",
                    "1",
                    "cookies.set",
                    serde_json::json!({"url": "https://example.com/", "name": "sid", "value": "abc"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "1").unwrap()["name"],
            serde_json::json!("sid")
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "cook",
                    "2",
                    "cookies.remove",
                    serde_json::json!({"url": "https://example.com/", "name": "sid"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "2").unwrap()["name"],
            serde_json::json!("sid")
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "cook",
                    "3",
                    "cookies.remove",
                    serde_json::json!({"url": "https://example.com/", "name": "missing"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "3").unwrap(), serde_json::Value::Null);

        let changes: Vec<(String, String, bool)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::CookieChanged {
                    cookie,
                    cause,
                    removed,
                } => Some((
                    event.extension_id.clone(),
                    format!(
                        "{}:{}",
                        cookie["name"].as_str().unwrap_or_default(),
                        cause.as_str().unwrap_or_default()
                    ),
                    *removed,
                )),
                _ => None,
            })
            .collect();
        let mut changes = changes;
        changes.sort();
        assert_eq!(
            changes,
            vec![
                ("cook".to_owned(), "sid:explicit".to_owned(), false),
                ("cook".to_owned(), "sid:explicit".to_owned(), true),
                ("witness".to_owned(), "sid:explicit".to_owned(), false),
                ("witness".to_owned(), "sid:explicit".to_owned(), true)
            ],
            "onChanged must reach every enabled cookies extension for set and remove,              never extensions without the permission, and never for a missing cookie"
        );

        let changed_cookie = renderer
            .extension_events
            .iter()
            .find_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::CookieChanged {
                    cookie,
                    removed: false,
                    ..
                } => Some(cookie.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            changed_cookie["storeId"],
            serde_json::json!("0"),
            "cookie change details must carry the Chromium storeId field"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_action_setters_getters() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"act","name":"Act","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"},"action":{"default_title":"Tool","default_popup":"popup.html"}}"#,
                [("background.js".into(), "1;".into()), ("popup.html".into(), "<b>x</b>".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"quiet","name":"Quiet","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "1;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api("act", "1", "action.getBadgeText", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "1").unwrap(), serde_json::json!(""));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "2",
                    "action.setBadgeText",
                    serde_json::json!({"text": "9"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "2").is_ok());
        shell
            .receive_extension_message_with_renderer(
                api("act", "3", "action.getBadgeText", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "3").unwrap(), serde_json::json!("9"));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "4",
                    "action.setBadgeText",
                    serde_json::json!({"text": null}),
                ),
                &mut renderer,
            )
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                api("act", "5", "action.getBadgeText", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "5").unwrap(),
            serde_json::json!(""),
            "clearing the badge text must restore the empty default"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "21",
                    "action.setIcon",
                    serde_json::json!({"path": "icons/active.png"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "21").is_ok());

        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "6",
                    "action.setBadgeBackgroundColor",
                    serde_json::json!({"color": "#ff0000"}),
                ),
                &mut renderer,
            )
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "7",
                    "action.getBadgeBackgroundColor",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "7").unwrap(),
            serde_json::json!("#ff0000")
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "8",
                    "action.getBadgeTextColor",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "8").unwrap(),
            serde_json::json!("#ffffff"),
            "unset badge text color must default to white"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "9",
                    "action.setBadgeTextColor",
                    serde_json::json!({"color": "#000000"}),
                ),
                &mut renderer,
            )
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "10",
                    "action.getBadgeTextColor",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "10").unwrap(),
            serde_json::json!("#000000")
        );

        shell
            .receive_extension_message_with_renderer(
                api("act", "11", "action.getTitle", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "11").unwrap(),
            serde_json::json!("Tool"),
            "getTitle must fall back to the manifest default_title"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "12",
                    "action.setTitle",
                    serde_json::json!({"title": "Renamed"}),
                ),
                &mut renderer,
            )
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                api("act", "13", "action.getTitle", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "13").unwrap(),
            serde_json::json!("Renamed")
        );

        shell
            .receive_extension_message_with_renderer(
                api("act", "14", "action.getPopup", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "14").unwrap(),
            serde_json::json!("popup.html"),
            "getPopup must fall back to the manifest default_popup"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "15",
                    "action.setPopup",
                    serde_json::json!({"popup": "other.html"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "15").is_ok());
        shell
            .receive_extension_message_with_renderer(
                api("act", "16", "action.getPopup", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "16").unwrap(),
            serde_json::json!("other.html")
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "act",
                    "17",
                    "action.setPopup",
                    serde_json::json!({"popup": ""}),
                ),
                &mut renderer,
            )
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                api("act", "18", "action.getPopup", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "18").unwrap(),
            serde_json::json!(""),
            "an empty popup must disable the popup entirely"
        );

        assert!(shell
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .action_is_enabled("act"));
        shell
            .receive_extension_message_with_renderer(
                api("act", "19", "action.disable", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "19").is_ok());
        assert!(!shell
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .action_is_enabled("act"));
        shell
            .receive_extension_message_with_renderer(
                api("act", "20", "action.enable", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "20").is_ok());
        assert!(shell
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .action_is_enabled("act"));

        assert_eq!(
            shell
                .extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .action_get_title("quiet"),
            None,
            "an extension without a declared action must report no title"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_declarative_net_request_remaining_apis() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest, dnr) in [
            (
                "rules",
                r#"{"manifest_version":3,"id":"rules","name":"Rules","version":"1","permissions":["declarativeNetRequest"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                false,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            if dnr {
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::DeclarativeNetRequest,
                        &mut renderer,
                    )
                    .unwrap();
            }
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "1",
                    "declarativeNetRequest.isSessionEnabled",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "1").unwrap(),
            serde_json::json!(true),
            "session rules are always active"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "2",
                    "declarativeNetRequest.getEnabledRulesets",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "2").unwrap(),
            serde_json::json!([]),
            "no static rulesets are loaded"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "3",
                    "declarativeNetRequest.updateEnabledRulesets",
                    serde_json::json!({"enableRulesetIds": [], "disableRulesetIds": []}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "3").is_ok());
        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "4",
                    "declarativeNetRequest.updateEnabledRulesets",
                    serde_json::json!({"enableRulesetIds": ["blocklist"], "disableRulesetIds": []}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "4").is_err(),
            "enabling an unknown static ruleset must fail"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "5",
                    "declarativeNetRequest.isRegexSupported",
                    serde_json::json!({"regex": "^https://[a-z]+\\.example/.*$"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let supported = respond(&renderer, "5").unwrap();
        assert_eq!(supported["isSupported"], true);
        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "6",
                    "declarativeNetRequest.isRegexSupported",
                    serde_json::json!({"regex": "^(?=.*secret).*$"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let lookahead = respond(&renderer, "6").unwrap();
        assert_eq!(lookahead["isSupported"], false);
        assert_eq!(lookahead["reason"], "syntaxError");

        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "7",
                    "declarativeNetRequest.setExtensionActionOptions",
                    serde_json::json!({"options": {"displayActionCountAsBadgeText": true}}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "7").is_ok());
        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "8",
                    "declarativeNetRequest.setExtensionActionOptions",
                    serde_json::json!({"options": {"displayActionCountAsBadgeText": "yes"}}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "8").is_err());

        shell
            .receive_extension_message_with_renderer(
                api(
                    "deaf",
                    "9",
                    "declarativeNetRequest.isSessionEnabled",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "9").is_err());

        shell
            .receive_extension_message_with_renderer(
                api(
                    "rules",
                    "10",
                    "declarativeNetRequest.updateDynamicRules",
                    serde_json::json!({
                        "addRules": [{
                            "id": 7,
                            "action": {"type": "block"},
                            "condition": {"requestDomains": ["ads.example"]}
                        }]
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "10").is_ok());

        let matched_before = renderer
            .extension_events
            .iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    nomad_engine::ExtensionEventKind::RuleMatched { .. }
                )
            })
            .count();
        shell.set_address_input("https://ads.example/banner");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let matched = renderer
            .extension_events
            .iter()
            .skip(matched_before)
            .filter(|event| {
                matches!(
                    event.kind,
                    nomad_engine::ExtensionEventKind::RuleMatched { .. }
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matched.len(),
            1,
            "onRuleMatched must fire for a matching rule"
        );
        if let nomad_engine::ExtensionEventKind::RuleMatched { details } = &matched[0].kind {
            assert_eq!(details["request"]["url"], "https://ads.example/banner");
            assert_eq!(details["rule"]["ruleId"], 7);
        } else {
            unreachable!();
        }
        assert!(
            renderer
                .blocking_patterns
                .iter()
                .any(|pattern| pattern == "*://ads.example/*"),
            "the dynamic block rule must surface as a renderer blocking pattern"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_web_request_lifecycle_and_blocking() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest, blocking, host) in [
            (
                "blk",
                r#"{"manifest_version":3,"id":"blk","name":"Blk","version":"1","permissions":["tabs","webRequest","webRequestBlocking"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                true,
                true,
            ),
            (
                "witness",
                r#"{"manifest_version":3,"id":"witness","name":"Witness","version":"1","permissions":["tabs","webRequest"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                false,
                true,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                false,
                false,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            if blocking {
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::Tabs,
                        &mut renderer,
                    )
                    .unwrap();
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::WebRequest,
                        &mut renderer,
                    )
                    .unwrap();
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::WebRequestBlocking,
                        &mut renderer,
                    )
                    .unwrap();
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::WebRequest,
                        &mut renderer,
                    )
                    .unwrap();
            }
            if host {
                shell
                    .grant_extension_host_permission_with_renderer(
                        id,
                        "https://example.com/*",
                        &mut renderer,
                    )
                    .unwrap();
            }
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };
        let received_web_requests = |renderer: &RecordingRenderer, id: &str| {
            renderer
                .extension_events
                .iter()
                .filter_map(|event| {
                    if event.extension_id == id {
                        if let nomad_engine::ExtensionEventKind::WebRequest { request, event } =
                            &event.kind
                        {
                            Some((*event, request.clone()))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };

        shell
            .dispatch_network_request_to_extensions(
                &nomad_engine::NetworkRequestRecord {
                    method: "GET".into(),
                    url: "https://example.com/page".into(),
                    status: Some(200),
                    duration_ms: Some(12),
                    failed: false,
                    request_headers: vec![("X-Trace".into(), "abc".into())],
                    response_headers: vec![("content-type".into(), "text/html".into())],
                    request_body_size: None,
                    request_body_unavailable: false,
                },
                &mut renderer,
            )
            .unwrap();
        let blk_events = received_web_requests(&renderer, "blk");
        let events = blk_events
            .iter()
            .map(|(event, _)| *event)
            .collect::<Vec<_>>();
        assert_eq!(
            events,
            vec![
                "web_request",
                "web_request_headers_received",
                "web_request_completed",
            ],
            "a successful request must deliver onBeforeRequest, onHeadersReceived and onCompleted"
        );
        for (event, request) in &blk_events {
            assert_eq!(request["url"], "https://example.com/page");
            assert_eq!(request["method"], "GET");
            if *event == "web_request" {
                assert_eq!(request["duration_ms"], 12);
                assert_eq!(request["failed"], false);
            }
            if *event == "web_request_completed" {
                assert_eq!(request["status"], 200);
            }
        }
        assert_eq!(
            received_web_requests(&renderer, "deaf"),
            vec![],
            "extensions without the webRequest permission must not receive request events"
        );

        let events_before_failed = received_web_requests(&renderer, "blk").len();
        shell
            .dispatch_network_request_to_extensions(
                &nomad_engine::NetworkRequestRecord {
                    method: "POST".into(),
                    url: "https://example.com/failing".into(),
                    status: None,
                    duration_ms: Some(3),
                    failed: true,
                    request_headers: Vec::new(),
                    response_headers: Vec::new(),
                    request_body_size: None,
                    request_body_unavailable: false,
                },
                &mut renderer,
            )
            .unwrap();
        let blk_events = received_web_requests(&renderer, "blk");
        assert_eq!(
            blk_events
                .iter()
                .skip(events_before_failed)
                .map(|(event, _)| *event)
                .collect::<Vec<_>>(),
            vec!["web_request", "web_request_error"],
            "a failed request must deliver onBeforeRequest and onErrorOccurred only"
        );

        let tab_count = shell.tabs().len();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "witness",
                    "1",
                    "webRequest.handlerBehaviorChanged",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "1").is_err(),
            "handlerBehaviorChanged requires webRequestBlocking"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "blk",
                    "2",
                    "webRequest.handlerBehaviorChanged",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "2").is_ok(),
            "handlerBehaviorChanged must resolve for extensions holding webRequestBlocking"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "blk",
                    "3",
                    "webRequest.resolveBlocking",
                    serde_json::json!({
                        "url": "https://example.com/blocked",
                        "method": "GET",
                        "cancel": true,
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "3").is_ok());
        let created = shell.tabs().len();
        let blocked = shell.execute_extension_tabs_create(
            "blk",
            &nomad_engine::ExtensionApiRequest {
                request_id: "4".into(),
                method: "tabs.create".into(),
                arguments: serde_json::json!({"url": "https://example.com/blocked"}),
            },
            &mut renderer,
        );
        assert!(
            matches!(
                blocked,
                Err(ShellError::Navigation(
                    nomad_engine::NavigationError::BlockedByWebRequest(url)
                )) if url == "https://example.com/blocked"
            ),
            "a cancelled navigation must surface BlockedByWebRequest"
        );
        assert_eq!(
            shell.tabs().len(),
            created,
            "no tab must be created when a blocking listener cancelled the navigation"
        );
        assert_eq!(
            shell.tabs().len() - tab_count,
            0,
            "cancelled navigation must not leave a tab behind"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "blk",
                    "5",
                    "webRequest.resolveBlocking",
                    serde_json::json!({
                        "url": "https://example.com/redirected",
                        "method": "GET",
                        "redirectUrl": "https://example.com/target",
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(respond(&renderer, "5").is_ok());
        shell
            .execute_extension_tabs_create(
                "blk",
                &nomad_engine::ExtensionApiRequest {
                    request_id: "6".into(),
                    method: "tabs.create".into(),
                    arguments: serde_json::json!({"url": "https://example.com/redirected"}),
                },
                &mut renderer,
            )
            .unwrap();
        let redirected = shell
            .tabs()
            .last()
            .and_then(|tab| tab.url.as_ref())
            .map(ToString::to_string);
        assert_eq!(
            redirected.as_deref(),
            Some("https://example.com/target"),
            "a redirectUrl decision must send the navigation to the redirect target"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "witness",
                    "7",
                    "webRequest.resolveBlocking",
                    serde_json::json!({
                        "url": "https://example.com/any",
                        "cancel": true,
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "7").is_err(),
            "resolveBlocking without webRequestBlocking must be denied"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_identity_browser_account_fallback() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest, permission) in [
            (
                "id",
                r#"{"manifest_version":3,"id":"id","name":"ID","version":"1","permissions":["identity"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                false,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            if permission {
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::Identity,
                        &mut renderer,
                    )
                    .unwrap();
            }
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        // Without an `oauth2` manifest section the browser profile account
        // token remains the getAuthToken source, per the legacy contract.
        shell
            .receive_extension_message_with_renderer(
                api(
                    "id",
                    "1",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "1").is_err(),
            "getAuthToken without an account token must reject like Chromium's Not authorized"
        );

        shell.set_identity_account_token(Some("oauth-token-123".into()));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "id",
                    "2",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": true}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "2").unwrap(),
            serde_json::json!("oauth-token-123"),
            "getAuthToken must return the configured identity account token"
        );
        shell.set_identity_account_token(None);
        shell
            .receive_extension_message_with_renderer(
                api(
                    "id",
                    "3",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "3").is_err(),
            "clearing the account token must restore the Not authorized rejection"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "id",
                    "4",
                    "identity.launchWebAuthFlow",
                    serde_json::json!({"url": "ftp://accounts.example.com/x"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "4").is_err(),
            "launchWebAuthFlow must reject non-http(s) urls"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "deaf",
                    "5",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "5").is_err(),
            "extensions without the identity permission must be denied"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "deaf",
                    "6",
                    "identity.launchWebAuthFlow",
                    serde_json::json!({"url": "https://accounts.example.com/a"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "6").is_err(),
            "launchWebAuthFlow must also be permission-gated"
        );
    }

    #[test]
    fn test_webextension_browser_account_sign_in_changed_event() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"id","name":"ID","version":"1","permissions":["identity"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "1;".into())].into_iter().collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "id",
                nomad_engine::ExtensionPermission::Identity,
                &mut renderer,
            )
            .unwrap();

        shell
            .set_identity_account_token_with_renderer(Some("oauth-token-123".into()), &mut renderer)
            .unwrap();
        assert!(
            renderer.extension_events.iter().any(|event| {
                event.extension_id == "id"
                    && matches!(
                        &event.kind,
                        nomad_engine::ExtensionEventKind::IdentitySignInChanged {
                            signed_in: true,
                            ..
                        }
                    )
            }),
            "browser sign-in must dispatch onSignInChanged to identity extensions"
        );
        shell
            .set_identity_account_token_with_renderer(None, &mut renderer)
            .unwrap();
        assert!(
            renderer.extension_events.iter().any(|event| {
                event.extension_id == "id"
                    && matches!(
                        &event.kind,
                        nomad_engine::ExtensionEventKind::IdentitySignInChanged {
                            signed_in: false,
                            ..
                        }
                    )
            }),
            "browser sign-out must dispatch onSignInChanged with signed_in false"
        );
    }

    /// Deterministic token-endpoint stand-in: logs every request and serves
    /// pre-programmed responses so error paths run without network access.
    #[derive(Default)]
    struct MockTokenExchange {
        requests: std::sync::Mutex<Vec<(String, String)>>,
        responses:
            std::sync::Mutex<std::collections::VecDeque<Result<OAuthTokenRecord, OAuthFlowError>>>,
    }

    impl nomad_engine::TokenExchange for MockTokenExchange {
        fn exchange(
            &self,
            request: &TokenExchangeRequest,
        ) -> Result<OAuthTokenRecord, OAuthFlowError> {
            self.requests
                .lock()
                .unwrap()
                .push((request.token_endpoint.to_string(), request.body.clone()));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected token exchange")
        }
    }

    fn record(access_token: &str, refresh_token: Option<&str>, account: &str) -> OAuthTokenRecord {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis();
        let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);
        OAuthTokenRecord {
            access_token: access_token.to_owned(),
            refresh_token: refresh_token.map(str::to_owned),
            expires_at_ms: now_ms + 3_600_000,
            scopes: vec!["openid".into()],
            account_id: Some(account.to_owned()),
            stored_at_ms: now_ms,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_oauth_provider_sign_in_flow() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"prov","name":"Prov","version":"1",
                    "permissions":["identity","tabs"],"host_permissions":["https://*/*"],
                    "oauth2":{"client_id":"client-123","scopes":["openid"]},
                    "background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "1;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "prov",
                nomad_engine::ExtensionPermission::Identity,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "prov",
                nomad_engine::ExtensionPermission::Tabs,
                &mut renderer,
            )
            .unwrap();

        let exchange = std::sync::Arc::new(MockTokenExchange::default());
        shell.set_oauth_token_exchange(exchange.clone());

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };
        let flow_tab_of = |renderer: &RecordingRenderer, index: usize| {
            renderer
                .extension_events
                .iter()
                .filter_map(|event| {
                    if let nomad_engine::ExtensionEventKind::TabCreated { tab } = &event.kind {
                        tab["id"].as_u64()
                    } else {
                        None
                    }
                })
                .nth(index)
                .unwrap()
        };

        // Non-interactive without a stored grant must reject.
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "1",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "1").is_err(),
            "non-interactive getAuthToken without a grant must reject"
        );

        // Interactive starts a real provider flow: a tab navigates to the
        // authorize endpoint with client_id, PKCE challenge, state, and the
        // extension redirect.
        exchange
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(record("at-1", Some("rt-1"), "acct-7")));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "2",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": true}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            !renderer.extension_events.iter().any(|event| matches!(
                &event.kind,
                nomad_engine::ExtensionEventKind::RuntimeResponse { request_id, .. }
                if request_id == "2"
            )),
            "interactive getAuthToken must defer its response until the redirect"
        );
        let flow_tab = TabId::new(flow_tab_of(&renderer, 0));
        let auth_url = shell
            .tab(flow_tab)
            .unwrap()
            .url
            .clone()
            .unwrap()
            .to_string();
        assert!(
            auth_url.starts_with(nomad_engine::GOOGLE_OAUTH_AUTH_ENDPOINT),
            "authorize URL must target the provider authorize endpoint: {auth_url}"
        );
        for fragment in [
            "client_id=client-123",
            "response_type=code",
            "scope=openid",
            "code_challenge=",
            "state=",
            "redirect_uri=https%3A%2F%2Fprov.chromiumapp.org%2F",
        ] {
            assert!(
                auth_url.contains(fragment),
                "authorize URL must contain {fragment}: {auth_url}"
            );
        }

        // The provider redirect completes the flow through real navigation.
        let redirect_url = "https://prov.chromiumapp.org/?code=abc".to_owned();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "3",
                    "tabs.update",
                    serde_json::json!({"tabId": flow_tab.get(), "updateProperties": {"url": redirect_url}}),
                ),
                &mut renderer,
            )
            .unwrap();
        let requests = exchange.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "the redirect must trigger exactly one token exchange"
        );
        for fragment in [
            "grant_type=authorization_code",
            "code=abc",
            "client_id=client-123",
            "code_verifier=",
            "redirect_uri=https%3A%2F%2Fprov.chromiumapp.org%2F",
        ] {
            assert!(
                requests[0].1.contains(fragment),
                "exchange body must contain {fragment}: {}",
                requests[0].1
            );
        }
        drop(requests);
        assert_eq!(
            respond(&renderer, "2").unwrap(),
            serde_json::json!("at-1"),
            "the deferred getAuthToken must resolve with the exchanged access token"
        );
        assert!(
            renderer.extension_events.iter().any(|event| {
                event.extension_id == "prov"
                    && matches!(
                        &event.kind,
                        nomad_engine::ExtensionEventKind::IdentitySignInChanged {
                            signed_in: true,
                            account
                        } if account["id"] == serde_json::json!("acct-7")
                    )
            }),
            "sign-in must dispatch onSignInChanged with the account id"
        );
        assert!(
            shell.tab(flow_tab).is_none(),
            "the flow tab must close once the flow completes"
        );

        // A cached, unexpired grant answers non-interactive requests without
        // touching the provider.
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "4",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "4").unwrap(),
            serde_json::json!("at-1"),
            "cached grants must be served without an exchange"
        );

        // An expired grant silently refreshes through the token endpoint.
        let key = nomad_engine::token_key("prov", "client-123", &[String::from("openid")]);
        let mut expired = record("at-1", Some("rt-1"), "acct-7");
        expired.expires_at_ms = 1;
        shell
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .store_oauth_token(key, expired);
        exchange
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(record("at-2", Some("rt-2"), "acct-7")));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "5",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "5").unwrap(),
            serde_json::json!("at-2"),
            "expired grants must refresh through the token endpoint"
        );
        {
            let requests = exchange.requests.lock().unwrap();
            assert!(
                requests[1].1.contains("grant_type=refresh_token")
                    && requests[1].1.contains("refresh_token=rt-1")
                    && requests[1].1.contains("client_id=client-123"),
                "refresh body must carry grant_type, refresh_token, and client_id: {}",
                requests[1].1
            );
        }
        assert_eq!(
            renderer
                .extension_events
                .iter()
                .filter(|event| {
                    event.extension_id == "prov"
                        && matches!(
                            &event.kind,
                            nomad_engine::ExtensionEventKind::IdentitySignInChanged { .. }
                        )
                })
                .count(),
            1,
            "refreshing an unchanged account must not re-dispatch onSignInChanged"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_oauth_provider_error_paths() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"prov","name":"Prov","version":"1",
                    "permissions":["identity","tabs"],"host_permissions":["https://*/*"],
                    "oauth2":{"client_id":"client-123","scopes":["openid"]},
                    "background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "1;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "prov",
                nomad_engine::ExtensionPermission::Identity,
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "prov",
                nomad_engine::ExtensionPermission::Tabs,
                &mut renderer,
            )
            .unwrap();

        let exchange = std::sync::Arc::new(MockTokenExchange::default());
        shell.set_oauth_token_exchange(exchange.clone());

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };
        let flow_tab_of = |renderer: &RecordingRenderer, index: usize| {
            renderer
                .extension_events
                .iter()
                .filter_map(|event| {
                    if let nomad_engine::ExtensionEventKind::TabCreated { tab } = &event.kind {
                        tab["id"].as_u64()
                    } else {
                        None
                    }
                })
                .nth(index)
                .unwrap()
        };

        // User denial: the provider redirects back with an error parameter.
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "1",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": true}),
                ),
                &mut renderer,
            )
            .unwrap();
        let flow_tab = TabId::new(flow_tab_of(&renderer, 0));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "2",
                    "tabs.update",
                    serde_json::json!({"tabId": flow_tab.get(), "updateProperties": {"url": "https://prov.chromiumapp.org/?error=access_denied"}}),
                ),
                &mut renderer,
            )
            .unwrap();
        let denial = respond(&renderer, "1").unwrap_err();
        assert!(
            denial.contains("access_denied"),
            "user denial must surface the provider error: {denial}"
        );
        assert!(
            !exchange
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(_, body)| body.contains("grant_type=authorization_code")),
            "a denied flow must never reach the token endpoint"
        );

        // Provider rejects the client at the token endpoint: no token is
        // stored and the error surfaces through runtime.lastError.
        exchange
            .responses
            .lock()
            .unwrap()
            .push_back(Err(nomad_engine::OAuthFlowError::InvalidClient));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "3",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": true}),
                ),
                &mut renderer,
            )
            .unwrap();
        let flow_tab = TabId::new(flow_tab_of(&renderer, 1));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "4",
                    "tabs.update",
                    serde_json::json!({"tabId": flow_tab.get(), "updateProperties": {"url": "https://prov.chromiumapp.org/?code=zz"}}),
                ),
                &mut renderer,
            )
            .unwrap();
        let failure = respond(&renderer, "3").unwrap_err();
        assert!(
            failure.contains("invalid_client"),
            "token endpoint failures must surface: {failure}"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "5",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "5").is_err(),
            "failed exchanges must not leave a usable token behind"
        );

        // Expired refresh grants restart the interactive flow instead of
        // returning a dead token.
        let key = nomad_engine::token_key("prov", "client-123", &[String::from("openid")]);
        let mut dead = record("at-1", Some("rt-dead"), "acct-7");
        dead.expires_at_ms = 1;
        shell
            .extensions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .store_oauth_token(key, dead);
        exchange
            .responses
            .lock()
            .unwrap()
            .push_back(Err(nomad_engine::OAuthFlowError::InvalidGrant));
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "6",
                    "identity.getAuthToken",
                    serde_json::json!({"interactive": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        let rejection = respond(&renderer, "6").unwrap_err();
        assert!(
            rejection.contains("user interaction"),
            "an expired refresh token must require interactive sign-in: {rejection}"
        );

        // launchWebAuthFlow resolves through the same navigation machinery
        // and honors an explicit redirect_uri.
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "7",
                    "identity.launchWebAuthFlow",
                    serde_json::json!({"url": "https://accounts.example.com/authorize?client_id=c&redirect_uri=https://cb.example.com/done"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let flow_tab = TabId::new(flow_tab_of(&renderer, 2));
        let auth_url = shell
            .tab(flow_tab)
            .unwrap()
            .url
            .clone()
            .unwrap()
            .to_string();
        assert!(
            auth_url.starts_with("https://accounts.example.com/authorize"),
            "launchWebAuthFlow must navigate to the requested authorize URL: {auth_url}"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "prov",
                    "8",
                    "tabs.update",
                    serde_json::json!({"tabId": flow_tab.get(), "updateProperties": {"url": "https://cb.example.com/done?code=xyz"}}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "7").unwrap(),
            serde_json::json!({"responseUrl": "https://cb.example.com/done?code=xyz"}),
            "launchWebAuthFlow must resolve with the redirect URL"
        );
        assert!(
            shell.tab(flow_tab).is_none(),
            "the launchWebAuthFlow tab must close once the flow completes"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_web_navigation_lifecycle_events() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest, permission) in [
            (
                "nav",
                r#"{"manifest_version":3,"id":"nav","name":"Nav","version":"1","permissions":["webNavigation","tabs"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "witness",
                r#"{"manifest_version":3,"id":"witness","name":"Witness","version":"1","permissions":["webNavigation","tabs"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                false,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            if permission {
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::WebNavigation,
                        &mut renderer,
                    )
                    .unwrap();
                shell
                    .grant_extension_host_permission_with_renderer(
                        id,
                        "https://example.com/*",
                        &mut renderer,
                    )
                    .unwrap();
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::Tabs,
                        &mut renderer,
                    )
                    .unwrap();
            }
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let navigation_events = |renderer: &RecordingRenderer| {
            let mut events: Vec<(String, String, String)> = renderer
                .extension_events
                .iter()
                .filter_map(|event| match &event.kind {
                    nomad_engine::ExtensionEventKind::WebNavigation {
                        event: event_name,
                        details,
                    } => Some((
                        event.extension_id.clone(),
                        event_name.clone(),
                        details["url"].as_str().unwrap_or_default().to_owned(),
                    )),
                    _ => None,
                })
                .collect();
            events.sort();
            events
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "nav",
                    "1",
                    "tabs.create",
                    serde_json::json!({"url": "https://example.com/lifecycle"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let events = navigation_events(&renderer);
        let nav_events: Vec<String> = events
            .iter()
            .filter(|(extension_id, _, _)| extension_id == "nav")
            .map(|(_, event, _)| event.clone())
            .collect();
        assert!(
            nav_events.iter().any(|event| event == "onBeforeNavigate"),
            "tabs.create must dispatch onBeforeNavigate"
        );
        assert!(
            nav_events.iter().any(|event| event == "onCommitted"),
            "tabs.create must dispatch onCommitted"
        );
        assert!(
            nav_events.iter().any(|event| event == "onDOMContentLoaded"),
            "tabs.create must dispatch onDOMContentLoaded"
        );
        assert!(
            nav_events.iter().any(|event| event == "onCompleted"),
            "tabs.create must dispatch onCompleted"
        );
        assert!(
            nav_events
                .iter()
                .all(|event| event != "onHistoryStateUpdated"),
            "a new-tab navigation must not dispatch onHistoryStateUpdated"
        );
        assert_eq!(
            nav_events
                .iter()
                .filter(|event| *event == "onBeforeNavigate")
                .count(),
            1,
            "onBeforeNavigate must fire exactly once per navigation"
        );
        let before_position = nav_events
            .iter()
            .position(|event| event == "onBeforeNavigate")
            .unwrap();
        let committed_position = nav_events
            .iter()
            .position(|event| event == "onCommitted")
            .unwrap();
        assert!(
            before_position < committed_position,
            "onBeforeNavigate must precede onCommitted"
        );
        let witness_events: Vec<_> = events
            .iter()
            .filter(|(extension_id, _, _)| extension_id == "witness")
            .collect();
        assert_eq!(
            witness_events.len(),
            nav_events.len(),
            "every enabled webNavigation extension must receive the same lifecycle"
        );
        assert!(
            !events
                .iter()
                .any(|(extension_id, _, _)| extension_id == "deaf"),
            "extensions without the webNavigation permission must receive nothing"
        );
        let tab_id = shell
            .tabs()
            .iter()
            .find(|tab| tab.url.as_ref().map(Url::as_str) == Some("https://example.com/lifecycle"))
            .map(|tab| tab.id)
            .expect("the created tab must have committed the lifecycle URL");
        let previous_url = shell.tab(tab_id).and_then(|tab| tab.url.clone());
        shell
            .receive_extension_message_with_renderer(
                api(
                    "nav",
                    "2",
                    "tabs.update",
                    serde_json::json!({
                        "tabId": tab_id.get(),
                        "updateProperties": {"url": "https://example.com/lifecycle"},
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        let events = navigation_events(&renderer);
        let nav_events: Vec<String> = events
            .iter()
            .filter(|(extension_id, _, _)| extension_id == "nav")
            .map(|(_, event, _)| event.clone())
            .collect();
        assert!(
            nav_events
                .iter()
                .any(|event| event == "onHistoryStateUpdated"),
            "navigating to the same committed URL must dispatch onHistoryStateUpdated"
        );
        assert_eq!(
            previous_url.as_ref().map(Url::as_str),
            Some("https://example.com/lifecycle")
        );
        let _ = previous_url;
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_downloads_actions_and_events() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest, permission) in [
            (
                "dl",
                r#"{"manifest_version":3,"id":"dl","name":"DL","version":"1","permissions":["downloads"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "witness",
                r#"{"manifest_version":3,"id":"witness","name":"Witness","version":"1","permissions":["downloads"],"host_permissions":["https://example.com/*"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                false,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            if permission {
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::Downloads,
                        &mut renderer,
                    )
                    .unwrap();
                shell
                    .grant_extension_host_permission_with_renderer(
                        id,
                        "https://example.com/*",
                        &mut renderer,
                    )
                    .unwrap();
            }
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };
        #[allow(clippy::match_same_arms)]
        let download_events = |renderer: &RecordingRenderer, kind: &str| {
            let mut events: Vec<(String, String)> = renderer
                .extension_events
                .iter()
                .filter_map(|event| match (&event.kind, kind) {
                    (nomad_engine::ExtensionEventKind::DownloadCreated { details }, "created") => {
                        Some((
                            event.extension_id.clone(),
                            format!(
                                "{}:{}",
                                details["id"],
                                details["state"].as_str().unwrap_or_default()
                            ),
                        ))
                    }
                    (nomad_engine::ExtensionEventKind::DownloadChanged { details }, "changed") => {
                        Some((
                            event.extension_id.clone(),
                            format!(
                                "{}:{}",
                                details["id"],
                                details["state"].as_str().unwrap_or_default()
                            ),
                        ))
                    }
                    (nomad_engine::ExtensionEventKind::DownloadErased { id }, "erased") => {
                        Some((event.extension_id.clone(), id.clone()))
                    }
                    _ => None,
                })
                .collect();
            events.sort();
            events
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "1",
                    "downloads.download",
                    serde_json::json!({
                        "url": "https://example.com/file.bin",
                        "filename": "file.bin",
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        let first_id = respond(&renderer, "1").unwrap().as_u64().unwrap();
        let id = nomad_engine::DownloadId::new(first_id);
        assert_eq!(
            download_events(&renderer, "created"),
            vec![
                ("dl".to_owned(), format!("{first_id}:queued"),),
                ("witness".to_owned(), format!("{first_id}:queued"),),
            ],
            "onCreated must reach every enabled downloads extension with the new item"
        );
        assert_eq!(
            shell.downloads.get(id).unwrap().state,
            nomad_engine::DownloadState::Queued
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "2",
                    "downloads.pause",
                    serde_json::json!({"id": first_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "2").unwrap(),
            serde_json::json!(false),
            "pausing a queued download must be rejected without an event"
        );
        shell.begin_download(id).unwrap();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "3",
                    "downloads.pause",
                    serde_json::json!({"id": first_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "3").unwrap(), serde_json::json!(true));
        assert_eq!(
            shell.downloads.get(id).unwrap().state,
            nomad_engine::DownloadState::Paused
        );
        assert_eq!(
            download_events(&renderer, "changed")
                .iter()
                .filter(|(extension_id, details)| extension_id == "dl"
                    && details == &format!("{first_id}:paused"))
                .count(),
            1,
            "pause must dispatch onChanged with the paused state"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "4",
                    "downloads.resume",
                    serde_json::json!({"id": first_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "4").unwrap(), serde_json::json!(true));
        assert_eq!(
            shell.downloads.get(id).unwrap().state,
            nomad_engine::DownloadState::InProgress
        );
        assert!(
            download_events(&renderer, "changed")
                .iter()
                .any(|(extension_id, details)| extension_id == "witness"
                    && details == &format!("{first_id}:in_progress")),
            "resume must dispatch onChanged to every enabled downloads extension"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "5",
                    "downloads.cancel",
                    serde_json::json!({"id": first_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "5").unwrap(), serde_json::json!(true));
        assert_eq!(
            shell.downloads.get(id).unwrap().state,
            nomad_engine::DownloadState::Cancelled
        );
        assert_eq!(
            download_events(&renderer, "changed")
                .iter()
                .filter(|(extension_id, details)| extension_id == "dl"
                    && details == &format!("{first_id}:cancelled"))
                .count(),
            1,
            "cancel must dispatch onChanged with the cancelled state"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "6",
                    "downloads.open",
                    serde_json::json!({"id": first_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "6").is_err(),
            "open must be rejected for non-completed downloads"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "7",
                    "downloads.erase",
                    serde_json::json!({"id": first_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "7").unwrap(), serde_json::Value::Null);
        assert!(
            shell.downloads.get(id).is_none(),
            "erase must remove the download from history"
        );
        assert_eq!(
            download_events(&renderer, "erased"),
            vec![
                ("dl".to_owned(), format!("{first_id}")),
                ("witness".to_owned(), format!("{first_id}")),
            ],
            "erase must dispatch onErased to every enabled downloads extension"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "8",
                    "downloads.download",
                    serde_json::json!({
                        "url": "https://example.com/other.bin",
                        "filename": "other.bin",
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        let second_id = respond(&renderer, "8").unwrap().as_u64().unwrap();
        let second = nomad_engine::DownloadId::new(second_id);
        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "9",
                    "downloads.remove",
                    serde_json::json!({"id": second_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "9").unwrap(), serde_json::Value::Null);
        assert!(
            shell.downloads.get(second).is_none(),
            "remove must erase the download"
        );
        assert!(
            download_events(&renderer, "changed")
                .iter()
                .any(|(extension_id, details)| extension_id == "dl"
                    && details == &format!("{second_id}:cancelled")),
            "remove must cancel and report the cancellation before erasing"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "dl",
                    "10",
                    "downloads.pause",
                    serde_json::json!({"id": second_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "10").is_err(),
            "actions on missing downloads must be rejected"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "deaf",
                    "11",
                    "downloads.cancel",
                    serde_json::json!({"id": first_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "11").is_err(),
            "extensions without the downloads permission must be denied"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_history_api_and_events() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest, permission) in [
            (
                "hist",
                r#"{"manifest_version":3,"id":"hist","name":"Hist","version":"1","permissions":["history","tabs"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "bystander",
                r#"{"manifest_version":3,"id":"bystander","name":"Bystander","version":"1","permissions":["history","tabs"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                false,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            if permission {
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::History,
                        &mut renderer,
                    )
                    .unwrap();
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::Tabs,
                        &mut renderer,
                    )
                    .unwrap();
            }
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "hist",
                    "1",
                    "history.addUrl",
                    serde_json::json!({"url": "https://example.com/a"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "1").unwrap(), serde_json::Value::Null);
        let visited: Vec<(String, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::HistoryVisited { details } => Some((
                    event.extension_id.clone(),
                    details["url"].as_str().unwrap_or_default().to_owned(),
                )),
                _ => None,
            })
            .collect();
        let mut visited = visited;
        visited.sort();
        assert_eq!(
            visited,
            vec![
                ("bystander".to_owned(), "https://example.com/a".to_owned()),
                ("hist".to_owned(), "https://example.com/a".to_owned()),
            ],
            "onVisited must reach every enabled history extension"
        );
        let visited_details = renderer
            .extension_events
            .iter()
            .find_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::HistoryVisited { details }
                    if event.extension_id == "hist" =>
                {
                    Some(details.clone())
                }
                _ => None,
            })
            .unwrap();
        assert!(
            visited_details["visitTime"].as_u64().unwrap() > 0,
            "visitTime must be a real unix millis timestamp"
        );
        assert!(
            visited_details["visitId"].as_u64().unwrap() > 0,
            "visitId must be a stable visit identifier"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "hist",
                    "2",
                    "history.addUrl",
                    serde_json::json!({"url": "ftp://example.com/a"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "2").is_err(),
            "history.addUrl must reject non-http(s)/file schemes"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "hist",
                    "3",
                    "history.getVisits",
                    serde_json::json!({"url": "https://example.com/a"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let visits = respond(&renderer, "3").unwrap();
        assert_eq!(visits.as_array().unwrap().len(), 1);
        assert_eq!(
            visits[0]["transitionType"],
            serde_json::json!("link"),
            "getVisits must report the Chromium transition type"
        );

        let tab_id = shell.new_tab();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "hist",
                    "4",
                    "tabs.create",
                    serde_json::json!({"url": "https://example.com/b"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let navigation_visited = renderer
            .extension_events
            .iter()
            .any(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::HistoryVisited { details } => {
                    event.extension_id == "hist"
                        && details["url"] == serde_json::json!("https://example.com/b")
                }
                _ => false,
            });
        assert!(
            navigation_visited,
            "navigating a tab through tabs.create must record and dispatch onVisited"
        );
        let title_tab = respond(&renderer, "4").unwrap()["id"]
            .as_u64()
            .map(nomad_engine::TabId::new)
            .unwrap();
        shell
            .dispatch_history_title_changed(title_tab, Some("Example title".into()), &mut renderer)
            .unwrap();
        let title_events: Vec<_> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::HistoryTitleChanged { details } => {
                    Some((event.extension_id.clone(), details.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            title_events.len(),
            2,
            "history title events must be permission filtered"
        );
        assert!(title_events.iter().all(|(id, details)| {
            (id == "hist" || id == "bystander")
                && details["id"] == serde_json::json!(title_tab.get())
                && details["url"] == serde_json::json!("https://example.com/b")
                && details["title"] == serde_json::json!("Example title")
        }));

        shell
            .receive_extension_message_with_renderer(
                api(
                    "hist",
                    "5",
                    "history.deleteUrl",
                    serde_json::json!({"url": "https://example.com/a"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "5").unwrap(), serde_json::Value::Null);
        let removed: Vec<(String, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::HistoryVisitRemoved { details } => Some((
                    event.extension_id.clone(),
                    format!("{}:{}", details["allHistory"], details["urls"]),
                )),
                _ => None,
            })
            .collect();
        let mut removed = removed;
        removed.sort();
        assert_eq!(
            removed,
            vec![
                (
                    "bystander".to_owned(),
                    "false:[\"https://example.com/a\"]".to_owned()
                ),
                (
                    "hist".to_owned(),
                    "false:[\"https://example.com/a\"]".to_owned()
                ),
            ],
            "deleteUrl must dispatch onVisitRemoved with the exact URL in both history extensions"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "hist",
                    "6",
                    "history.getVisits",
                    serde_json::json!({"url": "https://example.com/a"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "6")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty(),
            "deleted URLs must be gone from history"
        );

        let b_visit_time = shell
            .runtime
            .history()
            .iter()
            .find(|visit| visit.url.as_str() == "https://example.com/b")
            .map(|visit| visit.visited_at)
            .unwrap();
        shell
            .receive_extension_message_with_renderer(
                api(
                    "hist",
                    "7",
                    "history.deleteRange",
                    serde_json::json!({"startTime": b_visit_time, "endTime": b_visit_time}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "7").unwrap(), serde_json::Value::Null);
        assert!(
            shell
                .runtime
                .history()
                .iter()
                .all(|visit| visit.url.as_str() != "https://example.com/b"),
            "deleteRange must remove visits inside the requested timestamp window"
        );
        assert!(
            renderer
                .extension_events
                .iter()
                .any(|event| match &event.kind {
                    nomad_engine::ExtensionEventKind::HistoryVisitRemoved { details } => {
                        event.extension_id == "hist"
                            && details["allHistory"] == serde_json::json!(false)
                            && details["urls"] == serde_json::json!(["https://example.com/b"])
                    }
                    _ => false,
                }),
            "deleteRange must dispatch the removed URL"
        );

        shell
            .receive_extension_message_with_renderer(
                api("hist", "8", "history.deleteAll", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "8").unwrap(), serde_json::Value::Null);
        let all_removed = renderer
            .extension_events
            .iter()
            .any(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::HistoryVisitRemoved { details } => {
                    event.extension_id == "hist"
                        && details["allHistory"] == serde_json::json!(true)
                        && details["urls"].as_array().unwrap().is_empty()
                }
                _ => false,
            });
        assert!(
            all_removed,
            "deleteAll must dispatch onVisitRemoved with allHistory true"
        );
        assert!(
            shell.runtime.history().is_empty(),
            "deleteAll must clear the recorded history"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "deaf",
                    "9",
                    "history.getVisits",
                    serde_json::json!({"url": "https://example.com/b"}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "9").is_err(),
            "extensions without the history permission must be denied"
        );
        let _ = tab_id;
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_bookmarks_crud_and_events() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest, permission) in [
            (
                "bm",
                r#"{"manifest_version":3,"id":"bm","name":"BM","version":"1","permissions":["bookmarks"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "bystander",
                r#"{"manifest_version":3,"id":"bystander","name":"Bystander","version":"1","permissions":["bookmarks"],"background":{"service_worker":"background.js"}}"#,
                true,
            ),
            (
                "deaf",
                r#"{"manifest_version":3,"id":"deaf","name":"Deaf","version":"1","permissions":["storage"],"background":{"service_worker":"background.js"}}"#,
                false,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            if permission {
                shell
                    .grant_extension_permission_with_renderer(
                        id,
                        nomad_engine::ExtensionPermission::Bookmarks,
                        &mut renderer,
                    )
                    .unwrap();
            }
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };
        let created_events = |renderer: &RecordingRenderer| {
            let mut events: Vec<(String, String, String)> = renderer
                .extension_events
                .iter()
                .filter_map(|event| match &event.kind {
                    nomad_engine::ExtensionEventKind::BookmarkCreated { bookmark } => Some((
                        event.extension_id.clone(),
                        bookmark["id"].as_str().unwrap_or_default().to_owned(),
                        bookmark["title"].as_str().unwrap_or_default().to_owned(),
                    )),
                    _ => None,
                })
                .collect();
            events.sort();
            events
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "1",
                    "bookmarks.create",
                    serde_json::json!({"title": "Folder"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let folder = respond(&renderer, "1").unwrap();
        let folder_id = folder["id"].as_str().unwrap().to_owned();
        assert_eq!(folder["parentId"], serde_json::json!("0"));
        assert_eq!(folder["index"], serde_json::json!(0));
        assert!(folder.get("url").is_none(), "folders have no url");

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "2",
                    "bookmarks.create",
                    serde_json::json!({
                        "parentId": folder_id,
                        "title": "Example",
                        "url": "https://example.com/x",
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        let bookmark = respond(&renderer, "2").unwrap();
        let bookmark_id = bookmark["id"].as_str().unwrap().to_owned();
        assert_eq!(bookmark["parentId"], serde_json::json!(folder_id));
        assert_eq!(bookmark["title"], serde_json::json!("Example"));
        assert_eq!(bookmark["url"], serde_json::json!("https://example.com/x"));
        let mut expected_created = vec![
            ("bm".to_owned(), bookmark_id.clone(), "Example".to_owned()),
            ("bm".to_owned(), folder_id.clone(), "Folder".to_owned()),
            (
                "bystander".to_owned(),
                bookmark_id.clone(),
                "Example".to_owned(),
            ),
            (
                "bystander".to_owned(),
                folder_id.clone(),
                "Folder".to_owned(),
            ),
        ];
        expected_created.sort();
        assert_eq!(
            created_events(&renderer),
            expected_created,
            "onCreated must reach every enabled bookmarks extension"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "3",
                    "bookmarks.create",
                    serde_json::json!({
                        "parentId": folder_id,
                        "title": "Dedup",
                        "url": "https://example.com/x",
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "3").unwrap()["id"],
            serde_json::json!(bookmark_id),
            "creating a bookmark for an already-bookmarked URL must reuse the existing one"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "4",
                    "bookmarks.get",
                    serde_json::json!({"ids": [bookmark_id]}),
                ),
                &mut renderer,
            )
            .unwrap();
        let got = respond(&renderer, "4").unwrap();
        assert_eq!(got.as_array().unwrap().len(), 1);
        assert_eq!(got[0]["id"], serde_json::json!(bookmark_id));
        assert!(
            got[0].get("children").is_none(),
            "bookmarks.get returns plain nodes"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "5",
                    "bookmarks.get",
                    serde_json::json!({"ids": ["0"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "5").unwrap()[0]["id"],
            serde_json::json!("0"),
            "the root folder is addressable through bookmarks.get like Chromium"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "6",
                    "bookmarks.getChildren",
                    serde_json::json!({"id": "0"}),
                ),
                &mut renderer,
            )
            .unwrap();
        let children = respond(&renderer, "6").unwrap();
        let children_ids: Vec<&str> = children
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["id"].as_str().unwrap())
            .collect();
        assert!(
            children_ids.contains(&folder_id.as_str()),
            "root children must include the folder"
        );

        shell
            .receive_extension_message_with_renderer(
                api("bm", "7", "bookmarks.getTree", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        let tree = respond(&renderer, "7").unwrap();
        assert_eq!(tree.as_array().unwrap().len(), 1);
        assert_eq!(tree[0]["id"], serde_json::json!("0"));
        let tree_ids: Vec<&str> = tree[0]["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["id"].as_str().unwrap())
            .collect();
        assert!(tree_ids.contains(&folder_id.as_str()));

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "8",
                    "bookmarks.getSubTree",
                    serde_json::json!({"id": folder_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        let subtree = respond(&renderer, "8").unwrap();
        let subtree_ids: Vec<&str> = subtree[0]["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            subtree_ids,
            vec![bookmark_id.as_str()],
            "the folder subtree must contain its bookmarks"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "9",
                    "bookmarks.move",
                    serde_json::json!({
                        "id": bookmark_id,
                        "destination": {"parentId": "0"},
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        let moved = respond(&renderer, "9").unwrap();
        assert_eq!(
            moved["parentId"],
            serde_json::json!("0"),
            "moving to the root must reassign the parent"
        );
        let moved_events: Vec<String> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::BookmarkMoved {
                    id,
                    old_parent_id,
                    index,
                    ..
                } if event.extension_id == "bm" && id == &bookmark_id => {
                    Some(format!("{old_parent_id}:{index}"))
                }
                _ => None,
            })
            .collect();
        assert!(
            moved_events
                .iter()
                .any(|moved| moved == &format!("{folder_id}:0")),
            "onMoved must carry the old parent and the new index"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "10",
                    "bookmarks.update",
                    serde_json::json!({
                        "id": bookmark_id,
                        "changes": {"title": "Renamed", "url": "https://example.com/y"},
                    }),
                ),
                &mut renderer,
            )
            .unwrap();
        let updated = respond(&renderer, "10").unwrap();
        assert_eq!(updated["title"], serde_json::json!("Renamed"));
        assert_eq!(updated["url"], serde_json::json!("https://example.com/y"));
        let changed_events: Vec<(String, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::BookmarkChanged { id, title, url }
                    if event.extension_id == "bm" && id == &bookmark_id =>
                {
                    Some((title.clone(), url.clone().unwrap_or_default()))
                }
                _ => None,
            })
            .collect();
        assert!(
            changed_events
                .iter()
                .any(|(title, url)| title == "Renamed" && url == "https://example.com/y"),
            "update must dispatch onChanged with the new title and url"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "11",
                    "bookmarks.remove",
                    serde_json::json!({"id": folder_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "11").is_err(),
            "bookmarks.remove must reject folders"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "12",
                    "bookmarks.remove",
                    serde_json::json!({"id": bookmark_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "12").unwrap(), serde_json::Value::Null);
        let removed_events: Vec<(String, String, String)> = renderer
            .extension_events
            .iter()
            .filter_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::BookmarkRemoved {
                    id,
                    parent_id,
                    index,
                } if event.extension_id == "bm" && id == &bookmark_id => {
                    Some((id.clone(), parent_id.clone(), index.to_string()))
                }
                _ => None,
            })
            .collect();
        assert!(
            removed_events
                .iter()
                .any(|(id, parent_id, _)| id == &bookmark_id && parent_id == "0"),
            "remove must dispatch onRemoved with the parent"
        );

        shell
            .receive_extension_message_with_renderer(
                api(
                    "bm",
                    "13",
                    "bookmarks.removeTree",
                    serde_json::json!({"id": folder_id}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "13").unwrap(), serde_json::Value::Null);
        assert!(
            shell
                .bookmarks
                .folder(nomad_engine::BookmarkFolderId::new(
                    folder_id.parse().unwrap()
                ))
                .is_none(),
            "removeTree must delete the folder"
        );
        let folder_removed = renderer
            .extension_events
            .iter()
            .any(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::BookmarkRemoved { id, .. } => {
                    event.extension_id == "bm" && id == &folder_id
                }
                _ => false,
            });
        assert!(
            folder_removed,
            "removeTree must dispatch onRemoved for the folder itself"
        );

        shell
            .receive_extension_message_with_renderer(
                api("deaf", "14", "bookmarks.getTree", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "14").is_err(),
            "extensions without the bookmarks permission must be denied"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_management_self_and_events() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        for (id, manifest) in [
            (
                "supervisor",
                r#"{"manifest_version":3,"id":"supervisor","name":"Supervisor","version":"1","permissions":["management"],"background":{"service_worker":"background.js"}}"#,
            ),
            (
                "ordinary",
                r#"{"manifest_version":3,"id":"ordinary","name":"Ordinary","version":"1","background":{"service_worker":"background.js"}}"#,
            ),
        ] {
            shell
                .install_extension_package_with_renderer(
                    manifest,
                    [("background.js".into(), "1;".into())]
                        .into_iter()
                        .collect(),
                    &mut renderer,
                )
                .unwrap();
            shell
                .grant_extension_permission_with_renderer(
                    id,
                    nomad_engine::ExtensionPermission::Management,
                    &mut renderer,
                )
                .unwrap_or(());
        }

        let api = |id: &str, request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: id.into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "supervisor",
                    "1",
                    "management.getSelf",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        let myself = respond(&renderer, "1").unwrap();
        assert_eq!(myself["id"], serde_json::json!("supervisor"));
        assert_eq!(myself["enabled"], serde_json::json!(true));

        let management_events = |renderer: &RecordingRenderer| {
            let mut events: Vec<(String, String)> = renderer
                .extension_events
                .iter()
                .filter_map(|event| match &event.kind {
                    nomad_engine::ExtensionEventKind::ManagementInstalled { info }
                    | nomad_engine::ExtensionEventKind::ManagementUninstalled { info }
                    | nomad_engine::ExtensionEventKind::ManagementEnabled { info }
                    | nomad_engine::ExtensionEventKind::ManagementDisabled { info } => Some((
                        event.extension_id.clone(),
                        info["id"].as_str().unwrap_or_default().to_owned(),
                    )),
                    _ => None,
                })
                .collect();
            events.sort();
            events
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "supervisor",
                    "2",
                    "management.setEnabled",
                    serde_json::json!({"id": "ordinary", "enabled": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "2").unwrap(), serde_json::Value::Null);
        let events = management_events(&renderer);
        assert!(
            events.iter().any(|(extension_id, subject)| {
                extension_id == "supervisor" && *subject == "ordinary"
            }),
            "the supervising extension must observe management.onDisabled for the toggled extension"
        );
        assert!(
            !events
                .iter()
                .any(|(extension_id, _)| extension_id == "ordinary"),
            "the toggled extension must not observe its own management event"
        );

        shell
            .receive_extension_message_with_renderer(
                api("ordinary", "3", "management.getSelf", serde_json::json!({})),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "3").is_err(),
            "extensions without the management permission must be denied"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "ordinary",
                    "4",
                    "management.setEnabled",
                    serde_json::json!({"id": "supervisor", "enabled": false}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert!(
            respond(&renderer, "4").is_err(),
            "extensions without the management permission must be denied"
        );
        shell
            .receive_extension_message_with_renderer(
                api(
                    "supervisor",
                    "5",
                    "management.uninstallSelf",
                    serde_json::json!({}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(respond(&renderer, "5").unwrap(), serde_json::Value::Null);
        assert!(
            shell.extension_manifest("supervisor").is_none(),
            "uninstallSelf must remove the extension"
        );
        let events = management_events(&renderer);
        assert!(
            events.iter().any(|(extension_id, subject)| {
                extension_id == "supervisor" && *subject == "ordinary"
            }),
            "management extensions must observe onInstalled for newly installed extensions"
        );
        assert!(
            !events.iter().any(|(extension_id, subject)| {
                extension_id == "ordinary" && *subject == "supervisor"
            }),
            "a disabled extension cannot observe management events"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_context_menus_dispatch_click_and_show_events() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"menu","name":"Menu","version":"1","permissions":["contextMenus"],"background":{"service_worker":"background.js"}}"#,
                [("background.js".into(), "1;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();
        shell
            .grant_extension_permission_with_renderer(
                "menu",
                nomad_engine::ExtensionPermission::ContextMenus,
                &mut renderer,
            )
            .unwrap();
        let api = |request_id: &str, method: &str, arguments: serde_json::Value| {
            nomad_engine::ExtensionMessage {
                extension_id: "menu".into(),
                tab_id: None,
                payload: serde_json::json!({
                    "__nomad_api_request": {"id": request_id, "method": method, "arguments": arguments}
                }),
            }
        };
        let respond = |renderer: &RecordingRenderer, request_id: &str| {
            renderer
                .extension_events
                .iter()
                .find_map(|event| {
                    if let nomad_engine::ExtensionEventKind::RuntimeResponse {
                        request_id: id,
                        result,
                    } = &event.kind
                    {
                        (id == request_id).then_some(result.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no response for {request_id}"))
        };

        shell
            .receive_extension_message_with_renderer(
                api(
                    "1",
                    "contextMenus.create",
                    serde_json::json!({"id": "open-link", "title": "Open Link", "contexts": ["link"]}),
                ),
                &mut renderer,
            )
            .unwrap();
        assert_eq!(
            respond(&renderer, "1").unwrap(),
            serde_json::json!("open-link")
        );

        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let tab_id = shell.active_tab().unwrap();

        shell
            .notify_extension_context_menu_shown("menu", Some(tab_id), &mut renderer)
            .unwrap();
        shell
            .notify_extension_context_menu_clicked("menu", "open-link", Some(tab_id), &mut renderer)
            .unwrap();
        shell
            .notify_extension_context_menu_hidden("menu", &mut renderer)
            .unwrap();

        let kinds: Vec<&str> = renderer
            .extension_events
            .iter()
            .map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::ContextMenuClicked { .. } => "clicked",
                nomad_engine::ExtensionEventKind::ContextMenuShown { .. } => "shown",
                nomad_engine::ExtensionEventKind::ContextMenuHidden => "hidden",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind != "other")
                .copied()
                .collect::<Vec<_>>(),
            ["shown", "clicked", "hidden"]
        );
        let shown = renderer
            .extension_events
            .iter()
            .find_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::ContextMenuShown { info, .. } => Some(info),
                _ => None,
            })
            .unwrap();
        assert_eq!(shown["pageUrl"], serde_json::json!("https://example.com/"));
        let clicked = renderer
            .extension_events
            .iter()
            .find_map(|event| match &event.kind {
                nomad_engine::ExtensionEventKind::ContextMenuClicked { info, .. } => Some(info),
                _ => None,
            })
            .unwrap();
        assert_eq!(clicked["menuItemId"], serde_json::json!("open-link"));
        assert_eq!(
            clicked["pageUrl"],
            serde_json::json!("https://example.com/")
        );

        assert!(matches!(
            shell.notify_extension_context_menu_clicked(
                "menu",
                "missing",
                Some(tab_id),
                &mut renderer,
            ),
            Err(ShellError::Extension(
                nomad_engine::ExtensionError::InvalidManifest(_)
            ))
        ));
    }

    #[test]
    fn test_webextension_declarative_rules_update_renderer_blocking_state() {
        let mut shell = ShellState::new(runtime());
        shell
            .install_extension(
                nomad_engine::ExtensionManifest::from_json(
                    r#"{"manifest_version":3,"id":"rules","name":"Rules","version":"1","permissions":["declarativeNetRequest"]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        shell
            .grant_extension_permission(
                "rules",
                nomad_engine::ExtensionPermission::DeclarativeNetRequest,
            )
            .unwrap();
        let mut renderer = RecordingRenderer::default();
        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "rules".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "1",
                            "method": "declarativeNetRequest.updateDynamicRules",
                            "arguments": {
                                "addRules": [{
                                    "id": 1,
                                    "action": {"type": "block"},
                                    "condition": {"requestDomains": ["ads.example"]}
                                }]
                            }
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert_eq!(renderer.blocking_patterns, ["*://ads.example/*"]);
        assert!(matches!(
            renderer.extension_events.last(),
            Some(ExtensionEvent {
                kind: nomad_engine::ExtensionEventKind::RuntimeResponse {
                    request_id,
                    result: Ok(serde_json::Value::Null),
                },
                ..
            }) if request_id == "1"
        ));
    }

    #[test]
    fn web_navigation_committed_event_exposes_authorized_page_context() {
        let mut shell = ShellState::new(runtime());
        shell
            .install_extension(
                nomad_engine::ExtensionManifest::from_json(
                    r#"{"manifest_version":3,"id":"observer","name":"Observer","version":"1","permissions":["webNavigation"],"host_permissions":["https://example.com/*"]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        shell
            .grant_extension_permission(
                "observer",
                nomad_engine::ExtensionPermission::WebNavigation,
            )
            .unwrap();
        shell
            .grant_extension_host_permission("observer", "https://example.com/*")
            .unwrap();

        let mut renderer = RecordingRenderer::default();
        shell.set_address_input("https://example.com/docs");
        shell.submit_address_with_renderer(&mut renderer).unwrap();

        assert!(renderer.extension_events.iter().any(|event| matches!(
            &event.kind,
            nomad_engine::ExtensionEventKind::WebNavigation { event, details }
                if event == "onCommitted"
                    && details["tabId"] == serde_json::json!(1)
                    && details["url"] == "https://example.com/docs"
        )));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "observer".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "frames",
                            "method": "webNavigation.getAllFrames",
                            "arguments": {"tabId": 1}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(matches!(
            renderer.extension_events.last(),
            Some(ExtensionEvent {
                kind: ExtensionEventKind::RuntimeResponse {
                    request_id,
                    result: Ok(value),
                },
                ..
            }) if request_id == "frames"
                && value[0]["frameId"] == serde_json::json!(0)
                && value[0]["url"] == "https://example.com/docs"
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_webextension_management_and_windows_apis_return_browser_state() {
        let mut shell = ShellState::new(runtime());
        shell
            .install_extension(
                nomad_engine::ExtensionManifest::from_json(
                    r#"{"manifest_version":3,"id":"inspector","name":"Inspector","version":"1.2.3","permissions":["management","windows","tabs"],"host_permissions":["https://example.com/*"]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        for permission in [
            nomad_engine::ExtensionPermission::Management,
            nomad_engine::ExtensionPermission::Windows,
            nomad_engine::ExtensionPermission::Tabs,
        ] {
            shell
                .grant_extension_permission("inspector", permission)
                .unwrap();
        }
        shell
            .grant_extension_host_permission("inspector", "https://example.com/*")
            .unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();

        let mut renderer = RecordingRenderer::default();
        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "inspector".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "windows",
                            "method": "windows.getAll",
                            "arguments": {"populate": true}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        let windows = match &renderer.extension_events.last().unwrap().kind {
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "windows" => value,
            event => panic!("unexpected windows response: {event:?}"),
        };
        assert_eq!(windows[0]["id"], serde_json::json!(1));
        assert_eq!(windows[0]["tabs"][0]["url"], "https://example.com/");
        assert_eq!(windows[0]["tabs"][0]["windowId"], serde_json::json!(1));

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "inspector".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "management",
                            "method": "management.getAll",
                            "arguments": null
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        let management = match &renderer.extension_events.last().unwrap().kind {
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "management" => value,
            event => panic!("unexpected management response: {event:?}"),
        };
        assert_eq!(management[0]["id"], "inspector");
        assert_eq!(management[0]["version"], "1.2.3");
        assert_eq!(management[0]["enabled"], serde_json::json!(true));

        shell.new_tab();
        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "inspector".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "query",
                            "method": "tabs.query",
                            "arguments": {
                                "active": false,
                                "windowId": 1,
                                "url": "https://example.com/*"
                            }
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        let query = match &renderer.extension_events.last().unwrap().kind {
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "query" => value,
            event => panic!("unexpected query response: {event:?}"),
        };
        assert_eq!(query.as_array().map(Vec::len), Some(1));
        assert_eq!(query[0]["windowId"], serde_json::json!(1));
        assert_eq!(query[0]["url"], "https://example.com/");

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "inspector".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "disable",
                            "method": "management.setEnabled",
                            "arguments": {"id": "inspector", "enabled": false}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        assert!(!shell.extensions().is_enabled("inspector"));
        assert!(matches!(
            renderer.extension_events.last(),
            Some(ExtensionEvent {
                kind: nomad_engine::ExtensionEventKind::RuntimeResponse {
                    request_id,
                    result: Ok(serde_json::Value::Null),
                },
                ..
            }) if request_id == "disable"
        ));
    }

    #[test]
    fn test_webextension_i18n_get_message_resolves_locale_catalog() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{"manifest_version":3,"id":"localized","name":"Localized","version":"1"}"#,
                [
                    (
                        "_locales/en/messages.json".into(),
                        serde_json::json!({
                            "hello": {"message": "Hello $1!"},
                            "pausedOn": {"message": "Paused on $1"},
                            "missing": {"message": "Missing"}
                        })
                        .to_string(),
                    ),
                    ("background.js".into(), "globalThis.ping = true;".into()),
                ]
                .into_iter()
                .collect(),
                &mut renderer,
            )
            .unwrap();

        let mut response = |id: &str, method: &str, arguments: serde_json::Value| {
            shell
                .receive_extension_message_with_renderer(
                    ExtensionMessage {
                        extension_id: "localized".into(),
                        tab_id: None,
                        payload: serde_json::json!({
                            "__nomad_api_request": {"id": id, "method": method, "arguments": arguments}
                        }),
                    },
                    &mut renderer,
                )
                .unwrap();
            match renderer.extension_events.last().unwrap().kind.clone() {
                nomad_engine::ExtensionEventKind::RuntimeResponse { request_id, result }
                    if request_id == id =>
                {
                    result
                }
                event => panic!("unexpected response: {event:?}"),
            }
        };

        // Positional placeholder substitution.
        assert_eq!(
            response(
                "hello",
                "i18n.getMessage",
                serde_json::json!({"messageName": "hello", "substitutions": ["Nomad"]})
            )
            .unwrap(),
            serde_json::json!("Hello Nomad!")
        );
        // Positional substitution.
        assert_eq!(
            response(
                "paused",
                "i18n.getMessage",
                serde_json::json!({"messageName": "pausedOn", "substitutions": ["page 2"]})
            )
            .unwrap(),
            serde_json::json!("Paused on page 2")
        );
        // Unknown keys resolve to the empty string.
        assert_eq!(
            response(
                "unknown",
                "i18n.getMessage",
                serde_json::json!({"messageName": "does-not-exist", "substitutions": []})
            )
            .unwrap(),
            serde_json::json!("")
        );
        assert_eq!(
            response(
                "languages",
                "i18n.getAcceptLanguages",
                serde_json::json!({})
            )
            .unwrap(),
            serde_json::json!(["en-US", "en"])
        );
        assert_eq!(
            response(
                "detect",
                "i18n.detectLanguage",
                serde_json::json!({"text": "Привет, Nomad"}),
            )
            .unwrap()["languages"][0]["language"],
            "ru"
        );
        let contexts = response(
            "contexts",
            "runtime.getContexts",
            serde_json::json!({"contextTypes": ["BACKGROUND"]}),
        )
        .unwrap();
        assert_eq!(contexts.as_array().map(Vec::len), Some(1));
        assert_eq!(contexts[0]["contextType"], "BACKGROUND");
    }

    #[test]
    fn test_webextension_commands_get_all_and_on_command_dispatch() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell
            .install_extension_package_with_renderer(
                r#"{
                    "manifest_version": 3,
                    "id": "commander",
                    "name": "Commander",
                    "version": "1",
                    "background": {"service_worker": "background.js"},
                    "commands": {
                        "toggle-panel": {"suggested_key": {"default": "Alt+P"}, "description": "Toggle the panel"},
                        "focus-address": {"suggested_key": {"default": "Alt+A"}, "description": "Focus the address bar"}
                    }
                }"#,
                [("background.js".into(), "globalThis.cmd = true;".into())]
                    .into_iter()
                    .collect(),
                &mut renderer,
            )
            .unwrap();

        shell
            .receive_extension_message_with_renderer(
                ExtensionMessage {
                    extension_id: "commander".into(),
                    tab_id: None,
                    payload: serde_json::json!({
                        "__nomad_api_request": {
                            "id": "commands",
                            "method": "commands.getAll",
                            "arguments": {}
                        }
                    }),
                },
                &mut renderer,
            )
            .unwrap();
        let commands = match &renderer.extension_events.last().unwrap().kind {
            nomad_engine::ExtensionEventKind::RuntimeResponse {
                request_id,
                result: Ok(value),
            } if request_id == "commands" => value,
            event => panic!("unexpected commands response: {event:?}"),
        };
        assert_eq!(
            commands.as_array().map(Vec::len),
            Some(2),
            "commands.getAll must return the manifest commands"
        );
        assert_eq!(commands[0]["name"], serde_json::json!("focus-address"));

        // Triggering a declared command dispatches commands.onCommand.
        shell
            .trigger_extension_command_with_renderer("commander", "toggle-panel", &mut renderer)
            .unwrap();
        assert!(matches!(
            renderer.extension_events.last(),
            Some(ExtensionEvent {
                kind: nomad_engine::ExtensionEventKind::Command { command },
                ..
            }) if command == "toggle-panel"
        ));

        // Triggering an undeclared command fails closed.
        let error = shell
            .trigger_extension_command_with_renderer("commander", "no-such-command", &mut renderer)
            .unwrap_err();
        assert!(matches!(
            error,
            ShellError::Extension(nomad_engine::ExtensionError::PermissionDenied(message))
                if message.contains("not declared")
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_real_mv2_and_mv3_packages_complete_lifecycle() {
        // Real MV2 and MV3 packages with actual background scripts, a content
        // script, locale data, and a popup, driven through install, permission
        // changes, disable, re-enable, update, crash recovery (registry
        // snapshot/restore), and uninstall.
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();

        shell
            .install_extension_package_with_renderer(
                r#"{
                "manifest_version": 2,
                "id": "legacy-tool",
                "name": "Legacy Tool",
                "version": "1.0.0",
                "permissions": ["storage", "tabs"],
                "host_permissions": ["https://example.com/*"],
                "browser_action": {"default_title": "Legacy Tool"},
                "background": {"scripts": ["background.js"]},
                "content_scripts": [{
                    "matches": ["https://example.com/*"],
                    "js": "content.js"
                }],
                "default_locale": "en",
                "options_ui": {"page": "options.html"}
            }"#,
                [
                    ("background.js".into(), "globalThis.mv = 2;".into()),
                    ("content.js".into(), "document.title = 'patched';".into()),
                    (
                        "_locales/en/messages.json".into(),
                        r#"{"name":{"message":"Legacy Tool"}}"#.into(),
                    ),
                    (
                        "options.html".into(),
                        "<!doctype html><p>options</p>".into(),
                    ),
                ]
                .into_iter()
                .collect(),
                &mut renderer,
            )
            .unwrap();
        assert!(shell.extensions().is_enabled("legacy-tool"));
        assert_eq!(
            shell.extensions().manifest("legacy-tool").unwrap().version,
            "1.0.0"
        );

        shell
            .install_extension_package_with_renderer(
                r#"{
                "manifest_version": 3,
                "id": "modern-tool",
                "name": "Modern Tool",
                "version": "2.0.0",
                "permissions": ["storage", "scripting"],
                "host_permissions": ["https://example.com/*"],
                "action": {"default_title": "Modern Tool"},
                "background": {"service_worker": "background.js", "type": "module"},
                "commands": {"toggle": {"suggested_key": {"default": "Alt+M"}, "description": "Toggle"}}
            }"#,
            [
                ("background.js".into(), "globalThis.mv = 3;".into()),
                ("popup.html".into(), "<!doctype html><p>popup</p>".into()),
            ]
            .into_iter()
            .collect(),
            &mut renderer,
        )
        .unwrap();
        assert!(shell.extensions().is_enabled("modern-tool"));
        assert_eq!(shell.extensions().commands("modern-tool").len(), 1);

        // Permission changes are visible and revocable.
        shell
            .grant_extension_permission_with_renderer(
                "modern-tool",
                nomad_engine::ExtensionPermission::Storage,
                &mut renderer,
            )
            .unwrap();
        shell
            .revoke_extension_permission_with_renderer(
                "modern-tool",
                nomad_engine::ExtensionPermission::Storage,
                &mut renderer,
            )
            .unwrap();

        // Disable then re-enable (management.setEnabled path).
        shell
            .set_extension_enabled_with_renderer("modern-tool", false, &mut renderer)
            .unwrap();
        assert!(!shell.extensions().is_enabled("modern-tool"));
        shell
            .set_extension_enabled_with_renderer("modern-tool", true, &mut renderer)
            .unwrap();
        assert!(shell.extensions().is_enabled("modern-tool"));

        // Update replaces resources/background and preserves storage state.
        shell
            .grant_extension_permission_with_renderer(
                "modern-tool",
                nomad_engine::ExtensionPermission::Storage,
                &mut renderer,
            )
            .unwrap();
        shell
            .extension_storage_set("modern-tool", "kept", serde_json::json!(true))
            .unwrap();
        let updated = nomad_engine::ExtensionPackage::from_manifest_json(
            r#"{
                "manifest_version": 3,
                "id": "modern-tool",
                "name": "Modern Tool",
                "version": "2.1.0",
                "permissions": ["storage"],
                "background": {"service_worker": "background.js"}
            }"#,
            [("background.js".into(), "globalThis.mv = 3.1;".into())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        shell
            .update_extension_package_with_renderer(updated, &mut renderer)
            .unwrap();
        assert_eq!(
            shell.extensions().manifest("modern-tool").unwrap().version,
            "2.1.0"
        );
        assert_eq!(
            shell.extension_storage_get("modern-tool", "kept").unwrap(),
            Some(serde_json::json!(true))
        );

        // Crash recovery: persist the session, simulate a restart in a fresh
        // shell, and confirm the extension registry and storage survive.
        let saved_session = shell.save_session().unwrap();
        let mut restarted = ShellState::new(runtime());
        let mut restart_renderer = RecordingRenderer::default();
        restarted
            .restore_session_with_renderer(&saved_session, &mut restart_renderer)
            .unwrap();
        assert!(restarted.extensions().is_enabled("modern-tool"));
        assert!(restarted.extensions().is_enabled("legacy-tool"));
        assert_eq!(
            restarted
                .extension_storage_get("modern-tool", "kept")
                .unwrap(),
            Some(serde_json::json!(true))
        );

        // Uninstall the legacy MV2 package.
        shell
            .uninstall_extension_with_renderer("legacy-tool", &mut renderer)
            .unwrap();
        assert!(!shell.extensions().is_enabled("legacy-tool"));
    }

    #[test]
    fn test_submit_address_navigates_active_tab_and_canonicalizes_input() {
        let mut shell = ShellState::new(runtime());

        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();

        let active_tab = shell.active_tab().unwrap();
        assert_eq!(
            shell
                .tab(active_tab)
                .unwrap()
                .url
                .as_ref()
                .unwrap()
                .as_str(),
            "https://example.com/"
        );
        assert_eq!(shell.address_bar().input(), "https://example.com/");
    }

    #[test]
    fn test_renderer_navigation_updates_browser_state_without_duplicate_commit() {
        let mut shell = ShellState::new(runtime());
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let tab_id = shell.active_tab().unwrap();
        let page_url = Url::parse("https://example.com/next").unwrap();

        shell.sync_renderer_navigation(tab_id, &page_url).unwrap();

        assert_eq!(shell.active_url(), Some(&page_url));
        assert_eq!(shell.address_bar().input(), page_url.as_str());
        assert_eq!(shell.runtime.tab_history(tab_id).unwrap().entries.len(), 2);

        shell.sync_renderer_navigation(tab_id, &page_url).unwrap();
        assert_eq!(shell.runtime.tab_history(tab_id).unwrap().entries.len(), 2);
    }

    #[test]
    fn test_submit_address_normalizes_bare_hosts_and_searches_plain_text() {
        let mut shell = ShellState::new(runtime());

        shell.set_address_input("localhost:3000");
        shell.submit_address().unwrap();
        assert_eq!(shell.address_bar().input(), "http://localhost:3000/");

        shell.set_address_input("servo memory usage");
        shell.submit_address().unwrap();
        assert_eq!(
            shell.address_bar().input(),
            "https://duckduckgo.com/?q=servo+memory+usage"
        );
    }

    #[test]
    fn test_universal_suggestions_include_explicit_commands() {
        let shell = ShellState::new(runtime());

        let suggestions = shell.universal_suggestions(":new");

        assert_eq!(suggestions[0].title, "New tab");
        assert_eq!(
            suggestions[0].target,
            UniversalTarget::Command(BrowserCommand::NewTab)
        );
    }

    #[test]
    fn test_universal_suggestions_find_commands_without_prefix() {
        let shell = ShellState::new(runtime());

        let suggestions = shell.universal_suggestions("privacy");

        assert!(suggestions.iter().any(|suggestion| {
            suggestion.kind == UniversalSuggestionKind::Command
                && suggestion.target == UniversalTarget::Command(BrowserCommand::OpenPrivacy)
        }));
    }

    #[test]
    fn test_universal_suggestions_deduplicate_repeated_history_urls() {
        let mut shell = ShellState::new(runtime());
        for _ in 0..3 {
            shell.set_address_input("https://google.com");
            shell.submit_address().unwrap();
        }

        let suggestions = shell.universal_suggestions("google.com");
        let matching_history = suggestions
            .iter()
            .filter(|suggestion| {
                suggestion.kind == UniversalSuggestionKind::History
                    && suggestion.detail == "History"
            })
            .count();

        assert_eq!(matching_history, 1);
    }

    #[test]
    fn test_submit_address_with_renderer_sends_request_and_canonicalizes_input() {
        let mut shell = ShellState::new(runtime());
        shell.set_address_input("https://example.com");
        let tab_id = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();

        shell.submit_address_with_renderer(&mut renderer).unwrap();

        assert_eq!(renderer.loaded.len(), 1);
        assert_eq!(renderer.loaded[0].tab_id, tab_id);
        assert_eq!(renderer.loaded[0].url.as_str(), "https://example.com/");
        assert_eq!(shell.address_bar().input(), "https://example.com/");
        assert_eq!(shell.tab(tab_id).unwrap().state, TabState::Loading);
    }

    #[test]
    fn test_open_address_in_new_tab_reuses_blank_then_creates_next_tab() {
        let mut shell = ShellState::new(runtime());
        let initial_blank = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();

        let first = shell
            .open_address_in_new_tab_with_renderer("https://example.com", &mut renderer)
            .unwrap();
        let second = shell
            .open_address_in_new_tab_with_renderer("servo browser", &mut renderer)
            .unwrap();

        assert_eq!(first, initial_blank);
        assert_ne!(second, first);
        assert_eq!(shell.active_tab(), Some(second));
        assert_eq!(shell.tabs().len(), 2);
        assert_eq!(renderer.loaded[0].tab_id, first);
        assert_eq!(renderer.loaded[0].url.as_str(), "https://example.com/");
        assert_eq!(renderer.loaded[1].tab_id, second);
        assert_eq!(
            renderer.loaded[1].url.as_str(),
            "https://duckduckgo.com/?q=servo+browser"
        );
    }

    #[test]
    fn test_open_settings_uses_a_reusable_normal_tab() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();

        let settings_tab = shell
            .open_settings_tab_with_renderer(&mut renderer)
            .unwrap();
        assert_eq!(shell.active_tab(), Some(settings_tab));
        assert!(renderer.activated.is_empty());
        assert_eq!(
            shell
                .tab(settings_tab)
                .unwrap()
                .url
                .as_ref()
                .unwrap()
                .as_str(),
            "about:settings"
        );

        let page_tab = shell
            .open_address_in_new_tab_with_renderer("https://example.com", &mut renderer)
            .unwrap();
        assert_ne!(page_tab, settings_tab);
        assert_eq!(shell.active_tab(), Some(page_tab));

        let reopened = shell
            .open_settings_tab_with_renderer(&mut renderer)
            .unwrap();
        assert_eq!(reopened, settings_tab);
        assert_eq!(shell.tabs().len(), 2);
        assert_eq!(renderer.activated, vec![page_tab]);
    }

    #[test]
    fn test_open_address_in_new_tab_rejects_input_before_creating_tab() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell.set_address_input("https://example.com");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let original_tab = shell.active_tab().unwrap();

        assert!(shell
            .open_address_in_new_tab_with_renderer("bad\ninput", &mut renderer)
            .is_err());

        assert_eq!(shell.active_tab(), Some(original_tab));
        assert_eq!(shell.tabs().len(), 1);
        assert_eq!(shell.address_bar().input(), "https://example.com/");
    }

    #[test]
    fn test_finish_navigation_with_renderer_updates_loading_tab() {
        let mut shell = ShellState::new(runtime());
        shell.set_address_input("https://example.com");
        let tab_id = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();

        shell.submit_address_with_renderer(&mut renderer).unwrap();
        shell.finish_navigation(tab_id).unwrap();

        assert_eq!(shell.tab(tab_id).unwrap().state, TabState::Active);
    }

    #[test]
    fn test_submit_address_with_renderer_preserves_state_when_renderer_fails() {
        let mut shell = ShellState::new(runtime());
        shell.set_address_input("https://example.com");
        let tab_id = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer {
            fail: true,
            ..RecordingRenderer::default()
        };

        assert_eq!(
            shell.submit_address_with_renderer(&mut renderer),
            Err(ShellError::Navigation(NavigationError::Render(
                RenderError::BackendUnavailable
            )))
        );
        assert_eq!(shell.address_bar().input(), "https://example.com");
        assert_eq!(shell.tab(tab_id).unwrap().url, None);
        assert_eq!(shell.tab(tab_id).unwrap().state, TabState::Error);
    }

    #[test]
    fn test_submit_address_preserves_input_when_navigation_fails() {
        let mut shell = ShellState::new(runtime());
        shell.set_address_input("javascript:alert(1)");

        assert_eq!(
            shell.submit_address(),
            Err(ShellError::Navigation(NavigationError::UnsupportedScheme(
                "javascript".into()
            )))
        );
        assert_eq!(shell.address_bar().input(), "javascript:alert(1)");
        assert_eq!(shell.tabs()[0].state, TabState::New);
    }

    #[test]
    fn test_history_navigation_updates_address_bar_and_availability() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();

        for address in ["https://one.example", "https://two.example"] {
            shell.set_address_input(address);
            shell.submit_address_with_renderer(&mut renderer).unwrap();
        }

        assert!(shell.can_go_back());
        assert!(!shell.can_go_forward());
        shell.go_back_with_renderer(&mut renderer).unwrap();
        assert_eq!(shell.address_bar().input(), "https://one.example/");
        assert!(!shell.can_go_back());
        assert!(shell.can_go_forward());

        shell.go_forward_with_renderer(&mut renderer).unwrap();
        assert_eq!(shell.address_bar().input(), "https://two.example/");
        assert!(shell.can_go_back());
        assert!(!shell.can_go_forward());
    }

    #[test]
    fn test_shell_exposes_recent_and_filtered_history() {
        let mut shell = ShellState::new(runtime());

        for address in ["https://one.example", "https://two.example"] {
            shell.set_address_input(address);
            shell.submit_address().unwrap();
        }

        assert_eq!(shell.history().len(), 2);
        assert_eq!(shell.recent_history(1).len(), 1);
        assert_eq!(shell.search_history("one").len(), 1);
    }

    #[test]
    fn test_private_settings_disable_history_recording() {
        let mut shell = ShellState::with_settings(
            runtime(),
            BrowserSettings {
                privacy_mode: PrivacyMode::Private,
                ..BrowserSettings::default()
            },
        );

        shell.set_address_input("https://private.example");
        shell.submit_address().unwrap();

        assert!(shell.history().is_empty());
    }

    #[test]
    fn test_permission_prompt_can_be_resolved_once() {
        let mut shell = ShellState::new(runtime());
        let prompt = PermissionPrompt {
            id: nomad_engine::PermissionPromptId::new(1),
            site: "https://example.com".into(),
            kind: nomad_engine::PermissionKind::Camera,
        };
        shell.queue_permission(prompt.clone());

        shell
            .resolve_permission(prompt.id, nomad_engine::PermissionDecision::AllowOnce)
            .unwrap();

        assert!(shell.pending_permissions().is_empty());
        assert_eq!(
            shell.permission_decision(&prompt.site, prompt.kind),
            nomad_engine::PermissionDecision::Ask
        );
    }

    #[test]
    fn test_session_round_trip_restores_tabs_and_bookmarks() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell.set_address_input("https://one.example");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        shell.toggle_active_bookmark().unwrap();
        shell.new_tab();
        shell.set_address_input("https://two.example");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let session = shell.save_session().unwrap();

        let mut restored = ShellState::new(runtime());
        let mut restore_renderer = RecordingRenderer::default();
        restored
            .restore_session_with_renderer(&session, &mut restore_renderer)
            .unwrap();

        assert_eq!(restored.tabs().len(), 2);
        assert_eq!(restored.bookmarks().len(), 1);
        assert_eq!(restored.address_bar().input(), "https://two.example/");
        assert_eq!(
            restored.tabs()[0].url.as_ref().unwrap().as_str(),
            "https://one.example/"
        );
    }

    #[test]
    fn test_session_round_trip_restores_phase_two_state() {
        let directory =
            std::env::temp_dir().join(format!("nomad-session-downloads-{}", std::process::id()));
        let mut shell = ShellState::with_download_directory(runtime(), &directory);
        shell.apply_settings(BrowserSettings {
            privacy_mode: PrivacyMode::Hardened,
            persist_permissions: true,
            ..shell.settings().clone()
        });
        let mut renderer = RecordingRenderer::default();
        shell.set_address_input("https://one.example");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        shell.toggle_active_bookmark().unwrap();
        let folder = shell.create_bookmark_folder("Research").unwrap();
        let bookmark = shell.bookmarks()[0].id;
        shell.move_bookmark(bookmark, Some(folder)).unwrap();
        shell.rename_bookmark(bookmark, "One site").unwrap();
        shell.queue_permission(PermissionPrompt {
            id: nomad_engine::PermissionPromptId::new(9),
            site: "https://one.example".into(),
            kind: PermissionKind::Camera,
        });
        shell
            .resolve_permission(
                nomad_engine::PermissionPromptId::new(9),
                PermissionDecision::Allow,
            )
            .unwrap();
        shell.new_tab();
        shell.set_address_input("https://two.example");
        shell.submit_address_with_renderer(&mut renderer).unwrap();

        let session = shell.save_session().unwrap();
        let mut restored = ShellState::new(runtime());
        let mut restore_renderer = RecordingRenderer::default();
        restored
            .restore_session_with_renderer(&session, &mut restore_renderer)
            .unwrap();

        assert_eq!(restored.history().len(), 2);
        assert_eq!(restored.bookmark_folders().len(), 1);
        assert_eq!(restored.bookmarks()[0].title, "One site");
        assert_eq!(
            restored.bookmarks()[0].folder_id,
            Some(restored.bookmark_folders()[0].id)
        );
        assert_eq!(restored.settings().privacy_mode, PrivacyMode::Hardened);
        assert_eq!(
            restored.permission_decision("https://one.example", PermissionKind::Camera),
            PermissionDecision::Allow
        );

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn test_session_restore_is_lazy_for_background_tabs() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell.set_address_input("https://one.example");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        shell.new_tab();
        shell.set_address_input("https://two.example");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        shell.new_tab();
        shell.set_address_input("https://three.example");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let session = shell.save_session().unwrap();

        let mut restored = ShellState::new(runtime());
        let mut restore_renderer = RecordingRenderer::default();
        restored
            .restore_session_with_renderer(&session, &mut restore_renderer)
            .unwrap();

        assert_eq!(restore_renderer.loaded.len(), 1);
        assert_eq!(restored.tabs()[0].lifecycle, TabLifecycle::Archived);
        assert_eq!(restored.tabs()[1].lifecycle, TabLifecycle::Archived);
        assert_eq!(restored.tabs()[2].lifecycle, TabLifecycle::Active);
    }

    #[test]
    fn test_memory_reclamation_suspends_low_priority_background_tabs() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        shell.new_tab();
        shell
            .set_tab_memory_estimate(first_tab, 4 * 1024 * 1024 * 1024)
            .unwrap();
        shell.set_memory_mode(MemoryMode::LowMemory);
        let mut renderer = RecordingRenderer::default();

        let suspended = shell.reclaim_memory_with_renderer(&mut renderer).unwrap();

        assert_eq!(suspended, vec![first_tab]);
        assert_eq!(
            shell.tab(first_tab).unwrap().lifecycle,
            TabLifecycle::Suspended
        );
        assert_eq!(renderer.released, vec![first_tab]);
    }

    #[test]
    fn test_tab_search_matches_url_and_tab_id() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        shell.set_address_input("https://alpha.example");
        shell.submit_address().unwrap();
        let second_tab = shell.new_tab();
        shell.set_address_input("https://beta.example");
        shell.submit_address().unwrap();

        let url_matches = shell.search_tabs("ALPHA");
        assert_eq!(url_matches.len(), 1);
        assert_eq!(url_matches[0].id, first_tab);
        assert!(!url_matches[0].active);

        let id_matches = shell.search_tabs(&second_tab.get().to_string());
        assert_eq!(id_matches.len(), 1);
        assert_eq!(id_matches[0].id, second_tab);
        assert!(id_matches[0].active);
        assert_eq!(shell.search_tabs("no-match"), Vec::new());
    }

    #[test]
    fn test_shell_exposes_download_lifecycle() {
        let directory =
            std::env::temp_dir().join(format!("nomad-shell-download-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let mut shell = ShellState::with_download_directory(runtime(), &directory);
        let tab_id = shell.active_tab();
        let id = shell
            .queue_download(DownloadRequest {
                tab_id,
                url: Url::parse("https://example.com/file.bin").unwrap(),
                suggested_filename: "file.bin".into(),
                total_bytes: Some(4),
            })
            .unwrap();

        shell.begin_download(id).unwrap();
        shell.receive_download_bytes(id, 4).unwrap();
        shell.complete_download(id).unwrap();

        assert_eq!(shell.downloads()[0].id, id);
        assert_eq!(
            shell.downloads()[0].state,
            nomad_engine::DownloadState::Completed
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_shell_toggles_and_opens_bookmarks() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell.set_address_input("https://example.com");
        shell.submit_address_with_renderer(&mut renderer).unwrap();

        shell.toggle_active_bookmark().unwrap();
        assert_eq!(shell.bookmarks().len(), 1);
        assert!(shell.is_bookmarked(&Url::parse("https://example.com/").unwrap()));

        let bookmark_id = shell.bookmarks()[0].id;
        shell.new_tab();
        shell
            .open_bookmark_with_renderer(bookmark_id, &mut renderer)
            .unwrap();
        assert_eq!(shell.address_bar().input(), "https://example.com/");

        shell.toggle_active_bookmark().unwrap();
        assert_eq!(shell.bookmarks().len(), 0);
    }

    #[test]
    fn test_open_bookmark_in_new_tab_keeps_current_page_open() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        shell.set_address_input("https://example.com");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let original_tab = shell.active_tab().unwrap();
        shell.toggle_active_bookmark().unwrap();
        let bookmark_id = shell.bookmarks()[0].id;

        let bookmark_tab = shell
            .open_bookmark_in_new_tab_with_renderer(bookmark_id, &mut renderer)
            .unwrap();

        assert_ne!(bookmark_tab, original_tab);
        assert_eq!(shell.active_tab(), Some(bookmark_tab));
        assert_eq!(shell.tabs().len(), 2);
        assert_eq!(
            shell
                .tab(original_tab)
                .unwrap()
                .url
                .as_ref()
                .unwrap()
                .as_str(),
            "https://example.com/"
        );
        assert_eq!(
            shell
                .tab(bookmark_tab)
                .unwrap()
                .url
                .as_ref()
                .unwrap()
                .as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_vertical_sidebar_tracks_visibility_and_collapsed_state() {
        let mut sidebar = VerticalTabSidebarState::default();

        assert!(sidebar.is_visible());
        assert!(!sidebar.is_collapsed());

        sidebar.set_visible(false);
        sidebar.set_collapsed(true);

        assert!(!sidebar.is_visible());
        assert!(sidebar.is_collapsed());
    }

    #[test]
    fn test_new_tab_updates_sidebar_and_clears_address_input() {
        let mut shell = ShellState::new(runtime());
        shell.set_address_input("https://example.com");
        let first_tab = shell.active_tab().unwrap();

        let second_tab = shell.new_tab();

        assert_ne!(first_tab, second_tab);
        assert_eq!(shell.active_tab(), Some(second_tab));
        assert_eq!(shell.address_bar().input(), "");
        assert_eq!(shell.sidebar().tab_ids(), &[first_tab, second_tab]);
    }

    #[test]
    fn test_user_new_tab_reuses_an_existing_blank_tab() {
        let mut shell = ShellState::new(runtime());
        let blank_tab = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();

        let selected = shell
            .focus_or_create_blank_tab_with_renderer(&mut renderer)
            .unwrap();
        let selected_again = shell
            .focus_or_create_blank_tab_with_renderer(&mut renderer)
            .unwrap();

        assert_eq!(selected, blank_tab);
        assert_eq!(selected_again, blank_tab);
        assert_eq!(shell.tabs().len(), 1);
        assert_eq!(shell.active_tab(), Some(blank_tab));
    }

    #[test]
    fn test_user_new_tab_creates_one_after_the_existing_tab_navigates() {
        let mut shell = ShellState::new(runtime());
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let navigated_tab = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();

        let blank_tab = shell
            .focus_or_create_blank_tab_with_renderer(&mut renderer)
            .unwrap();
        let selected_again = shell
            .focus_or_create_blank_tab_with_renderer(&mut renderer)
            .unwrap();

        assert_ne!(blank_tab, navigated_tab);
        assert_eq!(selected_again, blank_tab);
        assert_eq!(shell.tabs().len(), 2);
        assert_eq!(shell.active_tab(), Some(blank_tab));
    }

    #[test]
    fn test_select_tab_updates_sidebar_and_address_input() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();
        let second_tab = shell.new_tab();

        shell.select_tab(first_tab).unwrap();

        assert_eq!(shell.active_tab(), Some(first_tab));
        assert_eq!(shell.sidebar().active_tab(), Some(first_tab));
        assert_eq!(shell.address_bar().input(), "https://example.com/");
        assert_eq!(shell.tab(second_tab).unwrap().state, TabState::New);
    }

    #[test]
    fn test_select_tab_updates_the_visible_single_pane() {
        let mut shell = ShellState::new(runtime());
        let second_tab = shell.new_tab();

        shell.select_tab(second_tab).unwrap();

        assert_eq!(shell.split_layout().panes()[0].tab_id, second_tab);
    }

    #[test]
    fn test_select_tab_with_renderer_activates_tab_surface() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let second_tab = shell.new_tab();
        let mut renderer = RecordingRenderer::default();

        shell
            .select_tab_with_renderer(first_tab, &mut renderer)
            .unwrap();

        assert_eq!(renderer.activated, vec![first_tab]);
        assert_eq!(shell.active_tab(), Some(first_tab));
        assert_ne!(shell.active_tab(), Some(second_tab));
    }

    #[test]
    fn test_close_tab_updates_sidebar_and_selects_remaining_tab() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let second_tab = shell.new_tab();

        shell.close_tab(second_tab).unwrap();

        assert_eq!(shell.active_tab(), Some(first_tab));
        assert_eq!(shell.sidebar().active_tab(), Some(first_tab));
        assert_eq!(shell.sidebar().tab_ids(), &[first_tab]);
        assert_eq!(shell.tab(second_tab), None);
    }

    #[test]
    fn test_close_tab_with_renderer_activates_remaining_tab_surface() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let second_tab = shell.new_tab();
        let mut renderer = RecordingRenderer::default();

        shell
            .close_tab_with_renderer(second_tab, &mut renderer)
            .unwrap();

        assert_eq!(renderer.activated, vec![first_tab]);
        assert_eq!(shell.active_tab(), Some(first_tab));
        assert_eq!(shell.split_layout().panes()[0].tab_id, first_tab);
        assert_eq!(shell.tab(second_tab), None);
    }

    #[test]
    fn test_closing_last_tab_creates_persistent_blank_replacement() {
        let mut shell = ShellState::new(runtime());
        let original = shell.active_tab().unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address().unwrap();

        shell.close_tab(original).unwrap();

        let replacement = shell.active_tab().unwrap();
        assert_ne!(replacement, original);
        assert_eq!(shell.tabs().len(), 1);
        assert_eq!(shell.tab(replacement).unwrap().url, None);
        assert_eq!(shell.sidebar().tab_ids(), &[replacement]);
        assert_eq!(shell.split_layout().panes()[0].tab_id, replacement);
    }

    #[test]
    fn test_closing_last_tab_with_renderer_activates_blank_replacement() {
        let mut shell = ShellState::new(runtime());
        let original = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();

        shell
            .close_tab_with_renderer(original, &mut renderer)
            .unwrap();

        let replacement = shell.active_tab().unwrap();
        assert_ne!(replacement, original);
        assert_eq!(shell.tabs().len(), 1);
        assert_eq!(shell.tab(replacement).unwrap().url, None);
        assert_eq!(renderer.released, vec![original]);
        assert_eq!(renderer.activated, vec![replacement]);
    }

    #[test]
    fn test_selecting_missing_tab_does_not_change_shell_state() {
        let mut shell = ShellState::new(runtime());
        let active_tab = shell.active_tab().unwrap();
        let missing_tab = TabId::new(99);

        assert_eq!(
            shell.select_tab(missing_tab),
            Err(ShellError::MissingTab(missing_tab))
        );
        assert_eq!(shell.active_tab(), Some(active_tab));
        assert_eq!(shell.sidebar().active_tab(), Some(active_tab));
    }

    #[test]
    fn test_workspace_context_and_split_browsing_are_shell_features() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let workspace = shell.create_workspace("Work").unwrap();
        let container = shell.create_container("Corporate", false).unwrap();
        shell
            .assign_tab_context(first_tab, workspace, container)
            .unwrap();
        shell.select_workspace(workspace).unwrap();

        let second_tab = shell.new_tab();
        let pane = shell
            .split_tab(second_tab, SplitOrientation::Vertical)
            .unwrap();

        assert_eq!(shell.active_workspace(), workspace);
        assert_eq!(shell.tab_context(first_tab).container_id, container);
        assert_eq!(shell.split_layout().panes().len(), 2);
        assert_eq!(shell.split_layout().active_pane(), pane);
    }

    #[test]
    fn test_reorder_tab_moves_tab_to_anchor_position() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let second_tab = shell.new_tab();
        let third_tab = shell.new_tab();

        shell.reorder_tab(third_tab, first_tab).unwrap();

        assert_eq!(
            shell.sidebar().tab_ids(),
            &[third_tab, first_tab, second_tab]
        );
    }

    #[test]
    fn test_user_tab_groups_support_add_collapse_and_ungroup() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let second_tab = shell.new_tab();

        let group_id = shell.create_tab_group(first_tab).unwrap();
        shell.add_tab_to_group(group_id, second_tab).unwrap();

        let groups = shell.tab_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group_id);
        assert_eq!(groups[0].tab_ids, vec![first_tab, second_tab]);
        assert_eq!(shell.tab_group_of(second_tab), Some(group_id));

        // A tab lives in at most one group: re-grouping detaches it elsewhere.
        let third_tab = shell.new_tab();
        let other_group = shell.create_tab_group(third_tab).unwrap();
        shell.add_tab_to_group(other_group, first_tab).unwrap();
        assert_eq!(shell.tab_group_of(first_tab), Some(other_group));
        assert_eq!(shell.tab_groups().len(), 2);

        shell.set_tab_group_collapsed(group_id, true).unwrap();
        assert!(shell
            .tab_groups()
            .iter()
            .find(|group| group.id == group_id)
            .is_some_and(|group| group.collapsed));

        shell.remove_tab_from_group(first_tab).unwrap();
        assert_eq!(shell.tab_group_of(first_tab), None);

        shell.ungroup_tab_group(other_group).unwrap();
        assert_eq!(shell.tab_group_of(third_tab), None);
        assert!(shell.tabs().iter().any(|tab| tab.id == third_tab));
    }

    #[test]
    fn test_tab_groups_persist_in_session_snapshot() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        shell.set_address_input("https://example.com");
        let mut renderer = RecordingRenderer::default();
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let second_tab = shell.new_tab();
        let group_id = shell.create_tab_group(first_tab).unwrap();
        shell.add_tab_to_group(group_id, second_tab).unwrap();
        shell.set_tab_group_collapsed(group_id, true).unwrap();

        let raw_session = shell.save_session().unwrap();
        assert!(raw_session.contains("\"groups\""));

        let mut restored = ShellState::new(runtime());
        restored
            .restore_session_with_renderer(&raw_session, &mut renderer)
            .unwrap();

        let groups = restored.tab_groups();
        assert_eq!(groups.len(), 1);
        assert!(groups[0].collapsed);
        assert_eq!(groups[0].tab_ids.len(), 2);
        assert!(groups[0]
            .tab_ids
            .iter()
            .all(|tab_id| restored.tab(*tab_id).is_some()));
    }

    #[test]
    fn test_selecting_non_pane_tab_resets_split_layout() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let mut renderer = RecordingRenderer::default();
        let second_tab = shell.new_tab();
        shell
            .split_tab(second_tab, SplitOrientation::Horizontal)
            .unwrap();
        assert_eq!(shell.split_layout().panes().len(), 2);

        // A brand-new tab is not a pane: selecting it leaves split view.
        let third_tab = shell.new_tab();
        shell
            .select_tab_with_renderer(third_tab, &mut renderer)
            .unwrap();

        assert_eq!(shell.split_layout().panes().len(), 1);
        assert_eq!(shell.split_layout().panes()[0].tab_id, third_tab);
        assert_ne!(shell.split_layout().panes()[0].tab_id, first_tab);
    }

    #[test]
    fn test_split_pane_supports_mixed_orientation_nesting() {
        let mut shell = ShellState::new(runtime());
        let first_tab = shell.active_tab().unwrap();
        let second_tab = shell.new_tab();
        shell
            .split_tab(second_tab, SplitOrientation::Horizontal)
            .unwrap();

        let first_pane = shell.split_layout().pane_for_tab(first_tab).unwrap();
        let third_tab = shell.new_tab();
        shell
            .split_pane(first_pane, third_tab, SplitOrientation::Vertical)
            .unwrap();

        assert_eq!(shell.split_layout().panes().len(), 3);
        let rects = shell.split_layout().pane_rects(0.0, 0.0, 100.0, 100.0);
        assert!((rects[0].1.width - 50.0).abs() < 0.001);
        assert!((rects[0].1.height - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_switching_active_container_rebuilds_and_reloads_renderer_context() {
        let mut shell = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        let tab_id = shell.active_tab().unwrap();
        shell.set_address_input("https://example.com");
        shell.submit_address_with_renderer(&mut renderer).unwrap();
        let container = shell.create_container("Temporary", true).unwrap();

        shell
            .assign_active_tab_to_container_with_renderer(container, &mut renderer)
            .unwrap();

        assert_eq!(shell.tab_context(tab_id).container_id, container);
        assert_eq!(renderer.loaded.len(), 2);
    }

    #[test]
    fn test_reader_toggle_and_encrypted_session_round_trip() {
        let mut shell = ShellState::new(runtime());
        let tab_id = shell.active_tab().unwrap();
        let workspace = shell.create_workspace("Research").unwrap();
        let container = shell.create_container("Temporary", true).unwrap();
        shell
            .assign_tab_context(tab_id, workspace, container)
            .unwrap();
        shell.select_workspace(workspace).unwrap();
        assert_eq!(shell.reader_mode(tab_id), ReaderMode::Original);
        assert_eq!(
            shell.toggle_reader_mode(tab_id).unwrap(),
            ReaderMode::Reader
        );

        let envelope = shell.save_encrypted_session([5; 32]).unwrap();
        let mut restored = ShellState::new(runtime());
        let mut renderer = RecordingRenderer::default();
        restored
            .restore_encrypted_session_with_renderer(&envelope, [5; 32], &mut renderer)
            .unwrap();
        assert_eq!(restored.tabs().len(), 1);
        assert_eq!(restored.workspaces().len(), 2);
        assert_eq!(restored.active_workspace(), workspace);
        let restored_tab = restored.tabs()[0].id;
        assert_eq!(restored.tab_context(restored_tab).container_id, container);
    }

    #[test]
    fn test_sync_key_setup_recovery_selective_payload_and_file_transport() {
        let endpoint = std::env::temp_dir().join(format!(
            "nomad-shell-sync-{}-{}.json",
            std::process::id(),
            std::time::UNIX_EPOCH
                .elapsed()
                .expect("system clock is after the epoch")
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&endpoint);
        let mut settings = BrowserSettings::default();
        settings.sync.enabled = true;
        settings.sync.endpoint = endpoint.display().to_string();

        let mut source = ShellState::with_settings(runtime(), settings.clone());
        let phrase = source.setup_sync_key().unwrap();
        assert_eq!(
            source
                .sync_status()
                .key_fingerprint
                .as_deref()
                .unwrap()
                .len(),
            16
        );
        source.bookmarks.add(
            Url::parse("https://sync.example.test/").unwrap(),
            "Sync example",
        );
        source.sync_now().unwrap();

        let mut restored = ShellState::with_settings(runtime(), settings);
        assert!(restored.recover_sync_key(&phrase).is_ok());
        restored.pull_sync().unwrap();
        assert!(restored
            .bookmarks()
            .iter()
            .any(|bookmark| bookmark.url.as_str() == "https://sync.example.test/"));
        assert_eq!(restored.sync_status().pending_uploads, 0);
        let _ = std::fs::remove_file(endpoint);
    }

    #[test]
    fn test_workspace_resolver_override_precedence_and_hot_swap() {
        let mut shell = ShellState::new(runtime());

        // Global resolver applies while no workspace pins an override.
        let mut global = BrowserSettings::default();
        global.resolver.mode = nomad_engine::ResolverMode::Doh;
        global.resolver.server_url = "https://global.example/dns-query".to_owned();
        shell.apply_settings(global);
        assert_eq!(shell.resolver().mode(), &nomad_engine::ResolverMode::Doh);

        // Pinning an override on the active workspace hot-swaps the engine
        // away from the global settings.
        let workspace = shell.active_workspace();
        let pinned = nomad_engine::ResolverSettings {
            mode: nomad_engine::ResolverMode::Custom,
            custom_server: "1.1.1.1:5353".to_owned(),
            ..nomad_engine::ResolverSettings::default()
        };
        shell
            .set_workspace_resolver(workspace, Some(pinned.clone()))
            .unwrap();
        assert_eq!(shell.resolver().mode(), &nomad_engine::ResolverMode::Custom);
        assert_eq!(shell.effective_resolver_settings(), pinned);
        assert!(shell.resolver_override_active());

        // A second workspace without an override inherits the global.
        let inherited = shell.create_workspace("Inherited").unwrap();
        shell
            .select_workspace_with_renderer(inherited, &mut RecordingRenderer::default())
            .unwrap();
        assert_eq!(shell.resolver().mode(), &nomad_engine::ResolverMode::Doh);
        assert!(!shell.resolver_override_active());

        // Switching back re-applies the pinned override.
        shell
            .select_workspace_with_renderer(workspace, &mut RecordingRenderer::default())
            .unwrap();
        assert_eq!(shell.resolver().mode(), &nomad_engine::ResolverMode::Custom);
        assert!(shell.resolver_override_active());

        // Clearing the override returns the workspace to the global.
        shell.set_workspace_resolver(workspace, None).unwrap();
        assert_eq!(shell.resolver().mode(), &nomad_engine::ResolverMode::Doh);
        assert!(!shell.resolver_override_active());
    }

    #[test]
    fn test_invalid_workspace_override_falls_back_to_global() {
        let mut shell = ShellState::new(runtime());
        let mut global = BrowserSettings::default();
        global.resolver.mode = nomad_engine::ResolverMode::Dot;
        global.resolver.server_host = "dns.example".to_owned();
        shell.apply_settings(global);

        let workspace = shell.active_workspace();
        let invalid = nomad_engine::ResolverSettings {
            mode: nomad_engine::ResolverMode::Custom,
            // A plain-DNS server cannot be a hostname: it would recurse.
            custom_server: "dns.example".to_owned(),
            ..nomad_engine::ResolverSettings::default()
        };
        shell
            .set_workspace_resolver(workspace, Some(invalid))
            .unwrap();
        // The unusable override falls back to the global resolver instead
        // of leaving the engine with no working transport.
        assert_eq!(shell.resolver().mode(), &nomad_engine::ResolverMode::Dot);
    }

    #[test]
    fn test_workspace_resolver_override_persists_across_session_snapshot() {
        let mut source = ShellState::new(runtime());
        let mut settings = BrowserSettings::default();
        settings.resolver.mode = nomad_engine::ResolverMode::Doh;
        settings.resolver.server_url = "https://global.example/dns-query".to_owned();
        source.apply_settings(settings);

        let workspace = source.active_workspace();
        let pinned = nomad_engine::ResolverSettings {
            mode: nomad_engine::ResolverMode::Dot,
            server_host: "pinned.example".to_owned(),
            ..nomad_engine::ResolverSettings::default()
        };
        source
            .set_workspace_resolver(workspace, Some(pinned.clone()))
            .unwrap();
        let raw = source.save_session().unwrap();
        let mut restored = ShellState::new(runtime());
        restored
            .restore_session_with_renderer(&raw, &mut RecordingRenderer::default())
            .unwrap();
        assert_eq!(restored.resolver().mode(), &nomad_engine::ResolverMode::Dot);
        assert_eq!(
            restored
                .workspace(restored.active_workspace())
                .unwrap()
                .resolver,
            Some(pinned)
        );
    }

    #[test]
    fn test_workspace_override_transport_failure_is_fail_closed() {
        let mut shell = ShellState::new(runtime());
        let workspace = shell.active_workspace();
        let pinned = nomad_engine::ResolverSettings {
            mode: nomad_engine::ResolverMode::Dot,
            // Valid configuration, unreachable transport: loopback port 1
            // refuses connections. `localhost` would resolve through the
            // platform resolver, so any success would be a leak.
            server_host: "127.0.0.1:1".to_owned(),
            ..nomad_engine::ResolverSettings::default()
        };
        shell
            .set_workspace_resolver(workspace, Some(pinned))
            .unwrap();
        assert_eq!(shell.resolver().mode(), &nomad_engine::ResolverMode::Dot);
        let error = shell.resolver().resolve("localhost").unwrap_err();
        assert!(error.is_transport_failure());
        // The status surface reports the fail-closed outcome so the UI
        // can show it instead of leaving the failure silent.
        let status = shell.resolver().status();
        let last = status.last().unwrap();
        assert_eq!(last.mode, nomad_engine::ResolverMode::Dot);
        assert_eq!(last.host, "localhost");
        assert!(!last.success());
        assert!(last.transport_failure());
    }
}
