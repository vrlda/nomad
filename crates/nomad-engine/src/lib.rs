use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub use crate::extensions::{
    WebRequestBlockingDecision, WebRequestBlockingHandler, WebRequestBlockingRequest,
};
use nomad_core::{BackendAvailability, RouteError, RouteMode, Switches};
use url::Url;

pub mod bookmarks;
pub mod credentials;
pub mod devtools;
pub mod dns;
pub mod downloads;
pub mod extensions;
pub mod network;
pub mod oauth;
pub mod permissions;
pub mod platform;
pub mod privacy;
pub mod reader;
pub mod resources;
pub mod split;
pub mod sync;
pub mod translation;
pub mod umc;
pub mod update;
pub mod workspaces;
pub mod xray;

#[cfg(feature = "servo")]
pub mod servo;

#[cfg(feature = "servo")]
mod pdf;

#[cfg(feature = "servo")]
pub use ::servo::{MediaSessionActionType, MediaSessionEvent, MediaSessionPlaybackState};
#[cfg(feature = "servo")]
pub use servo::{MediaBackend, NavigationLoadStatus, ServoError, ServoRenderer};

pub use bookmarks::{
    Bookmark, BookmarkError, BookmarkFolder, BookmarkFolderId, BookmarkId, BookmarkManager,
};
pub use credentials::{
    classify_autofill_field, AutofillFieldDescriptor, AutofillFieldKind, CredentialStoreBackend,
    CredentialStoreError, OsCredentialStore,
};
pub use devtools::{
    filter_console_entries, ConsoleEntry, ConsoleLevel, DevToolsDomNode, DevToolsDomSnapshot,
    DevToolsEvaluation, DevToolsPageSnapshot, DevToolsSnapshot, DevToolsSource, DevToolsStore,
    DevToolsStyleSheet, NetworkRequestRecord,
};
pub use dns::{
    CustomResolverProtocol, DnsCache, ResolverConfigError, ResolverEngine, ResolverError,
    ResolverLookupStatus, ResolverMode, ResolverPath, ResolverSettings, ResolverStatus,
    DNS_CACHE_MAX_ENTRIES,
};
pub use downloads::{
    DownloadError, DownloadId, DownloadManager, DownloadRequest, DownloadSnapshot, DownloadState,
    DownloadTransportEvent,
};
pub use extensions::{
    extension_api_request, extension_resource_uri, permission_name, ExtensionAction,
    ExtensionAlarm, ExtensionApiRequest, ExtensionBackground, ExtensionBackgroundInfo,
    ExtensionBackgroundKind, ExtensionContentScript, ExtensionError, ExtensionEvent,
    ExtensionEventKind, ExtensionFrame, ExtensionFrameRegistry, ExtensionFrameTarget,
    ExtensionInjection, ExtensionManifest, ExtensionMessage, ExtensionPackage, ExtensionPermission,
    ExtensionRegistry, ExtensionRegistrySnapshot, ExtensionResource, ExtensionRuleset,
    ExtensionScriptWorld, ExtensionSnapshot, ExtensionStorage, ExtensionStorageArea,
    ExtensionTabInfo, PendingAuthFlow, PendingAuthFlowKind,
};
pub use network::{
    parse_proxy_endpoint, ConnectionState, DnsRoute, NetworkDiagnostics, NetworkProfile,
    NetworkProfileError, NetworkProfileStore, NetworkRoute, NetworkTelemetryEvent, ProxyEndpoint,
    ProxyEndpointError, ProxyScheme, RouteConfigError, RouteDecision, SiteRouteAction,
    SiteRoutePolicy, SiteRoutePolicyError,
};
pub use nomad_core::RouteSelection;
pub use oauth::{
    account_id_from_id_token, authorization_completion, build_authorize_url,
    challenge_from_verifier, exchange_request_body, generate_pkce_pair,
    redirect_matches_redirect_uri, redirect_uri_for_extension, refresh_request_body, token_key,
    HttpsTokenClient, OAuthFlowError, OAuthProviderConfig, OAuthTokenRecord, PkcePair,
    TokenExchange, TokenExchangeRequest, GOOGLE_OAUTH_AUTH_ENDPOINT, GOOGLE_OAUTH_TOKEN_ENDPOINT,
};
pub use permissions::{
    PermissionDecision, PermissionKind, PermissionManager, PermissionPromptId, PermissionRule,
};
pub use platform::{
    current_release_target, user_paths, Platform, PlatformPaths, ReleaseTarget, ReleaseTargetError,
};
pub use privacy::{
    security_info, PrivacyDiagnostics, PrivacyMode, PrivacyPolicy, ResourceBlockReason,
    SecurityInfo, SecurityLevel,
};
pub use reader::{reader_document_from_html, ReaderDocument, ReaderMode};
pub use resources::{
    browser_memory_bytes, MemoryDiagnostics, MemoryManager, MemoryMode, MemoryObservationSource,
    MemoryPressure, TabActivity, TabMemorySource, TabMemoryUsage, TabPriorityScore,
};
pub use split::{SplitError, SplitLayout, SplitOrientation, SplitPane, SplitPaneId, SplitRect};
pub use sync::{
    EncryptedSyncCodec, EncryptedSyncStore, FileSyncTransport, MemorySyncTransport, SyncConflict,
    SyncConflictChoice, SyncCryptoError, SyncKeyMaterial, SyncRecord, SyncTransport,
    SyncTransportError,
};
pub use translation::{
    EndpointTranslationExecutor, TranslationError, TranslationLanguage, TranslationProvider,
    TranslationRequest, TranslationResult,
};
pub use umc::{
    transport_url as umc_transport_url, ControlEnvelope, ControlEnvelopeError, UmcDatagram,
    UmcDiagnostics, UmcIdentityKind, UmcPathDiagnostics, UmcPathKind, UmcPeerTrustState,
    UmcResourceInfo, UmcSecurityInfo, UmcSessionDiagnostics, UmcSessionPrivacy, UmcSessionSecurity,
    UmcSessionState, UmcStreamRead, UmcTrustState, UmcUrlError,
};
pub use update::{
    verify_update, SignedUpdate, StagedUpdate, TrustedUpdateKey, UpdateAvailability, UpdateChannel,
    UpdateError, UpdateFeed, UpdateFeedError, UpdateInstallError, UpdateInstaller,
    UpdateInstallerError, UpdateManifest, UpdatePolicy, UpdateStager, UpdateStagingError,
    VerifiedUpdate,
};
pub use workspaces::{
    Container, ContainerId, TabContext, Workspace, WorkspaceError, WorkspaceId, WorkspaceManager,
};

/// Installs the single process-wide TLS provider used by Nomad and Servo.
///
/// The workspace enables both Rustls crypto backends because different
/// protocol stacks require different feature flags. Rustls cannot infer a
/// provider in that configuration, so the browser must choose one before any
/// network worker is created.
///
/// # Errors
///
/// Returns an error if another thread installs a provider between the
/// availability check and Nomad's installation attempt.
pub fn initialize_tls_provider() -> Result<(), &'static str> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "TLS crypto provider was already installed concurrently")
}

#[cfg(any(unix, windows))]
pub use umc::{
    UmcApplicationBridge, UmcApplicationSession, UmcApplicationSnapshot, UmcApplicationStream,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TabId(u64);

impl TabId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TabState {
    New,
    Loading,
    Active,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TabLifecycle {
    New,
    Active,
    Warm,
    Sleeping,
    Suspended,
    Archived,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TabSnapshot {
    pub id: TabId,
    pub url: Option<Url>,
    pub state: TabState,
    pub error: Option<NavigationError>,
    pub lifecycle: TabLifecycle,
    pub pinned: bool,
    pub keep_alive: bool,
    pub user_priority: i8,
    pub last_used_tick: u64,
    pub memory_bytes: u64,
    pub memory_source: TabMemorySource,
    pub restoration_cost: u8,
    pub activity: TabActivity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TabHistorySnapshot {
    pub entries: Vec<Url>,
    pub current_index: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryVisit {
    pub id: u64,
    pub tab_id: TabId,
    pub url: Url,
    pub visited_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavigationRequest {
    pub tab_id: TabId,
    pub url: Url,
    pub route: RouteMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NavigationError {
    MissingTab(TabId),
    InvalidUrl(String),
    UnsupportedScheme(String),
    RouteRequired(RouteMode),
    NoBackNavigation(TabId),
    NoForwardNavigation(TabId),
    BlockedByWebRequest(String),
    Render(RenderError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderError {
    BackendUnavailable,
}

pub trait PageRenderer {
    /// Requests a viewport screenshot for a tab. Renderers complete the
    /// request asynchronously and expose results through
    /// [`Self::take_tab_screenshots`].
    ///
    /// # Errors
    ///
    /// Returns a rendering error when screenshots are unavailable.
    fn request_tab_screenshot(&mut self, _tab_id: TabId) -> Result<(), RenderError> {
        Err(RenderError::BackendUnavailable)
    }

    /// Drains completed viewport screenshots as PNG byte strings.
    fn take_tab_screenshots(&mut self) -> Vec<(TabId, Result<Vec<u8>, RenderError>)> {
        Vec::new()
    }

    /// Applies a tab's storage/container identity before its first load.
    /// Renderers that do not expose browser storage partitions may keep the
    /// default no-op behavior.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the renderer cannot bind the container.
    fn configure_tab(
        &mut self,
        _tab_id: TabId,
        _container_id: workspaces::ContainerId,
        _ephemeral: bool,
    ) -> Result<(), RenderError> {
        Ok(())
    }

    /// Installs content scripts selected for the destination URL.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when script installation fails.
    fn install_extension_scripts(
        &mut self,
        _scripts: &[ExtensionInjection],
    ) -> Result<(), RenderError> {
        Ok(())
    }

    /// Installs content scripts into the renderer context owned by `tab_id`.
    /// Renderers with a shared user-content manager may use the legacy method;
    /// browser engines with per-document contexts should override this hook.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when script installation fails.
    fn install_extension_scripts_for_tab(
        &mut self,
        _tab_id: TabId,
        scripts: &[ExtensionInjection],
    ) -> Result<(), RenderError> {
        self.install_extension_scripts(scripts)
    }

    /// Publishes extension-origin resources to the renderer.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the resource store cannot be updated.
    fn install_extension_resources(
        &mut self,
        _resources: &[ExtensionResource],
    ) -> Result<(), RenderError> {
        Ok(())
    }

    /// Removes all resources owned by one extension from the renderer.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the resource store cannot be updated.
    fn uninstall_extension_resources(&mut self, _extension_id: &str) -> Result<(), RenderError> {
        Ok(())
    }

    /// Installs an extension background page or service-worker context.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the background context cannot be created.
    fn install_extension_background(
        &mut self,
        _extension_id: &str,
        _manifest: &ExtensionManifest,
        _script: &str,
        _service_worker: bool,
        _script_paths: &[String],
        _storage: &ExtensionStorage,
    ) -> Result<(), RenderError> {
        Ok(())
    }

    /// Dispatches a browser event into an extension background context.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the event cannot be delivered.
    fn dispatch_extension_event(&mut self, _event: &ExtensionEvent) -> Result<(), RenderError> {
        Ok(())
    }

    /// Polls background contexts for extension-to-browser messages.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the renderer cannot poll a context.
    fn request_extension_background_messages(&mut self) -> Result<(), RenderError> {
        Ok(())
    }

    /// Removes all renderer-side content scripts owned by an extension.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the backend cannot remove the scripts.
    fn uninstall_extension(&mut self, _extension_id: &str) -> Result<(), RenderError> {
        Ok(())
    }

    /// Polls the active document's `WebExtension` runtime-message queue.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the backend cannot evaluate the queue.
    fn request_extension_messages(&mut self, _tab_id: TabId) -> Result<(), RenderError> {
        Ok(())
    }

    /// Delivers a background message to content scripts in one tab.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the backend cannot evaluate the
    /// extension dispatch bridge.
    fn dispatch_extension_message(
        &mut self,
        _tab_id: TabId,
        _extension_id: &str,
        _payload: &serde_json::Value,
    ) -> Result<(), RenderError> {
        Ok(())
    }

    /// Takes messages collected by the renderer-side `WebExtension` bridge.
    fn take_extension_messages(&mut self) -> Vec<ExtensionMessage> {
        Vec::new()
    }

    /// Opens a browser-rendered extension action popup surface.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the popup surface cannot be created.
    fn open_extension_popup(
        &mut self,
        _extension_id: &str,
        _manifest: &ExtensionManifest,
        _source: &str,
        _resource_path: &str,
        _storage: &ExtensionStorage,
    ) -> Result<(), RenderError> {
        Err(RenderError::BackendUnavailable)
    }

    /// Executes a permission-checked extension script in the target document.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the document is unavailable.
    fn execute_extension_script(
        &mut self,
        _tab_id: TabId,
        _extension_id: &str,
        _source: &str,
    ) -> Result<(), RenderError> {
        Err(RenderError::BackendUnavailable)
    }
    /// Executes script in a specific frame. `None` targets top frame; other
    /// values are opaque Servo-owned pipeline handles.
    #[allow(clippy::missing_errors_doc)]
    fn execute_extension_script_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
        source: &str,
    ) -> Result<(), RenderError> {
        if frame_handle.is_some() {
            return Err(RenderError::BackendUnavailable);
        }
        self.execute_extension_script(tab_id, extension_id, source)
    }

    /// Injects a permission-checked stylesheet into the target document.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the document is unavailable.
    fn insert_extension_css(
        &mut self,
        _tab_id: TabId,
        _extension_id: &str,
        _source: &str,
    ) -> Result<(), RenderError> {
        Err(RenderError::BackendUnavailable)
    }
    #[allow(clippy::missing_errors_doc)]
    fn insert_extension_css_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
        source: &str,
    ) -> Result<(), RenderError> {
        if frame_handle.is_some() {
            return Err(RenderError::BackendUnavailable);
        }
        self.insert_extension_css(tab_id, extension_id, source)
    }

    #[allow(clippy::missing_errors_doc)]
    fn remove_extension_css_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
    ) -> Result<(), RenderError> {
        if frame_handle.is_some() {
            return Err(RenderError::BackendUnavailable);
        }
        self.remove_extension_css(tab_id, extension_id)
    }

    /// Removes the stylesheet previously injected by an extension.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the document is unavailable.
    fn remove_extension_css(
        &mut self,
        _tab_id: TabId,
        _extension_id: &str,
    ) -> Result<(), RenderError> {
        Err(RenderError::BackendUnavailable)
    }

    /// Performs a browser-owned cookie operation against Servo's cookie jar.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the cookie backend is unavailable.
    fn extension_cookie_operation(
        &mut self,
        _method: &str,
        _arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, RenderError> {
        Err(RenderError::BackendUnavailable)
    }

    #[allow(clippy::type_complexity)]
    fn take_extension_frame_tree_events(
        &mut self,
    ) -> Vec<(TabId, Vec<(u64, Option<u64>, String)>)> {
        Vec::new()
    }

    /// Updates the pre-request declarative extension blocking rules.
    fn set_extension_blocking_patterns(&mut self, _patterns: &[String]) {}

    /// Installs synchronous webRequest blocking callback.
    fn set_web_request_blocking_handler(
        &mut self,
        _handler: std::sync::Arc<dyn WebRequestBlockingHandler>,
    ) {
    }

    /// Applies the renderer's low-activity policy to a tab.
    ///
    /// # Errors
    ///
    /// Returns a rendering error when the backend cannot update throttling.
    fn set_tab_throttled(&mut self, _tab_id: TabId, _throttled: bool) -> Result<(), RenderError> {
        Ok(())
    }

    /// Loads a validated URL for a browser tab.
    ///
    /// The renderer must not mutate browser tab state directly. The runtime
    /// commits the navigation only after this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when the rendering backend cannot accept the load.
    fn load(&mut self, request: &NavigationRequest) -> Result<(), RenderError>;

    /// Reloads the current document without creating a competing navigation.
    /// Renderers with a native reload primitive should override this method.
    ///
    /// # Errors
    ///
    /// Returns an error when the rendering backend cannot reload the page.
    fn reload(&mut self, request: &NavigationRequest) -> Result<(), RenderError> {
        self.load(request)
    }

    /// Makes a tab's renderer surface visible and active.
    ///
    /// The default implementation is suitable for renderers that expose a
    /// single shared surface.
    ///
    /// # Errors
    ///
    /// Returns an error when the rendering backend cannot activate the tab.
    fn activate(&mut self, _tab_id: TabId) -> Result<(), RenderError> {
        Ok(())
    }

    /// Releases renderer resources associated with a browser tab.
    ///
    /// The default implementation is suitable for renderers that do not hold
    /// per-tab resources outside the runtime.
    ///
    /// # Errors
    ///
    /// Returns an error when the rendering backend cannot release the tab.
    fn release(&mut self, _tab_id: TabId) -> Result<(), RenderError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TabError {
    MissingTab(TabId),
    Render(RenderError),
    ActiveTabCannotBeSuspended(TabId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineError {
    Route(RouteError),
}

impl From<RouteError> for EngineError {
    fn from(error: RouteError) -> Self {
        Self::Route(error)
    }
}

pub struct BrowserRuntime {
    switches: Switches,
    route: RouteMode,
    availability: BackendAvailability,
    next_tab_id: u64,
    next_visit_id: u64,
    next_usage_tick: u64,
    tabs: Vec<TabSnapshot>,
    histories: HashMap<TabId, TabHistory>,
    visits: Vec<HistoryVisit>,
    history_enabled: bool,
    active_tab: Option<TabId>,
}

/// Bounds the global persisted visit list. It survives sessions, so an
/// uncapped Vec grows without limit across the browser's lifetime.
const MAX_PERSISTED_HISTORY_VISITS: usize = 10_000;

/// Caps the back/forward entry list so a single tab's history cannot grow
/// without limit over its lifetime. Forward entries are already truncated on
/// navigate; this bounds the retained back entries.
const MAX_TAB_HISTORY_ENTRIES: usize = 512;

#[derive(Default)]
struct TabHistory {
    entries: Vec<Url>,
    current_index: Option<usize>,
}

impl BrowserRuntime {
    /// Creates a browser runtime after validating its selected network route.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected UMC or Xray backend is unavailable.
    pub fn new(switches: Switches, availability: BackendAvailability) -> Result<Self, EngineError> {
        let selection = RouteSelection::resolve(switches, availability)?;

        Ok(Self {
            switches,
            route: selection.route(),
            availability,
            next_tab_id: 1,
            next_visit_id: 1,
            next_usage_tick: 1,
            tabs: Vec::new(),
            histories: HashMap::new(),
            visits: Vec::new(),
            history_enabled: true,
            active_tab: None,
        })
    }

    #[must_use]
    pub fn tabs(&self) -> &[TabSnapshot] {
        &self.tabs
    }

    #[must_use]
    pub const fn active_tab(&self) -> Option<TabId> {
        self.active_tab
    }

    #[must_use]
    pub const fn route(&self) -> RouteMode {
        self.route
    }

    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics only if the runtime's internal validated-route invariant has
    /// been violated.
    pub fn route_selection(&self) -> nomad_core::RouteSelection {
        RouteSelection::resolve(self.switches, self.availability)
            .expect("BrowserRuntime stores only validated route selections")
    }

    #[must_use]
    pub fn history(&self) -> &[HistoryVisit] {
        &self.visits
    }

    #[must_use]
    pub fn recent_history(&self, limit: usize) -> Vec<HistoryVisit> {
        self.visits.iter().rev().take(limit).cloned().collect()
    }

    #[must_use]
    pub fn search_history(&self, query: &str) -> Vec<HistoryVisit> {
        let query = query.trim().to_ascii_lowercase();
        self.visits
            .iter()
            .rev()
            .filter(|visit| {
                query.is_empty() || visit.url.as_str().to_ascii_lowercase().contains(&query)
            })
            .cloned()
            .collect()
    }

    #[must_use]
    pub const fn history_enabled(&self) -> bool {
        self.history_enabled
    }

    pub fn set_history_enabled(&mut self, enabled: bool) {
        self.history_enabled = enabled;
        if !enabled {
            self.visits.clear();
        }
    }

    /// Replaces persisted browser history after session tabs have been rebuilt.
    pub fn replace_history(&mut self, visits: Vec<HistoryVisit>) {
        self.next_visit_id = visits
            .iter()
            .map(|visit| visit.id)
            .max()
            .unwrap_or_default()
            .saturating_add(1);
        self.visits = visits;
    }

    /// Records a synthetic visit without a backing tab (used by
    /// `history.addUrl`); the visit keeps the normal scheme gating.
    pub fn record_visit_for_url(&mut self, url: Url) {
        self.record_visit(TabId::new(0), url);
    }

    /// Removes every visit for `url`, returning whether any were removed.
    #[must_use]
    pub fn delete_history_url(&mut self, url: &Url) -> bool {
        let before = self.visits.len();
        self.visits.retain(|visit| &visit.url != url);
        self.visits.len() != before
    }

    /// Removes visits whose timestamps fall within the inclusive range.
    pub fn delete_history_range(&mut self, start_time: u64, end_time: u64) -> Vec<HistoryVisit> {
        let mut removed = Vec::new();
        self.visits.retain(|visit| {
            if (start_time..=end_time).contains(&visit.visited_at) {
                removed.push(visit.clone());
                false
            } else {
                true
            }
        });
        removed
    }

    /// Clears the whole history, returning the number of removed visits.
    #[must_use]
    pub fn clear_history(&mut self) -> usize {
        let removed = self.visits.len();
        self.visits.clear();
        removed
    }

    #[must_use]
    pub fn tab(&self, tab_id: TabId) -> Option<&TabSnapshot> {
        self.tabs.iter().find(|tab| tab.id == tab_id)
    }

    pub fn new_tab(&mut self) -> TabId {
        for tab in &mut self.tabs {
            if tab.lifecycle == TabLifecycle::Active {
                tab.lifecycle = TabLifecycle::Warm;
            }
        }
        let tab_id = TabId::new(self.next_tab_id);
        self.next_tab_id = self.next_tab_id.saturating_add(1);
        self.tabs.push(TabSnapshot {
            id: tab_id,
            url: None,
            state: TabState::New,
            error: None,
            lifecycle: TabLifecycle::Active,
            pinned: false,
            keep_alive: false,
            user_priority: 0,
            last_used_tick: self.next_usage_tick,
            memory_bytes: 64 * 1024 * 1024,
            memory_source: TabMemorySource::Estimated,
            restoration_cost: 1,
            activity: TabActivity::default(),
        });
        self.next_usage_tick = self.next_usage_tick.saturating_add(1);
        self.histories.insert(tab_id, TabHistory::default());
        self.active_tab = Some(tab_id);
        tab_id
    }

    /// Returns the committed navigation entries for a tab and its current
    /// history position.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn tab_history(&self, tab_id: TabId) -> Result<TabHistorySnapshot, TabError> {
        let history = self
            .histories
            .get(&tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        Ok(TabHistorySnapshot {
            entries: history.entries.clone(),
            current_index: history.current_index,
        })
    }

    /// Reports whether a tab has a previous navigation entry.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn can_go_back(&self, tab_id: TabId) -> Result<bool, TabError> {
        let history = self
            .histories
            .get(&tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        Ok(history.current_index.is_some_and(|index| index > 0))
    }

    /// Reports whether a tab has a forward navigation entry.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn can_go_forward(&self, tab_id: TabId) -> Result<bool, TabError> {
        let history = self
            .histories
            .get(&tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        Ok(history
            .current_index
            .is_some_and(|index| index.saturating_add(1) < history.entries.len()))
    }

    /// Navigates a tab to a supported URL and marks it as loading.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist, the URL cannot be parsed,
    /// or the URL uses a scheme outside the browser navigation boundary.
    pub fn navigate(&mut self, tab_id: TabId, raw_url: &str) -> Result<(), NavigationError> {
        if self.tab(tab_id).is_none() {
            return Err(NavigationError::MissingTab(tab_id));
        }
        let url = parse_navigation_url(raw_url)?;
        self.ensure_route_for_url(&url)?;
        self.commit_new_navigation(tab_id, url)
    }

    /// Navigates a tab through a rendering backend and commits the tab state
    /// only after the backend accepts the load.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist, the URL cannot be parsed,
    /// the URL uses an unsupported scheme, or the renderer rejects the load.
    pub fn navigate_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        raw_url: &str,
        renderer: &mut R,
    ) -> Result<(), NavigationError> {
        if self.tab(tab_id).is_none() {
            return Err(NavigationError::MissingTab(tab_id));
        }
        let url = parse_navigation_url(raw_url)?;
        self.ensure_route_for_url(&url)?;
        let request = NavigationRequest {
            tab_id,
            url,
            route: self.route,
        };
        if let Err(error) = renderer.load(&request) {
            let error = NavigationError::Render(error);
            self.mark_navigation_error(tab_id, error.clone())?;
            return Err(error);
        }

        self.commit_new_navigation(tab_id, request.url)
    }

    /// Reloads a tab through the renderer without creating a new history
    /// entry. This is used when a privacy-mode boundary requires a fresh
    /// renderer storage context.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no committed URL or the renderer
    /// rejects the reload.
    pub fn reload_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), NavigationError> {
        let url = self
            .tab(tab_id)
            .ok_or(NavigationError::MissingTab(tab_id))?
            .url
            .clone()
            .ok_or(NavigationError::InvalidUrl(
                "tab has no committed URL".to_owned(),
            ))?;
        self.ensure_route_for_url(&url)?;
        renderer
            .reload(&NavigationRequest {
                tab_id,
                url,
                route: self.route,
            })
            .map_err(NavigationError::Render)
    }

    /// Moves a tab to its previous committed URL through a renderer.
    ///
    /// The history cursor and tab URL change only after the renderer accepts
    /// the target. A failed render leaves the cursor on the previous entry and
    /// records an explicit error on the tab.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is missing, has no previous entry, or the
    /// renderer rejects the target.
    pub fn go_back_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), NavigationError> {
        self.move_history_with_renderer(tab_id, HistoryDirection::Back, renderer)
    }

    /// Moves a tab to its next committed URL through a renderer.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is missing, has no forward entry, or the
    /// renderer rejects the target.
    pub fn go_forward_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), NavigationError> {
        self.move_history_with_renderer(tab_id, HistoryDirection::Forward, renderer)
    }

    /// Marks a tab's current navigation as active.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist.
    pub fn finish_navigation(&mut self, tab_id: TabId) -> Result<(), TabError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.state = TabState::Active;
        tab.error = None;
        if tab.lifecycle == TabLifecycle::New {
            tab.lifecycle = TabLifecycle::Warm;
        }
        Ok(())
    }

    /// Selects a tab in the browser's active tab set.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist.
    pub fn select_tab(&mut self, tab_id: TabId) -> Result<(), TabError> {
        if self.tab(tab_id).is_none() {
            return Err(TabError::MissingTab(tab_id));
        }
        self.mark_tab_active(tab_id)?;
        Ok(())
    }

    /// Activates a tab's renderer surface before changing the active tab.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist or the renderer cannot
    /// activate its surface. The active tab remains unchanged on failure.
    pub fn select_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), TabError> {
        if self.tab(tab_id).is_none() {
            return Err(TabError::MissingTab(tab_id));
        }
        let (lifecycle, url) = {
            let tab = self.tab(tab_id).ok_or(TabError::MissingTab(tab_id))?;
            (tab.lifecycle, tab.url.clone())
        };
        if matches!(lifecycle, TabLifecycle::Suspended | TabLifecycle::Archived) {
            if let Some(url) = url {
                renderer
                    .load(&NavigationRequest {
                        tab_id,
                        url,
                        route: self.route,
                    })
                    .map_err(TabError::Render)?;
            }
        }
        renderer.activate(tab_id).map_err(TabError::Render)?;
        renderer
            .set_tab_throttled(tab_id, false)
            .map_err(TabError::Render)?;
        self.mark_tab_active(tab_id)?;
        Ok(())
    }

    /// Marks a background tab as suspended after releasing renderer resources.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is missing, active, or the renderer cannot
    /// release its resources.
    pub fn suspend_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), TabError> {
        let lifecycle = self
            .tab(tab_id)
            .ok_or(TabError::MissingTab(tab_id))?
            .lifecycle;
        if self.active_tab == Some(tab_id) {
            return Err(TabError::ActiveTabCannotBeSuspended(tab_id));
        }
        if matches!(lifecycle, TabLifecycle::Suspended | TabLifecycle::Archived) {
            return Ok(());
        }
        renderer.release(tab_id).map_err(TabError::Render)?;
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.lifecycle = TabLifecycle::Suspended;
        tab.memory_bytes = 0;
        tab.memory_source = TabMemorySource::Estimated;
        Ok(())
    }

    /// Recreates a suspended tab's renderer and makes it active.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is missing or the renderer cannot reload
    /// the saved page.
    pub fn resume_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), TabError> {
        self.select_tab_with_renderer(tab_id, renderer)
    }

    /// Restricts background execution without releasing the renderer surface.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is missing or is active.
    pub fn sleep_tab(&mut self, tab_id: TabId) -> Result<(), TabError> {
        if self.active_tab == Some(tab_id) {
            return Err(TabError::ActiveTabCannotBeSuspended(tab_id));
        }
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        if tab.lifecycle == TabLifecycle::Warm {
            tab.lifecycle = TabLifecycle::Sleeping;
        }
        Ok(())
    }

    /// Throttles a background tab in the renderer and records its sleeping
    /// lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is active, missing, or the renderer
    /// cannot apply throttling.
    pub fn sleep_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), TabError> {
        let lifecycle = self
            .tab(tab_id)
            .ok_or(TabError::MissingTab(tab_id))?
            .lifecycle;
        if self.active_tab == Some(tab_id) {
            return Err(TabError::ActiveTabCannotBeSuspended(tab_id));
        }
        if lifecycle != TabLifecycle::Warm {
            return Ok(());
        }
        renderer
            .set_tab_throttled(tab_id, true)
            .map_err(TabError::Render)?;
        self.sleep_tab(tab_id)
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
    ) -> Result<(), TabError> {
        self.select_tab_with_renderer(tab_id, renderer)
    }

    /// Restores tab metadata without creating a renderer surface.
    ///
    /// This is used by lazy session restoration for background tabs.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn restore_tab_metadata(
        &mut self,
        tab_id: TabId,
        url: Option<Url>,
        lifecycle: TabLifecycle,
    ) -> Result<(), TabError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.url = url;
        tab.state = if tab.url.is_some() {
            TabState::Active
        } else {
            TabState::New
        };
        tab.error = None;
        tab.lifecycle = lifecycle;
        if matches!(lifecycle, TabLifecycle::Suspended | TabLifecycle::Archived) {
            tab.memory_bytes = 0;
            tab.memory_source = TabMemorySource::Estimated;
        }
        Ok(())
    }

    /// Updates a tab's measured or estimated resident memory for diagnostics and policy.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn set_tab_memory_usage(
        &mut self,
        tab_id: TabId,
        memory_bytes: u64,
        memory_source: TabMemorySource,
    ) -> Result<(), TabError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.memory_bytes = memory_bytes;
        tab.memory_source = memory_source;
        Ok(())
    }

    /// Stores an exact memory sample reported by the embedded Servo engine.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn set_tab_memory_measurement(
        &mut self,
        tab_id: TabId,
        memory_bytes: u64,
    ) -> Result<(), TabError> {
        self.set_tab_memory_usage(tab_id, memory_bytes, TabMemorySource::Servo)
    }

    /// Pins or unpins a tab so automatic suspension will protect it.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn set_tab_pinned(&mut self, tab_id: TabId, pinned: bool) -> Result<(), TabError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.pinned = pinned;
        Ok(())
    }

    /// Moves `tab_id` to the list position currently occupied by `anchor`,
    /// persisting the sidebar drag-and-drop order in the tab list itself.
    /// Split-pane references hold `TabId`s, so reordering never invalidates
    /// them. Self-anchored moves are a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when either tab does not exist.
    pub fn move_tab(&mut self, tab_id: TabId, anchor: TabId) -> Result<(), TabError> {
        if tab_id == anchor {
            return self
                .tabs
                .iter()
                .any(|tab| tab.id == tab_id)
                .then_some(())
                .ok_or(TabError::MissingTab(tab_id));
        }
        let from = self
            .tabs
            .iter()
            .position(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        let to = self
            .tabs
            .iter()
            .position(|tab| tab.id == anchor)
            .ok_or(TabError::MissingTab(anchor))?;
        let moved = self.tabs.remove(from);
        self.tabs.insert(to, moved);
        Ok(())
    }

    /// Enables or disables automatic suspension for a tab.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn set_tab_keep_alive(&mut self, tab_id: TabId, keep_alive: bool) -> Result<(), TabError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.keep_alive = keep_alive;
        Ok(())
    }

    /// Sets user-defined priority for a tab.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn set_tab_priority(&mut self, tab_id: TabId, priority: i8) -> Result<(), TabError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.user_priority = priority.clamp(-10, 10);
        Ok(())
    }

    /// Updates live activity flags used by the resource manager.
    ///
    /// Activity is runtime-only and is intentionally not persisted in a
    /// session snapshot. The browser shell refreshes it from media, download,
    /// WebRTC, form, `DevTools`, and worker events.
    ///
    /// # Errors
    ///
    /// Returns [`TabError::MissingTab`] when the tab does not exist.
    pub fn set_tab_activity(
        &mut self,
        tab_id: TabId,
        activity: TabActivity,
    ) -> Result<(), TabError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.activity = activity;
        Ok(())
    }

    /// Closes a tab and selects the newest remaining tab when needed.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist.
    pub fn close_tab(&mut self, tab_id: TabId) -> Result<(), TabError> {
        let index = self
            .tabs
            .iter()
            .position(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        self.tabs.remove(index);
        self.histories.remove(&tab_id);

        if self.active_tab == Some(tab_id) {
            self.active_tab = self.tabs.last().map(|tab| tab.id);
            if let Some(active_tab) = self.active_tab {
                let _ = self.mark_tab_active(active_tab);
            }
        }

        Ok(())
    }

    /// Releases renderer resources and closes a tab.
    ///
    /// The tab remains available when the renderer cannot release its
    /// resources.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab does not exist or the renderer rejects
    /// the release.
    pub fn close_tab_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        renderer: &mut R,
    ) -> Result<(), TabError> {
        if self.tab(tab_id).is_none() {
            return Err(TabError::MissingTab(tab_id));
        }
        renderer.release(tab_id).map_err(TabError::Render)?;
        self.close_tab(tab_id)
    }

    /// Changes the selected route without changing existing tab state.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected UMC or Xray backend is unavailable.
    /// The previous route remains active in that case.
    pub fn set_switches(&mut self, switches: Switches) -> Result<(), EngineError> {
        let selection = RouteSelection::resolve(switches, self.availability)?;
        self.switches = switches;
        self.route = selection.route();
        Ok(())
    }

    fn commit_new_navigation(&mut self, tab_id: TabId, url: Url) -> Result<(), NavigationError> {
        let history = self
            .histories
            .get_mut(&tab_id)
            .ok_or(NavigationError::MissingTab(tab_id))?;
        if let Some(current_index) = history.current_index {
            history.entries.truncate(current_index.saturating_add(1));
        }
        history.entries.push(url.clone());
        if history.entries.len() > MAX_TAB_HISTORY_ENTRIES {
            let drop_count = history.entries.len() - MAX_TAB_HISTORY_ENTRIES;
            history.entries.drain(0..drop_count);
        }
        history.current_index = Some(history.entries.len().saturating_sub(1));
        self.set_tab_loading(tab_id, Some(url.clone()))?;
        self.touch_tab(tab_id)
            .map_err(|_| NavigationError::MissingTab(tab_id))?;
        self.record_visit(tab_id, url);
        Ok(())
    }

    fn ensure_route_for_url(&self, url: &Url) -> Result<(), NavigationError> {
        if url.scheme() == "umc" && self.route != RouteMode::Umc {
            return Err(NavigationError::RouteRequired(RouteMode::Umc));
        }
        Ok(())
    }

    fn move_history_with_renderer<R: PageRenderer>(
        &mut self,
        tab_id: TabId,
        direction: HistoryDirection,
        renderer: &mut R,
    ) -> Result<(), NavigationError> {
        let (target_index, target_url) = self.history_target(tab_id, direction)?;
        let request = NavigationRequest {
            tab_id,
            url: target_url.clone(),
            route: self.route,
        };
        if let Err(error) = renderer.load(&request) {
            let error = NavigationError::Render(error);
            self.mark_navigation_error(tab_id, error.clone())?;
            return Err(error);
        }

        let history = self
            .histories
            .get_mut(&tab_id)
            .ok_or(NavigationError::MissingTab(tab_id))?;
        history.current_index = Some(target_index);
        self.set_tab_loading(tab_id, Some(target_url))
    }

    fn history_target(
        &self,
        tab_id: TabId,
        direction: HistoryDirection,
    ) -> Result<(usize, Url), NavigationError> {
        let history = self
            .histories
            .get(&tab_id)
            .ok_or(NavigationError::MissingTab(tab_id))?;
        let current_index = history.current_index;
        let target_index = match direction {
            HistoryDirection::Back => current_index
                .filter(|index| *index > 0)
                .map(|index| index - 1)
                .ok_or(NavigationError::NoBackNavigation(tab_id))?,
            HistoryDirection::Forward => current_index
                .filter(|index| index.saturating_add(1) < history.entries.len())
                .map(|index| index + 1)
                .ok_or(NavigationError::NoForwardNavigation(tab_id))?,
        };
        Ok((target_index, history.entries[target_index].clone()))
    }

    fn set_tab_loading(&mut self, tab_id: TabId, url: Option<Url>) -> Result<(), NavigationError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(NavigationError::MissingTab(tab_id))?;
        tab.url = url;
        tab.state = TabState::Loading;
        tab.error = None;
        if self.active_tab == Some(tab_id) {
            tab.lifecycle = TabLifecycle::Active;
        } else if tab.lifecycle == TabLifecycle::New {
            tab.lifecycle = TabLifecycle::Warm;
        }
        Ok(())
    }

    fn mark_tab_active(&mut self, tab_id: TabId) -> Result<(), TabError> {
        if self.tab(tab_id).is_none() {
            return Err(TabError::MissingTab(tab_id));
        }
        for tab in &mut self.tabs {
            if tab.id != tab_id && tab.lifecycle == TabLifecycle::Active {
                tab.lifecycle = TabLifecycle::Warm;
            }
        }
        self.active_tab = Some(tab_id);
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.lifecycle = TabLifecycle::Active;
        if tab.memory_bytes == 0 {
            tab.memory_bytes = 64 * 1024 * 1024;
            tab.memory_source = TabMemorySource::Estimated;
        }
        self.touch_tab(tab_id)
    }

    fn touch_tab(&mut self, tab_id: TabId) -> Result<(), TabError> {
        let tick = self.next_usage_tick;
        self.next_usage_tick = self.next_usage_tick.saturating_add(1);
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(TabError::MissingTab(tab_id))?;
        tab.last_used_tick = tick;
        Ok(())
    }

    fn mark_navigation_error(
        &mut self,
        tab_id: TabId,
        error: NavigationError,
    ) -> Result<(), NavigationError> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == tab_id)
            .ok_or(NavigationError::MissingTab(tab_id))?;
        tab.state = TabState::Error;
        tab.error = Some(error);
        Ok(())
    }

    fn record_visit(&mut self, tab_id: TabId, url: Url) {
        if !self.history_enabled || !matches!(url.scheme(), "file" | "http" | "https" | "umc") {
            return;
        }
        let visit = HistoryVisit {
            id: self.next_visit_id,
            tab_id,
            url,
            visited_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| {
                    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
                }),
        };
        self.next_visit_id = self.next_visit_id.saturating_add(1);
        self.visits.push(visit);
        if self.visits.len() > MAX_PERSISTED_HISTORY_VISITS {
            let drop_count = self.visits.len() - MAX_PERSISTED_HISTORY_VISITS;
            self.visits.drain(0..drop_count);
        }
    }
}

#[derive(Clone, Copy)]
enum HistoryDirection {
    Back,
    Forward,
}

fn parse_navigation_url(raw_url: &str) -> Result<Url, NavigationError> {
    let url = Url::parse(raw_url).map_err(|_| NavigationError::InvalidUrl(raw_url.to_owned()))?;
    let scheme = url.scheme();

    if !matches!(
        scheme,
        "about" | "file" | "http" | "https" | "umc" | "nomad-extension"
    ) {
        return Err(NavigationError::UnsupportedScheme(scheme.to_owned()));
    }
    if scheme == "file"
        && url
            .host_str()
            .is_some_and(|host| !host.eq_ignore_ascii_case("localhost"))
    {
        return Err(NavigationError::InvalidUrl(raw_url.to_owned()));
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use nomad_core::{BackendAvailability, RouteError, RouteMode, Switches};
    use url::Url;

    use super::{
        initialize_tls_provider, BrowserRuntime, NavigationError, NavigationRequest, PageRenderer,
        RenderError, TabError, TabId, TabLifecycle, TabState,
    };

    #[derive(Default)]
    struct RecordingRenderer {
        loaded: Vec<NavigationRequest>,
        activated: Vec<super::TabId>,
        released: Vec<super::TabId>,
        throttled: Vec<(super::TabId, bool)>,
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

        fn activate(&mut self, tab_id: super::TabId) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.activated.push(tab_id);
            Ok(())
        }

        fn release(&mut self, tab_id: super::TabId) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.released.push(tab_id);
            Ok(())
        }

        fn set_tab_throttled(
            &mut self,
            tab_id: super::TabId,
            throttled: bool,
        ) -> Result<(), RenderError> {
            if self.fail {
                return Err(RenderError::BackendUnavailable);
            }
            self.throttled.push((tab_id, throttled));
            Ok(())
        }
    }

    fn runtime() -> BrowserRuntime {
        BrowserRuntime::new(Switches::default(), BackendAvailability::all_available())
            .expect("direct mode should always initialize")
    }

    #[test]
    fn test_runtime_starts_without_tabs() {
        let runtime = runtime();

        assert!(runtime.tabs().is_empty());
        assert_eq!(runtime.active_tab(), None);
        assert_eq!(runtime.route(), RouteMode::Direct);
    }

    #[test]
    fn test_new_tab_becomes_active() {
        let mut runtime = runtime();

        let tab_id = runtime.new_tab();

        assert_eq!(runtime.active_tab(), Some(tab_id));
        assert_eq!(runtime.tab(tab_id).unwrap().state, TabState::New);
    }

    #[test]
    fn test_new_tab_selects_latest_tab() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();

        assert_ne!(first_tab, second_tab);
        assert_eq!(runtime.active_tab(), Some(second_tab));
        assert_eq!(runtime.tabs().len(), 2);
    }

    #[test]
    fn test_background_tab_lifecycle_suspends_and_resumes_renderer() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime
            .navigate(first_tab, "https://background.example")
            .unwrap();
        assert_eq!(
            runtime.tab(first_tab).unwrap().lifecycle,
            TabLifecycle::Warm
        );
        assert_eq!(
            runtime.tab(second_tab).unwrap().lifecycle,
            TabLifecycle::Active
        );

        runtime
            .suspend_tab_with_renderer(first_tab, &mut renderer)
            .unwrap();
        assert_eq!(
            runtime.tab(first_tab).unwrap().lifecycle,
            TabLifecycle::Suspended
        );
        assert_eq!(renderer.released, vec![first_tab]);

        runtime
            .resume_tab_with_renderer(first_tab, &mut renderer)
            .unwrap();
        assert_eq!(runtime.active_tab(), Some(first_tab));
        assert_eq!(
            runtime.tab(first_tab).unwrap().lifecycle,
            TabLifecycle::Active
        );
        assert_eq!(renderer.loaded.len(), 1);
        assert_eq!(renderer.activated, vec![first_tab]);
    }

    #[test]
    fn test_active_tab_cannot_be_suspended() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        assert_eq!(
            runtime.suspend_tab_with_renderer(tab_id, &mut renderer),
            Err(TabError::ActiveTabCannotBeSuspended(tab_id))
        );
    }

    #[test]
    fn test_background_tab_can_sleep_without_releasing_renderer() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime.sleep_tab(first_tab).unwrap();

        assert_eq!(
            runtime.tab(first_tab).unwrap().lifecycle,
            TabLifecycle::Sleeping
        );
        assert!(renderer.released.is_empty());
        runtime
            .wake_tab_with_renderer(first_tab, &mut renderer)
            .unwrap();
        assert_eq!(runtime.active_tab(), Some(first_tab));
        assert_eq!(
            runtime.tab(second_tab).unwrap().lifecycle,
            TabLifecycle::Warm
        );
    }

    #[test]
    fn test_background_tab_sleep_throttles_renderer() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let _second_tab = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime
            .sleep_tab_with_renderer(first_tab, &mut renderer)
            .unwrap();

        assert_eq!(renderer.throttled, vec![(first_tab, true)]);
        assert_eq!(
            runtime.tab(first_tab).unwrap().lifecycle,
            TabLifecycle::Sleeping
        );

        runtime
            .wake_tab_with_renderer(first_tab, &mut renderer)
            .unwrap();
        assert_eq!(
            renderer.throttled,
            vec![(first_tab, true), (first_tab, false)]
        );
    }

    #[test]
    fn test_navigate_accepts_supported_web_and_umc_urls() {
        let mut runtime =
            BrowserRuntime::new(Switches::umc(), BackendAvailability::new(true, false)).unwrap();
        let tab_id = runtime.new_tab();

        runtime.navigate(tab_id, "https://example.com").unwrap();
        assert_eq!(runtime.tab(tab_id).unwrap().state, TabState::Loading);
        assert_eq!(
            runtime.tab(tab_id).unwrap().url.as_ref().unwrap().as_str(),
            "https://example.com/"
        );

        runtime.navigate(tab_id, "umc://service-id/home").unwrap();
        assert_eq!(
            runtime.tab(tab_id).unwrap().url.as_ref().unwrap().as_str(),
            "umc://service-id/home"
        );
    }

    #[test]
    fn test_umc_navigation_requires_umc_route() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();

        assert_eq!(
            runtime.navigate(tab_id, "umc://service-id/home"),
            Err(NavigationError::RouteRequired(RouteMode::Umc))
        );
    }

    #[test]
    fn test_navigation_history_tracks_back_forward_and_truncates_forward_entries() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime.navigate(tab_id, "https://one.example").unwrap();
        runtime.navigate(tab_id, "https://two.example").unwrap();
        runtime.navigate(tab_id, "https://three.example").unwrap();

        assert!(!runtime.can_go_forward(tab_id).unwrap());
        assert!(runtime.can_go_back(tab_id).unwrap());

        runtime
            .go_back_with_renderer(tab_id, &mut renderer)
            .unwrap();
        runtime
            .go_back_with_renderer(tab_id, &mut renderer)
            .unwrap();
        assert_eq!(
            runtime.tab(tab_id).unwrap().url.as_ref().unwrap().as_str(),
            "https://one.example/"
        );
        assert!(!runtime.can_go_back(tab_id).unwrap());
        assert!(runtime.can_go_forward(tab_id).unwrap());

        runtime
            .navigate(tab_id, "https://replacement.example")
            .unwrap();
        let history = runtime.tab_history(tab_id).unwrap();
        assert_eq!(
            history.entries.iter().map(Url::as_str).collect::<Vec<_>>(),
            vec!["https://one.example/", "https://replacement.example/",]
        );
        assert_eq!(history.current_index, Some(1));
        assert!(!runtime.can_go_forward(tab_id).unwrap());
    }

    #[test]
    fn test_browser_history_records_new_web_visits_and_supports_queries() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();

        runtime.navigate(tab_id, "about:blank").unwrap();
        runtime.navigate(tab_id, "https://one.example").unwrap();
        runtime
            .navigate(tab_id, "https://two.example/path")
            .unwrap();

        assert_eq!(runtime.history().len(), 2);
        assert_eq!(runtime.history()[0].id, 1);
        assert_eq!(runtime.history()[0].tab_id, tab_id);
        assert_eq!(
            runtime.recent_history(1)[0].url.as_str(),
            "https://two.example/path"
        );
        assert_eq!(runtime.search_history("ONE").len(), 1);
        assert_eq!(runtime.search_history("missing").len(), 0);
    }

    #[test]
    fn test_browser_history_delete_range_returns_only_matching_visits() {
        let mut runtime = runtime();
        runtime.record_visit_for_url(Url::parse("https://one.example").unwrap());
        runtime.record_visit_for_url(Url::parse("https://two.example").unwrap());
        let middle = runtime.history()[0].visited_at;
        runtime.visits[1].visited_at = middle.saturating_add(1);

        let removed = runtime.delete_history_range(middle, middle);

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].url.as_str(), "https://one.example/");
        assert_eq!(runtime.history().len(), 1);
        assert_eq!(runtime.history()[0].url.as_str(), "https://two.example/");
    }

    #[test]
    fn test_browser_history_does_not_record_back_forward_as_new_visits() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime.navigate(tab_id, "https://one.example").unwrap();
        runtime.navigate(tab_id, "https://two.example").unwrap();
        runtime
            .go_back_with_renderer(tab_id, &mut renderer)
            .unwrap();
        runtime
            .go_forward_with_renderer(tab_id, &mut renderer)
            .unwrap();

        assert_eq!(runtime.history().len(), 2);
    }

    #[test]
    fn test_history_navigation_requires_a_target_entry() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        assert_eq!(
            runtime.go_back_with_renderer(tab_id, &mut renderer),
            Err(NavigationError::NoBackNavigation(tab_id))
        );
        runtime.navigate(tab_id, "https://example.com").unwrap();
        assert_eq!(
            runtime.go_forward_with_renderer(tab_id, &mut renderer),
            Err(NavigationError::NoForwardNavigation(tab_id))
        );
    }

    #[test]
    fn test_navigate_rejects_unsupported_schemes() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();

        assert_eq!(
            runtime.navigate(tab_id, "javascript:alert(1)"),
            Err(NavigationError::UnsupportedScheme("javascript".into()))
        );
    }

    #[test]
    fn test_navigate_accepts_local_file_resources() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();

        runtime.navigate(tab_id, "file:///tmp/nomad.html").unwrap();

        assert_eq!(
            runtime.tab(tab_id).and_then(|tab| tab.url.as_ref()),
            Some(&Url::parse("file:///tmp/nomad.html").unwrap())
        );
        assert_eq!(runtime.history().len(), 1);
    }

    #[test]
    fn test_navigate_rejects_remote_file_authorities() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();

        assert_eq!(
            runtime.navigate(tab_id, "file://remote-host/share/nomad.html"),
            Err(NavigationError::InvalidUrl(
                "file://remote-host/share/nomad.html".into()
            ))
        );
    }

    #[test]
    fn test_navigate_with_renderer_sends_url_to_backend() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime
            .navigate_with_renderer(tab_id, "https://example.com", &mut renderer)
            .unwrap();

        assert_eq!(renderer.loaded.len(), 1);
        assert_eq!(renderer.loaded[0].tab_id, tab_id);
        assert_eq!(renderer.loaded[0].url.as_str(), "https://example.com/");
        assert_eq!(renderer.loaded[0].route, RouteMode::Direct);
        assert_eq!(runtime.tab(tab_id).unwrap().state, TabState::Loading);
    }

    #[test]
    fn test_reload_with_renderer_preserves_history() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime.navigate(tab_id, "https://example.com").unwrap();
        let history_before = runtime.tab_history(tab_id).unwrap();
        runtime
            .reload_tab_with_renderer(tab_id, &mut renderer)
            .unwrap();

        assert_eq!(renderer.loaded.len(), 1);
        assert_eq!(renderer.loaded[0].url.as_str(), "https://example.com/");
        assert_eq!(runtime.tab_history(tab_id).unwrap(), history_before);
    }

    #[test]
    fn test_close_tab_with_renderer_releases_backend_before_removing_tab() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime
            .close_tab_with_renderer(tab_id, &mut renderer)
            .unwrap();

        assert_eq!(renderer.released, vec![tab_id]);
        assert_eq!(runtime.tab(tab_id), None);
        assert!(runtime.tabs().is_empty());
        assert_eq!(runtime.active_tab(), None);
    }

    #[test]
    fn test_close_tab_with_renderer_preserves_tab_when_release_fails() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer {
            fail: true,
            ..RecordingRenderer::default()
        };

        assert_eq!(
            runtime.close_tab_with_renderer(tab_id, &mut renderer),
            Err(TabError::Render(RenderError::BackendUnavailable))
        );
        assert!(runtime.tab(tab_id).is_some());
        assert_eq!(runtime.active_tab(), Some(tab_id));
    }

    #[test]
    fn test_navigate_with_renderer_marks_tab_error_when_backend_fails() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        let mut renderer = RecordingRenderer {
            fail: true,
            ..RecordingRenderer::default()
        };

        assert_eq!(
            runtime.navigate_with_renderer(tab_id, "https://example.com", &mut renderer),
            Err(NavigationError::Render(RenderError::BackendUnavailable))
        );
        assert_eq!(runtime.tab(tab_id).unwrap().url, None);
        assert_eq!(runtime.tab(tab_id).unwrap().state, TabState::Error);
        assert_eq!(
            runtime.tab(tab_id).unwrap().error,
            Some(NavigationError::Render(RenderError::BackendUnavailable))
        );
    }

    #[test]
    fn test_history_render_failure_preserves_cursor_and_marks_tab_error() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        runtime.navigate(tab_id, "https://one.example").unwrap();
        runtime.navigate(tab_id, "https://two.example").unwrap();
        let mut renderer = RecordingRenderer {
            fail: true,
            ..RecordingRenderer::default()
        };

        assert_eq!(
            runtime.go_back_with_renderer(tab_id, &mut renderer),
            Err(NavigationError::Render(RenderError::BackendUnavailable))
        );
        assert_eq!(
            runtime.tab(tab_id).unwrap().url.as_ref().unwrap().as_str(),
            "https://two.example/"
        );
        assert_eq!(runtime.tab_history(tab_id).unwrap().current_index, Some(1));
        assert_eq!(runtime.tab(tab_id).unwrap().state, TabState::Error);
    }

    #[test]
    fn test_navigate_rejects_missing_tab() {
        let mut runtime = runtime();

        assert_eq!(
            runtime.navigate(super::TabId::new(99), "https://example.com"),
            Err(NavigationError::MissingTab(super::TabId::new(99)))
        );
    }

    #[test]
    fn test_finish_navigation_marks_tab_active() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        runtime.navigate(tab_id, "https://example.com").unwrap();

        runtime.finish_navigation(tab_id).unwrap();

        assert_eq!(runtime.tab(tab_id).unwrap().state, TabState::Active);
    }

    #[test]
    fn test_tls_provider_initialization_is_explicit_and_idempotent() {
        initialize_tls_provider().unwrap();
        initialize_tls_provider().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn test_select_tab_changes_active_tab() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();

        runtime.select_tab(first_tab).unwrap();

        assert_eq!(runtime.active_tab(), Some(first_tab));
        assert_ne!(runtime.active_tab(), Some(second_tab));
    }

    #[test]
    fn test_select_tab_with_renderer_activates_backend_before_commit() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();
        let mut renderer = RecordingRenderer::default();

        runtime
            .select_tab_with_renderer(first_tab, &mut renderer)
            .unwrap();

        assert_eq!(renderer.activated, vec![first_tab]);
        assert_eq!(runtime.active_tab(), Some(first_tab));
        assert_eq!(runtime.tab(second_tab).unwrap().state, TabState::New);
    }

    #[test]
    fn test_select_tab_with_renderer_preserves_active_tab_when_backend_fails() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();
        let mut renderer = RecordingRenderer {
            fail: true,
            ..RecordingRenderer::default()
        };

        assert_eq!(
            runtime.select_tab_with_renderer(first_tab, &mut renderer),
            Err(TabError::Render(RenderError::BackendUnavailable))
        );
        assert_eq!(runtime.active_tab(), Some(second_tab));
    }

    #[test]
    fn test_close_active_tab_selects_remaining_tab() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();

        runtime.close_tab(second_tab).unwrap();

        assert_eq!(runtime.active_tab(), Some(first_tab));
        assert_eq!(runtime.tabs().len(), 1);
        assert_eq!(runtime.tab(second_tab), None);
    }

    #[test]
    fn test_move_tab_repositions_tab_at_anchor_slot() {
        let mut runtime = runtime();
        let first_tab = runtime.new_tab();
        let second_tab = runtime.new_tab();
        let third_tab = runtime.new_tab();

        runtime.move_tab(third_tab, first_tab).unwrap();

        let order: Vec<_> = runtime.tabs().iter().map(|tab| tab.id).collect();
        assert_eq!(order, vec![third_tab, first_tab, second_tab]);
    }

    #[test]
    fn test_move_tab_rejects_missing_tabs() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();

        assert_eq!(
            runtime.move_tab(TabId::new(999), tab_id),
            Err(TabError::MissingTab(TabId::new(999)))
        );
        assert_eq!(
            runtime.move_tab(tab_id, TabId::new(999)),
            Err(TabError::MissingTab(TabId::new(999)))
        );
    }

    #[test]
    fn test_move_tab_self_anchor_is_validated_noop() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();

        runtime.move_tab(tab_id, tab_id).unwrap();
        assert_eq!(
            runtime.move_tab(TabId::new(999), TabId::new(999)),
            Err(TabError::MissingTab(TabId::new(999)))
        );
    }

    #[test]
    fn test_enabling_unavailable_route_preserves_existing_route() {
        let mut runtime =
            BrowserRuntime::new(Switches::default(), BackendAvailability::new(false, true))
                .unwrap();

        assert_eq!(
            runtime.set_switches(Switches::umc()),
            Err(RouteError::UmcUnavailable.into())
        );
        assert_eq!(runtime.route(), RouteMode::Direct);
    }

    #[test]
    fn test_switching_route_does_not_change_existing_tabs() {
        let mut runtime = runtime();
        let tab_id = runtime.new_tab();
        runtime.navigate(tab_id, "https://example.com").unwrap();

        runtime.set_switches(Switches::xray()).unwrap();

        assert_eq!(runtime.route(), RouteMode::Xray);
        assert_eq!(
            runtime.tab(tab_id).unwrap().url.as_ref().unwrap().as_str(),
            "https://example.com/"
        );
    }
}
