use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{Display, Formatter};
use std::io::Cursor;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cookie::Cookie;
use crossbeam_channel::Receiver as WebDriverReceiver;
use euclid::{Point2D, Rect, Scale, Size2D};
use http::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use http::Method;
use image::{DynamicImage, ImageFormat};
use keyboard_types::{Code, Key, KeyState, Location, Modifiers, NamedKey};
use serde::Deserialize;
use servo::profile_traits::mem::MemoryReportResult;
use servo::{
    AllowOrDenyRequest, ConsoleLogLevel, CreateNewWebViewRequest, Cursor as ServoCursor,
    DeviceIntPoint, DeviceIntSize, DevicePoint, DownloadEvent as ServoDownloadEvent,
    DownloadRequest as ServoDownloadRequest, GenericCallback, InputEvent,
    InterceptedWebResourceLoad, KeyboardEvent, MediaSessionActionType, MediaSessionEvent,
    MouseButton as ServoMouseButton, MouseButtonAction, MouseButtonEvent, MouseLeftViewportEvent,
    MouseMoveEvent, OffscreenRenderingContext, PermissionFeature, PermissionRequest, PrefValue,
    RenderingContext, Servo, ServoBuilder, ServoDelegate, Theme, UserContentManager, UserScript,
    UserScriptWorld, WebDriverCommandMsg, WebDriverLoadStatus, WebDriverScriptCommand,
    WebResourceLoad, WebResourceResponse, WebView, WebViewBuilder, WebViewDelegate, WheelDelta,
    WheelEvent, WheelMode, WindowRenderingContext,
};
use url::Url;
use winit::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::keyboard::{Key as WinitKey, ModifiersState, NamedKey as WinitNamedKey};
use winit::raw_window_handle::{HasDisplayHandle, HasWindowHandle};
use winit::window::{CursorIcon, Window};

use super::{
    extension_resource_uri, AutofillFieldDescriptor, ConsoleEntry, ConsoleLevel,
    DevToolsDomSnapshot, DevToolsEvaluation, DevToolsPageSnapshot, DownloadId, DownloadRequest,
    DownloadTransportEvent, ExtensionEvent, ExtensionEventKind, ExtensionInjection,
    ExtensionManifest, ExtensionMessage, ExtensionResource, ExtensionStorage, NavigationRequest,
    NetworkDiagnostics, NetworkRequestRecord, NetworkRoute, NetworkTelemetryEvent, PageRenderer,
    PermissionKind, PermissionPromptId, PrivacyMode, PrivacyPolicy, RenderError,
    ResourceBlockReason, SiteRouteAction, TabId, UmcDiagnostics,
};
use crate::extensions::{
    WebRequestBlockingDecision, WebRequestBlockingHandler, WebRequestBlockingRequest,
};
use crate::workspaces::ContainerId;

pub use servo::EventLoopWaker;

struct NomadServoDelegate;

impl ServoDelegate for NomadServoDelegate {
    fn request_devtools_connection(&self, request: AllowOrDenyRequest) {
        // The remote inspector is only enabled by an explicit loopback CLI
        // option. There is no browser-wide network exposure to authorize here.
        request.allow();
    }
}

struct AllowAllWebRequestBlockingHandler;

impl WebRequestBlockingHandler for AllowAllWebRequestBlockingHandler {
    fn decide(&self, _request: &WebRequestBlockingRequest) -> WebRequestBlockingDecision {
        WebRequestBlockingDecision::default()
    }
}

const PENDING_EVENT_QUEUE_LIMIT: usize = 4_096;

fn push_bounded_event<T>(queue: &mut Vec<T>, value: T) {
    if queue.len() >= PENDING_EVENT_QUEUE_LIMIT {
        let drop_count = queue.len() - PENDING_EVENT_QUEUE_LIMIT + 1;
        queue.drain(..drop_count);
    }
    queue.push(value);
}

const PRIVACY_BASE_SCRIPT: &str = r#"
(() => {
    const navigatorPrototype = Object.getPrototypeOf(navigator);
    const defineStable = (name, value) => {
        try {
            Object.defineProperty(navigatorPrototype, name, {
                configurable: false,
                enumerable: true,
                get: () => value,
            });
        } catch (_) {}
    };
    defineStable("hardwareConcurrency", 4);
    defineStable("deviceMemory", 4);
    defineStable("maxTouchPoints", 0);
})();
"#;

const PRIVACY_WEBRTC_BLOCK_SCRIPT: &str = r#"
(() => {
    try {
        Object.defineProperty(window, "RTCPeerConnection", {
            configurable: true,
            get: () => undefined,
        });
    } catch (_) {}
    try {
        Object.defineProperty(navigator, "mediaDevices", {
            configurable: true,
            get: () => undefined,
        });
    } catch (_) {}
})();
"#;

const PRIVACY_WEBRTC_ALLOW_SCRIPT: &str = r"
(() => {
    try { delete window.RTCPeerConnection; } catch (_) {}
    try { delete navigator.mediaDevices; } catch (_) {}
})();
";

const PRIVACY_ADVANCED_SCRIPT: &str = r#"
(() => {
    const defineStable = (target, name, value) => {
        try {
            Object.defineProperty(target, name, {
                configurable: false,
                enumerable: true,
                get: () => value,
            });
        } catch (_) {}
    };
    defineStable(navigator, "platform", "Nomad");
    defineStable(navigator, "language", "en-US");
    defineStable(navigator, "languages", Object.freeze(["en-US"]));

    const quantize = (value) => Math.max(0, Math.min(255, Math.round(value / 8) * 8));
    const sanitizeImageData = (image) => {
        for (let index = 0; index < image.data.length; index += 4) {
            image.data[index] = quantize(image.data[index]);
            image.data[index + 1] = quantize(image.data[index + 1]);
            image.data[index + 2] = quantize(image.data[index + 2]);
        }
        return image;
    };

    if (window.CanvasRenderingContext2D) {
        const contextPrototype = CanvasRenderingContext2D.prototype;
        const originalGetImageData = contextPrototype.getImageData;
        try {
            Object.defineProperty(contextPrototype, "getImageData", {
                configurable: false,
                value: function(...args) {
                    return sanitizeImageData(originalGetImageData.apply(this, args));
                },
            });
        } catch (_) {}
    }

    const patchCanvasReadback = (prototype) => {
        if (!prototype) return;
        const originalToDataURL = prototype.toDataURL;
        const originalToBlob = prototype.toBlob;
        const sanitizedCanvas = (source) => {
            const copy = document.createElement("canvas");
            copy.width = source.width;
            copy.height = source.height;
            const context = copy.getContext("2d");
            if (!context) return null;
            context.drawImage(source, 0, 0);
            const image = sanitizeImageData(context.getImageData(0, 0, copy.width, copy.height));
            context.putImageData(image, 0, 0);
            return copy;
        };
        try {
            Object.defineProperty(prototype, "toDataURL", {
                configurable: false,
                value: function(...args) {
                    const copy = sanitizedCanvas(this);
                    return copy ? originalToDataURL.apply(copy, args) : originalToDataURL.apply(this, args);
                },
            });
            Object.defineProperty(prototype, "toBlob", {
                configurable: false,
                value: function(callback, ...args) {
                    const copy = sanitizedCanvas(this);
                    return originalToBlob.call(copy || this, callback, ...args);
                },
            });
        } catch (_) {}
    };
    if (window.HTMLCanvasElement) patchCanvasReadback(HTMLCanvasElement.prototype);

    const patchWebgl = (prototype) => {
        if (!prototype) return;
        const originalGetParameter = prototype.getParameter;
        const originalGetExtension = prototype.getExtension;
        const originalGetSupportedExtensions = prototype.getSupportedExtensions;
        try {
            Object.defineProperty(prototype, "getParameter", {
                configurable: false,
                value: function(parameter) {
                    if (parameter === 37445) return "Nomad WebGL";
                    if (parameter === 37446) return "Nomad Renderer";
                    return originalGetParameter.call(this, parameter);
                },
            });
            Object.defineProperty(prototype, "getExtension", {
                configurable: false,
                value: function(name) {
                    if (name === "WEBGL_debug_renderer_info") return null;
                    return originalGetExtension.call(this, name);
                },
            });
            Object.defineProperty(prototype, "getSupportedExtensions", {
                configurable: false,
                value: function() {
                    return (originalGetSupportedExtensions.call(this) || [])
                        .filter((name) => name !== "WEBGL_debug_renderer_info");
                },
            });
        } catch (_) {}
    };
    patchWebgl(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchWebgl(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);

    try {
        const originalDateTimeFormat = Intl.DateTimeFormat;
        const NomadDateTimeFormat = function(locales, options) {
            const normalized = Object.assign({}, options || {}, { timeZone: "UTC" });
            return new originalDateTimeFormat(locales || "en-US", normalized);
        };
        NomadDateTimeFormat.prototype = originalDateTimeFormat.prototype;
        Object.defineProperty(Intl, "DateTimeFormat", {
            configurable: false,
            value: NomadDateTimeFormat,
        });
    } catch (_) {}
})();
"#;

const PAGE_ZOOM_LEVELS: [f32; 17] = [
    0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0,
];

fn stepped_page_zoom(current: f32, increase: bool) -> f32 {
    const EPSILON: f32 = 0.001;
    if increase {
        PAGE_ZOOM_LEVELS
            .iter()
            .copied()
            .find(|level| *level > current + EPSILON)
            .unwrap_or(*PAGE_ZOOM_LEVELS.last().expect("page zoom levels exist"))
    } else {
        PAGE_ZOOM_LEVELS
            .iter()
            .rev()
            .copied()
            .find(|level| *level < current - EPSILON)
            .unwrap_or(PAGE_ZOOM_LEVELS[0])
    }
}

fn privacy_script(policy: PrivacyPolicy) -> String {
    let mut script = PRIVACY_BASE_SCRIPT.to_owned();
    if policy.block_webrtc() {
        script.push_str(PRIVACY_WEBRTC_BLOCK_SCRIPT);
    }
    if policy.advanced_fingerprinting() {
        script.push_str(PRIVACY_ADVANCED_SCRIPT);
    }
    script
}

/// Preferences used by Nomad's native Servo embedder.
///
/// Servo keeps several interoperable web-platform APIs disabled by default
/// because its standalone shell treats them as experimental. Nomad is an
/// application embedder, so its browser baseline must make those APIs part of
/// the renderer contract explicitly. APIs that still need an embedder-side
/// permission or device backend remain disabled until that contract exists.
fn nomad_preferences() -> servo::Preferences {
    servo::Preferences {
        dom_abort_controller_enabled: true,
        dom_adoptedstylesheet_enabled: true,
        dom_allow_preloading_module_descendants: true,
        dom_async_clipboard_enabled: true,
        dom_canvas_capture_enabled: true,
        dom_canvas_text_enabled: true,
        dom_clipboardevent_enabled: true,
        dom_composition_event_enabled: true,
        dom_cookiestore_enabled: true,
        dom_credential_management_enabled: true,
        dom_crypto_subtle_enabled: true,
        dom_entries_api_enabled: true,
        dom_fontface_enabled: true,
        dom_indexeddb_enabled: true,
        dom_intersection_observer_enabled: true,
        dom_mutation_observer_enabled: true,
        dom_navigator_protocol_handlers_enabled: true,
        dom_offscreen_canvas_enabled: true,
        dom_permissions_enabled: true,
        dom_resize_observer_enabled: true,
        dom_sanitizer_enabled: true,
        dom_serviceworker_enabled: true,
        dom_sharedworker_enabled: true,
        dom_storage_manager_api_enabled: true,
        dom_worklet_enabled: true,
        dom_visual_viewport_enabled: true,
        // Servo's Web Animations DOM implementation currently parses keyframes but
        // does not play the resulting Animation. Advertising Element.animate()
        // causes animation libraries to choose a non-functional native code path
        // instead of their JavaScript fallback, leaving reveal content invisible.
        // Keep the experimental API disabled until Servo implements playback.
        dom_web_animations_enabled: false,
        dom_webgpu_enabled: true,
        dom_webgl2_enabled: true,
        dom_webrtc_enabled: true,
        dom_webrtc_transceiver_enabled: true,
        layout_columns_enabled: true,
        layout_container_queries_enabled: true,
        layout_css_alpha_color_function_enabled: true,
        layout_css_attr_enabled: true,
        layout_css_ellipse_corners_enabled: true,
        layout_css_progress_function_enabled: true,
        layout_grid_enabled: true,
        layout_variable_fonts_enabled: true,
        layout_writing_mode_enabled: true,
        largest_contentful_paint_enabled: true,
        media_glvideo_enabled: cfg!(feature = "media-gstreamer"),
        accessibility_enabled: true,
        ..servo::Preferences::default()
    }
}

fn start_webdriver_server(
    preferences: &servo::Preferences,
    waker: Box<dyn EventLoopWaker>,
    port: Option<u16>,
) -> Result<Option<WebDriverReceiver<servo::WebDriverCommandMsg>>, ServoError> {
    let Some(port) = port else {
        return Ok(None);
    };
    if port == 0 {
        return Err(ServoError::Native(
            "WebDriver port must be non-zero".to_owned(),
        ));
    }
    // Keep the native event loop authoritative under command floods. The
    // HTTP server reports a send failure once this bounded ingress queue is
    // full instead of allowing automation traffic to grow without limit.
    let (sender, receiver) = crossbeam_channel::bounded(256);
    let identity = webdriver_server::WebDriverIdentity::new("nomad", env!("CARGO_PKG_VERSION"))
        .with_capability(
            "nomad:capabilities",
            serde_json::json!({
                "protocolVersion": 1,
                "engine": "servo",
                "transport": "loopback-http",
                "nativeShell": true,
                "automationTabs": "isolated",
                "features": ["script", "actions", "screenshots", "multi-window"]
            }),
        );
    webdriver_server::start_server_with_identity(
        port,
        sender,
        waker,
        preferences.clone(),
        identity,
    );
    Ok(Some(receiver))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServoError {
    InvalidInitialUrl(String),
    Native(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaBackend {
    GStreamer,
    Dummy,
}

/// Load milestones emitted by the embedded Servo webview delegate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavigationLoadStatus {
    Started,
    HeadParsed,
    Complete,
}

impl Display for ServoError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInitialUrl(url) => write!(formatter, "invalid initial URL: {url}"),
            Self::Native(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for ServoError {}

/// Start times of in-flight web resource loads, keyed by (webview, URL, resource type).
type WebResourceLoadStarts = Arc<Mutex<VecDeque<((servo::WebViewId, String, String), Instant)>>>;

/// Pending page-title change events per webview.
type PageTitleEvents = Arc<Mutex<Vec<(servo::WebViewId, Option<String>)>>>;

/// Pending autofill descriptors per tab.
type AutofillSnapshots = Arc<Mutex<Vec<(TabId, Vec<AutofillFieldDescriptor>)>>>;

/// Callback that composes a Servo offscreen surface into its parent window.
type RenderToParentCallback =
    Box<dyn Fn(&glow::Context, euclid::Rect<i32, euclid::UnknownUnit>, i32) + Send + Sync>;

type RenderingContexts = (
    Rc<WindowRenderingContext>,
    Rc<OffscreenRenderingContext>,
    PhysicalSize<u32>,
);

type ExtensionFrameTreeEvents =
    Arc<Mutex<Vec<(servo::WebViewId, Vec<(u64, Option<u64>, String)>)>>>;

/// Window and offscreen page rendering contexts with the initial content size.
struct FrameDelegate {
    window: Rc<Window>,
    dirty_webviews: Arc<Mutex<HashSet<servo::WebViewId>>>,
    download_sender: std::sync::mpsc::Sender<PendingDownload>,
    pdf_load_sender: Sender<PendingPdfLoad>,
    permission_requests: Rc<RefCell<Vec<PendingPermission>>>,
    privacy_policy: Rc<RefCell<PrivacyPolicy>>,
    network_route: Rc<RefCell<NetworkRoute>>,
    extension_block_patterns: Rc<RefCell<Vec<String>>>,
    web_request_blocking_handler: Arc<Mutex<Arc<dyn WebRequestBlockingHandler>>>,
    extension_resources: Arc<Mutex<HashMap<(String, String), ExtensionResource>>>,
    background_webview_ids: Arc<Mutex<HashSet<(String, servo::WebViewId)>>>,
    blocked_resource_count: Arc<AtomicU64>,
    blocked_ad_count: Arc<AtomicU64>,
    blocked_tracker_count: Arc<AtomicU64>,
    console_messages: Arc<Mutex<Vec<(servo::WebViewId, ConsoleLevel, String)>>>,
    network_records: Arc<Mutex<Vec<(servo::WebViewId, NetworkRequestRecord)>>>,
    /// Request times for in-flight web resource loads, in arrival order.
    /// Bounded; matched against completion notifications to fill record
    /// status and duration.
    web_resource_load_starts: WebResourceLoadStarts,
    url_events: Arc<Mutex<Vec<(servo::WebViewId, Url)>>>,
    page_title_events: PageTitleEvents,
    load_status_events: Arc<Mutex<Vec<(servo::WebViewId, NavigationLoadStatus)>>>,
    frame_tree_events: ExtensionFrameTreeEvents,
    accessibility_updates: Rc<RefCell<Vec<(servo::WebViewId, servo::accesskit::TreeUpdate)>>>,
    media_session_events: Arc<Mutex<Vec<(servo::WebViewId, MediaSessionEvent)>>>,
    webdriver_load_status_senders:
        Arc<Mutex<HashMap<servo::WebViewId, servo::GenericSender<WebDriverLoadStatus>>>>,
    /// Window rendering context used to create auxiliary `window.open`
    /// popup surfaces that composite into the main window.
    window_rendering_context: Rc<WindowRenderingContext>,
    /// Live auxiliary `window.open` popups in creation order, bounded to
    /// `AUXILIARY_WEBVIEWS_LIMIT` with oldest-first eviction.
    auxiliary_webviews: Rc<RefCell<Vec<AuxiliaryWebViewEntry>>>,
    /// Auxiliary popup currently under the pointer, if any.
    hovered_auxiliary: Cell<Option<servo::WebViewId>>,
    /// Auxiliary popup holding keyboard focus, set on mouse-down over it.
    focused_auxiliary: Cell<Option<servo::WebViewId>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MediaSessionEventKind {
    Metadata,
    PlaybackState,
    PositionState,
}

fn media_session_event_kind(event: &MediaSessionEvent) -> MediaSessionEventKind {
    match event {
        MediaSessionEvent::SetMetadata(_) => MediaSessionEventKind::Metadata,
        MediaSessionEvent::PlaybackStateChange(_) => MediaSessionEventKind::PlaybackState,
        MediaSessionEvent::SetPositionState(_) => MediaSessionEventKind::PositionState,
    }
}

fn enqueue_media_session_event<T: Copy + PartialEq>(
    events: &mut Vec<(T, MediaSessionEvent)>,
    webview_id: T,
    event: MediaSessionEvent,
) {
    let kind = media_session_event_kind(&event);
    if let Some((_, pending)) = events
        .iter_mut()
        .rev()
        .find(|(id, pending)| *id == webview_id && media_session_event_kind(pending) == kind)
    {
        *pending = event;
    } else {
        events.push((webview_id, event));
    }
}

struct PendingDownload {
    webview_id: servo::WebViewId,
    request: ServoDownloadRequest,
}

struct PendingPdfLoad {
    webview_id: servo::WebViewId,
    request: InterceptedWebResourceLoad,
    bytes: Vec<u8>,
    failure: Option<String>,
}

enum PdfLoadEvent {
    Response { total_bytes: Option<u64> },
    BodyChunk(Vec<u8>),
    Finished(Result<(), String>),
}

struct PendingPdfEvent {
    id: u64,
    event: PdfLoadEvent,
}

fn pdf_viewer_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline' blob:; style-src 'unsafe-inline'; img-src data: blob:; worker-src blob:",
        ),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers
}

struct PendingPermission {
    webview_id: servo::WebViewId,
    site: String,
    feature: PermissionFeature,
    request: PermissionRequest,
}

#[derive(Debug, Deserialize)]
struct RawExtensionPageMessage {
    extension_id: String,
    payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RawExtensionBackgroundMessage {
    payload: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionPrompt {
    pub id: PermissionPromptId,
    pub tab_id: Option<TabId>,
    pub site: String,
    pub kind: PermissionKind,
}

struct PendingDownloadEvent {
    id: DownloadId,
    event: DownloadTransportEvent,
}

struct ExtensionPopup {
    context: Rc<OffscreenRenderingContext>,
    webview: WebView,
    _user_content_manager: Rc<UserContentManager>,
}

/// A live auxiliary `window.open` popup composited over Nomad's chrome.
#[derive(Clone)]
struct AuxiliaryWebViewEntry {
    webview: WebView,
    context: Rc<OffscreenRenderingContext>,
    /// Overlay rectangle in device pixels. Owned here so hit-testing,
    /// compositing, and `resizeTo`/`moveTo` share one source of truth;
    /// chrome paints the surface at this rect divided by the hidpi scale.
    rect: Rect<f32, euclid::UnknownUnit>,
}

/// Maximum live auxiliary `window.open` popups before the oldest entries
/// are hidden and evicted, so a misbehaving page cannot spawn unbounded
/// `WebView`s.
const AUXILIARY_WEBVIEWS_LIMIT: usize = 8;

/// Default auxiliary popup size in device-independent points, matching the
/// extension popup overlay precedent.
const AUXILIARY_POPUP_SIZE: (f32, f32) = (420.0, 620.0);

/// Range of oldest auxiliary registry entries to evict so that pushing one
/// more entry keeps the registry within `limit`. Pure so the bound is
/// unit-testable without a live `WebView`.
fn auxiliary_eviction_range(len: usize, limit: usize) -> std::ops::Range<usize> {
    0..len.saturating_sub(limit.saturating_sub(1))
}

/// Maximum tracked in-flight web resource loads before the oldest start
/// entries are dropped.
const WEB_RESOURCE_LOAD_STARTS_LIMIT: usize = 1_024;

/// Converts optional blocking-decision header pairs into an HTTP header map,
/// skipping pairs whose names or values are not valid header components.
fn header_map_from_pairs(pairs: Option<Vec<(String, String)>>) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in pairs.unwrap_or_default() {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&value) else {
            continue;
        };
        headers.insert(name, value);
    }
    headers
}

/// Captures the bounded, redacted metadata of an intercepted web resource
/// load: original headers, declared body size, and unavailability flag.
fn network_record_for(load: &WebResourceLoad) -> NetworkRequestRecord {
    NetworkRequestRecord {
        method: load.request.method.to_string(),
        url: load.request.url.to_string(),
        status: None,
        duration_ms: None,
        failed: false,
        request_headers: load
            .request
            .headers
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect(),
        response_headers: Vec::new(),
        request_body_size: load.request.request_body_size,
        request_body_unavailable: load.request.request_body_unavailable,
    }
}

impl WebViewDelegate for FrameDelegate {
    /// Completes the matching network record when a web resource load
    /// finishes, filling in the final HTTP status, duration, and failure
    /// flag. Loads whose start entry was evicted are ignored.
    fn web_resource_load_finished(
        &self,
        webview: WebView,
        method: http::Method,
        url: servo_url::ServoUrl,
        status: Option<u16>,
        response_headers: Vec<(String, String)>,
        failed: bool,
    ) {
        let key = (webview.id(), method.to_string(), url.to_string());
        let started_at = if let Ok(mut starts) = self.web_resource_load_starts.lock() {
            if let Some(position) = starts.iter().position(|(entry, _)| *entry == key) {
                starts.remove(position).map(|(_, started_at)| started_at)
            } else {
                None
            }
        } else {
            None
        };
        let duration_ms = started_at
            .map(|started_at| u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX));
        if let Ok(mut records) = self.network_records.lock() {
            for (_, record) in records.iter_mut().rev() {
                if record.method == key.1
                    && record.url == key.2
                    && record.status.is_none()
                    && record.duration_ms.is_none()
                {
                    record.status = status;
                    record.duration_ms = duration_ms;
                    record.response_headers = response_headers;
                    record.failed = failed;
                    break;
                }
            }
        }
    }

    fn notify_new_frame_ready(&self, webview: WebView) {
        if let Ok(mut dirty_webviews) = self.dirty_webviews.lock() {
            dirty_webviews.insert(webview.id());
        }
        self.window.request_redraw();
    }

    /// Accepts a `window.open` request by building the auxiliary `WebView`
    /// inline on an offscreen surface of the main window. The opener script
    /// thread blocks on this request's responder, so the build must happen
    /// here and now: deferring would freeze the opener page. No `.url()`
    /// call — the `about:blank` load and the requested navigation are issued
    /// by the script side once the browsing context exists. Deliberately not
    /// `.private_browsing(true)`: auxiliary popups keep storage (service
    /// workers, cache) across navigations. The popup gets a fresh user
    /// content manager, so extension and privacy user scripts do not apply
    /// to it (acceptable: the delegate cannot map the opener webview back to
    /// its tab's manager).
    // Window scale factors and popup pixel sizes are modest on-screen
    // values; narrowing winit's f64/u32 to Servo's f32 geometry is
    // the intended conversion.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    fn request_create_new(&self, parent_webview: WebView, request: CreateNewWebViewRequest) {
        let scale = self.window.scale_factor() as f32;
        let width = (AUXILIARY_POPUP_SIZE.0 * scale).round().max(1.0);
        let height = (AUXILIARY_POPUP_SIZE.1 * scale).round().max(1.0);
        let size = PhysicalSize::new(width as u32, height as u32);
        let rect = self.default_auxiliary_rect(width, height, scale);
        let context = Rc::new(self.window_rendering_context.offscreen_context(size));
        let webview = request
            .builder(context.clone())
            .delegate(parent_webview.delegate())
            .hidpi_scale_factor(Scale::new(scale))
            .build();
        webview.show();
        self.push_auxiliary_webview(AuxiliaryWebViewEntry {
            webview,
            context,
            rect,
        });
        self.window.request_redraw();
    }

    /// Removes a `window.close()`d auxiliary popup from the overlay registry.
    /// Strictly scoped to registry membership: tab teardown does not route
    /// through this delegate method, so it is unaffected.
    fn notify_closed(&self, webview: WebView) {
        let webview_id = webview.id();
        let mut entries = self.auxiliary_webviews.borrow_mut();
        let Some(position) = entries
            .iter()
            .position(|entry| entry.webview.id() == webview_id)
        else {
            return;
        };
        entries[position].webview.hide();
        entries.remove(position);
        drop(entries);
        if self.hovered_auxiliary.get() == Some(webview_id) {
            self.hovered_auxiliary.set(None);
        }
        if self.focused_auxiliary.get() == Some(webview_id) {
            self.focused_auxiliary.set(None);
        }
        self.window.request_redraw();
    }

    /// Resizes an auxiliary popup's surface and overlay rect from
    /// `window.resizeTo`. Sizes arrive as outer dimensions in device
    /// pixels; they are clamped to the window so a page cannot inflate the
    /// popup beyond what the overlay can display (Servo already clamps to
    /// positive). The compositor callback captures the source framebuffer
    /// at creation time, so chrome re-fetches it every frame.
    fn request_resize_to(&self, webview: WebView, requested_outer_size: DeviceIntSize) {
        // Outer-size clamping bounds are window dimensions; narrowing the
        // u32 window size to Servo's i32 device size is intended.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss
        )]
        {
            let mut entries = self.auxiliary_webviews.borrow_mut();
            let Some(entry) = entries
                .iter_mut()
                .find(|entry| entry.webview.id() == webview.id())
            else {
                return;
            };
            let window_size = self.window.inner_size();
            let max_width = window_size.width.min(i32::MAX as u32) as i32;
            let max_height = window_size.height.min(i32::MAX as u32) as i32;
            let width = requested_outer_size.width.clamp(1, max_width) as u32;
            let height = requested_outer_size.height.clamp(1, max_height) as u32;
            let size = PhysicalSize::new(width, height);
            entry.context.resize(size);
            entry.webview.resize(size);
            entry.rect.size = Size2D::new(width as f32, height as f32);
            drop(entries);
            self.window.request_redraw();
        }
    }

    /// Moves an auxiliary popup's overlay rect from `window.moveTo`, in
    /// device pixels relative to the window's top-left. Negative
    /// coordinates are clamped to the window edge.
    // Device coordinates are modest on-screen values; narrowing Servo's
    // i32 device point to the f32 overlay rect is intended.
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    fn request_move_to(&self, webview: WebView, point: DeviceIntPoint) {
        let mut entries = self.auxiliary_webviews.borrow_mut();
        let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.webview.id() == webview.id())
        else {
            return;
        };
        entry.rect.origin = Point2D::new(point.x.max(0) as f32, point.y.max(0) as f32);
        drop(entries);
        self.window.request_redraw();
    }

    fn notify_cursor_changed(&self, _webview: WebView, cursor: ServoCursor) {
        let cursor = match cursor {
            ServoCursor::Default => CursorIcon::Default,
            ServoCursor::Pointer => CursorIcon::Pointer,
            ServoCursor::ContextMenu => CursorIcon::ContextMenu,
            ServoCursor::Help => CursorIcon::Help,
            ServoCursor::Progress => CursorIcon::Progress,
            ServoCursor::Wait => CursorIcon::Wait,
            ServoCursor::Cell => CursorIcon::Cell,
            ServoCursor::Crosshair => CursorIcon::Crosshair,
            ServoCursor::Text => CursorIcon::Text,
            ServoCursor::VerticalText => CursorIcon::VerticalText,
            ServoCursor::Alias => CursorIcon::Alias,
            ServoCursor::Copy => CursorIcon::Copy,
            ServoCursor::Move => CursorIcon::Move,
            ServoCursor::NoDrop => CursorIcon::NoDrop,
            ServoCursor::NotAllowed => CursorIcon::NotAllowed,
            ServoCursor::Grab => CursorIcon::Grab,
            ServoCursor::Grabbing => CursorIcon::Grabbing,
            ServoCursor::EResize => CursorIcon::EResize,
            ServoCursor::NResize => CursorIcon::NResize,
            ServoCursor::NeResize => CursorIcon::NeResize,
            ServoCursor::NwResize => CursorIcon::NwResize,
            ServoCursor::SResize => CursorIcon::SResize,
            ServoCursor::SeResize => CursorIcon::SeResize,
            ServoCursor::SwResize => CursorIcon::SwResize,
            ServoCursor::WResize => CursorIcon::WResize,
            ServoCursor::EwResize => CursorIcon::EwResize,
            ServoCursor::NsResize => CursorIcon::NsResize,
            ServoCursor::NeswResize => CursorIcon::NeswResize,
            ServoCursor::NwseResize => CursorIcon::NwseResize,
            ServoCursor::ColResize => CursorIcon::ColResize,
            ServoCursor::RowResize => CursorIcon::RowResize,
            ServoCursor::AllScroll => CursorIcon::AllScroll,
            ServoCursor::ZoomIn => CursorIcon::ZoomIn,
            ServoCursor::ZoomOut => CursorIcon::ZoomOut,
            ServoCursor::None => {
                self.window.set_cursor_visible(false);
                return;
            }
        };
        self.window.set_cursor(cursor);
        self.window.set_cursor_visible(true);
    }

    fn notify_url_changed(&self, webview: WebView, url: Url) {
        if let Ok(mut events) = self.url_events.lock() {
            push_bounded_event(&mut events, (webview.id(), url));
        }
        self.window.request_redraw();
    }

    fn notify_traversal_complete(&self, webview: WebView, _traversal_id: servo::TraversalId) {
        if let Ok(mut senders) = self.webdriver_load_status_senders.lock() {
            if let Some(sender) = senders.remove(&webview.id()) {
                let _ = sender.send(WebDriverLoadStatus::Complete);
            }
        }
        self.window.request_redraw();
    }
    fn notify_frame_tree_changed(&self, webview: WebView, frames: Vec<(u64, Option<u64>, String)>) {
        if let Ok(mut events) = self.frame_tree_events.lock() {
            push_bounded_event(&mut events, (webview.id(), frames));
        }
    }

    fn notify_load_status_changed(&self, webview: WebView, status: servo::LoadStatus) {
        if let Ok(mut events) = self.load_status_events.lock() {
            push_bounded_event(&mut events, (webview.id(), map_load_status(status)));
        }
        if status == servo::LoadStatus::Complete {
            if let Ok(mut senders) = self.webdriver_load_status_senders.lock() {
                if let Some(sender) = senders.remove(&webview.id()) {
                    let _ = sender.send(WebDriverLoadStatus::Complete);
                }
            }
        }
        self.window.request_redraw();
    }

    fn notify_page_title_changed(&self, webview: WebView, title: Option<String>) {
        if let Ok(mut events) = self.page_title_events.lock() {
            push_bounded_event(&mut events, (webview.id(), title));
        }
        self.window.request_redraw();
    }

    fn request_download(&self, webview: WebView, request: ServoDownloadRequest) {
        let _ = self.download_sender.send(PendingDownload {
            webview_id: webview.id(),
            request,
        });
    }

    fn request_permission(&self, webview: WebView, request: PermissionRequest) {
        let Some(url) = webview.url() else {
            request.deny();
            return;
        };
        let policy = *self.privacy_policy.borrow();
        let kind = permission_kind(request.feature());
        if !policy.allows_permission_request(&url, kind) {
            request.deny();
            return;
        }
        self.permission_requests
            .borrow_mut()
            .push(PendingPermission {
                webview_id: webview.id(),
                site: permission_site(&url),
                feature: request.feature(),
                request,
            });
        self.window.request_redraw();
    }

    fn show_console_message(&self, webview: WebView, level: ConsoleLogLevel, message: String) {
        if let Ok(mut messages) = self.console_messages.lock() {
            push_bounded_event(
                &mut messages,
                (webview.id(), map_console_level(&level), message),
            );
        }
        self.window.request_redraw();
    }

    fn notify_accessibility_tree_update(
        &self,
        webview: WebView,
        tree_update: servo::accesskit::TreeUpdate,
    ) {
        push_bounded_event(
            &mut self.accessibility_updates.borrow_mut(),
            (webview.id(), tree_update),
        );
        eprintln!("Nomad AX diag: servo tree update queued");
        self.window.request_redraw();
    }

    fn notify_media_session_event(&self, webview: WebView, event: MediaSessionEvent) {
        if let Ok(mut events) = self.media_session_events.lock() {
            enqueue_media_session_event(&mut events, webview.id(), event);
            if events.len() > PENDING_EVENT_QUEUE_LIMIT {
                let drop_count = events.len() - PENDING_EVENT_QUEUE_LIMIT;
                events.drain(..drop_count);
            }
        }
        self.window.request_redraw();
    }
    fn load_web_resource(&self, webview: WebView, load: WebResourceLoad) {
        if load.request.url.scheme() == "nomad-extension" {
            self.load_extension_resource(&webview, load);
            return;
        }
        // Blocking/record tracking may intercept the load (route, pattern,
        // privacy, or PDF paths); it returns the load only when the caller
        // should proceed with the extension blocking decision.
        let Some(load) = self.track_web_resource_load_start(&webview, load) else {
            return;
        };
        let request = WebRequestBlockingRequest {
            webview_id: None,
            url: load.request.url.to_string(),
            method: load.request.method.to_string(),
            headers: load
                .request
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect(),
            request_body_size: load.request.request_body_size,
            request_body_unavailable: load.request.request_body_unavailable,
            is_for_main_frame: load.request.is_for_main_frame,
        };
        let decision = self
            .web_request_blocking_handler
            .lock()
            .ok()
            .map_or_else(WebRequestBlockingDecision::default, |handler| {
                handler.decide(&request)
            });
        let request_headers = header_map_from_pairs(decision.request_headers);
        let redirect_url = decision.redirect_url.and_then(|url| Url::parse(&url).ok());
        let response_headers = header_map_from_pairs(decision.response_headers);
        load.continue_request(servo::WebResourceRequestDecision {
            cancel: decision.cancel,
            redirect_url,
            request_headers,
            response_headers,
        });
    }
}

impl FrameDelegate {
    fn load_extension_resource(&self, webview: &WebView, load: WebResourceLoad) {
        let url = load.request.url.clone();
        let key = (
            url.host_str().unwrap_or_default().to_owned(),
            url.path().trim_start_matches('/').to_owned(),
        );
        let resource = self
            .extension_resources
            .lock()
            .ok()
            .and_then(|resources| resources.get(&key).cloned());
        if load.request.method != Method::GET {
            load.intercept(WebResourceResponse::new(url)).cancel();
            return;
        }
        let resource = resource.or_else(|| {
            (key.1 == "__nomad/background.html").then(|| ExtensionResource {
                extension_id: key.0.clone(),
                path: key.1.clone(),
                source: "<!doctype html><html><head></head><body></body></html>".into(),
                bytes: b"<!doctype html><html><head></head><body></body></html>".to_vec(),
                mime_type: "text/html".into(),
                web_accessible: false,
                web_accessible_matches: Vec::new(),
            })
        });
        let Some(resource) = resource else {
            load.intercept(WebResourceResponse::new(url).status_code(http::StatusCode::NOT_FOUND))
                .finish();
            return;
        };
        let extension_page = webview.url().is_some_and(|page_url| {
            page_url.scheme() == "nomad-extension" && page_url.host_str() == Some(key.0.as_str())
        });
        let extension_referrer = load.request.referrer_url.as_ref().is_some_and(|referrer| {
            referrer.scheme() == "nomad-extension" && referrer.host_str() == Some(key.0.as_str())
        });
        let page_access = load.request.referrer_url.as_ref().is_some_and(|referrer| {
            resource.web_accessible
                && (resource.web_accessible_matches.is_empty()
                    || resource
                        .web_accessible_matches
                        .iter()
                        .any(|pattern| extension_block_pattern_matches(pattern, referrer)))
        });
        let is_background_webview = self
            .background_webview_ids
            .lock()
            .map(|ids| ids.contains(&(key.0.clone(), webview.id())))
            .unwrap_or(false);
        if !extension_page && !extension_referrer && !page_access && !is_background_webview {
            load.intercept(WebResourceResponse::new(url).status_code(http::StatusCode::FORBIDDEN))
                .finish();
            return;
        }
        let mut intercepted = load.intercept(WebResourceResponse::new(url).headers({
            let mut headers = http::HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(&resource.mime_type) {
                headers.insert(CONTENT_TYPE, value);
            }
            headers
        }));
        intercepted.send_body_data(resource.bytes);
        intercepted.finish();
    }
    fn track_web_resource_load_start(
        &self,
        webview: &WebView,
        load: WebResourceLoad,
    ) -> Option<WebResourceLoad> {
        if let Ok(mut starts) = self.web_resource_load_starts.lock() {
            starts.push_back((
                (
                    webview.id(),
                    load.request.method.to_string(),
                    load.request.url.to_string(),
                ),
                Instant::now(),
            ));
            if starts.len() > WEB_RESOURCE_LOAD_STARTS_LIMIT {
                let drop_count = starts.len() - WEB_RESOURCE_LOAD_STARTS_LIMIT;
                starts.drain(0..drop_count);
            }
        }
        if let Ok(mut records) = self.network_records.lock() {
            push_bounded_event(&mut records, (webview.id(), network_record_for(&load)));
        }
        if self
            .network_route
            .borrow()
            .decision_for(&load.request.url)
            .action()
            == SiteRouteAction::Block
        {
            let resource_url = load.request.url.clone();
            load.intercept(WebResourceResponse::new(resource_url))
                .cancel();
            return None;
        }
        if self
            .extension_block_patterns
            .borrow()
            .iter()
            .any(|pattern| extension_block_pattern_matches(pattern, &load.request.url))
        {
            self.blocked_resource_count.fetch_add(1, Ordering::Relaxed);
            let resource_url = load.request.url.clone();
            load.intercept(WebResourceResponse::new(resource_url))
                .cancel();
            return None;
        }
        let Some(top_level_url) = webview.url().or_else(|| load.request.referrer_url.clone())
        else {
            return Some(load);
        };
        let block_reason = self.privacy_policy.borrow().block_reason(
            &top_level_url,
            &load.request.url,
            load.request.is_for_main_frame,
        );
        if let Some(reason) = block_reason {
            self.blocked_resource_count.fetch_add(1, Ordering::Relaxed);
            match reason {
                ResourceBlockReason::Ad => {
                    self.blocked_ad_count.fetch_add(1, Ordering::Relaxed);
                }
                ResourceBlockReason::Tracker => {
                    self.blocked_tracker_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            let resource_url = load.request.url.clone();
            load.intercept(WebResourceResponse::new(resource_url))
                .cancel();
            return None;
        }
        if crate::pdf::is_pdf_navigation(&load.request.url, load.request.is_for_main_frame) {
            let resource_url = load.request.url.clone();
            let intercepted = load
                .intercept(WebResourceResponse::new(resource_url).headers(pdf_viewer_headers()));
            let pending = PendingPdfLoad {
                webview_id: webview.id(),
                request: intercepted,
                bytes: Vec::new(),
                failure: None,
            };
            if let Err(error) = self.pdf_load_sender.send(pending) {
                error.0.request.cancel();
            }
            return None;
        }
        Some(load)
    }

    /// Computes the default overlay rectangle for a new auxiliary popup in
    /// device pixels: anchored to the top-right of the window and cascaded
    /// downward per existing popup so stacked popups stay visible. Chrome
    /// paints each surface at this rect divided by the hidpi scale.
    fn default_auxiliary_rect(
        &self,
        width: f32,
        height: f32,
        scale: f32,
    ) -> Rect<f32, euclid::UnknownUnit> {
        // Window pixel dimensions are bounded by on-screen sizes; narrowing
        // winit's u32 inner size to f32 overlay geometry is intended.
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        {
            let inner = self.window.inner_size();
            let cascade = self.auxiliary_webviews.borrow().len() as f32 * 28.0 * scale;
            let margin = 20.0 * scale;
            let x = (inner.width as f32 - width - margin).max(0.0);
            let y = (margin + cascade).min((inner.height as f32 - height).max(0.0));
            Rect::new(Point2D::new(x, y), Size2D::new(width, height))
        }
    }

    /// Registers a new auxiliary popup, hiding and evicting the oldest
    /// entries when the bounded registry would exceed
    /// `AUXILIARY_WEBVIEWS_LIMIT`.
    fn push_auxiliary_webview(&self, entry: AuxiliaryWebViewEntry) {
        let mut entries = self.auxiliary_webviews.borrow_mut();
        let eviction = auxiliary_eviction_range(entries.len(), AUXILIARY_WEBVIEWS_LIMIT);
        for evicted in entries.drain(eviction) {
            evicted.webview.hide();
        }
        entries.push(entry);
    }

    /// Hit-tests auxiliary popup overlay rects (device pixels); returns the
    /// popup id and the pointer position relative to its rect.
    fn auxiliary_hit_test(&self, point: DevicePoint) -> Option<(servo::WebViewId, DevicePoint)> {
        self.auxiliary_webviews
            .borrow()
            .iter()
            .rev()
            .find(|entry| entry.rect.contains(Point2D::new(point.x, point.y)))
            .map(|entry| {
                (
                    entry.webview.id(),
                    DevicePoint::new(point.x - entry.rect.origin.x, point.y - entry.rect.origin.y),
                )
            })
    }

    /// Returns the live auxiliary popup with the given id, if any.
    fn auxiliary_webview(&self, webview_id: servo::WebViewId) -> Option<WebView> {
        self.auxiliary_webviews
            .borrow()
            .iter()
            .find(|entry| entry.webview.id() == webview_id)
            .map(|entry| entry.webview.clone())
    }

    /// Returns the pointer position relative to the given auxiliary popup's
    /// rect, given the absolute pointer position.
    fn auxiliary_relative_point(
        &self,
        webview_id: servo::WebViewId,
        absolute: DevicePoint,
    ) -> Option<DevicePoint> {
        self.auxiliary_webviews
            .borrow()
            .iter()
            .find(|entry| entry.webview.id() == webview_id)
            .map(|entry| {
                DevicePoint::new(
                    absolute.x - entry.rect.origin.x,
                    absolute.y - entry.rect.origin.y,
                )
            })
    }

    /// Returns snapshots of all live auxiliary popup entries.
    fn auxiliary_entries(&self) -> Vec<AuxiliaryWebViewEntry> {
        self.auxiliary_webviews.borrow().clone()
    }
}

pub struct ServoRenderer {
    servo: Servo,
    network_route: NetworkRoute,
    network_diagnostics: Arc<Mutex<NetworkDiagnostics>>,
    umc_diagnostics: Option<UmcDiagnostics>,
    webviews: HashMap<TabId, WebView>,
    pending_tab_loads: HashMap<TabId, Url>,
    tab_containers: HashMap<TabId, (ContainerId, bool)>,
    active_tab: Option<TabId>,
    delegate: Rc<FrameDelegate>,
    download_receiver: std::sync::mpsc::Receiver<PendingDownload>,
    pdf_load_receiver: Receiver<PendingPdfLoad>,
    pdf_event_sender: Sender<PendingPdfEvent>,
    pdf_event_receiver: Receiver<PendingPdfEvent>,
    pdf_loads: HashMap<u64, PendingPdfLoad>,
    pdf_handles: HashMap<u64, servo::DownloadHandle>,
    next_pdf_id: u64,
    download_event_sender: Sender<PendingDownloadEvent>,
    download_event_receiver: Receiver<PendingDownloadEvent>,
    download_handles: HashMap<DownloadId, servo::DownloadHandle>,
    permission_requests: Rc<RefCell<Vec<PendingPermission>>>,
    pending_permissions: HashMap<PermissionPromptId, PermissionRequest>,
    next_permission_id: u64,
    download_waker: Box<dyn EventLoopWaker>,
    fallback_page_rendering_context: Rc<OffscreenRenderingContext>,
    page_rendering_contexts: HashMap<TabId, Rc<OffscreenRenderingContext>>,
    window_rendering_context: Rc<WindowRenderingContext>,
    content_size: Cell<PhysicalSize<u32>>,
    content_rects: RefCell<HashMap<TabId, Rect<f32, euclid::UnknownUnit>>>,
    hovered_tab: Cell<Option<TabId>>,
    absolute_pointer_position: Cell<DevicePoint>,
    pointer_position: Cell<DevicePoint>,
    modifiers: Cell<ModifiersState>,
    memory_reports: Arc<Mutex<Vec<(TabId, u64)>>>,
    privacy_policy: Rc<RefCell<PrivacyPolicy>>,
    privacy_script: Rc<UserScript>,
    tab_content_managers: HashMap<TabId, Rc<UserContentManager>>,
    extension_scripts: HashMap<TabId, HashMap<String, Vec<Rc<UserScript>>>>,
    background_webviews: HashMap<String, WebView>,
    background_content_managers: HashMap<String, Rc<UserContentManager>>,
    extension_messages: Arc<Mutex<Vec<ExtensionMessage>>>,
    extension_popup: Option<ExtensionPopup>,
    network_route_state: Rc<RefCell<NetworkRoute>>,
    extension_block_patterns: Rc<RefCell<Vec<String>>>,
    extension_resources: Arc<Mutex<HashMap<(String, String), ExtensionResource>>>,
    background_webview_ids: Arc<Mutex<HashSet<(String, servo::WebViewId)>>>,
    blocked_resource_count: Arc<AtomicU64>,
    blocked_ad_count: Arc<AtomicU64>,
    blocked_tracker_count: Arc<AtomicU64>,
    console_messages: Arc<Mutex<Vec<(servo::WebViewId, ConsoleLevel, String)>>>,
    devtools_evaluations: Arc<Mutex<Vec<(TabId, DevToolsEvaluation)>>>,
    reader_snapshots: Arc<Mutex<Vec<(TabId, String)>>>,
    dom_snapshots: Arc<Mutex<Vec<(TabId, DevToolsDomSnapshot)>>>,
    page_text_snapshots: Arc<Mutex<Vec<(TabId, String)>>>,
    autofill_snapshots: AutofillSnapshots,
    page_inspection_snapshots: Arc<Mutex<Vec<(TabId, DevToolsPageSnapshot)>>>,
    accessibility_updates: Rc<RefCell<Vec<(servo::WebViewId, servo::accesskit::TreeUpdate)>>>,
    #[allow(clippy::type_complexity)]
    tab_screenshots: Arc<Mutex<Vec<(TabId, Result<Vec<u8>, RenderError>)>>>,
    load_status_events: Arc<Mutex<Vec<(servo::WebViewId, NavigationLoadStatus)>>>,
    frame_tree_events: ExtensionFrameTreeEvents,
    network_records: Arc<Mutex<Vec<(servo::WebViewId, NetworkRequestRecord)>>>,
    url_events: Arc<Mutex<Vec<(servo::WebViewId, Url)>>>,
    page_title_events: PageTitleEvents,
    media_session_events: Arc<Mutex<Vec<(servo::WebViewId, MediaSessionEvent)>>>,
    webdriver_receiver: Option<WebDriverReceiver<servo::WebDriverCommandMsg>>,
    webdriver_tab_ids: HashSet<TabId>,
    webdriver_load_status_senders:
        Arc<Mutex<HashMap<servo::WebViewId, servo::GenericSender<WebDriverLoadStatus>>>>,
    webdriver_shutdown_requested: bool,
    theme: Theme,
    accessibility_active: bool,
}

impl ServoRenderer {
    /// Embeds Servo into an existing native window.
    ///
    /// # Errors
    ///
    /// Returns an error when Servo or its rendering surface cannot be
    /// initialized.
    pub fn new(
        window: Rc<Window>,
        waker: Box<dyn EventLoopWaker>,
        network_route: NetworkRoute,
    ) -> Result<Self, ServoError> {
        Self::new_with_webdriver(window, waker, network_route, None)
    }

    /// Embeds Servo and, when requested, attaches Servo's `WebDriver`
    /// protocol to the same event loop as Nomad's native shell.
    ///
    /// # Errors
    ///
    /// Returns an error when Servo or its rendering surface cannot be
    /// initialized.
    pub fn new_with_webdriver(
        window: Rc<Window>,
        waker: Box<dyn EventLoopWaker>,
        network_route: NetworkRoute,
        webdriver_port: Option<u16>,
    ) -> Result<Self, ServoError> {
        Self::new_with_webdriver_options(window, waker, network_route, webdriver_port, false)
    }

    /// Embeds Servo with native-runner options that are not part of ordinary
    /// browser startup, such as the WPT certificate override.
    ///
    /// # Errors
    ///
    /// Returns an error when Servo or its rendering surface cannot be
    /// initialized.
    pub fn new_with_webdriver_options(
        window: Rc<Window>,
        waker: Box<dyn EventLoopWaker>,
        network_route: NetworkRoute,
        webdriver_port: Option<u16>,
        ignore_certificate_errors: bool,
    ) -> Result<Self, ServoError> {
        Self::new_with_webdriver_devtools_options(
            window,
            waker,
            network_route,
            webdriver_port,
            None,
            ignore_certificate_errors,
        )
    }

    /// Embeds Servo with the loopback `WebDriver` and remote `DevTools`
    /// endpoints. `DevTools` is intentionally opt-in because it exposes
    /// powerful inspection and debugging capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error when the `DevTools` port is zero, the network route is
    /// invalid, the window handles or rendering surface cannot be acquired,
    /// or the `WebDriver` server fails to start.
    // Wires ~25 locals into one struct literal; the clearly separable
    // factory chunks are extracted below, but the shared-state literal
    // itself cannot be split without reshaping the struct's API.
    #[allow(clippy::too_many_lines)]
    pub fn new_with_webdriver_devtools_options(
        window: Rc<Window>,
        waker: Box<dyn EventLoopWaker>,
        network_route: NetworkRoute,
        webdriver_port: Option<u16>,
        devtools_port: Option<u16>,
        ignore_certificate_errors: bool,
    ) -> Result<Self, ServoError> {
        let theme = match window.theme() {
            Some(winit::window::Theme::Dark) => Theme::Dark,
            _ => Theme::Light,
        };
        if devtools_port == Some(0) {
            return Err(ServoError::Native(
                "DevTools port must be non-zero".to_owned(),
            ));
        }
        network_route
            .validate()
            .map_err(|error| ServoError::Native(format!("invalid network route: {error:?}")))?;
        let (window_rendering_context, page_rendering_context, content_size) =
            Self::create_rendering_contexts(&window)?;
        let download_waker = waker.clone();
        let privacy_policy = PrivacyPolicy::for_mode(PrivacyMode::Standard);
        let preferences =
            Self::embedder_preferences(&privacy_policy, &network_route, devtools_port);
        let webdriver_preferences = preferences.clone();
        let webdriver_waker = waker.clone();
        let servo = Self::build_servo_instance(
            preferences,
            waker,
            ignore_certificate_errors,
            devtools_port,
        );
        let webdriver_receiver =
            start_webdriver_server(&webdriver_preferences, webdriver_waker, webdriver_port)?;
        let (download_sender, download_receiver) = std::sync::mpsc::channel();
        let (pdf_load_sender, pdf_load_receiver) = mpsc::channel();
        let (pdf_event_sender, pdf_event_receiver) = mpsc::channel();
        let (download_event_sender, download_event_receiver) = mpsc::channel();
        let permission_requests = Rc::new(RefCell::new(Vec::new()));
        let privacy_script = Rc::new(UserScript::new(privacy_script(privacy_policy), None));
        let privacy_policy = Rc::new(RefCell::new(privacy_policy));
        let blocked_resource_count = Arc::new(AtomicU64::new(0));
        let blocked_ad_count = Arc::new(AtomicU64::new(0));
        let blocked_tracker_count = Arc::new(AtomicU64::new(0));
        let console_messages = Arc::new(Mutex::new(Vec::new()));
        let devtools_evaluations = Arc::new(Mutex::new(Vec::new()));
        let reader_snapshots = Arc::new(Mutex::new(Vec::new()));
        let dom_snapshots = Arc::new(Mutex::new(Vec::new()));
        let page_text_snapshots = Arc::new(Mutex::new(Vec::new()));
        let autofill_snapshots = Arc::new(Mutex::new(Vec::new()));
        let page_inspection_snapshots = Arc::new(Mutex::new(Vec::new()));
        let tab_screenshots = Arc::new(Mutex::new(Vec::new()));
        let extension_messages = Arc::new(Mutex::new(Vec::new()));
        let network_records = Arc::new(Mutex::new(Vec::new()));
        let web_resource_load_starts = Arc::new(Mutex::new(VecDeque::<(
            (servo::WebViewId, String, String),
            Instant,
        )>::new()));
        let url_events = Arc::new(Mutex::new(Vec::new()));
        let page_title_events = Arc::new(Mutex::new(Vec::new()));
        let load_status_events = Arc::new(Mutex::new(Vec::new()));
        let frame_tree_events = Arc::new(Mutex::new(Vec::new()));
        let accessibility_updates = Rc::new(RefCell::new(Vec::new()));
        let media_session_events = Arc::new(Mutex::new(Vec::new()));
        let webdriver_load_status_senders = Arc::new(Mutex::new(HashMap::new()));
        let dirty_webviews = Arc::new(Mutex::new(HashSet::new()));
        let network_route_state = Rc::new(RefCell::new(network_route.clone()));
        let extension_block_patterns = Rc::new(RefCell::new(Vec::new()));
        let web_request_blocking_handler = Arc::new(Mutex::new(Arc::new(
            AllowAllWebRequestBlockingHandler,
        )
            as Arc<dyn WebRequestBlockingHandler>));
        let extension_resources = Arc::new(Mutex::new(HashMap::new()));
        let background_webview_ids = Arc::new(Mutex::new(HashSet::new()));
        let network_diagnostics = Self::install_network_observer(&network_route);

        Ok(Self {
            servo,
            network_route,
            network_diagnostics,
            umc_diagnostics: None,
            webviews: HashMap::new(),
            pending_tab_loads: HashMap::new(),
            tab_containers: HashMap::new(),
            active_tab: None,
            delegate: Rc::new(FrameDelegate {
                window,
                dirty_webviews,
                download_sender,
                pdf_load_sender,
                permission_requests: permission_requests.clone(),
                privacy_policy: privacy_policy.clone(),
                network_route: network_route_state.clone(),
                extension_block_patterns: extension_block_patterns.clone(),
                extension_resources: extension_resources.clone(),
                background_webview_ids: background_webview_ids.clone(),
                blocked_resource_count: blocked_resource_count.clone(),
                blocked_ad_count: blocked_ad_count.clone(),
                blocked_tracker_count: blocked_tracker_count.clone(),
                console_messages: console_messages.clone(),
                network_records: network_records.clone(),
                web_resource_load_starts: web_resource_load_starts.clone(),
                url_events: url_events.clone(),
                page_title_events: page_title_events.clone(),
                web_request_blocking_handler: web_request_blocking_handler.clone(),
                load_status_events: load_status_events.clone(),
                frame_tree_events: frame_tree_events.clone(),
                accessibility_updates: accessibility_updates.clone(),
                media_session_events: media_session_events.clone(),
                webdriver_load_status_senders: webdriver_load_status_senders.clone(),
                window_rendering_context: window_rendering_context.clone(),
                auxiliary_webviews: Rc::new(RefCell::new(Vec::new())),
                hovered_auxiliary: Cell::new(None),
                focused_auxiliary: Cell::new(None),
            }),
            download_receiver,
            pdf_load_receiver,
            pdf_event_sender,
            pdf_event_receiver,
            pdf_loads: HashMap::new(),
            pdf_handles: HashMap::new(),
            next_pdf_id: 1,
            download_event_sender,
            download_event_receiver,
            download_handles: HashMap::new(),
            permission_requests,
            pending_permissions: HashMap::new(),
            next_permission_id: 1,
            download_waker,
            fallback_page_rendering_context: page_rendering_context,
            absolute_pointer_position: Cell::new(DevicePoint::zero()),
            pointer_position: Cell::new(DevicePoint::zero()),
            page_rendering_contexts: HashMap::new(),
            window_rendering_context,
            content_size: Cell::new(content_size),
            content_rects: RefCell::new(HashMap::new()),
            hovered_tab: Cell::new(None),
            modifiers: Cell::new(ModifiersState::empty()),
            memory_reports: Arc::new(Mutex::new(Vec::new())),
            privacy_policy,
            privacy_script,
            tab_content_managers: HashMap::new(),
            extension_scripts: HashMap::new(),
            background_webviews: HashMap::new(),
            background_content_managers: HashMap::new(),
            extension_messages,
            extension_popup: None,
            network_route_state,
            extension_block_patterns,
            extension_resources,
            background_webview_ids,
            blocked_resource_count,
            blocked_ad_count,
            blocked_tracker_count,
            console_messages,
            devtools_evaluations,
            reader_snapshots,
            dom_snapshots,
            page_text_snapshots,
            autofill_snapshots,
            page_inspection_snapshots,
            tab_screenshots,
            network_records,
            url_events,
            page_title_events,
            load_status_events,
            frame_tree_events,
            accessibility_updates,
            media_session_events,
            webdriver_receiver,
            webdriver_tab_ids: HashSet::new(),
            webdriver_load_status_senders,
            webdriver_shutdown_requested: false,
            theme,
            accessibility_active: false,
        })
    }

    /// Creates the window and offscreen page rendering contexts.
    fn create_rendering_contexts(window: &Window) -> Result<RenderingContexts, ServoError> {
        let display_handle = window
            .display_handle()
            .map_err(|error| ServoError::Native(format!("display handle: {error}")))?;
        let window_handle = window
            .window_handle()
            .map_err(|error| ServoError::Native(format!("window handle: {error}")))?;
        let content_size = window.inner_size();
        let window_rendering_context = Rc::new(
            WindowRenderingContext::new(display_handle, window_handle, content_size)
                .map_err(|error| ServoError::Native(format!("rendering context: {error:?}")))?,
        );
        let page_rendering_context =
            Rc::new(window_rendering_context.offscreen_context(content_size));
        Ok((
            window_rendering_context,
            page_rendering_context,
            content_size,
        ))
    }

    /// Builds Servo preferences for the embedder's privacy policy, network
    /// route, and optional `DevTools` server.
    fn embedder_preferences(
        privacy_policy: &PrivacyPolicy,
        network_route: &NetworkRoute,
        devtools_port: Option<u16>,
    ) -> servo::Preferences {
        let mut preferences = nomad_preferences();
        preferences.dom_webrtc_enabled = !privacy_policy.block_webrtc();
        preferences.dom_webrtc_transceiver_enabled = !privacy_policy.block_webrtc();
        preferences.network_http_proxy_uri.clear();
        preferences.network_https_proxy_uri.clear();
        preferences.network_http_no_proxy.clear();
        if let Some(proxy) = network_route.proxy() {
            let proxy_uri = proxy.uri();
            preferences.network_http_proxy_uri.clone_from(&proxy_uri);
            preferences.network_https_proxy_uri = proxy_uri;
        }
        preferences.network_nomad_block_third_party_cookies =
            privacy_policy.third_party_cookie_blocking();
        preferences.network_nomad_reduce_cross_site_referrers =
            privacy_policy.reduced_cross_site_referrers();
        preferences.network_nomad_partition_storage = privacy_policy.storage_partitioning();
        if let Some(port) = devtools_port {
            preferences.devtools_server_enabled = true;
            preferences.devtools_server_listen_address = format!("127.0.0.1:{port}");
        }
        preferences
    }

    /// Builds the Servo instance with the embedder's options and logging.
    fn build_servo_instance(
        preferences: servo::Preferences,
        waker: Box<dyn EventLoopWaker>,
        ignore_certificate_errors: bool,
        devtools_port: Option<u16>,
    ) -> Servo {
        let servo_options = servo::Opts {
            ignore_certificate_errors,
            ..servo::Opts::default()
        };
        let servo = ServoBuilder::default()
            .opts(servo_options)
            .preferences(preferences)
            .event_loop_waker(waker)
            .build();
        if devtools_port.is_some() {
            servo.set_delegate(Rc::new(NomadServoDelegate));
        }
        servo.setup_logging();
        servo
    }

    /// Installs Servo's network connection observer, feeding the diagnostics
    /// log. Returns the diagnostics handle.
    fn install_network_observer(network_route: &NetworkRoute) -> Arc<Mutex<NetworkDiagnostics>> {
        let network_diagnostics = Arc::new(Mutex::new(NetworkDiagnostics::new(
            network_route.dns_route(),
        )));
        let observer_diagnostics = network_diagnostics.clone();
        servo::set_network_observer(Some(Arc::new(move |event| {
            let event = map_network_connection_event(event);
            if let Ok(mut diagnostics) = observer_diagnostics.lock() {
                diagnostics.observe(event);
            }
        })));
        network_diagnostics
    }

    /// Returns whether the opt-in local `WebDriver` endpoint is attached to this
    /// renderer. The endpoint is disabled unless the native shell receives a
    /// `--webdriver <PORT>` argument, and it always binds to loopback.
    #[must_use]
    pub const fn webdriver_enabled(&self) -> bool {
        self.webdriver_receiver.is_some()
    }

    /// Returns and clears a WebDriver-requested process shutdown.
    pub fn take_webdriver_shutdown_request(&mut self) -> bool {
        std::mem::take(&mut self.webdriver_shutdown_requested)
    }

    #[must_use]
    pub const fn network_route(&self) -> &NetworkRoute {
        &self.network_route
    }

    #[must_use]
    pub const fn media_backend() -> MediaBackend {
        #[cfg(feature = "media-gstreamer")]
        {
            MediaBackend::GStreamer
        }
        #[cfg(not(feature = "media-gstreamer"))]
        {
            MediaBackend::Dummy
        }
    }

    #[must_use]
    pub const fn umc_diagnostics(&self) -> Option<&UmcDiagnostics> {
        self.umc_diagnostics.as_ref()
    }

    pub fn set_umc_diagnostics(&mut self, diagnostics: Option<UmcDiagnostics>) {
        self.umc_diagnostics = diagnostics;
    }

    #[must_use]
    pub fn network_diagnostics(&self) -> NetworkDiagnostics {
        match self.network_diagnostics.lock() {
            Ok(value) => value.clone(),
            Err(_) => NetworkDiagnostics::new(self.network_route.dns_route()),
        }
    }

    /// Reconfigures the live HTTP proxy contract while preserving site rules.
    ///
    /// The caller must replace the selected backend core before invoking this
    /// method. The renderer refuses invalid routes and never falls back to
    /// direct traffic.
    ///
    /// # Errors
    ///
    /// Returns an error when the route is invalid.
    pub fn set_network_route(&mut self, route: NetworkRoute) -> Result<(), ServoError> {
        let route = route.with_policy(self.network_route.policy().clone());
        route
            .validate()
            .map_err(|error| ServoError::Native(format!("invalid network route: {error:?}")))?;
        let proxy_uri = route
            .proxy()
            .map_or_else(String::new, super::network::ProxyEndpoint::uri);
        self.servo
            .set_preference("network_http_proxy_uri", PrefValue::Str(proxy_uri.clone()));
        self.servo
            .set_preference("network_https_proxy_uri", PrefValue::Str(proxy_uri));
        self.servo
            .set_preference("network_http_no_proxy", PrefValue::Str(String::new()));
        let dns_route = route.dns_route();
        self.network_route = route.clone();
        *self.network_route_state.borrow_mut() = route;
        if let Ok(mut diagnostics) = self.network_diagnostics.lock() {
            diagnostics.set_dns_route(dns_route);
        }
        Ok(())
    }

    /// Paints the active page, extension popup surface, and auxiliary
    /// `window.open` popup surfaces.
    ///
    /// # Errors
    ///
    /// Returns an error when a page's dirty-state queue or rendering context
    /// is poisoned or cannot be made current.
    pub fn paint_page(&self) -> Result<(), ServoError> {
        self.paint_visible_pages(&self.active_tab.into_iter().collect::<Vec<_>>())?;
        if let Some(popup) = &self.extension_popup {
            popup
                .context
                .make_current()
                .map_err(|error| ServoError::Native(format!("popup context: {error:?}")))?;
            popup.context.prepare_for_rendering();
            popup.webview.paint();
        }
        // Auxiliary `window.open` popups paint unconditionally like the
        // extension popup; their frames arrive via `notify_new_frame_ready`.
        for auxiliary in self.delegate.auxiliary_entries() {
            auxiliary
                .context
                .make_current()
                .map_err(|error| ServoError::Native(format!("auxiliary context: {error:?}")))?;
            auxiliary.context.prepare_for_rendering();
            auxiliary.webview.paint();
        }
        Ok(())
    }

    /// Paints visible split panes whose `WebView`s have produced a new frame.
    ///
    /// # Errors
    ///
    /// Returns an error when a dirty-state queue is poisoned or a page's
    /// rendering context cannot be made current.
    pub fn paint_visible_pages(&self, tab_ids: &[TabId]) -> Result<(), ServoError> {
        for tab_id in tab_ids {
            let Some(webview) = self.webviews.get(tab_id) else {
                continue;
            };
            let should_paint = self
                .delegate
                .dirty_webviews
                .lock()
                .map_err(|_| ServoError::Native("dirty WebView set is poisoned".to_owned()))?
                .remove(&webview.id());
            if !should_paint {
                continue;
            }
            let Some(context) = self.page_rendering_contexts.get(tab_id) else {
                continue;
            };
            context
                .make_current()
                .map_err(|error| ServoError::Native(format!("page context: {error:?}")))?;
            context.prepare_for_rendering();
            webview.paint();
        }
        Ok(())
    }

    pub fn resize(&self, size: PhysicalSize<u32>) {
        self.content_size.set(size);
        self.window_rendering_context.resize(size);
    }

    /// Moves the active page to the next browser-style zoom level while leaving
    /// Nomad's native chrome at its fixed logical size.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab or its webview is missing.
    pub fn step_active_page_zoom(&self, increase: bool) -> Result<f32, ServoError> {
        let tab_id = self
            .active_tab
            .ok_or_else(|| ServoError::Native("no active tab to zoom".to_owned()))?;
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native("active tab has no webview to zoom".to_owned()))?;
        let next_zoom = stepped_page_zoom(webview.page_zoom(), increase);
        webview.set_page_zoom(next_zoom);
        self.delegate.window.request_redraw();
        Ok(next_zoom)
    }

    /// Restores the active page to 100% without changing native chrome sizing.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab or its webview is missing.
    pub fn reset_active_page_zoom(&self) -> Result<(), ServoError> {
        let tab_id = self
            .active_tab
            .ok_or_else(|| ServoError::Native("no active tab to zoom".to_owned()))?;
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native("active tab has no webview to zoom".to_owned()))?;
        webview.set_page_zoom(1.0);
        self.delegate.window.request_redraw();
        Ok(())
    }

    /// Records the physical window rectangle occupied by a tab's composited page.
    // Physical window coordinates are bounded by on-screen window sizes;
    // narrowing f64 to the f32 page-rect geometry is intended.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn set_content_rect_for(
        &self,
        tab_id: TabId,
        origin: PhysicalPosition<f64>,
        size: PhysicalSize<u32>,
    ) {
        self.content_rects.borrow_mut().insert(
            tab_id,
            Rect::new(
                Point2D::new(origin.x as f32, origin.y as f32),
                Size2D::new(size.width as f32, size.height as f32),
            ),
        );
    }

    #[must_use]
    pub fn pointer_over_content(&self) -> bool {
        self.hovered_tab.get().is_some() || self.delegate.hovered_auxiliary.get().is_some()
    }

    /// Forwards native pointer and wheel input to the page under the pointer.
    pub fn handle_window_event(&self, event: &WindowEvent) {
        match event {
            WindowEvent::CursorMoved { position, .. } => self.handle_cursor_moved(position),
            WindowEvent::CursorLeft { .. } => {
                if let Some(webview) = self
                    .hovered_tab
                    .take()
                    .and_then(|tab_id| self.webviews.get(&tab_id))
                {
                    webview.notify_input_event(InputEvent::MouseLeftViewport(
                        MouseLeftViewportEvent::default(),
                    ));
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                self.handle_mouse_input(*state, *button);
            }
            WindowEvent::MouseWheel { delta, .. } => self.handle_mouse_wheel(delta),
            WindowEvent::ModifiersChanged(modifiers) => self.modifiers.set(modifiers.state()),
            WindowEvent::KeyboardInput { event, .. } => self.handle_keyboard_input(event),
            _ => {}
        }
    }

    // Pointer positions arrive as f64 physical pixels, but page geometry is
    // stored in f32; the values are bounded by on-screen window sizes.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn handle_cursor_moved(&self, position: &PhysicalPosition<f64>) {
        let absolute = Point2D::new(position.x as f32, position.y as f32);
        self.absolute_pointer_position
            .set(DevicePoint::new(absolute.x, absolute.y));
        // Auxiliary popups overlay both the chrome and the tab content
        // rects, so they are hit-tested first.
        let auxiliary_target = self
            .delegate
            .auxiliary_hit_test(DevicePoint::new(absolute.x, absolute.y));
        let previous_auxiliary = self.delegate.hovered_auxiliary.get();
        let next_auxiliary = auxiliary_target.map(|(webview_id, _)| webview_id);
        if previous_auxiliary != next_auxiliary {
            if let Some(previous_id) = previous_auxiliary {
                if let Some(webview) = self.delegate.auxiliary_webview(previous_id) {
                    webview.notify_input_event(InputEvent::MouseLeftViewport(
                        MouseLeftViewportEvent::default(),
                    ));
                }
            }
        }
        if let Some((webview_id, point)) = auxiliary_target {
            self.delegate.hovered_auxiliary.set(Some(webview_id));
            // Leave the previously hovered tab when the pointer moves onto
            // a popup.
            if let Some(webview) = self
                .hovered_tab
                .take()
                .and_then(|tab_id| self.webviews.get(&tab_id))
            {
                webview.notify_input_event(InputEvent::MouseLeftViewport(
                    MouseLeftViewportEvent::default(),
                ));
            }
            if let Some(webview) = self.delegate.auxiliary_webview(webview_id) {
                webview
                    .notify_input_event(InputEvent::MouseMove(MouseMoveEvent::new(point.into())));
            }
            return;
        }
        self.delegate.hovered_auxiliary.set(None);
        let target = self
            .content_rects
            .borrow()
            .iter()
            .find_map(|(tab_id, rect)| {
                let relative = absolute - rect.origin;
                rect.contains(absolute)
                    .then_some((*tab_id, DevicePoint::new(relative.x, relative.y)))
            });
        let previous = self.hovered_tab.replace(target.map(|(tab_id, _)| tab_id));
        if previous != self.hovered_tab.get() {
            if let Some(webview) = previous.and_then(|id| self.webviews.get(&id)) {
                webview.notify_input_event(InputEvent::MouseLeftViewport(
                    MouseLeftViewportEvent::default(),
                ));
            }
        }
        if let Some((tab_id, point)) = target {
            self.pointer_position.set(point);
            if let Some(webview) = self.webviews.get(&tab_id) {
                webview
                    .notify_input_event(InputEvent::MouseMove(MouseMoveEvent::new(point.into())));
            }
        }
    }

    fn handle_mouse_input(&self, state: ElementState, button: MouseButton) {
        // Auxiliary popups overlay the chrome and tab content; a press over
        // one routes there and moves keyboard focus to it.
        if let Some(webview_id) = self.delegate.hovered_auxiliary.get() {
            if let Some(webview) = self.delegate.auxiliary_webview(webview_id) {
                let button = match button {
                    MouseButton::Left => ServoMouseButton::Left,
                    MouseButton::Right => ServoMouseButton::Right,
                    MouseButton::Middle => ServoMouseButton::Middle,
                    MouseButton::Back => ServoMouseButton::Back,
                    MouseButton::Forward => ServoMouseButton::Forward,
                    MouseButton::Other(value) => ServoMouseButton::Other(value),
                };
                let action = match state {
                    ElementState::Pressed => MouseButtonAction::Down,
                    ElementState::Released => MouseButtonAction::Up,
                };
                if state == ElementState::Pressed {
                    self.delegate.focused_auxiliary.set(Some(webview_id));
                }
                let point = self
                    .delegate
                    .auxiliary_relative_point(webview_id, self.absolute_pointer_position.get())
                    .unwrap_or_default();
                webview.notify_input_event(InputEvent::MouseButton(MouseButtonEvent::new(
                    action,
                    button,
                    point.into(),
                )));
            }
            return;
        }
        if state == ElementState::Pressed {
            // Pressing outside any popup returns keyboard focus to the tabs.
            self.delegate.focused_auxiliary.set(None);
        }
        let Some(tab_id) = self.hovered_tab.get() else {
            return;
        };
        let Some(webview) = self.webviews.get(&tab_id) else {
            return;
        };
        let button = match button {
            MouseButton::Left => ServoMouseButton::Left,
            MouseButton::Right => ServoMouseButton::Right,
            MouseButton::Middle => ServoMouseButton::Middle,
            MouseButton::Back => ServoMouseButton::Back,
            MouseButton::Forward => ServoMouseButton::Forward,
            MouseButton::Other(value) => ServoMouseButton::Other(value),
        };
        let action = match state {
            ElementState::Pressed => MouseButtonAction::Down,
            ElementState::Released => MouseButtonAction::Up,
        };
        webview.notify_input_event(InputEvent::MouseButton(MouseButtonEvent::new(
            action,
            button,
            self.pointer_position.get().into(),
        )));
    }

    fn handle_mouse_wheel(&self, delta: &MouseScrollDelta) {
        // Auxiliary popups receive wheel input ahead of the hovered tab.
        if let Some(webview_id) = self.delegate.hovered_auxiliary.get() {
            if let Some(webview) = self.delegate.auxiliary_webview(webview_id) {
                let (x, y, mode) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => {
                        (f64::from(*x), f64::from(*y), WheelMode::DeltaLine)
                    }
                    MouseScrollDelta::PixelDelta(delta) => {
                        (delta.x, delta.y, WheelMode::DeltaPixel)
                    }
                };
                let (x, y) = stabilize_wheel_axes(x, y);
                if let Some(point) = self
                    .delegate
                    .auxiliary_relative_point(webview_id, self.absolute_pointer_position.get())
                {
                    webview.notify_input_event(InputEvent::Wheel(WheelEvent::new(
                        WheelDelta { x, y, z: 0.0, mode },
                        point.into(),
                    )));
                }
            }
            return;
        }
        let Some(tab_id) = self.hovered_tab.get() else {
            return;
        };
        let Some(webview) = self.webviews.get(&tab_id) else {
            return;
        };
        let (x, y, mode) = match delta {
            MouseScrollDelta::LineDelta(x, y) => {
                (f64::from(*x), f64::from(*y), WheelMode::DeltaLine)
            }
            MouseScrollDelta::PixelDelta(delta) => (delta.x, delta.y, WheelMode::DeltaPixel),
        };
        let (x, y) = stabilize_wheel_axes(x, y);
        webview.notify_input_event(InputEvent::Wheel(WheelEvent::new(
            WheelDelta { x, y, z: 0.0, mode },
            self.pointer_position.get().into(),
        )));
    }

    fn handle_keyboard_input(&self, event: &winit::event::KeyEvent) {
        // A focused auxiliary popup receives keyboard input ahead of the
        // active tab; stale focus entries fall through to the tab.
        if let Some(webview_id) = self.delegate.focused_auxiliary.get() {
            match self.delegate.auxiliary_webview(webview_id) {
                Some(webview) => {
                    webview.notify_input_event(InputEvent::Keyboard(servo_keyboard_event(
                        event,
                        self.modifiers.get(),
                    )));
                    return;
                }
                None => self.delegate.focused_auxiliary.set(None),
            }
        }
        let Some(tab_id) = self.active_tab else {
            return;
        };
        let Some(webview) = self.webviews.get(&tab_id) else {
            return;
        };
        webview.notify_input_event(InputEvent::Keyboard(servo_keyboard_event(
            event,
            self.modifiers.get(),
        )));
    }

    /// Applies the active browser privacy policy to new and existing `WebView`s.
    pub fn set_privacy_policy(&mut self, policy: PrivacyPolicy) -> bool {
        let previous_mode = self.privacy_policy.borrow().mode();
        let requires_private_context_reset = previous_mode != policy.mode()
            && matches!(
                (previous_mode, policy.mode()),
                (PrivacyMode::Private, _) | (_, PrivacyMode::Private)
            );
        if requires_private_context_reset {
            self.reset_tab_webviews_for_privacy_mode();
        }
        self.servo.set_preference(
            "network_nomad_block_third_party_cookies",
            PrefValue::Bool(policy.third_party_cookie_blocking()),
        );
        self.servo.set_preference(
            "network_nomad_reduce_cross_site_referrers",
            PrefValue::Bool(policy.reduced_cross_site_referrers()),
        );
        self.servo.set_preference(
            "network_nomad_partition_storage",
            PrefValue::Bool(policy.storage_partitioning()),
        );
        self.servo.set_preference(
            "dom_webrtc_enabled",
            PrefValue::Bool(!policy.block_webrtc()),
        );
        self.servo.set_preference(
            "dom_webrtc_transceiver_enabled",
            PrefValue::Bool(!policy.block_webrtc()),
        );
        let script_source = privacy_script(policy);
        let privacy_script = Rc::new(UserScript::new(script_source.clone(), None));
        for manager in self.tab_content_managers.values() {
            manager.remove_script(self.privacy_script.clone());
            manager.add_script(privacy_script.clone());
        }
        self.privacy_script = privacy_script;
        for webview in self.webviews.values() {
            webview.evaluate_javascript(&script_source, |_| {});
            if !policy.block_webrtc() {
                webview.evaluate_javascript(PRIVACY_WEBRTC_ALLOW_SCRIPT, |_| {});
            }
        }
        *self.privacy_policy.borrow_mut() = policy;
        requires_private_context_reset
    }

    fn reset_tab_webviews_for_privacy_mode(&mut self) {
        let tab_ids: Vec<_> = self.webviews.keys().copied().collect();
        for tab_id in tab_ids {
            if let Some(webview) = self.webviews.remove(&tab_id) {
                webview.hide();
            }
            self.page_rendering_contexts.remove(&tab_id);
            self.tab_content_managers.remove(&tab_id);
            self.extension_scripts.remove(&tab_id);
        }
        self.active_tab = None;
    }

    /// Applies site route rules to the live renderer without changing its proxy backend.
    ///
    /// # Errors
    ///
    /// Returns an error when the rules would create a direct bypass for a privacy route.
    pub fn set_route_policy(&mut self, policy: crate::SiteRoutePolicy) -> Result<(), ServoError> {
        let route = self.network_route.clone().with_policy(policy);
        route
            .validate()
            .map_err(|error| ServoError::Native(format!("invalid site route policy: {error:?}")))?;
        self.network_route = route.clone();
        *self.network_route_state.borrow_mut() = route;
        Ok(())
    }

    pub fn set_extension_blocking_patterns(&mut self, patterns: &[String]) {
        let mut target = self.extension_block_patterns.borrow_mut();
        target.clear();
        target.extend(
            patterns
                .iter()
                .filter(|pattern| !pattern.is_empty())
                .cloned(),
        );
    }

    pub fn set_web_request_blocking_handler(
        &mut self,
        handler: Arc<dyn WebRequestBlockingHandler>,
    ) {
        if let Ok(mut current) = self.delegate.web_request_blocking_handler.lock() {
            *current = handler;
        }
    }

    /// Registers static extension resources for interception.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource store is poisoned or a resource
    /// lacks an owner and path.
    pub fn install_extension_resources(
        &mut self,
        resources: &[ExtensionResource],
    ) -> Result<(), ServoError> {
        let mut installed = self
            .extension_resources
            .lock()
            .map_err(|_| ServoError::Native("extension resource store is poisoned".into()))?;
        for resource in resources {
            if resource.extension_id.trim().is_empty() || resource.path.trim().is_empty() {
                return Err(ServoError::Native(
                    "extension resource requires an owner and path".into(),
                ));
            }
            installed.insert(
                (resource.extension_id.clone(), resource.path.clone()),
                resource.clone(),
            );
        }
        Ok(())
    }

    /// Removes all static resources owned by an extension.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource store is poisoned.
    pub fn uninstall_extension_resources(&mut self, extension_id: &str) -> Result<(), ServoError> {
        let mut resources = self
            .extension_resources
            .lock()
            .map_err(|_| ServoError::Native("extension resource store is poisoned".into()))?;
        resources.retain(|(id, _), _| id != extension_id);
        Ok(())
    }

    /// Returns the live privacy policy and blocked-resource counter for the UI.
    #[must_use]
    pub fn privacy_diagnostics(&self) -> crate::PrivacyDiagnostics {
        let policy = *self.privacy_policy.borrow();
        crate::PrivacyDiagnostics {
            mode: policy.mode(),
            blocked_resources: self.blocked_resource_count.load(Ordering::Relaxed),
            blocked_ads: self.blocked_ad_count.load(Ordering::Relaxed),
            blocked_trackers: self.blocked_tracker_count.load(Ordering::Relaxed),
            tracking_protection: policy.tracking_protection(),
            storage_partitioning: policy.storage_partitioning(),
            anti_fingerprinting: policy.anti_fingerprinting(),
            advanced_fingerprinting: policy.advanced_fingerprinting(),
            block_webrtc: policy.block_webrtc(),
            dns_leak_protection: policy.dns_leak_protection(),
            third_party_cookie_blocking: policy.third_party_cookie_blocking(),
            reduced_cross_site_referrers: policy.reduced_cross_site_referrers(),
        }
    }

    /// Requests an allocator-backed Servo memory report for one tab.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab is not active or the report callback
    /// cannot be registered.
    pub fn request_memory_report(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview_id =
            self.webviews.get(&tab_id).map(WebView::id).ok_or_else(|| {
                ServoError::Native(format!("memory tab {tab_id:?} is not active"))
            })?;
        let reports = self.memory_reports.clone();
        let waker = self.download_waker.clone();
        let callback = GenericCallback::new(move |message| {
            if let Ok(MemoryReportResult { results }) = message {
                let bytes = results
                    .into_iter()
                    .flat_map(|process| process.reports)
                    .fold(0_u64, |total, report| {
                        total.saturating_add(u64::try_from(report.size).unwrap_or(u64::MAX))
                    });
                if let Ok(mut pending_reports) = reports.lock() {
                    push_bounded_event(&mut pending_reports, (tab_id, bytes));
                }
                waker.wake();
            }
        })
        .map_err(|error| ServoError::Native(format!("memory callback: {error}")))?;
        self.servo
            .create_webview_memory_report(webview_id, callback);
        Ok(())
    }

    /// Drains completed exact Servo memory samples.
    #[must_use]
    pub fn take_memory_reports(&self) -> Vec<(TabId, u64)> {
        self.memory_reports
            .lock()
            .map(|mut reports| reports.drain(..).collect())
            .unwrap_or_default()
    }

    /// Drains console records emitted by page content and maps them to Nomad
    /// tabs for the local `DevTools` panel.
    #[must_use]
    pub fn take_console_messages(&self) -> Vec<(TabId, ConsoleEntry)> {
        let messages = self
            .console_messages
            .lock()
            .map(|mut messages| messages.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        messages
            .into_iter()
            .filter_map(|(webview_id, level, message)| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == webview_id).then_some(*tab_id)
                })?;
                Some((
                    tab_id,
                    ConsoleEntry {
                        level,
                        message,
                        source: None,
                        line: None,
                    },
                ))
            })
            .collect()
    }

    /// Evaluates JavaScript in the active page context for the local
    /// `DevTools` console. Results are queued because Servo completes script
    /// execution asynchronously on its script thread.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview or the expression is
    /// empty.
    pub fn evaluate_devtools_javascript(
        &self,
        tab_id: TabId,
        expression: String,
    ) -> Result<(), ServoError> {
        if expression.trim().is_empty() {
            return Err(ServoError::Native(
                "DevTools expression must not be empty".to_owned(),
            ));
        }
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("DevTools tab {tab_id:?} is not active")))?;
        let evaluations = self.devtools_evaluations.clone();
        let waker = self.download_waker.clone();
        webview.evaluate_javascript(expression.clone(), move |result| {
            let result = result
                .map(|value| format_devtools_value(&value))
                .map_err(|error| format!("{error:?}"));
            if let Ok(mut pending) = evaluations.lock() {
                push_bounded_event(
                    &mut pending,
                    (tab_id, DevToolsEvaluation { expression, result }),
                );
            }
            waker.wake();
        });
        Ok(())
    }

    #[must_use]
    pub fn take_devtools_evaluations(&self) -> Vec<(TabId, DevToolsEvaluation)> {
        self.devtools_evaluations
            .lock()
            .map(|mut evaluations| evaluations.drain(..).collect())
            .unwrap_or_default()
    }

    /// Drains request-start records emitted by Servo's resource delegate.
    /// Response status is filled when the network backend exposes it; a
    /// pending record is still useful for local `DevTools` diagnostics.
    #[must_use]
    pub fn take_network_records(&self) -> Vec<(TabId, NetworkRequestRecord)> {
        let records = self
            .network_records
            .lock()
            .map(|mut records| records.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        records
            .into_iter()
            .filter_map(|(webview_id, record)| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == webview_id).then_some(*tab_id)
                })?;
                Some((tab_id, record))
            })
            .collect()
    }

    /// Drains page-title updates emitted by Servo and maps them to Nomad tabs.
    #[must_use]
    pub fn take_page_title_events(&self) -> Vec<(TabId, Option<String>)> {
        let events = self
            .page_title_events
            .lock()
            .map(|mut events| events.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        events
            .into_iter()
            .filter_map(|(webview_id, title)| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == webview_id).then_some(*tab_id)
                })?;
                Some((tab_id, title))
            })
            .collect()
    }

    /// Drains Servo load milestones and maps them to Nomad tabs.
    #[must_use]
    pub fn take_load_status_events(&self) -> Vec<(TabId, NavigationLoadStatus)> {
        let events = self
            .load_status_events
            .lock()
            .map(|mut events| events.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        events
            .into_iter()
            .filter_map(|(webview_id, status)| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == webview_id).then_some(*tab_id)
                })?;
                if self.webdriver_tab_ids.contains(&tab_id) {
                    return None;
                }
                Some((tab_id, status))
            })
            .collect()
    }

    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn take_extension_frame_tree_events(
        &self,
    ) -> Vec<(TabId, Vec<(u64, Option<u64>, String)>)> {
        let webviews = &self.webviews;
        self.frame_tree_events
            .lock()
            .map(|mut events| {
                events
                    .drain(..)
                    .filter_map(|(webview_id, frames)| {
                        webviews.iter().find_map(|(tab_id, webview)| {
                            (webview.id() == webview_id).then_some((*tab_id, frames.clone()))
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Drains top-level URL changes emitted by Servo and maps them to Nomad
    /// tabs. WebDriver-owned tabs are intentionally excluded from browser-shell
    /// state, because their navigation is controlled by the automation session.
    #[must_use]
    pub fn take_url_events(&self) -> Vec<(TabId, Url)> {
        let events = self
            .url_events
            .lock()
            .map(|mut events| events.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        events
            .into_iter()
            .filter_map(|(webview_id, url)| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == webview_id).then_some(*tab_id)
                })?;
                if self.webdriver_tab_ids.contains(&tab_id) {
                    return None;
                }
                Some((tab_id, url))
            })
            .collect()
    }

    /// Drains AccessKit updates emitted by Servo and maps them to Nomad tabs.
    ///
    /// The native shell owns the platform adapter. Keeping the renderer API
    /// independent of a specific macOS, Windows, or AT-SPI adapter lets the
    /// same Servo integration feed every supported desktop target.
    ///
    /// Updates keep their Servo-assigned subtree IDs: the browser chrome
    /// grafts each tab's document subtree under a graft node instead of
    /// merging ID spaces, so renderer node IDs can never collide with chrome
    /// node IDs.
    #[must_use]
    pub fn take_accessibility_updates(&self) -> Vec<(TabId, servo::accesskit::TreeUpdate)> {
        self.accessibility_updates
            .borrow_mut()
            .drain(..)
            .filter_map(|(webview_id, update)| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == webview_id).then_some(*tab_id)
                })?;
                Some((tab_id, update))
            })
            .collect()
    }

    /// Dispatch a supported page accessibility action to a tab's active Servo document.
    pub fn dispatch_accessibility_action(
        &mut self,
        tab_id: TabId,
        request: servo::accesskit::ActionRequest,
    ) -> bool {
        let Some(webview) = self.webviews.get(&tab_id) else {
            return false;
        };
        webview.notify_accessibility_action(request);
        true
    }

    /// Drains media-session metadata and playback updates emitted by page media.
    #[must_use]
    pub fn take_media_session_events(&self) -> Vec<(TabId, MediaSessionEvent)> {
        self.media_session_events
            .lock()
            .map(|mut events| events.drain(..).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(webview_id, event)| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == webview_id).then_some(*tab_id)
                })?;
                Some((tab_id, event))
            })
            .collect()
    }

    /// Sends a media-session action from the native UI to the active page media.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn dispatch_media_session_action(
        &self,
        tab_id: TabId,
        action: MediaSessionActionType,
    ) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("media tab {tab_id:?} is not active")))?;
        webview.notify_media_session_action_event(action);
        Ok(())
    }

    /// Toggles a local reader stylesheet inside one page without granting the
    /// page access to Nomad state or sending its contents elsewhere.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn set_reader_mode(&self, tab_id: TabId, enabled: bool) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("reader tab {tab_id:?} is not active")))?;
        let script = if enabled {
            r#"(() => {
                document.documentElement.classList.add("nomad-reader");
                let style = document.getElementById("nomad-reader-style");
                if (!style) {
                    style = document.createElement("style");
                    style.id = "nomad-reader-style";
                    style.textContent = "html.nomad-reader body { max-width: 760px !important; margin: 0 auto !important; padding: 2rem !important; line-height: 1.7 !important; } html.nomad-reader nav, html.nomad-reader aside, html.nomad-reader footer, html.nomad-reader script, html.nomad-reader style { display: none !important; }";
                    document.head.appendChild(style);
                }
            })();"#
        } else {
            r#"(() => { document.documentElement.classList.remove("nomad-reader"); })();"#
        };
        webview.evaluate_javascript(script, |_| {});
        Ok(())
    }

    /// Installs one permission-checked `WebExtension` content script into the
    /// forked Servo user-content pipeline. URL matching remains in the page
    /// wrapper because Servo's low-level user-script API is intentionally
    /// URL-agnostic.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab or an injection fails
    /// validation.
    pub fn install_extension_script(
        &mut self,
        injection: ExtensionInjection,
    ) -> Result<(), ServoError> {
        let tab_id = self
            .active_tab
            .ok_or_else(|| ServoError::Native("no active tab for extension script".into()))?;
        self.install_extension_scripts_for_tab(tab_id, &[injection])
    }

    /// Installs permission-checked `WebExtension` content scripts for the
    /// active tab.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no active tab or an injection fails
    /// validation.
    pub fn install_extension_scripts(
        &mut self,
        injections: &[ExtensionInjection],
    ) -> Result<(), ServoError> {
        let tab_id = self
            .active_tab
            .ok_or_else(|| ServoError::Native("no active tab for extension scripts".into()))?;
        self.install_extension_scripts_for_tab(tab_id, injections)
    }

    /// Installs permission-checked `WebExtension` content scripts into one
    /// tab.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab's content manager is unavailable or an
    /// injection fails validation.
    pub fn install_extension_scripts_for_tab(
        &mut self,
        tab_id: TabId,
        injections: &[ExtensionInjection],
    ) -> Result<(), ServoError> {
        self.ensure_webview(tab_id);
        let manager = self
            .tab_content_managers
            .get(&tab_id)
            .cloned()
            .ok_or_else(|| ServoError::Native("tab content manager is unavailable".into()))?;
        if let Some(previous) = self.extension_scripts.remove(&tab_id) {
            for scripts in previous.into_values() {
                for script in scripts {
                    manager.remove_script(script);
                }
            }
        }
        let mut grouped: HashMap<(String, bool), Vec<String>> = HashMap::new();
        for injection in injections {
            grouped
                .entry((
                    injection.extension_id.clone(),
                    matches!(injection.world, super::ExtensionScriptWorld::Main),
                ))
                .or_default()
                .push(Self::extension_script_source(injection)?);
        }
        let mut installed: HashMap<String, Vec<Rc<UserScript>>> = HashMap::new();
        for ((extension_id, main_world), scripts) in grouped {
            let world = if main_world {
                UserScriptWorld::Page
            } else {
                UserScriptWorld::Isolated(extension_id.clone())
            };
            let user_script = Rc::new(UserScript::new_in_world(scripts.join("\n"), None, world));
            manager.add_script(user_script.clone());
            installed.entry(extension_id).or_default().push(user_script);
        }
        self.extension_scripts.insert(tab_id, installed);
        Ok(())
    }

    fn extension_script_source(injection: &ExtensionInjection) -> Result<String, ServoError> {
        if injection.extension_id.trim().is_empty()
            || (injection.script.trim().is_empty()
                && injection
                    .style
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty())
        {
            return Err(ServoError::Native(
                "extension script requires an ID and source or stylesheet".to_owned(),
            ));
        }
        let patterns = injection
            .matches
            .iter()
            .map(|pattern| wildcard_pattern_regex(pattern))
            .collect::<Vec<_>>();
        let patterns = serde_json::to_string(&patterns)
            .map_err(|error| ServoError::Native(format!("extension pattern encoding: {error}")))?;
        let extension_id = serde_json::to_string(&injection.extension_id)
            .map_err(|error| ServoError::Native(format!("extension ID encoding: {error}")))?;
        let manifest = serde_json::to_string(&injection.manifest)
            .map_err(|error| ServoError::Native(format!("extension manifest encoding: {error}")))?;
        let storage_state = injection
            .storage
            .as_ref()
            .map(|storage| serde_json::to_string(&storage.local))
            .transpose()
            .map_err(|error| ServoError::Native(format!("extension storage encoding: {error}")))?
            .unwrap_or_else(|| "null".into());
        let sync_storage_state = injection
            .storage
            .as_ref()
            .map(|storage| serde_json::to_string(&storage.sync))
            .transpose()
            .map_err(|error| ServoError::Native(format!("extension storage encoding: {error}")))?
            .unwrap_or_else(|| "null".into());
        let session_storage_state = injection
            .storage
            .as_ref()
            .map(|storage| serde_json::to_string(&storage.session))
            .transpose()
            .map_err(|error| ServoError::Native(format!("extension storage encoding: {error}")))?
            .unwrap_or_else(|| "null".into());
        let tab_info = injection
            .tab
            .as_ref()
            .map(|tab| {
                serde_json::to_string(&serde_json::json!({
                    "id": tab.id,
                    "url": tab.url.as_ref().map(ToString::to_string),
                    "active": tab.active,
                }))
            })
            .transpose()
            .map_err(|error| ServoError::Native(format!("extension tab encoding: {error}")))?
            .unwrap_or_else(|| "null".into());
        let source = serde_json::to_string(&injection.script)
            .map_err(|error| ServoError::Native(format!("extension source encoding: {error}")))?;
        let (
            isolated_queue_key,
            isolated_dispatch_key,
            isolated_dispatch_event,
            isolated_dispatch_attribute,
            isolated_dispatch_element_id,
        ) = Self::isolated_dispatch_encodings(&injection.extension_id)?;
        let style = serde_json::to_string(injection.style.as_deref().unwrap_or_default())
            .map_err(|error| ServoError::Native(format!("extension style encoding: {error}")))?;
        let main_world = matches!(injection.world, super::ExtensionScriptWorld::Main);
        let script = EXTENSION_CONTENT_SCRIPT_TEMPLATE
            .replace("__NOMAD_EXTENSION_ID__", &extension_id)
            .replace("__NOMAD_MANIFEST__", &manifest)
            .replace("__NOMAD_STORAGE_STATE__", &storage_state)
            .replace("__NOMAD_SYNC_STORAGE_STATE__", &sync_storage_state)
            .replace("__NOMAD_SESSION_STORAGE_STATE__", &session_storage_state)
            .replace("__NOMAD_TAB_INFO__", &tab_info)
            .replace("__NOMAD_PATTERNS__", &patterns)
            .replace("__NOMAD_STYLE__", &style)
            .replace("__NOMAD_SOURCE__", &source)
            .replace("__NOMAD_ISOLATED_QUEUE_KEY__", &isolated_queue_key)
            .replace("__NOMAD_ISOLATED_DISPATCH_KEY__", &isolated_dispatch_key)
            .replace(
                "__NOMAD_ISOLATED_DISPATCH_EVENT__",
                &isolated_dispatch_event,
            )
            .replace(
                "__NOMAD_ISOLATED_DISPATCH_ATTRIBUTE__",
                &isolated_dispatch_attribute,
            )
            .replace(
                "__NOMAD_ISOLATED_DISPATCH_ELEMENT_ID__",
                &isolated_dispatch_element_id,
            )
            .replace(
                "__NOMAD_MAIN_WORLD__",
                if main_world { "true" } else { "false" },
            );
        Ok(script)
    }

    /// Encodes the isolated-world queue and dispatcher identifiers for one
    /// extension.
    fn isolated_dispatch_encodings(
        extension_id: &str,
    ) -> Result<(String, String, String, String, String), ServoError> {
        let isolated_queue_key = serde_json::to_string(&format!(
            "__nomad_extension_messages_{extension_id}_isolated"
        ))
        .map_err(|error| ServoError::Native(format!("extension queue key encoding: {error}")))?;
        let isolated_dispatch_key = serde_json::to_string(&format!(
            "__nomad_extension_dispatchers_{extension_id}_isolated"
        ))
        .map_err(|error| ServoError::Native(format!("extension dispatch key encoding: {error}")))?;
        let isolated_dispatch_event =
            serde_json::to_string(&format!("__nomad_extension_dispatch_{extension_id}")).map_err(
                |error| ServoError::Native(format!("extension dispatch event encoding: {error}")),
            )?;
        let isolated_dispatch_attribute =
            serde_json::to_string(&format!("data-nomad-extension-dispatch-{extension_id}"))
                .map_err(|error| {
                    ServoError::Native(format!("extension dispatch attribute encoding: {error}"))
                })?;
        let isolated_dispatch_element_id =
            serde_json::to_string(&format!("nomad-extension-dispatch-{extension_id}")).map_err(
                |error| ServoError::Native(format!("extension dispatch element encoding: {error}")),
            )?;
        Ok((
            isolated_queue_key,
            isolated_dispatch_key,
            isolated_dispatch_event,
            isolated_dispatch_attribute,
            isolated_dispatch_element_id,
        ))
    }
    /// Requests content-script messages queued by the renderer-side bridge.
    /// The bridge exposes permission-scoped `runtime.sendMessage`,
    /// `storage.local`, and current-tab `tabs.query` shims. Rust validates the
    /// target extension, host, and storage capability before applying any
    /// page-originated operation. Each isolated extension world has its own
    /// message queue, so retrieval is evaluated in the matching Servo world.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview or the isolated
    /// world queue key cannot be encoded.
    pub fn request_extension_messages(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        let Some(scripts) = self.extension_scripts.get(&tab_id) else {
            return Ok(());
        };
        if scripts.is_empty() {
            return Ok(());
        }
        let isolated_worlds = scripts.keys().cloned().collect::<Vec<_>>();
        let messages = self.extension_messages.clone();
        webview.evaluate_javascript(
            "(() => { const queue = globalThis.__nomad_extension_messages; if (!Array.isArray(queue)) return '[]'; return JSON.stringify(queue.splice(0, 1024)); })()",
            Self::collect_extension_page_messages(messages.clone(), tab_id),
        );
        for extension_id in isolated_worlds {
            let messages = messages.clone();
            let queue_key = serde_json::to_string(&format!(
                "__nomad_extension_messages_{extension_id}_isolated"
            ))
            .map_err(|error| {
                ServoError::Native(format!("extension queue key encoding: {error}"))
            })?;
            webview.evaluate_javascript_in_world(
                format!(
                    "(() => {{ const queue = globalThis[Symbol.for({queue_key})]; if (!Array.isArray(queue)) return '[]'; return JSON.stringify(queue.splice(0, 1024)); }})()"
                ),
                UserScriptWorld::Isolated(extension_id),
                Self::collect_extension_page_messages(messages, tab_id),
            );
        }
        Ok(())
    }

    fn collect_extension_page_messages(
        messages: Arc<Mutex<Vec<ExtensionMessage>>>,
        tab_id: TabId,
    ) -> impl FnOnce(Result<servo::JSValue, servo::JavaScriptEvaluationError>) + 'static {
        move |result| {
            let Ok(servo::JSValue::String(raw)) = result else {
                return;
            };
            let Ok(raw_messages) = serde_json::from_str::<Vec<RawExtensionPageMessage>>(&raw)
            else {
                return;
            };
            if let Ok(mut pending) = messages.lock() {
                for message in raw_messages {
                    push_bounded_event(
                        &mut pending,
                        ExtensionMessage {
                            extension_id: message.extension_id,
                            tab_id: Some(tab_id.get()),
                            payload: message.payload,
                        },
                    );
                }
            }
        }
    }

    pub fn take_extension_messages(&self) -> Vec<ExtensionMessage> {
        self.extension_messages
            .lock()
            .map(|mut messages| std::mem::take(&mut *messages))
            .unwrap_or_default()
    }

    /// Opens the active extension popup in its own browser-rendered surface.
    ///
    /// # Errors
    ///
    /// Returns an error when the popup resource is unavailable or Servo cannot
    /// create the rendering surface.
    ///
    /// # Panics
    ///
    /// Panics if the hard-coded `about:blank` URL fails to parse, which
    /// cannot happen in practice.
    pub fn open_extension_popup(
        &mut self,
        extension_id: &str,
        manifest: &ExtensionManifest,
        source: &str,
        resource_path: &str,
        storage: &ExtensionStorage,
    ) -> Result<(), ServoError> {
        if extension_id.trim().is_empty()
            || (source.trim().is_empty() && resource_path.trim().is_empty())
        {
            return Err(ServoError::Native(
                "extension popup requires an ID and resource".into(),
            ));
        }
        if let Some(popup) = self.extension_popup.take() {
            popup.webview.hide();
        }
        let popup_size = PhysicalSize::new(420, 620);
        let context = Rc::new(self.window_rendering_context.offscreen_context(popup_size));
        let manager = Rc::new(UserContentManager::new(&self.servo));
        let bootstrap = Self::extension_background_source(
            extension_id,
            manifest,
            "",
            false,
            false,
            &[],
            storage,
        )?;
        manager.add_script(Rc::new(UserScript::new(bootstrap, None)));
        let initial_url = if resource_path.trim().is_empty() {
            Url::parse("about:blank").expect("about:blank is a valid URL")
        } else {
            extension_resource_uri(extension_id, resource_path)
                .map_err(|error| ServoError::Native(format!("extension popup URL: {error:?}")))?
        };
        let webview = WebViewBuilder::new(&self.servo, context.clone())
            .url(initial_url.clone())
            .delegate(self.delegate.clone())
            .private_browsing(true)
            .user_content_manager(manager.clone())
            .build();
        webview.load(initial_url);
        if resource_path.trim().is_empty() {
            let html = serde_json::to_string(source).map_err(|error| {
                ServoError::Native(format!("extension popup encoding: {error}"))
            })?;
            webview.evaluate_javascript(
                format!(
                    "(() => {{ document.open(); document.write({html}); document.close(); }})()"
                ),
                |_| {},
            );
        }
        webview.show();
        self.extension_popup = Some(ExtensionPopup {
            context,
            webview,
            _user_content_manager: manager,
        });
        self.servo.spin_event_loop();
        Ok(())
    }

    pub fn extension_popup_render_callback(&self) -> Option<RenderToParentCallback> {
        self.extension_popup
            .as_ref()
            .and_then(|popup| popup.context.render_to_parent_callback())
    }

    /// Render callbacks and overlay rectangles (device pixels) for all live
    /// auxiliary `window.open` popups, oldest first.
    pub fn auxiliary_render_callbacks(
        &self,
    ) -> Vec<(Rect<f32, euclid::UnknownUnit>, RenderToParentCallback)> {
        self.delegate
            .auxiliary_entries()
            .iter()
            .filter_map(|entry| {
                entry
                    .context
                    .render_to_parent_callback()
                    .map(|callback| (entry.rect, callback))
            })
            .collect()
    }

    /// Executes a checked extension script in the target document.
    ///
    /// # Errors
    ///
    /// Returns an error when the target `WebView` or script encoding is missing.
    pub fn execute_extension_script(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
        source: &str,
    ) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        if extension_id.trim().is_empty() {
            return Err(ServoError::Native(
                "extension script requires a non-empty extension id".into(),
            ));
        }
        webview.evaluate_javascript_in_world(
            source,
            UserScriptWorld::Isolated(extension_id.to_owned()),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }
    #[allow(clippy::missing_errors_doc)]
    pub fn execute_extension_script_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
        source: &str,
    ) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        let Some(handle) = frame_handle else {
            return self.execute_extension_script(tab_id, extension_id, source);
        };
        let pipeline_id = servo::PipelineId::from_u64(handle)
            .ok_or_else(|| ServoError::Native("invalid extension frame handle".into()))?;
        webview.evaluate_javascript_in_pipeline(
            pipeline_id,
            source,
            UserScriptWorld::Isolated(extension_id.to_owned()),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }

    /// Inserts isolated-world CSS for an extension into the target tab.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview, the extension id
    /// is empty, or the CSS payload cannot be JSON-encoded.
    pub fn insert_extension_css(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
        source: &str,
    ) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        if extension_id.trim().is_empty() {
            return Err(ServoError::Native(
                "extension css requires a non-empty extension id".into(),
            ));
        }
        let css = serde_json::to_string(source)
            .map_err(|error| ServoError::Native(format!("extension css encoding: {error}")))?;
        webview.evaluate_javascript_in_world(
            format!(
                "(() => {{ const id = '__nomad_css_' + {extension_id:?}; \
                   const previous = document.getElementById(id); \
                   if (previous) previous.remove(); \
                   const style = document.createElement('style'); \
                   style.id = id; \
                   style.textContent = {css}; \
                   (document.head || document.documentElement).appendChild(style); }})()"
            ),
            UserScriptWorld::Isolated(extension_id.to_owned()),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }

    /// Removes previously inserted isolated-world CSS for an extension.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview or the extension
    /// id is empty.
    pub fn remove_extension_css(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
    ) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        if extension_id.trim().is_empty() {
            return Err(ServoError::Native(
                "extension css requires a non-empty extension id".into(),
            ));
        }
        webview.evaluate_javascript_in_world(
            format!(
                "(() => {{ const el = document.getElementById('__nomad_css_' + {extension_id:?}); \
                   if (el) el.remove(); }})()"
            ),
            UserScriptWorld::Isolated(extension_id.to_owned()),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn insert_extension_css_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
        source: &str,
    ) -> Result<(), ServoError> {
        let Some(handle) = frame_handle else {
            return self.insert_extension_css(tab_id, extension_id, source);
        };
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        let pipeline_id = servo::PipelineId::from_u64(handle)
            .ok_or_else(|| ServoError::Native("invalid extension frame handle".into()))?;
        let css = serde_json::to_string(source)
            .map_err(|error| ServoError::Native(format!("extension css encoding: {error}")))?;
        webview.evaluate_javascript_in_pipeline(
            pipeline_id,
            format!(
                "(() => {{ const id = '__nomad_css_' + {extension_id:?}; \
                   const previous = document.getElementById(id); \
                   if (previous) previous.remove(); \
                   const style = document.createElement('style'); \
                   style.id = id; style.textContent = {css}; \
                   (document.head || document.documentElement).appendChild(style); }})()"
            ),
            UserScriptWorld::Isolated(extension_id.to_owned()),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn remove_extension_css_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
    ) -> Result<(), ServoError> {
        let Some(handle) = frame_handle else {
            return self.remove_extension_css(tab_id, extension_id);
        };
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        let pipeline_id = servo::PipelineId::from_u64(handle)
            .ok_or_else(|| ServoError::Native("invalid extension frame handle".into()))?;
        webview.evaluate_javascript_in_pipeline(
            pipeline_id,
            format!(
                "(() => {{ const el = document.getElementById('__nomad_css_' + {extension_id:?}); \
                   if (el) el.remove(); }})()"
            ),
            UserScriptWorld::Isolated(extension_id.to_owned()),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }

    /// Performs a cookie operation against Servo's site-data cookie jar.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation arguments or cookie value are
    /// invalid.
    pub fn extension_cookie_operation(
        &mut self,
        method: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, ServoError> {
        let options = arguments.as_object().ok_or_else(|| {
            ServoError::Native("extension cookie operation expects an object".into())
        })?;
        let url = options
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ServoError::Native("cookie operation requires url".into()))?
            .parse::<Url>()
            .map_err(|_| ServoError::Native("cookie URL is invalid".into()))?;
        let manager = self.servo.site_data_manager();
        match method {
            "cookies.get" | "cookies.getAll" => {
                let name = options.get("name").and_then(serde_json::Value::as_str);
                let domain = options.get("domain").and_then(serde_json::Value::as_str);
                let path = options.get("path").and_then(serde_json::Value::as_str);
                let cookies = manager
                    .cookies_for_url(url, servo::CookieSource::HTTP)
                    .into_iter()
                    .filter(|cookie| name.is_none_or(|value| cookie.name() == value))
                    .filter(|cookie| domain.is_none_or(|value| cookie.domain() == Some(value)))
                    .filter(|cookie| path.is_none_or(|value| cookie.path() == Some(value)))
                    .map(|cookie| cookie_to_json(&cookie))
                    .collect::<Vec<_>>();
                if method == "cookies.get" {
                    Ok(cookies
                        .into_iter()
                        .next()
                        .unwrap_or(serde_json::Value::Null))
                } else {
                    Ok(serde_json::Value::Array(cookies))
                }
            }
            "cookies.set" => {
                let name = options
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| ServoError::Native("cookies.set requires name".into()))?;
                let value = options
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let mut builder = Cookie::build((name.to_owned(), value.to_owned()));
                if let Some(path) = options.get("path").and_then(serde_json::Value::as_str) {
                    builder = builder.path(path.to_owned());
                }
                if let Some(domain) = options.get("domain").and_then(serde_json::Value::as_str) {
                    builder = builder.domain(domain.to_owned());
                }
                if options
                    .get("secure")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                {
                    builder = builder.secure(true);
                }
                if options
                    .get("httpOnly")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                {
                    builder = builder.http_only(true);
                }
                let cookie = builder.build().into_owned();
                let result = cookie_to_json(&cookie);
                manager.set_cookie_for_url(url, cookie, None);
                Ok(result)
            }
            "cookies.remove" => {
                let name = options
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| ServoError::Native("cookies.remove requires name".into()))?;
                let mut builder = Cookie::build((name.to_owned(), String::new()))
                    .max_age(cookie::time::Duration::seconds(0));
                if let Some(path) = options.get("path").and_then(serde_json::Value::as_str) {
                    builder = builder.path(path.to_owned());
                }
                if let Some(domain) = options.get("domain").and_then(serde_json::Value::as_str) {
                    builder = builder.domain(domain.to_owned());
                }
                manager.set_cookie_for_url(url.clone(), builder.build().into_owned(), None);
                Ok(serde_json::json!({"url": url, "name": name}))
            }
            _ => Err(ServoError::Native(format!(
                "unsupported cookie operation {method}"
            ))),
        }
    }

    /// Dispatches a `WebExtension` runtime message to its tab's content and
    /// isolated-world dispatchers.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview or a message payload
    /// cannot be encoded.
    pub fn dispatch_extension_message(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
        payload: &serde_json::Value,
    ) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("extension tab {tab_id:?} is not active")))?;
        let isolated_dispatch_key = serde_json::to_string(&format!(
            "__nomad_extension_dispatchers_{extension_id}_isolated"
        ))
        .map_err(|error| ServoError::Native(format!("isolated dispatch key encoding: {error}")))?;
        let isolated_world_name = extension_id.to_owned();
        let extension_id = serde_json::to_string(extension_id)
            .map_err(|error| ServoError::Native(format!("extension ID encoding: {error}")))?;
        let payload = serde_json::to_string(payload)
            .map_err(|error| ServoError::Native(format!("extension message encoding: {error}")))?;
        webview.evaluate_javascript(
            format!(
                "(() => {{ const dispatchers = globalThis.__nomad_extension_dispatchers; const dispatch = dispatchers && dispatchers[{extension_id}]; if (typeof dispatch !== 'function') return false; dispatch({payload}); return true; }})()"
            ),
            |_| {},
        );
        // DOM events dispatched from the page realm do not cross into Servo's
        // isolated user-script realm. Invoke the per-extension dispatcher in
        // its owning world directly; this keeps the event and listener
        // closures in one realm and matches WebExtensions delivery semantics.
        webview.evaluate_javascript_in_world(
            format!(
                "(() => {{ const dispatchers = globalThis[Symbol.for({isolated_dispatch_key})]; const dispatch = dispatchers && dispatchers[{extension_id}]; if (typeof dispatch !== 'function') return false; dispatch({payload}); return true; }})()"
            ),
            UserScriptWorld::Isolated(isolated_world_name),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }

    pub fn uninstall_extension_script(&mut self, extension_id: &str) {
        for (tab_id, scripts) in &mut self.extension_scripts {
            if let Some(removed) = scripts.remove(extension_id) {
                if let Some(manager) = self.tab_content_managers.get(tab_id) {
                    for script in removed {
                        manager.remove_script(script);
                    }
                }
            }
        }
    }

    /// Installs an extension's background page or service worker in a hidden
    /// webview.
    ///
    /// # Errors
    ///
    /// Returns an error when the extension id or source is empty, the
    /// background source cannot be built, or the background URL cannot be
    /// resolved.
    pub fn install_extension_background(
        &mut self,
        extension_id: &str,
        manifest: &ExtensionManifest,
        script: &str,
        service_worker: bool,
        script_paths: &[String],
        storage: &ExtensionStorage,
    ) -> Result<(), ServoError> {
        if extension_id.trim().is_empty() || (script.trim().is_empty() && script_paths.is_empty()) {
            return Err(ServoError::Native(
                "extension background requires an ID and source".into(),
            ));
        }
        if let Some(webview) = self.background_webviews.remove(extension_id) {
            webview.hide();
        }
        if let Ok(mut ids) = self.background_webview_ids.lock() {
            ids.retain(|(id, _)| id != extension_id);
        }
        self.background_content_managers.remove(extension_id);
        let manager = Rc::new(UserContentManager::new(&self.servo));
        let source = Self::extension_background_source(
            extension_id,
            manifest,
            script,
            service_worker,
            manifest
                .background
                .as_ref()
                .is_some_and(|background| background.module),
            script_paths,
            storage,
        )?;
        let user_script = Rc::new(UserScript::new(source, None));
        manager.add_script(user_script);
        let initial_url = extension_resource_uri(extension_id, "__nomad/background.html")
            .map_err(|error| ServoError::Native(format!("extension background URL: {error:?}")))?;
        let webview =
            WebViewBuilder::new(&self.servo, self.fallback_page_rendering_context.clone())
                .url(initial_url.clone())
                .delegate(self.delegate.clone())
                .private_browsing(true)
                .user_content_manager(manager.clone())
                .build();
        webview.hide();
        webview.load(initial_url);
        self.background_content_managers
            .insert(extension_id.to_owned(), manager);
        let webview_id = webview.id();
        self.background_webviews
            .insert(extension_id.to_owned(), webview);
        if let Ok(mut ids) = self.background_webview_ids.lock() {
            ids.insert((extension_id.to_owned(), webview_id));
        }
        self.servo.spin_event_loop();
        Ok(())
    }

    /// Dispatches an extension event to the installed background page.
    ///
    /// # Errors
    ///
    /// Returns an error when the background is not installed or the event
    /// payload cannot be encoded.
    pub fn dispatch_extension_event(&mut self, event: &ExtensionEvent) -> Result<(), ServoError> {
        let webview = self
            .background_webviews
            .get(&event.extension_id)
            .ok_or_else(|| ServoError::Native("extension background is not installed".into()))?;
        let value = extension_event_value(event);
        let encoded = serde_json::to_string(&value)
            .map_err(|error| ServoError::Native(format!("extension event encoding: {error}")))?;
        webview.evaluate_javascript(
            format!(
                "(() => {{ const dispatch = globalThis.__nomad_extension_dispatch; if (typeof dispatch !== 'function') return false; dispatch({encoded}); return true; }})()"
            ),
            |_| {},
        );
        self.servo.spin_event_loop();
        Ok(())
    }

    /// Polls each installed extension background for queued page messages.
    ///
    /// # Errors
    ///
    /// Currently never fails; the `Result` keeps the bridge's fallible
    /// contract stable.
    pub fn request_extension_background_messages(&self) -> Result<(), ServoError> {
        if self.background_webviews.is_empty() {
            return Ok(());
        }
        for (extension_id, webview) in &self.background_webviews {
            let messages = self.extension_messages.clone();
            let extension_id = extension_id.clone();
            webview.evaluate_javascript(
                "(() => { const queue = globalThis.__nomad_extension_messages; if (!Array.isArray(queue)) return '[]'; return JSON.stringify(queue.splice(0, 1024)); })()",
                move |result| {
                    let Ok(servo::JSValue::String(raw)) = result else {
                        return;
                    };
                    let Ok(raw_messages) =
                        serde_json::from_str::<Vec<RawExtensionBackgroundMessage>>(&raw)
                    else {
                        return;
                    };
                    if let Ok(mut pending) = messages.lock() {
                        for message in raw_messages {
                            push_bounded_event(
                                &mut pending,
                                ExtensionMessage {
                                    extension_id: extension_id.clone(),
                                    tab_id: None,
                                    payload: message.payload,
                                },
                            );
                        }
                    }
                },
            );
        }
        Ok(())
    }

    pub fn uninstall_extension_background(&mut self, extension_id: &str) {
        if let Some(webview) = self.background_webviews.remove(extension_id) {
            webview.hide();
        }
        if let Ok(mut ids) = self.background_webview_ids.lock() {
            ids.retain(|(id, _)| id != extension_id);
        }
        self.background_content_managers.remove(extension_id);
    }

    fn extension_background_source(
        extension_id: &str,
        manifest: &ExtensionManifest,
        source: &str,
        service_worker: bool,
        module: bool,
        script_paths: &[String],
        storage: &ExtensionStorage,
    ) -> Result<String, ServoError> {
        let extension_id = serde_json::to_string(extension_id)
            .map_err(|error| ServoError::Native(format!("extension ID encoding: {error}")))?;
        let context_kind = if service_worker {
            "service_worker"
        } else {
            "background_page"
        };
        let context_kind = serde_json::to_string(context_kind)
            .map_err(|error| ServoError::Native(format!("extension context encoding: {error}")))?;
        let module = if module { "true" } else { "false" };
        let storage_state = serde_json::to_string(&storage.local)
            .map_err(|error| ServoError::Native(format!("extension storage encoding: {error}")))?;
        let sync_storage_state = serde_json::to_string(&storage.sync)
            .map_err(|error| ServoError::Native(format!("extension storage encoding: {error}")))?;
        let session_storage_state = serde_json::to_string(&storage.session)
            .map_err(|error| ServoError::Native(format!("extension storage encoding: {error}")))?;
        let manifest = serde_json::to_string(manifest)
            .map_err(|error| ServoError::Native(format!("extension manifest encoding: {error}")))?;
        let script_paths = serde_json::to_string(script_paths).map_err(|error| {
            ServoError::Native(format!("extension script path encoding: {error}"))
        })?;
        let source = serde_json::to_string(source)
            .map_err(|error| ServoError::Native(format!("extension source encoding: {error}")))?;
        let script = EXTENSION_BACKGROUND_SCRIPT_TEMPLATE
            .replace("__NOMAD_EXTENSION_ID__", &extension_id)
            .replace("__NOMAD_STORAGE_STATE__", &storage_state)
            .replace("__NOMAD_SYNC_STORAGE_STATE__", &sync_storage_state)
            .replace("__NOMAD_SESSION_STORAGE_STATE__", &session_storage_state)
            .replace("__NOMAD_SCRIPT_PATHS__", &script_paths)
            .replace("__NOMAD_MANIFEST__", &manifest)
            .replace("__NOMAD_CONTEXT_KIND__", &context_kind)
            .replace("__NOMAD_MODULE__", module)
            .replace("__NOMAD_SOURCE__", &source);
        Ok(script)
    }

    /// Requests a serialized DOM snapshot for reader mode. The callback is
    /// asynchronous because page JavaScript executes on Servo's script thread.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn request_reader_snapshot(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("reader tab {tab_id:?} is not active")))?;
        let snapshots = self.reader_snapshots.clone();
        let waker = self.download_waker.clone();
        webview.evaluate_javascript(
            "document.documentElement ? document.documentElement.outerHTML : ''",
            move |result| {
                if let Ok(servo::JSValue::String(html)) = result {
                    if let Ok(mut pending) = snapshots.lock() {
                        push_bounded_event(&mut pending, (tab_id, html));
                    }
                    waker.wake();
                }
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn take_reader_snapshots(&self) -> Vec<(TabId, String)> {
        self.reader_snapshots
            .lock()
            .map(|mut snapshots| snapshots.drain(..).collect())
            .unwrap_or_default()
    }

    /// Requests the current serialized DOM for the `DevTools` inspector.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn request_dom_snapshot(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("DOM tab {tab_id:?} is not active")))?;
        let snapshots = self.dom_snapshots.clone();
        let waker = self.download_waker.clone();
        webview.evaluate_javascript(
            r"JSON.stringify((() => {
                const serialize = (node, depth) => ({
                    node_type: node.nodeType,
                    node_name: node.nodeName || '#text',
                    node_value: node.nodeType === 3 || node.nodeType === 8
                        ? (node.nodeValue || '').slice(0, 2000)
                        : null,
                    attributes: node.nodeType === 1
                        ? Array.from(node.attributes || [])
                            .slice(0, 64)
                            .map((attribute) => [attribute.name, attribute.value])
                        : [],
                    children: depth >= 8
                        ? []
                        : Array.from(node.childNodes || [])
                            .slice(0, 256)
                            .map((child) => serialize(child, depth + 1)),
                });
                const stylesheets = Array.from(document.styleSheets || [])
                    .slice(0, 64)
                    .map((sheet) => {
                        let rules = [];
                        try {
                            rules = Array.from(sheet.cssRules || [])
                                .slice(0, 256)
                                .map((rule) => rule.cssText || '');
                        } catch (_) {}
                        return { href: sheet.href || 'inline', rules };
                    });
                return {
                    root: serialize(document.documentElement || document, 0),
                    stylesheets,
                };
            })())",
            move |result| {
                let Ok(servo::JSValue::String(json)) = result else {
                    return;
                };
                if let Ok(dom) = serde_json::from_str::<DevToolsDomSnapshot>(&json) {
                    if let Ok(mut pending) = snapshots.lock() {
                        push_bounded_event(&mut pending, (tab_id, dom));
                    }
                    waker.wake();
                }
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn take_dom_snapshots(&self) -> Vec<(TabId, DevToolsDomSnapshot)> {
        self.dom_snapshots
            .lock()
            .map(|mut snapshots| snapshots.drain(..).collect())
            .unwrap_or_default()
    }

    /// Requests page-visible text for the local translation widget.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn request_page_text(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview = self.webviews.get(&tab_id).ok_or_else(|| {
            ServoError::Native(format!("translation tab {tab_id:?} is not active"))
        })?;
        let snapshots = self.page_text_snapshots.clone();
        let waker = self.download_waker.clone();
        webview.evaluate_javascript(
            "document.body ? document.body.innerText : ''",
            move |result| {
                if let Ok(servo::JSValue::String(text)) = result {
                    if let Ok(mut pending) = snapshots.lock() {
                        push_bounded_event(&mut pending, (tab_id, text));
                    }
                    waker.wake();
                }
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn take_page_text_snapshots(&self) -> Vec<(TabId, String)> {
        self.page_text_snapshots
            .lock()
            .map(|mut snapshots| snapshots.drain(..).collect())
            .unwrap_or_default()
    }

    /// Collects non-secret form metadata for the browser-owned autofill UI.
    /// Field values are never read by this probe.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn request_autofill_snapshot(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("autofill tab {tab_id:?} is not active")))?;
        let snapshots = self.autofill_snapshots.clone();
        let waker = self.download_waker.clone();
        webview.evaluate_javascript_in_world(
            r"JSON.stringify(Array.from(document.querySelectorAll('input, textarea, select'))
                .slice(0, 128)
                .map((field) => ({
                    name: field.name || '',
                    id: field.id || '',
                    label: field.labels?.[0]?.innerText || field.getAttribute('aria-label') || '',
                    input_type: field.type || field.tagName.toLowerCase(),
                    autocomplete: field.autocomplete || '',
                })))",
            UserScriptWorld::Isolated("__nomad_browser_autofill".into()),
            move |result| {
                let Ok(servo::JSValue::String(json)) = result else {
                    return;
                };
                let Ok(fields) = serde_json::from_str::<Vec<AutofillFieldDescriptor>>(&json) else {
                    return;
                };
                if let Ok(mut pending) = snapshots.lock() {
                    push_bounded_event(&mut pending, (tab_id, fields));
                }
                waker.wake();
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn take_autofill_snapshots(&self) -> Vec<(TabId, Vec<AutofillFieldDescriptor>)> {
        self.autofill_snapshots
            .lock()
            .map(|mut snapshots| snapshots.drain(..).collect())
            .unwrap_or_default()
    }

    /// Fills the first classified username and password fields in an isolated
    /// browser-owned world after the native confirmation flow has completed.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview, the credentials are
    /// empty, or they cannot be encoded.
    pub fn fill_autofill_credentials(
        &self,
        tab_id: TabId,
        username: &str,
        password: &str,
    ) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("autofill tab {tab_id:?} is not active")))?;
        if username.trim().is_empty() || password.is_empty() {
            return Err(ServoError::Native(
                "autofill requires a non-empty username and password".into(),
            ));
        }
        let username = serde_json::to_string(username)
            .map_err(|error| ServoError::Native(format!("autofill username encoding: {error}")))?;
        let password = serde_json::to_string(password)
            .map_err(|error| ServoError::Native(format!("autofill password encoding: {error}")))?;
        webview.evaluate_javascript_in_world(
            format!(
                r"(() => {{
                    const username = {username};
                    const password = {password};
                    const fields = Array.from(document.querySelectorAll('input, textarea, select'));
                    const metadata = (field) => ({{
                        name: field.name || '',
                        id: field.id || '',
                        label: field.labels?.[0]?.innerText || field.getAttribute('aria-label') || '',
                        input_type: field.type || field.tagName.toLowerCase(),
                        autocomplete: field.autocomplete || '',
                    }});
                    const classified = fields.map((field) => [field, metadata(field)]);
                    const usernameField = classified.find(([, field]) =>
                        ['username', 'email'].includes(field.autocomplete.toLowerCase().split(/\s+/).find((token) => token === 'username' || token === 'email'))
                        || /user|login|email/i.test(`${{field.name}} ${{field.id}} ${{field.label}}`));
                    const passwordField = classified.find(([, field]) =>
                        field.input_type.toLowerCase() === 'password' && field.autocomplete.toLowerCase() !== 'new-password');
                    const setValue = (entry, value) => {{
                        if (!entry) return false;
                        const field = entry[0];
                        const prototype = Object.getPrototypeOf(field);
                        const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
                        if (setter) setter.call(field, value); else field.value = value;
                        field.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        field.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return true;
                    }};
                    return setValue(usernameField, username) && setValue(passwordField, password);
                }})()",
            ),
            UserScriptWorld::Isolated("__nomad_browser_autofill".into()),
            |_| {},
        );
        Ok(())
    }

    /// Requests a privacy-safe structured page inspection for `DevTools`. It
    /// includes metadata and keys only for Web Storage; values, cookies, and
    /// other credentials never cross the renderer boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn request_page_inspection(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("DevTools tab {tab_id:?} is not active")))?;
        let snapshots = self.page_inspection_snapshots.clone();
        let waker = self.download_waker.clone();
        webview.evaluate_javascript(
            r#"JSON.stringify((() => {
                const storageEntries = (storage) => {
                    try {
                        return Object.keys(storage).slice(0, 200).map((key) => [key, storage.getItem(key)]);
                    } catch (_) { return []; }
                };
                const cookieEntries = () => {
                    try {
                        return document.cookie.split(';').map((part) => part.trim()).filter(Boolean).map((part) => {
                            const separator = part.indexOf('=');
                            return separator < 0
                                ? [part, '']
                                : [part.slice(0, separator), part.slice(separator + 1)];
                        }).slice(0, 200);
                    } catch (_) { return []; }
                };
                const navigation = performance.getEntriesByType("navigation")[0];
                return {
                    url: location.href,
                    title: document.title,
                    ready_state: document.readyState,
                    visible_text: (document.body?.innerText || "").slice(0, 100000),
                    metadata: Array.from(document.querySelectorAll("meta"))
                        .slice(0, 100)
                        .map((meta) => [meta.name || meta.httpEquiv || meta.property || "", meta.content || ""]),
                    stylesheets: Array.from(document.styleSheets)
                        .slice(0, 200)
                        .map((sheet) => sheet.href || "inline"),
                    sources: Array.from(document.scripts)
                        .slice(0, 128)
                        .map((script) => ({
                            url: script.src || location.href,
                            content: script.src
                                ? null
                                : (script.textContent || '').slice(0, 100000),
                        })),
                    local_storage_keys: storageEntries(window.localStorage).map(([key]) => key),
                    session_storage_keys: storageEntries(window.sessionStorage).map(([key]) => key),
                    local_storage: storageEntries(window.localStorage),
                    session_storage: storageEntries(window.sessionStorage),
                    cookies: cookieEntries(),
                    navigation_duration_ms: navigation && Number.isFinite(navigation.duration)
                        ? Math.round(navigation.duration)
                        : null,
                };
            })())"#,
            move |result| {
                let Ok(servo::JSValue::String(json)) = result else {
                    return;
                };
                let Ok(snapshot) = serde_json::from_str::<DevToolsPageSnapshot>(&json) else {
                    return;
                };
                if let Ok(mut pending) = snapshots.lock() {
                    push_bounded_event(&mut pending, (tab_id, snapshot));
                }
                waker.wake();
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn take_page_inspections(&self) -> Vec<(TabId, DevToolsPageSnapshot)> {
        self.page_inspection_snapshots
            .lock()
            .map(|mut snapshots| snapshots.drain(..).collect())
            .unwrap_or_default()
    }

    /// Requests a PNG screenshot of a tab's visible viewport.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn request_tab_screenshot(&self, tab_id: TabId) -> Result<(), ServoError> {
        let webview = self.webviews.get(&tab_id).ok_or_else(|| {
            ServoError::Native(format!("screenshot tab {tab_id:?} is not active"))
        })?;
        let screenshots = self.tab_screenshots.clone();
        let waker = self.download_waker.clone();
        webview.take_screenshot(None, move |result| {
            let result = result
                .map(|image| {
                    let mut encoded = Cursor::new(Vec::new());
                    DynamicImage::ImageRgba8(image)
                        .write_to(&mut encoded, ImageFormat::Png)
                        .map(|()| encoded.into_inner())
                        .map_err(|_| RenderError::BackendUnavailable)
                })
                .unwrap_or(Err(RenderError::BackendUnavailable));
            if let Ok(mut pending) = screenshots.lock() {
                push_bounded_event(&mut pending, (tab_id, result));
            }
            waker.wake();
        });
        Ok(())
    }

    #[must_use]
    pub fn take_tab_screenshots(&self) -> Vec<(TabId, Result<Vec<u8>, RenderError>)> {
        self.tab_screenshots
            .lock()
            .map(|mut screenshots| screenshots.drain(..).collect())
            .unwrap_or_default()
    }

    fn process_pdf_loads(&mut self) {
        while let Ok(pending) = self.pdf_load_receiver.try_recv() {
            let id = self.next_pdf_id;
            self.next_pdf_id = self.next_pdf_id.saturating_add(1);
            let webview_id = pending.webview_id;
            let url = pending.request.request.url.clone();
            self.pdf_loads.insert(id, pending);

            let event_sender = self.pdf_event_sender.clone();
            let waker = self.download_waker.clone();
            let handle = self.servo.start_download(
                webview_id,
                url,
                Box::new(move |event| {
                    let event = match event {
                        ServoDownloadEvent::Response { total_bytes } => {
                            PdfLoadEvent::Response { total_bytes }
                        }
                        ServoDownloadEvent::BodyChunk(bytes) => PdfLoadEvent::BodyChunk(bytes),
                        ServoDownloadEvent::Finished(result) => PdfLoadEvent::Finished(result),
                    };
                    if event_sender.send(PendingPdfEvent { id, event }).is_ok() {
                        waker.wake();
                    }
                }),
            );
            self.pdf_handles.insert(id, handle);
        }
    }

    fn process_pdf_events(&mut self) {
        while let Ok(PendingPdfEvent { id, event }) = self.pdf_event_receiver.try_recv() {
            match event {
                PdfLoadEvent::Response { total_bytes } => {
                    let too_large =
                        total_bytes.is_some_and(|size| size > crate::pdf::MAX_PDF_BYTES as u64);
                    if too_large {
                        if let Some(pending) = self.pdf_loads.get_mut(&id) {
                            pending.failure = Some(format!(
                                "the PDF is too large (more than {} bytes)",
                                crate::pdf::MAX_PDF_BYTES
                            ));
                        }
                        if let Some(handle) = self.pdf_handles.get(&id).copied() {
                            self.servo.cancel_download(handle);
                        }
                    }
                }
                PdfLoadEvent::BodyChunk(bytes) => {
                    let mut cancel = false;
                    if let Some(pending) = self.pdf_loads.get_mut(&id) {
                        if pending.failure.is_some() {
                            continue;
                        }
                        if pending.bytes.len().saturating_add(bytes.len())
                            > crate::pdf::MAX_PDF_BYTES
                        {
                            pending.failure = Some(format!(
                                "the PDF is too large (more than {} bytes)",
                                crate::pdf::MAX_PDF_BYTES
                            ));
                            cancel = true;
                        } else {
                            pending.bytes.extend(bytes);
                        }
                    }
                    if cancel {
                        if let Some(handle) = self.pdf_handles.get(&id).copied() {
                            self.servo.cancel_download(handle);
                        }
                    }
                }
                PdfLoadEvent::Finished(result) => {
                    self.pdf_handles.remove(&id);
                    let Some(pending) = self.pdf_loads.remove(&id) else {
                        continue;
                    };
                    let source_url = pending.request.request.url.clone();
                    let failure = pending
                        .failure
                        .or_else(|| {
                            result
                                .err()
                                .map(|error| format!("PDF download failed: {error}"))
                        })
                        .or_else(|| {
                            crate::pdf::validate_pdf_bytes(&pending.bytes)
                                .err()
                                .map(|error| error.to_string())
                        });
                    let html = match failure {
                        Some(error) => crate::pdf::viewer_error_html(&source_url, &error),
                        None => crate::pdf::viewer_html(&source_url, &pending.bytes),
                    };
                    let mut intercepted = pending.request;
                    intercepted.send_body_data(html.into_bytes());
                    intercepted.finish();
                }
            }
        }
    }

    pub fn spin_event_loop(&mut self) {
        self.process_pdf_loads();
        self.process_webdriver_commands();
        self.servo.spin_event_loop();
        self.flush_ready_tab_loads();
        self.process_webdriver_commands();
        self.process_pdf_loads();
        self.process_pdf_events();
    }

    fn flush_ready_tab_loads(&mut self) {
        let ready = self
            .pending_tab_loads
            .keys()
            .copied()
            .filter(|tab_id| {
                self.webviews
                    .get(tab_id)
                    .is_some_and(|webview| webview.url().is_some())
            })
            .collect::<Vec<_>>();
        for tab_id in ready {
            if let (Some(url), Some(webview)) = (
                self.pending_tab_loads.remove(&tab_id),
                self.webviews.get(&tab_id),
            ) {
                webview.load(url);
            }
        }
    }

    fn process_webdriver_commands(&mut self) {
        if self.webdriver_receiver.is_none() {
            return;
        }
        while let Some(command) = self
            .webdriver_receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok())
        {
            match command {
                WebDriverCommandMsg::GetWindowRect(_, _)
                | WebDriverCommandMsg::GetViewportSize(_, _)
                | WebDriverCommandMsg::GetFocusedWebView(_)
                | WebDriverCommandMsg::GetAllWebViews(_)
                | WebDriverCommandMsg::IsWebViewOpen(_, _)
                | WebDriverCommandMsg::FocusWebView(_)
                | WebDriverCommandMsg::SetWindowRect(_, _, _)
                | WebDriverCommandMsg::MaximizeWebView(_, _) => {
                    self.handle_webdriver_window_commands(command);
                }
                WebDriverCommandMsg::LoadUrl(_, _, _)
                | WebDriverCommandMsg::Refresh(_, _)
                | WebDriverCommandMsg::GoBack(_, _)
                | WebDriverCommandMsg::GoForward(_, _) => {
                    self.handle_webdriver_navigation_commands(command);
                }
                WebDriverCommandMsg::ScriptCommand(_, _)
                | WebDriverCommandMsg::InputEvent(_, _, _)
                | WebDriverCommandMsg::TakeScreenshot(_, _, _)
                | WebDriverCommandMsg::CurrentUserPrompt(_, _)
                | WebDriverCommandMsg::HandleUserPrompt(_, _, _)
                | WebDriverCommandMsg::GetAlertText(_, _)
                | WebDriverCommandMsg::SendAlertText(_, _)
                | WebDriverCommandMsg::NewWindow(_, _, _)
                | WebDriverCommandMsg::CloseWebView(_, _)
                | WebDriverCommandMsg::ResetAllCookies(_)
                | WebDriverCommandMsg::Shutdown => {
                    self.handle_webdriver_session_commands(command);
                }
                command => self.servo.execute_webdriver_command(command),
            }
        }
    }

    // Physical window geometry is bounded by on-screen sizes; the f32/u32
    // conversions feed Servo's and winit's fixed-width APIs.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn handle_webdriver_window_commands(&mut self, command: WebDriverCommandMsg) {
        match command {
            WebDriverCommandMsg::GetWindowRect(_webview_id, sender) => {
                sender.send_or_warn(self.webdriver_window_rect());
            }
            WebDriverCommandMsg::GetViewportSize(_webview_id, sender) => {
                let size = self.content_size.get();
                sender.send_or_warn(Size2D::new(size.width as f32, size.height as f32));
            }
            WebDriverCommandMsg::GetFocusedWebView(sender) => {
                let focused = self
                    .active_tab
                    .and_then(|tab_id| self.webviews.get(&tab_id))
                    .map(WebView::id);
                sender.send_or_warn(focused);
            }
            WebDriverCommandMsg::GetAllWebViews(sender) => {
                sender.send_or_warn(self.webviews.values().map(WebView::id).collect());
            }
            WebDriverCommandMsg::IsWebViewOpen(webview_id, sender) => {
                sender.send_or_warn(
                    self.webviews
                        .values()
                        .any(|webview| webview.id() == webview_id),
                );
            }
            WebDriverCommandMsg::FocusWebView(webview_id) => {
                if let Some(tab_id) = self
                    .webviews
                    .iter()
                    .find_map(|(tab_id, webview)| (webview.id() == webview_id).then_some(*tab_id))
                {
                    self.show_tab(tab_id);
                    if let Some(webview) = self.webviews.get(&tab_id) {
                        webview.focus();
                    }
                }
            }
            WebDriverCommandMsg::SetWindowRect(_webview_id, requested_rect, sender) => {
                let size = requested_rect.size();
                let _ = self.delegate.window.request_inner_size(LogicalSize::new(
                    size.width.max(1) as u32,
                    size.height.max(1) as u32,
                ));
                sender.send_or_warn(requested_rect);
            }
            WebDriverCommandMsg::MaximizeWebView(_webview_id, sender) => {
                sender.send_or_warn(self.webdriver_window_rect());
            }
            command => self.servo.execute_webdriver_command(command),
        }
    }

    fn handle_webdriver_navigation_commands(&mut self, command: WebDriverCommandMsg) {
        match command {
            WebDriverCommandMsg::LoadUrl(webview_id, url, sender) => {
                self.set_webdriver_load_status_sender(webview_id, sender);
                if let Some(webview) = self.webview_by_id(webview_id) {
                    webview.load(url);
                }
            }
            WebDriverCommandMsg::Refresh(webview_id, sender) => {
                self.set_webdriver_load_status_sender(webview_id, sender);
                if let Some(webview) = self.webview_by_id(webview_id) {
                    webview.reload();
                }
            }
            WebDriverCommandMsg::GoBack(webview_id, sender) => {
                self.set_webdriver_load_status_sender(webview_id, sender);
                if let Some(webview) = self.webview_by_id(webview_id) {
                    webview.go_back(1);
                }
            }
            WebDriverCommandMsg::GoForward(webview_id, sender) => {
                self.set_webdriver_load_status_sender(webview_id, sender);
                if let Some(webview) = self.webview_by_id(webview_id) {
                    webview.go_forward(1);
                }
            }
            command => self.servo.execute_webdriver_command(command),
        }
    }

    fn handle_webdriver_session_commands(&mut self, command: WebDriverCommandMsg) {
        match command {
            WebDriverCommandMsg::ScriptCommand(browsing_context_id, command) => {
                self.capture_webdriver_script_command(&command);
                self.servo
                    .execute_webdriver_command(WebDriverCommandMsg::ScriptCommand(
                        browsing_context_id,
                        command,
                    ));
            }
            WebDriverCommandMsg::InputEvent(webview_id, input_event, response_sender) => {
                if let Some(webview) = self.webview_by_id(webview_id) {
                    webview.notify_input_event(input_event);
                }
                if let Some(response_sender) = response_sender {
                    let _ = response_sender.send(());
                }
            }
            WebDriverCommandMsg::TakeScreenshot(webview_id, rect, sender) => {
                let Some(webview) = self.webview_by_id(webview_id) else {
                    return;
                };
                webview.take_screenshot(rect.map(|rect| rect.to_box2d().into()), move |result| {
                    let _ = sender.send(result);
                });
            }
            WebDriverCommandMsg::CurrentUserPrompt(_webview_id, sender) => {
                sender.send_or_warn(None);
            }
            WebDriverCommandMsg::HandleUserPrompt(_webview_id, _action, sender) => {
                sender.send_or_warn(Err(()));
            }
            WebDriverCommandMsg::GetAlertText(_webview_id, sender) => {
                sender.send_or_warn(Err(()));
            }
            WebDriverCommandMsg::SendAlertText(_webview_id, _text) => {}
            WebDriverCommandMsg::NewWindow(_type_hint, sender, load_status_sender) => {
                let next_tab = self
                    .webviews
                    .keys()
                    .map(|tab_id| tab_id.get())
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                let tab_id = TabId::new(next_tab);
                self.ensure_webview(tab_id);
                self.webdriver_tab_ids.insert(tab_id);
                if let Some(webview) = self.webviews.get(&tab_id) {
                    webview.hide();
                    if let Some(load_status_sender) = load_status_sender {
                        self.set_webdriver_load_status_sender(webview.id(), load_status_sender);
                    }
                    sender.send_or_warn(webview.id());
                }
            }
            WebDriverCommandMsg::CloseWebView(webview_id, sender) => {
                if let Some(tab_id) = self
                    .webviews
                    .iter()
                    .find_map(|(tab_id, webview)| (webview.id() == webview_id).then_some(*tab_id))
                {
                    self.webdriver_tab_ids.remove(&tab_id);
                    let _ = self.release(tab_id);
                }
                sender.send_or_warn(());
            }
            WebDriverCommandMsg::ResetAllCookies(sender) => {
                self.servo.site_data_manager().clear_cookies(None);
                let _ = sender.send(());
            }
            WebDriverCommandMsg::Shutdown => {
                // The native shell owns process shutdown. Consume this command here so it
                // cannot reach the constellation's unreachable embedder-only branch.
                self.webdriver_shutdown_requested = true;
            }
            command => self.servo.execute_webdriver_command(command),
        }
    }

    fn webview_by_id(&self, webview_id: servo::WebViewId) -> Option<&WebView> {
        self.webviews
            .values()
            .find(|webview| webview.id() == webview_id)
    }

    // Rounded logical window sizes are bounded by physical screen bounds and
    // always fit an i32 rect.
    #[allow(clippy::cast_possible_truncation)]
    fn webdriver_window_rect(&self) -> servo::DeviceIndependentIntRect {
        let size = self
            .content_size
            .get()
            .to_logical::<f64>(self.delegate.window.scale_factor());
        servo::DeviceIndependentIntRect::new(
            Point2D::new(0, 0),
            Point2D::new(size.width.round() as i32, size.height.round() as i32),
        )
    }

    fn set_webdriver_load_status_sender(
        &self,
        webview_id: servo::WebViewId,
        sender: servo::GenericSender<WebDriverLoadStatus>,
    ) {
        if let Ok(mut senders) = self.webdriver_load_status_senders.lock() {
            senders.insert(webview_id, sender);
        }
    }

    fn capture_webdriver_script_command(&self, command: &WebDriverScriptCommand) {
        match command {
            WebDriverScriptCommand::AddLoadStatusSender(webview_id, sender) => {
                self.set_webdriver_load_status_sender(*webview_id, sender.clone());
            }
            WebDriverScriptCommand::RemoveLoadStatusSender(webview_id) => {
                if let Ok(mut senders) = self.webdriver_load_status_senders.lock() {
                    senders.remove(webview_id);
                }
            }
            _ => {}
        }
    }

    /// Drains page-triggered download requests and associates them with Nomad tabs.
    #[must_use]
    pub fn take_download_requests(&self) -> Vec<DownloadRequest> {
        self.download_receiver
            .try_iter()
            .map(|pending| {
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == pending.webview_id).then_some(*tab_id)
                });
                DownloadRequest {
                    tab_id,
                    url: pending.request.url,
                    suggested_filename: pending.request.suggested_filename,
                    total_bytes: None,
                }
            })
            .collect()
    }

    /// Starts a queued download through Servo's shared network stack.
    ///
    /// # Errors
    ///
    /// Returns an error when the download has no owning tab or the tab has no
    /// live webview.
    pub fn start_download(
        &mut self,
        id: DownloadId,
        request: &DownloadRequest,
    ) -> Result<(), ServoError> {
        let tab_id = request
            .tab_id
            .ok_or_else(|| ServoError::Native("download has no owning tab".to_owned()))?;
        let webview_id =
            self.webviews.get(&tab_id).map(WebView::id).ok_or_else(|| {
                ServoError::Native(format!("download tab {tab_id:?} is not active"))
            })?;
        let sender = self.download_event_sender.clone();
        let waker = self.download_waker.clone();
        let handle = self.servo.start_download(
            webview_id,
            request.url.clone(),
            Box::new(move |event| {
                let event = match event {
                    ServoDownloadEvent::Response { total_bytes } => {
                        DownloadTransportEvent::Response { total_bytes }
                    }
                    ServoDownloadEvent::BodyChunk(bytes) => {
                        DownloadTransportEvent::BodyChunk(bytes)
                    }
                    ServoDownloadEvent::Finished(result) => {
                        DownloadTransportEvent::Finished(result)
                    }
                };
                if sender.send(PendingDownloadEvent { id, event }).is_ok() {
                    waker.wake();
                }
            }),
        );
        self.download_handles.insert(id, handle);
        Ok(())
    }

    /// Cancels an active download through Servo's shared network stack.
    ///
    /// # Errors
    ///
    /// Currently never fails; the `Result` keeps the download API's fallible
    /// contract stable.
    pub fn cancel_download(&mut self, id: DownloadId) -> Result<(), ServoError> {
        if let Some(handle) = self.download_handles.remove(&id) {
            self.servo.cancel_download(handle);
        }
        Ok(())
    }

    /// Drains permission requests raised by page content.
    pub fn take_permission_requests(&mut self) -> Vec<PermissionPrompt> {
        let requests: Vec<_> = self.permission_requests.borrow_mut().drain(..).collect();
        requests
            .into_iter()
            .map(|pending| {
                let id = PermissionPromptId::new(self.next_permission_id);
                self.next_permission_id = self.next_permission_id.saturating_add(1);
                let tab_id = self.webviews.iter().find_map(|(tab_id, webview)| {
                    (webview.id() == pending.webview_id).then_some(*tab_id)
                });
                let kind = permission_kind(pending.feature);
                self.pending_permissions.insert(id, pending.request);
                PermissionPrompt {
                    id,
                    tab_id,
                    site: pending.site,
                    kind,
                }
            })
            .collect()
    }

    /// Sends an allow or deny response to a pending Servo permission request.
    ///
    /// # Errors
    ///
    /// Returns an error when the permission request no longer exists.
    pub fn respond_permission(
        &mut self,
        id: PermissionPromptId,
        allow: bool,
    ) -> Result<(), ServoError> {
        let request = self.pending_permissions.remove(&id).ok_or_else(|| {
            ServoError::Native(format!("permission request {} no longer exists", id.get()))
        })?;
        if allow {
            request.allow();
        } else {
            request.deny();
        }
        Ok(())
    }

    /// Drains response events emitted by Servo's download transport.
    pub fn take_download_events(&mut self) -> Vec<(DownloadId, DownloadTransportEvent)> {
        let events: Vec<_> = self.download_event_receiver.try_iter().collect();
        events
            .into_iter()
            .map(|event| {
                if matches!(&event.event, DownloadTransportEvent::Finished(_)) {
                    self.download_handles.remove(&event.id);
                }
                (event.id, event.event)
            })
            .collect()
    }

    pub fn resize_content(&self, size: PhysicalSize<u32>) {
        self.content_size.set(size);
        if let Some(active_tab) = self.active_tab {
            if let Some(webview) = self.webviews.get(&active_tab) {
                let current = webview.size().to_u32();
                if current.width != size.width || current.height != size.height {
                    webview.resize(size);
                }
            }
        }
    }

    pub fn resize_content_for(&self, tab_id: TabId, size: PhysicalSize<u32>) {
        if let Some(webview) = self.webviews.get(&tab_id) {
            let current = webview.size().to_u32();
            if current.width != size.width || current.height != size.height {
                // WebView::resize updates both the offscreen framebuffer and
                // Servo's document viewport. Resizing the rendering context
                // directly first makes Servo treat this as a no-op, leaving
                // layout at the previous window size.
                webview.resize(size);
            }
        }
    }

    /// Updates the device-pixel ratio for every live Servo surface.
    ///
    /// Winit emits `ScaleFactorChanged` when a native window moves between
    /// displays with different backing scales. Existing `WebView` instances
    /// retain the scale supplied by their builder until it is explicitly
    /// replaced; only updating the outer window would therefore leave CSS
    /// pixels and the
    /// offscreen compositor disagreeing about the viewport dimensions.
    pub fn set_hidpi_scale_factor(&self, scale_factor: f32) {
        let scale_factor = Scale::new(scale_factor);
        for webview in self.webviews.values() {
            webview.set_hidpi_scale_factor(scale_factor);
        }
        for webview in self.background_webviews.values() {
            webview.set_hidpi_scale_factor(scale_factor);
        }
        if let Some(popup) = &self.extension_popup {
            popup.webview.set_hidpi_scale_factor(scale_factor);
        }
        for auxiliary in self.delegate.auxiliary_entries() {
            auxiliary.webview.set_hidpi_scale_factor(scale_factor);
        }
    }

    pub fn set_dark_theme(&mut self, dark: bool) {
        self.theme = if dark { Theme::Dark } else { Theme::Light };
        for webview in self.webviews.values() {
            webview.notify_theme_change(self.theme);
        }
        for webview in self.background_webviews.values() {
            webview.notify_theme_change(self.theme);
        }
        if let Some(popup) = &self.extension_popup {
            popup.webview.notify_theme_change(self.theme);
        }
    }

    pub fn set_accessibility_active(&mut self, active: bool) {
        if self.accessibility_active == active {
            return;
        }
        self.accessibility_active = active;
        for (tab_id, webview) in &self.webviews {
            webview.set_accessibility_active(active && Some(*tab_id) == self.active_tab);
        }
    }

    pub fn render_to_parent_callback(&self) -> Option<RenderToParentCallback> {
        self.current_page_rendering_context()
            .render_to_parent_callback()
    }

    pub fn render_to_parent_callback_for(&self, tab_id: TabId) -> Option<RenderToParentCallback> {
        self.page_rendering_contexts
            .get(&tab_id)
            .and_then(|context| context.render_to_parent_callback())
    }

    pub fn set_visible_tabs(&mut self, tab_ids: &[TabId]) {
        // Hit testing must follow the same visibility set as painting. Keeping
        // rectangles for hidden tabs lets HashMap iteration route clicks and
        // wheel events to an invisible page occupying the same screen area.
        self.content_rects
            .borrow_mut()
            .retain(|tab_id, _| tab_ids.contains(tab_id));
        for (candidate_id, webview) in &self.webviews {
            if tab_ids.contains(candidate_id) {
                webview.show();
            } else {
                webview.hide();
            }
        }
    }

    /// Applies Servo's low-activity timer and animation throttling to a tab.
    ///
    /// # Errors
    ///
    /// Returns an error when the tab has no live webview.
    pub fn set_tab_throttled(&mut self, tab_id: TabId, throttled: bool) -> Result<(), ServoError> {
        let webview = self
            .webviews
            .get(&tab_id)
            .ok_or_else(|| ServoError::Native(format!("throttle tab {tab_id:?} is not active")))?;
        webview.set_throttled(throttled);
        Ok(())
    }

    pub fn glow_context(&self) -> Arc<glow::Context> {
        self.window_rendering_context.glow_gl_api()
    }

    /// Makes the active tab's page rendering context current on this thread.
    ///
    /// # Errors
    ///
    /// Returns an error string when the OpenGL context cannot be made
    /// current.
    pub fn make_window_current(&self) -> Result<(), String> {
        self.current_page_rendering_context()
            .make_current()
            .map_err(|error| format!("{error:?}"))
    }

    /// Prepares the window for rendering the next frame.
    ///
    /// # Errors
    ///
    /// Returns an error string when the OpenGL context cannot be made
    /// current.
    pub fn prepare_window_frame(&self) -> Result<(), String> {
        self.make_window_current()?;
        self.window_rendering_context.prepare_for_rendering();
        Ok(())
    }

    pub fn present(&self) {
        self.window_rendering_context.present();
    }

    // Window scale factors are modest DPI multipliers; narrowing winit's
    // f64 scale to Servo's f32 scale is the intended conversion.
    #[allow(clippy::cast_possible_truncation)]
    fn ensure_webview_with_url(&mut self, tab_id: TabId, initial_url: Url) {
        if self.webviews.contains_key(&tab_id) {
            return;
        }

        let page_rendering_context = Rc::new(
            self.window_rendering_context
                .offscreen_context(self.content_size.get()),
        );
        let privacy_policy = *self.privacy_policy.borrow();
        let ephemeral = self
            .tab_containers
            .get(&tab_id)
            .is_some_and(|(_, ephemeral)| *ephemeral);
        let content_manager = Rc::new(UserContentManager::new(&self.servo));
        content_manager.add_script(self.privacy_script.clone());
        self.tab_content_managers
            .insert(tab_id, content_manager.clone());
        let webview = WebViewBuilder::new(&self.servo, page_rendering_context.clone())
            .url(initial_url)
            .hidpi_scale_factor(Scale::new(self.delegate.window.scale_factor() as f32))
            .delegate(self.delegate.clone())
            .private_browsing(privacy_policy.mode() == PrivacyMode::Private || ephemeral)
            .user_content_manager(content_manager)
            .build();
        webview.notify_theme_change(self.theme);
        webview.set_accessibility_active(self.accessibility_active);
        self.webviews.insert(tab_id, webview);
        self.page_rendering_contexts
            .insert(tab_id, page_rendering_context);
    }

    fn ensure_webview(&mut self, tab_id: TabId) {
        self.ensure_webview_with_url(
            tab_id,
            Url::parse("about:blank").expect("about:blank is a valid URL"),
        );
    }

    fn show_tab(&mut self, tab_id: TabId) {
        self.ensure_webview(tab_id);
        for (candidate_id, webview) in &self.webviews {
            let active = *candidate_id == tab_id;
            webview.set_accessibility_active(self.accessibility_active && active);
            if active {
                webview.show();
            } else {
                webview.hide();
            }
        }
        self.active_tab = Some(tab_id);
    }

    /// Binds a tab to a workspace container before its first navigation.
    /// Ephemeral containers use Servo's private storage/resource group, so
    /// cookies, local storage, cache, and permissions disappear with the
    /// tab. Persistent container IDs remain explicit in Nomad state and are
    /// ready for the fork's durable partition backend.
    ///
    /// # Errors
    ///
    /// Currently never fails; the `Result` keeps the call site's fallible
    /// contract stable across backends.
    pub fn configure_tab(
        &mut self,
        tab_id: TabId,
        container_id: ContainerId,
        ephemeral: bool,
    ) -> Result<(), ServoError> {
        if self
            .tab_containers
            .get(&tab_id)
            .is_some_and(|current| *current == (container_id, ephemeral))
        {
            return Ok(());
        }
        if let Some(webview) = self.webviews.remove(&tab_id) {
            webview.hide();
            self.page_rendering_contexts.remove(&tab_id);
        }
        self.tab_content_managers.remove(&tab_id);
        self.extension_scripts.remove(&tab_id);
        self.tab_containers
            .insert(tab_id, (container_id, ephemeral));
        Ok(())
    }

    fn current_page_rendering_context(&self) -> Rc<OffscreenRenderingContext> {
        self.active_tab
            .and_then(|tab_id| self.page_rendering_contexts.get(&tab_id).cloned())
            .unwrap_or_else(|| self.fallback_page_rendering_context.clone())
    }
}

/// Maps a native key event to Servo's keyboard input representation.
fn stabilize_wheel_axes(x: f64, y: f64) -> (f64, f64) {
    const CROSS_AXIS_RATIO: f64 = 0.2;
    const PIXEL_NOISE_FLOOR: f64 = 1.0;
    if x.abs() <= PIXEL_NOISE_FLOOR || x.abs() < y.abs() * CROSS_AXIS_RATIO {
        (0.0, y)
    } else if y.abs() <= PIXEL_NOISE_FLOOR || y.abs() < x.abs() * CROSS_AXIS_RATIO {
        (x, 0.0)
    } else {
        (x, y)
    }
}

fn servo_keyboard_event(
    event: &winit::event::KeyEvent,
    native_modifiers: ModifiersState,
) -> KeyboardEvent {
    let key = match &event.logical_key {
        WinitKey::Character(value) => Key::Character(value.to_string()),
        WinitKey::Named(WinitNamedKey::Space) => Key::Character(" ".to_owned()),
        WinitKey::Named(named) => Key::Named(match named {
            WinitNamedKey::Backspace => NamedKey::Backspace,
            WinitNamedKey::Delete => NamedKey::Delete,
            WinitNamedKey::Enter => NamedKey::Enter,
            WinitNamedKey::Tab => NamedKey::Tab,
            WinitNamedKey::Escape => NamedKey::Escape,
            WinitNamedKey::ArrowLeft => NamedKey::ArrowLeft,
            WinitNamedKey::ArrowRight => NamedKey::ArrowRight,
            WinitNamedKey::ArrowUp => NamedKey::ArrowUp,
            WinitNamedKey::ArrowDown => NamedKey::ArrowDown,
            WinitNamedKey::Home => NamedKey::Home,
            WinitNamedKey::End => NamedKey::End,
            WinitNamedKey::PageUp => NamedKey::PageUp,
            WinitNamedKey::PageDown => NamedKey::PageDown,
            _ => NamedKey::Unidentified,
        }),
        _ => Key::Named(NamedKey::Unidentified),
    };
    let state = match event.state {
        ElementState::Pressed => KeyState::Down,
        ElementState::Released => KeyState::Up,
    };
    let mut modifiers = Modifiers::empty();
    if native_modifiers.shift_key() {
        modifiers |= Modifiers::SHIFT;
    }
    if native_modifiers.control_key() {
        modifiers |= Modifiers::CONTROL;
    }
    if native_modifiers.alt_key() {
        modifiers |= Modifiers::ALT;
    }
    if native_modifiers.super_key() {
        modifiers |= Modifiers::META;
    }
    KeyboardEvent::new_without_event(
        state,
        key,
        Code::Unidentified,
        Location::Standard,
        modifiers,
        event.repeat,
        false,
    )
}

fn permission_kind(feature: PermissionFeature) -> PermissionKind {
    match feature {
        PermissionFeature::Geolocation => PermissionKind::Geolocation,
        PermissionFeature::Notifications => PermissionKind::Notifications,
        PermissionFeature::Push => PermissionKind::Push,
        PermissionFeature::Midi => PermissionKind::Midi,
        PermissionFeature::Camera => PermissionKind::Camera,
        PermissionFeature::Microphone => PermissionKind::Microphone,
        PermissionFeature::Speaker => PermissionKind::Speaker,
        PermissionFeature::DeviceInfo => PermissionKind::DeviceInfo,
        PermissionFeature::BackgroundSync => PermissionKind::BackgroundSync,
        PermissionFeature::Bluetooth => PermissionKind::Bluetooth,
        PermissionFeature::PersistentStorage => PermissionKind::PersistentStorage,
        PermissionFeature::ScreenWakeLock(_) => PermissionKind::ScreenWakeLock,
        PermissionFeature::Gamepad => PermissionKind::Gamepad,
    }
}

fn wildcard_pattern_regex(pattern: &str) -> String {
    if pattern == "<all_urls>" {
        return "^(https?|file):\\/\\/".to_owned();
    }
    let mut regex = String::from("^");
    for character in pattern.chars() {
        match character {
            '*' => regex.push_str(".*"),
            '.' | '+' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                regex.push('\\');
                regex.push(character);
            }
            _ => regex.push(character),
        }
    }
    regex.push('$');
    regex
}

fn extension_block_pattern_matches(pattern: &str, url: &Url) -> bool {
    if pattern == "<all_urls>" {
        return matches!(url.scheme(), "http" | "https" | "file" | "ftp");
    }
    let Some((scheme, rest)) = pattern.split_once("://") else {
        return false;
    };
    if scheme != "*" && scheme != url.scheme() {
        return false;
    }
    if scheme == "*" && !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let Some((host_pattern, path_pattern)) = rest.split_once('/') else {
        return false;
    };
    wildcard_text_matches(host_pattern, url.host_str().unwrap_or_default())
        && wildcard_text_matches(path_pattern, url.path())
}

fn wildcard_text_matches(pattern: &str, value: &str) -> bool {
    let mut remaining = value;
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return true;
    };
    if !remaining.starts_with(first) {
        return false;
    }
    remaining = &remaining[first.len()..];
    let fragments = parts.collect::<Vec<_>>();
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

/// Content-script runtime template. Placeholders are replaced with
/// per-extension values by `ServoRenderer::extension_script_source`.
const EXTENSION_CONTENT_SCRIPT_TEMPLATE: &str = r#"
(() => {
    const extensionId = __NOMAD_EXTENSION_ID__;
    const extensionBase = "nomad-extension://" + extensionId + "/";
    const extensionManifest = __NOMAD_MANIFEST__;
    const bridgeDocument = document;
    const bridgeDispatchElement = __NOMAD_MAIN_WORLD__ ? null : (() => {
        let element = bridgeDocument && bridgeDocument.getElementById(__NOMAD_ISOLATED_DISPATCH_ELEMENT_ID__);
        if (!element && bridgeDocument) {
            element = bridgeDocument.createElement("div");
            element.setAttribute("id", __NOMAD_ISOLATED_DISPATCH_ELEMENT_ID__);
            element.setAttribute("hidden", "hidden");
            if (bridgeDocument.documentElement) bridgeDocument.documentElement.appendChild(element);
        }
        return element;
    })();
    const queueHost = globalThis;
    const queueKey = __NOMAD_MAIN_WORLD__ ? "__nomad_extension_messages" : Symbol.for(__NOMAD_ISOLATED_QUEUE_KEY__);
    const queue = queueHost[queueKey] || (queueHost[queueKey] = []);
    const enqueue = (payload) => {
        if (!__NOMAD_MAIN_WORLD__) {
            if (queue.length >= 4096) {
                return Promise.reject(new Error("Nomad extension message queue is full"));
            }
            queue.push({ extension_id: extensionId, payload });
            return Promise.resolve();
        }
        if (queue.length >= 4096) {
            return Promise.reject(new Error("Nomad extension message queue is full"));
        }
        queue.push({ extension_id: extensionId, payload });
        return Promise.resolve();
    };
    const reportWorldError = (detail) => {
        const message = typeof detail === "string" ? detail :
            String(detail && (detail.stack || detail.message) || detail);
        try {
            enqueue(__NOMAD_MAIN_WORLD__ ? { __nomad_main_world_error: message } : { __nomad_isolated_world_error: message });
        } catch (_) {}
    };
        globalThis.addEventListener("error", (event) => {
            const location = event && (event.filename || event.lineno) ?
                " @" + String(event.filename || "") + ":" + String(event.lineno || 0) + ":" + String(event.colno || 0) : "";
            reportWorldError(((event && event.error && (event.error.stack || event.error.message)) || (event && event.message) || "content script error") + location);
        });
        globalThis.addEventListener("unhandledrejection", (event) => {
            const reason = event && event.reason;
            reportWorldError("unhandled rejection: " + String(reason && (reason.stack || reason.message) || reason));
        });
    } catch (_) {}
    const storageState = __NOMAD_STORAGE_STATE__;
    const pending = new Map();
    let nextRequestId = 1;
    let nextPortId = 1;
    let runtimeLastError = null;
    const ports = new Map();
    const pageMessageListeners = [];
    const globalMessageListeners = [];
    const messageListenerTargets = [];
    const rememberMessageTarget = (target) => {
        if (target && !messageListenerTargets.includes(target)) {
            messageListenerTargets.push(target);
        }
    };
    // Servo installs an isolated-world Window facade before extension code
    // runs. Keep its identity available: LavaMoat may capture that exact
    // object as the post-message stream's targetWindow before this bridge
    // installs its richer relay proxy.
    const vendorWindow = __NOMAD_MAIN_WORLD__ ? null : globalThis.window;
    let extensionWindow = null;
    let extensionMessageEvent = null;
    const withCallback = (promise, callback) => {
        if (typeof callback === "function") {
            promise.then((value) => {
                runtimeLastError = null;
                callback(value);
            }, (error) => {
                runtimeLastError = { message: String(error && error.message || error) };
                try { callback(); } finally {
                    Promise.resolve().then(() => { runtimeLastError = null; });
                }
            });
        }
        return promise;
    };
    const sendMessage = (payload, callback) => {
        const requestId = String(nextRequestId++);
        const promise = new Promise((resolve, reject) => pending.set(requestId, { resolve, reject }));
        enqueue({ __nomad_runtime_request: { request_id: requestId, payload } }).catch((error) => {
            pending.delete(requestId);
            const request = { reject };
            request.reject(error);
        });
        return withCallback(promise, callback);
    };
    const connect = (connectInfo) => {
        const portId = extensionId + "-" + String(nextPortId++);
        const messageListeners = [];
        const disconnectListeners = [];
        const name = typeof connectInfo === "string" ? connectInfo :
            (connectInfo && connectInfo.name) || "";
        const port = {
            name,
            sender: { id: extensionId, tab: tabInfo },
            postMessage: (payload) => {
                return enqueue({ __nomad_runtime_port: {
                    port_id: portId,
                    name,
                    payload,
                } });
            },
            disconnect: () => {
                if (ports.delete(portId)) {
                    enqueue({ __nomad_runtime_port_disconnect: { port_id: portId } });
                }
            },
            onMessage: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") messageListeners.push(listener);
            } }),
            onDisconnect: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") disconnectListeners.push(listener);
        } }),
        };
        ports.set(portId, { port, messageListeners, disconnectListeners });
        // runtime.connect() is synchronous for extension code, but the
        // background side still needs an explicit onConnect notification
        // before it can send the first response on this port.
        enqueue({ __nomad_runtime_port_connect: {
            port_id: portId,
            name,
        } }).catch(() => {});
        return port;
    };
    const syncState = __NOMAD_SYNC_STORAGE_STATE__;
    const sessionState = __NOMAD_SESSION_STORAGE_STATE__;
    function makeContentStorageArea(state, area) {
        return Object.freeze({
        get(keys) {
            const result = {};
            if (keys == null) return Promise.resolve(Object.assign(result, state));
            const names = typeof keys === "string" ? [keys] :
                Array.isArray(keys) ? keys : Object.keys(keys);
            for (const name of names) {
                if (Object.prototype.hasOwnProperty.call(state, name)) {
                    result[name] = state[name];
                } else if (keys && !Array.isArray(keys) && typeof keys === "object") {
                    result[name] = keys[name];
                }
            }
            return Promise.resolve(result);
        },
        set(items) {
            if (!items || typeof items !== "object" || Array.isArray(items)) {
                return Promise.reject(new TypeError("storage." + area + ".set expects an object"));
            }
            Object.assign(state, items);
            return enqueue({ __nomad_storage_area: area, __nomad_storage_set: items });
        },
        remove(keys) {
            const names = typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : [];
            for (const name of names) delete state[name];
            return enqueue({ __nomad_storage_area: area, __nomad_storage_remove: names });
        },
        clear() {
            for (const name of Object.keys(state)) delete state[name];
            return enqueue({ __nomad_storage_area: area, __nomad_storage_clear: true });
        },
        });
    }
    const storageApi = storageState === null ? undefined : Object.freeze({
        local: makeContentStorageArea(storageState, "local"),
        sync: syncState === null ? undefined : makeContentStorageArea(syncState, "sync"),
        session: sessionState === null ? undefined : makeContentStorageArea(sessionState, "session"),
        managed: Object.freeze({
            get: (keys) => Promise.resolve({}),
            getBytesInUse: () => Promise.resolve(0),
            onChanged: Object.freeze({ addListener: () => {}, removeListener: () => {} }),
        }),
    });
    const tabInfo = __NOMAD_TAB_INFO__;
    const tabsApi = tabInfo === null ? undefined : Object.freeze({
        query: () => Promise.resolve([tabInfo]),
        sendMessage: (tabId, payload) => {
            if (!tabInfo || tabId !== tabInfo.id) {
                return Promise.reject(new Error("Nomad content-script tab is unavailable"));
            }
            return enqueue({ __nomad_page_message: { payload } });
        },
    });
    const listeners = [];
    const connectListeners = [];
    const makeTabsPort = (event) => {
        const messageListeners = [];
        const disconnectListeners = [];
        const port = {
            name: event.name || "",
            sender: { id: extensionId, tab: tabInfo },
            postMessage: (payload) => enqueue({ __nomad_tabs_port_message: {
                port_id: event.port_id,
                payload,
            } }),
            disconnect: () => {
                if (ports.delete(event.port_id)) {
                    enqueue({ __nomad_tabs_port_disconnect: { port_id: event.port_id } });
                }
            },
            onMessage: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") messageListeners.push(listener);
            } }),
            onDisconnect: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") disconnectListeners.push(listener);
            } }),
        };
        ports.set(event.port_id, { port, messageListeners, disconnectListeners });
        return port;
    };
    const dispatch = (payload) => {
        const pageDomMessage = payload && payload.__nomad_page_dom_message_to_content;
        if (pageDomMessage && !__NOMAD_MAIN_WORLD__) {
            const messageSources = [
                ...messageListenerTargets,
                vendorWindow,
                extensionWindow,
                globalThis,
                pageWindow,
            ]
                .filter((source, index, sources) => source && sources.indexOf(source) === index);
            const dispatchMessage = (listeners) => {
                for (const source of messageSources) {
                let event;
                try {
                    event = new extensionMessageEvent("message", {
                        data: pageDomMessage.payload,
                        origin: String(pageLocation && pageLocation.origin || ""),
                        source,
                    });
                    try {
                        Object.defineProperty(event, "source", {
                            configurable: true,
                            get: () => source,
                        });
                    } catch (_) {}
                } catch (_) {
                    event = Object.freeze({
                        data: pageDomMessage.payload,
                        origin: String(pageLocation && pageLocation.origin || ""),
                        source,
                        target: source,
                        currentTarget: source,
                        type: "message",
                    });
                }
                for (const listener of listeners) listener(event);
                }
            };
            dispatchMessage(pageMessageListeners);
            dispatchMessage(globalMessageListeners);
            return;
        }
        const pageMessage = payload && payload.__nomad_page_dom_message_to_page;
        if (pageMessage && __NOMAD_MAIN_WORLD__) {
            pageWindow.postMessage(
                pageMessage.payload,
                pageMessage.target_origin || "*",
            );
            return;
        }
        const tabsConnected = payload && payload.__nomad_tabs_port_connected;
        if (tabsConnected && typeof tabsConnected.port_id === "string") {
            const port = makeTabsPort(tabsConnected);
            for (const listener of connectListeners) listener(port);
            return;
        }
        const tabsPortMessage = payload && payload.__nomad_tabs_port_message;
        if (tabsPortMessage && typeof tabsPortMessage.port_id === "string") {
            const entry = ports.get(tabsPortMessage.port_id);
            if (entry) {
                for (const listener of entry.messageListeners) {
                    listener(tabsPortMessage.payload, entry.port);
                }
            }
            return;
        }
        const tabsPortDisconnect = payload && (
            payload.__nomad_tabs_port_disconnect || payload.__nomad_port_disconnect
        );
        if (tabsPortDisconnect && typeof tabsPortDisconnect.port_id === "string") {
            const entry = ports.get(tabsPortDisconnect.port_id);
            if (entry) {
                ports.delete(tabsPortDisconnect.port_id);
                for (const listener of entry.disconnectListeners) listener(entry.port);
            }
            return;
        }
        const tabsRequest = payload && payload.__nomad_tabs_request;
        if (tabsRequest && typeof tabsRequest.request_id === "string") {
            let responseSent = false;
            const sendResponse = (value) => {
                if (responseSent) return;
                responseSent = true;
                emit({ __nomad_page_response: {
                    tab_id: tabInfo && tabInfo.id,
                    request_id: tabsRequest.request_id,
                    result: value,
                } });
            };
            for (const listener of listeners) {
                const result = listener(
                    tabsRequest.payload,
                    { id: extensionId, tab: tabInfo },
                    sendResponse,
                );
                if (result && typeof result.then === "function") result.then(sendResponse);
                else if (result !== undefined && result !== true) sendResponse(result);
            }
            if (listeners.length === 0) sendResponse(undefined);
            return;
        }
        const runtimeMessage = payload && payload.__nomad_runtime_message;
        if (runtimeMessage && Object.prototype.hasOwnProperty.call(runtimeMessage, "payload")) {
            const sender = runtimeMessage.sender || { id: extensionId, tab: null };
            for (const listener of listeners) {
                listener(runtimeMessage.payload, sender, () => {});
            }
            return;
        }
        const response = payload && payload.__nomad_runtime_response;
        if (response && typeof response.request_id === "string") {
            const request = pending.get(response.request_id);
            if (!request) return;
            pending.delete(response.request_id);
            if (Object.prototype.hasOwnProperty.call(response, "error")) {
                request.reject(new Error(String(response.error)));
            } else {
                request.resolve(response.result);
            }
            return;
        }
        const portResponse = payload && payload.__nomad_port_response;
        if (portResponse && typeof portResponse.port_id === "string") {
            const entry = ports.get(portResponse.port_id);
            if (!entry) return;
            for (const listener of entry.messageListeners) listener(portResponse.payload, entry.port);
            return;
        }
        for (const listener of listeners) {
            listener(payload, { id: extensionId, tab: tabInfo }, () => {});
        }
    };
    const browser = Object.freeze({
        runtime: Object.freeze({
            sendMessage,
            connect,
            id: extensionId,
            get lastError() { return runtimeLastError; },
            getURL: (path) => new URL(String(path || ""), extensionBase).href,
            getManifest: () => Object.assign({}, extensionManifest, { id: extensionId }),
            onMessage: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") listeners.push(listener);
            } }),
            onConnect: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") connectListeners.push(listener);
            } }),
        }),
        storage: storageApi && Object.freeze({ local: storageApi.local, session: storageApi.session, sync: storageApi.sync, managed: storageApi.managed }),
        tabs: tabsApi,
        extension: Object.freeze({
            getURL: (path) => new URL(String(path || ""), extensionBase).href,
            getManifest: () => Object.assign({}, extensionManifest, { id: extensionId }),
        }),
        i18n: Object.freeze({
            getUILanguage: () => Promise.resolve("en-US"),
            getMessage: (messageName, substitutions) =>
                requestApi("i18n.getMessage", {
                    messageName: String(messageName || ""),
                    substitutions: substitutions == null ? [] : Array.from(substitutions),
                }),
        }),
    });
    const chrome = browser;
    const patterns = __NOMAD_PATTERNS__.map((pattern) => new RegExp(pattern));
    const pageDocument = document;
    const pageWindow = (pageDocument && pageDocument.defaultView) || window;
    const pageLocation = pageWindow && pageWindow.location;
    if (!pageLocation || !patterns.some((pattern) => pattern.test(String(pageLocation.href)))) return;
    const isolatedWindow = __NOMAD_MAIN_WORLD__ ? pageWindow : new Proxy(pageWindow, {
        get(target, property, receiver) {
            if (property === "addEventListener") {
                return function(type, listener, options) {
                    if (type === "message" && typeof listener === "function") {
                        pageMessageListeners.push(listener);
                        rememberMessageTarget(receiver);
                        return;
                    }
                    return target.addEventListener.call(target, type, listener, options);
                };
            }
            if (property === "removeEventListener") {
                return (type, listener, options) => {
                    if (type === "message") {
                        const index = pageMessageListeners.indexOf(listener);
                        if (index >= 0) pageMessageListeners.splice(index, 1);
                        return;
                    }
                    return target.removeEventListener.call(target, type, listener, options);
                };
            }
            if (property === "postMessage") {
                return (payload, targetOrigin) => enqueue({
                    __nomad_isolated_world_message: {
                        payload,
                        target_origin: targetOrigin == null ? "*" : String(targetOrigin),
                    },
                }).catch(() => {});
            }
            if (property === "window" || property === "self") return receiver;
            const value = Reflect.get(target, property, target);
            return typeof value === "function" ? value.bind(target) : value;
        },
    });
    if (!__NOMAD_MAIN_WORLD__) {
        // The vendor isolated-world setup installs its own Window facade. Use
        // this bridge facade as the global window as well so libraries that
        // validate MessageEvent.source by identity see one stable object.
        try {
            for (const name of ["window", "self", "frames"]) {
                Object.defineProperty(globalThis, name, {
                    configurable: false,
                    enumerable: true,
                    writable: false,
                    value: isolatedWindow,
                });
            }
        } catch (_) {}
    }
    extensionWindow = isolatedWindow;
    if (!__NOMAD_MAIN_WORLD__) {
        const relayPostMessage = (payload, targetOrigin) => enqueue({
            __nomad_isolated_world_message: {
                payload,
                target_origin: targetOrigin == null ? "*" : String(targetOrigin),
            },
        }).catch(() => {});
        try {
            Object.defineProperty(globalThis, "addEventListener", {
                configurable: false,
                value: function(type, listener, options) {
                    if (type === "message" && typeof listener === "function") {
                        globalMessageListeners.push(listener);
                        rememberMessageTarget(this);
                        return;
                    }
                    return pageWindow.addEventListener.call(pageWindow, type, listener, options);
                },
            });
            Object.defineProperty(globalThis, "removeEventListener", {
                configurable: false,
                value: (type, listener, options) => {
                    if (type === "message") {
                        const index = globalMessageListeners.indexOf(listener);
                        if (index >= 0) globalMessageListeners.splice(index, 1);
                        return;
                    }
                    return pageWindow.removeEventListener.call(pageWindow, type, listener, options);
                },
            });
            Object.defineProperty(globalThis, "postMessage", {
                configurable: false,
                value: relayPostMessage,
            });
        } catch (_) {}
    }
    const styleSource = __NOMAD_STYLE__;
    if (styleSource && document.head) {
        const styleElement = document.createElement("style");
        styleElement.dataset.nomadExtension = extensionId;
        styleElement.textContent = styleSource;
        document.head.appendChild(styleElement);
    }
    const dispatchers = __NOMAD_MAIN_WORLD__
        ? (globalThis.__nomad_extension_dispatchers ||
            (globalThis.__nomad_extension_dispatchers = Object.create(null)))
        : (globalThis[Symbol.for(__NOMAD_ISOLATED_DISPATCH_KEY__)] ||
            (globalThis[Symbol.for(__NOMAD_ISOLATED_DISPATCH_KEY__)] = Object.create(null)));
    dispatchers[extensionId] = dispatch;
    if (__NOMAD_MAIN_WORLD__) {
        pageDocument.addEventListener("__nomad_extension_message", (event) => {
            const detail = event && event.detail;
            if (!detail || typeof detail !== "object" ||
                !Object.prototype.hasOwnProperty.call(detail, "payload")) return;
            enqueue({ __nomad_isolated_queue_message: detail });
        });
        // Servo currently does not deliver page MessageEvents to an isolated
        // user-script world in the same way Chromium does. Capture the page
        // side of the standard content-script transport in the main world;
        // the native bridge forwards it to the matching isolated dispatcher.
        pageWindow.addEventListener("message", (event) => {
            const data = event && event.data;
            if (!data || typeof data !== "object") return;
            if (Object.prototype.hasOwnProperty.call(data, "__nomad_isolated_queue_message")) {
                enqueue(data).catch(() => {});
            } else {
                enqueue({ __nomad_main_world_message: {
                    tab_id: tabInfo && tabInfo.id,
                    payload: data,
                } }).catch(() => {});
            }
        });
    } else {
        bridgeDispatchElement && bridgeDispatchElement.addEventListener(__NOMAD_ISOLATED_DISPATCH_EVENT__, () => {
            const element = bridgeDispatchElement;
            const raw = element && element.getAttribute(__NOMAD_ISOLATED_DISPATCH_ATTRIBUTE__);
            if (!raw) return;
            element.removeAttribute(__NOMAD_ISOLATED_DISPATCH_ATTRIBUTE__);
            try {
                dispatch(JSON.parse(raw));
            } catch (_) {}
        });
    }
    if (!__NOMAD_MAIN_WORLD__) {
        try {
            Object.defineProperty(globalThis, "console", {
                configurable: true,
                enumerable: true,
                writable: true,
                value: pageWindow && pageWindow.console,
            });
            Object.defineProperty(globalThis, "browser", {
                configurable: true,
                enumerable: false,
                value: browser,
            });
            Object.defineProperty(globalThis, "chrome", {
                configurable: true,
                enumerable: false,
                value: chrome,
            });
        } catch (_) {}
    }
    if (__NOMAD_MAIN_WORLD__) {
        try {
            pageWindow.Function("window", "document", "location", __NOMAD_SOURCE__)(
                pageWindow, pageDocument, pageLocation,
            );
        } catch (error) {
            reportWorldError(error && (error.stack || error.message) || error);
            console.error("Nomad extension main-world script failed", error && (error.stack || error));
        }
    } else {
        try {
            // Some isolated Servo globals expose a distinct MessageEvent
            // constructor without the standard source accessor. MetaMask's
            // post-message stream feature-detects this accessor and refuses
            // to start when it is absent. Message events delivered to this
            // content world originate from the page WindowProxy.
            const pageMessageEvent = pageWindow && pageWindow.MessageEvent;
            const baseMessageEvent = pageMessageEvent || globalThis.MessageEvent;
            if (typeof baseMessageEvent === "function") {
                let messageEvent = baseMessageEvent;
                try {
                    messageEvent = function NomadMessageEvent(type, init) {
                        const event = new baseMessageEvent(type, init);
                        try {
                            Object.defineProperty(event, "source", {
                                configurable: true,
                                get: () => extensionWindow,
                            });
                            Object.defineProperty(event, "origin", {
                                configurable: true,
                                get: () => String(pageLocation && pageLocation.origin || ""),
                            });
                        } catch (_) {}
                        return event;
                    };
                    messageEvent.prototype = Object.create(baseMessageEvent.prototype);
                    const baseSourceGetter = Object.getOwnPropertyDescriptor(
                        baseMessageEvent.prototype, "source",
                    )?.get;
                    const baseOriginGetter = Object.getOwnPropertyDescriptor(
                        baseMessageEvent.prototype, "origin",
                    )?.get;
                    Object.defineProperty(messageEvent.prototype, "source", {
                        configurable: true,
                        enumerable: true,
                        get() {
                            try {
                                return typeof baseSourceGetter === "function"
                                    ? baseSourceGetter.call(this)
                                    : extensionWindow;
                            } catch (_) {
                                return extensionWindow;
                            }
                        },
                    });
                    Object.defineProperty(messageEvent.prototype, "origin", {
                        configurable: true,
                        enumerable: true,
                        get() {
                            try {
                                return typeof baseOriginGetter === "function"
                                    ? baseOriginGetter.call(this)
                                    : String(pageLocation && pageLocation.origin || "");
                            } catch (_) {
                                return String(pageLocation && pageLocation.origin || "");
                            }
                        },
                    });
                    Object.defineProperty(globalThis, "MessageEvent", {
                        configurable: false,
                        enumerable: true,
                        writable: false,
                        value: messageEvent,
                    });
                } catch (_) {}
                extensionMessageEvent = messageEvent;
            }
            const execute = globalThis.Function("window", "document", "location", "browser", "chrome", __NOMAD_SOURCE__);
            execute(isolatedWindow, pageDocument, pageLocation, browser, chrome);
        } catch (error) {
            reportWorldError(error && (error.stack || error.message) || error);
            console.error("Nomad extension isolated-world script failed", error && (error.stack || error));
        }
    }
})();

"#;

/// Background-page runtime template. Placeholders are replaced with
/// per-extension values by `ServoRenderer::extension_background_source`.
const EXTENSION_BACKGROUND_SCRIPT_TEMPLATE: &str = r#"
(() => {
    const extensionId = __NOMAD_EXTENSION_ID__;
    const extensionBase = "nomad-extension://" + extensionId + "/";
    const queue = globalThis.__nomad_extension_messages ||
        (globalThis.__nomad_extension_messages = []);
    const emit = (payload) => {
        if (queue.length >= 4096) {
            return Promise.reject(new Error("Nomad extension message queue is full"));
        }
        queue.push({ extension_id: extensionId, payload });
        return Promise.resolve();
    };
    const pending = new Map();
    const extensionManifest = __NOMAD_MANIFEST__;
    let nextRequestId = 1;
    let nextPortId = 1;
    let runtimeLastError = null;
    const withCallback = (promise, callback) => {
        if (typeof callback === "function") {
            promise.then((value) => {
                runtimeLastError = null;
                callback(value);
            }, (error) => {
                runtimeLastError = { message: String(error && error.message || error) };
                try { callback(); } finally {
                    Promise.resolve().then(() => { runtimeLastError = null; });
                }
            });
        }
        return promise;
    };
    const requestApi = (method, argumentsValue) => new Promise((resolve, reject) => {
        const id = String(nextRequestId++);
        pending.set(id, { resolve, reject });
        emit({ __nomad_api_request: { id, method, arguments: argumentsValue } })
            .catch((error) => {
                pending.delete(id);
                reject(error);
            });
    });
    const storageState = Object.assign(Object.create(null), __NOMAD_STORAGE_STATE__);
    const syncState = Object.assign(Object.create(null), __NOMAD_SYNC_STORAGE_STATE__);
    const sessionState = Object.assign(Object.create(null), __NOMAD_SESSION_STORAGE_STATE__);
    const storageChangedListeners = [];
    const notifyStorageChanged = (area, changes) => {
        for (const listener of storageChangedListeners) listener(changes, area);
    };
    const makeStorageArea = (state, area) => Object.freeze({
        get(keys, callback) {
            const result = {};
            if (keys == null) return withCallback(Promise.resolve(Object.assign(result, state)), callback);
            const names = typeof keys === "string" ? [keys] :
                Array.isArray(keys) ? keys : Object.keys(keys);
            for (const name of names) {
                if (Object.prototype.hasOwnProperty.call(state, name)) {
                    result[name] = state[name];
                } else if (keys && !Array.isArray(keys) && typeof keys === "object") {
                    result[name] = keys[name];
                }
            }
            return withCallback(Promise.resolve(result), callback);
        },
        set(items, callback) {
            if (!items || typeof items !== "object" || Array.isArray(items)) {
                return Promise.reject(new TypeError("storage." + area + ".set expects an object"));
            }
            const changes = {};
            for (const [name, value] of Object.entries(items)) {
                changes[name] = { oldValue: state[name], newValue: value };
            }
            Object.assign(state, items);
            notifyStorageChanged(area, changes);
            return withCallback(emit({ __nomad_storage_area: area, __nomad_storage_set: items }), callback);
        },
        remove(keys, callback) {
            const names = typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : [];
            const changes = {};
            for (const name of names) {
                changes[name] = { oldValue: state[name], newValue: undefined };
                delete state[name];
            }
            notifyStorageChanged(area, changes);
            return withCallback(emit({ __nomad_storage_area: area, __nomad_storage_remove: names }), callback);
        },
        clear(callback) {
            const changes = {};
            for (const name of Object.keys(state)) {
                changes[name] = { oldValue: state[name], newValue: undefined };
            }
            for (const name of Object.keys(state)) delete state[name];
            notifyStorageChanged(area, changes);
            return withCallback(emit({ __nomad_storage_area: area, __nomad_storage_clear: true }), callback);
        },
        onChanged: Object.freeze({ addListener: (listener) => {
            if (typeof listener === "function") storageChangedListeners.push(listener);
        } }),
    });
    const storageLocal = makeStorageArea(storageState, "local");
    const storageSync = makeStorageArea(syncState, "sync");
    const storageSession = makeStorageArea(sessionState, "session");
    const emptyEvent = Object.freeze({ addListener: () => {}, removeListener: () => {} });
    const storageManaged = Object.freeze({
        get: (keys, callback) => {
            const result = {};
            if (keys && !Array.isArray(keys) && typeof keys === "object") {
                for (const [name, value] of Object.entries(keys)) result[name] = value;
            }
            return withCallback(Promise.resolve(result), callback);
        },
        getBytesInUse: (keys, callback) => withCallback(Promise.resolve(0), callback),
        onChanged: emptyEvent,
    });
    const listeners = {
        startup: [], installed: [], message: [], messageExternal: [], action: [], connect: [], connectExternal: [], webRequest: [], alarm: [],
        web_request: [], web_request_completed: [], web_request_headers_received: [], web_request_error: [],
        dnrRuleMatched: [],
        runtimeSuspend: [], runtimeUpdateAvailable: [],
        managementInstalled: [], managementUninstalled: [],
        managementEnabled: [], managementDisabled: [],
        historyVisited: [], historyTitleChanged: [], historyVisitRemoved: [],
        bookmarkCreated: [], bookmarkRemoved: [], bookmarkChanged: [], bookmarkMoved: [],
        downloadsCreated: [], downloadsChanged: [], downloadsErased: [],
        notificationClosed: [], notificationClicked: [], notificationButtonClicked: [],
        contextMenuClicked: [], contextMenuShown: [], contextMenuHidden: [],
        permissionAdded: [], permissionRemoved: [],
        cookieChanged: [],
        command: [],
        webNavigationCommitted: [], webNavigationCompleted: [], webNavigationError: [],
        webNavigationHistory: [], webNavigationBeforeNavigate: [], webNavigationDOMContentLoaded: [],
        tabCreated: [], tabUpdated: [], tabRemoved: [], tabActivated: [],
        windowCreated: [], windowRemoved: [], windowFocusChanged: [],
        identitySignInChanged: [],
    };
    const add = (name, listener) => {
        if (typeof listener === "function") listeners[name].push(listener);
    };
    const ports = new Map();
    const makePort = (event) => {
        const messageListeners = [];
        const disconnectListeners = [];
        const port = {
            name: event.name || "",
            sender: { id: extensionId, tab: { id: event.tab_id } },
            postMessage: (payload) => emit({ __nomad_port_response: {
                tab_id: event.tab_id,
                port_id: event.port_id,
                payload,
            } }),
            disconnect: () => {
                if (ports.delete(event.port_id)) {
                    emit({ __nomad_port_disconnect: {
                        tab_id: event.tab_id,
                        port_id: event.port_id,
                    } });
                }
            },
            onMessage: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") messageListeners.push(listener);
            } }),
            onDisconnect: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") disconnectListeners.push(listener);
            } }),
        };
        ports.set(event.port_id, { port, messageListeners, disconnectListeners });
        return port;
    };
    const makeExternalPort = (event) => {
        const messageListeners = [];
        const disconnectListeners = [];
        const port = {
            name: event.name || "",
            sender: { id: event.sender_extension_id },
            postMessage: (payload) => emit({ __nomad_extension_port_message: {
                target_id: event.sender_extension_id,
                port_id: event.port_id,
                payload,
            } }),
            disconnect: () => {
                if (ports.delete(event.port_id)) {
                    emit({ __nomad_extension_port_disconnect: {
                        target_id: event.sender_extension_id,
                        port_id: event.port_id,
                    } });
                }
            },
            onMessage: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") messageListeners.push(listener);
            } }),
            onDisconnect: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") disconnectListeners.push(listener);
            } }),
        };
        ports.set(event.port_id, { port, messageListeners, disconnectListeners });
        return port;
    };
    const dispatch = (event) => {
        if (!event || typeof event.kind !== "string") return;
        if (event.kind === "runtime_response") {
            const request = pending.get(event.request_id);
            if (!request) return;
            pending.delete(event.request_id);
            if (Object.prototype.hasOwnProperty.call(event, "error")) request.reject(new Error(event.error));
            else request.resolve(event.result);
        } else if (event.kind === "startup") {
            for (const listener of listeners.startup) listener();
        } else if (event.kind === "runtime_suspend") {
            for (const listener of listeners.runtimeSuspend) listener();
        } else if (event.kind === "history_visited") {
            for (const listener of listeners.historyVisited) listener(event.details);
        } else if (event.kind === "history_title_changed") {
            for (const listener of listeners.historyTitleChanged) listener(event.details);
        } else if (event.kind === "history_visit_removed") {
            for (const listener of listeners.historyVisitRemoved) listener(event.details);
        } else if (event.kind === "bookmark_created") {
            for (const listener of listeners.bookmarkCreated) listener(event.bookmark);
        } else if (event.kind === "bookmark_removed") {
            for (const listener of listeners.bookmarkRemoved) listener(event.id, { parentId: event.parent_id, index: event.index });
        } else if (event.kind === "bookmark_changed") {
            for (const listener of listeners.bookmarkChanged) listener(event.id, { title: event.title, url: event.url });
        } else if (event.kind === "bookmark_moved") {
            for (const listener of listeners.bookmarkMoved) listener(event.id, { oldParentId: event.old_parent_id, oldIndex: event.old_index, parentId: event.parent_id, index: event.index });
        } else if (event.kind === "download_created") {
            for (const listener of listeners.downloadsCreated) listener(event.details);
        } else if (event.kind === "download_changed") {
            for (const listener of listeners.downloadsChanged) listener(event.details);
        } else if (event.kind === "download_erased") {
            for (const listener of listeners.downloadsErased) listener({ id: event.id });
        } else if (event.kind === "management_installed") {
            for (const listener of listeners.managementInstalled) listener(event.info);
        } else if (event.kind === "management_uninstalled") {
            for (const listener of listeners.managementUninstalled) listener(event.info);
        } else if (event.kind === "management_enabled") {
            for (const listener of listeners.managementEnabled) listener(event.info);
        } else if (event.kind === "management_disabled") {
            for (const listener of listeners.managementDisabled) listener(event.info);
        } else if (event.kind === "runtime_update_available") {
            for (const listener of listeners.runtimeUpdateAvailable) listener({ version: event.version });
        } else if (event.kind === "installed") {
            for (const listener of listeners.installed) listener({ reason: event.reason });
        } else if (event.kind === "runtime_message") {
            const sender = event.sender_extension_id ? { id: event.sender_extension_id } : { id: extensionId };
            let responseSent = false;
            const sendResponse = (value) => {
                if (responseSent || !event.request_id || event.tab_id == null) return;
                responseSent = true;
                emit({ __nomad_page_response: {
                    tab_id: event.tab_id,
                    request_id: event.request_id,
                    result: value,
                } });
            };
            const messageListeners = event.sender_extension_id ? listeners.messageExternal : listeners.message;
            for (const listener of messageListeners) {
                const result = listener(
                    event.payload,
                    { id: sender.id, tab: { id: event.tab_id } },
                    sendResponse,
                );
                if (result && typeof result.then === "function") result.then(sendResponse);
                else if (result !== undefined && result !== true) sendResponse(result);
            }
            if (listeners.message.length === 0) sendResponse(undefined);
        } else if (event.kind === "runtime_port_connected") {
            const port = makePort(event);
            for (const listener of listeners.connect) listener(port);
        } else if (event.kind === "runtime_port_message") {
            const entry = ports.get(event.port_id);
            if (entry) for (const listener of entry.messageListeners) listener(event.payload, entry.port);
        } else if (event.kind === "runtime_port_disconnected") {
            const entry = ports.get(event.port_id);
            if (entry) {
                ports.delete(event.port_id);
                for (const listener of entry.disconnectListeners) listener(entry.port);
            }
        } else if (event.kind === "runtime_external_port_connected") {
            const port = makeExternalPort(event);
            for (const listener of listeners.connectExternal) listener(port);
        } else if (event.kind === "runtime_external_port_message") {
            const entry = ports.get(event.port_id);
            if (entry) for (const listener of entry.messageListeners) listener(event.payload, entry.port);
        } else if (event.kind === "runtime_external_port_disconnected") {
            const entry = ports.get(event.port_id);
            if (entry) {
                ports.delete(event.port_id);
                for (const listener of entry.disconnectListeners) listener(entry.port);
            }
        } else if (event.kind === "web_navigation") {
            const listenerName = event.event === "onCommitted" ? "webNavigationCommitted" :
                event.event === "onCompleted" ? "webNavigationCompleted" :
                event.event === "onErrorOccurred" ? "webNavigationError" :
                event.event === "onBeforeNavigate" ? "webNavigationBeforeNavigate" :
                event.event === "onDOMContentLoaded" ? "webNavigationDOMContentLoaded" : "webNavigationHistory";
            for (const listener of listeners[listenerName]) listener(event.details);
        } else if (event.kind === "storage_changed") {
            const changes = {};
            const payload = event.changes || {};
            const area = payload.__nomad_storage_area || "local";
            const state = area === "sync" ? syncState : area === "session" ? sessionState : storageState;
            for (const [name, value] of Object.entries(payload.__nomad_storage_set || {})) {
                changes[name] = { oldValue: state[name], newValue: value };
                state[name] = value;
            }
            for (const name of payload.__nomad_storage_remove || []) {
                changes[name] = { oldValue: state[name], newValue: undefined };
                delete state[name];
            }
            if (payload.__nomad_storage_clear) {
                for (const name of Object.keys(state)) {
                    changes[name] = { oldValue: state[name], newValue: undefined };
                    delete state[name];
                }
            }
            notifyStorageChanged(area, changes);
        } else if (event.kind === "context_menu_clicked") {
            for (const listener of listeners.contextMenuClicked) listener(event.info, event.tab);
        } else if (event.kind === "context_menu_shown") {
            for (const listener of listeners.contextMenuShown) listener(event.info, event.tab);
        } else if (event.kind === "context_menu_hidden") {
            for (const listener of listeners.contextMenuHidden) listener();
        } else if (event.kind === "cookie_changed") {
            for (const listener of listeners.cookieChanged) listener(event.cookie, event.cause, event.removed);
        } else if (event.kind === "permission_added") {
            for (const listener of listeners.permissionAdded) listener(event.details);
        } else if (event.kind === "permission_removed") {
            for (const listener of listeners.permissionRemoved) listener(event.details);
        } else if (event.kind === "notification_closed") {
            for (const listener of listeners.notificationClosed) listener(event.id, false);
        } else if (event.kind === "notification_clicked") {
            for (const listener of listeners.notificationClicked) listener(event.id);
        } else if (event.kind === "notification_button_clicked") {
            for (const listener of listeners.notificationButtonClicked) listener(event.id, event.button_index);
        } else if (event.kind === "alarm") {
            for (const listener of listeners.alarm) listener({ name: event.name, scheduledTime: event.scheduled_time_ms });
        } else if (event.kind === "web_request") {
            for (const listener of listeners[event.event] || []) listener(event.request);
        } else if (event.kind === "dnr_rule_matched") {
            for (const listener of listeners.dnrRuleMatched) listener(event.details);
        } else if (event.kind === "action_clicked") {
            for (const listener of listeners.action) listener(event.tab);
        } else if (event.kind === "command") {
            for (const listener of listeners.command) listener(event.command);
        } else if (event.kind === "tab_created") {
            for (const listener of listeners.tabCreated) listener(event.tab);
        } else if (event.kind === "tab_updated") {
            for (const listener of listeners.tabUpdated) listener(event.tab_id, event.change_info, event.tab);
        } else if (event.kind === "tab_removed") {
            for (const listener of listeners.tabRemoved) listener(event.tab_id, { windowId: event.window_id, isWindowClosing: false });
        } else if (event.kind === "tab_activated") {
            for (const listener of listeners.tabActivated) listener({ tabId: event.tab_id, windowId: event.window_id });
        } else if (event.kind === "window_created") {
            for (const listener of listeners.windowCreated) listener(event.window);
        } else if (event.kind === "window_removed") {
            for (const listener of listeners.windowRemoved) listener(event.window_id);
        } else if (event.kind === "window_focus_changed") {
            for (const listener of listeners.windowFocusChanged) listener(event.window_id);
        } else if (event.kind === "identity_sign_in_changed") {
            for (const listener of listeners.identitySignInChanged) listener(event.account, event.signed_in);
        }
    };
    const tabs = Object.freeze({
        query: (queryInfo, callback) => withCallback(requestApi("tabs.query", queryInfo || {}), callback),
        get: (tabId, callback) => withCallback(requestApi("tabs.get", { tabId }), callback),
        create: (createProperties, callback) => withCallback(requestApi("tabs.create", createProperties || {}), callback),
        update: (tabId, updateProperties, callback) => withCallback(requestApi("tabs.update", { tabId, updateProperties: updateProperties || {} }), callback),
        remove: (tabIds, callback) => withCallback(requestApi("tabs.remove", { tabIds }), callback),
        captureVisibleTab: (windowId, options, callback) => {
            if (windowId && typeof windowId === "object") {
                callback = typeof options === "function" ? options : callback;
                options = windowId;
                windowId = undefined;
            } else if (typeof windowId === "function") {
                callback = windowId;
                windowId = undefined;
                options = {};
            } else if (typeof options === "function") {
                callback = options;
                options = {};
            }
            return withCallback(requestApi("tabs.captureVisibleTab", Object.assign({}, options || {}, windowId == null ? {} : { windowId })), callback);
        },
        group: (options, callback) => withCallback(requestApi("tabs.group", options || {}), callback),
        ungroup: (tabIds, callback) => withCallback(requestApi("tabs.ungroup", { tabIds }), callback),
        reload: (tabId, reloadProperties, callback) => {
            if (typeof tabId === "object" && tabId !== null) {
                callback = typeof reloadProperties === "function" ? reloadProperties : callback;
                reloadProperties = tabId;
                tabId = reloadProperties.tabId;
            }
            return withCallback(requestApi("tabs.reload", { tabId }), callback);
        },
        duplicate: (tabId, callback) => withCallback(requestApi("tabs.duplicate", { tabId }), callback),
        discard: (tabId, callback) => withCallback(requestApi("tabs.discard", { tabId }), callback),
        goBack: (tabId, callback) => {
            if (typeof tabId === "function") { callback = tabId; tabId = undefined; }
            return withCallback(requestApi("tabs.goBack", tabId == null ? {} : { tabId }), callback);
        },
        goForward: (tabId, callback) => {
            if (typeof tabId === "function") { callback = tabId; tabId = undefined; }
            return withCallback(requestApi("tabs.goForward", tabId == null ? {} : { tabId }), callback);
        },
        getCurrent: (callback) => withCallback(requestApi("tabs.getCurrent", {}), callback),
        onCreated: Object.freeze({ addListener: (listener) => add("tabCreated", listener) }),
        onUpdated: Object.freeze({ addListener: (listener) => add("tabUpdated", listener) }),
        onRemoved: Object.freeze({ addListener: (listener) => add("tabRemoved", listener) }),
        onActivated: Object.freeze({ addListener: (listener) => add("tabActivated", listener) }),
        sendMessage: (tabId, message, options, callback) => {
            if (typeof options === "function") callback = options;
            return withCallback(requestApi("tabs.sendMessage", {
                tabId,
                message,
            }), callback);
        },
        connect: (tabId, connectInfo) => {
            const portId = extensionId + "-tabs-" + String(nextPortId++);
            const name = typeof connectInfo === "string" ? connectInfo :
                (connectInfo && connectInfo.name) || "";
            const messageListeners = [];
            const disconnectListeners = [];
            const port = {
                name,
                sender: { id: extensionId, tab: { id: tabId } },
                postMessage: (payload) => emit({ __nomad_tabs_port_message: {
                    tab_id: tabId,
                    port_id: portId,
                    payload,
                } }),
                disconnect: () => {
                    if (ports.delete(portId)) emit({ __nomad_tabs_port_disconnect: {
                        tab_id: tabId,
                        port_id: portId,
                    } });
                },
                onMessage: Object.freeze({ addListener: (listener) => {
                    if (typeof listener === "function") messageListeners.push(listener);
                } }),
                onDisconnect: Object.freeze({ addListener: (listener) => {
                    if (typeof listener === "function") disconnectListeners.push(listener);
                } }),
            };
            ports.set(portId, { port, messageListeners, disconnectListeners });
            emit({ __nomad_tabs_port_connect: { tab_id: tabId, port_id: portId, name } });
            return port;
        },
    });
    const history = Object.freeze({
        search: (query, callback) => withCallback(requestApi("history.search", query || {}), callback),
        getVisits: (query, callback) => withCallback(requestApi("history.getVisits", query || {}), callback),
        addUrl: (query, callback) => withCallback(requestApi("history.addUrl", query || {}), callback),
        deleteUrl: (query, callback) => withCallback(requestApi("history.deleteUrl", query || {}), callback),
        deleteRange: (query, callback) => withCallback(requestApi("history.deleteRange", query || {}), callback),
        deleteAll: (callback) => withCallback(requestApi("history.deleteAll", {}), callback),
        onVisited: Object.freeze({ addListener: (listener) => add("historyVisited", listener) }),
        onTitleChanged: Object.freeze({ addListener: (listener) => add("historyTitleChanged", listener) }),
        onVisitRemoved: Object.freeze({ addListener: (listener) => add("historyVisitRemoved", listener) }),
    });
    const bookmarks = Object.freeze({
        search: (query, callback) => withCallback(requestApi("bookmarks.search", query || {}), callback),
        get: (idOrIds, callback) => withCallback(requestApi("bookmarks.get", { ids: idOrIds == null ? null : Array.isArray(idOrIds) ? idOrIds : [idOrIds] }), callback),
        getChildren: (id, callback) => withCallback(requestApi("bookmarks.getChildren", { id }), callback),
        getTree: (callback) => withCallback(requestApi("bookmarks.getTree", {}), callback),
        getSubTree: (id, callback) => withCallback(requestApi("bookmarks.getSubTree", { id }), callback),
        create: (bookmark, callback) => withCallback(requestApi("bookmarks.create", bookmark || {}), callback),
        move: (id, destination, callback) => withCallback(requestApi("bookmarks.move", { id, destination: destination || {} }), callback),
        update: (id, changes, callback) => withCallback(requestApi("bookmarks.update", { id, changes: changes || {} }), callback),
        remove: (id, callback) => withCallback(requestApi("bookmarks.remove", { id }), callback),
        removeTree: (id, callback) => withCallback(requestApi("bookmarks.removeTree", { id }), callback),
        onCreated: Object.freeze({ addListener: (listener) => add("bookmarkCreated", listener) }),
        onRemoved: Object.freeze({ addListener: (listener) => add("bookmarkRemoved", listener) }),
        onChanged: Object.freeze({ addListener: (listener) => add("bookmarkChanged", listener) }),
        onMoved: Object.freeze({ addListener: (listener) => add("bookmarkMoved", listener) }),
    });
    const downloads = Object.freeze({
        search: (query, callback) => withCallback(requestApi("downloads.search", query || {}), callback),
        list: (callback) => withCallback(requestApi("downloads.list", {}), callback),
        download: (options, callback) => withCallback(requestApi("downloads.download", options || {}), callback),
        pause: (id, callback) => withCallback(requestApi("downloads.pause", { id }), callback),
        resume: (id, callback) => withCallback(requestApi("downloads.resume", { id }), callback),
        cancel: (id, callback) => withCallback(requestApi("downloads.cancel", { id }), callback),
        remove: (id, callback) => withCallback(requestApi("downloads.remove", { id }), callback),
        erase: (id, callback) => withCallback(requestApi("downloads.erase", { id }), callback),
        open: (id, callback) => withCallback(requestApi("downloads.open", { id }), callback),
        show: (id, callback) => withCallback(requestApi("downloads.show", { id }), callback),
        onCreated: Object.freeze({ addListener: (listener) => add("downloadsCreated", listener) }),
        onChanged: Object.freeze({ addListener: (listener) => add("downloadsChanged", listener) }),
        onErased: Object.freeze({ addListener: (listener) => add("downloadsErased", listener) }),
    });
    const identity = Object.freeze({
        getAuthToken: (details, callback) => withCallback(requestApi("identity.getAuthToken", details || {}), callback),
        launchWebAuthFlow: (details, callback) => withCallback(requestApi("identity.launchWebAuthFlow", details || {}), callback),
        onSignInChanged: Object.freeze({ addListener: (listener) => add("identitySignInChanged", listener) }),
    });
    const sendMessage = (targetOrPayload, payload, callback) => {
        if (typeof payload === "function") {
            callback = payload;
            payload = undefined;
        }
        if (typeof targetOrPayload === "string") {
            return withCallback(emit({ __nomad_extension_message: { target_id: targetOrPayload, payload } }), callback);
        }
        return withCallback(emit(targetOrPayload), callback);
    };
    const alarms = Object.freeze({
        create: (nameOrInfo, maybeInfo, maybeCallback) => {
            const callback = typeof maybeInfo === "function" ? maybeInfo : maybeCallback;
            const info = typeof nameOrInfo === "string" ? Object.assign({}, maybeInfo || {}, { name: nameOrInfo }) : (nameOrInfo || {});
            return withCallback(requestApi("alarms.create", info), callback);
        },
        clear: (name, callback) => withCallback(requestApi("alarms.clear", { name: name || "" }), callback),
        get: (name, callback) => withCallback(requestApi("alarms.get", { name: name || "" }), callback),
        getAll: (callback) => withCallback(requestApi("alarms.getAll", {}), callback),
        clearAll: (callback) => withCallback(requestApi("alarms.clearAll", {}), callback),
        onAlarm: Object.freeze({ addListener: (listener) => add("alarm", listener) }),
    });
    const notifications = Object.freeze({
        create: (idOrOptions, maybeOptions, maybeCallback) => {
            const callback = typeof maybeOptions === "function" ? maybeOptions : maybeCallback;
            const options = typeof idOrOptions === "string" ? Object.assign({}, maybeOptions || {}, { id: idOrOptions }) : (idOrOptions || {});
            return withCallback(requestApi("notifications.create", options), callback);
        },
        clear: (id, callback) => withCallback(requestApi("notifications.clear", { id: id || "" }), callback),
        getAll: (callback) => withCallback(requestApi("notifications.getAll", {}), callback),
        onClosed: Object.freeze({ addListener: (listener) => add("notificationClosed", listener) }),
        onClicked: Object.freeze({ addListener: (listener) => add("notificationClicked", listener) }),
        onButtonClicked: Object.freeze({ addListener: (listener) => add("notificationButtonClicked", listener) }),
    });
    const cookies = Object.freeze({
        get: (options, callback) => withCallback(requestApi("cookies.get", options || {}), callback),
        getAll: (options, callback) => withCallback(requestApi("cookies.getAll", options || {}), callback),
        set: (options, callback) => withCallback(requestApi("cookies.set", options || {}), callback),
        remove: (options, callback) => withCallback(requestApi("cookies.remove", options || {}), callback),
        onChanged: Object.freeze({ addListener: (listener) => add("cookieChanged", listener) }),
    });
    const scripting = Object.freeze({
        executeScript: (options, callback) => withCallback(requestApi("scripting.executeScript", options || {}), callback),
        registerContentScripts: (options, callback) => withCallback(requestApi("scripting.registerContentScripts", options || {}), callback),
        unregisterContentScripts: (options, callback) => withCallback(requestApi("scripting.unregisterContentScripts", options || {}), callback),
        updateContentScripts: (options, callback) => withCallback(requestApi("scripting.updateContentScripts", options || {}), callback),
        getRegisteredContentScripts: (options, callback) => withCallback(requestApi("scripting.getRegisteredContentScripts", options || {}), callback),
        insertCSS: (options, callback) => withCallback(requestApi("scripting.insertCSS", options || {}), callback),
        removeCSS: (options, callback) => withCallback(requestApi("scripting.removeCSS", options || {}), callback),
    });
    const sendNativeMessage = (hostName, message) =>
        requestApi("runtime.sendNativeMessage", { hostName, message });
    const connect = (targetOrInfo, maybeConnectInfo) => {
        const targetId = typeof targetOrInfo === "string" ? targetOrInfo : extensionId;
        const connectInfo = typeof targetOrInfo === "string" ? maybeConnectInfo : targetOrInfo;
        if (typeof targetId !== "string" || !targetId || targetId.length > 128) {
            throw new TypeError("runtime.connect target extension id is invalid");
        }
        const portId = extensionId + "-runtime-" + String(nextPortId++);
        const listeners = [];
        const disconnectListeners = [];
        const port = {
            name: typeof connectInfo === "string" ? connectInfo : (connectInfo && connectInfo.name) || "",
            sender: { id: extensionId },
            postMessage: (payload) => emit({ __nomad_extension_port_message: {
                target_id: targetId,
                port_id: portId,
                payload,
            } }),
            disconnect: () => {
                if (ports.delete(portId)) emit({ __nomad_extension_port_disconnect: {
                    target_id: targetId,
                    port_id: portId,
                } });
            },
            onMessage: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") listeners.push(listener);
            } }),
            onDisconnect: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") disconnectListeners.push(listener);
            } }),
        };
        ports.set(portId, { port, messageListeners: listeners, disconnectListeners });
        emit({ __nomad_extension_port_connect: { target_id: targetId, port_id: portId, name: port.name } });
        return port;
    };
    const contextMenus = Object.freeze({
        create: (properties, callback) => withCallback(requestApi("contextMenus.create", properties || {}), callback),
        remove: (menuItemId, callback) => withCallback(requestApi("contextMenus.remove", { menuItemId }), callback),
        removeAll: (callback) => withCallback(requestApi("contextMenus.removeAll", {}), callback),
        update: (menuItemId, updateProperties, callback) => withCallback(requestApi("contextMenus.update", { menuItemId, updateProperties: updateProperties || {} }), callback),
        onClicked: Object.freeze({ addListener: (listener) => add("contextMenuClicked", listener) }),
        onShown: Object.freeze({ addListener: (listener) => add("contextMenuShown", listener) }),
        onHidden: Object.freeze({ addListener: (listener) => add("contextMenuHidden", listener) }),
    });
    const offscreen = Object.freeze({
        hasDocument: (callback) => withCallback(requestApi("offscreen.hasDocument", {}), callback),
        createDocument: (options, callback) => withCallback(requestApi("offscreen.createDocument", options || {}), callback),
        closeDocument: (callback) => withCallback(requestApi("offscreen.closeDocument", {}), callback),
    });
    const management = Object.freeze({
        getAll: (callback) => withCallback(requestApi("management.getAll", {}), callback),
        get: (id, callback) => withCallback(requestApi("management.get", { id }), callback),
        getSelf: (callback) => withCallback(requestApi("management.getSelf", {}), callback),
        getPermissionWarningsById: (id, callback) => withCallback(requestApi("management.getPermissionWarningsById", { id }), callback),
        setEnabled: (id, enabled, callback) => withCallback(requestApi("management.setEnabled", { id, enabled }), callback),
        uninstallSelf: (options, callback) => withCallback(requestApi("management.uninstallSelf", options || {}), callback),
        onInstalled: Object.freeze({ addListener: (listener) => add("managementInstalled", listener) }),
        onUninstalled: Object.freeze({ addListener: (listener) => add("managementUninstalled", listener) }),
        onEnabled: Object.freeze({ addListener: (listener) => add("managementEnabled", listener) }),
        onDisabled: Object.freeze({ addListener: (listener) => add("managementDisabled", listener) }),
    });
    const permissions = Object.freeze({
        contains: (options, callback) => withCallback(requestApi("permissions.contains", options || {}), callback),
        request: (options, callback) => withCallback(requestApi("permissions.request", options || {}), callback),
        remove: (options, callback) => withCallback(requestApi("permissions.remove", options || {}), callback),
        getAll: (callback) => withCallback(requestApi("permissions.getAll", {}), callback),
        onAdded: Object.freeze({ addListener: (listener) => add("permissionAdded", listener) }),
        onRemoved: Object.freeze({ addListener: (listener) => add("permissionRemoved", listener) }),
    });

    const windows = Object.freeze({
        get: (windowId, callback) => withCallback(requestApi("windows.get", { windowId }), callback),
        getCurrent: (callback) => withCallback(requestApi("windows.getCurrent", {}), callback),
        getAll: (queryInfo, callback) => withCallback(requestApi("windows.getAll", queryInfo || {}), callback),
        create: (createData, callback) => withCallback(requestApi("windows.create", createData || {}), callback),
        update: (windowId, updateInfo, callback) => withCallback(requestApi("windows.update", { windowId, updateInfo: updateInfo || {} }), callback),
        remove: (windowId, callback) => withCallback(requestApi("windows.remove", { windowId }), callback),
        onCreated: Object.freeze({ addListener: (listener) => add("windowCreated", listener) }),
        onRemoved: Object.freeze({ addListener: (listener) => add("windowRemoved", listener) }),
        onFocusChanged: Object.freeze({ addListener: (listener) => add("windowFocusChanged", listener) }),
    });
    const tabGroups = Object.freeze({
        get: (groupId, callback) => withCallback(requestApi("tabGroups.get", { groupId }), callback),
        query: (queryInfo, callback) => withCallback(requestApi("tabGroups.query", queryInfo || {}), callback),
        update: (groupId, updateProperties, callback) => withCallback(requestApi("tabGroups.update", { groupId, updateProperties: updateProperties || {} }), callback),
    });
    const webNavigation = Object.freeze({
        getAllFrames: (details, callback) => withCallback(requestApi("webNavigation.getAllFrames", details || {}), callback),
        getFrame: (details, callback) => withCallback(requestApi("webNavigation.getFrame", details || {}), callback),
        onCommitted: Object.freeze({ addListener: (listener) => add("webNavigationCommitted", listener) }),
        onCompleted: Object.freeze({ addListener: (listener) => add("webNavigationCompleted", listener) }),
        onBeforeNavigate: Object.freeze({ addListener: (listener) => add("webNavigationBeforeNavigate", listener) }),
        onDOMContentLoaded: Object.freeze({ addListener: (listener) => add("webNavigationDOMContentLoaded", listener) }),
        onErrorOccurred: Object.freeze({ addListener: (listener) => add("webNavigationError", listener) }),
        onHistoryStateUpdated: Object.freeze({ addListener: (listener) => add("webNavigationHistory", listener) }),
    });
    const declarativeNetRequest = Object.freeze({
        getDynamicRules: (callback) => withCallback(requestApi("declarativeNetRequest.getDynamicRules", {}), callback),
        getSessionRules: (callback) => withCallback(requestApi("declarativeNetRequest.getSessionRules", {}), callback),
        updateDynamicRules: (options, callback) => withCallback(requestApi("declarativeNetRequest.updateDynamicRules", options || {}), callback),
        updateSessionRules: (options, callback) => withCallback(requestApi("declarativeNetRequest.updateSessionRules", options || {}), callback),
        isSessionEnabled: (callback) => withCallback(requestApi("declarativeNetRequest.isSessionEnabled", {}), callback),
        getEnabledRulesets: (callback) => withCallback(requestApi("declarativeNetRequest.getEnabledRulesets", {}), callback),
        updateEnabledRulesets: (options, callback) => withCallback(requestApi("declarativeNetRequest.updateEnabledRulesets", options || {}), callback),
        isRegexSupported: (options, callback) => withCallback(requestApi("declarativeNetRequest.isRegexSupported", options || {}), callback),
        setExtensionActionOptions: (options, callback) => withCallback(requestApi("declarativeNetRequest.setExtensionActionOptions", options || {}), callback),
        onRuleMatched: Object.freeze({ addListener: (listener) => add("dnrRuleMatched", listener) }),
    });
    globalThis.__nomad_extension_dispatch = dispatch;
    const browser = Object.freeze({
        runtime: Object.freeze({
            sendMessage,
            sendNativeMessage,
            connect,
            id: extensionId,
            get lastError() { return runtimeLastError; },
            getURL: (path) => new URL(String(path || ""), extensionBase).href,
            getPlatformInfo: (callback) => withCallback(requestApi("runtime.getPlatformInfo", {}), callback),
            getBrowserInfo: (callback) => withCallback(requestApi("runtime.getBrowserInfo", {}), callback),
            getManifest: () => Object.assign({}, extensionManifest, { id: extensionId }),
            onStartup: Object.freeze({ addListener: (listener) => add("startup", listener) }),
            onInstalled: Object.freeze({ addListener: (listener) => add("installed", listener) }),
            onSuspend: Object.freeze({ addListener: (listener) => add("runtimeSuspend", listener) }),
            onUpdateAvailable: Object.freeze({ addListener: (listener) => add("runtimeUpdateAvailable", listener) }),
            openOptionsPage: (callback) => withCallback(requestApi("runtime.openOptionsPage", {}), callback),
            setUninstallURL: (url, callback) => withCallback(requestApi("runtime.setUninstallURL", { url: url || "" }), callback),
            onMessage: Object.freeze({ addListener: (listener) => add("message", listener) }),
            onMessageExternal: Object.freeze({ addListener: (listener) => add("messageExternal", listener) }),
            onConnect: Object.freeze({ addListener: (listener) => add("connect", listener) }),
            onConnectExternal: Object.freeze({ addListener: (listener) => add("connectExternal", listener) }),
            getContexts: (filter, callback) => withCallback(requestApi("runtime.getContexts", filter || {}), callback),
        }),
        storage: Object.freeze({
            local: storageLocal,
            sync: storageSync,
            session: storageSession,
            managed: storageManaged,
            onChanged: Object.freeze({ addListener: (listener) => {
                if (typeof listener === "function") storageChangedListeners.push(listener);
            } }),
        }),
        extension: Object.freeze({
            getURL: (path) => new URL(String(path || ""), extensionBase).href,
            getManifest: () => Object.assign({}, extensionManifest, { id: extensionId }),
        }),
        i18n: Object.freeze({
            getUILanguage: (callback) => withCallback(requestApi("i18n.getUILanguage", {}), callback),
            getAcceptLanguages: (callback) => withCallback(requestApi("i18n.getAcceptLanguages", {}), callback),
            detectLanguage: (text, callback) => withCallback(requestApi("i18n.detectLanguage", { text: String(text || "") }), callback),
            getMessage: (messageName, substitutions, callback) => {
                if (typeof substitutions === "function") {
                    callback = substitutions;
                    substitutions = undefined;
                }
                const values = Array.isArray(substitutions) ? substitutions :
                    substitutions == null ? [] : [substitutions];
                return withCallback(requestApi("i18n.getMessage", {
                    messageName,
                    substitutions: values,
                }), callback);
            },
        }),
        permissions,
        tabs,
        history,
        bookmarks,
        downloads,
        identity,
        alarms,
        notifications,
        cookies,
        scripting,
        contextMenus,
        offscreen,
        management,
        permissions,
        windows,
        tabGroups,
        webNavigation,
        declarativeNetRequest,
        webRequest: Object.freeze({
            onBeforeRequest: Object.freeze({ addListener: (listener) => add("web_request", listener) }),
            onCompleted: Object.freeze({ addListener: (listener) => add("web_request_completed", listener) }),
            onHeadersReceived: Object.freeze({ addListener: (listener) => add("web_request_headers_received", listener) }),
            onErrorOccurred: Object.freeze({ addListener: (listener) => add("web_request_error", listener) }),
            handlerBehaviorChanged: (callback) => withCallback(requestApi("webRequest.handlerBehaviorChanged", {}), callback),
            resolveBlocking: (details, callback) => withCallback(requestApi("webRequest.resolveBlocking", details || {}), callback),
        }),
        action: Object.freeze({
            onClicked: Object.freeze({ addListener: (listener) => add("action", listener) }),
            setBadgeText: (details, callback) => withCallback(requestApi("action.setBadgeText", details || {}), callback),
            setBadgeBackgroundColor: (details, callback) => withCallback(requestApi("action.setBadgeBackgroundColor", details || {}), callback),
            setBadgeTextColor: (details, callback) => withCallback(requestApi("action.setBadgeTextColor", details || {}), callback),
            setTitle: (details, callback) => withCallback(requestApi("action.setTitle", details || {}), callback),
            setPopup: (details, callback) => withCallback(requestApi("action.setPopup", details || {}), callback),
            setIcon: (details, callback) => withCallback(requestApi("action.setIcon", details || {}), callback),
            enable: (callback) => withCallback(requestApi("action.enable", {}), callback),
            disable: (callback) => withCallback(requestApi("action.disable", {}), callback),
            getBadgeText: (details, callback) => withCallback(requestApi("action.getBadgeText", details || {}), callback),
            getBadgeBackgroundColor: (details, callback) => withCallback(requestApi("action.getBadgeBackgroundColor", details || {}), callback),
            getBadgeTextColor: (details, callback) => withCallback(requestApi("action.getBadgeTextColor", details || {}), callback),
            getTitle: (details, callback) => withCallback(requestApi("action.getTitle", details || {}), callback),
            getPopup: (details, callback) => withCallback(requestApi("action.getPopup", details || {}), callback),
        }),
        browserAction: Object.freeze({
            onClicked: Object.freeze({ addListener: (listener) => add("action", listener) }),
            setBadgeText: (details, callback) => withCallback(requestApi("action.setBadgeText", details || {}), callback),
            setBadgeBackgroundColor: (details, callback) => withCallback(requestApi("action.setBadgeBackgroundColor", details || {}), callback),
            setBadgeTextColor: (details, callback) => withCallback(requestApi("action.setBadgeTextColor", details || {}), callback),
            setTitle: (details, callback) => withCallback(requestApi("action.setTitle", details || {}), callback),
            setPopup: (details, callback) => withCallback(requestApi("action.setPopup", details || {}), callback),
            setIcon: (details, callback) => withCallback(requestApi("action.setIcon", details || {}), callback),
            enable: (callback) => withCallback(requestApi("action.enable", {}), callback),
            disable: (callback) => withCallback(requestApi("action.disable", {}), callback),
            getBadgeText: (details, callback) => withCallback(requestApi("action.getBadgeText", details || {}), callback),
            getBadgeBackgroundColor: (details, callback) => withCallback(requestApi("action.getBadgeBackgroundColor", details || {}), callback),
            getBadgeTextColor: (details, callback) => withCallback(requestApi("action.getBadgeTextColor", details || {}), callback),
            getTitle: (details, callback) => withCallback(requestApi("action.getTitle", details || {}), callback),
            getPopup: (details, callback) => withCallback(requestApi("action.getPopup", details || {}), callback),
        }),
        commands: Object.freeze({
            getAll: (callback) => withCallback(requestApi("commands.getAll", {}), callback),
            onCommand: Object.freeze({ addListener: (listener) => add("command", listener) }),
        }),
    });
    globalThis.browser = browser;
    globalThis.chrome = browser;
    globalThis.self = globalThis;
    // MetaMask's MV3 bootstrap expects the ServiceWorkerGlobalScope
    // `self.serviceWorker` attribute. The background context is a window,
    // so provide an activated-worker stand-in: its final top-level check
    // (`"activated"===globalThis.serviceWorker.state`) is what starts the
    // app runtime when no real install/activate lifecycle exists.
    if (typeof globalThis.serviceWorker === "undefined") {
        Object.defineProperty(globalThis, "serviceWorker", {
            configurable: true,
            value: Object.freeze({
                state: "activated",
                addEventListener: () => {},
                removeEventListener: () => {},
                dispatchEvent: () => false,
                onstatechange: null,
            }),
        });
    }
    // MetaMask's MV3 service worker loads its webpack chunks through
    // `importScripts`, which exists in a real ServiceWorkerGlobalScope but
    // not in this window-based background. Provide the synchronous
    // fetch-and-evaluate semantics webpack's chunk loader depends on.
    if (typeof globalThis.importScripts !== "function") {
        const importScriptsImpl = (...paths) => {
            // Chunks must parse as sloppy classic scripts: LavaMoat wraps
            // modules in `with` blocks that SES's strict evaluator rejects,
            // and a compartment-recreated eval is strict. Fetch synchronously
            // (webpack's worker-mode loader contract) and execute through an
            // inline script element so the chunk runs as a classic script in
            // the background page's real global, where the main bundle's
            // intercepted webpackChunk push array lives.
            for (const path of paths) {
                const url = new URL(String(path), extensionBase).href;
                const request = new XMLHttpRequest();
                request.open("GET", url, false);
                request.send(null);
                if (request.status !== 0 && (request.status < 200 || request.status >= 300)) {
                    throw new Error("importScripts failed for " + url + " (status " + request.status + ")");
                }
                const scriptElement = document.createElement("script");
                scriptElement.textContent = String(request.responseText || "");
                (document.head || document.documentElement).appendChild(scriptElement);
            }
        };
        // Present as a native function: LavaMoat recreates user-defined
        // host functions inside the SES compartment, where the chunk's
        // sloppy `with` module wrappers fail to parse.
        Object.defineProperty(importScriptsImpl, "name", { value: "importScripts" });
        Object.defineProperty(importScriptsImpl, "toString", {
            value: () => "function importScripts() { [native code] }",
        });
        Object.defineProperty(globalThis, "importScripts", {
            configurable: true,
            writable: true,
            value: importScriptsImpl,
        });
    }
    void __NOMAD_CONTEXT_KIND__;
    const scriptPaths = __NOMAD_SCRIPT_PATHS__;
    const inlineSource = __NOMAD_SOURCE__;
    const runInlineSource = () => {
        if (typeof inlineSource === "string" && inlineSource.trim()) {
            try {
                return eval(inlineSource);
            } catch (error) {
                console.error("Nomad extension background script failed", error && (error.stack || error));
            }
        }
        return undefined;
    };
    const reportBackgroundError = (detail) => {
        let message = typeof detail === "string" ? detail :
            String(detail && (detail.stack || detail.message) || detail);
        if (detail && detail.stack && detail.message && !detail.stack.includes(detail.message)) {
            message = String(detail.name || "Error") + ": " + String(detail.message) + "\n" + String(detail.stack);
        }
        try {
            queue.push({ extension_id: extensionId, payload: { __nomad_background_error: message } });
        } catch (_) {}
    };
    window.addEventListener("error", (event) => {
        const error = event && event.error;
        reportBackgroundError(error || (event && event.message) || "background script error");
    });
    window.addEventListener("unhandledrejection", (event) => {
        const reason = event && event.reason;
        const name = reason && (reason.message || reason) || "rejection";
        const stack = reason && reason.stack;
        reportBackgroundError(stack && !String(stack).includes(String(name)) ?
            String(name) + "\n" + String(stack) : (stack || name));
    });
            if (Array.isArray(scriptPaths) && scriptPaths.length) {
        const parent = document.head || document.documentElement || document.body;
        for (const path of scriptPaths) {
            if (typeof path !== "string" || !path || path.includes("..")) continue;
            const scriptElement = document.createElement("script");
            scriptElement.src = new URL(path, extensionBase).href;
            scriptElement.addEventListener("error", () => {
                reportBackgroundError("failed to load background script " + path);
            });
            if (__NOMAD_MODULE__) scriptElement.type = "module";
            parent.appendChild(scriptElement);
        }
    } else {
        runInlineSource();
    }
})();

"#;

fn extension_event_value(event: &ExtensionEvent) -> serde_json::Value {
    let kind = &event.kind;
    extension_runtime_event_value(kind)
        .or_else(|| extension_content_event_value(kind))
        .or_else(|| extension_menu_event_value(kind))
        .or_else(|| extension_management_event_value(kind))
        .or_else(|| extension_tab_window_event_value(kind))
        .expect("every ExtensionEventKind variant is handled by an extension event helper")
}

fn extension_runtime_event_value(kind: &ExtensionEventKind) -> Option<serde_json::Value> {
    match kind {
        ExtensionEventKind::Startup => Some(serde_json::json!({"kind": "startup"})),
        ExtensionEventKind::Installed { reason } => Some(serde_json::json!({
            "kind": "installed",
            "reason": reason,
        })),
        ExtensionEventKind::RuntimeMessage {
            sender_extension_id,
            tab_id,
            request_id,
            payload,
        } => Some(serde_json::json!({
            "kind": "runtime_message",
            "sender_extension_id": sender_extension_id,
            "tab_id": tab_id,
            "request_id": request_id,
            "payload": payload,
        })),
        ExtensionEventKind::RuntimePortConnected {
            tab_id,
            port_id,
            name,
        } => Some(serde_json::json!({
            "kind": "runtime_port_connected",
            "tab_id": tab_id,
            "port_id": port_id,
            "name": name,
        })),
        ExtensionEventKind::RuntimePortMessage {
            tab_id,
            port_id,
            payload,
        } => Some(serde_json::json!({
            "kind": "runtime_port_message",
            "tab_id": tab_id,
            "port_id": port_id,
            "payload": payload,
        })),
        ExtensionEventKind::RuntimePortDisconnected { tab_id, port_id } => {
            Some(serde_json::json!({
                "kind": "runtime_port_disconnected",
                "tab_id": tab_id,
                "port_id": port_id,
            }))
        }
        ExtensionEventKind::RuntimeExternalPortConnected {
            sender_extension_id,
            port_id,
            name,
        } => Some(serde_json::json!({
            "kind": "runtime_external_port_connected",
            "sender_extension_id": sender_extension_id,
            "port_id": port_id,
            "name": name,
        })),
        ExtensionEventKind::RuntimeExternalPortMessage {
            sender_extension_id,
            port_id,
            payload,
        } => Some(serde_json::json!({
            "kind": "runtime_external_port_message",
            "sender_extension_id": sender_extension_id,
            "port_id": port_id,
            "payload": payload,
        })),
        ExtensionEventKind::RuntimeExternalPortDisconnected {
            sender_extension_id,
            port_id,
        } => Some(serde_json::json!({
            "kind": "runtime_external_port_disconnected",
            "sender_extension_id": sender_extension_id,
            "port_id": port_id,
        })),
        ExtensionEventKind::RuntimeSuspend => Some(serde_json::json!({
            "kind": "runtime_suspend",
        })),
        ExtensionEventKind::RuntimeUpdateAvailable { version } => Some(serde_json::json!({
            "kind": "runtime_update_available",
            "version": version,
        })),
        ExtensionEventKind::RuntimeResponse { request_id, result } => Some(match result {
            Ok(result) => serde_json::json!({
                "kind": "runtime_response",
                "request_id": request_id,
                "result": result,
            }),
            Err(error) => serde_json::json!({
                "kind": "runtime_response",
                "request_id": request_id,
                "error": error,
            }),
        }),
        _ => None,
    }
}

fn extension_content_event_value(kind: &ExtensionEventKind) -> Option<serde_json::Value> {
    match kind {
        ExtensionEventKind::WebNavigation { event, details } => Some(serde_json::json!({
            "kind": "web_navigation",
            "event": event,
            "details": details,
        })),
        ExtensionEventKind::StorageChanged { changes } => Some(serde_json::json!({
            "kind": "storage_changed",
            "changes": changes,
        })),
        ExtensionEventKind::NotificationClosed { id } => Some(serde_json::json!({
            "kind": "notification_closed",
            "id": id,
        })),
        ExtensionEventKind::NotificationClicked { id } => Some(serde_json::json!({
            "kind": "notification_clicked",
            "id": id,
        })),
        ExtensionEventKind::NotificationButtonClicked { id, button_index } => {
            Some(serde_json::json!({
                "kind": "notification_button_clicked",
                "id": id,
                "button_index": button_index,
            }))
        }
        ExtensionEventKind::Alarm {
            name,
            scheduled_time_ms,
        } => Some(serde_json::json!({
            "kind": "alarm",
            "name": name,
            "scheduled_time_ms": scheduled_time_ms,
        })),
        ExtensionEventKind::CookieChanged {
            cookie,
            cause,
            removed,
        } => Some(serde_json::json!({
            "kind": "cookie_changed",
            "cookie": cookie,
            "cause": cause,
            "removed": removed,
        })),
        ExtensionEventKind::Command { command } => Some(serde_json::json!({
            "kind": "command",
            "command": command,
        })),
        ExtensionEventKind::IdentitySignInChanged { signed_in, account } => {
            Some(serde_json::json!({
                "kind": "identity_sign_in_changed",
                "signed_in": signed_in,
                "account": account,
            }))
        }
        _ => None,
    }
}

fn extension_menu_event_value(kind: &ExtensionEventKind) -> Option<serde_json::Value> {
    match kind {
        ExtensionEventKind::ContextMenuClicked { info, tab } => Some(serde_json::json!({
            "kind": "context_menu_clicked",
            "info": info,
            "tab": tab.as_ref().map(|tab: &crate::extensions::ExtensionTabInfo| {
                serde_json::json!({
                    "id": tab.id,
                    "url": tab.url.as_ref().map(ToString::to_string),
                    "active": tab.active,
                })
            }),
        })),
        ExtensionEventKind::ContextMenuShown { info, tab } => Some(serde_json::json!({
            "kind": "context_menu_shown",
            "info": info,
            "tab": tab.as_ref().map(|tab: &crate::extensions::ExtensionTabInfo| {
                serde_json::json!({
                    "id": tab.id,
                    "url": tab.url.as_ref().map(ToString::to_string),
                    "active": tab.active,
                })
            }),
        })),
        ExtensionEventKind::ContextMenuHidden => Some(serde_json::json!({
            "kind": "context_menu_hidden",
        })),
        ExtensionEventKind::ActionClicked { tab } => Some(serde_json::json!({
            "kind": "action_clicked",
            "tab": {
                "id": tab.id,
                "url": tab.url.as_ref().map(ToString::to_string),
                "active": tab.active,
            },
        })),
        _ => None,
    }
}

fn extension_management_event_value(kind: &ExtensionEventKind) -> Option<serde_json::Value> {
    match kind {
        ExtensionEventKind::PermissionAdded { details } => Some(serde_json::json!({
            "kind": "permission_added",
            "details": details,
        })),
        ExtensionEventKind::PermissionRemoved { details } => Some(serde_json::json!({
            "kind": "permission_removed",
            "details": details,
        })),
        ExtensionEventKind::ManagementInstalled { info } => Some(serde_json::json!({
            "kind": "management_installed",
            "info": info,
        })),
        ExtensionEventKind::ManagementUninstalled { info } => Some(serde_json::json!({
            "kind": "management_uninstalled",
            "info": info,
        })),
        ExtensionEventKind::ManagementEnabled { info } => Some(serde_json::json!({
            "kind": "management_enabled",
            "info": info,
        })),
        ExtensionEventKind::ManagementDisabled { info } => Some(serde_json::json!({
            "kind": "management_disabled",
            "info": info,
        })),
        ExtensionEventKind::HistoryVisited { details } => Some(serde_json::json!({
            "kind": "history_visited",
            "details": details,
        })),
        ExtensionEventKind::HistoryTitleChanged { details } => Some(serde_json::json!({
            "kind": "history_title_changed",
            "details": details,
        })),
        ExtensionEventKind::HistoryVisitRemoved { details } => Some(serde_json::json!({
            "kind": "history_visit_removed",
            "details": details,
        })),
        ExtensionEventKind::BookmarkCreated { bookmark } => Some(serde_json::json!({
            "kind": "bookmark_created",
            "bookmark": bookmark,
        })),
        ExtensionEventKind::BookmarkRemoved {
            id,
            parent_id,
            index,
        } => Some(serde_json::json!({
            "kind": "bookmark_removed",
            "id": id,
            "parent_id": parent_id,
            "index": index,
        })),
        ExtensionEventKind::BookmarkChanged { id, title, url } => Some(serde_json::json!({
            "kind": "bookmark_changed",
            "id": id,
            "title": title,
            "url": url,
        })),
        ExtensionEventKind::BookmarkMoved {
            id,
            old_parent_id,
            old_index,
            parent_id,
            index,
        } => Some(serde_json::json!({
            "kind": "bookmark_moved",
            "id": id,
            "old_parent_id": old_parent_id,
            "old_index": old_index,
            "parent_id": parent_id,
            "index": index,
        })),
        ExtensionEventKind::DownloadCreated { details } => Some(serde_json::json!({
            "kind": "download_created",
            "details": details,
        })),
        ExtensionEventKind::DownloadChanged { details } => Some(serde_json::json!({
            "kind": "download_changed",
            "details": details,
        })),
        ExtensionEventKind::DownloadErased { id } => Some(serde_json::json!({
            "kind": "download_erased",
            "id": id,
        })),
        ExtensionEventKind::WebRequest { request, event } => Some(serde_json::json!({
            "kind": "web_request",
            "event": event,
            "request": request,
        })),
        ExtensionEventKind::RuleMatched { details } => Some(serde_json::json!({
            "kind": "dnr_rule_matched",
            "details": details,
        })),
        _ => None,
    }
}

fn extension_tab_window_event_value(kind: &ExtensionEventKind) -> Option<serde_json::Value> {
    match kind {
        ExtensionEventKind::TabCreated { tab } => Some(serde_json::json!({
            "kind": "tab_created",
            "tab": tab,
        })),
        ExtensionEventKind::TabUpdated {
            tab_id,
            change_info,
            tab,
        } => Some(serde_json::json!({
            "kind": "tab_updated",
            "tab_id": tab_id,
            "change_info": change_info,
            "tab": tab,
        })),
        ExtensionEventKind::TabRemoved { tab_id, window_id } => Some(serde_json::json!({
            "kind": "tab_removed",
            "tab_id": tab_id,
            "window_id": window_id,
        })),
        ExtensionEventKind::TabActivated { tab_id, window_id } => Some(serde_json::json!({
            "kind": "tab_activated",
            "tab_id": tab_id,
            "window_id": window_id,
        })),
        ExtensionEventKind::WindowCreated { window } => Some(serde_json::json!({
            "kind": "window_created",
            "window": window,
        })),
        ExtensionEventKind::WindowRemoved { window_id } => Some(serde_json::json!({
            "kind": "window_removed",
            "window_id": window_id,
        })),
        ExtensionEventKind::WindowFocusChanged { window_id } => Some(serde_json::json!({
            "kind": "window_focus_changed",
            "window_id": window_id,
        })),
        _ => None,
    }
}

fn cookie_to_json(cookie: &Cookie<'static>) -> serde_json::Value {
    serde_json::json!({
        "name": cookie.name(),
        "value": cookie.value(),
        "domain": cookie.domain(),
        "path": cookie.path(),
        "secure": cookie.secure().unwrap_or(false),
        "httpOnly": cookie.http_only().unwrap_or(false),
        "expirationDate": cookie
            .expires_datetime()
            .map(cookie::time::OffsetDateTime::unix_timestamp),
    })
}

fn map_console_level(level: &ConsoleLogLevel) -> ConsoleLevel {
    match level {
        ConsoleLogLevel::Log | ConsoleLogLevel::Debug | ConsoleLogLevel::Dir => ConsoleLevel::Log,
        ConsoleLogLevel::Info => ConsoleLevel::Info,
        ConsoleLogLevel::Warn => ConsoleLevel::Warn,
        ConsoleLogLevel::Error | ConsoleLogLevel::Trace => ConsoleLevel::Error,
    }
}

fn format_devtools_value(value: &servo::JSValue) -> String {
    match value {
        servo::JSValue::Undefined => "undefined".to_owned(),
        servo::JSValue::Null => "null".to_owned(),
        servo::JSValue::Boolean(value) => value.to_string(),
        servo::JSValue::Number(value) => value.to_string(),
        servo::JSValue::String(value)
        | servo::JSValue::Element(value)
        | servo::JSValue::ShadowRoot(value)
        | servo::JSValue::Frame(value)
        | servo::JSValue::Window(value) => value.clone(),
        servo::JSValue::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(format_devtools_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        servo::JSValue::Object(values) => {
            let mut values = values
                .iter()
                .map(|(key, value)| format!("{key}: {}", format_devtools_value(value)))
                .collect::<Vec<_>>();
            values.sort_unstable();
            format!("{{{}}}", values.join(", "))
        }
    }
}

fn map_load_status(status: servo::LoadStatus) -> NavigationLoadStatus {
    match status {
        servo::LoadStatus::Started => NavigationLoadStatus::Started,
        servo::LoadStatus::HeadParsed => NavigationLoadStatus::HeadParsed,
        servo::LoadStatus::Complete => NavigationLoadStatus::Complete,
    }
}

fn permission_site(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return url.as_str().to_owned();
    };
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

fn map_network_connection_event(event: servo::NetworkConnectionEvent) -> NetworkTelemetryEvent {
    match event {
        servo::NetworkConnectionEvent::Connecting {
            destination,
            proxy,
            dns_route,
        } => NetworkTelemetryEvent::Connecting {
            destination,
            proxy,
            dns_route: map_dns_resolution_route(dns_route),
        },
        servo::NetworkConnectionEvent::Connected {
            destination,
            proxy,
            dns_route,
            tls_protocol,
            tls_cipher_suite,
            alpn_protocol,
            used_ech,
        } => NetworkTelemetryEvent::Connected {
            destination,
            proxy,
            dns_route: map_dns_resolution_route(dns_route),
            tls_protocol,
            tls_cipher_suite,
            alpn_protocol,
            used_ech,
        },
        servo::NetworkConnectionEvent::Failed {
            destination,
            proxy,
            dns_route,
            error,
        } => NetworkTelemetryEvent::Failed {
            destination,
            proxy,
            dns_route: map_dns_resolution_route(dns_route),
            error,
        },
    }
}

const fn map_dns_resolution_route(route: servo::DnsResolutionRoute) -> crate::DnsRoute {
    match route {
        servo::DnsResolutionRoute::System => crate::DnsRoute::System,
        servo::DnsResolutionRoute::Proxy => crate::DnsRoute::ViaProxy,
    }
}

impl PageRenderer for ServoRenderer {
    fn request_tab_screenshot(&mut self, tab_id: TabId) -> Result<(), RenderError> {
        ServoRenderer::request_tab_screenshot(self, tab_id)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn take_tab_screenshots(&mut self) -> Vec<(TabId, Result<Vec<u8>, RenderError>)> {
        ServoRenderer::take_tab_screenshots(self)
    }

    fn configure_tab(
        &mut self,
        tab_id: TabId,
        container_id: ContainerId,
        ephemeral: bool,
    ) -> Result<(), RenderError> {
        ServoRenderer::configure_tab(self, tab_id, container_id, ephemeral)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn install_extension_scripts(
        &mut self,
        scripts: &[ExtensionInjection],
    ) -> Result<(), RenderError> {
        ServoRenderer::install_extension_scripts(self, scripts)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn install_extension_scripts_for_tab(
        &mut self,
        tab_id: TabId,
        scripts: &[ExtensionInjection],
    ) -> Result<(), RenderError> {
        ServoRenderer::install_extension_scripts_for_tab(self, tab_id, scripts)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn install_extension_resources(
        &mut self,
        resources: &[ExtensionResource],
    ) -> Result<(), RenderError> {
        ServoRenderer::install_extension_resources(self, resources)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn uninstall_extension_resources(&mut self, extension_id: &str) -> Result<(), RenderError> {
        ServoRenderer::uninstall_extension_resources(self, extension_id)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn install_extension_background(
        &mut self,
        extension_id: &str,
        manifest: &ExtensionManifest,
        script: &str,
        service_worker: bool,
        script_paths: &[String],
        storage: &ExtensionStorage,
    ) -> Result<(), RenderError> {
        ServoRenderer::install_extension_background(
            self,
            extension_id,
            manifest,
            script,
            service_worker,
            script_paths,
            storage,
        )
        .map_err(|_| RenderError::BackendUnavailable)
    }

    fn dispatch_extension_event(&mut self, event: &ExtensionEvent) -> Result<(), RenderError> {
        ServoRenderer::dispatch_extension_event(self, event)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn request_extension_background_messages(&mut self) -> Result<(), RenderError> {
        ServoRenderer::request_extension_background_messages(self)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn uninstall_extension(&mut self, extension_id: &str) -> Result<(), RenderError> {
        self.uninstall_extension_script(extension_id);
        self.uninstall_extension_background(extension_id);
        self.uninstall_extension_resources(extension_id)
            .map_err(|_| RenderError::BackendUnavailable)?;
        Ok(())
    }

    fn request_extension_messages(&mut self, tab_id: TabId) -> Result<(), RenderError> {
        ServoRenderer::request_extension_messages(self, tab_id)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn dispatch_extension_message(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
        payload: &serde_json::Value,
    ) -> Result<(), RenderError> {
        ServoRenderer::dispatch_extension_message(self, tab_id, extension_id, payload)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn take_extension_messages(&mut self) -> Vec<ExtensionMessage> {
        ServoRenderer::take_extension_messages(self)
    }

    fn open_extension_popup(
        &mut self,
        extension_id: &str,
        manifest: &ExtensionManifest,
        source: &str,
        resource_path: &str,
        storage: &ExtensionStorage,
    ) -> Result<(), RenderError> {
        ServoRenderer::open_extension_popup(
            self,
            extension_id,
            manifest,
            source,
            resource_path,
            storage,
        )
        .map_err(|_| RenderError::BackendUnavailable)
    }

    fn execute_extension_script(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
        source: &str,
    ) -> Result<(), RenderError> {
        ServoRenderer::execute_extension_script(self, tab_id, extension_id, source)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn execute_extension_script_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
        source: &str,
    ) -> Result<(), RenderError> {
        ServoRenderer::execute_extension_script_target(
            self,
            tab_id,
            frame_handle,
            extension_id,
            source,
        )
        .map_err(|_| RenderError::BackendUnavailable)
    }

    fn insert_extension_css(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
        source: &str,
    ) -> Result<(), RenderError> {
        ServoRenderer::insert_extension_css(self, tab_id, extension_id, source)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn insert_extension_css_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
        source: &str,
    ) -> Result<(), RenderError> {
        ServoRenderer::insert_extension_css_target(self, tab_id, frame_handle, extension_id, source)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn remove_extension_css(
        &mut self,
        tab_id: TabId,
        extension_id: &str,
    ) -> Result<(), RenderError> {
        ServoRenderer::remove_extension_css(self, tab_id, extension_id)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn remove_extension_css_target(
        &mut self,
        tab_id: TabId,
        frame_handle: Option<u64>,
        extension_id: &str,
    ) -> Result<(), RenderError> {
        ServoRenderer::remove_extension_css_target(self, tab_id, frame_handle, extension_id)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn take_extension_frame_tree_events(
        &mut self,
    ) -> Vec<(TabId, Vec<(u64, Option<u64>, String)>)> {
        ServoRenderer::take_extension_frame_tree_events(self)
    }

    fn extension_cookie_operation(
        &mut self,
        method: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, RenderError> {
        ServoRenderer::extension_cookie_operation(self, method, arguments)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn set_extension_blocking_patterns(&mut self, patterns: &[String]) {
        ServoRenderer::set_extension_blocking_patterns(self, patterns);
    }

    fn set_web_request_blocking_handler(&mut self, handler: Arc<dyn WebRequestBlockingHandler>) {
        ServoRenderer::set_web_request_blocking_handler(self, handler);
    }

    fn set_tab_throttled(&mut self, tab_id: TabId, throttled: bool) -> Result<(), RenderError> {
        ServoRenderer::set_tab_throttled(self, tab_id, throttled)
            .map_err(|_| RenderError::BackendUnavailable)
    }

    fn load(&mut self, request: &NavigationRequest) -> Result<(), RenderError> {
        let transport_url = if request.url.scheme() == "umc" {
            crate::umc_transport_url(&request.url).map_err(|_| RenderError::BackendUnavailable)?
        } else {
            request.url.clone()
        };
        let newly_created = !self.webviews.contains_key(&request.tab_id);
        if newly_created {
            self.ensure_webview_with_url(request.tab_id, transport_url.clone());
        }
        self.show_tab(request.tab_id);
        if !newly_created {
            let webview = self
                .webviews
                .get(&request.tab_id)
                .expect("webview is created by show_tab");
            if webview.url().is_some() {
                webview.load(transport_url);
            } else {
                self.pending_tab_loads.insert(request.tab_id, transport_url);
            }
        }
        self.servo.spin_event_loop();
        Ok(())
    }

    fn reload(&mut self, request: &NavigationRequest) -> Result<(), RenderError> {
        self.show_tab(request.tab_id);
        self.webviews
            .get(&request.tab_id)
            .expect("webview is created by show_tab")
            .reload();
        self.servo.spin_event_loop();
        Ok(())
    }

    fn activate(&mut self, tab_id: TabId) -> Result<(), RenderError> {
        self.show_tab(tab_id);
        Ok(())
    }

    fn release(&mut self, tab_id: TabId) -> Result<(), RenderError> {
        if let Some(webview) = self.webviews.remove(&tab_id) {
            webview.hide();
        }
        self.page_rendering_contexts.remove(&tab_id);
        self.pending_tab_loads.remove(&tab_id);
        self.content_rects.borrow_mut().remove(&tab_id);
        self.tab_content_managers.remove(&tab_id);
        self.extension_scripts.remove(&tab_id);
        self.tab_containers.remove(&tab_id);
        if self.active_tab == Some(tab_id) {
            self.active_tab = None;
        }
        Ok(())
    }
}

impl Drop for ServoRenderer {
    fn drop(&mut self) {
        servo::set_network_observer(None);
    }
}

#[cfg(test)]
mod tests {
    // Exact comparisons against compile-time constants are intentional.
    #![allow(clippy::float_cmp)]
    use super::{
        auxiliary_eviction_range, enqueue_media_session_event, map_load_status,
        media_session_event_kind, nomad_preferences, privacy_script, stabilize_wheel_axes,
        stepped_page_zoom, MediaSessionEventKind, NavigationLoadStatus, PrivacyMode, PrivacyPolicy,
    };

    #[test]
    fn wheel_axis_stabilization_removes_only_minor_cross_axis_noise() {
        assert_eq!(stabilize_wheel_axes(0.7, 18.0), (0.0, 18.0));
        assert_eq!(stabilize_wheel_axes(18.0, 0.7), (18.0, 0.0));
        assert_eq!(stabilize_wheel_axes(8.0, 12.0), (8.0, 12.0));
    }

    #[test]
    fn auxiliary_eviction_keeps_registry_within_bound() {
        // Below the cap nothing is evicted.
        assert_eq!(auxiliary_eviction_range(0, 8), 0..0);
        assert_eq!(auxiliary_eviction_range(7, 8), 0..0);
        // At the cap exactly one (the oldest) is evicted per new popup.
        assert_eq!(auxiliary_eviction_range(8, 8), 0..1);
        assert_eq!(auxiliary_eviction_range(9, 8), 0..2);
        assert_eq!(auxiliary_eviction_range(12, 8), 0..5);
        // Degenerate zero cap evicts everything so the push stays bounded.
        assert_eq!(auxiliary_eviction_range(3, 0), 0..3);
    }

    #[test]
    fn page_zoom_uses_stable_browser_steps() {
        assert_eq!(stepped_page_zoom(1.0, true), 1.1);
        assert_eq!(stepped_page_zoom(1.0, false), 0.9);
        assert_eq!(stepped_page_zoom(1.1, true), 1.25);
        assert_eq!(stepped_page_zoom(1.1, false), 1.0);
        assert_eq!(stepped_page_zoom(5.0, true), 5.0);
        assert_eq!(stepped_page_zoom(0.25, false), 0.25);
    }

    #[test]
    fn nomad_preferences_enable_browser_core_capabilities() {
        let preferences = nomad_preferences();

        assert!(preferences.dom_adoptedstylesheet_enabled);
        assert!(preferences.dom_allow_preloading_module_descendants);
        assert!(preferences.dom_async_clipboard_enabled);
        assert!(preferences.dom_canvas_capture_enabled);
        assert!(preferences.dom_canvas_text_enabled);
        assert!(preferences.dom_composition_event_enabled);
        assert!(preferences.dom_cookiestore_enabled);
        assert!(preferences.dom_credential_management_enabled);
        assert!(preferences.dom_entries_api_enabled);
        assert!(preferences.dom_indexeddb_enabled);
        assert!(preferences.dom_intersection_observer_enabled);
        assert!(preferences.dom_navigator_protocol_handlers_enabled);
        assert!(preferences.dom_offscreen_canvas_enabled);
        assert!(preferences.dom_permissions_enabled);
        assert!(preferences.dom_sanitizer_enabled);
        assert!(preferences.dom_serviceworker_enabled);
        assert!(preferences.dom_storage_manager_api_enabled);
        assert!(preferences.dom_worklet_enabled);
        assert!(preferences.dom_visual_viewport_enabled);
        assert!(!preferences.dom_web_animations_enabled);
        assert!(preferences.dom_webgpu_enabled);
        assert!(preferences.dom_webgl2_enabled);
        assert!(preferences.dom_webrtc_enabled);
        assert!(preferences.dom_webrtc_transceiver_enabled);
        assert_eq!(
            preferences.media_glvideo_enabled,
            cfg!(feature = "media-gstreamer")
        );
        assert!(preferences.layout_columns_enabled);
        assert!(preferences.layout_container_queries_enabled);
        assert!(preferences.layout_css_alpha_color_function_enabled);
        assert!(preferences.layout_css_attr_enabled);
        assert!(preferences.layout_css_ellipse_corners_enabled);
        assert!(preferences.layout_css_progress_function_enabled);
        assert!(preferences.layout_grid_enabled);
        assert!(preferences.layout_variable_fonts_enabled);
        assert!(preferences.layout_writing_mode_enabled);
        assert!(preferences.largest_contentful_paint_enabled);
        assert!(preferences.accessibility_enabled);
    }

    #[test]
    fn webrtc_privacy_controls_disable_renderer_surface_in_hardened_and_private_modes() {
        for mode in [
            PrivacyMode::Standard,
            PrivacyMode::Hardened,
            PrivacyMode::Private,
        ] {
            let policy = PrivacyPolicy::for_mode(mode);
            let mut preferences = nomad_preferences();
            preferences.dom_webrtc_enabled = !policy.block_webrtc();
            preferences.dom_webrtc_transceiver_enabled = !policy.block_webrtc();
            let script = privacy_script(policy);
            if policy.block_webrtc() {
                assert!(!preferences.dom_webrtc_enabled);
                assert!(!preferences.dom_webrtc_transceiver_enabled);
                // The injected page script hides RTCPeerConnection and device
                // enumeration from page scripts.
                assert!(script.contains("RTCPeerConnection"));
                assert!(script.contains("mediaDevices"));
            } else {
                assert!(preferences.dom_webrtc_enabled);
                assert!(preferences.dom_webrtc_transceiver_enabled);
                assert!(!script.contains("RTCPeerConnection"));
            }
        }
    }

    #[test]
    fn load_status_mapping_preserves_servo_milestones() {
        assert_eq!(
            map_load_status(servo::LoadStatus::Started),
            NavigationLoadStatus::Started
        );
        assert_eq!(
            map_load_status(servo::LoadStatus::HeadParsed),
            NavigationLoadStatus::HeadParsed
        );
        assert_eq!(
            map_load_status(servo::LoadStatus::Complete),
            NavigationLoadStatus::Complete
        );
    }

    #[test]
    fn media_session_events_have_stable_coalescing_kinds() {
        assert_eq!(
            media_session_event_kind(&servo::MediaSessionEvent::SetMetadata(
                servo::MediaMetadata::new("track".to_owned()),
            )),
            MediaSessionEventKind::Metadata
        );
        assert_eq!(
            media_session_event_kind(&servo::MediaSessionEvent::PlaybackStateChange(
                servo::MediaSessionPlaybackState::Playing,
            )),
            MediaSessionEventKind::PlaybackState
        );
        assert_eq!(
            media_session_event_kind(&servo::MediaSessionEvent::SetPositionState(
                servo::MediaPositionState::new(120.0, 1.0, 12.0),
            )),
            MediaSessionEventKind::PositionState
        );
    }

    #[test]
    fn media_session_position_updates_are_coalesced_per_tab() {
        let mut events = Vec::new();
        enqueue_media_session_event(
            &mut events,
            1_u8,
            servo::MediaSessionEvent::SetPositionState(servo::MediaPositionState::new(
                120.0, 1.0, 1.0,
            )),
        );
        enqueue_media_session_event(
            &mut events,
            2_u8,
            servo::MediaSessionEvent::SetPositionState(servo::MediaPositionState::new(
                90.0, 1.0, 2.0,
            )),
        );
        enqueue_media_session_event(
            &mut events,
            1_u8,
            servo::MediaSessionEvent::SetPositionState(servo::MediaPositionState::new(
                120.0, 1.0, 3.0,
            )),
        );

        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0].1,
            servo::MediaSessionEvent::SetPositionState(ref state) if state.position == 3.0
        ));
    }

    #[test]
    fn privacy_script_adds_hardened_readback_protection_only_when_requested() {
        let standard = privacy_script(PrivacyPolicy::for_mode(PrivacyMode::Standard));
        let hardened = privacy_script(PrivacyPolicy::for_mode(PrivacyMode::Hardened));

        assert!(!standard.contains("RTCPeerConnection"));
        assert!(!standard.contains("WEBGL_debug_renderer_info"));
        assert!(hardened.contains("RTCPeerConnection"));
        assert!(hardened.contains("WEBGL_debug_renderer_info"));
        assert!(hardened.contains("timeZone: \"UTC\""));
    }
}
