use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use egui::{CentralPanel, Key, PaintCallback, Panel, ProgressBar, TextEdit};
use egui_glow::{CallbackFn, EguiGlow};
use euclid::{Point2D, Rect, Size2D};
use image::load_from_memory;
use nomad_core::Switches;
use nomad_engine::{
    classify_autofill_field, filter_console_entries, AutofillFieldDescriptor, AutofillFieldKind,
    BookmarkFolderId, BookmarkId, ConsoleLevel, ContainerId, CustomResolverProtocol,
    DevToolsDomNode, DownloadState, MediaSessionActionType, MediaSessionEvent,
    MediaSessionPlaybackState, MemoryMode, PermissionDecision, PermissionPromptId,
    ResolverLookupStatus, ResolverMode, ResolverPath, ResolverSettings, ServoError, ServoRenderer,
    SplitOrientation, SplitPaneId, TabId, TabLifecycle, TabSnapshot, TranslationLanguage,
    UmcResourceInfo, UpdateChannel, WorkspaceId,
};
use nomad_shell::{
    BrowserSettings, PrivacyMode, ShellState, TabGroupInfo, UniversalSuggestion,
    UniversalSuggestionKind, UniversalTarget,
};
use url::Url;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, EventLoopProxy};
use winit::window::Window;

#[derive(Default)]
struct BackdropBlurRenderer {
    program: Option<glow::Program>,
    vao: Option<glow::VertexArray>,
    source: Option<glow::Texture>,
    intermediate: Option<glow::Texture>,
    framebuffer: Option<glow::Framebuffer>,
    size: (i32, i32),
}
// Zen's shell is deliberately compact: a narrow vertical toolbox, small
// separations between surfaces, and macOS-sized radii rather than oversized
// pills. Chrome uses a fixed logical-point scale so resizing a window changes
// available page space without resizing controls or text.
pub(crate) const CHROME_SCALE: f32 = 0.60;
pub(crate) const ICON_VISUAL_SCALE: f32 = 1.0;

/// Single source of truth for Nomad's fixed chrome geometry and type sizes.
///
/// Every value is a design-space logical point. Drawing code consumes these
/// values through `DesignGeometry`, which multiplies them by `CHROME_SCALE`;
/// window size, display scale, and page zoom never mutate them. Positions are
/// measured from the sidebar's left edge unless noted. Changing a value here
/// changes the rendered chrome everywhere it is used.
///
/// Exception: `address::SUGGESTIONS_*`, `extensions_menu`, and
/// `suggestions` describe egui popup/overlay surfaces, which egui draws in
/// unscaled logical screen points rather than through `DesignGeometry`.
pub(crate) mod layout {
    /// Sidebar shell width and the fixed viewport gutters around the page.
    pub const SIDEBAR_WIDTH: f32 = 420.0;
    pub const CONTENT_LEFT_INSET: f32 = 0.0;
    pub const CONTENT_TOP_INSET: f32 = address::ROW_TOP;
    pub const CONTENT_RIGHT_INSET: f32 = 12.0;
    pub const CONTENT_BOTTOM_INSET: f32 = 12.0;
    /// Horizontal padding inside the sidebar toolbox; also the popup margin.
    pub const TOOLBOX_PADDING: f32 = 16.0;

    /// Corner radius tokens in design points, drawn scaled.
    pub mod radius {
        /// Outer browser shell.
        pub const SHELL: f32 = 27.0;
        /// Toolbar pills and the extensions menu.
        pub const TOOLBAR: f32 = 20.0;
        /// Outer shell and page viewport corners.
        pub const CONTENT: f32 = 20.0;
        /// Tab rows, icon hover plates, popups, and the global style.
        pub const ROW: f32 = 20.0;
        /// Bookmark tabs on the content strip.
        pub const BOOKMARK_TAB: f32 = 20.0;
        /// Workspace dots at the bottom of the sidebar.
        pub const WORKSPACE_DOT: f32 = 8.0;
    }

    /// Text sizes in design points, drawn scaled.
    pub mod type_scale {
        pub const ADDRESS: f32 = 16.0;
        pub const TAB: f32 = 14.0;
        pub const BOOKMARK_TAB: f32 = 13.0;
    }

    /// Toolbar (nav) row pinned to the top of the sidebar.
    pub mod nav {
        pub const ROW_TOP: f32 = 13.0;
        pub const ICON_WIDTH: f32 = 52.0;
        pub const ICON_HEIGHT: f32 = 52.0;
        pub const MENU_X: f32 = 158.0;
        pub const BACK_X: f32 = 220.0;
        pub const FORWARD_X: f32 = 280.0;
        pub const RELOAD_X: f32 = 345.0;
        pub const RELOAD_WIDTH: f32 = 52.0;
        /// Asset boxes: layout glyph, back/forward arrows, reload glyph.
        pub const LAYOUT_ICON_X: f32 = 171.0;
        pub const LAYOUT_ICON_Y: f32 = 26.0;
        pub const LAYOUT_ICON_SIZE: f32 = 24.0;
        pub const ARROW_X_BACK: f32 = 234.25;
        pub const ARROW_X_FORWARD: f32 = 294.25;
        pub const ARROW_Y: f32 = 29.0;
        pub const ARROW_WIDTH: f32 = 22.5;
        pub const ARROW_HEIGHT: f32 = 18.0;
        pub const RELOAD_ICON_X: f32 = 354.75;
        pub const RELOAD_ICON_Y: f32 = 24.75;
        pub const RELOAD_ICON_SIZE: f32 = 26.5;
    }

    /// Search/address row at the sidebar top.
    pub mod address {
        pub const ROW_TOP: f32 = 74.0;
        pub const ROW_HEIGHT: f32 = 62.0;
        pub const FIELD_X: f32 = 40.0;
        /// Vertical offset of the suggestion popup below the address row.
        pub const SUGGESTIONS_OFFSET: f32 = 70.0;
        /// Popup width reduction from the sidebar width (both padding edges).
        pub const SUGGESTIONS_INSET: f32 = 2.0 * super::TOOLBOX_PADDING;
        pub const SUGGESTIONS_MARGIN: f32 = 6.0;
        pub const SUGGESTIONS_MAX_ITEMS: usize = 6;
        /// Sidebar-relative left edge of the context menu on tab rows.
        pub const CONTEXT_MENU_WIDTH: f32 = 180.0;
    }

    /// Tab group header rows interleaved with the tab list.
    pub mod tab_groups {
        pub const HEADER_HEIGHT: f32 = 26.0;
        pub const HEADER_PITCH: f32 = 32.0;
        pub const CARET_X: f32 = 20.0;
        pub const DOT_CENTER_X: f32 = 34.0;
        pub const DOT_SIZE: f32 = 10.0;
        pub const LABEL_X: f32 = 46.0;
        pub const COUNT_INSET: f32 = 20.0;
    }

    /// Split-view pane overlays inside the content viewport.
    pub mod split_pane {
        pub const ACTIVE_STROKE_WIDTH: f32 = 2.0;
        pub const CLOSE_SIZE: f32 = 26.0;
        pub const CLOSE_INSET: f32 = 8.0;
    }

    /// Vertical tab list inside the sidebar.
    pub mod tab_list {
        pub const LIST_TOP: f32 = 156.0;
        pub const ROW_PITCH: f32 = 67.0;
        pub const ROW_HEIGHT: f32 = 52.0;
        pub const ICON_X: f32 = 33.0;
        pub const ICON_SIZE: f32 = 32.0;
        pub const ICON_OFFSET: f32 = 10.0;
        pub const WIDE_ICON_WIDTH: f32 = 32.0;
        pub const WIDE_ICON_HEIGHT: f32 = 22.0;
        pub const WIDE_ICON_OFFSET: f32 = 15.0;
        pub const FALLBACK_CENTER_X: f32 = 49.0;
        pub const LABEL_X: f32 = 80.0;
        /// Vertical center of the fallback glyph and the row label.
        pub const CONTENT_CENTER_OFFSET: f32 = 26.0;
        pub const CLOSE_SIZE: f32 = 40.0;
        pub const CLOSE_OFFSET: f32 = 6.0;
        /// Horizontal center chosen so visual icon has equal top, bottom, and right spacing.
        pub const CLOSE_CENTER_X: f32 = 378.0;
        /// Pre-opacity-scale half extent; renders about two logical pixels larger than before.
        pub const CLOSE_ICON_HALF_EXTENT: f32 = 7.75;
        /// Center x of the audio playback indicator, left of the close button.
        pub const AUDIO_CENTER_X: f32 = 281.0;
        /// Small color dot marking group membership, left of the favicon.
        pub const GROUP_DOT_CENTER_X: f32 = 17.0;
        pub const GROUP_DOT_SIZE: f32 = 8.0;
    }

    /// Settings surface spacing tokens, logical points (unscaled).
    pub mod settings {
        /// Gap between cards and around section separators.
        pub const SPACE: f32 = 10.0;
        /// Gap between list items inside a section.
        pub const LIST_SPACE: f32 = 8.0;
    }

    /// Bottom control bar inside the sidebar.
    pub mod bottom_bar {
        pub const MARGIN: f32 = 40.0;
        pub const CONTROL_INSET: f32 = 38.0;
        pub const HIT_SIZE: f32 = 48.0;
        pub const SETTINGS_WIDTH: f32 = 26.43;
        pub const SETTINGS_HEIGHT: f32 = 24.40;
        pub const DOWNLOAD_SIZE: f32 = 26.5;
        pub const WORKSPACE_DOT_SIZE: f32 = 28.0;
        pub const WORKSPACE_DOT_PITCH: f32 = 32.0;
        pub const WORKSPACE_DOT_RADIUS: f32 = 3.0;
        pub const WORKSPACE_DOT_RADIUS_ACTIVE: f32 = 3.5;
        pub const WORKSPACE_MAX_DOTS: usize = 7;
    }

    /// Bookmark tab strip across the top of the content area.
    pub mod bookmark_strip {
        pub const STRIP_TOP: f32 = 17.0;
        pub const TAB_PITCH: f32 = 135.0;
        pub const TAB_WIDTH: f32 = 120.0;
        pub const TAB_HEIGHT: f32 = 42.0;
        pub const ICON_CENTER_OFFSET: [f32; 2] = [21.5, 21.0];
        pub const WIDE_ICON_SIZE: [f32; 2] = [25.0, 17.0];
        pub const ICON_SIZE: [f32; 2] = [25.0, 25.0];
        pub const FALLBACK_ICON_SCALE: f32 = 0.82;
        /// Title clip rectangle relative to each tab.
        pub const TEXT_CLIP_MIN: [f32; 2] = [46.0, 3.0];
        pub const TEXT_CLIP_MAX: [f32; 2] = [116.0, 39.0];
        pub const TEXT_OFFSET: [f32; 2] = [46.0, 21.0];
        /// Window-drag corridor: gap after the last tab, top, right margin,
        /// and bottom edge in design points.
        pub const DRAG_LEADING_GAP: f32 = 8.0;
        pub const DRAG_TOP: f32 = 8.0;
        pub const DRAG_RIGHT_MARGIN: f32 = 12.0;
        pub const DRAG_BOTTOM: f32 = 67.0;
    }

    /// Extensions (more) menu anchored below the toolbar.
    pub mod extensions_menu {
        pub const POS_X: f32 = 146.0;
        pub const POS_Y: f32 = super::CONTENT_TOP_INSET;
        pub const WIDTH: f32 = 286.0;
        pub const BUTTON_HEIGHT: f32 = 34.0;
    }

    /// Universal suggestion rows (address popup, command palette), logical
    /// points (unscaled).
    pub mod suggestions {
        pub const ITEM_HEIGHT: f32 = 44.0;
        pub const HOVER_RADIUS: f32 = 10.0;
        pub const PANEL_RADIUS: f32 = 16.0;
    }
}

const AUTOCOMPLETE_DEBOUNCE: Duration = Duration::from_millis(180);
const AUTOCOMPLETE_LIMIT: usize = 5;
const FAVICON_LIMIT_BYTES: u64 = 2 * 1024 * 1024;

struct AutocompleteResult {
    query: String,
    suggestions: Vec<String>,
}

struct FaviconResult {
    host: String,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct PendingChromeTooltip {
    id: egui::Id,
    anchor: egui::Rect,
    text: &'static str,
}

use layout::radius::{
    CONTENT as CONTENT_RADIUS, ROW as ROW_RADIUS, SHELL as SHELL_RADIUS, TOOLBAR as TOOLBAR_RADIUS,
};
use layout::{
    CONTENT_BOTTOM_INSET, CONTENT_LEFT_INSET, CONTENT_RIGHT_INSET, CONTENT_TOP_INSET,
    SIDEBAR_WIDTH, TOOLBOX_PADDING,
};

fn shell_background() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(29, 29, 29, 128)
}

fn chrome_surface() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 20)
}

fn content_surface() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(217, 217, 217, 128)
}

fn is_unopened_tab(url: Option<&Url>) -> bool {
    url.is_none_or(|url| url.as_str() == "about:blank")
}

fn should_show_sidebar_tab(tab_id: TabId, url: Option<&Url>, pending_tab: Option<TabId>) -> bool {
    !is_unopened_tab(url) || pending_tab == Some(tab_id)
}

fn idle_icon_tint() -> egui::Color32 {
    egui::Color32::from_white_alpha(204)
}

fn interactive_icon_tint(response: &egui::Response) -> egui::Color32 {
    if response.hovered() || response.has_focus() {
        egui::Color32::from_white_alpha(245)
    } else {
        idle_icon_tint()
    }
}

fn glass_border() -> egui::Stroke {
    egui::Stroke::new(
        1.0,
        egui::Color32::from_rgba_unmultiplied(255, 255, 255, 34),
    )
}

fn design_white() -> egui::Color32 {
    egui::Color32::from_white_alpha(232)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum DesignAsset {
    TrafficRed,
    TrafficYellow,
    TrafficGreen,
    Layout,
    Back,
    Forward,
    Download,
    Reddit,
    RedditTab,
    YouTube,
    Settings,
}

impl DesignAsset {
    const ALL: [Self; 11] = [
        Self::TrafficRed,
        Self::TrafficYellow,
        Self::TrafficGreen,
        Self::Layout,
        Self::Back,
        Self::Forward,
        Self::Download,
        Self::Reddit,
        Self::RedditTab,
        Self::YouTube,
        Self::Settings,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::TrafficRed => "figma-traffic-red",
            Self::TrafficYellow => "figma-traffic-yellow",
            Self::TrafficGreen => "figma-traffic-green",
            Self::Layout => "figma-layout",
            Self::Back => "figma-arrow",
            Self::Forward => "figma-arrow-forward",
            Self::Download => "figma-download",
            Self::Reddit => "figma-reddit",
            Self::RedditTab => "figma-reddit-tab",
            Self::YouTube => "figma-youtube",
            Self::Settings => "figma-settings",
        }
    }

    // Each arm embeds a different asset file; merging arms would change behavior.
    #[allow(clippy::match_same_arms)]
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::TrafficRed => include_bytes!("../assets/traffic-red-filled.png"),
            Self::TrafficYellow => include_bytes!("../assets/traffic-yellow.png"),
            Self::TrafficGreen => include_bytes!("../assets/traffic-green-filled.png"),
            Self::Layout => include_bytes!("../assets/figma-layout.svg"),
            Self::Back => include_bytes!("../assets/figma-back.svg"),
            Self::Forward => include_bytes!("../assets/figma-forward.svg"),
            Self::Download => include_bytes!("../assets/figma-download.svg"),
            Self::Reddit => include_bytes!("../assets/reddit.png"),
            Self::RedditTab => include_bytes!("../assets/reddit-tab.png"),
            Self::YouTube => include_bytes!("../assets/youtube.png"),
            Self::Settings => include_bytes!("../assets/figma-settings.svg"),
        }
    }
}

fn load_design_assets(context: &egui::Context) -> HashMap<DesignAsset, egui::TextureHandle> {
    // SVGs are rasterized at 4x for clean source edges, then shown as compact
    // toolbar glyphs. Mipmaps preserve those edges during heavy minification;
    // plain bilinear sampling produced the visibly stair-stepped icons.
    let vector_texture_options =
        egui::TextureOptions::LINEAR.with_mipmap_mode(Some(egui::TextureFilter::Linear));
    DesignAsset::ALL
        .into_iter()
        .filter_map(|asset| {
            let color_image = decode_design_asset(asset.bytes())?;
            Some((
                asset,
                context.load_texture(asset.name(), color_image, vector_texture_options),
            ))
        })
        .collect()
}

// SVG raster dimensions are small positive f32 sizes; `ceil` before the u32
// cast keeps the value an exact integer, and u32 pixel sizes are bounded.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn decode_design_asset(bytes: &[u8]) -> Option<egui::ColorImage> {
    if bytes.starts_with(b"<svg") {
        let tree = resvg::usvg::Tree::from_data(bytes, &resvg::usvg::Options::default()).ok()?;
        let source_size = tree.size();
        let width = (source_size.width() * 4.0).ceil() as u32;
        let height = (source_size.height() * 4.0).ceil() as u32;
        let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)?;
        let transform = resvg::tiny_skia::Transform::from_scale(4.0, 4.0);
        resvg::render(&tree, transform, &mut pixmap.as_mut());
        return Some(egui::ColorImage::from_rgba_premultiplied(
            [width as usize, height as usize],
            pixmap.data(),
        ));
    }

    let image = load_from_memory(bytes).ok()?.to_rgba8();
    Some(egui::ColorImage::from_rgba_unmultiplied(
        [image.width() as usize, image.height() as usize],
        image.as_raw(),
    ))
}

#[derive(Clone, Copy, Debug)]
struct DesignGeometry {
    scale: f32,
    sidebar_width: f32,
}

impl DesignGeometry {
    fn from_bounds(_bounds: egui::Rect) -> Self {
        let scale = CHROME_SCALE;
        Self {
            scale,
            sidebar_width: SIDEBAR_WIDTH * scale,
        }
    }

    fn point(self, x: f32, y: f32) -> egui::Pos2 {
        egui::pos2(x * self.scale, y * self.scale)
    }

    fn size(self, width: f32, height: f32) -> egui::Vec2 {
        egui::vec2(width * self.scale, height * self.scale)
    }

    fn rect(self, x: f32, y: f32, width: f32, height: f32) -> egui::Rect {
        egui::Rect::from_min_size(self.point(x, y), self.size(width, height))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChromePanel {
    Downloads,
    History,
    Memory,
    Privacy,
    Bookmarks,
    Settings,
    Permissions,
    Workspaces,
}

/// One rendered row in the sidebar tab list: a tab, or a group header.
#[derive(Clone, Copy)]
enum SidebarRow<'a> {
    Tab(&'a TabSnapshot),
    Group(&'a TabGroupInfo),
}

#[derive(Debug)]
pub enum ChromeAction {
    Quit,
    OpenSettings(SettingsSection),
    NavigatePending {
        tab_id: TabId,
        address: String,
    },
    NavigateInNewTab(String),
    OpenUniversal(UniversalTarget),
    OpenUniversalInNewTab(UniversalTarget),
    CreateContainer {
        name: String,
        ephemeral: bool,
    },
    AssignActiveContainer(ContainerId),
    GoBack,
    GoForward,
    SelectTab(TabId),
    CreateWorkspace(String),
    SelectWorkspace(WorkspaceId),
    SetWorkspaceResolver {
        workspace: WorkspaceId,
        resolver: Option<ResolverSettings>,
    },
    SplitActive(SplitOrientation),
    ActivateSplitPane(SplitPaneId),
    CloseSplitPane(SplitPaneId),
    MoveTabToSplit {
        tab: TabId,
        orientation: SplitOrientation,
    },
    ReorderTab {
        tab: TabId,
        anchor: TabId,
    },
    CreateTabGroup {
        tab: TabId,
    },
    AddTabToGroup {
        tab: TabId,
        group_id: u64,
    },
    RemoveTabFromGroup(TabId),
    SetTabGroupCollapsed {
        group_id: u64,
        collapsed: bool,
    },
    UngroupTabGroup(u64),
    ToggleReader,
    OpenDevTools,
    ClearDevTools,
    EvaluateDevTools(String),
    Reload,
    ZoomIn,
    ZoomOut,
    ResetZoom,
    TranslateText {
        source: TranslationLanguage,
        target: TranslationLanguage,
        text: String,
    },
    CloseTab(TabId),
    RestoreSession,
    StartCleanSession,
    NavigateFromHistory(String),
    SetMemoryMode(MemoryMode),
    ReclaimMemory,
    SleepTab(TabId),
    WakeTab(TabId),
    ResumeTab(TabId),
    SuspendTab(TabId),
    SetTabPinned {
        id: TabId,
        pinned: bool,
    },
    SetTabKeepAlive {
        id: TabId,
        keep_alive: bool,
    },
    RetryDownload(nomad_engine::DownloadId),
    CancelDownload(nomad_engine::DownloadId),
    ToggleBookmark,
    OpenBookmark(BookmarkId),
    RemoveBookmark(BookmarkId),
    RenameBookmark {
        id: BookmarkId,
        title: String,
    },
    CreateBookmarkFolder(String),
    RenameBookmarkFolder {
        id: BookmarkFolderId,
        name: String,
    },
    RemoveBookmarkFolder(BookmarkFolderId),
    MoveBookmark {
        id: BookmarkId,
        folder_id: Option<BookmarkFolderId>,
    },
    ApplySettings(BrowserSettings),
    SetupSyncKey,
    RecoverSyncKey(String),
    SyncNow,
    PullSync,
    ResolveSyncConflict {
        key: String,
        choice: nomad_engine::SyncConflictChoice,
    },
    RequestAutofill,
    FillSavedPassword(String),
    FillEnteredPassword {
        username: String,
        password: String,
    },
    SaveCredential {
        username: String,
        password: String,
    },
    SetRoute(Switches),
    ResolvePermission {
        id: PermissionPromptId,
        decision: PermissionDecision,
    },
    TriggerExtensionAction(String),
    ClearExtensionNotification(String),
    MediaSessionAction {
        tab_id: TabId,
        action: MediaSessionActionType,
    },
}

#[derive(Clone, Debug, Default)]
struct MediaSessionUiState {
    title: String,
    artist: String,
    album: String,
    playing: bool,
    position: Option<(f64, f64, f64)>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SettingsSection {
    #[default]
    General,
    Privacy,
    Sync,
    Advanced,
    Bookmarks,
    History,
    Downloads,
    Workspaces,
    Permissions,
    Autofill,
    Memory,
}

// Each bool is an independent UI surface toggle; grouping them into a flags
// struct would force mechanical renames across every accessor with no gain.
#[allow(clippy::struct_excessive_bools)]
pub struct Chrome {
    context: EguiGlow,
    design_assets: HashMap<DesignAsset, egui::TextureHandle>,
    downloads_visible: bool,
    history_visible: bool,
    history_query: String,
    memory_visible: bool,
    privacy_visible: bool,
    bookmarks_visible: bool,
    settings_visible: bool,
    settings_tab: Option<TabId>,
    settings_section: SettingsSection,
    settings_draft: BrowserSettings,
    /// Draft of the active workspace's resolver override while it is being
    /// edited in Settings → Workspaces; `None` while inheriting global.
    workspace_resolver_draft: Option<(WorkspaceId, ResolverSettings)>,
    sync_recovery_input: String,
    sync_recovery_phrase: Option<String>,
    autofill_visible: bool,
    autofill_username: String,
    autofill_password: String,
    autofill_tab: Option<TabId>,
    autofill_fields: Vec<AutofillFieldDescriptor>,
    permissions_visible: bool,
    workspaces_visible: bool,
    commands_visible: bool,
    more_visible: bool,
    search_input: String,
    pending_navigations: VecDeque<(TabId, String)>,
    submitted_tabs: HashSet<TabId>,
    address_query_active: bool,
    autocomplete_generation: Arc<AtomicU64>,
    autocomplete_sender: mpsc::Sender<AutocompleteResult>,
    autocomplete_receiver: mpsc::Receiver<AutocompleteResult>,
    web_suggestions: Vec<String>,
    selected_suggestion: Option<usize>,
    favicon_sender: mpsc::Sender<FaviconResult>,
    favicon_receiver: mpsc::Receiver<FaviconResult>,
    favicon_requested: HashSet<String>,
    favicon_textures: HashMap<String, egui::TextureHandle>,
    command_query: String,
    container_name: String,
    container_ephemeral: bool,
    devtools_visible: bool,
    devtools_console_input: String,
    devtools_console_filters: [bool; 4],
    reader_visible: bool,
    translation_visible: bool,
    translation_source: TranslationLanguage,
    translation_target: TranslationLanguage,
    translation_input: String,
    translation_output: Option<String>,
    translation_error: Option<String>,
    navigation_error: Option<String>,
    session_recovery_prompt: bool,
    bookmark_folder_name: String,
    bookmark_folder_rename_id: Option<BookmarkFolderId>,
    bookmark_folder_rename: String,
    bookmark_edit_id: Option<BookmarkId>,
    bookmark_edit_title: String,
    accessibility_updates: HashMap<TabId, Vec<egui::accesskit::TreeUpdate>>,
    media_sessions: HashMap<TabId, MediaSessionUiState>,
    last_reload_at: Option<Instant>,
    /// Tab whose full URL is temporarily shown in the sidebar after a double-click.
    revealed_tab_url: Option<TabId>,
    /// Last pushed chrome accessibility snapshot; rebuilt only on change.
    ax_signature: String,
    /// Chrome node most recently focused through assistive technology.
    ax_focus: Option<egui::accesskit::NodeId>,
    /// Last time the chrome subtree was pushed. Updates are dropped silently
    /// while no assistive technology is attached, so this re-pushes
    /// periodically to converge after late activation.
    ax_last_push: Instant,
    /// Document subtree IDs per tab, grafted under the chrome content node.
    web_graft: HashMap<TabId, egui::accesskit::TreeId>,
    backdrop_blur: Arc<Mutex<BackdropBlurRenderer>>,
}

fn render_devtools_dom_node(ui: &mut egui::Ui, node: &DevToolsDomNode) {
    let mut label = node.node_name.clone();
    if !node.attributes.is_empty() {
        label.push(' ');
        label.push_str(
            &node
                .attributes
                .iter()
                .take(8)
                .map(|(name, value)| format!("{name}=\"{value}\""))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if let Some(value) = &node.node_value {
        if !value.trim().is_empty() {
            label.push_str(": ");
            label.push_str(value.trim());
        }
    }
    if node.children.is_empty() {
        ui.label(label);
        return;
    }
    ui.collapsing(label, |ui| {
        for child in &node.children {
            render_devtools_dom_node(ui, child);
        }
    });
}

impl Chrome {
    #[allow(clippy::too_many_lines)]
    pub fn new(event_loop: &ActiveEventLoop, renderer: &ServoRenderer) -> Result<Self, ServoError> {
        renderer
            .make_window_current()
            .map_err(|error| ServoError::Native(format!("window context: {error}")))?;
        let context = EguiGlow::new(event_loop, renderer.glow_context(), None, None, false);
        let mut style = (*context.egui_ctx.global_style()).clone();
        style.visuals = egui::Visuals::dark();
        style.visuals.override_text_color = Some(design_white());
        style.visuals.panel_fill = egui::Color32::TRANSPARENT;
        // Popup surfaces paint their own tint after a GPU backdrop pass.
        style.visuals.window_fill = egui::Color32::TRANSPARENT;
        style.visuals.extreme_bg_color = egui::Color32::TRANSPARENT;
        style.visuals.text_edit_bg_color = Some(egui::Color32::TRANSPARENT);
        style.visuals.window_stroke = egui::Stroke::NONE;
        style.visuals.window_corner_radius = egui::CornerRadius::same(12);
        style.visuals.window_shadow = egui::epaint::Shadow::NONE;
        style.visuals.popup_shadow = egui::epaint::Shadow::NONE;
        style.visuals.menu_corner_radius = egui::CornerRadius::same(12);
        style.visuals.widgets.noninteractive.bg_fill = egui::Color32::TRANSPARENT;
        style.visuals.widgets.noninteractive.weak_bg_fill = egui::Color32::TRANSPARENT;
        style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, design_white());
        style.visuals.widgets.inactive.bg_fill = egui::Color32::TRANSPARENT;
        style.visuals.widgets.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
        style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, design_white());
        style.visuals.widgets.hovered.bg_fill =
            egui::Color32::from_rgba_unmultiplied(255, 255, 255, 25);
        style.visuals.widgets.hovered.weak_bg_fill =
            egui::Color32::from_rgba_unmultiplied(255, 255, 255, 25);
        style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, design_white());
        style.visuals.widgets.active.bg_fill =
            egui::Color32::from_rgba_unmultiplied(255, 255, 255, 38);
        style.visuals.widgets.active.weak_bg_fill =
            egui::Color32::from_rgba_unmultiplied(255, 255, 255, 38);
        style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, design_white());
        style.visuals.selection.bg_fill = egui::Color32::from_rgba_unmultiplied(255, 255, 255, 34);
        style.visuals.selection.stroke = egui::Stroke::new(1.0, design_white());
        style.visuals.text_cursor.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
        style.visuals.interact_cursor = Some(egui::CursorIcon::PointingHand);
        style.spacing.item_spacing = egui::vec2(7.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        context.egui_ctx.set_global_style(style);
        context
            .egui_ctx
            .options_mut(|options| options.zoom_with_keyboard = false);
        #[cfg(target_os = "macos")]
        if let Some((font_name, bytes)) = [
            ("sf-pro-text", "/Library/Fonts/SF-Pro-Text-Regular.otf"),
            ("sf-system", "/System/Library/Fonts/SFNS.ttf"),
        ]
        .into_iter()
        .find_map(|(name, path)| std::fs::read(path).ok().map(|bytes| (name, bytes)))
        {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                font_name.to_owned(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.insert(0, font_name.to_owned());
            }
            context.egui_ctx.set_fonts(fonts);
        } else {
            eprintln!("Nomad could not load SF Pro; using egui's proportional fallback");
        }
        let design_assets = load_design_assets(&context.egui_ctx);
        let (autocomplete_sender, autocomplete_receiver) = mpsc::channel();
        let (favicon_sender, favicon_receiver) = mpsc::channel();
        Ok(Self {
            context,
            design_assets,
            downloads_visible: false,
            history_visible: false,
            history_query: String::new(),
            memory_visible: false,
            workspace_resolver_draft: None,
            privacy_visible: false,
            bookmarks_visible: false,
            settings_visible: false,
            settings_tab: None,
            settings_section: SettingsSection::General,
            settings_draft: BrowserSettings::default(),
            sync_recovery_input: String::new(),
            sync_recovery_phrase: None,
            autofill_visible: false,
            autofill_username: String::new(),
            autofill_password: String::new(),
            autofill_tab: None,
            autofill_fields: Vec::new(),
            permissions_visible: false,
            workspaces_visible: false,
            commands_visible: false,
            more_visible: false,
            search_input: String::new(),
            pending_navigations: VecDeque::new(),
            submitted_tabs: HashSet::new(),
            address_query_active: false,
            autocomplete_generation: Arc::new(AtomicU64::new(0)),
            autocomplete_sender,
            autocomplete_receiver,
            web_suggestions: Vec::new(),
            selected_suggestion: None,
            favicon_sender,
            favicon_receiver,
            favicon_requested: HashSet::new(),
            favicon_textures: HashMap::new(),
            command_query: String::new(),
            container_name: String::new(),
            container_ephemeral: false,
            devtools_visible: false,
            devtools_console_input: String::new(),
            devtools_console_filters: [true; 4],
            reader_visible: false,
            translation_visible: false,
            translation_source: TranslationLanguage::Auto,
            translation_target: TranslationLanguage::English,
            translation_input: String::new(),
            translation_output: None,
            translation_error: None,
            navigation_error: None,
            session_recovery_prompt: false,
            bookmark_folder_name: String::new(),
            bookmark_folder_rename_id: None,
            bookmark_folder_rename: String::new(),
            bookmark_edit_id: None,
            bookmark_edit_title: String::new(),
            accessibility_updates: HashMap::new(),
            media_sessions: HashMap::new(),
            last_reload_at: None,
            revealed_tab_url: None,
            ax_signature: String::new(),
            ax_focus: None,
            ax_last_push: Instant::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap_or_else(Instant::now),
            web_graft: HashMap::new(),
            backdrop_blur: Arc::new(Mutex::new(BackdropBlurRenderer::default())),
        })
    }

    pub fn set_request_repaint_callback(
        &self,
        callback: impl Fn(egui::RequestRepaintInfo) + Send + Sync + 'static,
    ) {
        self.context.egui_ctx.set_request_repaint_callback(callback);
    }

    pub fn on_window_event(
        &mut self,
        window: &Window,
        event: &WindowEvent,
    ) -> egui_winit::EventResponse {
        self.context.on_window_event(window, event)
    }

    fn poll_remote_ui_resources(&mut self) {
        while let Ok(result) = self.autocomplete_receiver.try_recv() {
            if result.query == self.search_input.trim() {
                self.web_suggestions = result.suggestions;
                self.selected_suggestion = None;
            }
        }
        while let Ok(result) = self.favicon_receiver.try_recv() {
            if let Some(image) = decode_design_asset(&result.bytes) {
                let texture = self.context.egui_ctx.load_texture(
                    format!("favicon:{}", result.host),
                    image,
                    egui::TextureOptions::LINEAR
                        .with_mipmap_mode(Some(egui::TextureFilter::Linear)),
                );
                self.favicon_textures.insert(result.host, texture);
            }
        }
    }

    fn request_favicon(&mut self, url: &Url) {
        let Some(host) = favicon_host(url) else {
            return;
        };
        if self.favicon_textures.contains_key(&host) || !self.favicon_requested.insert(host.clone())
        {
            return;
        }
        let sender = self.favicon_sender.clone();
        let context = self.context.egui_ctx.clone();
        let source_url = url.clone();
        std::thread::spawn(move || {
            if let Some(bytes) = fetch_favicon(&source_url) {
                let _ = sender.send(FaviconResult { host, bytes });
                context.request_repaint();
            }
        });
    }

    #[must_use]
    pub fn blocks_page_pointer_input(&self) -> bool {
        self.downloads_visible
            || self.history_visible
            || self.memory_visible
            || self.privacy_visible
            || self.bookmarks_visible
            || self.settings_visible
            || self.autofill_visible
            || self.permissions_visible
            || self.workspaces_visible
            || self.commands_visible
            || self.more_visible
            || self.devtools_visible
            || self.reader_visible
            || self.translation_visible
            || self.navigation_error.is_some()
            || self.session_recovery_prompt
    }

    pub fn init_accessibility<T>(
        &mut self,
        event_loop: &ActiveEventLoop,
        window: &Window,
        event_loop_proxy: EventLoopProxy<T>,
    ) where
        T: From<egui_winit::accesskit_winit::Event> + Send + 'static,
    {
        self.context
            .egui_winit
            .init_accesskit(event_loop, window, event_loop_proxy);
    }

    pub fn on_accessibility_event(
        &mut self,
        event: egui_winit::accesskit_winit::Event,
    ) -> Option<egui::accesskit::ActionRequest> {
        match &event.window_event {
            egui_winit::accesskit_winit::WindowEvent::InitialTreeRequested => {
                eprintln!("Nomad AX diag: InitialTreeRequested");
                self.update_accessibility_tree(std::iter::once(initial_accessibility_tree()));
                None
            }
            egui_winit::accesskit_winit::WindowEvent::ActionRequested(request) => {
                eprintln!("Nomad AX diag: ActionRequested");
                let request = request.clone();
                if is_chrome_ax_node(request.target_node) {
                    // Handled by take_chrome_ax_action in native code.
                    return None;
                }
                page_accessibility_action(request)
            }
            egui_winit::accesskit_winit::WindowEvent::AccessibilityDeactivated => {
                eprintln!("Nomad AX diag: AccessibilityDeactivated");
                None
            }
        }
    }

    pub fn update_accessibility_tree(
        &mut self,
        updates: impl IntoIterator<Item = egui::accesskit::TreeUpdate>,
    ) {
        let Some(adapter) = self.context.egui_winit.accesskit.as_mut() else {
            eprintln!("Nomad AX diag: no adapter");
            return;
        };
        static PUSHES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = PUSHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < 5 || n % 50 == 0 {
            eprintln!("Nomad AX diag: update_accessibility_tree push #{n}");
        }
        for update in updates {
            adapter.update_if_active(|| update);
        }
    }

    pub fn update_accessibility_tree_for_tab(
        &mut self,
        active_tab: Option<TabId>,
        updates: impl IntoIterator<Item = (TabId, egui::accesskit::TreeUpdate)>,
    ) {
        for (tab_id, update) in updates {
            self.accessibility_updates
                .entry(tab_id)
                .or_default()
                .push(update);
        }

        let Some(active_tab) = active_tab else {
            return;
        };
        let Some(updates) = self.accessibility_updates.remove(&active_tab) else {
            return;
        };
        // Record the document subtree ID before pushing: the chrome content
        // node grafts this subtree, and the graft must exist first.
        for update in &updates {
            self.web_graft.insert(active_tab, update.tree_id);
        }
        let Some(adapter) = self.context.egui_winit.accesskit.as_mut() else {
            self.accessibility_updates.insert(active_tab, updates);
            return;
        };
        for update in updates {
            adapter.update_if_active(|| update);
        }
    }

    pub fn forget_accessibility_tab(&mut self, tab_id: TabId) {
        self.accessibility_updates.remove(&tab_id);
    }

    /// Assistive-technology action on browser chrome (toolbar, address field,
    /// tab list). Returns the action for native handling, or `None` when the
    /// request targets page content or an unsupported action.
    pub fn take_chrome_ax_action(
        &mut self,
        shell: &ShellState,
        event: &egui_winit::accesskit_winit::Event,
    ) -> Option<ChromeAxAction> {
        use egui::accesskit::Action;
        use egui_winit::accesskit_winit::WindowEvent;
        let WindowEvent::ActionRequested(request) = &event.window_event else {
            return None;
        };
        if !is_chrome_ax_node(request.target_node) {
            return None;
        }
        let node = request.target_node.0;
        match request.action {
            Action::Click => {
                if node == ax_node(AX_BACK) {
                    Some(ChromeAxAction::Back)
                } else if node == ax_node(AX_FORWARD) {
                    Some(ChromeAxAction::Forward)
                } else if node == ax_node(AX_RELOAD) {
                    Some(ChromeAxAction::Reload)
                } else if node == ax_node(AX_NEW_TAB) {
                    Some(ChromeAxAction::NewTab)
                } else {
                    shell.tabs().iter().find_map(|tab| {
                        (ax_tab_id(tab.id) == request.target_node)
                            .then_some(ChromeAxAction::ActivateTab(tab.id))
                    })
                }
            }
            Action::Focus => {
                self.ax_focus = Some(request.target_node);
                None
            }
            _ => None,
        }
    }

    /// Rebuild the chrome accessibility subtree when toolbar, address, tab, or
    /// focus state changed. Web content updates flow separately; both share
    /// the platform root with disjoint node ID ranges.
    pub fn push_chrome_accessibility(&mut self, shell: &ShellState) {
        let tabs: Vec<(TabId, String)> = shell
            .tabs()
            .iter()
            .map(|tab| {
                let label = tab
                    .url
                    .as_ref()
                    .map(|url| {
                        let host = url.host_str().unwrap_or_default();
                        let path = url.path();
                        let text = if path.is_empty() || path == "/" {
                            host.to_owned()
                        } else {
                            format!("{host}{path}")
                        };
                        text.chars().take(80).collect()
                    })
                    .unwrap_or_else(|| "New tab".to_owned());
                (tab.id, label)
            })
            .collect();
        let active = shell.active_tab();
        let address = active
            .and_then(|id| tabs.iter().find(|(tab_id, _)| *tab_id == id))
            .map(|(_, label)| label.clone())
            .unwrap_or_default();
        let graft = active.and_then(|id| self.web_graft.get(&id));
        let signature = format!(
            "{active:?}|{}|{}|{address}|{}|{:?}|{graft:?}",
            shell.can_go_back(),
            shell.can_go_forward(),
            tabs.iter()
                .map(|(id, label)| format!("{}={label}", id.get()))
                .collect::<Vec<_>>()
                .join(","),
            self.ax_focus.map(|node| node.0),
        );
        if signature == self.ax_signature && self.ax_last_push.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.ax_signature = signature;
        self.ax_last_push = Instant::now();
        eprintln!("Nomad AX diag: push chrome tree");

        let mut nodes = Vec::new();
        let mut root = egui::accesskit::Node::new(egui::accesskit::Role::Window);
        root.set_label("Nomad Browser");
        root.set_children(vec![
            ax_id(AX_TOOLBAR),
            ax_id(AX_TAB_LIST),
            ax_id(AX_CONTENT),
        ]);
        nodes.push((ax_id(AX_ROOT), root));

        let mut toolbar = egui::accesskit::Node::new(egui::accesskit::Role::Toolbar);
        toolbar.set_label("Browser toolbar");
        toolbar.set_children(vec![
            ax_id(AX_BACK),
            ax_id(AX_FORWARD),
            ax_id(AX_RELOAD),
            ax_id(AX_ADDRESS),
            ax_id(AX_NEW_TAB),
        ]);
        nodes.push((ax_id(AX_TOOLBAR), toolbar));

        nodes.push(button_node(AX_BACK, "Back", shell.can_go_back()));
        nodes.push(button_node(AX_FORWARD, "Forward", shell.can_go_forward()));
        nodes.push(button_node(AX_RELOAD, "Reload", true));

        let mut address_node = egui::accesskit::Node::new(egui::accesskit::Role::TextInput);
        address_node.set_label("Address");
        address_node.set_value(address);
        address_node.add_action(egui::accesskit::Action::Focus);
        nodes.push((ax_id(AX_ADDRESS), address_node));

        nodes.push(button_node(AX_NEW_TAB, "New tab", true));

        let mut tab_list = egui::accesskit::Node::new(egui::accesskit::Role::TabList);
        tab_list.set_label("Tabs");
        let tab_ids: Vec<egui::accesskit::NodeId> =
            tabs.iter().map(|(id, _)| ax_tab_id(*id)).collect();
        tab_list.set_children(tab_ids.clone());
        nodes.push((ax_id(AX_TAB_LIST), tab_list));

        for (tab_id, label) in &tabs {
            let mut tab = egui::accesskit::Node::new(egui::accesskit::Role::Tab);
            tab.set_label(label.clone());
            if Some(*tab_id) == active {
                tab.set_selected(true);
            }
            tab.add_action(egui::accesskit::Action::Click);
            tab.add_action(egui::accesskit::Action::Focus);
            nodes.push((ax_tab_id(*tab_id), tab));
        }

        // Graft the active tab's document subtree: the web updates keep
        // their Servo-assigned subtree ID, and this node points at it so
        // assistive technology can descend from chrome into page content.
        let mut content = egui::accesskit::Node::new(egui::accesskit::Role::GenericContainer);
        content.set_label("Page content");
        if let Some(tab_id) = active {
            if let Some(tree_id) = self.web_graft.get(&tab_id) {
                content.set_tree_id(*tree_id);
            }
        }
        nodes.push((ax_id(AX_CONTENT), content));

        eprintln!(
            "Nomad AX diag: chrome push tabs={} webq={}",
            tab_ids.len(),
            self.accessibility_updates
                .values()
                .map(Vec::len)
                .sum::<usize>()
        );
        let focus = self.ax_focus.unwrap_or(ax_id(AX_ROOT));
        self.update_accessibility_tree(std::iter::once(egui::accesskit::TreeUpdate {
            nodes,
            tree: Some(egui::accesskit::Tree::new(ax_id(AX_ROOT))),
            focus,
            tree_id: egui::accesskit::TreeId::ROOT,
        }));
    }

    pub fn update_media_session(&mut self, tab_id: TabId, event: MediaSessionEvent) {
        let state = self.media_sessions.entry(tab_id).or_default();
        match event {
            MediaSessionEvent::SetMetadata(metadata) => {
                state.title = metadata.title;
                state.artist = metadata.artist;
                state.album = metadata.album;
            }
            MediaSessionEvent::PlaybackStateChange(playback_state) => {
                state.playing = matches!(playback_state, MediaSessionPlaybackState::Playing);
            }
            MediaSessionEvent::SetPositionState(position) => {
                state.position =
                    Some((position.duration, position.playback_rate, position.position));
            }
        }
    }

    pub fn forget_media_session_tab(&mut self, tab_id: TabId) {
        self.media_sessions.remove(&tab_id);
    }

    pub fn show_settings_tab(
        &mut self,
        tab_id: TabId,
        section: SettingsSection,
        settings: &BrowserSettings,
    ) {
        self.settings_tab = Some(tab_id);
        self.settings_section = section;
        self.settings_draft = settings.clone();
        self.settings_visible = true;
    }

    pub fn forget_settings_tab(&mut self, tab_id: TabId) {
        if self.settings_tab == Some(tab_id) {
            self.settings_tab = None;
            self.settings_visible = false;
        }
        self.submitted_tabs.remove(&tab_id);
        self.pending_navigations
            .retain(|(pending_tab, _)| *pending_tab != tab_id);
    }

    pub fn queue_navigation(&mut self, tab_id: TabId, address: String) {
        self.submitted_tabs.insert(tab_id);
        self.pending_navigations.push_back((tab_id, address));
    }

    #[must_use]
    pub fn navigation_pending_for(&self, tab_id: TabId) -> bool {
        self.pending_navigations
            .iter()
            .any(|(pending_tab, _)| *pending_tab == tab_id)
    }

    // Chrome drawing casts bounded design constants (small positive f32
    // radii/sizes) to egui's integer types; truncation, sign loss, and
    // precision loss cannot occur for these values.
    // `update` renders the entire chrome inside one egui closure sharing ~45
    // mutable UI locals; beyond the separable shortcut block, extraction
    // would be a structural rewrite, not a lint cleanup.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::too_many_lines
    )]
    pub fn update(
        &mut self,
        window: &Window,
        renderer: &mut ServoRenderer,
        shell: &mut ShellState,
    ) -> Result<Option<ChromeAction>, ServoError> {
        renderer
            .make_window_current()
            .map_err(|error| ServoError::Native(format!("window context: {error}")))?;
        self.poll_remote_ui_resources();

        let mut action = None;
        let mut search_input = self.search_input.clone();
        let downloads_visible = self.downloads_visible;
        let history_visible = self.history_visible;
        let mut history_query = self.history_query.clone();
        let memory_visible = self.memory_visible;
        let mut privacy_visible = self.privacy_visible;
        let bookmarks_visible = self.bookmarks_visible;
        let active_settings_tab = shell.active_tab().filter(|tab_id| {
            shell
                .tab(*tab_id)
                .and_then(|tab| tab.url.as_ref())
                .is_some_and(|url| url.as_str() == "about:settings")
        });
        self.settings_tab = active_settings_tab;
        let mut settings_visible = active_settings_tab.is_some();
        let mut settings_section = self.settings_section;
        let mut settings_draft = self.settings_draft.clone();
        let mut workspace_resolver_draft = self.workspace_resolver_draft.clone();
        let mut sync_recovery_input = self.sync_recovery_input.clone();
        let sync_recovery_phrase = self.sync_recovery_phrase.clone();
        let mut autofill_visible = self.autofill_visible;
        let mut autofill_username = self.autofill_username.clone();
        let mut autofill_password = self.autofill_password.clone();
        let autofill_tab = self.autofill_tab;
        let autofill_fields = self.autofill_fields.clone();
        let permissions_visible = self.permissions_visible;
        let workspaces_visible = self.workspaces_visible;
        let mut commands_visible = self.commands_visible;
        let mut more_visible = self.more_visible;
        let mut address_query_active = self.address_query_active;
        let mut web_suggestions = self.web_suggestions.clone();
        let mut selected_suggestion = self.selected_suggestion;
        let mut command_query = self.command_query.clone();
        let mut container_name = self.container_name.clone();
        let mut container_ephemeral = self.container_ephemeral;
        let mut devtools_visible = self.devtools_visible;
        let mut devtools_console_input = self.devtools_console_input.clone();
        let mut devtools_console_filters = self.devtools_console_filters;
        let mut reader_visible = self.reader_visible;
        let translation_visible = self.translation_visible;
        let mut translation_source = self.translation_source;
        let mut translation_target = self.translation_target;
        let mut translation_input = self.translation_input.clone();
        let translation_output = self.translation_output.clone();
        let translation_error = self.translation_error.clone();
        let navigation_error = self.navigation_error.clone();
        let mut session_recovery_prompt = self.session_recovery_prompt;
        let mut bookmark_folder_name = self.bookmark_folder_name.clone();
        let mut bookmark_folder_rename_id = self.bookmark_folder_rename_id;
        let mut bookmark_folder_rename = self.bookmark_folder_rename.clone();
        let mut bookmark_edit_id = self.bookmark_edit_id;
        let mut bookmark_edit_title = self.bookmark_edit_title.clone();
        let mut page_paint_error = None;
        let mut address_suggestions = Vec::new();
        let command_suggestions = shell.command_suggestions(&command_query);
        let downloads = shell.downloads().to_vec();
        let history = shell.search_history(&history_query);
        let memory_diagnostics = shell.memory_diagnostics();
        let privacy_diagnostics = renderer.privacy_diagnostics();
        let network_route = renderer.network_route().clone();
        let network_diagnostics = renderer.network_diagnostics();
        let bookmarks = shell.bookmarks().to_vec();
        let bookmark_folders = shell.bookmark_folders().to_vec();
        let permission_prompts = shell.pending_permissions().to_vec();
        let sync_status = shell.sync_status();
        let extension_notifications = shell.extension_notifications().to_vec();
        let split_panes = shell.split_layout().panes();
        let active_split_pane = shell.split_layout().active_pane();
        let active_url = shell
            .active_tab()
            .and_then(|tab_id| shell.tab(tab_id))
            .and_then(|tab| tab.url.clone());
        let show_new_tab_page = is_unopened_tab(active_url.as_ref());
        // Browser-owned documents occupy a normal tab and the same rounded
        // content viewport as a website, but chrome paints them instead of an
        // offscreen Servo WebView.
        let show_web_content = !show_new_tab_page && active_settings_tab.is_none();
        let active_bookmarked = active_url
            .as_ref()
            .is_some_and(|url| shell.is_bookmarked(url));
        let security_info = nomad_engine::security_info(active_url.as_ref());
        let route_decision = active_url
            .as_ref()
            .map(|url| network_route.decision_for(url));
        let umc_resource = active_url
            .as_ref()
            .and_then(|url| UmcResourceInfo::from_url(url).ok());
        let resolver_status = shell.resolver().status();
        let effective_resolver = shell.effective_resolver_settings();
        let resolver_override_active = shell.resolver_override_active();
        let umc_diagnostics = renderer.umc_diagnostics().cloned();
        let active_media = shell
            .active_tab()
            .and_then(|tab_id| self.media_sessions.get(&tab_id))
            .cloned();
        let active_workspace = shell.active_workspace();
        let workspaces = shell.workspaces().to_vec();
        let mut tabs = shell
            .tabs()
            .iter()
            .filter(|tab| shell.tab_context(tab.id).workspace_id == active_workspace)
            .cloned()
            .collect::<Vec<_>>();
        tabs.sort_by_key(|tab| !tab.pinned);
        for url in tabs
            .iter()
            .filter_map(|tab| tab.url.as_ref())
            .chain(bookmarks.iter().map(|bookmark| &bookmark.url))
        {
            self.request_favicon(url);
        }
        let design_assets = self.design_assets.clone();
        let favicon_textures = self.favicon_textures.clone();
        // Sidebar tab groups, filtered to the active workspace and ordered
        // deterministically by id. Group state is shell-owned so it persists.
        let mut tab_groups = shell.tab_groups();
        tab_groups.sort_by_key(|group| group.id);
        tab_groups.retain(|group| {
            group
                .tab_ids
                .iter()
                .any(|group_tab_id| tabs.iter().any(|tab| tab.id == *group_tab_id))
        });
        let mut group_id_by_tab: HashMap<TabId, u64> = HashMap::new();
        let mut group_color_by_tab: HashMap<TabId, String> = HashMap::new();
        let mut collapsed_group_tabs: Vec<TabId> = Vec::new();
        for group in &tab_groups {
            for group_tab_id in &group.tab_ids {
                group_id_by_tab.insert(*group_tab_id, group.id);
                group_color_by_tab.insert(*group_tab_id, group.color.clone());
                if group.collapsed {
                    collapsed_group_tabs.push(*group_tab_id);
                }
            }
        }
        let split_tab_ids: Vec<TabId> = split_panes.iter().map(|pane| pane.tab_id).collect();
        let media_playing_tabs: Vec<TabId> = self
            .media_sessions
            .iter()
            .filter(|(_, state)| state.playing)
            .map(|(tab_id, _)| *tab_id)
            .collect();
        let mut revealed_tab_url = self.revealed_tab_url;
        let backdrop_blur = self.backdrop_blur.clone();

        self.context.run(window, |context| {
            context.data_mut(|data| {
                data.remove::<PendingChromeTooltip>(egui::Id::new("nomad-pending-tooltip"));
            });
            if context.input(|input| input.pointer.any_pressed()) {
                revealed_tab_url = None;
            }
            let geometry = DesignGeometry::from_bounds(context.content_rect());
            let screen = context.content_rect();
            let address_id = egui::Id::new("nomad-address-input");
            handle_global_shortcuts(
                context,
                address_id,
                &mut search_input,
                &mut action,
                shell,
            );
            if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::D)) {
                action = Some(ChromeAction::ToggleBookmark);
            }
            if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::Comma)) {
                action = Some(ChromeAction::OpenSettings(SettingsSection::General));
            }
            if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::W)) {
                if let Some(tab_id) = shell.active_tab() {
                    action = Some(ChromeAction::CloseTab(tab_id));
                }
            }
            let background = context.layer_painter(egui::LayerId::background());
            background.rect_filled(
                screen,
                egui::CornerRadius::same((SHELL_RADIUS * geometry.scale) as u8),
                shell_background(),
            );
            Panel::left("nomad-vertical-tabs")
                .resizable(false)
                .exact_size(geometry.sidebar_width)
                .frame(egui::Frame::NONE)
                .show_separator_line(false)
                .show_inside(context, |ui| {
                    let panel_rect = ui.max_rect();
                    let ui_context = ui.ctx().clone();
                    // Figma circles share the same design coordinate system as
                    // the toolbar. Native actions retain macOS window behavior.
                    for (index, (x, color, label)) in [
                        (30.0, egui::Color32::from_rgb(242, 106, 95), "Close window"),
                        (70.0, egui::Color32::from_rgb(246, 204, 98), "Minimize window"),
                        (110.0, egui::Color32::from_rgb(105, 201, 97), "Zoom window"),
                    ].into_iter().enumerate() {
                        let rect = geometry.rect(x, 26.0, 24.0, 24.0);
                        let response = ui.allocate_rect(rect, egui::Sense::click())
                            .on_hover_text(label);
                        ui.painter().circle_filled(rect.center(), rect.width() * 0.5, color);
                        if response.hovered() {
                            ui.painter().circle_stroke(rect.center(), rect.width() * 0.5 - 1.0,
                                egui::Stroke::new(1.0, egui::Color32::from_black_alpha(45)));
                        }
                        if response.clicked() {
                            match index {
                                0 => action = Some(ChromeAction::Quit),
                                1 => window.set_minimized(true),
                                _ => window.set_maximized(!window.is_maximized()),
                            }
                        }
                    }
                    let menu_response = chrome_icon_response(
                        ui,
                        egui::Id::new("nomad-menu-control"),
                        geometry.rect(
                            layout::nav::MENU_X,
                            layout::nav::ROW_TOP,
                            layout::nav::ICON_WIDTH,
                            layout::nav::ICON_HEIGHT,
                        ),
                        "Menu",
                        geometry.scale,
                    );
                    let back_response = chrome_icon_response(
                        ui,
                        egui::Id::new("nomad-back-control"),
                        geometry.rect(
                            layout::nav::BACK_X,
                            layout::nav::ROW_TOP,
                            layout::nav::ICON_WIDTH,
                            layout::nav::ICON_HEIGHT,
                        ),
                        "Back",
                        geometry.scale,
                    );
                    let forward_response = chrome_icon_response(
                        ui,
                        egui::Id::new("nomad-forward-control"),
                        geometry.rect(
                            layout::nav::FORWARD_X,
                            layout::nav::ROW_TOP,
                            layout::nav::ICON_WIDTH,
                            layout::nav::ICON_HEIGHT,
                        ),
                        "Forward",
                        geometry.scale,
                    );
                    let reload_response = chrome_icon_response(
                        ui,
                        egui::Id::new("nomad-reload-control"),
                        geometry.rect(
                            layout::nav::RELOAD_X,
                            layout::nav::ROW_TOP,
                            layout::nav::RELOAD_WIDTH,
                            layout::nav::ICON_HEIGHT,
                        ),
                        "Reload",
                        geometry.scale,
                    );
                    paint_asset(
                        ui.painter(),
                        &design_assets,
                        DesignAsset::Layout,
                        geometry.rect(
                            layout::nav::LAYOUT_ICON_X,
                            layout::nav::LAYOUT_ICON_Y,
                            layout::nav::LAYOUT_ICON_SIZE,
                            layout::nav::LAYOUT_ICON_SIZE,
                        ),
                        false,
                        interactive_icon_tint(&menu_response),
                    );
                    paint_asset(
                        ui.painter(),
                        &design_assets,
                        DesignAsset::Back,
                        geometry.rect(
                            layout::nav::ARROW_X_BACK,
                            layout::nav::ARROW_Y,
                            layout::nav::ARROW_WIDTH,
                            layout::nav::ARROW_HEIGHT,
                        ),
                        false,
                        interactive_icon_tint(&back_response),
                    );
                    paint_asset(
                        ui.painter(),
                        &design_assets,
                        DesignAsset::Forward,
                        geometry.rect(
                            layout::nav::ARROW_X_FORWARD,
                            layout::nav::ARROW_Y,
                            layout::nav::ARROW_WIDTH,
                            layout::nav::ARROW_HEIGHT,
                        ),
                        false,
                        interactive_icon_tint(&forward_response),
                    );
                    paint_reload_icon(
                        ui.painter(),
                        geometry.rect(
                            layout::nav::RELOAD_ICON_X,
                            layout::nav::RELOAD_ICON_Y,
                            layout::nav::RELOAD_ICON_SIZE,
                            layout::nav::RELOAD_ICON_SIZE,
                        ),
                        interactive_icon_tint(&reload_response),
                    );

                    if menu_response.clicked() {
                        more_visible = !more_visible;
                    }
                    if back_response.clicked() && shell.can_go_back() {
                        action = Some(ChromeAction::GoBack);
                    }
                    if forward_response.clicked() && shell.can_go_forward() {
                        action = Some(ChromeAction::GoForward);
                    }
                    if reload_response.clicked() {
                        action = Some(ChromeAction::Reload);
                    }

                    let address_rect = geometry.rect(
                        TOOLBOX_PADDING,
                        layout::address::ROW_TOP,
                        SIDEBAR_WIDTH - TOOLBOX_PADDING * 2.0,
                        layout::address::ROW_HEIGHT,
                    );
                    paint_search_surface(ui.painter(), address_rect, geometry.scale);
                    let search_surface_response = ui.allocate_rect(address_rect, egui::Sense::click());
                    if search_surface_response.clicked() {
                        ui.memory_mut(|memory| memory.request_focus(address_id));
                    }
                    if search_surface_response.hovered() || search_surface_response.has_focus() {
                        ui.painter().rect_filled(
                            address_rect,
                            egui::CornerRadius::same((TOOLBAR_RADIUS * geometry.scale) as u8),
                            egui::Color32::from_white_alpha(10),
                        );
                    }
                    let response = ui.put(
                        geometry.rect(
                            layout::address::FIELD_X,
                            layout::address::ROW_TOP,
                            SIDEBAR_WIDTH
                                - layout::address::FIELD_X
                                - TOOLBOX_PADDING,
                            layout::address::ROW_HEIGHT,
                        ),
                        TextEdit::singleline(&mut search_input)
                            .id(address_id)
                            .frame(egui::Frame::NONE)
                            .background_color(egui::Color32::TRANSPARENT)
                            .font(egui::FontId::proportional(
                                layout::type_scale::ADDRESS,
                            ))
                            .vertical_align(egui::Align::Center)
                            .text_color(design_white())
                            .hint_text(
                                egui::RichText::new("Search...").font(
                                    egui::FontId::proportional(layout::type_scale::ADDRESS),
                                ),
                            )
                            .margin(egui::Margin::ZERO)
                            .desired_width(f32::INFINITY),
                    );
                    if response.changed() {
                        address_query_active = true;
                        web_suggestions.clear();
                        selected_suggestion = None;
                        schedule_autocomplete(
                            search_input.trim().to_owned(),
                            self.autocomplete_generation.clone(),
                            self.autocomplete_sender.clone(),
                            ui_context.clone(),
                        );
                    }
                    if response.gained_focus() {
                        address_query_active = true;
                    }
                    let enter_pressed = ui.input(|input| input.key_pressed(Key::Enter));
                    if response.has_focus()
                        && ui.input(|input| input.key_pressed(Key::Escape))
                    {
                        search_input.clear();
                        address_query_active = false;
                    }
                    if response.has_focus()
                        && address_query_active
                        && !search_input.trim().is_empty()
                    {
                        address_suggestions = shell
                            .universal_suggestions(&search_input)
                            .into_iter()
                            .filter(|suggestion| {
                                matches!(
                                    suggestion.kind,
                                    UniversalSuggestionKind::Tab
                                        | UniversalSuggestionKind::Bookmark
                                        | UniversalSuggestionKind::History
                                        | UniversalSuggestionKind::Address
                                )
                            })
                            .collect();
                        for title in web_suggestions.iter().take(AUTOCOMPLETE_LIMIT) {
                            if let Ok(target) = nomad_shell::normalize_address_input(
                                title,
                                &shell.settings().search_url,
                            ) {
                                address_suggestions.push(UniversalSuggestion {
                                    kind: UniversalSuggestionKind::Search,
                                    title: title.clone(),
                                    detail: String::new(),
                                    target: UniversalTarget::Navigate(target),
                                });
                            }
                        }
                        address_suggestions.truncate(layout::address::SUGGESTIONS_MAX_ITEMS);

                        if !address_suggestions.is_empty()
                            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::ArrowDown))
                        {
                            selected_suggestion = Some(
                                selected_suggestion
                                    .map_or(0, |index| (index + 1) % address_suggestions.len()),
                            );
                        }
                        if !address_suggestions.is_empty()
                            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::ArrowUp))
                        {
                            selected_suggestion = Some(selected_suggestion.map_or(
                                address_suggestions.len() - 1,
                                |index| index.checked_sub(1).unwrap_or(address_suggestions.len() - 1),
                            ));
                        }
                    }
                    if !search_input.trim().is_empty()
                        && enter_pressed
                        && (response.has_focus() || response.lost_focus())
                    {
                        action = Some(selected_suggestion
                            .and_then(|index| address_suggestions.get(index))
                            .map_or_else(
                                || ChromeAction::NavigateInNewTab(search_input.clone()),
                                universal_suggestion_action,
                            ));
                        search_input.clear();
                        address_query_active = false;
                    }
                    let mut suggestion_panel_hovered = false;
                    if address_query_active && !address_suggestions.is_empty() {
                        let panel = egui::Area::new(egui::Id::new("nomad-address-suggestions"))
                            .order(egui::Order::Foreground)
                            .fixed_pos(geometry.point(
                                TOOLBOX_PADDING,
                                layout::address::ROW_TOP + layout::address::SUGGESTIONS_OFFSET,
                            ))
                            .show(&ui_context, |ui| {
                                let content_width = suggestion_panel_content_width(
                                    geometry.sidebar_width,
                                    geometry.scale,
                                );
                                let margin = layout::address::SUGGESTIONS_MARGIN;
                                let blur_rect = egui::Rect::from_min_size(
                                    ui.min_rect().min,
                                    egui::vec2(
                                        content_width + margin * 2.0,
                                        layout::suggestions::ITEM_HEIGHT
                                            * address_suggestions
                                                .len()
                                                .min(layout::address::SUGGESTIONS_MAX_ITEMS)
                                                as f32
                                            + margin * 2.0,
                                    ),
                                );
                                paint_backdrop_blur(
                                    ui.painter(),
                                    blur_rect,
                                    backdrop_blur.clone(),
                                    layout::suggestions::PANEL_RADIUS,
                                );
                                egui::Frame::NONE
                                    .fill(egui::Color32::from_rgba_unmultiplied(29, 29, 29, 128))
                                    .stroke(egui::Stroke::new(
                                        1.0,
                                        egui::Color32::from_white_alpha(40),
                                    ))
                                    .corner_radius(egui::CornerRadius::same(
                                        layout::suggestions::PANEL_RADIUS as u8,
                                    ))
                                    .inner_margin(egui::Margin::same(
                                        layout::address::SUGGESTIONS_MARGIN as i8,
                                    ))
                                    .show(ui, |ui| {
                                    ui.set_width(content_width);
                                    for (index, suggestion) in address_suggestions
                                        .iter()
                                        .take(layout::address::SUGGESTIONS_MAX_ITEMS)
                                        .enumerate()
                                    {
                                        let suggestion_response = universal_suggestion_button(
                                            ui,
                                            suggestion,
                                            selected_suggestion == Some(index),
                                        );
                                        if suggestion_activated(
                                            suggestion_response.clicked(),
                                            suggestion_response.is_pointer_button_down_on(),
                                        ) {
                                            action = Some(universal_suggestion_action(suggestion));
                                            search_input.clear();
                                            address_query_active = false;
                                        }
                                    }
                                });
                            });
                        suggestion_panel_hovered = ui_context
                            .pointer_latest_pos()
                            .is_some_and(|pointer| panel.response.rect.contains(pointer));
                    }
                    if should_dismiss_suggestions(
                        response.lost_focus(),
                        suggestion_panel_hovered,
                        action.is_some(),
                    ) {
                        search_input.clear();
                        address_query_active = false;
                    }

                    // Build displayed rows: group headers with member tabs,
                    // then ungrouped tabs. Global search already includes tab
                    // matches, so the Figma rail needs no second filter field.
                    let mut sidebar_rows: Vec<SidebarRow> = Vec::new();
                    for group in &tab_groups {
                        let members: Vec<&TabSnapshot> = tabs
                            .iter()
                            .filter(|tab| group.tab_ids.contains(&tab.id))
                            .collect();
                        if members.is_empty() {
                            continue;
                        }
                        sidebar_rows.push(SidebarRow::Group(group));
                        if !group.collapsed {
                            for member in members {
                                sidebar_rows.push(SidebarRow::Tab(member));
                            }
                        }
                    }
                    for tab in &tabs {
                        if group_id_by_tab.contains_key(&tab.id)
                            || !should_show_sidebar_tab(
                                tab.id,
                                tab.url.as_ref(),
                                self.submitted_tabs.contains(&tab.id).then_some(tab.id),
                            )
                        {
                            continue;
                        }
                        sidebar_rows.push(SidebarRow::Tab(tab));
                    }

                    // Drag-and-drop reorder: the dragged row tracks the row
                    // under the pointer; on release it takes that row's slot.
                    // Drops only land within the same pinned partition
                    // because the sidebar pins are displayed first.
                    let pointer_pos = ui.input(|input| input.pointer.latest_pos());
                    let mut drag_source: Option<(TabId, bool)> = None;
                    let mut drag_released = false;
                    let mut drop_anchor: Option<TabId> = None;
                    let mut revealed_row_top: Option<f32> = None;

                    let mut row_y = layout::tab_list::LIST_TOP;
                    for row in sidebar_rows.iter().copied() {
                        match row {
                            SidebarRow::Group(group) => {
                                let header_rect = geometry.rect(
                                    TOOLBOX_PADDING,
                                    row_y,
                                    SIDEBAR_WIDTH - TOOLBOX_PADDING * 2.0,
                                    layout::tab_groups::HEADER_HEIGHT,
                                );
                                let header_response = ui
                                    .allocate_rect(header_rect, egui::Sense::click())
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(if group.collapsed {
                                        "Expand group"
                                    } else {
                                        "Collapse group"
                                    });
                                if header_response.hovered() {
                                    ui.painter().rect_filled(
                                        header_rect,
                                        egui::CornerRadius::same(
                                            (ROW_RADIUS * geometry.scale) as u8,
                                        ),
                                        egui::Color32::from_white_alpha(16),
                                    );
                                }
                                paint_caret_icon(
                                    ui.painter(),
                                    geometry.point(
                                        layout::tab_groups::CARET_X,
                                        row_y + layout::tab_groups::HEADER_HEIGHT * 0.5,
                                    ),
                                    geometry.scale,
                                    !group.collapsed,
                                    design_white(),
                                );
                                ui.painter().circle_filled(
                                    geometry.point(
                                        layout::tab_groups::DOT_CENTER_X,
                                        row_y + layout::tab_groups::HEADER_HEIGHT * 0.5,
                                    ),
                                    layout::tab_groups::DOT_SIZE * 0.5 * geometry.scale,
                                    tab_group_color(&group.color),
                                );
                                ui.painter().text(
                                    geometry.point(
                                        layout::tab_groups::LABEL_X,
                                        row_y + layout::tab_groups::HEADER_HEIGHT * 0.5,
                                    ),
                                    egui::Align2::LEFT_CENTER,
                                    group
                                        .title
                                        .clone()
                                        .unwrap_or_else(|| format!("Group {}", group.id)),
                                    egui::FontId::proportional(layout::type_scale::BOOKMARK_TAB),
                                    design_white(),
                                );
                                ui.painter().text(
                                    geometry.point(
                                        geometry.sidebar_width
                                            - TOOLBOX_PADDING
                                            - layout::tab_groups::COUNT_INSET * geometry.scale,
                                        row_y + layout::tab_groups::HEADER_HEIGHT * 0.5,
                                    ),
                                    egui::Align2::RIGHT_CENTER,
                                    group.tab_ids.len().to_string(),
                                    egui::FontId::proportional(layout::type_scale::BOOKMARK_TAB),
                                    egui::Color32::from_white_alpha(140),
                                );
                                if header_response.clicked() {
                                    action = Some(ChromeAction::SetTabGroupCollapsed {
                                        group_id: group.id,
                                        collapsed: !group.collapsed,
                                    });
                                }
                                header_response.context_menu(|ui| {
                                    let blur_shape = ui.painter().add(egui::Shape::Noop);
                                    let tint_shape = ui.painter().add(egui::Shape::Noop);
                                    ui.set_min_width(layout::address::CONTEXT_MENU_WIDTH);
                                    if ui.button("Ungroup tabs").clicked() {
                                        action = Some(ChromeAction::UngroupTabGroup(group.id));
                                        ui.close();
                                    }
                                    let rect = ui.min_rect().expand(8.0);
                                    ui.painter().set(
                                        blur_shape,
                                        backdrop_blur_shape(
                                            rect,
                                            backdrop_blur.clone(),
                                            12.0,
                                        ),
                                    );
                                    ui.painter().set(
                                        tint_shape,
                                        egui::Shape::rect_filled(
                                            rect,
                                            egui::CornerRadius::same(12),
                                            egui::Color32::from_rgba_unmultiplied(29, 29, 29, 176),
                                        ),
                                    );
                                });
                                row_y += layout::tab_groups::HEADER_PITCH;
                            }
                            SidebarRow::Tab(tab) => {
                                let row_top = row_y;
                                if revealed_tab_url == Some(tab.id) {
                                    revealed_row_top = Some(row_top);
                                }
                                let row_rect = geometry.rect(
                                    TOOLBOX_PADDING,
                                    row_top,
                                    SIDEBAR_WIDTH - TOOLBOX_PADDING * 2.0,
                                    layout::tab_list::ROW_HEIGHT,
                                );
                                let row_response = ui
                                    .allocate_rect(row_rect, egui::Sense::click_and_drag())
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                let active = Some(tab.id) == shell.active_tab();
                                if active {
                                    ui.painter().rect_filled(
                                        row_rect,
                                        egui::CornerRadius::same(
                                            (ROW_RADIUS * geometry.scale) as u8,
                                        ),
                                        egui::Color32::from_white_alpha(20),
                                    );
                                } else if row_response.hovered() {
                                    ui.painter().rect_filled(
                                        row_rect,
                                        egui::CornerRadius::same(
                                            (ROW_RADIUS * geometry.scale) as u8,
                                        ),
                                        egui::Color32::from_white_alpha(12),
                                    );
                                }
                                if row_response.dragged() || row_response.drag_stopped() {
                                    drag_source = Some((tab.id, tab.pinned));
                                    drag_released |= row_response.drag_stopped();
                                }
                                let is_drop_target = drag_source.is_some()
                                    && drag_source.map(|(source, _)| source) != Some(tab.id)
                                    && drag_source.map(|(_, pinned)| pinned) == Some(tab.pinned)
                                    && pointer_pos.is_some_and(|pointer| row_rect.contains(pointer));
                                if is_drop_target {
                                    drop_anchor = Some(tab.id);
                                    ui.painter().rect_stroke(
                                        row_rect,
                                        egui::CornerRadius::same(
                                            (ROW_RADIUS * geometry.scale) as u8,
                                        ),
                                        egui::Stroke::new(
                                            2.0 * geometry.scale,
                                            egui::Color32::from_white_alpha(200),
                                        ),
                                        egui::StrokeKind::Inside,
                                    );
                                }
                                if let Some(color) = group_color_by_tab.get(&tab.id) {
                                    ui.painter().circle_filled(
                                        geometry.point(
                                            layout::tab_list::GROUP_DOT_CENTER_X,
                                            row_top + layout::tab_list::CONTENT_CENTER_OFFSET,
                                        ),
                                        layout::tab_list::GROUP_DOT_SIZE * 0.5 * geometry.scale,
                                        tab_group_color(color),
                                    );
                                }
                                if let Some(texture) =
                                    favicon_texture(&favicon_textures, tab.url.as_ref())
                                {
                                    paint_favicon_texture(
                                        ui.painter(),
                                        texture,
                                        geometry.rect(
                                            layout::tab_list::ICON_X,
                                            row_top + layout::tab_list::ICON_OFFSET,
                                            layout::tab_list::ICON_SIZE,
                                            layout::tab_list::ICON_SIZE,
                                        ),
                                    );
                                } else if let Some(asset) = site_icon_asset(tab.url.as_ref()) {
                                    let icon_rect = match asset {
                                        DesignAsset::YouTube => geometry.rect(
                                            layout::tab_list::ICON_X,
                                            row_top + layout::tab_list::WIDE_ICON_OFFSET,
                                            layout::tab_list::WIDE_ICON_WIDTH,
                                            layout::tab_list::WIDE_ICON_HEIGHT,
                                        ),
                                        _ => geometry.rect(
                                            layout::tab_list::ICON_X,
                                            row_top + layout::tab_list::ICON_OFFSET,
                                            layout::tab_list::ICON_SIZE,
                                            layout::tab_list::ICON_SIZE,
                                        ),
                                    };
                                    paint_asset(
                                        ui.painter(),
                                        &design_assets,
                                        asset,
                                        icon_rect,
                                        false,
                                        design_white(),
                                    );
                                } else {
                                    paint_favicon_fallback(
                                        ui.painter(),
                                        geometry.point(
                                            layout::tab_list::FALLBACK_CENTER_X,
                                            row_top + layout::tab_list::CONTENT_CENTER_OFFSET,
                                        ),
                                        tab.url.as_ref(),
                                        geometry.scale,
                                    );
                                }
                                let label_clip = egui::Rect::from_min_max(
                                    geometry.point(
                                        layout::tab_list::LABEL_X,
                                        row_top,
                                    ),
                                    egui::pos2(
                                        row_rect.right()
                                            - layout::tab_list::CLOSE_SIZE * geometry.scale,
                                        row_rect.bottom(),
                                    ),
                                );
                                let label = tab_display_label(
                                    tab.url.as_ref(),
                                    revealed_tab_url == Some(tab.id),
                                );
                                ui.painter().with_clip_rect(label_clip).text(
                                    geometry.point(
                                        layout::tab_list::LABEL_X,
                                        row_top + layout::tab_list::CONTENT_CENTER_OFFSET,
                                    ),
                                    egui::Align2::LEFT_CENTER,
                                    label,
                                    egui::FontId::proportional(layout::type_scale::TAB),
                                    design_white(),
                                );
                                if media_playing_tabs.contains(&tab.id) {
                                    paint_speaker_icon(
                                        ui.painter(),
                                        geometry.point(
                                            layout::tab_list::AUDIO_CENTER_X,
                                            row_top + layout::tab_list::CONTENT_CENTER_OFFSET,
                                        ),
                                        geometry.scale,
                                        design_white(),
                                    );
                                }
                                if row_response.double_clicked() {
                                    revealed_tab_url = if revealed_tab_url == Some(tab.id) {
                                        None
                                    } else {
                                        Some(tab.id)
                                    };
                                    if !active {
                                        action = Some(ChromeAction::SelectTab(tab.id));
                                    }
                                } else if row_response.clicked() {
                                    revealed_tab_url = None;
                                    if !active {
                                        action = Some(ChromeAction::SelectTab(tab.id));
                                    }
                                }
                                row_response.context_menu(|ui| {
                                    let blur_shape = ui.painter().add(egui::Shape::Noop);
                                    let tint_shape = ui.painter().add(egui::Shape::Noop);
                                    ui.set_min_width(layout::address::CONTEXT_MENU_WIDTH);
                                    if ui
                                        .button(if tab.pinned { "Unpin Tab" } else { "Pin Tab" })
                                        .clicked()
                                    {
                                        action = Some(ChromeAction::SetTabPinned {
                                            id: tab.id,
                                            pinned: !tab.pinned,
                                        });
                                        ui.close();
                                    }
                                    if !matches!(tab.lifecycle, TabLifecycle::Active)
                                        && ui.button("Sleep Tab").clicked()
                                    {
                                        action = Some(ChromeAction::SleepTab(tab.id));
                                        ui.close();
                                    }
                                    if !split_tab_ids.contains(&tab.id) {
                                        ui.menu_button("Move to split view", |ui| {
                                            if ui.button("To the right").clicked() {
                                                action = Some(ChromeAction::MoveTabToSplit {
                                                    tab: tab.id,
                                                    orientation: SplitOrientation::Horizontal,
                                                });
                                                ui.close();
                                            }
                                            if ui.button("Below").clicked() {
                                                action = Some(ChromeAction::MoveTabToSplit {
                                                    tab: tab.id,
                                                    orientation: SplitOrientation::Vertical,
                                                });
                                                ui.close();
                                            }
                                        });
                                    }
                                    ui.separator();
                                    if group_id_by_tab.contains_key(&tab.id) {
                                        if ui.button("Remove from group").clicked() {
                                            action =
                                                Some(ChromeAction::RemoveTabFromGroup(tab.id));
                                            ui.close();
                                        }
                                    } else {
                                        ui.menu_button("Add tab to group", |ui| {
                                            for group in &tab_groups {
                                                if ui
                                                    .button(
                                                        group.title.clone().unwrap_or_else(|| {
                                                            format!("Group {}", group.id)
                                                        }),
                                                    )
                                                    .clicked()
                                                {
                                                    action = Some(ChromeAction::AddTabToGroup {
                                                        tab: tab.id,
                                                        group_id: group.id,
                                                    });
                                                    ui.close();
                                                }
                                            }
                                            if ui.button("New group").clicked() {
                                                action = Some(ChromeAction::CreateTabGroup {
                                                    tab: tab.id,
                                                });
                                                ui.close();
                                            }
                                        });
                                    }
                                    ui.separator();
                                    if ui.button("Close Tab").clicked() {
                                        action = Some(ChromeAction::CloseTab(tab.id));
                                        ui.close();
                                    }
                                    let rect = ui.min_rect().expand(8.0);
                                    ui.painter().set(
                                        blur_shape,
                                        backdrop_blur_shape(
                                            rect,
                                            backdrop_blur.clone(),
                                            12.0,
                                        ),
                                    );
                                    ui.painter().set(
                                        tint_shape,
                                        egui::Shape::rect_filled(
                                            rect,
                                            egui::CornerRadius::same(12),
                                            egui::Color32::from_rgba_unmultiplied(29, 29, 29, 176),
                                        ),
                                    );
                                });
                                if row_response.hovered() {
                                    let close_rect = geometry.rect(
                                        layout::tab_list::CLOSE_CENTER_X
                                            - layout::tab_list::CLOSE_SIZE / 2.0,
                                        row_top + layout::tab_list::CLOSE_OFFSET,
                                        layout::tab_list::CLOSE_SIZE,
                                        layout::tab_list::CLOSE_SIZE,
                                    );
                                    let close_response = ui
                                        .allocate_rect(close_rect, egui::Sense::click())
                                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                                        .on_hover_text("Close tab");
                                    let close_color = if close_response.hovered() {
                                        egui::Color32::WHITE
                                    } else {
                                        egui::Color32::from_white_alpha(170)
                                    };
                                    paint_close_icon(
                                        ui.painter(),
                                        close_rect.center(),
                                        geometry.scale,
                                        close_color,
                                    );
                                    let primary_press_on_button = ui.input(|input| {
                                        input.pointer.primary_pressed()
                                            && input
                                                .pointer
                                                .interact_pos()
                                                .is_some_and(|pointer| close_rect.contains(pointer))
                                    });
                                    if close_tab_activated(
                                        close_response.clicked(),
                                        primary_press_on_button,
                                    ) {
                                        action = Some(ChromeAction::CloseTab(tab.id));
                                    }
                                }
                                row_y += layout::tab_list::ROW_PITCH;
                            }
                        }
                    }

                    if drag_released {
                        if let (Some((source, _)), Some(anchor)) = (drag_source, drop_anchor) {
                            if source != anchor {
                                action = Some(ChromeAction::ReorderTab { tab: source, anchor });
                            }
                        }
                    }

                    if let (Some(tab_id), Some(top)) = (revealed_tab_url, revealed_row_top) {
                        if let Some(url) = tabs
                            .iter()
                            .find(|tab| tab.id == tab_id)
                            .and_then(|tab| tab.url.as_ref())
                        {
                            egui::Area::new(egui::Id::new("nomad-tab-url"))
                                .order(egui::Order::Foreground)
                                .fixed_pos(geometry.point(
                                    SIDEBAR_WIDTH + 8.0,
                                    top,
                                ))
                                .show(&ui_context, |ui| {
                                    paint_backdrop_blur(
                                        ui.painter(),
                                        egui::Rect::from_min_size(
                                            ui.min_rect().min,
                                            egui::vec2(436.0, 44.0),
                                        ),
                                        backdrop_blur.clone(),
                                        10.0,
                                    );
                                    egui::Frame::popup(ui.style())
                                        .fill(egui::Color32::from_rgba_unmultiplied(
                                            29, 29, 29, 220,
                                        ))
                                        .shadow(egui::epaint::Shadow::NONE)
                                        .stroke(egui::Stroke::new(
                                            1.0,
                                            egui::Color32::from_white_alpha(28),
                                        ))
                                        .corner_radius(egui::CornerRadius::same(10))
                                        .inner_margin(egui::Margin::same(8))
                                        .show(ui, |ui| {
                                            ui.set_max_width(420.0 * geometry.scale);
                                            ui.label(url.as_str());
                                        });
                                });
                        }
                    }

                    let bottom_center_y =
                        panel_rect.bottom() - layout::bottom_bar::MARGIN * geometry.scale;
                    let settings_response = chrome_icon_response(
                        ui,
                        egui::Id::new("nomad-settings-control"),
                        egui::Rect::from_center_size(
                            egui::pos2(
                                layout::bottom_bar::CONTROL_INSET * geometry.scale,
                                bottom_center_y,
                            ),
                            geometry.size(
                                layout::bottom_bar::HIT_SIZE,
                                layout::bottom_bar::HIT_SIZE,
                            ),
                        ),
                        "Settings",
                        geometry.scale,
                    );
                    let downloads_response = chrome_icon_response(
                        ui,
                        egui::Id::new("nomad-downloads-control"),
                        egui::Rect::from_center_size(
                            egui::pos2(
                                geometry.sidebar_width
                                    - layout::bottom_bar::CONTROL_INSET * geometry.scale,
                                bottom_center_y,
                            ),
                            geometry.size(
                                layout::bottom_bar::HIT_SIZE,
                                layout::bottom_bar::HIT_SIZE,
                            ),
                        ),
                        "Downloads",
                        geometry.scale,
                    );
                    let visible_workspaces = workspaces
                        .iter()
                        .filter(|_| workspaces.len() > 1)
                        .take(layout::bottom_bar::WORKSPACE_MAX_DOTS)
                        .collect::<Vec<_>>();
                    let workspace_step =
                        layout::bottom_bar::WORKSPACE_DOT_PITCH * geometry.scale;
                    let workspace_start = geometry.sidebar_width * 0.5
                        - workspace_step * (visible_workspaces.len().saturating_sub(1) as f32) * 0.5;
                    for (index, workspace) in visible_workspaces.into_iter().enumerate() {
                        let center = egui::pos2(
                            workspace_start + index as f32 * workspace_step,
                            bottom_center_y,
                        );
                        let rect = egui::Rect::from_center_size(
                            center,
                            geometry.size(
                                layout::bottom_bar::WORKSPACE_DOT_SIZE,
                                layout::bottom_bar::WORKSPACE_DOT_SIZE,
                            ),
                        );
                        let response = ui
                            .allocate_rect(rect, egui::Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(&workspace.name);
                        let active = workspace.id == active_workspace;
                        if active || response.hovered() {
                            ui.painter().rect_filled(
                                rect,
                                egui::CornerRadius::same(
                                    (layout::radius::WORKSPACE_DOT * geometry.scale) as u8,
                                ),
                                egui::Color32::from_white_alpha(if active { 28 } else { 16 }),
                            );
                        }
                        ui.painter().circle_filled(
                            center,
                            if active {
                                layout::bottom_bar::WORKSPACE_DOT_RADIUS_ACTIVE
                            } else {
                                layout::bottom_bar::WORKSPACE_DOT_RADIUS
                            } * geometry.scale,
                            egui::Color32::from_white_alpha(if active { 225 } else { 120 }),
                        );
                        if response.clicked() && !active {
                            action = Some(ChromeAction::SelectWorkspace(workspace.id));
                        }
                    }
                    paint_asset(
                        ui.painter(),
                        &design_assets,
                        DesignAsset::Settings,
                        egui::Rect::from_center_size(
                            egui::pos2(
                                layout::bottom_bar::CONTROL_INSET * geometry.scale,
                                bottom_center_y,
                            ),
                            geometry.size(
                                layout::bottom_bar::SETTINGS_WIDTH,
                                layout::bottom_bar::SETTINGS_HEIGHT,
                            ),
                        ),
                        false,
                        interactive_icon_tint(&settings_response),
                    );
                    paint_asset(
                        ui.painter(),
                        &design_assets,
                        DesignAsset::Download,
                        egui::Rect::from_center_size(
                            egui::pos2(
                                geometry.sidebar_width
                                    - layout::bottom_bar::CONTROL_INSET * geometry.scale,
                                bottom_center_y,
                            ),
                            geometry.size(
                                layout::bottom_bar::DOWNLOAD_SIZE,
                                layout::bottom_bar::DOWNLOAD_SIZE,
                            ),
                        ),
                        false,
                        interactive_icon_tint(&downloads_response),
                    );
                    if settings_response.clicked() {
                        action = Some(ChromeAction::OpenSettings(SettingsSection::General));
                    }
                    if downloads_response.clicked() {
                        action = Some(ChromeAction::OpenSettings(SettingsSection::Downloads));
                    }
                });

            let drag_rect = egui::Rect::from_min_max(
                egui::pos2(
                    (SIDEBAR_WIDTH
                        + CONTENT_LEFT_INSET
                        + bookmarks.len() as f32 * layout::bookmark_strip::TAB_PITCH
                        + layout::bookmark_strip::DRAG_LEADING_GAP)
                        * geometry.scale,
                    layout::bookmark_strip::DRAG_TOP * geometry.scale,
                ),
                egui::pos2(
                    screen.right() - layout::bookmark_strip::DRAG_RIGHT_MARGIN * geometry.scale,
                    layout::bookmark_strip::DRAG_BOTTOM * geometry.scale,
                ),
            );
            if drag_rect.is_positive() {
                egui::Area::new(egui::Id::new("nomad-window-drag-area"))
                    .fixed_pos(drag_rect.min)
                    .show(context, |ui| {
                        let response = ui.allocate_exact_size(drag_rect.size(), egui::Sense::drag()).1;
                        if response.drag_started() {
                            let _ = window.drag_window();
                        }
                    });
            }

            egui::Area::new(egui::Id::new("nomad-tab-strip"))
                .order(egui::Order::Foreground)
                .fixed_pos(geometry.point(
                    SIDEBAR_WIDTH + CONTENT_LEFT_INSET,
                    layout::bookmark_strip::STRIP_TOP,
                ))
                .show(context, |ui| {
                    let tab_origin = ui.min_rect().min;
                    ui.horizontal(|ui| {
                        for (index, bookmark) in bookmarks.iter().enumerate() {
                            let tab_rect = egui::Rect::from_min_size(
                                egui::pos2(
                                    tab_origin.x
                                        + index as f32
                                            * layout::bookmark_strip::TAB_PITCH
                                            * geometry.scale,
                                    tab_origin.y,
                                ),
                                geometry.size(
                                    layout::bookmark_strip::TAB_WIDTH,
                                    layout::bookmark_strip::TAB_HEIGHT,
                                ),
                            );
                            let bookmark_response = ui
                                .allocate_rect(tab_rect, egui::Sense::click())
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .on_hover_text(&bookmark.title);
                            ui.painter().rect_filled(
                                tab_rect,
                                egui::CornerRadius::same(
                                    (layout::radius::BOOKMARK_TAB * geometry.scale) as u8,
                                ),
                                if bookmark_response.hovered() {
                                    egui::Color32::from_white_alpha(28)
                                } else {
                                    chrome_surface()
                                },
                            );
                            let tab_content_origin = tab_origin
                                + geometry.size(index as f32 * layout::bookmark_strip::TAB_PITCH, 0.0);
                            if let Some(texture) =
                                favicon_texture(&favicon_textures, Some(&bookmark.url))
                            {
                                paint_favicon_texture(
                                    ui.painter(),
                                    texture,
                                    egui::Rect::from_center_size(
                                        tab_content_origin
                                            + geometry.size(
                                                layout::bookmark_strip::ICON_CENTER_OFFSET[0],
                                                layout::bookmark_strip::ICON_CENTER_OFFSET[1],
                                            ),
                                        geometry.size(
                                            layout::bookmark_strip::ICON_SIZE[0],
                                            layout::bookmark_strip::ICON_SIZE[1],
                                        ),
                                    ),
                                );
                            } else if let Some(asset) = bookmark_icon_asset(&bookmark.url) {
                                let icon_rect = match asset {
                                    DesignAsset::YouTube => egui::Rect::from_center_size(
                                        tab_content_origin
                                            + geometry.size(
                                                layout::bookmark_strip::ICON_CENTER_OFFSET[0],
                                                layout::bookmark_strip::ICON_CENTER_OFFSET[1],
                                            ),
                                        geometry.size(
                                            layout::bookmark_strip::WIDE_ICON_SIZE[0],
                                            layout::bookmark_strip::WIDE_ICON_SIZE[1],
                                        ),
                                    ),
                                    _ => egui::Rect::from_center_size(
                                        tab_content_origin
                                            + geometry.size(
                                                layout::bookmark_strip::ICON_CENTER_OFFSET[0],
                                                layout::bookmark_strip::ICON_CENTER_OFFSET[1],
                                            ),
                                        geometry.size(
                                            layout::bookmark_strip::ICON_SIZE[0],
                                            layout::bookmark_strip::ICON_SIZE[1],
                                        ),
                                    ),
                                };
                                paint_asset(
                                    ui.painter(),
                                    &design_assets,
                                    asset,
                                    icon_rect,
                                    false,
                                    design_white(),
                                );
                            } else {
                                paint_favicon_fallback(
                                    ui.painter(),
                                    tab_content_origin
                                        + geometry.size(
                                            layout::bookmark_strip::ICON_CENTER_OFFSET[0],
                                            layout::bookmark_strip::ICON_CENTER_OFFSET[1],
                                        ),
                                    Some(&bookmark.url),
                                    geometry.scale * layout::bookmark_strip::FALLBACK_ICON_SCALE,
                                );
                            }
                            let text_clip = egui::Rect::from_min_max(
                                tab_content_origin
                                    + geometry.size(
                                        layout::bookmark_strip::TEXT_CLIP_MIN[0],
                                        layout::bookmark_strip::TEXT_CLIP_MIN[1],
                                    ),
                                tab_content_origin
                                    + geometry.size(
                                        layout::bookmark_strip::TEXT_CLIP_MAX[0],
                                        layout::bookmark_strip::TEXT_CLIP_MAX[1],
                                    ),
                            );
                            ui.painter().with_clip_rect(text_clip).text(
                                tab_content_origin
                                    + geometry.size(
                                        layout::bookmark_strip::TEXT_OFFSET[0],
                                        layout::bookmark_strip::TEXT_OFFSET[1],
                                    ),
                                egui::Align2::LEFT_CENTER,
                                bookmark.title.as_str(),
                                egui::FontId::proportional(layout::type_scale::BOOKMARK_TAB),
                                design_white(),
                            );
                            if bookmark_response.clicked() {
                                action = Some(ChromeAction::OpenBookmark(bookmark.id));
                            }
                        }
                    });
                });

            if more_visible {
                egui::Area::new(egui::Id::new("nomad-extensions-menu"))
                    .order(egui::Order::Foreground)
                    .fixed_pos(geometry.point(
                        layout::extensions_menu::POS_X,
                        layout::extensions_menu::POS_Y,
                    ))
                    .show(context, |ui| {
                        let frame = egui::Frame::popup(ui.style())
                            .fill(egui::Color32::from_rgba_unmultiplied(38, 38, 40, 246))
                            .stroke(glass_border())
                            .corner_radius(egui::CornerRadius::same(TOOLBAR_RADIUS as u8))
                            .inner_margin(egui::Margin::same(TOOLBOX_PADDING as i8));
                        frame.show(ui, |ui| {
                            ui.set_width(layout::extensions_menu::WIDTH);
                            ui.strong("Extensions");
                            ui.add_space(4.0);

                            let mut has_extensions = false;
                            for extension in shell
                                .extensions()
                                .installed()
                                .filter(|extension| extension.action.is_some())
                            {
                                has_extensions = true;
                                let label = extension
                                    .action
                                    .as_ref()
                                    .and_then(|action| action.default_title.as_deref())
                                    .unwrap_or(extension.name.as_str());
                                if ui
                                    .add_sized(
                                        [ui.available_width(), layout::extensions_menu::BUTTON_HEIGHT],
                                        egui::Button::new(format!("◫   {label}"))
                                            .frame(false),
                                    )
                                    .clicked()
                                {
                                    action = Some(ChromeAction::TriggerExtensionAction(
                                        extension.id.clone(),
                                    ));
                                    more_visible = false;
                                }
                            }
                            if !has_extensions {
                                ui.label(
                                    egui::RichText::new("No extensions installed")
                                        .color(egui::Color32::from_white_alpha(150)),
                                );
                            }

                            if !extension_notifications.is_empty() {
                                ui.add_space(6.0);
                                ui.separator();
                                ui.add_space(4.0);
                                ui.label(
                                    egui::RichText::new("Notifications")
                                        .color(egui::Color32::from_white_alpha(170)),
                                );
                                for notification in extension_notifications.iter().rev() {
                                    egui::Frame::NONE
                                        .fill(egui::Color32::from_white_alpha(12))
                                        .corner_radius(egui::CornerRadius::same(9))
                                        .inner_margin(egui::Margin::same(8))
                                        .show(ui, |ui| {
                                            ui.set_width(ui.available_width());
                                            ui.strong(&notification.title);
                                            ui.small(&notification.message);
                                            if ui.small_button("Dismiss").clicked() {
                                                action = Some(
                                                    ChromeAction::ClearExtensionNotification(
                                                        notification.id.clone(),
                                                    ),
                                                );
                                            }
                                        });
                                }
                            }
                        });
                    });
            }

            let scale = context.pixels_per_point();
            CentralPanel::default()
                .frame(egui::Frame::NONE)
                .show_inside(context, |ui| {
                    let viewport = content_viewport_rect(ui.ctx(), geometry);
                    // Web content is a background surface, not ordinary panel paint.  In
                    // particular, native GL callbacks are not reliably interleaved with
                    // egui's clipped mesh batches when they share a panel painter.  Keeping
                    // the page callback on its own background layer prevents it from
                    // overwriting browser-owned overlays (tooltips, menus, and popovers)
                    // that cross the content viewport boundary.
                    let page_painter = ui.ctx().layer_painter(egui::LayerId::new(
                        egui::Order::Background,
                        egui::Id::new("nomad-web-content"),
                    ));
                    if show_web_content {
                        page_painter.rect_filled(
                            viewport,
                            egui::CornerRadius::same((CONTENT_RADIUS * geometry.scale) as u8),
                            content_surface(),
                        );
                    }
                    // Tree-based split layout: each group divides its extent
                    // along its own orientation, so 2-row and 3-pane mixed
                    // arrangements render correctly.
                    let pane_rects: Vec<(nomad_engine::SplitPane, egui::Rect)> =
                        shell.split_layout()
                            .pane_rects(
                                viewport.left(),
                                viewport.top(),
                                viewport.width(),
                                viewport.height(),
                            )
                            .into_iter()
                            .map(|(pane, rect)| {
                                (
                                    pane,
                                    egui::Rect::from_min_size(
                                        egui::pos2(rect.x, rect.y),
                                        egui::vec2(rect.width, rect.height),
                                    ),
                                )
                            })
                            .collect();
                    if show_web_content {
                        let mut page_layouts = Vec::with_capacity(pane_rects.len());
                        for (pane, page_rect) in &pane_rects {
                            let size = physical_size_for_rect(*page_rect, scale);
                            renderer.set_content_rect_for(
                                pane.tab_id,
                                winit::dpi::PhysicalPosition::new(
                                    f64::from(page_rect.left() * scale),
                                    f64::from(page_rect.top() * scale),
                                ),
                                size,
                            );
                            renderer.resize_content_for(pane.tab_id, size);
                            page_layouts.push((pane.tab_id, *page_rect));
                        }

                        // Servo applies WebView resizes asynchronously. Process those messages
                        // before asking the offscreen context for its compositor callback: that
                        // callback captures the framebuffer id and source dimensions at creation
                        // time. Capturing it before resize made pages retain the previous (often
                        // full-window) width and clip their right edge inside Nomad's viewport.
                        renderer.spin_event_loop();

                        // Painting can change the contents of the offscreen framebuffer. Do it
                        // before capturing the callback that will composite that framebuffer into
                        // this window frame. Previously native.rs painted after `update` returned,
                        // leaving loading and caret-animation frames with a callback captured from
                        // the preceding page-paint phase.
                        let visible_tabs: Vec<_> = page_layouts
                            .iter()
                            .map(|(tab_id, _)| *tab_id)
                            .collect();
                        if let Err(error) = renderer.paint_visible_pages(&visible_tabs) {
                            page_paint_error = Some(error);
                        }

                        for (tab_id, page_rect) in page_layouts {
                            if let Some(render_to_parent) =
                                renderer.render_to_parent_callback_for(tab_id)
                            {
                                page_painter.add(PaintCallback {
                                    rect: page_rect,
                                    callback: Arc::new(CallbackFn::new(move |info, painter| {
                                        let clip = info.viewport_in_pixels();
                                        let target = Rect::new(
                                            Point2D::new(clip.left_px, clip.from_bottom_px),
                                            Size2D::new(clip.width_px, clip.height_px),
                                        );
                                        let radius = (CONTENT_RADIUS
                                            * geometry.scale
                                            * info.pixels_per_point)
                                            .round() as i32;
                                        render_to_parent(painter.gl(), target, radius);
                                    })),
                                });
                            }
                        }

                    }
                        // Pane overlays: click an inactive pane to activate
                        // it, or use its corner button to close it. The page
                        // under an inactive pane may also receive the click
                        // (Servo routes pointer input by content rect), the
                        // same as first-click-to-focus window managers.
                        if pane_rects.len() > 1 {
                            for (pane, rect) in &pane_rects {
                                if pane.id == active_split_pane {
                                    ui.painter().rect_stroke(
                                        *rect,
                                        egui::CornerRadius::same(
                                            (CONTENT_RADIUS * geometry.scale) as u8,
                                        ),
                                        egui::Stroke::new(
                                            layout::split_pane::ACTIVE_STROKE_WIDTH
                                                * geometry.scale,
                                            egui::Color32::from_white_alpha(200),
                                        ),
                                        egui::StrokeKind::Inside,
                                    );
                                    continue;
                                }
                                let activate_response = ui
                                    .allocate_rect(*rect, egui::Sense::click())
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text("Activate pane");
                                if activate_response.clicked() {
                                    action = Some(ChromeAction::ActivateSplitPane(pane.id));
                                }
                                let close_rect = egui::Rect::from_min_size(
                                    egui::pos2(
                                        rect.right()
                                            - layout::split_pane::CLOSE_SIZE * geometry.scale
                                            - layout::split_pane::CLOSE_INSET * geometry.scale,
                                        rect.top()
                                            + layout::split_pane::CLOSE_INSET * geometry.scale,
                                    ),
                                    egui::vec2(
                                        layout::split_pane::CLOSE_SIZE * geometry.scale,
                                        layout::split_pane::CLOSE_SIZE * geometry.scale,
                                    ),
                                );
                                let close_response = ui
                                    .allocate_rect(close_rect, egui::Sense::click())
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text("Close pane");
                                paint_close_icon(
                                    ui.painter(),
                                    close_rect.center(),
                                    geometry.scale,
                                    if close_response.hovered() {
                                        egui::Color32::WHITE
                                    } else {
                                        egui::Color32::from_white_alpha(170)
                                    },
                                );
                                if close_response.clicked() {
                                    action = Some(ChromeAction::CloseSplitPane(pane.id));
                                }
                            }
                        }
                });

            if let Some(render_to_parent) = renderer.extension_popup_render_callback() {
                let screen = context.content_rect();
                let popup_rect = egui::Rect::from_min_size(
                    egui::pos2(
                        (screen.right() - 440.0).max(screen.left() + geometry.sidebar_width),
                        8.0,
                    ),
                    egui::vec2(420.0, 620.0),
                );
                ui_paint_callback(context, popup_rect, render_to_parent);
            }

            // Auxiliary `window.open` popups: each is an offscreen Servo
            // surface composited at its registry rect (device pixels)
            // divided by the hidpi scale. The render callback is re-fetched
            // every frame because it captures the source framebuffer id at
            // creation time (see the resize note above). A pointer-sensing
            // area over each popup consumes clicks so chrome widgets
            // underneath are not activated through the overlay.
            for (index, (rect, render_to_parent)) in renderer
                .auxiliary_render_callbacks()
                .into_iter()
                .enumerate()
            {
                let popup_rect = egui::Rect::from_min_size(
                    egui::pos2(rect.origin.x / scale, rect.origin.y / scale),
                    egui::vec2(rect.size.width / scale, rect.size.height / scale),
                );
                egui::Area::new(egui::Id::new(("nomad-auxiliary-popup", index)))
                    .order(egui::Order::Foreground)
                    .fixed_pos(popup_rect.min)
                    .show(context, |ui| {
                        ui.allocate_rect(popup_rect, egui::Sense::click_and_drag());
                    });
                ui_paint_callback(context, popup_rect, render_to_parent);
            }

            if downloads_visible {
                egui::Window::new("Downloads")
                    .frame(zen_popup_frame())
                    .default_width(380.0)
                    .resizable(true)
                    .show(context, |ui| {
                        if downloads.is_empty() {
                            ui.label("No downloads yet.");
                        }
                        for download in downloads.iter().rev().take(12) {
                            let filename = download
                                .destination
                                .file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or("download");
                            ui.horizontal(|ui| {
                                ui.strong(filename);
                                ui.label(download_state_label(download.state));
                            });
                            if let Some(total_bytes) = download.total_bytes {
                                let progress = if total_bytes == 0 {
                                    1.0
                                } else {
                                    download.bytes_received as f32 / total_bytes as f32
                                };
                                ui.add(
                                    ProgressBar::new(progress.clamp(0.0, 1.0)).show_percentage(),
                                );
                            } else if download.state == DownloadState::InProgress {
                                ui.spinner();
                            }
                            if let Some(error) = &download.error {
                                ui.colored_label(egui::Color32::LIGHT_RED, error);
                            }
                            ui.small(format!("Destination: {}", download.destination.display()));
                            if let Some(checksum) = &download.checksum {
                                ui.small(format!("Checksum: {checksum}"));
                            }
                            if let Some(warning) = &download.security_warning {
                                ui.colored_label(egui::Color32::YELLOW, warning);
                            }
                            ui.horizontal(|ui| {
                                if matches!(
                                    download.state,
                                    DownloadState::Queued | DownloadState::InProgress
                                ) && ui.small_button("Cancel").clicked()
                                {
                                    action = Some(ChromeAction::CancelDownload(download.id));
                                }
                                if download.state == DownloadState::Failed
                                    && ui.small_button("Retry").clicked()
                                {
                                    action = Some(ChromeAction::RetryDownload(download.id));
                                }
                            });
                            ui.separator();
                        }
                    });
            }

            if commands_visible {
                egui::Window::new("Command palette")
                    .frame(zen_popup_frame())
                    .default_width(460.0)
                    .resizable(false)
                    .show(context, |ui| {
                        let response = ui.add(
                            TextEdit::singleline(&mut command_query)
                                .hint_text("Search commands")
                                .desired_width(f32::INFINITY),
                        );
                        if response.has_focus()
                            && ui.input(|input| input.key_pressed(Key::Enter))
                        {
                            if let Some(suggestion) = command_suggestions.first() {
                                action = Some(ChromeAction::OpenUniversal(
                                    suggestion.target.clone(),
                                ));
                            }
                        }
                        ui.separator();
                        if command_suggestions.is_empty() {
                            ui.label("No matching commands.");
                        }
                        ui.separator();
                        if ui
                            .selectable_label(false, "Quit Nomad  ·  Save session and exit")
                            .clicked()
                        {
                            action = Some(ChromeAction::Quit);
                        }
                        for suggestion in &command_suggestions {
                            if ui
                                .selectable_label(
                                    false,
                                    format!("{}  ·  {}", suggestion.title, suggestion.detail),
                                )
                                .clicked()
                            {
                                action = Some(ChromeAction::OpenUniversal(
                                    suggestion.target.clone(),
                                ));
                            }
                        }
                    });
            }

            if workspaces_visible {
                egui::Window::new("Workspaces and containers")
                    .frame(zen_popup_frame())
                    .default_width(300.0)
                    .show(context, |ui| {
                        ui.heading("Workspaces");
                        for workspace in shell.workspaces() {
                            let selected = workspace.id == shell.active_workspace();
                            if ui.selectable_label(selected, &workspace.name).clicked() && !selected {
                                action = Some(ChromeAction::SelectWorkspace(workspace.id));
                            }
                        }
                        if ui.button("+ New workspace").clicked() {
                            let name = format!("Workspace {}", shell.workspaces().len() + 1);
                            action = Some(ChromeAction::CreateWorkspace(name));
                        }
                        ui.separator();
                        ui.heading("Containers");
                        ui.horizontal(|ui| {
                            ui.add_sized(
                                [150.0, 22.0],
                                TextEdit::singleline(&mut container_name)
                                    .hint_text("New container"),
                            );
                            ui.checkbox(&mut container_ephemeral, "temporary");
                        });
                        if ui.button("+ Create container").clicked()
                            && !container_name.trim().is_empty()
                        {
                            action = Some(ChromeAction::CreateContainer {
                                name: container_name.trim().to_owned(),
                                ephemeral: container_ephemeral,
                            });
                            container_name.clear();
                            container_ephemeral = false;
                        }
                        let active_container = shell
                            .active_tab()
                            .map(|tab_id| shell.tab_context(tab_id).container_id);
                        for container in shell.containers() {
                            ui.horizontal(|ui| {
                                let selected = active_container == Some(container.id);
                                if ui
                                    .selectable_label(
                                        selected,
                                        format!(
                                            "{}{}",
                                            container.name,
                                            if container.ephemeral { " · temporary" } else { "" }
                                        ),
                                    )
                                    .clicked()
                                    && !selected
                                {
                                    action = Some(ChromeAction::AssignActiveContainer(container.id));
                                }
                            });
                        }
                    });
            }

            if devtools_visible {
                egui::Window::new("DevTools")
                    .frame(zen_popup_frame())
                    .default_width(480.0)
                    .show(context, |ui| {
                        ui.horizontal(|ui| {
                            if ui.button("Refresh snapshot").clicked() {
                                action = Some(ChromeAction::OpenDevTools);
                            }
                            if ui.button("Clear captured data").clicked() {
                                action = Some(ChromeAction::ClearDevTools);
                            }
                        });
                        ui.separator();
                        let snapshot = shell
                            .active_tab()
                            .and_then(|tab_id| shell.devtools_snapshot(tab_id));
                        ui.heading("Console");
                        ui.horizontal(|ui| {
                            ui.label("Levels:");
                            for (label, index) in [("Log", 0), ("Info", 1), ("Warn", 2), ("Error", 3)] {
                                ui.checkbox(&mut devtools_console_filters[index], label);
                            }
                        });
                        let input_response = ui.add_sized(
                            [ui.available_width() - 52.0, 24.0],
                            TextEdit::singleline(&mut devtools_console_input)
                                .hint_text("Evaluate JavaScript"),
                        );
                        let submit_from_enter = input_response.lost_focus()
                            && ui.input(|input| input.key_pressed(Key::Enter));
                        let submit_from_button = ui.button("Run").clicked();
                        if (submit_from_enter || submit_from_button)
                            && !devtools_console_input.trim().is_empty()
                        {
                            action = Some(ChromeAction::EvaluateDevTools(
                                devtools_console_input.trim().to_owned(),
                            ));
                            devtools_console_input.clear();
                        }
                        if let Some(snapshot) = snapshot {
                            let enabled_levels = [
                                (devtools_console_filters[0], ConsoleLevel::Log),
                                (devtools_console_filters[1], ConsoleLevel::Info),
                                (devtools_console_filters[2], ConsoleLevel::Warn),
                                (devtools_console_filters[3], ConsoleLevel::Error),
                            ]
                            .into_iter()
                            .filter_map(|(enabled, level)| enabled.then_some(level))
                            .collect::<Vec<_>>();
                            for entry in filter_console_entries(&snapshot.console, &enabled_levels)
                                .iter()
                                .rev()
                                .take(100)
                            {
                                ui.label(format!("{:?}: {}", entry.level, entry.message));
                            }
                            ui.separator();
                            ui.heading("Network");
                            for request in snapshot.network.iter().rev().take(20) {
                                ui.label(format!(
                                    "{} {} · {} · {} ms{}",
                                    request.method,
                                    request.url,
                                    request.status.map_or("pending".to_owned(), |status| status.to_string()),
                                    request.duration_ms.map_or("?".to_owned(), |duration| duration.to_string()),
                                    if request.failed { " · failed" } else { "" }
                                ));
                            }
                            if let Some(dom) = &snapshot.dom {
                                ui.separator();
                                ui.heading("DOM / CSS");
                                render_devtools_dom_node(ui, &dom.root);
                                ui.collapsing(
                                    format!("Stylesheet rules ({})", dom.stylesheets.len()),
                                    |ui| {
                                        for stylesheet in &dom.stylesheets {
                                            ui.collapsing(
                                                format!(
                                                    "{} ({} rule(s))",
                                                    stylesheet.href,
                                                    stylesheet.rules.len()
                                                ),
                                                |ui| {
                                                    if stylesheet.rules.is_empty() {
                                                        ui.small("No readable CSS rules.");
                                                    }
                                                    for rule in &stylesheet.rules {
                                                        ui.code(rule);
                                                    }
                                                },
                                            );
                                        }
                                    },
                                );
                            }
                            if let Some(page) = &snapshot.page_inspection {
                                ui.separator();
                                ui.heading("Page inspection");
                                ui.label(format!("{} · {}", page.title, page.ready_state));
                                ui.small(format!(
                                    "{} stylesheet(s) · {} local key(s) · {} session key(s)",
                                    page.stylesheets.len(),
                                    page.local_storage.len(),
                                    page.session_storage.len()
                                ));
                                if let Some(duration) = page.navigation_duration_ms {
                                    ui.small(format!("Navigation: {duration} ms"));
                                }
                                let mut visible_text = page.visible_text.clone();
                                ui.add(
                                    TextEdit::multiline(&mut visible_text)
                                        .desired_rows(6)
                                        .interactive(false),
                                );
                                ui.collapsing("Metadata", |ui| {
                                    for (name, value) in &page.metadata {
                                        ui.label(format!("{name}: {value}"));
                                    }
                                });
                                ui.collapsing("Stylesheets", |ui| {
                                    for stylesheet in &page.stylesheets {
                                        ui.label(stylesheet);
                                    }
                                });
                                ui.collapsing(
                                    format!("Sources ({})", page.sources.len()),
                                    |ui| {
                                        if page.sources.is_empty() {
                                            ui.small("No script sources found.");
                                        }
                                        for source in &page.sources {
                                            ui.collapsing(&source.url, |ui| {
                                                if let Some(content) = &source.content {
                                                    ui.code(content);
                                                } else {
                                                    ui.small("External source content is not available in the page context.");
                                                }
                                            });
                                        }
                                    },
                                );
                                ui.collapsing("Local storage", |ui| {
                                    if page.local_storage.is_empty() {
                                        ui.small("No local-storage entries.");
                                    }
                                    for (key, value) in &page.local_storage {
                                        ui.label(format!("{key} = {value}"));
                                    }
                                });
                                ui.collapsing("Session storage", |ui| {
                                    if page.session_storage.is_empty() {
                                        ui.small("No session-storage entries.");
                                    }
                                    for (key, value) in &page.session_storage {
                                        ui.label(format!("{key} = {value}"));
                                    }
                                });
                                ui.collapsing("Cookies", |ui| {
                                    if page.cookies.is_empty() {
                                        ui.small("No script-visible cookies.");
                                    }
                                    for (key, value) in &page.cookies {
                                        ui.label(format!("{key} = {value}"));
                                    }
                                    ui.small("HttpOnly cookies are not visible to document.cookie.");
                                });
                            }
                        } else {
                            ui.label("No page events captured for this tab yet.");
                        }
                    });
            }

            if reader_visible {
                egui::Window::new("Reader tools")
                    .frame(zen_popup_frame())
                    .default_width(280.0)
                    .show(context, |ui| {
                        if let Some(tab_id) = shell.active_tab() {
                            ui.label(format!("Mode: {:?}", shell.reader_mode(tab_id)));
                            if let Some(document) = shell.reader_document(tab_id) {
                                if let Some(title) = &document.title {
                                    ui.heading(title);
                                }
                                ui.small(format!("{} words", document.word_count()));
                                for paragraph in document.paragraphs.iter().take(12) {
                                    ui.label(paragraph);
                                }
                            }
                            ui.small("Reader extraction keeps content local and does not execute page scripts.");
                        } else {
                            ui.label("No active tab.");
                        }
                    });
            }

            if translation_visible {
                egui::Window::new("Translation")
                    .frame(zen_popup_frame())
                    .default_width(320.0)
                    .show(context, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("From");
                            egui::ComboBox::from_id_salt("translation-source")
                                .selected_text(translation_source.code())
                                .show_ui(ui, |ui| {
                                    for language in translation_languages() {
                                        ui.selectable_value(
                                            &mut translation_source,
                                            language,
                                            language.code(),
                                        );
                                    }
                                });
                            ui.label("to");
                            egui::ComboBox::from_id_salt("translation-target")
                                .selected_text(translation_target.code())
                                .show_ui(ui, |ui| {
                                    for language in translation_languages()
                                        .into_iter()
                                        .filter(|language| *language != TranslationLanguage::Auto)
                                    {
                                        ui.selectable_value(
                                            &mut translation_target,
                                            language,
                                            language.code(),
                                        );
                                    }
                                });
                        });
                        ui.add(
                            TextEdit::multiline(&mut translation_input)
                                .hint_text("Text or page content")
                                .desired_rows(8),
                        );
                        if ui.button("Translate").clicked() {
                            action = Some(ChromeAction::TranslateText {
                                source: translation_source,
                                target: translation_target,
                                text: translation_input.clone(),
                            });
                        }
                        if let Some(error) = &translation_error {
                            ui.colored_label(egui::Color32::LIGHT_RED, error);
                        }
                        if let Some(output) = &translation_output {
                            ui.separator();
                            ui.label(output);
                        }
                        ui.separator();
                        ui.separator();
                        ui.label("Nomad does not send page text to a Nomad-operated service.");
                        ui.small("Set NOMAD_TRANSLATION_ENDPOINT to an explicit BYOK HTTP(S) endpoint.");
                    });
            }

            if history_visible {
                egui::Window::new("History")
                    .frame(zen_popup_frame())
                    .default_width(420.0)
                    .resizable(true)
                    .show(context, |ui| {
                        ui.add(
                            TextEdit::singleline(&mut history_query)
                                .hint_text("Search history")
                                .desired_width(f32::INFINITY),
                        );
                        if history.is_empty() {
                            ui.label("No history yet.");
                        }
                        for visit in history.iter().take(100) {
                            if ui.selectable_label(false, visit.url.as_str()).clicked() {
                                action =
                                    Some(ChromeAction::NavigateFromHistory(visit.url.to_string()));
                            }
                        }
                    });
            }

            if memory_visible {
                egui::Window::new("Memory and lifecycle")
                    .frame(zen_popup_frame())
                    .default_width(520.0)
                    .resizable(true)
                    .show(context, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(format!(
                                "Nomad estimated: {} / {} budget",
                                format_bytes(memory_diagnostics.browser_bytes),
                                format_bytes(memory_diagnostics.budget_bytes)
                            ));
                            ui.label(format!("Pressure: {:?}", memory_diagnostics.pressure));
                        });
                        ui.label(format!(
                            "Active {} · Warm {} · Sleeping {} · Suspended {} · Archived {}",
                            memory_diagnostics.active_tabs,
                            memory_diagnostics.warm_tabs,
                            memory_diagnostics.sleeping_tabs,
                            memory_diagnostics.suspended_tabs,
                            memory_diagnostics.archived_tabs
                        ));
                        ui.small(format!(
                            "Available memory: {} ({:?}); tabs: {} measured / {} estimated",
                            format_bytes(memory_diagnostics.available_bytes),
                            memory_diagnostics.observation_source,
                            memory_diagnostics.measured_tabs,
                            memory_diagnostics.estimated_tabs,
                        ));
                        ui.horizontal(|ui| {
                            ui.label("Budget mode");
                            for mode in [
                                MemoryMode::Automatic,
                                MemoryMode::LowMemory,
                                MemoryMode::Balanced,
                                MemoryMode::MaximumPerformance,
                            ] {
                                if ui
                                    .selectable_label(shell.memory_mode() == mode, mode.label())
                                    .clicked()
                                {
                                    action = Some(ChromeAction::SetMemoryMode(mode));
                                }
                            }
                            if ui.button("Reclaim now").clicked() {
                                action = Some(ChromeAction::ReclaimMemory);
                            }
                        });
                        ui.separator();
                        for tab in shell.tabs() {
                            let label = tab
                                .url
                                .as_ref()
                                .and_then(url::Url::host_str)
                                .unwrap_or("New tab");
                            ui.horizontal(|ui| {
                                ui.label(format!(
                                    "{} · {:?} · {}",
                                    label,
                                    tab.lifecycle,
                                    format_bytes(tab.memory_bytes)
                                ));
                                ui.small(match tab.memory_source {
                                    nomad_engine::TabMemorySource::Servo => "Servo measured",
                                    nomad_engine::TabMemorySource::Estimated => "Estimated",
                                });
                                if tab.lifecycle == TabLifecycle::Active {
                                    ui.label("Active");
                                } else if matches!(
                                    tab.lifecycle,
                                    TabLifecycle::Suspended | TabLifecycle::Archived
                                ) {
                                    if ui.small_button("Resume").clicked() {
                                        action = Some(ChromeAction::ResumeTab(tab.id));
                                    }
                                } else if tab.lifecycle == TabLifecycle::Sleeping {
                                    if ui.small_button("Wake").clicked() {
                                        action = Some(ChromeAction::WakeTab(tab.id));
                                    }
                                } else if ui.small_button("Sleep").clicked() {
                                    action = Some(ChromeAction::SleepTab(tab.id));
                                }
                                if !matches!(
                                    tab.lifecycle,
                                    TabLifecycle::Active
                                        | TabLifecycle::Suspended
                                        | TabLifecycle::Archived
                                ) && ui.small_button("Suspend").clicked()
                                {
                                    action = Some(ChromeAction::SuspendTab(tab.id));
                                }
                                if ui
                                    .small_button(if tab.pinned { "Unpin" } else { "Pin" })
                                    .clicked()
                                {
                                    action = Some(ChromeAction::SetTabPinned {
                                        id: tab.id,
                                        pinned: !tab.pinned,
                                    });
                                }
                                if ui
                                    .small_button(if tab.keep_alive {
                                        "Allow suspend"
                                    } else {
                                        "Keep alive"
                                    })
                                    .clicked()
                                {
                                    action = Some(ChromeAction::SetTabKeepAlive {
                                        id: tab.id,
                                        keep_alive: !tab.keep_alive,
                                    });
                                }
                            });
                        }
                    });
            }

            if bookmarks_visible {
                egui::Window::new("Bookmarks")
                    .frame(zen_popup_frame())
                    .default_width(380.0)
                    .resizable(true)
                    .show(context, |ui| {
                        ui.horizontal(|ui| {
                            ui.add_sized(
                                [180.0, 22.0],
                                TextEdit::singleline(&mut bookmark_folder_name)
                                    .hint_text("New folder"),
                            );
                            if ui.small_button("Create folder").clicked() {
                                action = Some(ChromeAction::CreateBookmarkFolder(
                                    bookmark_folder_name.trim().to_owned(),
                                ));
                                bookmark_folder_name.clear();
                            }
                        });
                        for folder in &bookmark_folders {
                            ui.horizontal(|ui| {
                                if bookmark_folder_rename_id == Some(folder.id) {
                                    ui.add_sized(
                                        [180.0, 22.0],
                                        TextEdit::singleline(&mut bookmark_folder_rename),
                                    );
                                    if ui.small_button("Save").clicked() {
                                        action = Some(ChromeAction::RenameBookmarkFolder {
                                            id: folder.id,
                                            name: bookmark_folder_rename.trim().to_owned(),
                                        });
                                        bookmark_folder_rename_id = None;
                                    }
                                } else {
                                    ui.label(format!("📁 {}", folder.name));
                                    if ui.small_button("Rename").clicked() {
                                        bookmark_folder_rename_id = Some(folder.id);
                                        bookmark_folder_rename.clone_from(&folder.name);
                                    }
                                }
                                if ui.small_button("×").clicked() {
                                    action = Some(ChromeAction::RemoveBookmarkFolder(folder.id));
                                }
                            });
                        }
                        if !bookmark_folders.is_empty() {
                            ui.separator();
                        }
                        if bookmarks.is_empty() {
                            ui.label("No bookmarks yet.");
                        }
                        for bookmark in &bookmarks {
                            ui.horizontal(|ui| {
                                if bookmark_edit_id == Some(bookmark.id) {
                                    ui.add_sized(
                                        [180.0, 22.0],
                                        TextEdit::singleline(&mut bookmark_edit_title),
                                    );
                                    if ui.small_button("Save").clicked() {
                                        action = Some(ChromeAction::RenameBookmark {
                                            id: bookmark.id,
                                            title: bookmark_edit_title.trim().to_owned(),
                                        });
                                        bookmark_edit_id = None;
                                    }
                                } else if ui.selectable_label(false, &bookmark.title).clicked() {
                                    action = Some(ChromeAction::OpenBookmark(bookmark.id));
                                } else if ui.small_button("Edit").clicked() {
                                    bookmark_edit_id = Some(bookmark.id);
                                    bookmark_edit_title.clone_from(&bookmark.title);
                                }
                                if ui.small_button("×").clicked() {
                                    action = Some(ChromeAction::RemoveBookmark(bookmark.id));
                                }
                            });
                            ui.small(bookmark.url.as_str());
                            let folder_name = bookmark
                                .folder_id
                                .and_then(|folder_id| {
                                    bookmark_folders
                                        .iter()
                                        .find(|folder| folder.id == folder_id)
                                })
                                .map_or("Unfiled", |folder| folder.name.as_str());
                            let mut selected_folder = bookmark.folder_id;
                            egui::ComboBox::from_id_salt(("bookmark-folder", bookmark.id.get()))
                                .selected_text(folder_name)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut selected_folder, None, "Unfiled");
                                    for folder in &bookmark_folders {
                                        ui.selectable_value(
                                            &mut selected_folder,
                                            Some(folder.id),
                                            &folder.name,
                                        );
                                    }
                                });
                            if selected_folder != bookmark.folder_id {
                                action = Some(ChromeAction::MoveBookmark {
                                    id: bookmark.id,
                                    folder_id: selected_folder,
                                });
                            }
                            ui.separator();
                        }
                    });
            }

            if settings_visible {
                let settings_rect = content_viewport_rect(context, geometry);
                let settings_inner_size = egui::vec2(
                    (settings_rect.width() - 24.0).max(260.0),
                    (settings_rect.height() - 24.0).max(260.0),
                );
                egui::Area::new(egui::Id::new("nomad-settings-surface"))
                    .order(egui::Order::Foreground)
                    .fixed_pos(settings_rect.min)
                    .show(context, |ui| {
                        egui::Frame::NONE
                            .fill(egui::Color32::from_rgb(30, 30, 32))
                            .stroke(egui::Stroke::new(
                                1.0,
                                egui::Color32::from_white_alpha(24),
                            ))
                            .corner_radius(egui::CornerRadius::same(12))
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                        // Frame margins are outside the child UI. Subtract them so the settings
                        // surface stays within the same visible viewport as a website.
                        ui.set_min_size(settings_inner_size);
                        ui.set_max_size(settings_inner_size);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Settings").size(18.0).strong());
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Done").clicked() {
                                        if let Some(tab_id) = self.settings_tab {
                                            action = Some(ChromeAction::CloseTab(tab_id));
                                        }
                                    }
                                },
                            );
                        });
                        ui.add_space(layout::settings::LIST_SPACE);
                        ui.separator();
                        ui.add_space(layout::settings::LIST_SPACE);
                        settings_section_bar(ui, &mut settings_section);
                        ui.add_space(layout::settings::LIST_SPACE);
                        ui.separator();
                        ui.add_space(layout::settings::SPACE);
                        ui.vertical(|ui| {
                                ui.set_width(ui.available_width());
                                egui::ScrollArea::vertical()
                                    .auto_shrink([false, false])
                                    .max_height((settings_inner_size.y - 132.0).max(180.0))
                                    .show(ui, |ui| match settings_section {
                                        SettingsSection::General => {
                                            settings_heading(
                                                ui,
                                                "General",
                                                "Startup, browsing data, downloads, and updates.",
                                            );
                                            settings_card(ui, |ui| {
                                                settings_toggle(
                                                    ui,
                                                    &mut settings_draft.persist_session,
                                                    "Restore previous session",
                                                    "Reopen your tabs and workspaces when Nomad starts.",
                                                );
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                settings_toggle(
                                                    ui,
                                                    &mut settings_draft.persist_history,
                                                    "Browsing history",
                                                    "Keep visited pages on this Mac.",
                                                );
                                                settings_divider(ui);
                                                settings_toggle(
                                                    ui,
                                                    &mut settings_draft.persist_bookmarks,
                                                    "Bookmarks",
                                                    "Keep bookmarks between sessions.",
                                                );
                                                settings_divider(ui);
                                                settings_toggle(
                                                    ui,
                                                    &mut settings_draft.persist_permissions,
                                                    "Site permissions",
                                                    "Remember camera, location, and notification choices.",
                                                );
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                settings_field_label(ui, "Search engine URL");
                                                ui.add(
                                                    TextEdit::singleline(
                                                        &mut settings_draft.search_url,
                                                    )
                                                    .desired_width(f32::INFINITY),
                                                );
                                                settings_divider(ui);
                                                settings_field_label(ui, "Download location");
                                                let mut directory = settings_draft
                                                    .download_directory
                                                    .display()
                                                    .to_string();
                                                if ui
                                                    .add(
                                                        TextEdit::singleline(&mut directory)
                                                            .desired_width(f32::INFINITY),
                                                    )
                                                    .changed()
                                                {
                                                    settings_draft.download_directory =
                                                        PathBuf::from(directory);
                                                }
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                settings_toggle(
                                                    ui,
                                                    &mut settings_draft
                                                        .update_policy
                                                        .automatic_checks,
                                                    "Automatic updates",
                                                    "Check for new Nomad versions automatically.",
                                                );
                                                settings_divider(ui);
                                                ui.horizontal(|ui| {
                                                    ui.label("Release channel");
                                                    ui.with_layout(
                                                        egui::Layout::right_to_left(
                                                            egui::Align::Center,
                                                        ),
                                                        |ui| {
                                                            egui::ComboBox::from_id_salt(
                                                                "release-channel",
                                                            )
                                                            .selected_text(match settings_draft
                                                                .update_policy
                                                                .channel
                                                            {
                                                                UpdateChannel::Stable => "Stable",
                                                                UpdateChannel::Beta => "Beta",
                                                                UpdateChannel::Nightly => "Nightly",
                                                            })
                                                            .show_ui(ui, |ui| {
                                                                ui.selectable_value(
                                                                    &mut settings_draft
                                                                        .update_policy
                                                                        .channel,
                                                                    UpdateChannel::Stable,
                                                                    "Stable",
                                                                );
                                                                ui.selectable_value(
                                                                    &mut settings_draft
                                                                        .update_policy
                                                                        .channel,
                                                                    UpdateChannel::Beta,
                                                                    "Beta",
                                                                );
                                                                ui.selectable_value(
                                                                    &mut settings_draft
                                                                        .update_policy
                                                                        .channel,
                                                                    UpdateChannel::Nightly,
                                                                    "Nightly",
                                                                );
                                                            });
                                                        },
                                                    );
                                                });
                                                settings_divider(ui);
                                                ui.label(
                                                    egui::RichText::new(
                                                        "Downloads are checked with Ed25519 signatures and staged for the next restart. An interrupted install can be recovered or rolled back.",
                                                    )
                                                    .color(egui::Color32::from_white_alpha(150)),
                                                );
                                            });
                                        }
                                        SettingsSection::Privacy => {
                                            settings_heading(
                                                ui,
                                                "Privacy & Security",
                                                "Choose how strongly Nomad isolates and protects browsing.",
                                            );
                                            settings_card(ui, |ui| {
                                                settings_field_label(ui, "Protection level");
                                                ui.horizontal(|ui| {
                                                    for mode in [
                                                        PrivacyMode::Standard,
                                                        PrivacyMode::Hardened,
                                                        PrivacyMode::Private,
                                                    ] {
                                                        ui.selectable_value(
                                                            &mut settings_draft.privacy_mode,
                                                            mode,
                                                            mode.label(),
                                                        );
                                                    }
                                                });
                                                ui.add_space(6.0);
                                                ui.label(
                                                    egui::RichText::new(match settings_draft
                                                        .privacy_mode
                                                    {
                                                        PrivacyMode::Standard => "Balanced protection for everyday browsing.",
                                                        PrivacyMode::Hardened => "Stronger tracking and fingerprinting resistance.",
                                                        PrivacyMode::Private => "Leaves no local session or history after closing.",
                                                    })
                                                    .color(egui::Color32::from_white_alpha(150)),
                                                );
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                ui.strong("Privacy dashboard");
                                                ui.small(format!(
                                                    "{} resources blocked in this session",
                                                    privacy_diagnostics.blocked_resources
                                                ));
                                                settings_divider(ui);
                                                ui.horizontal(|ui| {
                                                    ui.label("Network route");
                                                    ui.with_layout(
                                                        egui::Layout::right_to_left(
                                                            egui::Align::Center,
                                                        ),
                                                        |ui| {
                                                            ui.label(format!(
                                                                "{} · {}",
                                                                network_route.mode_label(),
                                                                network_route.dns_route_label()
                                                            ));
                                                        },
                                                    );
                                                });
                                                settings_divider(ui);
                                                ui.columns(2, |columns| {
                                                    columns[0].small(format!(
                                                        "{} Tracking protection",
                                                        status_mark(
                                                            privacy_diagnostics
                                                                .tracking_protection
                                                        )
                                                    ));
                                                    columns[0].small(format!(
                                                        "{} Third-party cookie blocking",
                                                        status_mark(
                                                            privacy_diagnostics
                                                                .third_party_cookie_blocking
                                                        )
                                                    ));
                                                    columns[0].small(format!(
                                                        "{} Storage partitioning",
                                                        status_mark(
                                                            privacy_diagnostics
                                                                .storage_partitioning
                                                        )
                                                    ));
                                                    columns[1].small(format!(
                                                        "{} Fingerprint resistance",
                                                        status_mark(
                                                            privacy_diagnostics
                                                                .anti_fingerprinting
                                                        )
                                                    ));
                                                    columns[1].small(format!(
                                                        "{} WebRTC leak control",
                                                        status_mark(
                                                            privacy_diagnostics.block_webrtc
                                                        )
                                                    ));
                                                    columns[1].small(format!(
                                                        "{} DNS leak control",
                                                        status_mark(
                                                            privacy_diagnostics
                                                                .dns_leak_protection
                                                        )
                                                    ));
                                                });
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                settings_field_label(ui, "DNS resolver");
                                                ui.small(resolver_effective_label(
                                                    &effective_resolver,
                                                    resolver_override_active,
                                                ));
                                                ui.horizontal(|ui| {
                                                    for mode in [
                                                        ResolverMode::System,
                                                        ResolverMode::Doh,
                                                        ResolverMode::Dot,
                                                        ResolverMode::Custom,
                                                    ] {
                                                        ui.selectable_value(
                                                            &mut settings_draft
                                                                .resolver
                                                                .mode,
                                                            mode,
                                                            mode.label(),
                                                        );
                                                    }
                                                });
                                                ui.small(
                                                    settings_draft.resolver.mode.description(),
                                                );
                                                if settings_draft.resolver.mode
                                                    == ResolverMode::Doh
                                                {
                                                    settings_divider(ui);
                                                    settings_field_label(ui, "DoH server URL");
                                                    ui.add(
                                                        TextEdit::singleline(
                                                            &mut settings_draft
                                                                .resolver
                                                                .server_url,
                                                        )
                                                        .hint_text(
                                                            "https://dns.example/dns-query",
                                                        )
                                                        .desired_width(f32::INFINITY),
                                                    );
                                                }
                                                if settings_draft.resolver.mode
                                                    == ResolverMode::Dot
                                                {
                                                    settings_divider(ui);
                                                    settings_field_label(ui, "DoT server host");
                                                    ui.add(
                                                        TextEdit::singleline(
                                                            &mut settings_draft
                                                                .resolver
                                                                .server_host,
                                                        )
                                                        .hint_text("dns.example:853")
                                                        .desired_width(f32::INFINITY),
                                                    );
                                                }
                                                if settings_draft.resolver.mode
                                                    == ResolverMode::Custom
                                                {
                                                    settings_divider(ui);
                                                    settings_field_label(ui, "Protocol");
                                                    ui.horizontal(|ui| {
                                                        for protocol in [
                                                            CustomResolverProtocol::Udp,
                                                            CustomResolverProtocol::Doh,
                                                            CustomResolverProtocol::Dot,
                                                        ] {
                                                            ui.selectable_value(
                                                                &mut settings_draft
                                                                    .resolver
                                                                    .custom_protocol,
                                                                protocol,
                                                                protocol.label(),
                                                            );
                                                        }
                                                    });
                                                    settings_field_label(ui, "DNS server");
                                                    ui.add(
                                                        TextEdit::singleline(
                                                            &mut settings_draft
                                                                .resolver
                                                                .custom_server,
                                                        )
                                                        .hint_text(
                                                            match settings_draft
                                                                .resolver
                                                                .custom_protocol
                                                            {
                                                                CustomResolverProtocol::Udp => {
                                                                    "1.1.1.1:53"
                                                                }
                                                                CustomResolverProtocol::Doh => {
                                                                    "https://dns.example/dns-query"
                                                                }
                                                                CustomResolverProtocol::Dot => {
                                                                    "dns.example:853"
                                                                }
                                                            },
                                                        )
                                                        .desired_width(f32::INFINITY),
                                                    );
                                                }
                                            });
                                        }
                                        SettingsSection::Sync => {
                                            settings_heading(
                                                ui,
                                                "Sync",
                                                "Encrypted, user-owned synchronization.",
                                            );
                                            settings_card(ui, |ui| {
                                                settings_toggle(
                                                    ui,
                                                    &mut settings_draft.sync.enabled,
                                                    "Enable Sync",
                                                    "Synchronize settings, bookmarks, and history.",
                                                );
                                                settings_divider(ui);
                                                ui.horizontal(|ui| {
                                                    ui.label("Provider");
                                                    ui.with_layout(
                                                        egui::Layout::right_to_left(
                                                            egui::Align::Center,
                                                        ),
                                                        |ui| {
                                                            egui::ComboBox::from_id_salt(
                                                                "sync-provider",
                                                            )
                                                            .selected_text(
                                                                settings_draft.sync.provider.clone(),
                                                            )
                                                            .show_ui(ui, |ui| {
                                                                for provider in [
                                                                    "file", "umc", "custom",
                                                                ] {
                                                                    ui.selectable_value(
                                                                        &mut settings_draft
                                                                            .sync
                                                                            .provider,
                                                                        provider.to_owned(),
                                                                        provider,
                                                                    );
                                                                }
                                                            });
                                                        },
                                                    );
                                                });
                                                settings_divider(ui);
                                                settings_field_label(ui, "Endpoint");
                                                ui.add(
                                                    TextEdit::singleline(
                                                        &mut settings_draft.sync.endpoint,
                                                    )
                                                    .hint_text("User-owned endpoint")
                                                    .desired_width(f32::INFINITY),
                                                );
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                ui.strong("Encryption key");
                                                if let Some(fingerprint) =
                                                    sync_status.key_fingerprint.as_deref()
                                                {
                                                    ui.small(format!(
                                                        "Fingerprint: {fingerprint}"
                                                    ));
                                                    ui.horizontal(|ui| {
                                                        if ui.button("Sync Now").clicked() {
                                                            action = Some(ChromeAction::SyncNow);
                                                        }
                                                        if ui.button("Pull Remote").clicked() {
                                                            action = Some(ChromeAction::PullSync);
                                                        }
                                                    });
                                                } else if ui.button("Generate Sync Key").clicked() {
                                                    action = Some(ChromeAction::SetupSyncKey);
                                                }
                                                settings_divider(ui);
                                                settings_field_label(ui, "Recovery phrase");
                                                ui.add(
                                                    TextEdit::singleline(
                                                        &mut sync_recovery_input,
                                                    )
                                                    .password(true)
                                                    .desired_width(f32::INFINITY),
                                                );
                                                if ui.button("Recover from Phrase").clicked() {
                                                    action = Some(ChromeAction::RecoverSyncKey(
                                                        sync_recovery_input.clone(),
                                                    ));
                                                }
                                                if let Some(phrase) =
                                                    sync_recovery_phrase.as_deref()
                                                {
                                                    ui.colored_label(
                                                        egui::Color32::YELLOW,
                                                        format!("Save this once: {phrase}"),
                                                    );
                                                }
                                            });
                                            if sync_status.pending_uploads > 0
                                                || sync_status.conflicts > 0
                                            {
                                                ui.add_space(layout::settings::SPACE);
                                                ui.small(format!(
                                                    "{} queued uploads · {} conflicts",
                                                    sync_status.pending_uploads,
                                                    sync_status.conflicts
                                                ));
                                            }
                                            for conflict in &sync_status.pending_conflicts {
                                                settings_card(ui, |ui| {
                                                    ui.strong(format!(
                                                        "Conflict: {}",
                                                        conflict.key
                                                    ));
                                                    ui.horizontal(|ui| {
                                                        if ui.button("Keep Local").clicked() {
                                                            action = Some(
                                                                ChromeAction::ResolveSyncConflict {
                                                                    key: conflict.key.clone(),
                                                                    choice: nomad_engine::SyncConflictChoice::Local,
                                                                },
                                                            );
                                                        }
                                                        if ui.button("Use Remote").clicked() {
                                                            action = Some(
                                                                ChromeAction::ResolveSyncConflict {
                                                                    key: conflict.key.clone(),
                                                                    choice: nomad_engine::SyncConflictChoice::Remote,
                                                                },
                                                            );
                                                        }
                                                    });
                                                });
                                            }
                                        }
                                        SettingsSection::Advanced => {
                                            settings_heading(
                                                ui,
                                                "Advanced",
                                                "Diagnostics and browser tools.",
                                            );
                                            settings_card(ui, |ui| {
                                                if settings_row_button(
                                                    ui,
                                                    "Memory",
                                                    "Inspect tab resource use and sleeping state.",
                                                )
                                                .clicked()
                                                {
                                                    settings_section = SettingsSection::Memory;
                                                }
                                                settings_divider(ui);
                                                if settings_row_button(
                                                    ui,
                                                    "Commands",
                                                    "Open the browser command palette.",
                                                )
                                                .clicked()
                                                {
                                                    commands_visible = true;
                                                    settings_visible = false;
                                                }
                                                settings_divider(ui);
                                                if settings_row_button(
                                                    ui,
                                                    "Developer Tools",
                                                    "Inspect the active page.",
                                                )
                                                .clicked()
                                                {
                                                    devtools_visible = true;
                                                    action = Some(ChromeAction::OpenDevTools);
                                                    settings_visible = false;
                                                }
                                                settings_divider(ui);
                                                if settings_row_button(
                                                    ui,
                                                    "Reader Mode",
                                                    "Show a simplified version of the active page.",
                                                )
                                                .clicked()
                                                {
                                                    reader_visible = !reader_visible;
                                                    action = Some(ChromeAction::ToggleReader);
                                                    settings_visible = false;
                                                }
                                                settings_divider(ui);
                                                if settings_row_button(
                                                    ui,
                                                    "Split View",
                                                    "Open the active page beside another pane.",
                                                )
                                                .clicked()
                                                {
                                                    action = Some(ChromeAction::SplitActive(
                                                        SplitOrientation::Vertical,
                                                    ));
                                                    settings_visible = false;
                                                }
                                            });
                                            if let Some(media) = active_media.as_ref() {
                                                ui.add_space(layout::settings::SPACE);
                                                settings_card(ui, |ui| {
                                                    ui.strong(if media.title.is_empty() {
                                                        "Media".to_owned()
                                                    } else {
                                                        media.title.clone()
                                                    });
                                                    ui.small(format_media_details(media));
                                                    ui.horizontal(|ui| {
                                                        if ui
                                                            .button(if media.playing {
                                                                "Pause"
                                                            } else {
                                                                "Play"
                                                            })
                                                            .clicked()
                                                        {
                                                            if let Some(tab_id) = shell.active_tab() {
                                                                action = Some(
                                                                    ChromeAction::MediaSessionAction {
                                                                        tab_id,
                                                                        action: if media.playing {
                                                                            MediaSessionActionType::Pause
                                                                        } else {
                                                                            MediaSessionActionType::Play
                                                                        },
                                                                    },
                                                                );
                                                            }
                                                        }
                                                        if ui.button("Stop").clicked() {
                                                            if let Some(tab_id) = shell.active_tab() {
                                                                action = Some(
                                                                    ChromeAction::MediaSessionAction {
                                                                        tab_id,
                                                                        action: MediaSessionActionType::Stop,
                                                                    },
                                                                );
                                                            }
                                                        }
                                                    });
                                                });
                                            }
                                        }
                                        SettingsSection::Bookmarks => {
                                            settings_heading(
                                                ui,
                                                "Bookmarks",
                                                "Organize saved pages without leaving Settings.",
                                            );
                                            ui.horizontal(|ui| {
                                                ui.add(
                                                    TextEdit::singleline(
                                                        &mut bookmark_folder_name,
                                                    )
                                                    .hint_text("New folder")
                                                    .desired_width(220.0),
                                                );
                                                if ui.button("Create Folder").clicked()
                                                    && !bookmark_folder_name.trim().is_empty()
                                                {
                                                    action = Some(
                                                        ChromeAction::CreateBookmarkFolder(
                                                            bookmark_folder_name
                                                                .trim()
                                                                .to_owned(),
                                                        ),
                                                    );
                                                    bookmark_folder_name.clear();
                                                }
                                                if ui
                                                    .button(if active_bookmarked {
                                                        "Remove Current Page"
                                                    } else {
                                                        "Bookmark Current Page"
                                                    })
                                                    .clicked()
                                                {
                                                    action = Some(ChromeAction::ToggleBookmark);
                                                }
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            for folder in &bookmark_folders {
                                                settings_card(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        if bookmark_folder_rename_id
                                                            == Some(folder.id)
                                                        {
                                                            ui.add(
                                                                TextEdit::singleline(
                                                                    &mut bookmark_folder_rename,
                                                                )
                                                                .desired_width(220.0),
                                                            );
                                                            if ui.button("Save").clicked() {
                                                                action = Some(
                                                                    ChromeAction::RenameBookmarkFolder {
                                                                        id: folder.id,
                                                                        name: bookmark_folder_rename
                                                                            .trim()
                                                                            .to_owned(),
                                                                    },
                                                                );
                                                                bookmark_folder_rename_id = None;
                                                            }
                                                        } else {
                                                            ui.strong(&folder.name);
                                                            if ui.button("Rename").clicked() {
                                                                bookmark_folder_rename_id =
                                                                    Some(folder.id);
                                                                bookmark_folder_rename
                                                                    .clone_from(&folder.name);
                                                            }
                                                        }
                                                        if ui.button("Delete").clicked() {
                                                            action = Some(
                                                                ChromeAction::RemoveBookmarkFolder(
                                                                    folder.id,
                                                                ),
                                                            );
                                                        }
                                                    });
                                                });
                                                ui.add_space(layout::settings::LIST_SPACE);
                                            }
                                            if bookmarks.is_empty() {
                                                settings_empty_state(
                                                    ui,
                                                    "No bookmarks yet",
                                                    "Pages you bookmark will appear here.",
                                                );
                                            }
                                            for bookmark in &bookmarks {
                                                settings_card(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.vertical(|ui| {
                                                            if bookmark_edit_id
                                                                == Some(bookmark.id)
                                                            {
                                                                ui.add(
                                                                    TextEdit::singleline(
                                                                        &mut bookmark_edit_title,
                                                                    )
                                                                    .desired_width(250.0),
                                                                );
                                                            } else {
                                                                ui.strong(&bookmark.title);
                                                            }
                                                            ui.label(
                                                                egui::RichText::new(
                                                                    bookmark.url.as_str(),
                                                                )
                                                                .size(12.0)
                                                                .color(
                                                                    egui::Color32::from_white_alpha(
                                                                        135,
                                                                    ),
                                                                ),
                                                            );
                                                        });
                                                        ui.with_layout(
                                                            egui::Layout::right_to_left(
                                                                egui::Align::Center,
                                                            ),
                                                            |ui| {
                                                                if ui.button("Delete").clicked() {
                                                                    action = Some(
                                                                        ChromeAction::RemoveBookmark(
                                                                            bookmark.id,
                                                                        ),
                                                                    );
                                                                }
                                                                if bookmark_edit_id
                                                                    == Some(bookmark.id)
                                                                {
                                                                    if ui.button("Save").clicked() {
                                                                        action = Some(
                                                                            ChromeAction::RenameBookmark {
                                                                                id: bookmark.id,
                                                                                title: bookmark_edit_title
                                                                                    .trim()
                                                                                    .to_owned(),
                                                                            },
                                                                        );
                                                                        bookmark_edit_id = None;
                                                                    }
                                                                } else if ui
                                                                    .button("Rename")
                                                                    .clicked()
                                                                {
                                                                    bookmark_edit_id =
                                                                        Some(bookmark.id);
                                                                    bookmark_edit_title
                                                                        .clone_from(&bookmark.title);
                                                                }
                                                                if ui.button("Open").clicked() {
                                                                    action = Some(
                                                                        ChromeAction::OpenBookmark(
                                                                            bookmark.id,
                                                                        ),
                                                                    );
                                                                }
                                                            },
                                                        );
                                                    });
                                                });
                                                ui.add_space(layout::settings::LIST_SPACE);
                                            }
                                        }
                                        SettingsSection::History => {
                                            settings_heading(
                                                ui,
                                                "History",
                                                "Search and reopen pages visited on this Mac.",
                                            );
                                            ui.add(
                                                TextEdit::singleline(&mut history_query)
                                                    .hint_text("Search history")
                                                    .desired_width(f32::INFINITY),
                                            );
                                            ui.add_space(layout::settings::SPACE);
                                            if history.is_empty() {
                                                settings_empty_state(
                                                    ui,
                                                    "No history yet",
                                                    "Visited pages will appear here.",
                                                );
                                            }
                                            for visit in history.iter().take(100) {
                                                if settings_row_button(
                                                    ui,
                                                    visit.url.host_str().unwrap_or("Page"),
                                                    visit.url.as_str(),
                                                )
                                                .clicked()
                                                {
                                                    action = Some(
                                                        ChromeAction::NavigateFromHistory(
                                                            visit.url.to_string(),
                                                        ),
                                                    );
                                                }
                                                settings_divider(ui);
                                            }
                                        }
                                        SettingsSection::Downloads => {
                                            settings_heading(
                                                ui,
                                                "Downloads",
                                                "Track files saved by Nomad.",
                                            );
                                            if downloads.is_empty() {
                                                settings_empty_state(
                                                    ui,
                                                    "No downloads yet",
                                                    "Downloaded files and their progress will appear here.",
                                                );
                                            }
                                            for download in downloads.iter().rev() {
                                                settings_card(ui, |ui| {
                                                    let filename = download
                                                        .destination
                                                        .file_name()
                                                        .and_then(|name| name.to_str())
                                                        .unwrap_or("download");
                                                    ui.horizontal(|ui| {
                                                        ui.strong(filename);
                                                        ui.with_layout(
                                                            egui::Layout::right_to_left(
                                                                egui::Align::Center,
                                                            ),
                                                            |ui| {
                                                                ui.label(download_state_label(
                                                                    download.state,
                                                                ));
                                                            },
                                                        );
                                                    });
                                                    if let Some(total) = download.total_bytes {
                                                        let progress = if total == 0 {
                                                            1.0
                                                        } else {
                                                            download.bytes_received as f32
                                                                / total as f32
                                                        };
                                                        ui.add(
                                                            ProgressBar::new(
                                                                progress.clamp(0.0, 1.0),
                                                            )
                                                            .show_percentage(),
                                                        );
                                                    }
                                                    ui.small(
                                                        download.destination.display().to_string(),
                                                    );
                                                    ui.horizontal(|ui| {
                                                        if matches!(
                                                            download.state,
                                                            DownloadState::Queued
                                                                | DownloadState::InProgress
                                                        ) && ui.button("Cancel").clicked()
                                                        {
                                                            action = Some(
                                                                ChromeAction::CancelDownload(
                                                                    download.id,
                                                                ),
                                                            );
                                                        }
                                                        if download.state
                                                            == DownloadState::Failed
                                                            && ui.button("Retry").clicked()
                                                        {
                                                            action = Some(
                                                                ChromeAction::RetryDownload(
                                                                    download.id,
                                                                ),
                                                            );
                                                        }
                                                    });
                                                });
                                                ui.add_space(layout::settings::LIST_SPACE);
                                            }
                                        }
                                        SettingsSection::Workspaces => {
                                            settings_heading(
                                                ui,
                                                "Workspaces",
                                                "Separate tabs and site storage by context.",
                                            );
                                            settings_card(ui, |ui| {
                                                for workspace in shell.workspaces() {
                                                    let selected = workspace.id
                                                        == shell.active_workspace();
                                                    if ui
                                                        .selectable_label(
                                                            selected,
                                                            &workspace.name,
                                                        )
                                                        .clicked()
                                                        && !selected
                                                    {
                                                        action = Some(
                                                            ChromeAction::SelectWorkspace(
                                                                workspace.id,
                                                            ),
                                                        );
                                                    }
                                                }
                                                if ui.button("New Workspace").clicked() {
                                                    action = Some(
                                                        ChromeAction::CreateWorkspace(format!(
                                                            "Workspace {}",
                                                            shell.workspaces().len() + 1
                                                        )),
                                                    );
                                                }
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                let active_override = shell
                                                    .workspace(active_workspace)
                                                    .and_then(|workspace| {
                                                        workspace.resolver.clone()
                                                    });
                                                // Keep the editor draft aligned with the
                                                // active workspace and its override.
                                                if workspace_resolver_draft
                                                    .as_ref()
                                                    .is_none_or(|(id, _)| {
                                                        *id != active_workspace
                                                    })
                                                {
                                                    workspace_resolver_draft =
                                                        active_override
                                                            .clone()
                                                            .map(|resolver| {
                                                                (active_workspace, resolver)
                                                            });
                                                }
                                                settings_field_label(
                                                    ui,
                                                    "DNS override for this workspace",
                                                );
                                                let current_mode =
                                                    active_override.as_ref().map(|r| r.mode);
                                                ui.horizontal(|ui| {
                                                    if ui
                                                        .selectable_label(
                                                            current_mode.is_none(),
                                                            "Inherit global",
                                                        )
                                                        .clicked()
                                                        && current_mode.is_some()
                                                    {
                                                        action = Some(
                                                            ChromeAction::SetWorkspaceResolver {
                                                                workspace: active_workspace,
                                                                resolver: None,
                                                            },
                                                        );
                                                    }
                                                    for mode in [
                                                        ResolverMode::System,
                                                        ResolverMode::Doh,
                                                        ResolverMode::Dot,
                                                        ResolverMode::Custom,
                                                    ] {
                                                        if ui
                                                            .selectable_label(
                                                                current_mode == Some(mode),
                                                                mode.label(),
                                                            )
                                                            .clicked()
                                                            && current_mode != Some(mode)
                                                        {
                                                            let mut resolver = active_override
                                                                .clone()
                                                                .unwrap_or_else(|| {
                                                                    shell
                                                                        .settings()
                                                                        .resolver
                                                                        .clone()
                                                                });
                                                            resolver.mode = mode;
                                                            action = Some(
                                                                ChromeAction::SetWorkspaceResolver {
                                                                    workspace: active_workspace,
                                                                    resolver: Some(resolver),
                                                                },
                                                            );
                                                        }
                                                    }
                                                });
                                                match current_mode {
                                                    None => {
                                                        ui.small(format!(
                                                            "Inheriting the global resolver: {}",
                                                            shell.settings().resolver.mode.label()
                                                        ));
                                                    }
                                                    Some(ResolverMode::System) => {
                                                        ui.small(
                                                            "This workspace resolves through the platform resolver.",
                                                        );
                                                    }
                                                    Some(_) => {
                                                        let Some((id, draft)) =
                                                            workspace_resolver_draft.as_mut()
                                                        else {
                                                            return;
                                                        };
                                                        if *id != active_workspace {
                                                            return;
                                                        }
                                                        match draft.mode {
                                                            ResolverMode::Doh => {
                                                                settings_field_label(
                                                                    ui,
                                                                    "DoH server URL",
                                                                );
                                                                ui.add(
                                                                    TextEdit::singleline(
                                                                        &mut draft.server_url,
                                                                    )
                                                                    .hint_text(
                                                                        "https://dns.example/dns-query",
                                                                    )
                                                                    .desired_width(
                                                                        f32::INFINITY,
                                                                    ),
                                                                );
                                                            }
                                                            ResolverMode::Dot => {
                                                                settings_field_label(
                                                                    ui,
                                                                    "DoT server host",
                                                                );
                                                                ui.add(
                                                                    TextEdit::singleline(
                                                                        &mut draft.server_host,
                                                                    )
                                                                    .hint_text(
                                                                        "dns.example:853",
                                                                    )
                                                                    .desired_width(
                                                                        f32::INFINITY,
                                                                    ),
                                                                );
                                                            }
                                                            ResolverMode::Custom => {
                                                                settings_field_label(
                                                                    ui,
                                                                    "Protocol",
                                                                );
                                                                ui.horizontal(|ui| {
                                                                    for protocol in [
                                                                        CustomResolverProtocol::Udp,
                                                                        CustomResolverProtocol::Doh,
                                                                        CustomResolverProtocol::Dot,
                                                                    ] {
                                                                        ui.selectable_value(
                                                                            &mut draft
                                                                                .custom_protocol,
                                                                            protocol,
                                                                            protocol.label(),
                                                                        );
                                                                    }
                                                                });
                                                                settings_field_label(
                                                                    ui,
                                                                    "DNS server",
                                                                );
                                                                ui.add(
                                                                    TextEdit::singleline(
                                                                        &mut draft.custom_server,
                                                                    )
                                                                    .hint_text(
                                                                        match draft.custom_protocol {
                                                                            CustomResolverProtocol::Udp => "1.1.1.1:53",
                                                                            CustomResolverProtocol::Doh => "https://dns.example/dns-query",
                                                                            CustomResolverProtocol::Dot => "dns.example:853",
                                                                        },
                                                                    )
                                                                    .desired_width(
                                                                        f32::INFINITY,
                                                                    ),
                                                                );
                                                            }
                                                            ResolverMode::System => {}
                                                        }
                                                        if ui.button("Save override").clicked() {
                                                            action = Some(
                                                                ChromeAction::SetWorkspaceResolver {
                                                                    workspace: active_workspace,
                                                                    resolver: Some(draft.clone()),
                                                                },
                                                            );
                                                        }
                                                    }
                                                }
                                            });
                                            settings_card(ui, |ui| {
                                                settings_field_label(ui, "New container");
                                                ui.add(
                                                    TextEdit::singleline(&mut container_name)
                                                        .desired_width(f32::INFINITY),
                                                );
                                                settings_toggle(
                                                    ui,
                                                    &mut container_ephemeral,
                                                    "Temporary container",
                                                    "Discard its site data when the session ends.",
                                                );
                                                if ui.button("Create Container").clicked()
                                                    && !container_name.trim().is_empty()
                                                {
                                                    action = Some(
                                                        ChromeAction::CreateContainer {
                                                            name: container_name.trim().to_owned(),
                                                            ephemeral: container_ephemeral,
                                                        },
                                                    );
                                                    container_name.clear();
                                                }
                                            });
                                        }
                                        SettingsSection::Permissions => {
                                            settings_heading(
                                                ui,
                                                "Permissions",
                                                "Review site requests and saved decisions.",
                                            );
                                            if permission_prompts.is_empty()
                                                && shell.permission_rules().is_empty()
                                            {
                                                settings_empty_state(
                                                    ui,
                                                    "No site permissions",
                                                    "Permission requests and saved decisions will appear here.",
                                                );
                                            }
                                            for prompt in &permission_prompts {
                                                settings_card(ui, |ui| {
                                                    ui.strong(format!(
                                                        "{} wants {}",
                                                        prompt.site,
                                                        prompt.kind.label()
                                                    ));
                                                    ui.horizontal(|ui| {
                                                        for (label, decision) in [
                                                            (
                                                                "Allow Once",
                                                                PermissionDecision::AllowOnce,
                                                            ),
                                                            (
                                                                "Allow",
                                                                PermissionDecision::Allow,
                                                            ),
                                                            (
                                                                "Block",
                                                                PermissionDecision::Block,
                                                            ),
                                                        ] {
                                                            if ui.button(label).clicked() {
                                                                action = Some(
                                                                    ChromeAction::ResolvePermission {
                                                                        id: prompt.id,
                                                                        decision,
                                                                    },
                                                                );
                                                            }
                                                        }
                                                    });
                                                });
                                                ui.add_space(layout::settings::LIST_SPACE);
                                            }
                                            for rule in shell.permission_rules() {
                                                settings_card(ui, |ui| {
                                                    ui.strong(&rule.site);
                                                    ui.small(format!(
                                                        "{} · {:?}",
                                                        rule.kind.label(),
                                                        rule.decision
                                                    ));
                                                });
                                                ui.add_space(layout::settings::LIST_SPACE);
                                            }
                                        }
                                        SettingsSection::Autofill => {
                                            settings_heading(
                                                ui,
                                                "Passwords & Autofill",
                                                "Credentials remain in the native credential manager.",
                                            );
                                            settings_card(ui, |ui| {
                                                if ui.button("Scan Current Page").clicked() {
                                                    action = Some(ChromeAction::RequestAutofill);
                                                }
                                                if autofill_tab == shell.active_tab() {
                                                    ui.small(format!(
                                                        "{} form fields detected",
                                                        autofill_fields.len()
                                                    ));
                                                } else {
                                                    ui.small("Scan the active page to detect login fields.");
                                                }
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            settings_card(ui, |ui| {
                                                settings_field_label(ui, "Username");
                                                ui.add(
                                                    TextEdit::singleline(
                                                        &mut autofill_username,
                                                    )
                                                    .desired_width(f32::INFINITY),
                                                );
                                                settings_field_label(ui, "Password");
                                                ui.add(
                                                    TextEdit::singleline(
                                                        &mut autofill_password,
                                                    )
                                                    .password(true)
                                                    .desired_width(f32::INFINITY),
                                                );
                                                ui.horizontal(|ui| {
                                                    if ui.button("Load Saved").clicked() {
                                                        action = Some(
                                                            ChromeAction::FillSavedPassword(
                                                                autofill_username.clone(),
                                                            ),
                                                        );
                                                    }
                                                    if ui.button("Save").clicked() {
                                                        action = Some(
                                                            ChromeAction::SaveCredential {
                                                                username: autofill_username.clone(),
                                                                password: autofill_password.clone(),
                                                            },
                                                        );
                                                    }
                                                    if ui.button("Fill Page").clicked() {
                                                        action = Some(
                                                            ChromeAction::FillEnteredPassword {
                                                                username: autofill_username.clone(),
                                                                password: autofill_password.clone(),
                                                            },
                                                        );
                                                    }
                                                });
                                            });
                                        }
                                        SettingsSection::Memory => {
                                            settings_heading(
                                                ui,
                                                "Memory",
                                                "Manage tab lifecycle and resource use.",
                                            );
                                            settings_card(ui, |ui| {
                                                ui.strong(format!(
                                                    "{} of {} used",
                                                    format_bytes(
                                                        memory_diagnostics.browser_bytes
                                                    ),
                                                    format_bytes(memory_diagnostics.budget_bytes)
                                                ));
                                                ui.small(format!(
                                                    "{} active · {} sleeping · {} suspended",
                                                    memory_diagnostics.active_tabs,
                                                    memory_diagnostics.sleeping_tabs,
                                                    memory_diagnostics.suspended_tabs
                                                ));
                                                ui.horizontal(|ui| {
                                                    for mode in [
                                                        MemoryMode::Automatic,
                                                        MemoryMode::LowMemory,
                                                        MemoryMode::Balanced,
                                                        MemoryMode::MaximumPerformance,
                                                    ] {
                                                        if ui
                                                            .selectable_label(
                                                                shell.memory_mode() == mode,
                                                                mode.label(),
                                                            )
                                                            .clicked()
                                                        {
                                                            action = Some(
                                                                ChromeAction::SetMemoryMode(mode),
                                                            );
                                                        }
                                                    }
                                                });
                                                if ui.button("Reclaim Memory Now").clicked() {
                                                    action = Some(ChromeAction::ReclaimMemory);
                                                }
                                            });
                                            ui.add_space(layout::settings::SPACE);
                                            for tab in shell.tabs() {
                                                settings_card(ui, |ui| {
                                                    let title = tab
                                                        .url
                                                        .as_ref()
                                                        .and_then(url::Url::host_str)
                                                        .unwrap_or("New tab");
                                                    ui.strong(title);
                                                    ui.small(format!(
                                                        "{:?} · {}",
                                                        tab.lifecycle,
                                                        format_bytes(tab.memory_bytes)
                                                    ));
                                                    ui.horizontal(|ui| {
                                                        if tab.lifecycle
                                                            == TabLifecycle::Sleeping
                                                            && ui.button("Wake").clicked()
                                                        {
                                                            action = Some(
                                                                ChromeAction::WakeTab(tab.id),
                                                            );
                                                        } else if !matches!(
                                                            tab.lifecycle,
                                                            TabLifecycle::Active
                                                                | TabLifecycle::Suspended
                                                                | TabLifecycle::Archived
                                                        ) && ui.button("Sleep").clicked()
                                                        {
                                                            action = Some(
                                                                ChromeAction::SleepTab(tab.id),
                                                            );
                                                        }
                                                        if matches!(
                                                            tab.lifecycle,
                                                            TabLifecycle::Suspended
                                                                | TabLifecycle::Archived
                                                        ) && ui.button("Resume").clicked()
                                                        {
                                                            action = Some(
                                                                ChromeAction::ResumeTab(tab.id),
                                                            );
                                                        }
                                                    });
                                                });
                                                ui.add_space(layout::settings::LIST_SPACE);
                                            }
                                        }
                                    });
                        });
                        if matches!(
                            settings_section,
                            SettingsSection::General
                                | SettingsSection::Privacy
                                | SettingsSection::Sync
                        ) {
                            ui.separator();
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Save Changes").clicked() {
                                        action = Some(ChromeAction::ApplySettings(
                                            settings_draft.clone(),
                                        ));
                                    }
                                },
                            );
                        }
                        });
                    });
            }

            if autofill_visible {
                egui::Window::new("Password fill")
                    .frame(zen_popup_frame())
                    .default_width(440.0)
                    .resizable(true)
                    .show(context, |ui| {
                        if let Some(url) = active_url.as_ref() {
                            ui.label(format!("Site: {}", url.origin().ascii_serialization()));
                        } else {
                            ui.label("No active HTTP(S) site is available.");
                        }
                        ui.label(
                            "Nomad reads form metadata only. Credential values stay in the native credential manager until you confirm an action.",
                        );
                        if autofill_tab != shell.active_tab() {
                            ui.label("The active page changed; scan the current page again.");
                        } else if autofill_fields.is_empty() {
                            ui.label("No form fields were found on this page.");
                        } else {
                            let mut kinds = Vec::new();
                            for field in autofill_fields.iter().take(16) {
                                let kind = classify_autofill_field(field);
                                if !matches!(kind, AutofillFieldKind::Unknown) {
                                    kinds.push(format!("{kind:?}: {}", field.name));
                                }
                            }
                            if kinds.is_empty() {
                                ui.label("No username/password fields were classified.");
                            } else {
                                ui.label(format!("Detected fields: {}", kinds.join(" · ")));
                            }
                        }
                        ui.label("Username");
                        ui.add(TextEdit::singleline(&mut autofill_username));
                        ui.label("Password");
                        ui.add(TextEdit::singleline(&mut autofill_password).password(true));
                        ui.horizontal(|ui| {
                            if ui.button("Load saved credential").clicked() {
                                action = Some(ChromeAction::FillSavedPassword(
                                    autofill_username.clone(),
                                ));
                            }
                            if ui.button("Save credential").clicked() {
                                action = Some(ChromeAction::SaveCredential {
                                    username: autofill_username.clone(),
                                    password: autofill_password.clone(),
                                });
                            }
                            if ui.button("Fill entered password").clicked() {
                                action = Some(ChromeAction::FillEnteredPassword {
                                    username: autofill_username.clone(),
                                    password: autofill_password.clone(),
                                });
                            }
                            if ui.button("Close").clicked() {
                                autofill_visible = false;
                            }
                        });
                    });
            }

            if permissions_visible {
                egui::Window::new("Permissions")
                    .frame(zen_popup_frame())
                    .default_width(420.0)
                    .resizable(true)
                    .show(context, |ui| {
                        if permission_prompts.is_empty() {
                            ui.label("No permission requests are waiting.");
                        }
                        for prompt in &permission_prompts {
                            ui.label(format!("{} wants {}", prompt.site, prompt.kind.label()));
                            ui.horizontal(|ui| {
                                if ui.small_button("Allow once").clicked() {
                                    action = Some(ChromeAction::ResolvePermission {
                                        id: prompt.id,
                                        decision: PermissionDecision::AllowOnce,
                                    });
                                }
                                if ui.small_button("Allow").clicked() {
                                    action = Some(ChromeAction::ResolvePermission {
                                        id: prompt.id,
                                        decision: PermissionDecision::Allow,
                                    });
                                }
                                if ui.small_button("Block").clicked() {
                                    action = Some(ChromeAction::ResolvePermission {
                                        id: prompt.id,
                                        decision: PermissionDecision::Block,
                                    });
                                }
                            });
                            ui.separator();
                        }
                        if !shell.permission_rules().is_empty() {
                            ui.collapsing("Saved decisions", |ui| {
                                for rule in shell.permission_rules() {
                                    ui.label(format!(
                                        "{} · {} · {:?}",
                                        rule.site,
                                        rule.kind.label(),
                                        rule.decision
                                    ));
                                }
                            });
                        }
                    });
            }

            if privacy_visible {
                egui::Window::new("Privacy & security")
                    .frame(zen_popup_frame())
                    .default_width(420.0)
                    .resizable(false)
                    .show(context, |ui| {
                        ui.heading(format!("{} mode", privacy_diagnostics.mode.label()));
                        ui.label(format!(
                            "Route: {} · DNS: {}",
                            network_route.mode_label(),
                            network_route.dns_route_label()
                        ));
                        ui.small(format!(
                            "Tunnel: {}",
                            tunnel_status_label(&network_route)
                        ));
                        ui.small(format!(
                            "Live connector: {} · DNS: {}",
                            network_diagnostics.state().label(),
                            network_diagnostics.dns_route().label()
                        ));
                        if let Some(destination) = network_diagnostics.destination() {
                            ui.small(format!("Last destination: {destination}"));
                        }
                        if let Some(proxy) = network_diagnostics.proxy() {
                            ui.small(format!("Observed proxy: {proxy}"));
                        } else if network_diagnostics.state()
                            == nomad_engine::ConnectionState::Connected
                        {
                            ui.small("Observed proxy: none (direct connection)");
                        }
                        if let Some(protocol) = network_diagnostics.tls_protocol() {
                            ui.small(format!(
                                "TLS: {protocol} · cipher: {} · ALPN: {}{}",
                                network_diagnostics.tls_cipher_suite().unwrap_or("unknown"),
                                network_diagnostics.alpn_protocol().unwrap_or("unknown"),
                                if network_diagnostics.used_ech() {
                                    " · ECH"
                                } else {
                                    ""
                                }
                            ));
                        }
                        ui.small(format!(
                            "Connections: {} succeeded · {} failed",
                            network_diagnostics.successful_connections(),
                            network_diagnostics.failed_connections()
                        ));
                        if let Some(error) = network_diagnostics.last_error() {
                            ui.small(format!("Last connection error: {error}"));
                        }
                        ui.horizontal(|ui| {
                            for (label, switches) in [
                                ("Direct", Switches::direct()),
                                ("UMC", Switches::umc()),
                                ("Xray", Switches::xray()),
                            ] {
                                if ui
                                    .selectable_label(network_route.mode_label() == label, label)
                                    .clicked()
                                {
                                    action = Some(ChromeAction::SetRoute(switches));
                                }
                            }
                        });
                        if let Some(decision) = &route_decision {
                            ui.label(format!(
                                "Site route: {}{}",
                                decision.action().label(),
                                decision
                                    .matched_site()
                                    .map_or(String::new(), |site| format!(" ({site})"))
                            ));
                        }
                        if let Some(resource) = &umc_resource {
                            let security = resource.security_info();
                            ui.separator();
                            ui.label("UMC resource");
                            ui.small(format!(
                                "Service identity: {}",
                                resource.service_identity()
                            ));
                            ui.small(format!("Path: {}", resource.path()));
                            ui.small(format!("Port: {}", resource.port()));
                            ui.small(format!("Stream target: {}", resource.stream_target()));
                            ui.small(format!(
                                "Identity: {}",
                                security.identity_kind().label()
                            ));
                            ui.small(format!("Trust: {}", security.trust_state().label()));
                            ui.small(format!(
                                "Connection path: {}",
                                security.path_kind().label()
                            ));
                            ui.small(format!(
                                "Session: {}",
                                security.session_security().label()
                            ));
                        }
                        if let Some(diagnostics) = &umc_diagnostics {
                            ui.separator();
                            ui.label("UMC runtime");
                            ui.small(format!("Application protocol: {}", diagnostics.protocol_id()));
                            ui.small(format!(
                                "Gateway destination: {}",
                                if diagnostics.gateway_configured() {
                                    "configured"
                                } else {
                                    "not configured; explicit identities only"
                                }
                            ));
                            ui.small(format!(
                                "Active application streams: {}",
                                diagnostics.active_streams()
                            ));
                            ui.small(format!(
                                "Browser UMC application sessions: {}",
                                diagnostics.active_application_sessions()
                            ));
                            if let Some(session) = diagnostics.last_session() {
                                ui.small(format!(
                                    "Session: {} · paths: {} · relayed: {}",
                                    session.state().label(),
                                    session.active_paths(),
                                    if session.relayed() { "yes" } else { "no" }
                                ));
                                if let Some(trust) = session.peer_trust_state() {
                                    ui.small(format!("Peer trust: {}", trust.label()));
                                }
                                for path in session.paths().iter().take(3) {
                                    ui.small(format!(
                                        "Path {}: {} · {} · RTT {} ms · MTU {}{}",
                                        path.path_id(),
                                        path.state(),
                                        path.carrier_type_id(),
                                        path.estimated_rtt_ms(),
                                        path.current_mtu(),
                                        if path.primary() { " · primary" } else { "" }
                                    ));
                                }
                                if let Some(privacy) = session.privacy() {
                                    ui.small(format!(
                                        "Privacy profile: {} → {} · hops: {} · direct: {}",
                                        privacy.requested_profile(),
                                        privacy.effective_profile(),
                                        privacy.hop_count(),
                                        if privacy.direct_path_allowed() {
                                            "allowed"
                                        } else {
                                            "blocked"
                                        }
                                    ));
                                    ui.small(format!(
                                        "Padding: {} · anonymous authorization: {}",
                                        if privacy.traffic_padding_active() {
                                            "active"
                                        } else {
                                            "inactive"
                                        },
                                        if privacy.anonymous_authorization_active() {
                                            "active"
                                        } else {
                                            "inactive"
                                        }
                                    ));
                                }
                            }
                            if let Some(error) = diagnostics.last_error() {
                                ui.small(format!("Last UMC error: {error}"));
                            }
                        }
                        if let Some(proxy) = network_route.proxy() {
                            ui.small(format!("Proxy endpoint: {}", proxy.uri()));
                        }
                        ui.label(format!(
                            "Security: {} — {}",
                            security_info.level.label(),
                            security_info.explanation
                        ));
                        ui.small(format!(
                            "Connection: {}",
                            connection_transport_label(active_url.as_ref())
                        ));
                        ui.small(format!(
                            "DNS resolver: {}",
                            network_route.dns_route_label()
                        ));
                        ui.separator();
                        ui.label("Resolver engine");
                        ui.small(resolver_effective_label(
                            &effective_resolver,
                            resolver_override_active,
                        ));
                        match resolver_status.last() {
                            Some(lookup) => {
                                ui.small(format!(
                                    "Last lookup: {}",
                                    resolver_lookup_label(lookup)
                                ));
                            }
                            None => {
                                ui.small("Last lookup: none recorded");
                            }
                        }
                        ui.small(format!(
                            "Handled by this engine: System {} · DoH {} · DoT {} · Custom {}",
                            resolver_status.handled(ResolverMode::System),
                            resolver_status.handled(ResolverMode::Doh),
                            resolver_status.handled(ResolverMode::Dot),
                            resolver_status.handled(ResolverMode::Custom),
                        ));
                        ui.small(
                            "Engine scope only: direct-mode browser requests still resolve through the system resolver.",
                        );
                        ui.small(format!("Origin: {}", security_info.origin));
                        ui.label(format!(
                            "Blocked privacy resources: {}",
                            privacy_diagnostics.blocked_resources
                        ));
                        ui.small(format!(
                            "Ads: {} · Trackers: {}",
                            privacy_diagnostics.blocked_ads,
                            privacy_diagnostics.blocked_trackers
                        ));
                        ui.separator();
                        ui.label(format!(
                            "{} Tracking protection",
                            status_mark(privacy_diagnostics.tracking_protection)
                        ));
                        ui.label(format!(
                            "{} Storage partitioning",
                            status_mark(privacy_diagnostics.storage_partitioning)
                        ));
                        ui.label(format!(
                            "{} Third-party cookie blocking",
                            status_mark(privacy_diagnostics.third_party_cookie_blocking)
                        ));
                        ui.label(format!(
                            "{} Reduced cross-site referrers",
                            status_mark(privacy_diagnostics.reduced_cross_site_referrers)
                        ));
                        ui.label(format!(
                            "{} Anti-fingerprinting baseline",
                            status_mark(privacy_diagnostics.anti_fingerprinting)
                        ));
                        ui.label(format!(
                            "{} Advanced fingerprint reduction",
                            status_mark(privacy_diagnostics.advanced_fingerprinting)
                        ));
                        ui.label(format!(
                            "{} WebRTC leak control",
                            status_mark(privacy_diagnostics.block_webrtc)
                        ));
                        ui.label(format!(
                            "{} DNS leak control",
                            status_mark(privacy_diagnostics.dns_leak_protection)
                        ));
                        ui.small(
                            "These indicators describe enforced browser policy; site permission prompts remain explicit.",
                        );
                    });
            }

            if let Some(error) = navigation_error.as_deref() {
                egui::Window::new("Navigation blocked")
                    .frame(zen_popup_frame())
                    .default_width(440.0)
                    .resizable(false)
                    .show(context, |ui| {
                        ui.colored_label(egui::Color32::LIGHT_RED, error);
                        if ui.button("Open Privacy & security").clicked() {
                            action = Some(ChromeAction::OpenSettings(SettingsSection::Privacy));
                            privacy_visible = false;
                        }
                    });
            }

            if session_recovery_prompt {
                egui::Window::new("Recover previous session")
                    .frame(zen_popup_frame())
                    .collapsible(false)
                    .resizable(false)
                    .default_width(460.0)
                    .show(context, |ui| {
                        ui.heading("Nomad did not close cleanly");
                        ui.label(
                            "The previous session was saved before the interruption. Choose how to continue.",
                        );
                        ui.horizontal(|ui| {
                            if ui.button("Restore session").clicked() {
                                session_recovery_prompt = false;
                                action = Some(ChromeAction::RestoreSession);
                            }
                            if ui.button("Start clean").clicked() {
                                session_recovery_prompt = false;
                                action = Some(ChromeAction::StartCleanSession);
                            }
                        });
                        ui.small("Starting clean keeps a recovery copy of the saved session.");
                    });
            }

            if let Some(tab) = shell.active_tab().and_then(|tab_id| shell.tab(tab_id)) {
                if tab.state == nomad_engine::TabState::Error {
                    egui::Window::new("Navigation error")
                        .frame(zen_popup_frame())
                        .default_width(420.0)
                        .show(context, |ui| {
                            ui.colored_label(
                                egui::Color32::LIGHT_RED,
                                tab.error
                                    .as_ref()
                                    .map_or("Navigation failed".to_owned(), |error| {
                                        format!("{error:?}")
                                    }),
                            );
                        });
                }
            }
            paint_pending_chrome_tooltip(context, backdrop_blur.clone());
        });

        if let Some(error) = page_paint_error {
            return Err(error);
        }

        if action.is_none() {
            action = self
                .pending_navigations
                .pop_front()
                .map(|(tab_id, address)| ChromeAction::NavigatePending { tab_id, address });
        }
        self.downloads_visible = downloads_visible;
        self.history_visible = history_visible;
        self.history_query = history_query;
        self.memory_visible = memory_visible;
        self.privacy_visible = privacy_visible;
        self.bookmarks_visible = bookmarks_visible;
        self.settings_visible = settings_visible;
        self.settings_section = settings_section;
        self.settings_draft = settings_draft;
        self.workspace_resolver_draft = workspace_resolver_draft;
        self.sync_recovery_input = sync_recovery_input;
        self.autofill_visible = autofill_visible;
        self.autofill_username = autofill_username;
        self.autofill_password = autofill_password;
        self.permissions_visible = permissions_visible;
        self.workspaces_visible = workspaces_visible;
        self.commands_visible = commands_visible;
        self.more_visible = more_visible;
        self.search_input = search_input;
        self.address_query_active = address_query_active;
        self.web_suggestions = web_suggestions;
        self.selected_suggestion = selected_suggestion;
        self.command_query = command_query;
        self.container_name = container_name;
        self.container_ephemeral = container_ephemeral;
        self.devtools_visible = devtools_visible;
        self.devtools_console_input = devtools_console_input;
        self.devtools_console_filters = devtools_console_filters;
        self.reader_visible = reader_visible;
        self.translation_visible = translation_visible;
        self.translation_source = translation_source;
        self.translation_target = translation_target;
        self.translation_input = translation_input;
        self.bookmark_folder_name = bookmark_folder_name;
        self.bookmark_folder_rename_id = bookmark_folder_rename_id;
        self.bookmark_folder_rename = bookmark_folder_rename;
        self.bookmark_edit_id = bookmark_edit_id;
        self.bookmark_edit_title = bookmark_edit_title;
        self.session_recovery_prompt = session_recovery_prompt;
        self.revealed_tab_url = revealed_tab_url;
        if matches!(action, Some(ChromeAction::Reload)) {
            let now = Instant::now();
            if self
                .last_reload_at
                .is_some_and(|previous| now.duration_since(previous) < Duration::from_millis(350))
            {
                action = None;
            } else {
                self.last_reload_at = Some(now);
            }
        }
        Ok(action)
    }

    pub fn toggle_devtools(&mut self) {
        self.devtools_visible = !self.devtools_visible;
    }

    pub fn open_command_palette(&mut self) {
        self.commands_visible = true;
    }

    pub fn toggle_panel(&mut self, panel: ChromePanel, settings: &BrowserSettings) {
        if panel == ChromePanel::Settings && self.settings_visible {
            self.settings_visible = false;
            return;
        }

        self.settings_section = match panel {
            ChromePanel::Downloads => SettingsSection::Downloads,
            ChromePanel::History => SettingsSection::History,
            ChromePanel::Memory => SettingsSection::Memory,
            ChromePanel::Privacy => SettingsSection::Privacy,
            ChromePanel::Bookmarks => SettingsSection::Bookmarks,
            ChromePanel::Settings => SettingsSection::General,
            ChromePanel::Permissions => SettingsSection::Permissions,
            ChromePanel::Workspaces => SettingsSection::Workspaces,
        };
        self.settings_draft = settings.clone();
        self.settings_visible = true;

        // Browser management lives in one stable surface. Keeping the legacy
        // transient panels closed prevents stacked, overlapping utility windows.
        self.downloads_visible = false;
        self.history_visible = false;
        self.memory_visible = false;
        self.privacy_visible = false;
        self.bookmarks_visible = false;
        self.permissions_visible = false;
        self.workspaces_visible = false;
    }

    pub fn toggle_translation(&mut self) {
        self.translation_visible = !self.translation_visible;
    }

    pub fn set_translation_input_if_empty(&mut self, text: String) {
        if self.translation_input.trim().is_empty() {
            self.translation_input = text;
        }
    }

    pub fn set_translation_result(&mut self, result: Result<String, String>) {
        match result {
            Ok(text) => {
                self.translation_output = Some(text);
                self.translation_error = None;
            }
            Err(error) => {
                self.translation_output = None;
                self.translation_error = Some(error);
            }
        }
    }

    pub fn set_navigation_error(&mut self, error: impl Into<String>) {
        self.navigation_error = Some(error.into());
    }

    pub fn clear_navigation_error(&mut self) {
        self.navigation_error = None;
    }

    pub fn set_sync_recovery_phrase(&mut self, phrase: String) {
        self.sync_recovery_phrase = Some(phrase);
    }

    pub fn begin_autofill_scan(&mut self, tab_id: TabId) {
        self.autofill_tab = Some(tab_id);
        self.autofill_fields.clear();
        self.autofill_visible = true;
    }

    pub fn set_autofill_fields(&mut self, tab_id: TabId, fields: Vec<AutofillFieldDescriptor>) {
        if self.autofill_tab == Some(tab_id) {
            self.autofill_fields = fields;
            self.autofill_visible = true;
        }
    }

    pub fn clear_autofill_secret(&mut self) {
        self.autofill_password.clear();
    }

    pub fn refresh_settings_draft(&mut self, settings: &BrowserSettings) {
        self.settings_draft = settings.clone();
    }

    /// Re-syncs the workspace resolver editor draft from the shell after a
    /// committed override change.
    pub fn refresh_workspace_resolver_draft(&mut self, shell: &ShellState) {
        let active = shell.active_workspace();
        self.workspace_resolver_draft = shell
            .workspace(active)
            .and_then(|workspace| workspace.resolver.clone())
            .map(|resolver| (active, resolver));
    }

    pub fn set_session_recovery_prompt(&mut self, visible: bool) {
        self.session_recovery_prompt = visible;
    }

    pub fn paint(&mut self, window: &Window, renderer: &ServoRenderer) -> Result<(), ServoError> {
        renderer
            .prepare_window_frame()
            .map_err(|error| ServoError::Native(format!("window context: {error}")))?;
        self.context
            .painter
            .clear(window.inner_size().into(), [0.0, 0.0, 0.0, 0.0]);
        self.context.paint(window);
        renderer.present();
        Ok(())
    }
}

fn zen_popup_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(34, 34, 36, 246))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_white_alpha(28)))
        .corner_radius(egui::CornerRadius::same(12))
        .inner_margin(egui::Margin::same(12))
}

fn paint_backdrop_blur(
    painter: &egui::Painter,
    rect: egui::Rect,
    renderer: Arc<Mutex<BackdropBlurRenderer>>,
    radius: f32,
) {
    painter.add(backdrop_blur_shape(rect, renderer, radius));
}

fn backdrop_blur_shape(
    rect: egui::Rect,
    renderer: Arc<Mutex<BackdropBlurRenderer>>,
    radius: f32,
) -> egui::Shape {
    backdrop_blur_shape_with_strength(rect, renderer, radius, 1.0)
}

fn backdrop_blur_shape_with_strength(
    rect: egui::Rect,
    renderer: Arc<Mutex<BackdropBlurRenderer>>,
    corner_radius: f32,
    blur_strength: f32,
) -> egui::Shape {
    egui::Shape::Callback(PaintCallback {
        rect,
        callback: Arc::new(CallbackFn::new(move |info, painter| {
            let viewport = info.viewport_in_pixels();
            let Ok(mut renderer) = renderer.lock() else {
                return;
            };
            renderer.paint(
                painter.gl(),
                viewport.left_px,
                viewport.from_bottom_px,
                viewport.width_px,
                viewport.height_px,
                corner_radius * info.pixels_per_point,
                blur_strength,
            );
        })),
    })
}

impl BackdropBlurRenderer {
    // glow exposes OpenGL state operations as unsafe; all handles are created
    // and used on the current window context inside egui's paint callback.
    #[allow(unsafe_code)]
    fn paint(
        &mut self,
        gl: &glow::Context,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        corner_radius: f32,
        blur_strength: f32,
    ) {
        use glow::HasContext as _;

        if width <= 0 || height <= 0 || self.ensure_resources(gl, width, height).is_err() {
            return;
        }
        let (Some(program), Some(vao), Some(source), Some(intermediate), Some(framebuffer)) = (
            self.program,
            self.vao,
            self.source,
            self.intermediate,
            self.framebuffer,
        ) else {
            return;
        };

        unsafe {
            let original_framebuffer = gl.get_parameter_i32(glow::DRAW_FRAMEBUFFER_BINDING);
            gl.bind_texture(glow::TEXTURE_2D, Some(source));
            gl.copy_tex_sub_image_2d(glow::TEXTURE_2D, 0, 0, 0, x, y, width, height);

            gl.use_program(Some(program));
            gl.bind_vertex_array(Some(vao));
            gl.disable(glow::BLEND);
            gl.disable(glow::SCISSOR_TEST);
            gl.active_texture(glow::TEXTURE0);
            if let Some(location) = gl.get_uniform_location(program, "source_texture") {
                gl.uniform_1_i32(Some(&location), 0);
            }
            if let Some(location) = gl.get_uniform_location(program, "corner_radius") {
                gl.uniform_1_f32(Some(&location), corner_radius);
            }
            if let Some(location) = gl.get_uniform_location(program, "surface_size") {
                gl.uniform_2_f32(Some(&location), width as f32, height as f32);
            }

            gl.bind_framebuffer(glow::FRAMEBUFFER, Some(framebuffer));
            gl.framebuffer_texture_2d(
                glow::FRAMEBUFFER,
                glow::COLOR_ATTACHMENT0,
                glow::TEXTURE_2D,
                Some(intermediate),
                0,
            );
            gl.viewport(0, 0, width, height);
            gl.bind_texture(glow::TEXTURE_2D, Some(source));
            if let Some(location) = gl.get_uniform_location(program, "direction") {
                gl.uniform_2_f32(Some(&location), blur_strength / width as f32, 0.0);
            }
            gl.draw_arrays(glow::TRIANGLES, 0, 3);

            let original_framebuffer = if original_framebuffer == 0 {
                None
            } else {
                std::num::NonZeroU32::new(original_framebuffer as u32).map(glow::NativeFramebuffer)
            };
            gl.bind_framebuffer(glow::FRAMEBUFFER, original_framebuffer);
            gl.viewport(x, y, width, height);
            gl.bind_texture(glow::TEXTURE_2D, Some(intermediate));
            if let Some(location) = gl.get_uniform_location(program, "direction") {
                gl.uniform_2_f32(Some(&location), 0.0, blur_strength / height as f32);
            }
            gl.draw_arrays(glow::TRIANGLES, 0, 3);
        }
    }

    #[allow(unsafe_code)]
    fn ensure_resources(
        &mut self,
        gl: &glow::Context,
        width: i32,
        height: i32,
    ) -> Result<(), String> {
        use glow::HasContext as _;

        unsafe {
            if self.program.is_none() {
                let program = gl.create_program().map_err(|error| error.to_string())?;
                let vertex = compile_blur_shader(gl, glow::VERTEX_SHADER, BLUR_VERTEX_SHADER)?;
                let fragment =
                    compile_blur_shader(gl, glow::FRAGMENT_SHADER, BLUR_FRAGMENT_SHADER)?;
                gl.attach_shader(program, vertex);
                gl.attach_shader(program, fragment);
                gl.link_program(program);
                gl.delete_shader(vertex);
                gl.delete_shader(fragment);
                if !gl.get_program_link_status(program) {
                    return Err(gl.get_program_info_log(program));
                }
                self.program = Some(program);
                self.vao = Some(
                    gl.create_vertex_array()
                        .map_err(|error| error.to_string())?,
                );
                self.source = Some(gl.create_texture().map_err(|error| error.to_string())?);
                self.intermediate = Some(gl.create_texture().map_err(|error| error.to_string())?);
                self.framebuffer =
                    Some(gl.create_framebuffer().map_err(|error| error.to_string())?);
            }
            if self.size != (width, height) {
                for texture in [self.source, self.intermediate].into_iter().flatten() {
                    gl.bind_texture(glow::TEXTURE_2D, Some(texture));
                    gl.tex_parameter_i32(
                        glow::TEXTURE_2D,
                        glow::TEXTURE_MIN_FILTER,
                        glow::LINEAR as i32,
                    );
                    gl.tex_parameter_i32(
                        glow::TEXTURE_2D,
                        glow::TEXTURE_MAG_FILTER,
                        glow::LINEAR as i32,
                    );
                    gl.tex_parameter_i32(
                        glow::TEXTURE_2D,
                        glow::TEXTURE_WRAP_S,
                        glow::CLAMP_TO_EDGE as i32,
                    );
                    gl.tex_parameter_i32(
                        glow::TEXTURE_2D,
                        glow::TEXTURE_WRAP_T,
                        glow::CLAMP_TO_EDGE as i32,
                    );
                    gl.tex_image_2d(
                        glow::TEXTURE_2D,
                        0,
                        glow::RGBA8 as i32,
                        width,
                        height,
                        0,
                        glow::RGBA,
                        glow::UNSIGNED_BYTE,
                        glow::PixelUnpackData::Slice(None),
                    );
                }
                self.size = (width, height);
            }
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
fn compile_blur_shader(
    gl: &glow::Context,
    shader_type: u32,
    source: &str,
) -> Result<glow::Shader, String> {
    use glow::HasContext as _;
    unsafe {
        let shader = gl
            .create_shader(shader_type)
            .map_err(|error| error.to_string())?;
        gl.shader_source(shader, source);
        gl.compile_shader(shader);
        if gl.get_shader_compile_status(shader) {
            Ok(shader)
        } else {
            Err(gl.get_shader_info_log(shader))
        }
    }
}

const BLUR_VERTEX_SHADER: &str = r#"#version 150
out vec2 uv;
void main() {
    vec2 position = vec2((gl_VertexID << 1) & 2, gl_VertexID & 2);
    // This is an oversized fullscreen triangle: its vertices use 0..2, while
    // the visible viewport covers the interpolated 0..1 portion. Halving here
    // restricted fragment UVs to 0..0.5, so the rounded-distance mask could
    // reach the left corners but never the right ones.
    uv = position;
    gl_Position = vec4(position * 2.0 - 1.0, 0.0, 1.0);
}
"#;

const BLUR_FRAGMENT_SHADER: &str = r#"#version 150
uniform sampler2D source_texture;
uniform vec2 direction;
uniform vec2 surface_size;
uniform float corner_radius;
in vec2 uv;
out vec4 output_color;
void main() {
    vec2 p = uv * surface_size;
    vec2 q = abs(p - surface_size * 0.5) - (surface_size * 0.5 - vec2(corner_radius));
    if (length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) > corner_radius) discard;
    vec4 color = texture(source_texture, uv) * 0.227027;
    color += texture(source_texture, uv + direction * 1.384615) * 0.316216;
    color += texture(source_texture, uv - direction * 1.384615) * 0.316216;
    color += texture(source_texture, uv + direction * 3.230769) * 0.070270;
    color += texture(source_texture, uv - direction * 3.230769) * 0.070270;
    output_color = color;
}
"#;

fn settings_section_bar(ui: &mut egui::Ui, current: &mut SettingsSection) {
    egui::ScrollArea::horizontal()
        .id_salt("settings-section-bar")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for (label, section) in [
                    ("General", SettingsSection::General),
                    ("Privacy", SettingsSection::Privacy),
                    ("Sync", SettingsSection::Sync),
                    ("Advanced", SettingsSection::Advanced),
                    ("Bookmarks", SettingsSection::Bookmarks),
                    ("History", SettingsSection::History),
                    ("Downloads", SettingsSection::Downloads),
                    ("Workspaces", SettingsSection::Workspaces),
                    ("Permissions", SettingsSection::Permissions),
                    ("Autofill", SettingsSection::Autofill),
                    ("Memory", SettingsSection::Memory),
                ] {
                    let response = ui
                        .selectable_value(current, section, label)
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if response.has_focus() {
                        response.scroll_to_me(Some(egui::Align::Center));
                    }
                }
            });
        });
}

fn settings_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(egui::RichText::new(title).size(21.0).strong());
    ui.label(egui::RichText::new(subtitle).color(egui::Color32::from_white_alpha(145)));
    ui.add_space(14.0);
}

fn settings_card<R>(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::NONE
        .fill(egui::Color32::from_white_alpha(14))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_white_alpha(20)))
        .corner_radius(egui::CornerRadius::same(11))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            content(ui)
        })
        .inner
}

fn settings_divider(ui: &mut egui::Ui) {
    ui.add_space(layout::settings::LIST_SPACE);
    ui.separator();
    ui.add_space(layout::settings::LIST_SPACE);
}

fn settings_field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .size(13.0)
            .color(egui::Color32::from_white_alpha(170)),
    );
    ui.add_space(3.0);
}

fn settings_empty_state(ui: &mut egui::Ui, title: &str, description: &str) {
    settings_card(ui, |ui| {
        ui.add_space(14.0);
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new(title).size(15.0).strong());
            ui.label(
                egui::RichText::new(description)
                    .size(12.0)
                    .color(egui::Color32::from_white_alpha(135)),
            );
        });
        ui.add_space(14.0);
    });
}

fn settings_toggle(ui: &mut egui::Ui, value: &mut bool, title: &str, description: &str) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.strong(title);
            ui.label(
                egui::RichText::new(description)
                    .size(12.0)
                    .color(egui::Color32::from_white_alpha(135)),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let (rect, response) =
                ui.allocate_exact_size(egui::vec2(38.0, 22.0), egui::Sense::click());
            let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
            if response.clicked() {
                *value = !*value;
            }
            let fill = if *value {
                egui::Color32::from_rgb(10, 132, 255)
            } else {
                egui::Color32::from_white_alpha(42)
            };
            ui.painter()
                .rect_filled(rect, egui::CornerRadius::same(11), fill);
            let knob_x = if *value {
                rect.right() - 11.0
            } else {
                rect.left() + 11.0
            };
            ui.painter().circle_filled(
                egui::pos2(knob_x, rect.center().y),
                8.0,
                egui::Color32::from_white_alpha(245),
            );
        });
    });
}

fn settings_row_button(ui: &mut egui::Ui, title: &str, subtitle: &str) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 54.0), egui::Sense::click());
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.hovered() {
        ui.painter().rect_filled(
            rect,
            egui::CornerRadius::same(7),
            egui::Color32::from_white_alpha(14),
        );
    }
    ui.painter().text(
        rect.left_top() + egui::vec2(2.0, 9.0),
        egui::Align2::LEFT_TOP,
        title,
        egui::FontId::proportional(14.0),
        design_white(),
    );
    ui.painter().text(
        rect.left_bottom() + egui::vec2(2.0, -9.0),
        egui::Align2::LEFT_BOTTOM,
        subtitle,
        egui::FontId::proportional(12.0),
        egui::Color32::from_white_alpha(140),
    );
    ui.painter().text(
        rect.right_center() - egui::vec2(4.0, 0.0),
        egui::Align2::RIGHT_CENTER,
        "›",
        egui::FontId::proportional(16.0),
        egui::Color32::from_white_alpha(145),
    );
    response
}

fn content_viewport_rect(context: &egui::Context, geometry: DesignGeometry) -> egui::Rect {
    content_viewport_rect_for_bounds(context.content_rect(), geometry)
}

fn content_viewport_rect_for_bounds(bounds: egui::Rect, geometry: DesignGeometry) -> egui::Rect {
    egui::Rect::from_min_max(
        geometry.point(SIDEBAR_WIDTH, CONTENT_TOP_INSET),
        egui::pos2(
            (bounds.right() - CONTENT_RIGHT_INSET * geometry.scale).max(geometry.sidebar_width),
            (bounds.bottom() - CONTENT_BOTTOM_INSET * geometry.scale)
                .max(CONTENT_TOP_INSET * geometry.scale),
        ),
    )
}

fn physical_size_for_rect(
    rect: egui::Rect,
    pixels_per_point: f32,
) -> winit::dpi::PhysicalSize<u32> {
    let left = (rect.left() * pixels_per_point).round();
    let right = (rect.right() * pixels_per_point).round();
    let top = (rect.top() * pixels_per_point).round();
    let bottom = (rect.bottom() * pixels_per_point).round();
    winit::dpi::PhysicalSize::new(
        (right - left).max(1.0) as u32,
        (bottom - top).max(1.0) as u32,
    )
}

fn paint_search_surface(painter: &egui::Painter, rect: egui::Rect, scale: f32) {
    let radius = TOOLBAR_RADIUS * scale;
    let corner_radius = egui::CornerRadius::from(radius);

    // Updated Figma tokens: 1% white fill and a 1 px solid white stroke.
    painter.rect_filled(rect, corner_radius, egui::Color32::from_white_alpha(3));

    // Figma inner shadow: x=0, y=0, blur=10, spread=0, 25% white.
    // Clip a blurred inside stroke to the surface so no outer glow escapes.
    let clipped = painter.with_clip_rect(rect);
    clipped.add(
        egui::epaint::RectShape::stroke(
            rect,
            corner_radius,
            egui::Stroke::new(scale, egui::Color32::from_white_alpha(64)),
            egui::StrokeKind::Inside,
        )
        .with_blur_width(10.0 * scale),
    );
    painter.rect_stroke(
        rect,
        corner_radius,
        egui::Stroke::new(scale, egui::Color32::WHITE),
        egui::StrokeKind::Inside,
    );
}

fn paint_asset(
    painter: &egui::Painter,
    assets: &HashMap<DesignAsset, egui::TextureHandle>,
    asset: DesignAsset,
    rect: egui::Rect,
    flip_x: bool,
    tint: egui::Color32,
) {
    let Some(texture) = assets.get(&asset) else {
        return;
    };
    let rect = egui::Rect::from_center_size(rect.center(), rect.size() * ICON_VISUAL_SCALE);
    let uv = if flip_x {
        egui::Rect::from_min_max(egui::pos2(1.0, 0.0), egui::pos2(0.0, 1.0))
    } else {
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0))
    };
    painter.image(texture.id(), rect, uv, tint);
}

/// Draws the Figma reload path as geometry at the current display scale.
/// Keeping this vector until final tessellation avoids the jagged edge caused
/// by shrinking a pre-rasterized texture into the compact toolbar control.
fn paint_reload_icon(painter: &egui::Painter, rect: egui::Rect, color: egui::Color32) {
    let rect = egui::Rect::from_center_size(rect.center(), rect.size() * ICON_VISUAL_SCALE);
    let map = |x: f32, y: f32| {
        egui::pos2(
            egui::lerp(rect.x_range(), x / 30.0),
            egui::lerp(rect.y_range(), y / 29.0),
        )
    };

    // The source curve is a 320-degree circular arc with a gap at top-right.
    let center = egui::vec2(14.305_75, 14.305_75);
    let radius = 13.052_3;
    let start = 0.252_65_f32;
    let sweep = 5.603_5_f32;
    let points = (0_u8..=48)
        .map(|step| {
            let angle = start + sweep * (f32::from(step) / 48.0);
            map(
                center.x + radius * angle.cos(),
                center.y + radius * angle.sin(),
            )
        })
        .collect::<Vec<_>>();
    let stroke_width = 2.5 * rect.width() / 30.0;
    let stroke = egui::Stroke::new(stroke_width, color);
    painter.add(egui::Shape::line(points.clone(), stroke));

    let arrow = [
        map(27.9076, 4.3359),
        map(26.4251, 10.0806),
        map(20.6804, 8.59809),
    ];
    painter.add(egui::Shape::line(arrow.to_vec(), stroke));

    // egui's polyline tessellator has square caps; these preserve Figma's
    // round line caps and joins without introducing another bitmap pass.
    let cap_radius = stroke_width * 0.5;
    for point in [points[0], points[48], arrow[0], arrow[1], arrow[2]] {
        painter.circle_filled(point, cap_radius, color);
    }
}

/// Handles the global keyboard shortcuts evaluated before the chrome panels.
// Single caller; the params are the disjoint pieces of `update`'s UI state the
// helper must mutate — a state struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn handle_global_shortcuts(
    context: &egui::Context,
    address_id: egui::Id,
    search_input: &mut String,
    action: &mut Option<ChromeAction>,
    shell: &mut ShellState,
) {
    if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::L)) {
        search_input.clear();
        context.memory_mut(|memory| memory.request_focus(address_id));
    }
    if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::T)) {
        search_input.clear();
        context.memory_mut(|memory| memory.request_focus(address_id));
    }
    if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::R)) {
        *action = Some(ChromeAction::Reload);
    }
    let zoom_in = context.input_mut(|input| {
        input.consume_key(egui::Modifiers::COMMAND, Key::Plus)
            || input.consume_key(egui::Modifiers::COMMAND, Key::Equals)
    });
    if zoom_in {
        *action = Some(ChromeAction::ZoomIn);
    }
    if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::Minus)) {
        *action = Some(ChromeAction::ZoomOut);
    }
    if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::Num0)) {
        *action = Some(ChromeAction::ResetZoom);
    }
    if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::Comma)) {
        *action = Some(ChromeAction::OpenSettings(SettingsSection::General));
    }
    if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, Key::W)) {
        if let Some(tab_id) = shell.active_tab() {
            *action = Some(ChromeAction::CloseTab(tab_id));
        }
    }
}

// Radius is a small positive f32 design constant; u8 is the intended egui encoding.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn chrome_icon_response(
    ui: &mut egui::Ui,
    id: egui::Id,
    rect: egui::Rect,
    tooltip: &'static str,
    scale: f32,
) -> egui::Response {
    let response = ui
        .interact(rect, id, egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let hover = ui.ctx().animate_bool_with_time(
        id.with("hover-fill"),
        response.hovered() || response.has_focus(),
        0.11,
    );
    if hover > 0.0 || response.is_pointer_button_down_on() {
        let alpha = if response.is_pointer_button_down_on() {
            31
        } else {
            (20.0 * hover).round() as u8
        };
        let center = chrome_icon_visual_center(id, rect, scale);
        ui.painter().circle_filled(
            center,
            rect.width().min(rect.height()) * 0.5,
            egui::Color32::from_white_alpha(alpha),
        );
    }
    if response.hovered() {
        ui.ctx().data_mut(|data| {
            data.insert_temp(
                egui::Id::new("nomad-pending-tooltip"),
                PendingChromeTooltip {
                    id,
                    anchor: rect,
                    text: tooltip,
                },
            );
        });
    }
    response
}

fn paint_pending_chrome_tooltip(
    context: &egui::Context,
    backdrop_blur: Arc<Mutex<BackdropBlurRenderer>>,
) {
    let Some(tooltip) = context
        .data(|data| data.get_temp::<PendingChromeTooltip>(egui::Id::new("nomad-pending-tooltip")))
    else {
        return;
    };
    let size = egui::vec2(tooltip_width(tooltip.text), 30.0);
    let screen = context.content_rect();
    let y = if tooltip.anchor.center().y < screen.center().y {
        tooltip.anchor.bottom() + 8.0
    } else {
        tooltip.anchor.top() - size.y - 8.0
    };
    let x = (tooltip.anchor.center().x - size.x * 0.5).clamp(8.0, screen.right() - size.x - 8.0);
    let rect = egui::Rect::from_min_size(egui::pos2(x, y), size);
    let painter = context
        .layer_painter(egui::LayerId::new(
            egui::Order::Tooltip,
            tooltip.id.with("tooltip"),
        ))
        .with_clip_rect(screen);
    // Tooltips are small and sit over mostly flat chrome, so the default
    // three-pixel kernel is visually lost beneath their tint. Increase only
    // their sampling distance; corner masking remains an independent uniform.
    painter.add(backdrop_blur_shape_with_strength(
        rect,
        backdrop_blur,
        8.0,
        3.0,
    ));
    painter.rect_filled(
        rect,
        egui::CornerRadius::same(8),
        egui::Color32::from_rgba_unmultiplied(29, 29, 29, 148),
    );
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        tooltip.text,
        egui::FontId::proportional(15.0),
        egui::Color32::from_white_alpha(204),
    );
}

fn tooltip_width(text: &str) -> f32 {
    24.0 + text.chars().count() as f32 * 8.0
}

fn chrome_icon_visual_center(id: egui::Id, rect: egui::Rect, scale: f32) -> egui::Pos2 {
    if id == egui::Id::new("nomad-menu-control") {
        return rect.center() + egui::vec2(-scale, -scale);
    }
    if id == egui::Id::new("nomad-back-control") || id == egui::Id::new("nomad-forward-control") {
        return rect.center() + egui::vec2(-0.5 * scale, -scale);
    }
    if id == egui::Id::new("nomad-reload-control") {
        return rect.center() + egui::vec2(-3.0 * scale, -1.0 * scale);
    }
    rect.center()
}

fn paint_favicon_fallback(
    painter: &egui::Painter,
    center: egui::Pos2,
    url: Option<&url::Url>,
    scale: f32,
) {
    let host = url
        .and_then(url::Url::host_str)
        .unwrap_or("new")
        .trim_start_matches("www.");
    let letter = host
        .chars()
        .next()
        .unwrap_or('N')
        .to_uppercase()
        .to_string();
    let color = if host.contains("google") {
        egui::Color32::from_rgb(66, 133, 244)
    } else {
        egui::Color32::from_rgb(103, 111, 126)
    };
    painter.circle_filled(center, 14.0 * scale * ICON_VISUAL_SCALE, color);
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        letter,
        egui::FontId::proportional(11.0),
        egui::Color32::WHITE,
    );
}

fn favicon_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|host| host.trim_start_matches("www.").to_ascii_lowercase())
}

fn favicon_texture<'a>(
    textures: &'a HashMap<String, egui::TextureHandle>,
    url: Option<&Url>,
) -> Option<&'a egui::TextureHandle> {
    textures.get(&favicon_host(url?)?)
}

fn paint_favicon_texture(
    painter: &egui::Painter,
    texture: &egui::TextureHandle,
    bounds: egui::Rect,
) {
    let source = texture.size_vec2();
    let scale = (bounds.width() / source.x)
        .min(bounds.height() / source.y)
        .min(1.0);
    let size = source * scale;
    painter.image(
        texture.id(),
        egui::Rect::from_center_size(bounds.center(), size),
        egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
        egui::Color32::WHITE,
    );
}

fn schedule_autocomplete(
    query: String,
    generation: Arc<AtomicU64>,
    sender: mpsc::Sender<AutocompleteResult>,
    context: egui::Context,
) {
    let request_generation = generation.fetch_add(1, Ordering::Relaxed) + 1;
    if query.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(AUTOCOMPLETE_DEBOUNCE);
        if generation.load(Ordering::Relaxed) != request_generation {
            return;
        }
        let suggestions = fetch_duckduckgo_suggestions(&query);
        if generation.load(Ordering::Relaxed) == request_generation {
            let _ = sender.send(AutocompleteResult { query, suggestions });
            context.request_repaint();
        }
    });
}

fn network_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(4))
        .user_agent("Nomad Browser/0.1")
        .build()
}

fn fetch_duckduckgo_suggestions(query: &str) -> Vec<String> {
    let encoded = url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
    let Ok(response) = network_agent()
        .get(&format!("https://duckduckgo.com/ac/?q={encoded}"))
        .call()
    else {
        return Vec::new();
    };
    let Ok(body) = response.into_string() else {
        return Vec::new();
    };
    parse_duckduckgo_suggestions(&body)
}

fn parse_duckduckgo_suggestions(body: &str) -> Vec<String> {
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let entries = payload
        .as_array()
        .and_then(|items| {
            items
                .get(1)
                .and_then(serde_json::Value::as_array)
                .or(Some(items))
        })
        .into_iter()
        .flatten();
    entries
        .filter_map(|item| {
            item.get("phrase")
                .and_then(serde_json::Value::as_str)
                .or_else(|| item.as_str())
                .map(str::to_owned)
        })
        .take(AUTOCOMPLETE_LIMIT)
        .collect()
}

fn fetch_favicon(page_url: &Url) -> Option<Vec<u8>> {
    let mut origin = page_url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let agent = network_agent();

    if let Ok(response) = agent.get(origin.as_str()).call() {
        let mut html = String::new();
        if response
            .into_reader()
            .take(512 * 1024)
            .read_to_string(&mut html)
            .is_ok()
        {
            if let Some(href) = extract_icon_href(&html) {
                if let Ok(icon_url) = origin.join(&href) {
                    if let Some(bytes) = fetch_icon_bytes(&agent, &icon_url) {
                        return Some(bytes);
                    }
                }
            }
        }
    }
    origin.set_path("/favicon.ico");
    fetch_icon_bytes(&agent, &origin)
}

fn fetch_icon_bytes(agent: &ureq::Agent, url: &Url) -> Option<Vec<u8>> {
    let response = agent.get(url.as_str()).call().ok()?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(FAVICON_LIMIT_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    (!bytes.is_empty()).then_some(bytes)
}

fn extract_icon_href(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    for (start, _) in lower.match_indices("<link") {
        let end = lower[start..].find('>')? + start;
        let lower_tag = &lower[start..=end];
        if lower_tag.contains("icon") {
            let original_tag = &html[start..=end];
            if let Some(href) = html_attribute(original_tag, "href") {
                return Some(href);
            }
        }
    }
    None
}

fn html_attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let start = lower.find(&format!("{name}="))? + name.len() + 1;
    let value = tag[start..].trim_start();
    let first = value.chars().next()?;
    if first == '"' || first == '\'' {
        return value[1..].split(first).next().map(str::to_owned);
    }
    value
        .split(|character: char| character.is_whitespace() || character == '>')
        .next()
        .map(str::to_owned)
}

fn paint_close_icon(painter: &egui::Painter, center: egui::Pos2, scale: f32, color: egui::Color32) {
    let half_extent = layout::tab_list::CLOSE_ICON_HALF_EXTENT * scale * ICON_VISUAL_SCALE;
    let stroke = egui::Stroke::new(2.0 * scale * ICON_VISUAL_SCALE, color);
    painter.line_segment(
        [
            center + egui::vec2(-half_extent, -half_extent),
            center + egui::vec2(half_extent, half_extent),
        ],
        stroke,
    );
    painter.line_segment(
        [
            center + egui::vec2(half_extent, -half_extent),
            center + egui::vec2(-half_extent, half_extent),
        ],
        stroke,
    );
}

/// Speaker glyph for tabs with active audio playback.
fn paint_speaker_icon(
    painter: &egui::Painter,
    center: egui::Pos2,
    scale: f32,
    color: egui::Color32,
) {
    let s = scale * ICON_VISUAL_SCALE;
    let body = [
        center + egui::vec2(-7.0 * s, -3.0 * s),
        center + egui::vec2(-3.0 * s, -3.0 * s),
        center + egui::vec2(1.0 * s, -7.0 * s),
        center + egui::vec2(1.0 * s, 7.0 * s),
        center + egui::vec2(-3.0 * s, 3.0 * s),
        center + egui::vec2(-7.0 * s, 3.0 * s),
    ];
    painter.add(egui::Shape::convex_polygon(
        body.to_vec(),
        color,
        egui::Stroke::NONE,
    ));
    // Two sound-wave arcs ahead of the speaker cone.
    for (radius, start, end) in [
        (4.0, -50.0_f32.to_radians(), 50.0_f32.to_radians()),
        (7.5, -55.0_f32.to_radians(), 55.0_f32.to_radians()),
    ] {
        let mut points = Vec::new();
        let steps = 6_f32;
        for i in 0_u8..=6 {
            let angle = start + (end - start) * (f32::from(i) / steps);
            points.push(
                center + egui::vec2(2.0 * s + radius * s * angle.cos(), radius * s * angle.sin()),
            );
        }
        painter.add(egui::Shape::line(points, egui::Stroke::new(1.4 * s, color)));
    }
}

/// Caret for collapsible group headers; `down` = expanded.
fn paint_caret_icon(
    painter: &egui::Painter,
    center: egui::Pos2,
    scale: f32,
    down: bool,
    color: egui::Color32,
) {
    let s = scale * ICON_VISUAL_SCALE;
    let dy = if down { 2.5 } else { 0.0 };
    let dx = if down { 0.0 } else { 2.5 };
    let points = [
        center + egui::vec2((-3.0 + dx) * s, (-1.5 + dy) * s),
        center + egui::vec2((3.0 + dx) * s, (-1.5 + dy) * s),
        center + egui::vec2(dx * s, (2.5 + dy) * s),
    ];
    painter.add(egui::Shape::convex_polygon(
        points.to_vec(),
        color,
        egui::Stroke::NONE,
    ));
}

/// Sidebar group colors, matching the extension `tabGroups` vocabulary.
fn tab_group_color(name: &str) -> egui::Color32 {
    match name {
        "blue" => egui::Color32::from_rgb(90, 140, 250),
        "cyan" => egui::Color32::from_rgb(70, 200, 210),
        "green" => egui::Color32::from_rgb(90, 200, 120),
        "yellow" => egui::Color32::from_rgb(230, 200, 80),
        "orange" => egui::Color32::from_rgb(240, 150, 70),
        "red" => egui::Color32::from_rgb(235, 100, 100),
        "pink" => egui::Color32::from_rgb(240, 130, 190),
        "purple" => egui::Color32::from_rgb(170, 120, 240),
        _ => egui::Color32::from_rgb(150, 150, 155), // grey / unknown
    }
}

fn site_icon_asset(url: Option<&url::Url>) -> Option<DesignAsset> {
    let host = url?
        .host_str()?
        .trim_start_matches("www.")
        .to_ascii_lowercase();
    if host.contains("reddit") {
        Some(DesignAsset::Reddit)
    } else if host.contains("youtube") {
        Some(DesignAsset::YouTube)
    } else {
        None
    }
}

fn bookmark_icon_asset(url: &url::Url) -> Option<DesignAsset> {
    match site_icon_asset(Some(url)) {
        Some(DesignAsset::Reddit) => Some(DesignAsset::RedditTab),
        other => other,
    }
}

fn tab_label(url: Option<&url::Url>) -> String {
    let Some(url) = url else {
        return "New tab".to_owned();
    };
    if url.as_str() == "about:blank" {
        return "New tab".to_owned();
    }
    if url.as_str() == "about:settings" {
        return "Settings".to_owned();
    }
    match url
        .host_str()
        .unwrap_or_default()
        .trim_start_matches("www.")
    {
        host if host.contains("reddit") => "Reddit".to_owned(),
        host if host.contains("youtube") => "Youtube".to_owned(),
        host if host.contains("google") => "google.com".to_owned(),
        host if !host.is_empty() => host.to_owned(),
        _ => url.as_str().to_owned(),
    }
}

fn tab_display_label(url: Option<&url::Url>, reveal_full_url: bool) -> String {
    if reveal_full_url {
        return url.map_or_else(|| "New tab".to_owned(), |url| url.as_str().to_owned());
    }
    tab_label(url)
}

fn page_accessibility_action(
    request: egui::accesskit::ActionRequest,
) -> Option<egui::accesskit::ActionRequest> {
    match request.action {
        egui::accesskit::Action::Click
        | egui::accesskit::Action::Focus
        | egui::accesskit::Action::Blur
        | egui::accesskit::Action::ScrollIntoView
        | egui::accesskit::Action::Increment
        | egui::accesskit::Action::Decrement
        | egui::accesskit::Action::ReplaceSelectedText => Some(request),
        _ => None,
    }
}

fn initial_accessibility_tree() -> egui::accesskit::TreeUpdate {
    let root_id = ax_id(AX_ROOT);
    let mut root = egui::accesskit::Node::new(egui::accesskit::Role::Window);
    root.set_label("Nomad Browser");
    egui::accesskit::TreeUpdate {
        nodes: vec![(root_id, root)],
        tree: Some(egui::accesskit::Tree::new(root_id)),
        focus: root_id,
        tree_id: egui::accesskit::TreeId::ROOT,
    }
}

/// Browser-chrome accessibility nodes live in a high ID range so they can
/// share the platform root with Servo's renderer-assigned node IDs (which
/// count up from zero) without collisions.
const AX_BASE: u64 = 1 << 60;
const AX_ROOT: u64 = 0;
const AX_TOOLBAR: u64 = 1;
const AX_BACK: u64 = 2;
const AX_FORWARD: u64 = 3;
const AX_RELOAD: u64 = 4;
const AX_ADDRESS: u64 = 5;
const AX_NEW_TAB: u64 = 6;
const AX_TAB_LIST: u64 = 7;
const AX_CONTENT: u64 = 8;
const AX_TAB_BASE: u64 = 0x1_0000;

fn ax_id(offset: u64) -> egui::accesskit::NodeId {
    egui::accesskit::NodeId(AX_BASE + offset)
}

fn ax_node(offset: u64) -> u64 {
    AX_BASE + offset
}

fn is_chrome_ax_node(id: egui::accesskit::NodeId) -> bool {
    id.0 >> 60 == 1
}

fn ax_tab_id(tab_id: TabId) -> egui::accesskit::NodeId {
    egui::accesskit::NodeId(AX_BASE + AX_TAB_BASE + (tab_id.get() & 0xFFFF_FFFF))
}

fn button_node(
    offset: u64,
    label: &str,
    enabled: bool,
) -> (egui::accesskit::NodeId, egui::accesskit::Node) {
    let mut node = egui::accesskit::Node::new(egui::accesskit::Role::Button);
    node.set_label(label);
    if !enabled {
        node.set_disabled();
    }
    node.add_action(egui::accesskit::Action::Click);
    node.add_action(egui::accesskit::Action::Focus);
    (ax_id(offset), node)
}

/// Assistive-technology action targeting browser chrome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChromeAxAction {
    Back,
    Forward,
    Reload,
    NewTab,
    ActivateTab(TabId),
}

#[cfg(test)]
mod accessibility_tests {
    use super::page_accessibility_action;
    use egui::accesskit::{Action, ActionRequest, NodeId, TreeId};

    #[test]
    fn page_accessibility_action_accepts_dom_actions() {
        for action in [
            Action::Click,
            Action::Focus,
            Action::Blur,
            Action::ScrollIntoView,
            Action::Increment,
            Action::Decrement,
            Action::ReplaceSelectedText,
        ] {
            let request = ActionRequest {
                action,
                target_tree: TreeId::ROOT,
                target_node: NodeId(7),
                data: None,
            };

            assert!(page_accessibility_action(request).is_some());
        }
    }

    #[test]
    fn page_accessibility_action_rejects_unwired_actions() {
        let request = ActionRequest {
            action: Action::Expand,
            target_tree: TreeId::ROOT,
            target_node: NodeId(7),
            data: None,
        };

        assert!(page_accessibility_action(request).is_none());
    }
}

#[cfg(test)]
mod geometry_tests {
    // Exact comparisons against compile-time constants are intentional.
    #![allow(clippy::float_cmp)]
    use super::layout;
    use super::{
        content_viewport_rect_for_bounds, physical_size_for_rect, DesignGeometry, CHROME_SCALE,
    };

    fn assert_near(left: f32, right: f32) {
        assert!((left - right).abs() < 0.001, "{left} != {right}");
    }

    #[test]
    fn chrome_geometry_does_not_scale_with_window_size() {
        let compact = DesignGeometry::from_bounds(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(860.0, 560.0),
        ));
        let large = DesignGeometry::from_bounds(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(2560.0, 1600.0),
        ));

        assert_eq!(compact.scale, CHROME_SCALE);
        assert_eq!(large.scale, CHROME_SCALE);
        assert_eq!(compact.sidebar_width, large.sidebar_width);
        assert_eq!(
            compact.size(layout::nav::ICON_WIDTH, layout::nav::ICON_HEIGHT,),
            large.size(layout::nav::ICON_WIDTH, layout::nav::ICON_HEIGHT),
        );
    }

    #[test]
    fn viewport_keeps_fixed_origin_and_gutters_while_window_resizes() {
        let compact_bounds = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(860.0, 560.0));
        let large_bounds = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1728.0, 1117.0));
        let compact_geometry = DesignGeometry::from_bounds(compact_bounds);
        let large_geometry = DesignGeometry::from_bounds(large_bounds);
        let compact = content_viewport_rect_for_bounds(compact_bounds, compact_geometry);
        let large = content_viewport_rect_for_bounds(large_bounds, large_geometry);

        assert_eq!(compact.min, large.min);
        assert_near(
            compact.right(),
            compact_bounds.right() - layout::CONTENT_RIGHT_INSET * CHROME_SCALE,
        );
        assert_near(
            large.right(),
            large_bounds.right() - layout::CONTENT_RIGHT_INSET * CHROME_SCALE,
        );
        assert_near(
            compact.bottom(),
            compact_bounds.bottom() - layout::CONTENT_BOTTOM_INSET * CHROME_SCALE,
        );
        assert_near(
            large.bottom(),
            large_bounds.bottom() - layout::CONTENT_BOTTOM_INSET * CHROME_SCALE,
        );
        assert_near(
            large.width() - compact.width(),
            large_bounds.width() - compact_bounds.width(),
        );
        assert_near(
            large.height() - compact.height(),
            large_bounds.height() - compact_bounds.height(),
        );
    }

    #[test]
    fn framebuffer_size_uses_rounded_edges_not_rounded_extent() {
        let rect = egui::Rect::from_min_max(egui::pos2(0.25, 0.25), egui::pos2(10.75, 10.75));
        assert_eq!(
            physical_size_for_rect(rect, 2.0),
            winit::dpi::PhysicalSize::new(21, 21)
        );
    }

    /// Pins the documented fixed-size values from the Figma UI specification
    /// so silent drift in the layout specification is caught.
    #[test]
    fn layout_spec_matches_documented_fixed_sizes() {
        assert_near(CHROME_SCALE, 0.60);
        assert_near(layout::SIDEBAR_WIDTH, 420.0);
        assert_near(layout::CONTENT_TOP_INSET, layout::address::ROW_TOP);
        assert_near(layout::CONTENT_RIGHT_INSET, 12.0);
        assert_near(layout::address::ROW_TOP, 74.0);
        assert_near(layout::address::ROW_HEIGHT, 62.0);
        assert_near(layout::SIDEBAR_WIDTH - layout::TOOLBOX_PADDING * 2.0, 388.0);
        assert_near(layout::tab_list::LIST_TOP, 156.0);
        assert_near(layout::tab_list::ROW_HEIGHT, 52.0);
        assert_near(layout::tab_list::ROW_PITCH, 67.0);
        assert_near(layout::bookmark_strip::STRIP_TOP, 17.0);
        assert_near(layout::bookmark_strip::TAB_WIDTH, 120.0);
        assert_near(layout::bookmark_strip::TAB_HEIGHT, 42.0);
        assert_near(layout::bookmark_strip::TAB_PITCH, 135.0);
        assert_near(layout::nav::LAYOUT_ICON_SIZE, 24.0);
        assert_near(layout::nav::ARROW_WIDTH, 22.5);
        assert_near(layout::nav::RELOAD_ICON_SIZE, 26.5);
        assert_near(layout::bottom_bar::SETTINGS_WIDTH, 26.43);
        assert_near(layout::bottom_bar::SETTINGS_HEIGHT, 24.40);
        assert_near(layout::bottom_bar::DOWNLOAD_SIZE, 26.5);
    }
}

#[cfg(test)]
mod interaction_tests {
    use super::{
        close_tab_activated, extract_icon_href, is_unopened_tab, layout,
        parse_duckduckgo_suggestions, should_dismiss_suggestions, should_show_sidebar_tab,
        suggestion_activated, suggestion_panel_content_width, tab_display_label,
    };
    use nomad_engine::TabId;
    use url::Url;

    #[test]
    fn tab_display_label_reveals_complete_url_only_when_requested() {
        let url = Url::parse("https://www.reddit.com/r/rust/?sort=new").unwrap();

        assert_eq!(tab_display_label(Some(&url), false), "Reddit");
        assert_eq!(
            tab_display_label(Some(&url), true),
            "https://www.reddit.com/r/rust/?sort=new"
        );
    }

    #[test]
    fn unopened_tabs_stay_out_of_the_initial_chrome() {
        let blank = Url::parse("about:blank").unwrap();
        let page = Url::parse("https://example.com/").unwrap();

        assert!(is_unopened_tab(None));
        assert!(is_unopened_tab(Some(&blank)));
        assert!(!is_unopened_tab(Some(&page)));
    }

    #[test]
    fn submitted_blank_tab_is_visible_while_navigation_is_pending() {
        let tab_id = TabId::new(7);

        assert!(!should_show_sidebar_tab(tab_id, None, None));
        assert!(should_show_sidebar_tab(tab_id, None, Some(tab_id)));
    }

    #[test]
    fn duckduckgo_payload_becomes_compact_search_suggestions() {
        let body = r#"[{"phrase":"rust browser"},{"phrase":"rust browser engine"}]"#;
        assert_eq!(
            parse_duckduckgo_suggestions(body),
            ["rust browser", "rust browser engine"]
        );
    }

    #[test]
    fn duckduckgo_list_payload_is_also_supported() {
        let body = r#"["rust",["rust browser","rust browser engine"]]"#;
        assert_eq!(
            parse_duckduckgo_suggestions(body),
            ["rust browser", "rust browser engine"]
        );
    }

    #[test]
    fn suggestion_panel_keeps_click_frame_alive_after_input_loses_focus() {
        assert!(!should_dismiss_suggestions(true, true, false));
        assert!(!should_dismiss_suggestions(true, false, true));
        assert!(should_dismiss_suggestions(true, false, false));
    }

    #[test]
    fn suggestion_activates_on_primary_press_before_focus_teardown() {
        assert!(suggestion_activated(false, true));
        assert!(suggestion_activated(true, false));
        assert!(!suggestion_activated(false, false));
    }

    #[test]
    fn close_tab_activates_on_primary_press_before_row_rerender() {
        assert!(close_tab_activated(false, true));
        assert!(close_tab_activated(true, false));
        assert!(!close_tab_activated(false, false));
    }

    #[test]
    fn tab_close_icon_is_centered_with_equal_visual_edge_spacing() {
        assert_eq!(layout::tab_list::CLOSE_OFFSET, 6.0);
        assert_eq!(layout::tab_list::CLOSE_CENTER_X, 378.0);
        assert_eq!(layout::tab_list::CLOSE_ICON_HALF_EXTENT, 7.75);
    }

    #[test]
    fn suggestion_panel_stays_inside_blurred_sidebar_surface() {
        assert_eq!(suggestion_panel_content_width(252.0, 0.6), 220.8);
    }

    #[test]
    fn declared_favicon_is_preferred_from_page_markup() {
        let html = r#"<html><head><link rel="icon" href="/assets/icon.png"></head></html>"#;
        assert_eq!(extract_icon_href(html).as_deref(), Some("/assets/icon.png"));
    }
}

fn translation_languages() -> [TranslationLanguage; 10] {
    [
        TranslationLanguage::Auto,
        TranslationLanguage::English,
        TranslationLanguage::Russian,
        TranslationLanguage::German,
        TranslationLanguage::French,
        TranslationLanguage::Spanish,
        TranslationLanguage::Arabic,
        TranslationLanguage::Chinese,
        TranslationLanguage::Japanese,
        TranslationLanguage::Korean,
    ]
}

fn download_state_label(state: DownloadState) -> &'static str {
    match state {
        DownloadState::Queued => "Queued",
        DownloadState::InProgress => "Downloading",
        DownloadState::Paused => "Paused",
        DownloadState::Completed => "Complete",
        DownloadState::Failed => "Failed",
        DownloadState::Cancelled => "Cancelled",
    }
}

fn format_media_details(media: &MediaSessionUiState) -> String {
    let mut details = media.title.clone();
    if !media.artist.is_empty() {
        details.push_str(" — ");
        details.push_str(&media.artist);
    }
    if !media.album.is_empty() {
        details.push_str(" · ");
        details.push_str(&media.album);
    }
    if let Some((duration, rate, position)) = media.position {
        // `write!` to a `String` cannot fail.
        write!(details, " · {position:.0}/{duration:.0}s @ {rate:.2}x")
            .expect("write to String cannot fail");
    }
    details
}

// Byte counts are modest (memory/download sizes); f64 division rounding is
// irrelevant for display at one decimal place.
#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.0} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.0} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// Type-erased callback that paints a Servo page/extension surface onto the parent.
type ParentRenderCallback =
    Box<dyn Fn(&glow::Context, Rect<i32, euclid::UnknownUnit>, i32) + Send + Sync>;
fn ui_paint_callback(
    context: &egui::Context,
    rect: egui::Rect,
    render_to_parent: ParentRenderCallback,
) {
    context
        .layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("nomad-extension-popup"),
        ))
        .add(PaintCallback {
            rect,
            callback: Arc::new(CallbackFn::new(move |info, painter| {
                let clip = info.viewport_in_pixels();
                let target = Rect::new(
                    Point2D::new(clip.left_px, clip.from_bottom_px),
                    Size2D::new(clip.width_px, clip.height_px),
                );
                render_to_parent(painter.gl(), target, 0);
            })),
        });
}

// Hover radius is a small positive f32 design constant; u8 is the intended
// egui encoding.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn universal_suggestion_button(
    ui: &mut egui::Ui,
    suggestion: &UniversalSuggestion,
    selected: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), layout::suggestions::ITEM_HEIGHT),
        egui::Sense::click(),
    );
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.hovered() || selected {
        ui.painter().rect_filled(
            rect,
            egui::CornerRadius::same(layout::suggestions::HOVER_RADIUS as u8),
            egui::Color32::from_white_alpha(18),
        );
    }
    let painter = ui.painter().with_clip_rect(rect.shrink(4.0));
    paint_suggestion_icon(
        &painter,
        egui::pos2(rect.left() + 16.0, rect.center().y),
        suggestion.kind,
        egui::Color32::from_white_alpha(170),
    );
    painter.text(
        egui::pos2(
            rect.left() + 32.0,
            if suggestion.detail.is_empty() {
                rect.center().y
            } else {
                rect.top() + 8.0
            },
        ),
        if suggestion.detail.is_empty() {
            egui::Align2::LEFT_CENTER
        } else {
            egui::Align2::LEFT_TOP
        },
        compact_suggestion_title(suggestion),
        egui::FontId::proportional(13.0),
        design_white(),
    );
    if !suggestion.detail.is_empty() {
        painter.text(
            egui::pos2(rect.left() + 32.0, rect.bottom() - 7.0),
            egui::Align2::LEFT_BOTTOM,
            &suggestion.detail,
            egui::FontId::proportional(10.5),
            egui::Color32::from_white_alpha(125),
        );
    }
    response
}

fn paint_suggestion_icon(
    painter: &egui::Painter,
    center: egui::Pos2,
    kind: UniversalSuggestionKind,
    color: egui::Color32,
) {
    let stroke = egui::Stroke::new(1.2, color);
    match kind {
        UniversalSuggestionKind::Search => {
            painter.circle_stroke(center - egui::vec2(1.5, 1.5), 4.5, stroke);
            painter.line_segment(
                [center + egui::vec2(1.8, 1.8), center + egui::vec2(5.5, 5.5)],
                stroke,
            );
        }
        UniversalSuggestionKind::History => {
            painter.circle_stroke(center, 6.0, stroke);
            painter.line_segment([center, center + egui::vec2(0.0, -3.5)], stroke);
            painter.line_segment([center, center + egui::vec2(3.0, 1.5)], stroke);
        }
        UniversalSuggestionKind::Bookmark => {
            let rect = egui::Rect::from_center_size(center, egui::vec2(9.0, 12.0));
            painter.rect_stroke(rect, 1.5, stroke, egui::StrokeKind::Inside);
        }
        UniversalSuggestionKind::Tab => {
            painter.rect_stroke(
                egui::Rect::from_center_size(center, egui::vec2(12.0, 9.0)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        UniversalSuggestionKind::Address | UniversalSuggestionKind::Command => {
            painter.line_segment(
                [center - egui::vec2(4.0, 0.0), center + egui::vec2(4.0, 0.0)],
                stroke,
            );
            painter.line_segment(
                [
                    center + egui::vec2(1.0, -3.0),
                    center + egui::vec2(4.0, 0.0),
                ],
                stroke,
            );
            painter.line_segment(
                [center + egui::vec2(1.0, 3.0), center + egui::vec2(4.0, 0.0)],
                stroke,
            );
        }
    }
}

fn universal_suggestion_action(suggestion: &UniversalSuggestion) -> ChromeAction {
    match &suggestion.target {
        UniversalTarget::SelectTab(_) => ChromeAction::OpenUniversal(suggestion.target.clone()),
        _ => ChromeAction::OpenUniversalInNewTab(suggestion.target.clone()),
    }
}

fn should_dismiss_suggestions(
    input_lost_focus: bool,
    panel_hovered: bool,
    action_taken: bool,
) -> bool {
    input_lost_focus && !panel_hovered && !action_taken
}

fn suggestion_activated(clicked: bool, primary_press_on_row: bool) -> bool {
    clicked || primary_press_on_row
}

fn close_tab_activated(clicked: bool, primary_press_on_button: bool) -> bool {
    clicked || primary_press_on_button
}

fn suggestion_panel_content_width(sidebar_width: f32, scale: f32) -> f32 {
    sidebar_width
        - layout::address::SUGGESTIONS_INSET * scale
        - 2.0 * layout::address::SUGGESTIONS_MARGIN
}

fn compact_suggestion_title(suggestion: &UniversalSuggestion) -> String {
    url::Url::parse(&suggestion.title)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| suggestion.title.clone())
}

fn connection_transport_label(url: Option<&url::Url>) -> String {
    let Some(url) = url else {
        return "No active connection".to_owned();
    };
    match url.scheme() {
        "https" => "HTTPS / TLS (managed by Servo)".to_owned(),
        "http" => "HTTP (unencrypted transport)".to_owned(),
        "umc" => "UMC logical resource (transport via selected route)".to_owned(),
        "about" | "data" | "blob" => "Browser-managed resource".to_owned(),
        scheme => format!("{scheme} resource"),
    }
}

/// One-line label of the resolver configuration currently in effect,
/// including the workspace override state and the configured server.
fn resolver_effective_label(settings: &ResolverSettings, override_active: bool) -> String {
    let mut label = format!("Effective: {}", settings.mode.label());
    if override_active {
        label.push_str(" · workspace override active");
    }
    let server = match settings.mode {
        ResolverMode::Doh => settings.server_url.trim().to_owned(),
        ResolverMode::Dot => settings.server_host.trim().to_owned(),
        ResolverMode::Custom => format!(
            "{} ({})",
            settings.custom_server.trim(),
            settings.custom_protocol.label()
        ),
        ResolverMode::System => String::new(),
    };
    if !server.is_empty() {
        label.push_str(" · server: ");
        label.push_str(&server);
    }
    label
}

/// One-line outcome label for the engine's last recorded lookup.
fn resolver_lookup_label(lookup: &ResolverLookupStatus) -> String {
    let host = &lookup.host;
    match (lookup.path, lookup.error.as_ref()) {
        (ResolverPath::Literal, _) => format!("{host} — literal IP, no resolver involved"),
        (ResolverPath::Cache, None) => {
            format!("{host} — {} (cache hit), success", lookup.mode.label())
        }
        (ResolverPath::Cache, Some(error)) => format!(
            "{host} — {} (cache hit), failed: {error}",
            lookup.mode.label()
        ),
        (ResolverPath::Transport, None) => format!("{host} — {}, success", lookup.mode.label()),
        (ResolverPath::Transport, Some(error)) => {
            let closed = if lookup.transport_failure() {
                " (fail-closed)"
            } else {
                ""
            };
            format!("{host} — {}, failed: {error}{closed}", lookup.mode.label())
        }
    }
}

fn tunnel_status_label(route: &nomad_engine::NetworkRoute) -> &'static str {
    if route.mode() == nomad_core::RouteMode::Direct {
        "off (direct connection)"
    } else if route.proxy().is_some() {
        "local endpoint ready"
    } else {
        "not configured"
    }
}

fn status_mark(active: bool) -> &'static str {
    if active {
        "✓"
    } else {
        "—"
    }
}

impl Drop for Chrome {
    fn drop(&mut self) {
        self.context.destroy();
    }
}
