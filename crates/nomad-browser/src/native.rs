use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nomad_core::{BackendAvailability, RouteMode, Switches};
#[cfg(any(unix, windows))]
use nomad_engine::umc::UmcCore;
use nomad_engine::xray::{XrayConfig, XrayCore};
use nomad_engine::{
    parse_proxy_endpoint, reader_document_from_html, BrowserRuntime, DnsRoute,
    DownloadTransportEvent, EndpointTranslationExecutor, MediaSessionEvent,
    MediaSessionPlaybackState, NavigationError, NavigationLoadStatus, NetworkRoute, PageRenderer,
    PermissionDecision, PrivacyPolicy, ReaderMode, ServoError, ServoRenderer, TranslationProvider,
    TranslationRequest,
};
use nomad_shell::{
    BrowserCommand, BrowserSettings, SessionSnapshot, ShellError, ShellState, UniversalTarget,
};
use url::Url;
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy};
use winit::window::Window;

#[cfg(target_os = "macos")]
use winit::platform::macos::WindowAttributesExtMacOS;

use crate::chrome::{Chrome, ChromeAction, ChromeAxAction, ChromePanel};
use crate::frame_stats::FrameProfiler;
use crate::memory::{AvailableMemorySampler, ServoMemoryReportScheduler};
use crate::SessionAction;

static SESSION_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn install_macos_app_icon() -> Result<(), String> {
    use objc2::{AnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    let mtm = MainThreadMarker::new()
        .ok_or_else(|| "application icon must be installed on the main thread".to_owned())?;
    let bytes = include_bytes!("../assets/nomad-app-icon.png");
    let data = NSData::with_bytes(bytes);
    let image = NSImage::initWithData(NSImage::alloc(), &data)
        .ok_or_else(|| "Nomad application icon PNG could not be decoded".to_owned())?;
    let application = NSApplication::sharedApplication(mtm);
    unsafe { application.setApplicationIconImage(Some(&image)) };
    Ok(())
}
const CRASH_RECOVERY_ATTEMPT_LIMIT: u32 = 3;
const DEFAULT_RUNTIME_LOG_FILTER: &str =
    "warn,script::timers=off,webrender::device::gl=off,profile_traits::mem=off";
const EXTENSION_POLL_INTERVAL: Duration = Duration::from_millis(25);
const RESOURCE_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(500);

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn install_macos_glass(window: &Window) -> Result<(), String> {
    use std::ffi::c_void;
    use std::ptr::NonNull;

    use objc2_app_kit::{NSColor, NSView};
    use raw_window_handle::{
        AppKitWindowHandle, HandleError, HasWindowHandle, RawWindowHandle, WindowHandle,
    };

    struct ViewHandle(NonNull<c_void>);

    impl HasWindowHandle for ViewHandle {
        fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
            let raw = RawWindowHandle::AppKit(AppKitWindowHandle::new(self.0));
            Ok(unsafe { WindowHandle::borrow_raw(raw) })
        }
    }

    let raw = window
        .window_handle()
        .map_err(|error| error.to_string())?
        .as_raw();
    let RawWindowHandle::AppKit(handle) = raw else {
        return Err("winit did not provide an AppKit view".to_owned());
    };
    let content_view = unsafe { handle.ns_view.cast::<NSView>().as_ref() };
    let native_window = content_view
        .window()
        .ok_or_else(|| "AppKit content view has no window".to_owned())?;
    native_window.setOpaque(false);
    native_window.setBackgroundColor(Some(&NSColor::clearColor()));
    // Surfman composites its IOSurface through child CALayers. The window
    // flag alone is insufficient when any of those layers claims opacity.
    if let Some(layer) = content_view.layer() {
        layer.setOpaque(false);
        if let Some(children) = unsafe { layer.sublayers() } {
            for child in &children {
                child.setOpaque(false);
                unsafe {
                    let _: () = objc2::msg_send![&*child, setContentsOpaque: false];
                }
            }
        }
    }
    let host_view = unsafe { content_view.superview() }
        .ok_or_else(|| "AppKit content view has no host view".to_owned())?;
    let host_view_ref: &NSView = &host_view;
    let host_handle = ViewHandle(NonNull::from(host_view_ref).cast());

    window_vibrancy::apply_vibrancy(
        &host_handle,
        window_vibrancy::NSVisualEffectMaterial::Sidebar,
        Some(window_vibrancy::NSVisualEffectState::Active),
        Some(f64::from(crate::chrome::CHROME_SCALE * 27.0)),
    )
    .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn align_macos_window_controls(window: &Window) -> Result<(), String> {
    use objc2_app_kit::{NSView, NSWindowButton};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let raw = window
        .window_handle()
        .map_err(|error| error.to_string())?
        .as_raw();
    let RawWindowHandle::AppKit(handle) = raw else {
        return Err("winit did not provide an AppKit view".to_owned());
    };
    let content_view = unsafe { handle.ns_view.cast::<NSView>().as_ref() };
    let native_window = content_view
        .window()
        .ok_or_else(|| "AppKit content view has no window".to_owned())?;

    let buttons = [
        NSWindowButton::CloseButton,
        NSWindowButton::MiniaturizeButton,
        NSWindowButton::ZoomButton,
    ]
    .into_iter()
    .map(|kind| native_window.standardWindowButton(kind))
    .collect::<Option<Vec<_>>>()
    .ok_or_else(|| "AppKit did not provide all standard window controls".to_owned())?;
    // Chrome draws the Figma controls; keep AppKit's copies hidden after resize.
    for button in buttons {
        button.setHidden(true);
    }
    Ok(())
}

fn session_path() -> Option<PathBuf> {
    nomad_engine::user_paths().map(|paths| paths.data_dir.join("session.json"))
}

fn settings_path() -> Option<PathBuf> {
    nomad_engine::user_paths().map(|paths| paths.data_dir.join("settings.json"))
}

fn crash_marker_path() -> Option<PathBuf> {
    nomad_engine::user_paths().map(|paths| paths.data_dir.join("session.running"))
}

fn secure_session_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

fn reject_symlink_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Nomad session directory is not a real directory",
        ));
    }
    Ok(())
}

fn read_session_file(path: &Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    secure_session_options(&mut options);
    let mut file = options.open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn write_session_file(path: &Path, contents: &str) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Nomad session path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    reject_symlink_directory(parent)?;

    let counter = SESSION_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(
        ".session.json.{}.{}.tmp",
        std::process::id(),
        counter
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    secure_session_options(&mut options);
    let write_result = (|| {
        let mut file = options.open(&temp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_data()?;
        drop(file);

        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Nomad session path is a symbolic link",
                ));
            }
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Nomad session path is not a regular file",
                ));
            }
            #[cfg(windows)]
            fs::remove_file(path)?;
        }
        fs::rename(&temp_path, path)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

fn read_settings_file(path: &Path) -> io::Result<BrowserSettings> {
    let raw = read_session_file(path)?;
    serde_json::from_str(&raw).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_settings_file(path: &Path, settings: &BrowserSettings) -> io::Result<()> {
    let raw = serde_json::to_string_pretty(settings)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_session_file(path, &raw)
}

fn persist_settings(settings: &BrowserSettings) -> io::Result<()> {
    let path = settings_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Nomad settings path could not be resolved",
        )
    })?;
    write_settings_file(&path, settings)
}

fn load_startup_settings(default_download_directory: PathBuf) -> BrowserSettings {
    let defaults = BrowserSettings {
        download_directory: default_download_directory,
        ..BrowserSettings::default()
    };
    let Some(path) = settings_path() else {
        return defaults;
    };
    match read_settings_file(&path) {
        Ok(settings) => settings,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // One-time migration from releases that stored preferences inside
            // the session checkpoint. Settings remain valid even when tab
            // restoration is subsequently disabled.
            let migrated = session_path()
                .and_then(|session| read_session_file(&session).ok())
                .and_then(|raw| SessionSnapshot::from_json(&raw).ok())
                .map_or(defaults, |snapshot| snapshot.settings);
            if let Err(error) = write_settings_file(&path, &migrated) {
                eprintln!("Nomad migrated settings could not be written: {error}");
            }
            migrated
        }
        Err(error) => {
            eprintln!("Nomad settings could not be loaded; using defaults: {error}");
            defaults
        }
    }
}

fn remove_session_file(path: &Path) -> io::Result<()> {
    fs::remove_file(path)
}

fn write_crash_marker(path: &Path) -> io::Result<()> {
    write_crash_marker_with_attempts(path, 1)
}

fn write_crash_marker_with_attempts(path: &Path, attempts: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Nomad crash-marker path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    reject_symlink_directory(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    secure_session_options(&mut options);
    let mut file = options.open(path)?;
    writeln!(file, "pid={}", std::process::id())?;
    writeln!(file, "attempts={attempts}")?;
    file.sync_data()
}

fn read_crash_marker_attempts(path: &Path) -> io::Result<Option<u32>> {
    let raw = match read_session_file(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let attempts = raw
        .lines()
        .find_map(|line| {
            line.strip_prefix("attempts=")
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(1);
    Ok(Some(attempts.max(1)))
}

const fn should_skip_session_restore(attempts: u32) -> bool {
    attempts >= CRASH_RECOVERY_ATTEMPT_LIMIT
}

fn clear_crash_marker(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Nomad crash-marker path is a symbolic link",
        )),
        Ok(metadata) if !metadata.is_file() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Nomad crash-marker path is not a regular file",
        )),
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn move_session_file(path: &Path, label: &str) -> io::Result<Option<PathBuf>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Nomad corrupt-session path is not a regular file",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Nomad session path has no parent directory",
        )
    })?;
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("session");
    let counter = SESSION_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let quarantine = parent.join(format!(
        ".{stem}.{label}.{}.{}.json",
        std::process::id(),
        counter
    ));
    if fs::symlink_metadata(&quarantine).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Nomad corrupt-session quarantine path already exists",
        ));
    }
    fs::rename(path, &quarantine)?;
    Ok(Some(quarantine))
}

fn quarantine_session_file(path: &Path) -> io::Result<Option<PathBuf>> {
    move_session_file(path, "corrupt")
}

fn archive_session_file(path: &Path) -> io::Result<Option<PathBuf>> {
    move_session_file(path, "discarded")
}

pub fn parse_initial_url(raw_url: Option<&str>) -> Result<Option<Url>, ServoError> {
    raw_url
        .map(|raw_url| {
            Url::parse(raw_url).map_err(|_| ServoError::InvalidInitialUrl(raw_url.to_owned()))
        })
        .transpose()
}

fn default_download_directory() -> PathBuf {
    if let Some(path) = std::env::var_os("NOMAD_DOWNLOADS_DIR") {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    if let Some(path) = std::env::var_os("XDG_DOWNLOAD_DIR") {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(
            || PathBuf::from("downloads"),
            |home| PathBuf::from(home).join("Downloads"),
        )
}

fn recover_interrupted_update() -> Result<(), ServoError> {
    let executable = std::env::current_exe()
        .map_err(|error| ServoError::Native(format!("locate Nomad executable: {error}")))?;
    let installer = nomad_engine::UpdateInstaller::new(executable);
    if installer
        .recover_interrupted()
        .map_err(|error| ServoError::Native(format!("recover Nomad update: {error:?}")))?
    {
        eprintln!("Nomad recovered an interrupted update before launch");
    }
    Ok(())
}

pub fn run(
    initial_url: Option<Url>,
    switches: Switches,
    webdriver_port: Option<u16>,
    devtools_port: Option<u16>,
    extension_archive: Option<PathBuf>,
    ignore_certificate_errors: bool,
    session_action: SessionAction,
) -> Result<(), ServoError> {
    recover_interrupted_update()?;
    // Servo currently emits three benign debug-build warnings during the first
    // frame and orderly shutdown: an idempotent timer resume, a zero-width
    // texture upload while the page surface is being sized, and a profiler
    // channel closing after the browser has already exited. Keep real warnings
    // visible and let advanced users override this filter with RUST_LOG.
    match std::env::var("RUST_LOG") {
        Ok(existing)
            if existing.contains("script::timers")
                || existing.contains("webrender::device::gl")
                || existing.contains("profile_traits::mem") => {}
        Ok(existing) if !existing.trim().is_empty() => {
            std::env::set_var(
                "RUST_LOG",
                format!("{existing},{DEFAULT_RUNTIME_LOG_FILTER}"),
            );
        }
        _ => std::env::set_var("RUST_LOG", DEFAULT_RUNTIME_LOG_FILTER),
    }
    nomad_engine::initialize_tls_provider()
        .map_err(|error| ServoError::Native(error.to_owned()))?;
    let network_runtime = network_runtime_for_switches(switches)?;
    let event_loop = EventLoop::with_user_event()
        .build()
        .map_err(|error| ServoError::Native(format!("event loop: {error}")))?;
    let proxy = event_loop.create_proxy();
    let mut app = NativeApp {
        frame_profiler: None,
        initial_url,
        switches,
        webdriver_port,
        devtools_port,
        extension_archive,
        ignore_certificate_errors,
        session_action,
        network_runtime,
        proxy,
        state: AppState::Initial,
    };
    event_loop
        .run_app(&mut app)
        .map_err(|error| ServoError::Native(format!("event loop: {error}")))
}

struct NetworkRuntime {
    route: NetworkRoute,
    #[cfg(any(unix, windows))]
    umc_core: Option<UmcCore>,
    xray_core: Option<XrayCore>,
}

impl NetworkRuntime {
    fn reconfigure(
        &mut self,
        switches: Switches,
        renderer: &mut ServoRenderer,
    ) -> Result<(), ServoError> {
        let replacement = network_runtime_for_switches(switches)?;
        renderer.set_network_route(replacement.route.clone())?;
        *self = replacement;
        Ok(())
    }

    fn close_umc_application(&mut self, tab_id: nomad_engine::TabId) {
        #[cfg(any(unix, windows))]
        if let Some(core) = self.umc_core.as_mut() {
            core.close_application(tab_id.get());
        }
        #[cfg(not(any(unix, windows)))]
        let _ = tab_id;
    }
}

fn network_runtime_for_switches(switches: Switches) -> Result<NetworkRuntime, ServoError> {
    let mut runtime = NetworkRuntime {
        route: NetworkRoute::direct(),
        #[cfg(any(unix, windows))]
        umc_core: None,
        xray_core: None,
    };
    if switches.umc_enabled() {
        #[cfg(any(unix, windows))]
        {
            let socket = umc_socket_from_environment()?;
            let protocol = std::env::var("NOMAD_UMC_PROTOCOL")
                .unwrap_or_else(|_| "org.nomad.browser.tcp/1".to_owned());
            let destination = umc_destination_from_environment()?;
            let core = UmcCore::start(socket, protocol, destination)
                .map_err(|error| ServoError::Native(format!("UMC core failed: {error}")))?;
            runtime.route = NetworkRoute::new(
                RouteMode::Umc,
                Some(core.endpoint().clone()),
                DnsRoute::ViaProxy,
            );
            runtime.umc_core = Some(core);
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(ServoError::Native(
                "UMC local Control API integration requires Unix sockets or Windows named pipes on this build".into(),
            ));
        }
    } else if switches.xray_enabled() {
        let config = xray_config_from_environment()?;
        let core = XrayCore::start(config)
            .map_err(|error| ServoError::Native(format!("Xray core failed: {error}")))?;
        runtime.route = NetworkRoute::new(
            RouteMode::Xray,
            Some(core.endpoint().clone()),
            DnsRoute::ViaProxy,
        );
        runtime.xray_core = Some(core);
    }
    runtime
        .route
        .validate()
        .map_err(|error| ServoError::Native(format!("network route rejected: {error:?}")))?;
    Ok(runtime)
}

fn sync_umc_diagnostics(network_runtime: &NetworkRuntime, renderer: &mut ServoRenderer) {
    #[cfg(any(unix, windows))]
    renderer.set_umc_diagnostics(
        network_runtime
            .umc_core
            .as_ref()
            .map(nomad_engine::umc::UmcCore::diagnostics),
    );
    #[cfg(not(any(unix, windows)))]
    {
        let _ = network_runtime;
        renderer.set_umc_diagnostics(None);
    }
}

fn umc_socket_from_environment() -> Result<std::path::PathBuf, ServoError> {
    if let Ok(path) = std::env::var("NOMAD_UMC_SOCKET") {
        if path.is_empty() {
            return Err(ServoError::Native("NOMAD_UMC_SOCKET is empty".into()));
        }
        return Ok(path.into());
    }
    #[cfg(unix)]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            ServoError::Native("NOMAD_UMC_SOCKET is required when HOME is unavailable".into())
        })?;
        Ok(std::path::PathBuf::from(home).join(".local/run/umc.sock"))
    }
    #[cfg(windows)]
    {
        Ok(std::path::PathBuf::from(r"\\.\pipe\umc-control"))
    }
    #[cfg(not(any(unix, windows)))]
    Err(ServoError::Native(
        "UMC local Control API has no supported IPC transport on this platform".into(),
    ))
}

#[cfg(any(unix, windows))]
fn umc_destination_from_environment() -> Result<Vec<u8>, ServoError> {
    let Ok(raw) = std::env::var("NOMAD_UMC_DESTINATION") else {
        return Ok(Vec::new());
    };
    if raw.is_empty() {
        return Err(ServoError::Native("NOMAD_UMC_DESTINATION is empty".into()));
    }
    if raw.len() != 64 {
        return Err(ServoError::Native(
            "NOMAD_UMC_DESTINATION must contain exactly 64 hex characters".into(),
        ));
    }
    let mut destination = Vec::with_capacity(32);
    let bytes = raw.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = hex_value(pair[0]).ok_or_else(|| {
            ServoError::Native("NOMAD_UMC_DESTINATION contains non-hex characters".into())
        })?;
        let low = hex_value(pair[1]).ok_or_else(|| {
            ServoError::Native("NOMAD_UMC_DESTINATION contains non-hex characters".into())
        })?;
        destination.push((high << 4) | low);
    }
    Ok(destination)
}

#[cfg(any(unix, windows))]
fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn xray_config_from_environment() -> Result<XrayConfig, ServoError> {
    if let Ok(path) = std::env::var("NOMAD_XRAY_CONFIG") {
        return XrayConfig::from_path(path)
            .map_err(|error| ServoError::Native(format!("invalid Xray config: {error}")));
    }
    let endpoint = proxy_from_environment("NOMAD_XRAY_PROXY")?.ok_or_else(|| {
        ServoError::Native(
            "Xray is enabled but NOMAD_XRAY_CONFIG or NOMAD_XRAY_PROXY is missing".into(),
        )
    })?;
    Ok(XrayConfig::from_upstream(endpoint))
}

fn proxy_from_environment(name: &str) -> Result<Option<nomad_engine::ProxyEndpoint>, ServoError> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(None);
    };
    parse_proxy_endpoint(&raw)
        .map(Some)
        .map_err(|error| ServoError::Native(format!("invalid {name} proxy endpoint: {error:?}")))
}

#[derive(Clone)]
struct ServoWaker(EventLoopProxy<ServoEvent>);

#[derive(Debug)]
enum ServoEvent {
    Wake,
    AccessKit(egui_winit::accesskit_winit::Event),
}

impl From<egui_winit::accesskit_winit::Event> for ServoEvent {
    fn from(event: egui_winit::accesskit_winit::Event) -> Self {
        Self::AccessKit(event)
    }
}

impl nomad_engine::servo::EventLoopWaker for ServoWaker {
    fn clone_box(&self) -> Box<dyn nomad_engine::servo::EventLoopWaker> {
        Box::new(self.clone())
    }

    fn wake(&self) {
        let _ = self.0.send_event(ServoEvent::Wake);
    }
}

fn install_egui_repaint_waker(chrome: &Chrome, repaint_proxy: EventLoopProxy<ServoEvent>) {
    chrome.set_request_repaint_callback(move |request| {
        let proxy = repaint_proxy.clone();
        if request.delay.is_zero() {
            let _ = proxy.send_event(ServoEvent::Wake);
        } else if request.delay != Duration::MAX {
            std::thread::spawn(move || {
                std::thread::sleep(request.delay);
                let _ = proxy.send_event(ServoEvent::Wake);
            });
        }
    });
}

struct NativeApp {
    initial_url: Option<Url>,
    switches: Switches,
    webdriver_port: Option<u16>,
    devtools_port: Option<u16>,
    extension_archive: Option<PathBuf>,
    ignore_certificate_errors: bool,
    session_action: SessionAction,
    network_runtime: NetworkRuntime,
    proxy: EventLoopProxy<ServoEvent>,
    frame_profiler: Option<FrameProfiler>,
    state: AppState,
}

enum AppState {
    Initial,
    Running {
        window: Rc<Window>,
        renderer: Box<ServoRenderer>,
        chrome: Box<Chrome>,
        shell: Box<ShellState>,
        maintenance: MaintenanceState,
        pending_session: Option<String>,
        pending_initial_url: Box<Option<(Url, Instant)>>,
        #[cfg(target_os = "macos")]
        macos_window_controls_aligned: bool,
    },
}

/// Periodic bookkeeping for background polling and resource maintenance.
struct MaintenanceState {
    memory_sampler: AvailableMemorySampler,
    memory_report_scheduler: ServoMemoryReportScheduler,
    last_extension_poll: Instant,
    last_resource_maintenance: Instant,
}

impl ApplicationHandler<ServoEvent> for NativeApp {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if !matches!(self.state, AppState::Initial) {
            return;
        }

        let Some((window, mut renderer, mut chrome, mut shell)) = self.resume_bootstrap(event_loop)
        else {
            return;
        };

        let (previous_crash_attempts, skip_session_restore) = self.prepare_crash_recovery();
        let Some((initial_url, pending_session, session_restored)) = self.restore_previous_session(
            event_loop,
            &mut renderer,
            &mut shell,
            &mut chrome,
            previous_crash_attempts,
            skip_session_restore,
        ) else {
            return;
        };

        if !session_restored {
            let blank_tab = shell.active_tab().expect("ShellState creates a tab");
            if let Err(error) = shell.configure_renderer_tab(blank_tab, &mut renderer) {
                eprintln!("Nomad blank-tab container initialization failed: {error:?}");
                event_loop.exit();
                return;
            }
            if let Err(error) = renderer.activate(blank_tab) {
                eprintln!("Nomad blank-tab initialization failed: {error:?}");
                event_loop.exit();
                return;
            }
            renderer.spin_event_loop();
        } else if let Err(error) = apply_active_workspace_route(&shell, &mut renderer) {
            eprintln!("Nomad workspace route restore failed: {error:?}");
            event_loop.exit();
            return;
        }

        renderer.spin_event_loop();
        window.request_redraw();
        self.frame_profiler = FrameProfiler::from_env(
            window
                .current_monitor()
                .and_then(|monitor| monitor.refresh_rate_millihertz()),
        );
        self.state = AppState::Running {
            window,
            renderer: Box::new(renderer),
            chrome: Box::new(chrome),
            shell: Box::new(shell),
            maintenance: MaintenanceState {
                memory_sampler: AvailableMemorySampler::default(),
                memory_report_scheduler: ServoMemoryReportScheduler::default(),
                last_extension_poll: Instant::now(),
                last_resource_maintenance: Instant::now(),
            },
            pending_session,
            pending_initial_url: Box::new(
                initial_url
                    .filter(|url| url.as_str() != "about:blank" || session_restored)
                    .map(|url| (url, Instant::now() + Duration::from_millis(150))),
            ),
            #[cfg(target_os = "macos")]
            macos_window_controls_aligned: false,
        };
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: ServoEvent) {
        if let ServoEvent::AccessKit(accesskit_event) = event {
            if let AppState::Running {
                window,
                chrome,
                shell,
                renderer,
                ..
            } = &mut self.state
            {
                if accesskit_event.window_id == window.id() {
                    match &accesskit_event.window_event {
                        egui_winit::accesskit_winit::WindowEvent::InitialTreeRequested => {
                            renderer.set_accessibility_active(true);
                        }
                        egui_winit::accesskit_winit::WindowEvent::AccessibilityDeactivated => {
                            renderer.set_accessibility_active(false);
                        }
                        egui_winit::accesskit_winit::WindowEvent::ActionRequested(_) => {}
                    }
                    // Chrome-targeted actions (toolbar, address field, tab
                    // list) are handled locally; everything else goes to the
                    // page renderer.
                    if let Some(ax_action) = chrome.take_chrome_ax_action(shell, &accesskit_event) {
                        apply_chrome_ax_action(ax_action, chrome, shell, renderer);
                    } else if let Some(request) = chrome.on_accessibility_event(accesskit_event) {
                        if let Some(tab_id) = shell.active_tab() {
                            renderer.dispatch_accessibility_action(tab_id, request);
                        }
                    }
                }
            }
        }
        self.process_servo_events(event_loop, true);
    }

    /// Spins the renderer, dispatches queued renderer events, and optionally
    /// requests a redraw. Returns `true` when the caller must return
    /// immediately because the event loop is exiting or the app is not
    /// running.
    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: winit::window::WindowId,
        event: WindowEvent,
    ) {
        let AppState::Running {
            renderer,
            chrome,
            window,
            ..
        } = &mut self.state
        else {
            return;
        };

        let egui_response = chrome.on_window_event(window, &event);
        let mut needs_redraw = egui_response.repaint;
        let page_pointer_event = matches!(
            &event,
            WindowEvent::MouseInput { .. } | WindowEvent::MouseWheel { .. }
        ) && renderer.pointer_over_content()
            && !chrome.blocks_page_pointer_input();
        let tracks_page_pointer = matches!(
            &event,
            WindowEvent::CursorMoved { .. } | WindowEvent::CursorLeft { .. }
        );
        if !egui_response.consumed || page_pointer_event || tracks_page_pointer {
            renderer.handle_window_event(&event);
        }
        match event {
            WindowEvent::CloseRequested => {
                if let Some(profiler) = self.frame_profiler.as_mut() {
                    profiler.finish(Instant::now());
                }
                event_loop.exit();
            }
            WindowEvent::RedrawRequested => {
                needs_redraw = self.handle_redraw_requested(event_loop);
            }
            WindowEvent::Resized(size) => {
                renderer.resize(size);
                #[cfg(target_os = "macos")]
                if let Err(error) = align_macos_window_controls(window) {
                    eprintln!("Nomad macOS window controls could not be realigned: {error}");
                }
                needs_redraw = true;
            }
            #[cfg(target_os = "macos")]
            WindowEvent::ScaleFactorChanged { scale_factor, .. } => {
                renderer.resize(window.inner_size());
                #[allow(clippy::cast_possible_truncation)]
                // winit reports f64; the renderer API takes f32.
                renderer.set_hidpi_scale_factor(scale_factor as f32);
                if let Err(error) = align_macos_window_controls(window) {
                    eprintln!("Nomad macOS window controls could not be realigned: {error}");
                }
                needs_redraw = true;
            }
            WindowEvent::ThemeChanged(theme) => {
                renderer.set_dark_theme(matches!(theme, winit::window::Theme::Dark));
                needs_redraw = true;
            }
            _ => (),
        }
        self.process_servo_events(event_loop, needs_redraw);
    }
}

impl NativeApp {
    /// Creates the window, renderer, chrome, and shell; returns `None` (after
    /// exiting the event loop) when any startup step fails.
    fn resume_bootstrap(
        &mut self,
        event_loop: &ActiveEventLoop,
    ) -> Option<(Rc<Window>, ServoRenderer, Chrome, ShellState)> {
        let attributes = Window::default_attributes()
            .with_title("Nomad Browser")
            .with_inner_size(LogicalSize::new(1280, 800))
            .with_min_inner_size(LogicalSize::new(860, 560))
            .with_transparent(true)
            .with_decorations(true)
            .with_visible(false);
        #[cfg(target_os = "macos")]
        let attributes = attributes
            .with_titlebar_transparent(true)
            .with_title_hidden(true)
            .with_titlebar_hidden(false)
            .with_titlebar_buttons_hidden(true)
            .with_fullsize_content_view(true)
            .with_has_shadow(true);

        let window = match event_loop.create_window(attributes) {
            Ok(window) => Rc::new(window),
            Err(error) => {
                eprintln!("Nomad native shell failed to create a window: {error}");
                return None;
            }
        };

        // Surfman captures NSWindow opacity when it creates its surface, then
        // restores that value on resize. Configure it before renderer creation.
        #[cfg(target_os = "macos")]
        if let Err(error) = install_macos_glass(&window) {
            eprintln!("Nomad macOS glass could not be initialized: {error}");
        }
        let waker = Box::new(ServoWaker(self.proxy.clone()));
        let mut renderer = match ServoRenderer::new_with_webdriver_devtools_options(
            window.clone(),
            waker,
            self.network_runtime.route.clone(),
            self.webdriver_port,
            self.devtools_port,
            self.ignore_certificate_errors,
        ) {
            Ok(renderer) => renderer,
            Err(error) => {
                eprintln!("Nomad Servo initialization failed: {error:?}");
                event_loop.exit();
                return None;
            }
        };
        let mut chrome = match Chrome::new(event_loop, &renderer) {
            Ok(chrome) => chrome,
            Err(error) => {
                eprintln!("Nomad chrome initialization failed: {error:?}");
                event_loop.exit();
                return None;
            }
        };
        install_egui_repaint_waker(&chrome, self.proxy.clone());
        #[cfg(target_os = "macos")]
        if let Err(error) = install_macos_glass(&window) {
            eprintln!("Nomad macOS glass could not be enabled: {error}");
        }
        #[cfg(target_os = "macos")]
        if let Err(error) = install_macos_app_icon() {
            eprintln!("Nomad macOS application icon could not be enabled: {error}");
        }
        chrome.init_accessibility(event_loop, &window, self.proxy.clone());
        window.set_visible(true);
        let runtime = match BrowserRuntime::new(self.switches, BackendAvailability::all_available())
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("Nomad runtime initialization failed: {error:?}");
                event_loop.exit();
                return None;
            }
        };
        let settings = load_startup_settings(default_download_directory());
        renderer.set_privacy_policy(PrivacyPolicy::for_mode(settings.privacy_mode));
        if let Err(error) = renderer.set_route_policy(settings.route_policy.clone()) {
            eprintln!("Nomad saved route policy could not be applied: {error}");
        }
        let mut shell = ShellState::with_settings(runtime, settings);

        if let Some(path) = self.extension_archive.take() {
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    eprintln!(
                        "Nomad extension archive could not be read ({}): {error}",
                        path.display()
                    );
                    event_loop.exit();
                    return None;
                }
            };
            if let Err(error) =
                shell.install_extension_archive_with_renderer_and_grants(&bytes, &mut renderer)
            {
                eprintln!(
                    "Nomad extension archive could not be installed ({}): {error:?}",
                    path.display()
                );
                event_loop.exit();
                return None;
            }
        }
        Some((window, renderer, chrome, shell))
    }

    /// Reads the crash marker, logs the previous interrupted session, and
    /// decides whether session restore must be skipped. Returns the previous
    /// crash attempt count and the skip-restore decision.
    fn prepare_crash_recovery(&self) -> (u32, bool) {
        let previous_crash_attempts = match crash_marker_path() {
            Some(path) => match read_crash_marker_attempts(&path) {
                Ok(Some(attempts)) => attempts,
                Ok(None) => 0,
                Err(error) => {
                    eprintln!("Nomad crash marker could not be read: {error}");
                    0
                }
            },
            None => 0,
        };
        let force_restore = matches!(self.session_action, SessionAction::Restore);
        let force_clean = matches!(self.session_action, SessionAction::StartClean);
        let skip_session_restore =
            force_clean || (!force_restore && should_skip_session_restore(previous_crash_attempts));
        if previous_crash_attempts > 0 {
            eprintln!(
                "Nomad detected an interrupted previous session (attempt {previous_crash_attempts})"
            );
        }
        if force_clean {
            eprintln!("Nomad starting a clean session by user request");
            if let Some(path) = session_path() {
                if let Err(error) = archive_session_file(&path) {
                    eprintln!("Nomad saved-session archive failed: {error}");
                }
            }
        } else if skip_session_restore {
            eprintln!(
                "Nomad detected a crash loop; starting a clean session and quarantining the saved session"
            );
            if let Some(path) = session_path() {
                if let Err(error) = quarantine_session_file(&path) {
                    eprintln!("Nomad crash-loop session quarantine failed: {error}");
                }
            }
        }
        if let Some(marker) = crash_marker_path() {
            let marker_result = if previous_crash_attempts == 0 {
                write_crash_marker(&marker)
            } else {
                write_crash_marker_with_attempts(&marker, previous_crash_attempts.saturating_add(1))
            };
            if let Err(error) = marker_result {
                eprintln!("Nomad crash marker could not be written: {error}");
            }
        }
        (previous_crash_attempts, skip_session_restore)
    }

    /// Restores the saved session after a clean exit and queues the pending
    /// recovery prompt when the previous session was interrupted. Returns
    /// `None` (after exiting the event loop) when a required renderer policy
    /// change fails; otherwise returns the initial URL, the pending recovery
    /// session JSON, and whether a session was restored.
    fn restore_previous_session(
        &mut self,
        event_loop: &ActiveEventLoop,
        renderer: &mut ServoRenderer,
        shell: &mut ShellState,
        chrome: &mut Chrome,
        previous_crash_attempts: u32,
        skip_session_restore: bool,
    ) -> Option<(Option<Url>, Option<String>, bool)> {
        let force_restore = matches!(self.session_action, SessionAction::Restore);
        let force_clean = matches!(self.session_action, SessionAction::StartClean);
        let initial_url = self.initial_url.take();
        let prompt_for_recovery =
            previous_crash_attempts > 0 && !force_restore && !force_clean && initial_url.is_none();
        let mut session_restored = false;
        let mut pending_session = None;
        if !skip_session_restore
            && (initial_url.is_none() || force_restore)
            && shell.settings().session_persistence_enabled()
        {
            if let Some(session_path) = session_path() {
                match read_session_file(&session_path) {
                    Ok(raw_session) => match SessionSnapshot::from_json(&raw_session) {
                        Ok(mut snapshot) => {
                            // Durable settings are authoritative. The settings copy in an
                            // old session exists for sync/backward compatibility only.
                            snapshot.settings = shell.settings().clone();
                            let raw_session = match snapshot.to_json() {
                                Ok(raw) => raw,
                                Err(error) => {
                                    eprintln!("Nomad session normalization failed: {error:?}");
                                    return Some((initial_url, None, false));
                                }
                            };
                            if prompt_for_recovery {
                                pending_session = Some(raw_session);
                                chrome.set_session_recovery_prompt(true);
                            } else {
                                renderer.set_privacy_policy(PrivacyPolicy::for_mode(
                                    shell.settings().privacy_mode,
                                ));
                                if let Err(error) =
                                    renderer.set_route_policy(shell.settings().route_policy.clone())
                                {
                                    eprintln!("Nomad session route policy rejected: {error}");
                                    event_loop.exit();
                                    return None;
                                }
                                if let Err(error) =
                                    shell.restore_session_with_renderer(&raw_session, renderer)
                                {
                                    eprintln!("Nomad session restore failed: {error:?}");
                                    if let Err(quarantine_error) =
                                        quarantine_session_file(&session_path)
                                    {
                                        eprintln!("Nomad failed-session quarantine failed: {quarantine_error}");
                                    }
                                } else {
                                    if let Err(error) =
                                        shell.sync_extension_backgrounds_with_renderer(renderer)
                                    {
                                        eprintln!(
                                            "Nomad extension background restore failed: {error:?}"
                                        );
                                    }
                                    if let Err(error) =
                                        shell.refresh_extension_scripts_with_renderer(renderer)
                                    {
                                        eprintln!(
                                            "Nomad extension script restore failed: {error:?}"
                                        );
                                    }
                                    if let Err(error) = shell.restore_persisted_sync_key() {
                                        eprintln!("Nomad sync key restore failed: {error:?}");
                                    }
                                    session_restored = true;
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!("Nomad session is corrupt; quarantining it: {error:?}");
                            if let Err(quarantine_error) = quarantine_session_file(&session_path) {
                                eprintln!(
                                    "Nomad corrupt session quarantine failed: {quarantine_error}"
                                );
                            }
                        }
                    },
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        eprintln!("Nomad session read failed: {error}");
                    }
                    Err(_) => {}
                }
            }
        }
        Some((initial_url, pending_session, session_restored))
    }

    fn process_servo_events(&mut self, event_loop: &ActiveEventLoop, request_redraw: bool) -> bool {
        let AppState::Running {
            window,
            renderer,
            chrome,
            shell,
            maintenance,
            ..
        } = &mut self.state
        else {
            return true;
        };
        renderer.spin_event_loop();
        if renderer.take_webdriver_shutdown_request() {
            persist_session(shell);
            event_loop.exit();
            return true;
        }
        process_autofill(renderer, chrome);
        process_permissions(renderer, shell);
        process_downloads(renderer, shell);
        process_resources(
            renderer,
            chrome,
            shell,
            &mut self.network_runtime,
            maintenance,
        );
        process_accessibility(renderer, chrome, shell);
        if request_redraw {
            window.request_redraw();
        }
        false
    }
    /// Runs one full redraw pass: aligns macOS window controls, flushes any
    /// ready initial navigation, paints chrome and pages, and applies the
    /// resulting chrome action.
    fn handle_redraw_requested(&mut self, event_loop: &ActiveEventLoop) -> bool {
        let AppState::Running {
            window,
            renderer,
            chrome,
            shell,
            pending_session,
            pending_initial_url,
            #[cfg(target_os = "macos")]
            macos_window_controls_aligned,
            ..
        } = &mut self.state
        else {
            return false;
        };
        let mut needs_redraw = false;
        let frame_start = Instant::now();
        // Standard titlebar buttons receive their final AppKit frames
        // only after the first presented window cycle. Capture and
        // offset that stable geometry here, not synchronously after
        // `set_visible`, so launch and live-resize layouts agree.
        #[cfg(target_os = "macos")]
        if !*macos_window_controls_aligned {
            if let Err(error) = align_macos_window_controls(window) {
                eprintln!("Nomad macOS window controls could not be aligned: {error}");
            } else {
                *macos_window_controls_aligned = true;
            }
        }
        flush_pending_navigation(window, renderer, shell, pending_initial_url);
        let visible_tabs: Vec<_> = shell
            .split_layout()
            .panes()
            .iter()
            .map(|pane| pane.tab_id)
            .filter(|tab_id| {
                shell
                    .tab(*tab_id)
                    .and_then(|tab| tab.url.as_ref())
                    .is_none_or(|url| url.as_str() != "about:settings")
            })
            .collect();
        renderer.set_visible_tabs(&visible_tabs);
        sync_umc_diagnostics(&self.network_runtime, renderer);
        let action = match chrome.update(window, renderer, shell) {
            Ok(action) => action,
            Err(error) => {
                eprintln!("Nomad chrome update failed: {error:?}");
                event_loop.exit();
                return false;
            }
        };
        // Chrome sizes and paints visible page surfaces before it captures their
        // composition callbacks. Keeping those operations in one phase avoids presenting
        // transient loading/caret frames against an out-of-date page surface.
        if let Err(error) = chrome.paint(window, renderer) {
            eprintln!("Nomad chrome paint failed: {error:?}");
            event_loop.exit();
            return false;
        }
        if let Some(action) = action {
            if matches!(action, ChromeAction::Quit) {
                persist_session(shell);
                if let Some(profiler) = self.frame_profiler.as_mut() {
                    profiler.finish(Instant::now());
                }
                event_loop.exit();
                return false;
            }
            apply_chrome_action(
                action,
                chrome,
                shell,
                renderer,
                &mut self.network_runtime,
                &mut self.switches,
                pending_session,
            );
            needs_redraw = true;
        }
        if let Some(profiler) = self.frame_profiler.as_mut() {
            profiler.record_frame(frame_start.elapsed(), Instant::now());
        }
        needs_redraw
    }
}

fn process_accessibility(renderer: &mut ServoRenderer, chrome: &mut Chrome, shell: &ShellState) {
    static TICKS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    if TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3 {
        eprintln!("Nomad AX diag: process_accessibility tick");
    }
    chrome.update_accessibility_tree_for_tab(
        shell.active_tab(),
        renderer.take_accessibility_updates(),
    );
    chrome.push_chrome_accessibility(shell);
}

/// Handles an assistive-technology action targeting browser chrome by reusing
/// the same shell flows as pointer and keyboard input.
fn apply_chrome_ax_action(
    action: ChromeAxAction,
    chrome: &mut Chrome,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) {
    let _ = chrome;
    match action {
        ChromeAxAction::Back => {
            let _ = shell.go_back_with_renderer(renderer);
        }
        ChromeAxAction::Forward => {
            let _ = shell.go_forward_with_renderer(renderer);
        }
        ChromeAxAction::Reload => {
            let _ = shell.reload_active_tab_with_renderer(renderer);
        }
        ChromeAxAction::NewTab => {
            let _ = shell.focus_or_create_blank_tab_with_renderer(renderer);
        }
        ChromeAxAction::ActivateTab(tab_id) => {
            let _ = shell.select_tab_with_renderer(tab_id, renderer);
        }
    }
}

fn process_autofill(renderer: &mut ServoRenderer, chrome: &mut Chrome) {
    for (tab_id, fields) in renderer.take_autofill_snapshots() {
        chrome.set_autofill_fields(tab_id, fields);
    }
}

/// Submits the queued initial navigation once its startup delay has elapsed,
/// requesting another redraw while it is still pending.
fn flush_pending_navigation(
    window: &Rc<Window>,
    renderer: &mut ServoRenderer,
    shell: &mut ShellState,
    pending_initial_url: &mut Option<(Url, Instant)>,
) {
    let initial_ready = pending_initial_url
        .as_ref()
        .is_some_and(|(_, ready_at)| Instant::now() >= *ready_at);
    if initial_ready {
        let (url, _) = pending_initial_url
            .take()
            .expect("ready initial navigation exists");
        shell.set_address_input(url.as_str());
        if let Err(error) = shell.submit_address_with_renderer(renderer) {
            eprintln!("Nomad initial navigation failed: {error:?}");
        }
    } else if pending_initial_url.is_some() {
        window.request_redraw();
    }
}

fn process_permissions(renderer: &mut ServoRenderer, shell: &mut ShellState) {
    for prompt in renderer.take_permission_requests() {
        match shell.permission_decision(&prompt.site, prompt.kind) {
            PermissionDecision::Allow => {
                if let Err(error) = renderer.respond_permission(prompt.id, true) {
                    eprintln!("Nomad permission allow failed: {error:?}");
                }
            }
            PermissionDecision::Block => {
                if let Err(error) = renderer.respond_permission(prompt.id, false) {
                    eprintln!("Nomad permission deny failed: {error:?}");
                }
            }
            PermissionDecision::Ask => shell.queue_permission(nomad_shell::PermissionPrompt {
                id: prompt.id,
                site: prompt.site,
                kind: prompt.kind,
            }),
            PermissionDecision::AllowOnce => {
                unreachable!("ShellState consumes AllowOnce decisions before returning them")
            }
        }
    }
}

fn persist_session(shell: &ShellState) {
    let Some(session_path) = session_path() else {
        eprintln!("Nomad session path could not be resolved");
        return;
    };
    if !shell.settings().session_persistence_enabled() {
        if let Err(error) = remove_session_file(&session_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("Nomad session cleanup failed: {error}");
            }
        }
        if let Some(marker) = crash_marker_path() {
            if let Err(error) = clear_crash_marker(&marker) {
                eprintln!("Nomad crash marker cleanup failed: {error}");
            }
        }
        return;
    }

    match shell.save_session() {
        Ok(raw_session) => {
            if let Err(error) = write_session_file(&session_path, &raw_session) {
                eprintln!("Nomad session write failed: {error}");
            } else if let Some(marker) = crash_marker_path() {
                if let Err(error) = clear_crash_marker(&marker) {
                    eprintln!("Nomad crash marker cleanup failed: {error}");
                }
            }
        }
        Err(error) => eprintln!("Nomad session serialization failed: {error:?}"),
    }
}

fn process_downloads(renderer: &mut ServoRenderer, shell: &mut ShellState) {
    for request in renderer.take_download_requests() {
        let transport_request = request.clone();
        match shell.queue_download(request) {
            Ok(id) => {
                if let Err(error) = shell.begin_download(id) {
                    eprintln!("Nomad download could not start: {error:?}");
                } else if let Err(error) = renderer.start_download(id, &transport_request) {
                    let _ = shell.fail_download(id, error.to_string());
                    eprintln!("Nomad download transport failed to start: {error}");
                }
            }
            Err(error) => eprintln!("Nomad download request rejected: {error:?}"),
        }
    }

    for (id, transport_request) in shell.queued_download_requests() {
        if let Err(error) = shell.begin_download(id) {
            eprintln!("Nomad extension download could not start: {error:?}");
            continue;
        }
        if let Err(error) = renderer.start_download(id, &transport_request) {
            let _ = shell.fail_download(id, error.to_string());
            eprintln!("Nomad extension download transport failed to start: {error}");
        }
    }

    for (id, event) in renderer.take_download_events() {
        let is_terminal = shell
            .downloads()
            .iter()
            .find(|download| download.id == id)
            .is_some_and(|download| {
                matches!(
                    download.state,
                    nomad_engine::DownloadState::Completed
                        | nomad_engine::DownloadState::Failed
                        | nomad_engine::DownloadState::Cancelled
                )
            });
        if is_terminal {
            continue;
        }
        let result = match event {
            DownloadTransportEvent::Response { total_bytes } => {
                shell.set_download_total_bytes(id, total_bytes)
            }
            DownloadTransportEvent::BodyChunk(chunk) => shell.receive_download_chunk(id, &chunk),
            DownloadTransportEvent::Finished(Ok(())) => shell.complete_download(id),
            DownloadTransportEvent::Finished(Err(error)) => shell.fail_download(id, error),
        };
        if let Err(error) = result {
            let error_message = format!("{error:?}");
            let _ = shell.fail_download(id, error_message);
            eprintln!("Nomad download update failed: {error:?}");
        }
    }
}

fn process_resources(
    renderer: &mut ServoRenderer,
    chrome: &mut Chrome,
    shell: &mut ShellState,
    network_runtime: &mut NetworkRuntime,
    maintenance: &mut MaintenanceState,
) {
    poll_extension_events(renderer, shell, maintenance);
    dispatch_renderer_events(renderer, chrome, shell, network_runtime);
    run_resource_maintenance(renderer, shell, maintenance);
}

/// Polls extension alarms, messages, and screenshots on the periodic
/// extension interval, then drains any extension messages the renderer
/// produced.
fn poll_extension_events(
    renderer: &mut ServoRenderer,
    shell: &mut ShellState,
    maintenance: &mut MaintenanceState,
) {
    let poll_extensions = maintenance.last_extension_poll.elapsed() >= EXTENSION_POLL_INTERVAL;
    if poll_extensions {
        maintenance.last_extension_poll = Instant::now();
        let has_extensions = shell.extensions().installed().next().is_some();
        if has_extensions {
            renderer.set_extension_blocking_patterns(&shell.extensions().blocking_host_patterns());
            let extension_tabs: Vec<_> = shell
                .tabs()
                .iter()
                .filter(|tab| {
                    tab.url.is_some()
                        && !matches!(
                            tab.lifecycle,
                            nomad_engine::TabLifecycle::Suspended
                                | nomad_engine::TabLifecycle::Archived
                        )
                })
                .map(|tab| tab.id)
                .collect();
            for tab_id in extension_tabs {
                if let Err(error) = renderer.request_extension_messages(tab_id) {
                    eprintln!("Nomad extension message poll failed for {tab_id:?}: {error:?}");
                }
            }
            if let Err(error) = renderer.request_extension_background_messages() {
                eprintln!("Nomad background extension message poll failed: {error:?}");
            }
            if let Err(error) = shell.poll_extension_alarms_with_renderer(renderer) {
                eprintln!("Nomad extension alarm dispatch failed: {error:?}");
            }
            if let Err(error) = shell.poll_extension_screenshots(renderer) {
                eprintln!("Nomad extension screenshot response failed: {error:?}");
            }
        }
    }
    let trace_extensions = std::env::var_os("NOMAD_EXTENSION_TRACE").is_some();
    for message in renderer.take_extension_messages() {
        if trace_extensions {
            eprintln!(
                "Nomad extension message trace (tab {:?}): {:?}",
                message.tab_id, message.payload
            );
        }
        if let Err(error) = shell.receive_extension_message_with_renderer(message, renderer) {
            eprintln!("Nomad extension message rejected: {error:?}");
        }
    }
}

/// Drains and dispatches every queued renderer event batch into the shell
/// and chrome.
fn dispatch_renderer_events(
    renderer: &mut ServoRenderer,
    chrome: &mut Chrome,
    shell: &mut ShellState,
    network_runtime: &mut NetworkRuntime,
) {
    for (tab_id, url) in renderer.take_url_events() {
        if let Err(error) = shell.sync_renderer_navigation(tab_id, &url) {
            eprintln!("Nomad renderer navigation synchronization failed for {tab_id:?}: {error:?}");
        }
    }
    for (tab_id, status) in renderer.take_load_status_events() {
        if status == NavigationLoadStatus::Complete {
            if let Err(error) = shell.finish_navigation(tab_id) {
                eprintln!("Nomad navigation completion update failed for {tab_id:?}: {error:?}");
            }
            sync_umc_application(network_runtime, shell, tab_id);
        }
    }
    for (tab_id, title) in renderer.take_page_title_events() {
        if let Err(error) = shell.dispatch_history_title_changed(tab_id, title, renderer) {
            eprintln!("Nomad history title event dispatch failed for {tab_id:?}: {error:?}");
        }
    }
    for (tab_id, event) in renderer.take_media_session_events() {
        let playing = match &event {
            MediaSessionEvent::PlaybackStateChange(state) => {
                Some(matches!(state, MediaSessionPlaybackState::Playing))
            }
            MediaSessionEvent::SetMetadata(_) | MediaSessionEvent::SetPositionState(_) => None,
        };
        chrome.update_media_session(tab_id, event);
        if let Some(playing) = playing {
            if let Err(error) = shell.set_tab_media_playing(tab_id, playing) {
                eprintln!("Nomad media activity update failed for {tab_id:?}: {error:?}");
            }
        }
    }
    for (tab_id, entry) in renderer.take_console_messages() {
        if let Ok(store) = shell.devtools_store_mut(tab_id) {
            store.record_console(entry);
        }
    }
    for (tab_id, evaluation) in renderer.take_devtools_evaluations() {
        if let Ok(store) = shell.devtools_store_mut(tab_id) {
            store.record_console(nomad_engine::ConsoleEntry {
                level: nomad_engine::ConsoleLevel::Log,
                message: format!("> {}", evaluation.expression),
                source: None,
                line: None,
            });
            let (level, message) = match evaluation.result {
                Ok(result) => (nomad_engine::ConsoleLevel::Log, result),
                Err(error) => (nomad_engine::ConsoleLevel::Error, error),
            };
            store.record_console(nomad_engine::ConsoleEntry {
                level,
                message,
                source: None,
                line: None,
            });
        }
    }
    for (tab_id, request) in renderer.take_network_records() {
        if let Err(error) = shell.dispatch_network_request_to_extensions(&request, renderer) {
            eprintln!("Nomad extension webRequest dispatch failed: {error:?}");
        }
        if let Ok(store) = shell.devtools_store_mut(tab_id) {
            store.record_network(request);
        }
    }
    for (tab_id, html) in renderer.take_reader_snapshots() {
        let source_url = shell.tab(tab_id).and_then(|tab| tab.url.clone());
        let document = reader_document_from_html(&html, source_url);
        if let Err(error) = shell.set_reader_document(tab_id, document) {
            eprintln!("Nomad reader snapshot failed for {tab_id:?}: {error:?}");
        }
    }
    for (tab_id, dom) in renderer.take_dom_snapshots() {
        if let Ok(store) = shell.devtools_store_mut(tab_id) {
            store.record_dom(dom);
        }
    }
    for (tab_id, inspection) in renderer.take_page_inspections() {
        if let Ok(store) = shell.devtools_store_mut(tab_id) {
            store.record_page_inspection(inspection);
        }
    }
    for (tab_id, text) in renderer.take_page_text_snapshots() {
        if shell.active_tab() == Some(tab_id) {
            chrome.set_translation_input_if_empty(text);
        }
    }
    for (tab_id, memory_bytes) in renderer.take_memory_reports() {
        if let Err(error) = shell.set_tab_memory_measurement(tab_id, memory_bytes) {
            eprintln!("Nomad Servo memory sample failed for {tab_id:?}: {error:?}");
        }
    }
}

/// Runs the periodic resource maintenance: download refresh, memory
/// sampling, memory-report requests, and renderer memory reclamation.
fn run_resource_maintenance(
    renderer: &mut ServoRenderer,
    shell: &mut ShellState,
    maintenance: &mut MaintenanceState,
) {
    if maintenance.last_resource_maintenance.elapsed() >= RESOURCE_MAINTENANCE_INTERVAL {
        maintenance.last_resource_maintenance = Instant::now();
        shell.refresh_download_activity();
        if let Some(available_bytes) = maintenance.memory_sampler.sample() {
            shell.observe_memory(available_bytes);
        }
        if maintenance.memory_report_scheduler.should_request() {
            let tab_ids: Vec<_> = shell
                .tabs()
                .iter()
                .filter(|tab| {
                    !matches!(
                        tab.lifecycle,
                        nomad_engine::TabLifecycle::Suspended
                            | nomad_engine::TabLifecycle::Archived
                    )
                })
                .map(|tab| tab.id)
                .collect();
            for tab_id in tab_ids {
                if let Err(error) = renderer.request_memory_report(tab_id) {
                    eprintln!("Nomad Servo memory report request failed: {error:?}");
                }
            }
        }
        if let Err(error) = shell.reclaim_memory_with_renderer(renderer) {
            eprintln!("Nomad resource manager failed: {error:?}");
        }
    }
}

fn sync_umc_application(
    network_runtime: &mut NetworkRuntime,
    shell: &ShellState,
    tab_id: nomad_engine::TabId,
) {
    #[cfg(any(unix, windows))]
    {
        let Some(core) = network_runtime.umc_core.as_mut() else {
            return;
        };
        let Some(url) = shell.tab(tab_id).and_then(|tab| tab.url.as_ref()) else {
            core.close_application(tab_id.get());
            return;
        };
        if url.scheme() != "umc" {
            core.close_application(tab_id.get());
            return;
        }
        let Ok(resource) = nomad_engine::UmcResourceInfo::from_url(url) else {
            core.close_application(tab_id.get());
            return;
        };
        if let Err(error) = core.open_application(tab_id.get(), &resource) {
            eprintln!("Nomad UMC application session failed for {tab_id:?}: {error}");
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (network_runtime, shell, tab_id);
    }
}

// One dispatch table over every `ChromeAction` variant. Splitting the match
// across functions would scatter the variant-to-behavior mapping without
// reducing complexity, so the length is accepted here.
#[allow(clippy::too_many_lines)]
fn apply_chrome_action(
    action: ChromeAction,
    chrome: &mut Chrome,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
    network_runtime: &mut NetworkRuntime,
    switches: &mut Switches,
    pending_session: &mut Option<String>,
) {
    let result = match action {
        ChromeAction::Quit => Ok(()),
        ChromeAction::OpenSettings(section) => shell
            .open_settings_tab_with_renderer(renderer)
            .inspect(|tab_id| chrome.show_settings_tab(*tab_id, section, shell.settings()))
            .map(|_| ()),
        ChromeAction::NavigatePending { tab_id, address } => {
            shell.select_tab(tab_id).and_then(|()| {
                shell.set_address_input(&address);
                shell.submit_address_with_renderer(renderer)
            })
        }
        ChromeAction::NavigateFromHistory(address) => {
            shell.set_address_input(&address);
            shell.submit_address_with_renderer(renderer)
        }
        ChromeAction::NavigateInNewTab(address) => {
            open_ready_address_in_new_tab(&address, chrome, shell)
        }
        ChromeAction::OpenUniversal(target) => {
            apply_universal_target(target, chrome, shell, renderer)
        }
        ChromeAction::OpenUniversalInNewTab(target) => {
            apply_universal_target_in_new_tab(target, chrome, shell, renderer)
        }
        ChromeAction::CreateContainer { name, ephemeral } => shell
            .create_container(name, ephemeral)
            .and_then(|container_id| {
                shell.assign_active_tab_to_container_with_renderer(container_id, renderer)
            }),
        ChromeAction::AssignActiveContainer(container_id) => {
            shell.assign_active_tab_to_container_with_renderer(container_id, renderer)
        }
        ChromeAction::GoBack => shell.go_back_with_renderer(renderer),
        ChromeAction::GoForward => shell.go_forward_with_renderer(renderer),
        ChromeAction::Reload => shell.reload_active_tab_with_renderer(renderer),
        ChromeAction::ZoomIn => renderer
            .step_active_page_zoom(true)
            .map(|_| ())
            .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string())),
        ChromeAction::ZoomOut => renderer
            .step_active_page_zoom(false)
            .map(|_| ())
            .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string())),
        ChromeAction::ResetZoom => renderer
            .reset_active_page_zoom()
            .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string())),
        ChromeAction::SelectTab(tab_id) => shell.select_tab_with_renderer(tab_id, renderer),
        ChromeAction::CreateWorkspace(name) => shell
            .create_workspace(name)
            .and_then(|id| shell.select_workspace_with_renderer(id, renderer))
            .and_then(|()| apply_active_workspace_route(shell, renderer)),
        ChromeAction::SelectWorkspace(id) => shell
            .select_workspace_with_renderer(id, renderer)
            .and_then(|()| apply_active_workspace_route(shell, renderer)),
        ChromeAction::SetWorkspaceResolver {
            workspace,
            resolver,
        } => shell
            .set_workspace_resolver(workspace, resolver)
            .inspect(|()| chrome.refresh_workspace_resolver_draft(shell)),
        ChromeAction::SplitActive(orientation) => {
            let tab_id = shell.new_tab();
            shell
                .configure_renderer_tab(tab_id, renderer)
                .and_then(|()| shell.split_tab(tab_id, orientation))
                .and_then(|pane_id| shell.activate_split_pane(pane_id, renderer))
        }
        ChromeAction::MoveTabToSplit { tab, orientation } => shell
            .split_tab(tab, orientation)
            .and_then(|pane_id| shell.activate_split_pane(pane_id, renderer)),
        ChromeAction::ReorderTab { tab, anchor } => shell.reorder_tab(tab, anchor),
        ChromeAction::CreateTabGroup { tab } => shell.create_tab_group(tab).map(|_| ()),
        ChromeAction::AddTabToGroup { tab, group_id } => shell.add_tab_to_group(group_id, tab),
        ChromeAction::RemoveTabFromGroup(tab) => shell.remove_tab_from_group(tab),
        ChromeAction::SetTabGroupCollapsed {
            group_id,
            collapsed,
        } => shell.set_tab_group_collapsed(group_id, collapsed),
        ChromeAction::UngroupTabGroup(group_id) => shell.ungroup_tab_group(group_id),
        ChromeAction::ActivateSplitPane(pane_id) => shell.activate_split_pane(pane_id, renderer),
        ChromeAction::CloseSplitPane(pane_id) => shell
            .close_split_pane(pane_id)
            .and_then(|tab_id| shell.close_tab_with_renderer(tab_id, renderer)),
        ChromeAction::ToggleReader => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| {
                let mode = shell.toggle_reader_mode(tab_id)?;
                if mode == ReaderMode::Reader {
                    renderer
                        .request_reader_snapshot(tab_id)
                        .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))?;
                }
                renderer
                    .set_reader_mode(tab_id, mode == ReaderMode::Reader)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
            }),
        ChromeAction::OpenDevTools => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| {
                renderer
                    .request_dom_snapshot(tab_id)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
                    .and_then(|()| {
                        renderer
                            .request_page_inspection(tab_id)
                            .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
                    })
            }),
        ChromeAction::EvaluateDevTools(expression) => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| {
                renderer
                    .evaluate_devtools_javascript(tab_id, expression)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
            }),
        ChromeAction::ClearDevTools => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| shell.clear_devtools(tab_id)),
        ChromeAction::TranslateText {
            source,
            target,
            text,
        } => {
            let result = (|| {
                let endpoint = std::env::var("NOMAD_TRANSLATION_ENDPOINT")
                    .map_err(|_| "NOMAD_TRANSLATION_ENDPOINT is not configured".to_owned())?;
                let endpoint = Url::parse(&endpoint)
                    .map_err(|error| format!("invalid translation endpoint: {error}"))?;
                let request = TranslationRequest::new(
                    source,
                    target,
                    text,
                    TranslationProvider::Endpoint(endpoint),
                )
                .map_err(|error| format!("translation request rejected: {error:?}"))?;
                EndpointTranslationExecutor::default()
                    .execute(&request)
                    .map(|response| response.text)
                    .map_err(|error| format!("translation failed: {error:?}"))
            })();
            chrome.set_translation_result(result);
            Ok(())
        }
        ChromeAction::CloseTab(tab_id) => {
            let result = shell.close_tab_with_renderer(tab_id, renderer);
            chrome.forget_settings_tab(tab_id);
            chrome.forget_accessibility_tab(tab_id);
            chrome.forget_media_session_tab(tab_id);
            network_runtime.close_umc_application(tab_id);
            result
        }
        ChromeAction::RestoreSession => (|| -> Result<(), nomad_shell::ShellError> {
            let raw_session = pending_session.as_deref().ok_or_else(|| {
                nomad_shell::ShellError::Session(nomad_shell::SessionError::InvalidJson(
                    "no pending session is available".into(),
                ))
            })?;
            let snapshot = SessionSnapshot::from_json(raw_session)
                .map_err(nomad_shell::ShellError::Session)?;
            renderer.set_privacy_policy(PrivacyPolicy::for_mode(snapshot.settings.privacy_mode));
            renderer
                .set_route_policy(snapshot.settings.route_policy)
                .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))?;
            shell.restore_session_with_renderer(raw_session, renderer)?;
            shell.restore_persisted_sync_key().map(|_| ())?;
            shell.sync_extension_backgrounds_with_renderer(renderer)?;
            shell.refresh_extension_scripts_with_renderer(renderer)?;
            apply_active_workspace_route(shell, renderer)?;
            pending_session.take();
            chrome.set_session_recovery_prompt(false);
            Ok(())
        })(),
        ChromeAction::StartCleanSession => (|| -> Result<(), nomad_shell::ShellError> {
            if let Some(path) = session_path() {
                archive_session_file(&path)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))?;
            }
            pending_session.take();
            chrome.set_session_recovery_prompt(false);
            Ok(())
        })(),
        ChromeAction::MediaSessionAction { tab_id, action } => renderer
            .dispatch_media_session_action(tab_id, action)
            .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string())),
        ChromeAction::SetMemoryMode(mode) => {
            shell.set_memory_mode(mode);
            Ok(())
        }
        ChromeAction::ReclaimMemory => shell.reclaim_memory_with_renderer(renderer).map(|_| ()),
        ChromeAction::SleepTab(tab_id) => shell.sleep_tab_with_renderer(tab_id, renderer),
        ChromeAction::WakeTab(tab_id) => shell.wake_tab_with_renderer(tab_id, renderer),
        ChromeAction::ResumeTab(tab_id) => shell.resume_tab_with_renderer(tab_id, renderer),
        ChromeAction::SuspendTab(tab_id) => shell.suspend_tab_with_renderer(tab_id, renderer),
        ChromeAction::SetTabPinned { id, pinned } => shell.set_tab_pinned(id, pinned),
        ChromeAction::SetTabKeepAlive { id, keep_alive } => {
            shell.set_tab_keep_alive(id, keep_alive)
        }
        ChromeAction::RetryDownload(id) => retry_download(id, shell, renderer),
        ChromeAction::CancelDownload(id) => cancel_download(id, shell, renderer),
        ChromeAction::ToggleBookmark => shell.toggle_active_bookmark(),
        ChromeAction::OpenBookmark(id) => shell
            .open_bookmark_in_new_tab_with_renderer(id, renderer)
            .map(|_| ()),
        ChromeAction::RemoveBookmark(id) => shell.remove_bookmark(id),
        ChromeAction::RenameBookmark { id, title } => shell.rename_bookmark(id, title),
        ChromeAction::CreateBookmarkFolder(name) => shell.create_bookmark_folder(name).map(|_| ()),
        ChromeAction::RenameBookmarkFolder { id, name } => shell.rename_bookmark_folder(id, name),
        ChromeAction::RemoveBookmarkFolder(id) => shell.remove_bookmark_folder(id),
        ChromeAction::MoveBookmark { id, folder_id } => shell.move_bookmark(id, folder_id),
        ChromeAction::ApplySettings(settings) => (|| {
            let privacy_policy = PrivacyPolicy::for_mode(settings.privacy_mode);
            let previous_route_policy = shell.settings().route_policy.clone();
            if let Err(error) = renderer.set_route_policy(settings.route_policy.clone()) {
                Err(nomad_shell::ShellError::Renderer(error.to_string()))
            } else {
                if let Err(error) = persist_settings(&settings) {
                    let _ = renderer.set_route_policy(previous_route_policy);
                    return Err(nomad_shell::ShellError::Renderer(format!(
                        "settings could not be saved: {error}"
                    )));
                }
                shell.apply_settings(settings);
                let private_context_reset = renderer.set_privacy_policy(privacy_policy);
                if private_context_reset {
                    shell.reload_active_tab_with_renderer(renderer)?;
                    shell.refresh_extension_scripts_with_renderer(renderer)?;
                }
                Ok(())
            }
        })(),
        ChromeAction::SetupSyncKey => shell.setup_sync_key().and_then(|phrase| {
            shell.persist_sync_key(&phrase)?;
            chrome.set_sync_recovery_phrase(phrase);
            chrome.refresh_settings_draft(shell.settings());
            Ok(())
        }),
        ChromeAction::RecoverSyncKey(phrase) => shell.recover_sync_key(&phrase).and_then(|()| {
            shell.persist_sync_key(&phrase)?;
            chrome.refresh_settings_draft(shell.settings());
            Ok(())
        }),
        ChromeAction::SyncNow => shell.sync_now().map(|_| ()),
        ChromeAction::PullSync => shell.pull_sync().map(|_| ()),
        ChromeAction::ResolveSyncConflict { key, choice } => {
            shell.resolve_sync_conflict(&key, choice).map(|_| ())
        }
        ChromeAction::RequestAutofill => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| {
                chrome.begin_autofill_scan(tab_id);
                renderer
                    .request_autofill_snapshot(tab_id)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
            }),
        ChromeAction::FillSavedPassword(username) => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| {
                let password = shell.load_active_credential(&username)?;
                renderer
                    .fill_autofill_credentials(tab_id, &username, &password)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
            }),
        ChromeAction::FillEnteredPassword { username, password } => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| {
                renderer
                    .fill_autofill_credentials(tab_id, &username, &password)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
                    .map(|()| {
                        chrome.clear_autofill_secret();
                    })
            }),
        ChromeAction::SaveCredential { username, password } => shell
            .save_active_credential(&username, &password)
            .map(|()| chrome.clear_autofill_secret()),
        ChromeAction::SetRoute(next_switches) => network_runtime
            .reconfigure(next_switches, renderer)
            .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
            .and_then(|()| shell.set_switches(next_switches))
            .map(|()| {
                *switches = next_switches;
            }),
        ChromeAction::ResolvePermission { id, decision } => {
            resolve_permission(id, decision, shell, renderer)
        }
        ChromeAction::TriggerExtensionAction(extension_id) => shell
            .active_tab()
            .ok_or(nomad_shell::ShellError::NoActiveTab)
            .and_then(|tab_id| {
                shell.trigger_extension_action_with_renderer(&extension_id, tab_id, renderer)
            }),
        ChromeAction::ClearExtensionNotification(id) => {
            shell.clear_extension_notification(&id);
            Ok(())
        }
    };
    if let Err(error) = result {
        let message = browser_action_error_message(&error);
        chrome.set_navigation_error(message);
        eprintln!("Nomad shell action failed: {error:?}");
    } else {
        chrome.clear_navigation_error();
    }
}

fn browser_action_error_message(error: &nomad_shell::ShellError) -> String {
    match error {
        nomad_shell::ShellError::Navigation(NavigationError::RouteRequired(route)) => {
            let route = match route {
                RouteMode::Direct => "Direct",
                RouteMode::Umc => "UMC",
                RouteMode::Xray => "Xray",
            };
            format!(
                "This resource requires the {route} route. Open Privacy & security and enable that route before retrying."
            )
        }
        nomad_shell::ShellError::Navigation(NavigationError::UnsupportedScheme(scheme)) => {
            format!("Navigation scheme '{scheme}' is not supported by this browser build.")
        }
        nomad_shell::ShellError::Navigation(NavigationError::InvalidUrl(url)) => {
            format!("The address is invalid or unsafe to load: {url}")
        }
        _ => format!("Nomad action failed: {error:?}"),
    }
}

fn apply_universal_target(
    target: UniversalTarget,
    chrome: &mut Chrome,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    match target {
        UniversalTarget::Navigate(address) => {
            shell.set_address_input(&address);
            shell.submit_address_with_renderer(renderer)
        }
        UniversalTarget::SelectTab(tab_id) => shell.select_tab_with_renderer(tab_id, renderer),
        UniversalTarget::OpenBookmark(bookmark_id) => shell
            .open_bookmark_in_new_tab_with_renderer(bookmark_id, renderer)
            .map(|_| ()),
        UniversalTarget::Command(command) => {
            apply_browser_command(command, chrome, shell, renderer)
        }
    }
}

fn apply_universal_target_in_new_tab(
    target: UniversalTarget,
    chrome: &mut Chrome,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    match target {
        UniversalTarget::Navigate(address) => {
            open_ready_address_in_new_tab(&address, chrome, shell)
        }
        UniversalTarget::OpenBookmark(bookmark_id) => {
            shell.focus_or_create_blank_tab_with_renderer(renderer)?;
            renderer.spin_event_loop();
            shell.open_bookmark_with_renderer(bookmark_id, renderer)
        }
        UniversalTarget::SelectTab(tab_id) => shell.select_tab_with_renderer(tab_id, renderer),
        UniversalTarget::Command(command) => {
            apply_browser_command(command, chrome, shell, renderer)
        }
    }
}

fn open_ready_address_in_new_tab(
    address: &str,
    chrome: &mut Chrome,
    shell: &mut ShellState,
) -> Result<(), ShellError> {
    let normalized = nomad_shell::normalize_address_input(address, &shell.settings().search_url)
        .map_err(|_| ShellError::Navigation(NavigationError::InvalidUrl(address.to_owned())))?;
    let mut tab_id = shell.focus_or_create_blank_tab()?;
    if chrome.navigation_pending_for(tab_id) {
        tab_id = shell.new_tab();
        shell.select_tab(tab_id)?;
    }
    // Servo creates a WebView asynchronously. Finish this redraw before
    // submitting LoadUrl so its browsing context is ready.
    chrome.queue_navigation(tab_id, normalized);
    Ok(())
}

/// Applies a universal-target browser command and reports the result.
fn apply_browser_command(
    command: BrowserCommand,
    chrome: &mut Chrome,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    match command {
        BrowserCommand::NewTab => shell
            .focus_or_create_blank_tab_with_renderer(renderer)
            .map(|_| ()),
        BrowserCommand::NewWorkspace => {
            let name = format!("Workspace {}", shell.workspaces().len() + 1);
            shell
                .create_workspace(name)
                .and_then(|id| shell.select_workspace_with_renderer(id, renderer))
                .and_then(|()| apply_active_workspace_route(shell, renderer))
        }
        BrowserCommand::Back => shell.go_back_with_renderer(renderer),
        BrowserCommand::Forward => shell.go_forward_with_renderer(renderer),
        BrowserCommand::ToggleBookmark => shell.toggle_active_bookmark(),
        BrowserCommand::ToggleSplit => {
            let tab_id = shell.new_tab();
            shell
                .split_tab(tab_id, nomad_engine::SplitOrientation::Vertical)
                .and_then(|pane_id| shell.activate_split_pane(pane_id, renderer))
        }
        BrowserCommand::ToggleReader => toggle_reader_command(shell, renderer),
        BrowserCommand::TranslatePage => {
            chrome.toggle_translation();
            if let Some(tab_id) = shell.active_tab() {
                renderer
                    .request_page_text(tab_id)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))?;
            }
            Ok(())
        }
        BrowserCommand::OpenDevTools => {
            chrome.toggle_devtools();
            if let Some(tab_id) = shell.active_tab() {
                renderer
                    .request_dom_snapshot(tab_id)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))?;
                renderer
                    .request_page_inspection(tab_id)
                    .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))?;
            }
            Ok(())
        }
        BrowserCommand::OpenDownloads => {
            chrome.toggle_panel(ChromePanel::Downloads, shell.settings());
            Ok(())
        }
        BrowserCommand::OpenHistory => {
            chrome.toggle_panel(ChromePanel::History, shell.settings());
            Ok(())
        }
        BrowserCommand::OpenMemory => {
            chrome.toggle_panel(ChromePanel::Memory, shell.settings());
            Ok(())
        }
        BrowserCommand::OpenPrivacy => {
            chrome.toggle_panel(ChromePanel::Privacy, shell.settings());
            Ok(())
        }
        BrowserCommand::OpenBookmarks => {
            chrome.toggle_panel(ChromePanel::Bookmarks, shell.settings());
            Ok(())
        }
        BrowserCommand::OpenSettings => {
            let tab_id = shell.open_settings_tab_with_renderer(renderer)?;
            chrome.show_settings_tab(
                tab_id,
                crate::chrome::SettingsSection::General,
                shell.settings(),
            );
            Ok(())
        }
        BrowserCommand::OpenPermissions => {
            chrome.toggle_panel(ChromePanel::Permissions, shell.settings());
            Ok(())
        }
        BrowserCommand::OpenWorkspaces => {
            chrome.toggle_panel(ChromePanel::Workspaces, shell.settings());
            Ok(())
        }
        BrowserCommand::OpenCommandPalette => {
            chrome.open_command_palette();
            Ok(())
        }
    }
}

/// Toggles reader mode for the active tab, requesting a reader snapshot when
/// reader mode is being enabled.
fn toggle_reader_command(
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    let tab_id = shell
        .active_tab()
        .ok_or(nomad_shell::ShellError::NoActiveTab)?;
    let mode = shell.toggle_reader_mode(tab_id)?;
    if mode == ReaderMode::Reader {
        renderer
            .request_reader_snapshot(tab_id)
            .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))?;
    }
    renderer
        .set_reader_mode(tab_id, mode == ReaderMode::Reader)
        .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
}

fn apply_active_workspace_route(
    shell: &ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    let workspace = shell
        .workspaces()
        .iter()
        .find(|workspace| workspace.id == shell.active_workspace())
        .ok_or_else(|| nomad_shell::ShellError::Renderer("active workspace disappeared".into()))?;
    renderer
        .set_route_policy(workspace.route_policy.clone())
        .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
}

fn resolve_permission(
    id: nomad_engine::PermissionPromptId,
    decision: PermissionDecision,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    shell.resolve_permission(id, decision)?;
    renderer
        .respond_permission(
            id,
            matches!(
                decision,
                PermissionDecision::Allow | PermissionDecision::AllowOnce
            ),
        )
        .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
}

fn retry_download(
    id: nomad_engine::DownloadId,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    let request = shell.retry_download(id)?;
    shell.begin_download(id)?;
    if let Err(error) = renderer.start_download(id, &request) {
        let _ = shell.fail_download(id, error.to_string());
        return Err(nomad_shell::ShellError::Renderer(error.to_string()));
    }
    Ok(())
}

fn cancel_download(
    id: nomad_engine::DownloadId,
    shell: &mut ShellState,
    renderer: &mut ServoRenderer,
) -> Result<(), nomad_shell::ShellError> {
    renderer
        .cancel_download(id)
        .map_err(|error| nomad_shell::ShellError::Renderer(error.to_string()))
        .and_then(|()| shell.cancel_download(id))
}

#[cfg(all(test, unix))]
mod session_tests {
    use super::{
        archive_session_file, clear_crash_marker, quarantine_session_file, read_session_file,
        read_settings_file, write_crash_marker, write_session_file, write_settings_file,
    };
    use nomad_shell::BrowserSettings;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn session_writer_does_not_follow_symlink_targets() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nomad-session-security-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create session test directory");
        let target = directory.join("target.json");
        let session = directory.join("session.json");
        fs::write(&target, b"original").expect("write symlink target");
        symlink(&target, &session).expect("create session symlink");

        let result = write_session_file(&session, "replacement");
        assert!(result.is_err(), "symlink session path must be rejected");
        assert_eq!(
            fs::read(&target).expect("read symlink target"),
            b"original",
            "the symlink target must not be modified"
        );
        assert!(
            read_session_file(&session).is_err(),
            "symlink session path must not be opened"
        );

        fs::remove_dir_all(directory).expect("remove session test directory");
    }

    #[test]
    fn crash_marker_is_created_and_cleared_safely() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nomad-crash-marker-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create crash-marker test directory");
        let marker = directory.join("session.running");

        write_crash_marker(&marker).expect("write crash marker");
        assert!(fs::read_to_string(&marker)
            .expect("read crash marker")
            .starts_with("pid="));
        clear_crash_marker(&marker).expect("clear crash marker");
        assert!(!marker.exists());

        fs::remove_dir_all(directory).expect("remove crash-marker test directory");
    }

    #[test]
    fn crash_marker_tracks_attempts_and_trips_recovery_guard() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("nomad-crash-loop-{}-{suffix}", std::process::id()));
        fs::create_dir(&directory).expect("create crash-loop test directory");
        let marker = directory.join("session.running");

        super::write_crash_marker_with_attempts(&marker, 3).expect("write crash marker");
        assert_eq!(super::read_crash_marker_attempts(&marker).unwrap(), Some(3));
        assert!(super::should_skip_session_restore(3));
        assert!(!super::should_skip_session_restore(2));

        fs::remove_dir_all(directory).expect("remove crash-loop test directory");
    }

    #[test]
    fn corrupt_session_is_quarantined_without_overwriting_it() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nomad-corrupt-session-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create quarantine test directory");
        let session = directory.join("session.json");
        fs::write(&session, b"not-json").expect("write corrupt session");

        let quarantined = quarantine_session_file(&session)
            .expect("quarantine corrupt session")
            .expect("quarantine path");
        assert!(!session.exists());
        assert_eq!(
            fs::read(&quarantined).expect("read quarantined session"),
            b"not-json"
        );

        fs::remove_dir_all(directory).expect("remove quarantine test directory");
    }

    #[test]
    fn clean_session_choice_archives_checkpoint_without_deleting_it() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nomad-discarded-session-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create archive test directory");
        let session = directory.join("session.json");
        fs::write(&session, b"valid checkpoint").expect("write checkpoint");

        let archived = archive_session_file(&session)
            .expect("archive checkpoint")
            .expect("archive path");
        assert!(!session.exists());
        assert!(archived
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains(".discarded.")));
        assert_eq!(
            fs::read(&archived).expect("read archived checkpoint"),
            b"valid checkpoint"
        );

        fs::remove_dir_all(directory).expect("remove archive test directory");
    }

    #[test]
    fn settings_are_stored_independently_from_session_restore() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nomad-independent-settings-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create settings test directory");
        let settings_path = directory.join("settings.json");
        let session_path = directory.join("session.json");
        let settings = BrowserSettings {
            persist_session: false,
            persist_history: false,
            search_url: "https://search.example/?q={query}".to_owned(),
            ..BrowserSettings::default()
        };

        write_session_file(&session_path, "session checkpoint").expect("write session");
        write_settings_file(&settings_path, &settings).expect("write settings");
        fs::remove_file(&session_path).expect("remove disabled session checkpoint");

        assert!(!session_path.exists());
        assert_eq!(
            read_settings_file(&settings_path).expect("read settings"),
            settings
        );

        fs::remove_dir_all(directory).expect("remove settings test directory");
    }
}
