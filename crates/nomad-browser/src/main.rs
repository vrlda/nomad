use nomad_core::{BackendAvailability, RouteError, RouteMode, Switches};
use nomad_engine::{BrowserRuntime, EngineError, NavigationError, RenderError};

#[cfg(feature = "native-servo")]
mod chrome;
#[cfg(feature = "native-servo")]
mod frame_stats;
#[cfg(feature = "native-servo")]
mod memory;
#[cfg(feature = "native-servo")]
mod native;

#[derive(Debug, Eq, PartialEq)]
struct CliOptions {
    switches: Switches,
    show_help: bool,
    initial_url: Option<String>,
    webdriver_port: Option<u16>,
    devtools_port: Option<u16>,
    extension_archive: Option<String>,
    ignore_certificate_errors: bool,
    session_action: SessionAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionAction {
    Automatic,
    Restore,
    StartClean,
}

#[cfg_attr(feature = "native-servo", allow(dead_code))]
#[allow(clippy::too_many_lines)]
fn parse_args<I>(args: I) -> Result<CliOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut switches = Switches::default();
    let mut show_help = false;
    let mut initial_url = None;
    let mut webdriver_port = None;
    let mut devtools_port = None;
    let mut extension_archive = None;
    let mut ignore_certificate_errors = false;
    let mut session_action = SessionAction::Automatic;
    let mut args = args.into_iter();

    args.next();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--umc" => {
                if switches.xray_enabled() {
                    return Err("UMC and Xray cannot be enabled together.".into());
                }
                switches.set_umc_enabled(true);
            }
            "--no-umc" => switches.set_umc_enabled(false),
            "--xray" => {
                if switches.umc_enabled() {
                    return Err("UMC and Xray cannot be enabled together.".into());
                }
                switches.set_xray_enabled(true);
            }
            "--no-xray" => switches.set_xray_enabled(false),
            "--restore-session" => {
                if session_action == SessionAction::StartClean {
                    return Err("--restore-session and --new-session cannot be combined.".into());
                }
                session_action = SessionAction::Restore;
            }
            "--new-session" => {
                if session_action == SessionAction::Restore {
                    return Err("--restore-session and --new-session cannot be combined.".into());
                }
                session_action = SessionAction::StartClean;
            }
            "--url" => {
                initial_url = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --url".to_owned())?,
                );
            }
            "--webdriver" => {
                let raw_port = args
                    .next()
                    .ok_or_else(|| "missing value for --webdriver".to_owned())?;
                let port = raw_port
                    .parse::<u16>()
                    .map_err(|_| "--webdriver requires a non-zero TCP port".to_owned())?;
                if port == 0 {
                    return Err("--webdriver requires a non-zero TCP port".to_owned());
                }
                webdriver_port = Some(port);
            }
            _ if arg.starts_with("--webdriver=") => {
                let raw_port = arg.trim_start_matches("--webdriver=");
                let port = raw_port
                    .parse::<u16>()
                    .map_err(|_| "--webdriver requires a non-zero TCP port".to_owned())?;
                if port == 0 {
                    return Err("--webdriver requires a non-zero TCP port".to_owned());
                }
                webdriver_port = Some(port);
            }
            "--devtools" => {
                let raw_port = args
                    .next()
                    .ok_or_else(|| "missing value for --devtools".to_owned())?;
                let port = raw_port
                    .parse::<u16>()
                    .map_err(|_| "--devtools requires a non-zero TCP port".to_owned())?;
                if port == 0 {
                    return Err("--devtools requires a non-zero TCP port".to_owned());
                }
                devtools_port = Some(port);
            }
            _ if arg.starts_with("--devtools=") => {
                let raw_port = arg.trim_start_matches("--devtools=");
                let port = raw_port
                    .parse::<u16>()
                    .map_err(|_| "--devtools requires a non-zero TCP port".to_owned())?;
                if port == 0 {
                    return Err("--devtools requires a non-zero TCP port".to_owned());
                }
                devtools_port = Some(port);
            }
            "--extension-archive" => {
                extension_archive = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --extension-archive".to_owned())?,
                );
            }
            _ if arg.starts_with("--extension-archive=") => {
                let path = arg.trim_start_matches("--extension-archive=");
                if path.is_empty() {
                    return Err("--extension-archive requires a non-empty path".to_owned());
                }
                extension_archive = Some(path.to_owned());
            }
            // Servo's WPT runner supplies these flags to the browser process.
            // Nomad owns the corresponding policy and renderer setup, so the
            // harness-only settings are accepted here without overriding it.
            "--hard-fail"
            | "--enable-experimental-web-platform-features"
            | "--headless"
            | "-z"
            | "--temporary-storage" => {}
            "--ignore-certificate-errors" => ignore_certificate_errors = true,
            "--window-size" | "--certificate-path" | "--config-dir" | "--prefs-file" | "--pref"
            | "--user-stylesheet" => {
                args.next()
                    .ok_or_else(|| format!("missing value for {arg}"))?;
            }
            _ if arg.starts_with("--window-size=")
                || arg.starts_with("--certificate-path=")
                || arg.starts_with("--config-dir=")
                || arg.starts_with("--prefs-file=")
                || arg.starts_with("--pref=")
                || arg.starts_with("--user-stylesheet=") => {}
            "--help" | "-h" => show_help = true,
            _ if arg.starts_with('-') => return Err(format!("unknown argument: {arg}")),
            _ => {
                if initial_url.is_some() {
                    return Err("only one initial URL may be provided".into());
                }
                initial_url = Some(arg);
            }
        }
    }

    Ok(CliOptions {
        switches,
        show_help,
        initial_url,
        webdriver_port,
        devtools_port,
        extension_archive,
        ignore_certificate_errors,
        session_action,
    })
}

#[cfg_attr(feature = "native-servo", allow(dead_code))]
fn run<I>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = String>,
{
    let options = parse_args(args)?;

    if options.show_help {
        return Ok(usage().to_owned());
    }
    if options.webdriver_port.is_some() {
        return Err("--webdriver requires the native-servo feature".to_owned());
    }
    if options.devtools_port.is_some() {
        return Err("--devtools requires the native-servo feature".to_owned());
    }
    if options.extension_archive.is_some() {
        return Err("--extension-archive requires the native-servo feature".to_owned());
    }

    let availability = BackendAvailability::new(false, false);
    let mut runtime =
        BrowserRuntime::new(options.switches, availability).map_err(engine_error_message)?;
    let tab_id = runtime.new_tab();

    if let Some(url) = options.initial_url.as_deref() {
        runtime
            .navigate(tab_id, url)
            .map_err(navigation_error_message)?;
    }

    let active_tab = runtime
        .active_tab()
        .map_or_else(|| "none".to_owned(), |tab_id| tab_id.get().to_string());

    Ok(format!(
        "route={}\numc={}\nxray={}\ntabs={}\nactive_tab={}",
        route_label(runtime.route()),
        on_off(options.switches.umc_enabled()),
        on_off(options.switches.xray_enabled()),
        runtime.tabs().len(),
        active_tab,
    ))
}

#[cfg_attr(feature = "native-servo", allow(dead_code))]
fn engine_error_message(error: EngineError) -> String {
    match error {
        EngineError::Route(route_error) => route_error_message(route_error),
    }
}

#[cfg_attr(feature = "native-servo", allow(dead_code))]
fn navigation_error_message(error: NavigationError) -> String {
    match error {
        NavigationError::MissingTab(tab_id) => {
            format!("navigation target tab {} does not exist", tab_id.get())
        }
        NavigationError::InvalidUrl(url) => format!("invalid navigation URL: {url}"),
        NavigationError::UnsupportedScheme(scheme) => {
            format!("unsupported navigation scheme: {scheme}")
        }
        NavigationError::RouteRequired(route) => {
            format!(
                "navigation requires the {} route to be enabled",
                route_label(route)
            )
        }
        NavigationError::NoBackNavigation(tab_id) => {
            format!("tab {} has no previous navigation", tab_id.get())
        }
        NavigationError::NoForwardNavigation(tab_id) => {
            format!("tab {} has no forward navigation", tab_id.get())
        }
        NavigationError::BlockedByWebRequest(url) => {
            format!("webRequest extension blocked navigation to {url}")
        }
        NavigationError::Render(RenderError::BackendUnavailable) => {
            "renderer backend is unavailable; refusing navigation".to_owned()
        }
    }
}

#[cfg_attr(feature = "native-servo", allow(dead_code))]
fn route_error_message(error: RouteError) -> String {
    match error {
        RouteError::UmcUnavailable => {
            "UMC switch enabled, but UMC backend is unavailable; refusing direct fallback."
                .to_owned()
        }
        RouteError::XrayUnavailable => {
            "Xray switch enabled, but Xray backend is unavailable; refusing direct fallback."
                .to_owned()
        }
    }
}

#[cfg_attr(feature = "native-servo", allow(dead_code))]
const fn route_label(route: RouteMode) -> &'static str {
    match route {
        RouteMode::Direct => "direct",
        RouteMode::Umc => "umc",
        RouteMode::Xray => "xray",
    }
}

#[cfg_attr(feature = "native-servo", allow(dead_code))]
const fn on_off(enabled: bool) -> &'static str {
    if enabled {
        "on"
    } else {
        "off"
    }
}

const fn usage() -> &'static str {
    "nomad-browser [--umc|--no-umc] [--xray|--no-xray] [--restore-session|--new-session] [--webdriver <PORT>] [--devtools <PORT>] [--extension-archive <PATH>] [--url <URL>]"
}

#[cfg(not(feature = "native-servo"))]
fn main() {
    match run(std::env::args()) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(feature = "native-servo")]
fn main() {
    let options = match parse_args(std::env::args()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    if options.show_help {
        println!("{}", usage());
        return;
    }

    let initial_url = match native::parse_initial_url(options.initial_url.as_deref()) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };

    if let Err(error) = native::run(
        initial_url,
        options.switches,
        options.webdriver_port,
        options.devtools_port,
        options.extension_archive.map(Into::into),
        options.ignore_certificate_errors,
        options.session_action,
    ) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, run, CliOptions, SessionAction};
    use nomad_core::Switches;

    #[test]
    fn test_parse_args_defaults_both_switches_off() {
        let options = parse_args(vec!["nomad-browser".into()]).unwrap();

        assert_eq!(
            options,
            CliOptions {
                switches: Switches::default(),
                show_help: false,
                initial_url: None,
                webdriver_port: None,
                devtools_port: None,
                extension_archive: None,
                ignore_certificate_errors: false,
                session_action: SessionAction::Automatic,
            }
        );
    }

    #[test]
    fn test_parse_args_accepts_initial_url() {
        let options = parse_args(vec![
            "nomad-browser".into(),
            "--url".into(),
            "https://example.com".into(),
        ])
        .unwrap();

        assert_eq!(options.initial_url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn test_parse_args_accepts_positional_initial_url() {
        let options =
            parse_args(vec!["nomad-browser".into(), "https://example.com".into()]).unwrap();

        assert_eq!(options.initial_url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn test_run_starts_runtime_with_one_tab() {
        assert_eq!(
            run(vec!["nomad-browser".into()]).unwrap(),
            "route=direct\numc=off\nxray=off\ntabs=1\nactive_tab=1"
        );
    }

    #[test]
    fn test_parse_args_accepts_webdriver_port() {
        let options = parse_args(vec![
            "nomad-browser".into(),
            "--webdriver".into(),
            "9515".into(),
        ])
        .unwrap();

        assert_eq!(options.webdriver_port, Some(9515));
    }

    #[test]
    fn test_parse_args_accepts_devtools_port() {
        let options = parse_args(vec!["nomad-browser".into(), "--devtools=7001".into()]).unwrap();

        assert_eq!(options.devtools_port, Some(7001));
    }

    #[test]
    fn test_parse_args_accepts_extension_archive() {
        let options = parse_args(vec![
            "nomad-browser".into(),
            "--extension-archive".into(),
            "/tmp/wallet.zip".into(),
        ])
        .unwrap();

        assert_eq!(
            options.extension_archive.as_deref(),
            Some("/tmp/wallet.zip")
        );
        assert!(parse_args(vec!["nomad-browser".into(), "--extension-archive=".into(),]).is_err());
    }

    #[test]
    fn test_parse_args_exposes_session_recovery_choices() {
        let restore = parse_args(vec!["nomad-browser".into(), "--restore-session".into()]).unwrap();
        assert_eq!(restore.session_action, SessionAction::Restore);

        let clean = parse_args(vec!["nomad-browser".into(), "--new-session".into()]).unwrap();
        assert_eq!(clean.session_action, SessionAction::StartClean);

        assert!(parse_args(vec![
            "nomad-browser".into(),
            "--restore-session".into(),
            "--new-session".into(),
        ])
        .is_err());
    }

    #[test]
    fn test_parse_args_accepts_servo_wpt_webdriver_form() {
        let options = parse_args(vec![
            "nomad-browser".into(),
            "--webdriver=9515".into(),
            "--headless".into(),
            "--window-size".into(),
            "800x600".into(),
            "about:blank".into(),
        ])
        .unwrap();

        assert_eq!(options.webdriver_port, Some(9515));
        assert_eq!(options.initial_url.as_deref(), Some("about:blank"));
    }

    #[test]
    fn test_parse_args_preserves_wpt_certificate_override() {
        let options = parse_args(vec![
            "nomad-browser".into(),
            "--ignore-certificate-errors".into(),
        ])
        .unwrap();

        assert!(options.ignore_certificate_errors);
    }

    #[test]
    fn test_parse_args_rejects_zero_webdriver_port() {
        let error = parse_args(vec![
            "nomad-browser".into(),
            "--webdriver".into(),
            "0".into(),
        ])
        .unwrap_err();

        assert!(error.contains("non-zero TCP port"));
    }

    #[test]
    fn test_run_rejects_unsupported_initial_url() {
        let result = run(vec![
            "nomad-browser".into(),
            "--url".into(),
            "javascript:alert(1)".into(),
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_args_enables_umc_and_xray_independently() {
        let options = parse_args(vec!["nomad-browser".into(), "--umc".into()]).unwrap();
        assert!(options.switches.umc_enabled());
        assert!(!options.switches.xray_enabled());

        let options = parse_args(vec!["nomad-browser".into(), "--xray".into()]).unwrap();
        assert!(!options.switches.umc_enabled());
        assert!(options.switches.xray_enabled());
    }

    #[test]
    fn test_parse_args_supports_explicit_disable_switches() {
        let options = parse_args(vec![
            "nomad-browser".into(),
            "--umc".into(),
            "--no-umc".into(),
            "--xray".into(),
            "--no-xray".into(),
        ])
        .unwrap();

        assert_eq!(options.switches, Switches::default());
    }

    #[test]
    fn test_parse_args_rejects_both_network_switches_enabled() {
        let result = parse_args(vec![
            "nomad-browser".into(),
            "--umc".into(),
            "--xray".into(),
        ]);

        assert_eq!(
            result,
            Err("UMC and Xray cannot be enabled together.".into())
        );
    }

    #[test]
    fn test_parse_args_rejects_unknown_flags() {
        let result = parse_args(vec!["nomad-browser".into(), "--tor".into()]);

        assert!(result.is_err());
    }

    #[test]
    fn test_run_refuses_direct_fallback_when_xray_is_enabled() {
        let result = run(vec!["nomad-browser".into(), "--xray".into()]);

        assert_eq!(
            result,
            Err(
                "Xray switch enabled, but Xray backend is unavailable; refusing direct fallback."
                    .into()
            )
        );
    }
}
