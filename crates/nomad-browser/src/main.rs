use nomad_core::{BackendAvailability, RouteError, RouteMode, Switches};

#[derive(Debug, Eq, PartialEq)]
struct CliOptions {
    switches: Switches,
    show_help: bool,
}

fn parse_args<I>(args: I) -> Result<CliOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut switches = Switches::default();
    let mut show_help = false;
    let mut args = args.into_iter();

    args.next();

    for arg in args {
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
            "--help" | "-h" => show_help = true,
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(CliOptions {
        switches,
        show_help,
    })
}

fn run<I>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = String>,
{
    let options = parse_args(args)?;

    if options.show_help {
        return Ok(usage().to_owned());
    }

    let availability = BackendAvailability::new(false, false);
    let route = options
        .switches
        .resolve_route(availability)
        .map_err(route_error_message)?;

    Ok(format!(
        "route={}\numc={}\nxray={}",
        route_label(route),
        on_off(options.switches.umc_enabled()),
        on_off(options.switches.xray_enabled()),
    ))
}

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

const fn route_label(route: RouteMode) -> &'static str {
    match route {
        RouteMode::Direct => "direct",
        RouteMode::Umc => "umc",
        RouteMode::Xray => "xray",
    }
}

const fn on_off(enabled: bool) -> &'static str {
    if enabled {
        "on"
    } else {
        "off"
    }
}

const fn usage() -> &'static str {
    "nomad-browser [--umc|--no-umc] [--xray|--no-xray]"
}

fn main() {
    match run(std::env::args()) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, run, CliOptions};
    use nomad_core::Switches;

    #[test]
    fn test_parse_args_defaults_both_switches_off() {
        let options = parse_args(vec!["nomad-browser".into()]).unwrap();

        assert_eq!(
            options,
            CliOptions {
                switches: Switches::default(),
                show_help: false,
            }
        );
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
