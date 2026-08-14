#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteMode {
    Direct,
    Umc,
    Xray,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Switches {
    mode: RouteMode,
}

impl Default for Switches {
    fn default() -> Self {
        Self::direct()
    }
}

impl Switches {
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            mode: RouteMode::Direct,
        }
    }

    #[must_use]
    pub const fn umc() -> Self {
        Self {
            mode: RouteMode::Umc,
        }
    }

    #[must_use]
    pub const fn xray() -> Self {
        Self {
            mode: RouteMode::Xray,
        }
    }

    #[must_use]
    pub const fn umc_enabled(self) -> bool {
        matches!(self.mode, RouteMode::Umc)
    }

    #[must_use]
    pub const fn xray_enabled(self) -> bool {
        matches!(self.mode, RouteMode::Xray)
    }

    pub fn set_umc_enabled(&mut self, enabled: bool) {
        if enabled {
            self.mode = RouteMode::Umc;
        } else if self.umc_enabled() {
            self.mode = RouteMode::Direct;
        }
    }

    pub fn set_xray_enabled(&mut self, enabled: bool) {
        if enabled {
            self.mode = RouteMode::Xray;
        } else if self.xray_enabled() {
            self.mode = RouteMode::Direct;
        }
    }

    /// Resolves enabled switches into one concrete network route.
    ///
    /// # Errors
    ///
    /// Returns an error when an enabled backend is unavailable. This prevents
    /// an enabled privacy route from silently falling back to direct traffic.
    pub fn resolve_route(self, availability: BackendAvailability) -> Result<RouteMode, RouteError> {
        match self.mode {
            RouteMode::Direct => Ok(RouteMode::Direct),
            RouteMode::Umc if availability.umc_available => Ok(RouteMode::Umc),
            RouteMode::Umc => Err(RouteError::UmcUnavailable),
            RouteMode::Xray if availability.xray_available => Ok(RouteMode::Xray),
            RouteMode::Xray => Err(RouteError::XrayUnavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendAvailability {
    pub umc_available: bool,
    pub xray_available: bool,
}

impl BackendAvailability {
    #[must_use]
    pub const fn new(umc_available: bool, xray_available: bool) -> Self {
        Self {
            umc_available,
            xray_available,
        }
    }

    #[must_use]
    pub const fn all_available() -> Self {
        Self::new(true, true)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    UmcUnavailable,
    XrayUnavailable,
}

#[cfg(test)]
mod tests {
    use super::{BackendAvailability, RouteError, RouteMode, Switches};

    #[test]
    fn test_switches_default_to_disabled() {
        let switches = Switches::default();

        assert!(!switches.umc_enabled());
        assert!(!switches.xray_enabled());
    }

    #[test]
    fn test_resolve_route_with_both_switches_off_uses_direct() {
        let switches = Switches::default();
        let availability = BackendAvailability::all_available();

        assert_eq!(switches.resolve_route(availability), Ok(RouteMode::Direct));
    }

    #[test]
    fn test_resolve_route_with_only_umc_enabled_uses_umc() {
        let switches = Switches::umc();
        let availability = BackendAvailability::new(true, false);

        assert_eq!(switches.resolve_route(availability), Ok(RouteMode::Umc));
    }

    #[test]
    fn test_resolve_route_with_only_xray_enabled_uses_xray() {
        let switches = Switches::xray();
        let availability = BackendAvailability::new(false, true);

        assert_eq!(switches.resolve_route(availability), Ok(RouteMode::Xray));
    }

    #[test]
    fn test_resolve_route_fails_closed_when_umc_is_enabled_but_unavailable() {
        let switches = Switches::umc();
        let availability = BackendAvailability::new(false, true);

        assert_eq!(
            switches.resolve_route(availability),
            Err(RouteError::UmcUnavailable)
        );
    }

    #[test]
    fn test_resolve_route_fails_closed_when_xray_is_enabled_but_unavailable() {
        let switches = Switches::xray();
        let availability = BackendAvailability::new(true, false);

        assert_eq!(
            switches.resolve_route(availability),
            Err(RouteError::XrayUnavailable)
        );
    }

    #[test]
    fn test_switches_can_be_toggled_exclusively() {
        let mut switches = Switches::umc();

        switches.set_umc_enabled(true);
        assert!(switches.umc_enabled());
        assert!(!switches.xray_enabled());

        switches.set_xray_enabled(true);
        assert!(!switches.umc_enabled());
        assert!(switches.xray_enabled());

        switches.set_xray_enabled(false);
        assert!(!switches.umc_enabled());
        assert!(!switches.xray_enabled());
    }
}
