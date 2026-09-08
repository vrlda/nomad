use std::env;
use std::path::PathBuf;

/// Host operating-system family used by release and storage policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Macos,
    Linux,
    Windows,
    Other,
}

impl Platform {
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Other
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Other => "other",
        }
    }
}

/// Release metadata used by native packaging and update selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseTarget {
    pub platform: Platform,
    pub target_triple: &'static str,
    pub archive_extension: &'static str,
    pub executable_name: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseTargetError {
    InvalidVersion,
}

impl ReleaseTarget {
    /// Returns the release target represented by this build.
    #[must_use]
    pub const fn current() -> Self {
        let platform = Platform::current();
        Self {
            platform,
            target_triple: current_target_triple(),
            archive_extension: match platform {
                Platform::Macos | Platform::Windows => "zip",
                Platform::Linux | Platform::Other => "tar.gz",
            },
            executable_name: if matches!(platform, Platform::Windows) {
                "nomad-browser.exe"
            } else {
                "nomad-browser"
            },
        }
    }

    /// Returns the deterministic package filename for a release version.
    ///
    /// Only numeric dot-separated versions are accepted so the result cannot
    /// escape the package directory when it is used by release tooling.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseTargetError::InvalidVersion`] when the version is not
    /// a bounded numeric dot-separated value.
    pub fn package_filename(self, version: &str) -> Result<String, ReleaseTargetError> {
        let version = version.trim();
        if version.is_empty()
            || version.len() > 64
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
            || version.starts_with('.')
            || version.ends_with('.')
            || version.contains("..")
        {
            return Err(ReleaseTargetError::InvalidVersion);
        }
        Ok(format!(
            "nomad-browser-{version}-{}.{}",
            self.target_triple, self.archive_extension
        ))
    }
}

/// Returns the target metadata for the running build.
#[must_use]
pub const fn current_release_target() -> ReleaseTarget {
    ReleaseTarget::current()
}

const fn current_target_triple() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        "aarch64-pc-windows-msvc"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else {
        "unknown-unknown"
    }
}

/// Per-user locations for Nomad configuration, durable data, and cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

/// Resolves platform-native user directories without creating them.
#[must_use]
pub fn user_paths() -> Option<PlatformPaths> {
    match Platform::current() {
        Platform::Macos => home_dir().map(|home| {
            let application_support = home
                .join("Library")
                .join("Application Support")
                .join("Nomad");
            PlatformPaths {
                config_dir: application_support.clone(),
                data_dir: application_support,
                cache_dir: home.join("Library").join("Caches").join("Nomad"),
            }
        }),
        Platform::Linux => home_dir().map(|home| {
            let config = env::var_os("XDG_CONFIG_HOME")
                .map_or_else(|| home.join(".config"), PathBuf::from)
                .join("nomad");
            let data = env::var_os("XDG_DATA_HOME")
                .map_or_else(|| home.join(".local").join("share"), PathBuf::from)
                .join("nomad");
            let cache = env::var_os("XDG_CACHE_HOME")
                .map_or_else(|| home.join(".cache"), PathBuf::from)
                .join("nomad");
            PlatformPaths {
                config_dir: config,
                data_dir: data,
                cache_dir: cache,
            }
        }),
        Platform::Windows => env::var_os("APPDATA").map(|appdata| {
            let appdata = PathBuf::from(appdata);
            let local = env::var_os("LOCALAPPDATA").map_or_else(|| appdata.clone(), PathBuf::from);
            PlatformPaths {
                config_dir: appdata.join("Nomad"),
                data_dir: appdata.join("Nomad"),
                cache_dir: local.join("Nomad").join("Cache"),
            }
        }),
        Platform::Other => None,
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::{current_release_target, user_paths, Platform, ReleaseTargetError};

    #[test]
    fn current_platform_has_stable_release_label() {
        assert!(!Platform::current().as_str().is_empty());
    }

    #[test]
    fn current_release_target_has_safe_package_metadata() {
        let target = current_release_target();
        assert!(!target.target_triple.is_empty());
        assert!(!target.archive_extension.is_empty());
        assert!(!target.executable_name.is_empty());
        let package = target.package_filename("1.2.3").unwrap();
        assert!(package.starts_with("nomad-browser-1.2.3-"));
        assert!(!package.contains('/'));
        assert!(!package.contains('\\'));
    }

    #[test]
    fn release_package_names_reject_path_like_versions() {
        let target = current_release_target();
        for version in ["", ".1", "1.", "1..2", "1/../../tmp", "v1.2"] {
            assert_eq!(
                target.package_filename(version),
                Err(ReleaseTargetError::InvalidVersion)
            );
        }
    }

    #[test]
    fn user_paths_are_platform_native_when_environment_is_available() {
        if let Some(paths) = user_paths() {
            assert!(paths.config_dir.ends_with("Nomad") || paths.config_dir.ends_with("nomad"));
            assert!(paths.data_dir.ends_with("Nomad") || paths.data_dir.ends_with("nomad"));
            assert!(paths
                .cache_dir
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("nomad"));
        }
    }
}
