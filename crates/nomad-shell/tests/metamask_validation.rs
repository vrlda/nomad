//! Real ``MetaMask`` package validation.
//!
//! ``MetaMask`` is the reference wallet compatibility target. This test installs
//! the actual ``MetaMask`` MV3 package (downloaded from ``MetaMask``'s GitHub
//! releases, see `tools/fetch-metamask.sh`) through Nomad's extension
//! install path and validates the wallet-critical surface: manifest shape,
//! service-worker background, provider content scripts, i18n locale data,
//! permissions, storage, and uninstall.
//!
//! The package is intentionally not committed to the repository; the test is
//! `#[ignore]`d and runs only when the package is available, mirroring the
//! completion-matrix rule that a real package must pass before wallet
//! compatibility is claimed.

use std::path::PathBuf;

use nomad_core::{BackendAvailability, Switches};
use nomad_engine::{BrowserRuntime, ExtensionManifest, ExtensionPermission};
use nomad_shell::ShellState;

fn metamask_zip_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("NOMAD_METAMASK_ZIP") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let default = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tools")
        .join("metamask")
        .join("metamask-chrome-13.44.0.zip");
    default.is_file().then_some(default)
}

fn runtime() -> BrowserRuntime {
    BrowserRuntime::new(Switches::default(), BackendAvailability::all_available())
        .expect("direct mode should always initialize")
}

#[test]
#[ignore = "requires the real MetaMask package (see tools/fetch-metamask.sh)"]
fn real_metamask_package_installs_and_exposes_wallet_surface() {
    let Some(zip_path) = metamask_zip_path() else {
        panic!("MetaMask package not found; run tools/fetch-metamask.sh or set NOMAD_METAMASK_ZIP");
    };
    let bytes = std::fs::read(&zip_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", zip_path.display()));

    let mut shell = ShellState::new(runtime());
    shell
        .install_extension_archive(&bytes)
        .expect("MetaMask archive must install through Nomad's validated package path");

    let ids: Vec<String> = shell
        .extensions()
        .installed()
        .map(|manifest| manifest.id.clone())
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "exactly one extension (MetaMask) must be installed"
    );

    let manifest: ExtensionManifest = shell
        .extensions()
        .manifest(&ids[0])
        .expect("installed MetaMask manifest must be available");
    assert_eq!(manifest.manifest_version, 3, "MetaMask is an MV3 package");
    assert_eq!(manifest.version, "13.44.0.0");

    // Wallet-critical resources must be present: the service-worker
    // background, the provider-injection content scripts, the action popup,
    // and the en locale catalog.
    for required in [
        "service-worker.js",
        "scripts/inpage.js",
        "scripts/contentscript.js",
        "popup-init.html",
        "_locales/en/messages.json",
    ] {
        assert!(
            shell
                .extensions()
                .resource_source(&ids[0], required)
                .is_some(),
            "MetaMask package is missing required resource {required}"
        );
    }

    // The background must be the MV3 service worker, and the content scripts
    // must include the provider-injection pair for the page surface.
    let background = manifest
        .background
        .as_ref()
        .expect("MetaMask declares a background");
    assert!(background.service_worker.is_some());
    assert!(
        manifest
            .content_scripts
            .iter()
            .any(|script| script.js.contains("scripts/inpage.js")
                || script
                    .js_files
                    .iter()
                    .any(|file| file.contains("scripts/inpage.js"))),
        "MetaMask must inject its provider into the page"
    );

    // Wallet-relevant permission surface must parse.
    for permission in [
        ExtensionPermission::Storage,
        ExtensionPermission::Alarms,
        ExtensionPermission::Notifications,
        ExtensionPermission::Scripting,
        ExtensionPermission::WebRequest,
        ExtensionPermission::Identity,
        ExtensionPermission::Cookies,
    ] {
        assert!(
            manifest.permissions.contains(&permission),
            "MetaMask must declare the {permission:?} permission"
        );
    }

    // i18n: MetaMask names itself via `__MSG_appName__`; its en catalog must
    // resolve through the locale data Nomad loads as resources.
    let locale = shell
        .extensions()
        .resource_source(&ids[0], "_locales/en/messages.json")
        .expect("en locale catalog");
    assert!(locale.contains("\"appName\""), "locale catalog has appName");

    // Uninstall removes the wallet extension cleanly.
    shell
        .uninstall_extension(&ids[0])
        .expect("MetaMask uninstall must succeed");
    assert!(shell.extensions().installed().next().is_none());
}
