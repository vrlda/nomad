#![no_main]

use libfuzzer_sys::fuzz_target;
use nomad_engine::ExtensionManifest;

fuzz_target!(|input: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(input) {
        let _ = ExtensionManifest::from_json(raw);
    }
});
