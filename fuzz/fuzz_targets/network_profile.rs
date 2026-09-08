#![no_main]

use libfuzzer_sys::fuzz_target;
use nomad_engine::{NetworkProfile, NetworkProfileStore};

fuzz_target!(|input: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(input) {
        let _ = NetworkProfile::from_json(raw);
        let _ = NetworkProfileStore::from_json(raw);
    }
});
