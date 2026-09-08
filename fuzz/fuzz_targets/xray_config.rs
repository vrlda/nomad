#![no_main]

use libfuzzer_sys::fuzz_target;
use nomad_engine::xray::{XrayConfig, FUZZ_INPUT_LIMIT};

fuzz_target!(|input: &[u8]| {
    // Parsing must be total over attacker-controlled profile bytes: malformed
    // configs are rejected as data and must never panic or start a listener.
    let input = &input[..input.len().min(FUZZ_INPUT_LIMIT)];
    let text = String::from_utf8_lossy(input);
    let _ = XrayConfig::from_json(&text);
});
