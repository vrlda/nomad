#![no_main]

use libfuzzer_sys::fuzz_target;
use nomad_engine::parse_proxy_endpoint;

fuzz_target!(|input: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(input) {
        let _ = parse_proxy_endpoint(raw);
    }
});
