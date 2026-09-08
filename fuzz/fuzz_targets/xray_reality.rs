#![no_main]

use libfuzzer_sys::fuzz_target;
use nomad_engine::xray::fuzzing;

fuzz_target!(|input: &[u8]| {
    // REALITY parsing is exercised without connecting to a remote peer.
    let _ = fuzzing::parse_reality_client_hello(input);
    let _ = fuzzing::parse_reality_server_hello(input);
});
