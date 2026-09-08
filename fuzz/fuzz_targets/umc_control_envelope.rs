#![no_main]

use libfuzzer_sys::fuzz_target;
use nomad_engine::ControlEnvelope;

fuzz_target!(|input: &[u8]| {
    // The decoder must treat arbitrary UMC protobuf bytes as untrusted data.
    // It validates size and wire framing without opening a socket or starting
    // a session.
    let _ = ControlEnvelope::from_bytes(input);
});
