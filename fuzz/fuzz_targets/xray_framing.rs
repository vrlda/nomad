#![no_main]

use libfuzzer_sys::fuzz_target;
use nomad_engine::xray::fuzzing;

fuzz_target!(|input: &[u8]| {
    // These are pure parser entry points. They never open a socket, resolve a
    // hostname, or start an Xray listener.
    let _ = fuzzing::decode_grpc_messages(input);
    let _ = fuzzing::decode_hysteria_request(input);
    let _ = fuzzing::decode_hysteria_response(input);
    let _ = fuzzing::decode_quic_varint(input);
    let _ = fuzzing::decode_shadowsocks_frame(input);
});
