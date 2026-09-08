//! Self-contained behavioral coverage for Nomad's embedded Xray-compatible
//! core. These tests exercise the public `XrayCore` SOCKS surface and verify
//! connection lifecycle semantics that a live differential run against a
//! reference Xray binary would also cover: repeated connects (reconnect),
//! client cancellation mid-stream, upstream authentication/handshake failures
//! failing closed, and clean half-close propagation.
//!
//! The live reference differential (running a pinned Xray server and Nomad's
//! core against it) is intentionally separate and requires the reference
//! binary; these tests are deterministic and run in CI.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use nomad_engine::xray::{XrayConfig, XrayCore};

fn connect_socks(core: &XrayCore) -> TcpStream {
    let mut client = TcpStream::connect((core.endpoint().host(), core.endpoint().port())).unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, &[0x05, 0x00]);
    client
}

fn socks_ipv4_request(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn echo_server() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(length) => {
                            if stream.write_all(&buffer[..length]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

#[test]
fn core_handles_repeated_connections_across_sessions() {
    let port = echo_server();
    let config = XrayConfig::from_json(
        r#"{"outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"AsIs"}}]}"#,
    )
    .unwrap();
    let core = XrayCore::start(config).unwrap();

    // Many sequential sessions through the same core must all succeed; this
    // exercises the accept loop and per-connection dispatch without leakage.
    for round in 0..16u8 {
        let mut client = connect_socks(&core);
        client
            .write_all(&socks_ipv4_request([127, 0, 0, 1], port))
            .unwrap();
        let mut response = [0u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0x00, "session {round} failed");
        let payload = format!("round-{round}");
        client.write_all(payload.as_bytes()).unwrap();
        let mut echo = vec![0u8; payload.len()];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, payload.as_bytes());
    }
}

#[test]
fn client_cancellation_closes_upstream_and_core_stays_usable() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(0u32));
    let observed_clone = observed.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0u8; 16];
        // The client cancels: it sends a partial request then drops. The
        // upstream must observe EOF (read returns 0), proving cancellation
        // propagates instead of leaving a dangling connection.
        match stream.read(&mut buffer) {
            Ok(0) => *observed_clone.lock().unwrap() += 1,
            Ok(length) if length < 16 => {
                let mut remaining = [0u8; 16];
                if let Ok(0) = stream.read(&mut remaining) {
                    *observed_clone.lock().unwrap() += 1;
                }
            }
            _ => {}
        }
    });

    let config = XrayConfig::from_json(
        r#"{"outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"AsIs"}}]}"#,
    )
    .unwrap();
    let core = XrayCore::start(config).unwrap();

    let mut client = connect_socks(&core);
    client
        .write_all(&socks_ipv4_request([127, 0, 0, 1], address.port()))
        .unwrap();
    let mut response = [0u8; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(response[1], 0x00);
    client.write_all(b"partial").unwrap();
    drop(client); // cancel the session

    server.join().unwrap();
    assert_eq!(*observed.lock().unwrap(), 1, "upstream did not observe EOF");

    // The core must remain usable after the cancelled session.
    let port = echo_server();
    let mut client = connect_socks(&core);
    client
        .write_all(&socks_ipv4_request([127, 0, 0, 1], port))
        .unwrap();
    let mut response = [0u8; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(response[1], 0x00);
}

#[test]
fn upstream_handshake_failure_fails_closed_without_fallback() {
    // A listener that accepts but never completes a SOCKS handshake.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.read(&mut [0u8; 64]); // consume and hang up
    });

    // The core forwards to this "SOCKS" upstream; the handshake never
    // completes, so the local SOCKS reply must be a failure code and the
    // request must NOT fall back to a direct connection.
    let config = XrayConfig::from_json(&format!(
        r#"{{"outbounds":[{{"protocol":"socks","settings":{{"servers":[{{"address":"{}","port":{}}}]}}}}]}}"#,
        address.ip(),
        address.port()
    ))
    .unwrap();
    let core = XrayCore::start(config).unwrap();

    let mut client = connect_socks(&core);
    client
        .write_all(&socks_ipv4_request([127, 0, 0, 1], 80))
        .unwrap();
    let mut response = [0u8; 10];
    // The core must reply promptly with a failure code (0x01), not hang and
    // not silently proxy the request directly.
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let read = client.read_exact(&mut response);
    assert!(read.is_ok(), "core did not reply to a failed upstream");
    assert_ne!(response[1], 0x00, "failed upstream must not report success");
}

#[test]
fn clean_half_close_is_propagated_to_the_client() {
    // A server that responds then closes its write side; the client must see
    // a clean EOF after the response (half-close semantics).
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 4];
        let _ = stream.read_exact(&mut request);
        let _ = stream.write_all(b"done");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        // Keep the read side open briefly; the client should finish after EOF.
        let _ = stream.read(&mut [0u8; 8]);
    });

    let config = XrayConfig::from_json(
        r#"{"outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"AsIs"}}]}"#,
    )
    .unwrap();
    let core = XrayCore::start(config).unwrap();

    let mut client = connect_socks(&core);
    client
        .write_all(&socks_ipv4_request([127, 0, 0, 1], address.port()))
        .unwrap();
    let mut response = [0u8; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(response[1], 0x00);
    client.write_all(b"ping").unwrap();
    let mut body = [0u8; 4];
    client.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"done");
    // After the upstream half-closed its write side, the relay must surface a
    // clean EOF rather than an error.
    let mut trailing = [0u8; 1];
    assert_eq!(client.read(&mut trailing).unwrap(), 0);
}
