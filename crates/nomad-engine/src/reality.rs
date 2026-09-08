use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::SecureRandom;
use ring::{aead, hkdf, hmac, rand, signature};
use sha2::{Digest, Sha256, Sha384};
use x25519_dalek::{PublicKey, StaticSecret};

use super::connect_tcp;
use super::XrayRealitySettings;

const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const TLS_APPLICATION_RECORD: u8 = 0x17;
const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_MAX_RECORD: usize = 18_432;
const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x01];
const CLIENT_HELLO: u8 = 0x01;
const X25519_GROUP: [u8; 2] = [0x00, 0x1d];
const CIPHER_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

pub(super) struct RealityClientHello {
    pub(super) record: Vec<u8>,
    pub(super) client_private_key: [u8; 32],
    auth_key: [u8; 32],
}

#[cfg(any(test, feature = "fuzzing"))]
#[cfg_attr(feature = "fuzzing", allow(dead_code))]
struct ParsedClientHello {
    handshake: Vec<u8>,
    client_random: [u8; 32],
    encrypted_session_id: [u8; 32],
    client_public_key: [u8; 32],
    server_name: String,
}

struct ParsedServerHello {
    handshake: Vec<u8>,
    server_public_key: [u8; 32],
    cipher_suite: CipherSuite,
}

#[derive(Clone, Copy)]
enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    fn from_id(id: u16) -> io::Result<Self> {
        match id {
            0x1301 => Ok(Self::Aes128GcmSha256),
            0x1302 => Ok(Self::Aes256GcmSha384),
            0x1303 => Ok(Self::ChaCha20Poly1305Sha256),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("REALITY server selected unsupported cipher suite 0x{id:04x}"),
            )),
        }
    }

    fn hash_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    fn hmac_algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Aes256GcmSha384 => hmac::HMAC_SHA384,
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => hmac::HMAC_SHA256,
        }
    }

    fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => Sha384::digest(input).to_vec(),
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => Sha256::digest(input).to_vec(),
        }
    }

    fn aead_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }
}

pub(super) struct RealityStream {
    stream: TcpStream,
    cipher_suite: CipherSuite,
    read_key: Vec<u8>,
    read_iv: [u8; 12],
    write_key: Vec<u8>,
    write_iv: [u8; 12],
    read_sequence: u64,
    write_sequence: u64,
    ciphertext: Vec<u8>,
    plaintext: Vec<u8>,
    write_pending: Vec<u8>,
    pending_plaintext_len: Option<usize>,
    nonblocking: bool,
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(super) fn build_client_hello(
    settings: &XrayRealitySettings,
    server_name: &str,
) -> io::Result<RealityClientHello> {
    let rng = rand::SystemRandom::new();
    let mut client_random = [0u8; 32];
    let mut client_private_key = [0u8; 32];
    rng.fill(&mut client_random)
        .map_err(|_| io::Error::other("failed to generate REALITY client random"))?;
    rng.fill(&mut client_private_key)
        .map_err(|_| io::Error::other("failed to generate REALITY client key"))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before Unix epoch"))?
        .as_secs();
    let timestamp = u32::try_from(timestamp & u64::from(u32::MAX)).unwrap_or_default();
    build_client_hello_with_material(
        settings,
        server_name,
        client_random,
        client_private_key,
        timestamp,
    )
}

pub(super) fn build_client_hello_with_material(
    settings: &XrayRealitySettings,
    server_name: &str,
    client_random: [u8; 32],
    client_private_key: [u8; 32],
    timestamp: u32,
) -> io::Result<RealityClientHello> {
    validate_settings(settings, server_name)?;
    let client_secret = StaticSecret::from(client_private_key);
    let client_public_key = PublicKey::from(&client_secret).to_bytes();
    let server_public_key = PublicKey::from(settings.public_key);
    let shared_secret = client_secret.diffie_hellman(&server_public_key);
    if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(invalid_input(
            "REALITY public key produces an invalid shared secret",
        ));
    }
    let auth_key = derive_auth_key(shared_secret.as_bytes(), &client_random);

    let mut session_id = [0u8; 16];
    session_id[..3].copy_from_slice(&[1, 8, 0]);
    session_id[4..8].copy_from_slice(&timestamp.to_be_bytes());
    session_id[8..8 + settings.short_id.len()].copy_from_slice(&settings.short_id);
    let mut session_id_block = [0u8; 32];
    session_id_block[..16].copy_from_slice(&session_id);

    let mut handshake = construct_client_hello(
        &client_random,
        &session_id_block,
        &client_public_key,
        server_name,
    )?;
    let aad = {
        handshake[39..71].fill(0);
        handshake.clone()
    };
    let encrypted_session_id =
        encrypt_session_id(&session_id, &auth_key, &client_random[20..], &aad)?;
    handshake[39..71].copy_from_slice(&encrypted_session_id);

    let record_length = u16::try_from(handshake.len())
        .map_err(|_| invalid_input("REALITY ClientHello is too large"))?;
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(TLS_HANDSHAKE_RECORD);
    record.extend_from_slice(&TLS_LEGACY_VERSION);
    record.extend_from_slice(&record_length.to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(RealityClientHello {
        record,
        client_private_key,
        auth_key,
    })
}

fn validate_settings(settings: &XrayRealitySettings, server_name: &str) -> io::Result<()> {
    if settings.short_id.len() > 8 {
        return Err(invalid_input("REALITY short ID cannot exceed 8 bytes"));
    }
    if settings.fingerprint != "chrome" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the embedded REALITY ClientHello currently supports the chrome fingerprint only",
        ));
    }
    if server_name.is_empty()
        || server_name.len() > 255
        || !server_name.is_ascii()
        || server_name.contains(['\0', '\r', '\n'])
    {
        return Err(invalid_input("invalid REALITY SNI server name"));
    }
    if settings.public_key.iter().all(|byte| *byte == 0) {
        return Err(invalid_input("REALITY public key cannot be all zeroes"));
    }
    Ok(())
}

fn construct_client_hello(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    client_public_key: &[u8; 32],
    server_name: &str,
) -> io::Result<Vec<u8>> {
    let name = server_name.as_bytes();
    let mut extensions = Vec::with_capacity(128);

    let sni_length = 5usize
        .checked_add(name.len())
        .ok_or_else(|| invalid_input("REALITY SNI length overflow"))?;
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(
        &u16::try_from(sni_length)
            .map_err(|_| invalid_input("REALITY SNI is too long"))?
            .to_be_bytes(),
    );
    extensions.extend_from_slice(
        &u16::try_from(3 + name.len())
            .map_err(|_| invalid_input("REALITY SNI is too long"))?
            .to_be_bytes(),
    );
    extensions.push(0x00);
    extensions.extend_from_slice(
        &u16::try_from(name.len())
            .map_err(|_| invalid_input("REALITY SNI is too long"))?
            .to_be_bytes(),
    );
    extensions.extend_from_slice(name);

    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24]);
    extensions.extend_from_slice(&X25519_GROUP);
    extensions.extend_from_slice(&[0x00, 0x20]);
    extensions.extend_from_slice(client_public_key);
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07]);

    let mut hello = Vec::with_capacity(512);
    hello.extend_from_slice(&[CLIENT_HELLO, 0, 0, 0]);
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(client_random);
    hello.push(32);
    hello.extend_from_slice(session_id);
    hello.extend_from_slice(
        &u16::try_from(CIPHER_SUITES.len() * 2)
            .unwrap_or_default()
            .to_be_bytes(),
    );
    for suite in CIPHER_SUITES {
        hello.extend_from_slice(&suite.to_be_bytes());
    }
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(
        &u16::try_from(extensions.len())
            .map_err(|_| invalid_input("REALITY extensions are too large"))?
            .to_be_bytes(),
    );
    hello.extend_from_slice(&extensions);
    let message_length = u32::try_from(hello.len().saturating_sub(4))
        .map_err(|_| invalid_input("REALITY ClientHello length overflow"))?;
    hello[1..4].copy_from_slice(&message_length.to_be_bytes()[1..]);
    Ok(hello)
}

fn derive_auth_key(shared_secret: &[u8], client_random: &[u8; 32]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &client_random[..20]);
    let pseudo_random_key = salt.extract(shared_secret);
    let info: [&[u8]; 1] = [b"REALITY"];
    let expanded = pseudo_random_key
        .expand(&info, hkdf::HKDF_SHA256)
        .expect("REALITY HKDF output length is valid");
    let mut key = [0u8; 32];
    expanded
        .fill(&mut key)
        .expect("REALITY HKDF output length is valid");
    key
}

fn encrypt_session_id(
    plaintext: &[u8; 16],
    key: &[u8; 32],
    nonce_bytes: &[u8],
    aad: &[u8],
) -> io::Result<[u8; 32]> {
    let nonce = <&[u8; 12]>::try_from(nonce_bytes)
        .map_err(|_| invalid_input("REALITY nonce must be 12 bytes"))?;
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| invalid_input("invalid REALITY AES key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut ciphertext)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY session ID encryption failed",
            )
        })?;
    ciphertext.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY session ID length mismatch",
        )
    })
}

#[cfg(test)]
fn decrypt_session_id(
    ciphertext: &[u8; 32],
    key: &[u8; 32],
    nonce_bytes: &[u8],
    aad: &[u8],
) -> io::Result<[u8; 16]> {
    let nonce = <&[u8; 12]>::try_from(nonce_bytes)
        .map_err(|_| invalid_input("REALITY nonce must be 12 bytes"))?;
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| invalid_input("invalid REALITY AES key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let mut plaintext = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, aead::Aad::from(aad), &mut plaintext)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY session ID authentication failed",
            )
        })?;
    plaintext.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY session ID length mismatch",
        )
    })
}

#[cfg(any(test, feature = "fuzzing"))]
fn parse_client_hello_record(record: &[u8]) -> io::Result<ParsedClientHello> {
    if record.len() < 5 || record[0] != TLS_HANDSHAKE_RECORD || record[1..3] != TLS_LEGACY_VERSION {
        return Err(invalid_data("invalid REALITY ClientHello record header"));
    }
    let record_length = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record_length != record.len() - 5 {
        return Err(invalid_data("REALITY record length mismatch"));
    }
    let handshake = &record[5..];
    if handshake.len() < 4 || handshake[0] != CLIENT_HELLO {
        return Err(invalid_data("REALITY record does not contain ClientHello"));
    }
    let handshake_length = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    if handshake_length != handshake.len() - 4 {
        return Err(invalid_data("REALITY ClientHello length mismatch"));
    }
    let mut offset = 4;
    offset = checked_advance(handshake, offset, 2 + 32)?;
    let session_id_length = *handshake
        .get(offset)
        .ok_or_else(|| invalid_data("missing REALITY session ID"))?;
    offset += 1;
    if session_id_length != 32 {
        return Err(invalid_data("REALITY session ID must be 32 bytes"));
    }
    let encrypted_session_id: [u8; 32] = handshake
        .get(offset..offset + 32)
        .ok_or_else(|| invalid_data("truncated REALITY session ID"))?
        .try_into()
        .map_err(|_| invalid_data("invalid REALITY session ID"))?;
    offset += 32;
    let cipher_suites_length = usize::from(read_u16(handshake, offset)?);
    offset = checked_advance(handshake, offset, 2 + cipher_suites_length)?;
    let compression_length = usize::from(
        *handshake
            .get(offset)
            .ok_or_else(|| invalid_data("missing REALITY compression methods"))?,
    );
    offset = checked_advance(handshake, offset + 1, compression_length)?;
    let extensions_length = usize::from(read_u16(handshake, offset)?);
    offset += 2;
    let extensions_end = offset
        .checked_add(extensions_length)
        .ok_or_else(|| invalid_data("REALITY extensions length overflow"))?;
    if extensions_end != handshake.len() {
        return Err(invalid_data("REALITY extensions length mismatch"));
    }

    let mut server_name = None;
    let mut client_public_key = None;
    while offset < extensions_end {
        let extension_type = read_u16(handshake, offset)?;
        let item_length = usize::from(read_u16(handshake, offset + 2)?);
        offset = checked_advance(handshake, offset, 4)?;
        let item_end = offset
            .checked_add(item_length)
            .ok_or_else(|| invalid_data("REALITY extension length overflow"))?;
        if item_end > extensions_end {
            return Err(invalid_data("truncated REALITY extension"));
        }
        let extension = &handshake[offset..item_end];
        match extension_type {
            0 => server_name = Some(parse_server_name(extension)?),
            51 => client_public_key = Some(parse_key_share(extension)?),
            _ => {}
        }
        offset = item_end;
    }
    let client_random = handshake[6..38]
        .try_into()
        .map_err(|_| invalid_data("invalid REALITY client random"))?;
    Ok(ParsedClientHello {
        handshake: handshake.to_vec(),
        client_random,
        encrypted_session_id,
        client_public_key: client_public_key
            .ok_or_else(|| invalid_data("missing REALITY X25519 key share"))?,
        server_name: server_name.ok_or_else(|| invalid_data("missing REALITY SNI"))?,
    })
}

fn checked_advance(packet: &[u8], offset: usize, amount: usize) -> io::Result<usize> {
    let end = offset
        .checked_add(amount)
        .ok_or_else(|| invalid_data("REALITY offset overflow"))?;
    if end > packet.len() {
        return Err(invalid_data("truncated REALITY ClientHello"));
    }
    Ok(end)
}

fn read_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| invalid_data("truncated REALITY field"))
}

#[cfg(any(test, feature = "fuzzing"))]
fn parse_server_name(extension: &[u8]) -> io::Result<String> {
    if extension.len() < 5
        || usize::from(u16::from_be_bytes([extension[0], extension[1]])) != extension.len() - 2
        || extension[2] != 0
    {
        return Err(invalid_data("invalid REALITY SNI extension"));
    }
    let length = usize::from(u16::from_be_bytes([extension[3], extension[4]]));
    if length != extension.len() - 5 {
        return Err(invalid_data("invalid REALITY SNI name length"));
    }
    String::from_utf8(extension[5..].to_vec()).map_err(|_| invalid_data("REALITY SNI is not UTF-8"))
}

#[cfg(any(test, feature = "fuzzing"))]
fn parse_key_share(extension: &[u8]) -> io::Result<[u8; 32]> {
    if extension.len() < 2
        || usize::from(u16::from_be_bytes([extension[0], extension[1]])) != extension.len() - 2
    {
        return Err(invalid_data("invalid REALITY key share list"));
    }
    if extension.len() != 2 + 4 + 32
        || extension[2..4] != X25519_GROUP
        || extension[4..6] != [0, 32]
    {
        return Err(invalid_data("REALITY key share is not X25519"));
    }
    extension[6..]
        .try_into()
        .map_err(|_| invalid_data("invalid REALITY key share"))
}

fn parse_server_hello_record(record: &[u8]) -> io::Result<ParsedServerHello> {
    if record.len() < 5 || record[0] != TLS_HANDSHAKE_RECORD || record[1..3] != TLS_LEGACY_VERSION {
        return Err(invalid_data("invalid REALITY ServerHello record header"));
    }
    let record_length = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record_length != record.len() - 5 {
        return Err(invalid_data("REALITY ServerHello record length mismatch"));
    }
    let handshake = &record[5..];
    if handshake.len() < 4 || handshake[0] != 0x02 {
        return Err(invalid_data("REALITY record does not contain ServerHello"));
    }
    let handshake_length = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    if handshake_length != handshake.len() - 4 {
        return Err(invalid_data("REALITY ServerHello length mismatch"));
    }
    let mut offset = 4;
    offset = checked_advance(handshake, offset, 2 + 32)?;
    let session_id_length = usize::from(
        *handshake
            .get(offset)
            .ok_or_else(|| invalid_data("missing REALITY ServerHello session ID"))?,
    );
    offset = checked_advance(handshake, offset + 1, session_id_length)?;
    let cipher_suite_id = read_u16(handshake, offset)?;
    offset = checked_advance(handshake, offset, 2 + 1)?;
    if handshake[offset - 1] != 0 {
        return Err(invalid_data(
            "REALITY ServerHello selected non-null compression",
        ));
    }
    let extensions_length = usize::from(read_u16(handshake, offset)?);
    offset += 2;
    let extensions_end = offset
        .checked_add(extensions_length)
        .ok_or_else(|| invalid_data("REALITY ServerHello extensions overflow"))?;
    if extensions_end != handshake.len() {
        return Err(invalid_data(
            "REALITY ServerHello extensions length mismatch",
        ));
    }
    let mut supported_tls13 = false;
    let mut server_public_key = None;
    while offset < extensions_end {
        let extension_type = read_u16(handshake, offset)?;
        let item_length = usize::from(read_u16(handshake, offset + 2)?);
        offset = checked_advance(handshake, offset, 4)?;
        let item_end = offset
            .checked_add(item_length)
            .ok_or_else(|| invalid_data("REALITY ServerHello extension overflow"))?;
        if item_end > extensions_end {
            return Err(invalid_data("truncated REALITY ServerHello extension"));
        }
        let extension = &handshake[offset..item_end];
        match extension_type {
            43 if extension == [0x03, 0x04] => supported_tls13 = true,
            51 => server_public_key = Some(parse_server_key_share(extension)?),
            _ => {}
        }
        offset = item_end;
    }
    if !supported_tls13 {
        return Err(invalid_data("REALITY peer did not select TLS 1.3"));
    }
    Ok(ParsedServerHello {
        handshake: handshake.to_vec(),
        server_public_key: server_public_key
            .ok_or_else(|| invalid_data("missing REALITY ServerHello key share"))?,
        cipher_suite: CipherSuite::from_id(cipher_suite_id)?,
    })
}

fn parse_server_key_share(extension: &[u8]) -> io::Result<[u8; 32]> {
    if extension.len() != 4 + 32 || extension[..2] != X25519_GROUP || extension[2..4] != [0, 32] {
        return Err(invalid_data("REALITY ServerHello key share is not X25519"));
    }
    extension[4..]
        .try_into()
        .map_err(|_| invalid_data("invalid REALITY ServerHello key share"))
}

#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_parse_client_hello(record: &[u8]) -> io::Result<()> {
    parse_client_hello_record(record).map(|_| ())
}

#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_parse_server_hello(record: &[u8]) -> io::Result<()> {
    parse_server_hello_record(record).map(|_| ())
}

fn hkdf_extract(algorithm: hmac::Algorithm, salt: &[u8], input: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(algorithm, salt);
    hmac::sign(&key, input).as_ref().to_vec()
}

fn hkdf_expand(
    algorithm: hmac::Algorithm,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> io::Result<Vec<u8>> {
    let hash_len = algorithm.digest_algorithm().output_len();
    let rounds = length.div_ceil(hash_len);
    if rounds > 255 {
        return Err(invalid_input("REALITY HKDF output is too large"));
    }
    let mut output = Vec::with_capacity(rounds * hash_len);
    let mut previous = Vec::new();
    for counter in 1..=rounds {
        let key = hmac::Key::new(algorithm, prk);
        let mut context = hmac::Context::with_key(&key);
        context.update(&previous);
        context.update(info);
        context
            .update(&[u8::try_from(counter)
                .map_err(|_| invalid_input("REALITY HKDF counter overflow"))?]);
        previous = context.sign().as_ref().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(length);
    Ok(output)
}

fn hkdf_expand_label(
    suite: CipherSuite,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> io::Result<Vec<u8>> {
    let full_label = [b"tls13 ", label].concat();
    if full_label.len() > 255 || context.len() > 255 || length > usize::from(u16::MAX) {
        return Err(invalid_input("REALITY HKDF label is too large"));
    }
    let mut info = Vec::with_capacity(4 + full_label.len() + context.len());
    info.extend_from_slice(&u16::try_from(length).unwrap_or_default().to_be_bytes());
    info.push(u8::try_from(full_label.len()).unwrap_or_default());
    info.extend_from_slice(&full_label);
    info.push(u8::try_from(context.len()).unwrap_or_default());
    info.extend_from_slice(context);
    hkdf_expand(suite.hmac_algorithm(), secret, &info, length)
}

fn derive_secret(
    suite: CipherSuite,
    secret: &[u8],
    label: &[u8],
    transcript: &[u8],
) -> io::Result<Vec<u8>> {
    hkdf_expand_label(
        suite,
        secret,
        label,
        &suite.digest(transcript),
        suite.hash_len(),
    )
}

fn derive_traffic_keys(suite: CipherSuite, secret: &[u8]) -> io::Result<(Vec<u8>, [u8; 12])> {
    let key = hkdf_expand_label(suite, secret, b"key", &[], suite.key_len())?;
    let iv = hkdf_expand_label(suite, secret, b"iv", &[], 12)?;
    Ok((
        key,
        iv.try_into()
            .map_err(|_| invalid_data("REALITY IV length mismatch"))?,
    ))
}

fn derive_handshake_secrets(
    suite: CipherSuite,
    shared_secret: &[u8],
    transcript: &[u8],
) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let zeros = vec![0u8; suite.hash_len()];
    let early_secret = hkdf_extract(suite.hmac_algorithm(), &zeros, &zeros);
    let derived = derive_secret(suite, &early_secret, b"derived", &[])?;
    let handshake_secret = hkdf_extract(suite.hmac_algorithm(), &derived, shared_secret);
    let client = derive_secret(suite, &handshake_secret, b"c hs traffic", transcript)?;
    let server = derive_secret(suite, &handshake_secret, b"s hs traffic", transcript)?;
    let derived = derive_secret(suite, &handshake_secret, b"derived", &[])?;
    let master = hkdf_extract(suite.hmac_algorithm(), &derived, &zeros);
    Ok((client, server, master))
}

fn derive_application_secrets(
    suite: CipherSuite,
    master_secret: &[u8],
    transcript: &[u8],
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        derive_secret(suite, master_secret, b"c ap traffic", transcript)?,
        derive_secret(suite, master_secret, b"s ap traffic", transcript)?,
    ))
}

fn finished_verify_data(
    suite: CipherSuite,
    secret: &[u8],
    transcript: &[u8],
) -> io::Result<Vec<u8>> {
    let finished_key = hkdf_expand_label(suite, secret, b"finished", &[], suite.hash_len())?;
    let key = hmac::Key::new(suite.hmac_algorithm(), &finished_key);
    Ok(hmac::sign(&key, &suite.digest(transcript))
        .as_ref()
        .to_vec())
}

fn verify_finished(
    suite: CipherSuite,
    secret: &[u8],
    transcript: &[u8],
    received: &[u8],
) -> io::Result<()> {
    let finished_key = hkdf_expand_label(suite, secret, b"finished", &[], suite.hash_len())?;
    let key = hmac::Key::new(suite.hmac_algorithm(), &finished_key);
    hmac::verify(&key, &suite.digest(transcript), received).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY Finished verification failed",
        )
    })
}

fn nonce_for_sequence(iv: [u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = iv;
    for (index, byte) in sequence.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    nonce
}

fn decrypt_tls_record(
    suite: CipherSuite,
    key: &[u8],
    iv: [u8; 12],
    sequence: u64,
    record_header: [u8; 5],
    ciphertext: &[u8],
) -> io::Result<(u8, Vec<u8>)> {
    let unbound = aead::UnboundKey::new(suite.aead_algorithm(), key)
        .map_err(|_| invalid_data("invalid REALITY traffic key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_for_sequence(iv, sequence));
    let mut plaintext = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            nonce,
            aead::Aad::from(record_header.as_slice()),
            &mut plaintext,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY record authentication failed",
            )
        })?;
    let content_end = plaintext
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or_else(|| invalid_data("REALITY record contains only padding"))?;
    let content_type = plaintext[content_end];
    if !matches!(
        content_type,
        TLS_APPLICATION_RECORD | TLS_HANDSHAKE_RECORD | 0x15
    ) {
        return Err(invalid_data(
            "REALITY record has an invalid inner content type",
        ));
    }
    Ok((content_type, plaintext[..content_end].to_vec()))
}

fn encrypt_tls_record(
    suite: CipherSuite,
    key: &[u8],
    iv: [u8; 12],
    sequence: u64,
    content: &[u8],
    content_type: u8,
) -> io::Result<Vec<u8>> {
    let mut plaintext = Vec::with_capacity(content.len() + 1);
    plaintext.extend_from_slice(content);
    plaintext.push(content_type);
    let record_length = u16::try_from(plaintext.len() + 16)
        .map_err(|_| invalid_input("REALITY application record is too large"))?;
    let record_length_bytes = record_length.to_be_bytes();
    let header = [
        TLS_APPLICATION_RECORD,
        0x03,
        0x03,
        record_length_bytes[0],
        record_length_bytes[1],
    ];
    let unbound = aead::UnboundKey::new(suite.aead_algorithm(), key)
        .map_err(|_| invalid_data("invalid REALITY traffic key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_for_sequence(iv, sequence));
    key.seal_in_place_append_tag(nonce, aead::Aad::from(header.as_slice()), &mut plaintext)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY record encryption failed",
            )
        })?;
    let mut record = Vec::with_capacity(5 + plaintext.len());
    record.extend_from_slice(&header);
    record.extend_from_slice(&plaintext);
    Ok(record)
}

fn read_u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

fn split_handshake_messages(bytes: &[u8]) -> io::Result<Option<Vec<&[u8]>>> {
    let mut offset = 0;
    let mut messages = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Ok(None);
        }
        let length = read_u24(&bytes[offset + 1..offset + 4]);
        let end = offset
            .checked_add(4 + length)
            .ok_or_else(|| invalid_data("REALITY handshake message length overflow"))?;
        if end > bytes.len() {
            return Ok(None);
        }
        messages.push(&bytes[offset..end]);
        offset = end;
    }
    Ok(Some(messages))
}

fn extract_certificate_der(certificate: &[u8]) -> io::Result<&[u8]> {
    if certificate.len() < 8 || certificate[0] != 0x0b {
        return Err(invalid_data("invalid REALITY Certificate message"));
    }
    let message_length = read_u24(&certificate[1..4]);
    if message_length != certificate.len() - 4 {
        return Err(invalid_data("REALITY Certificate length mismatch"));
    }
    let mut offset = 4;
    let context_length = usize::from(certificate[offset]);
    offset = checked_advance(certificate, offset + 1, context_length)?;
    let list_length = read_u24(
        certificate
            .get(offset..offset + 3)
            .ok_or_else(|| invalid_data("truncated REALITY certificate list"))?,
    );
    let list_start = offset + 3;
    let list_end = checked_advance(certificate, list_start, list_length)?;
    let cert_length = read_u24(
        certificate
            .get(list_start..list_start + 3)
            .ok_or_else(|| invalid_data("truncated REALITY certificate entry"))?,
    );
    let cert_start = list_start + 3;
    let cert_end = checked_advance(certificate, cert_start, cert_length)?;
    if cert_end + 2 > list_end {
        return Err(invalid_data(
            "REALITY certificate entry exceeds certificate list",
        ));
    }
    certificate
        .get(cert_start..cert_end)
        .ok_or_else(|| invalid_data("truncated REALITY certificate DER"))
}

fn der_element(input: &[u8]) -> io::Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return Err(invalid_data("truncated REALITY DER element"));
    }
    let tag = input[0];
    let (length, header_length) = if input[1] & 0x80 == 0 {
        (usize::from(input[1]), 2)
    } else {
        let count = usize::from(input[1] & 0x7f);
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err(invalid_data("invalid REALITY DER length"));
        }
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| invalid_data("REALITY DER length overflow"))?;
        }
        (length, 2 + count)
    };
    let end = header_length
        .checked_add(length)
        .ok_or_else(|| invalid_data("REALITY DER element overflow"))?;
    if end > input.len() {
        return Err(invalid_data("truncated REALITY DER element"));
    }
    Ok((tag, &input[header_length..end], &input[end..]))
}

fn certificate_public_key(cert_der: &[u8]) -> io::Result<[u8; 32]> {
    let (outer_tag, outer, _) = der_element(cert_der)?;
    if outer_tag != 0x30 {
        return Err(invalid_data("REALITY certificate is not a sequence"));
    }
    let (tbs_tag, tbs, rest) = der_element(outer)?;
    if tbs_tag != 0x30 {
        return Err(invalid_data(
            "REALITY certificate is missing TBSCertificate",
        ));
    }
    let (signature_tag, _signature, signature_remaining) = der_element(rest)?;
    if signature_tag != 0x30 {
        return Err(invalid_data(
            "REALITY certificate is missing signature algorithm",
        ));
    }
    let (value_tag, value, _) = der_element(signature_remaining)?;
    if value_tag != 0x03 || value.len() != 65 || value[0] != 0 {
        return Err(invalid_data(
            "REALITY certificate signature is not Ed25519-sized",
        ));
    }
    let mut cursor = tbs;
    while !cursor.is_empty() {
        let (tag, content, remaining) = der_element(cursor)?;
        if tag == 0x30 {
            if let Ok((algorithm_tag, _, algorithm_remaining)) = der_element(content) {
                if algorithm_tag == 0x30 {
                    if let Ok((key_tag, key, _)) = der_element(algorithm_remaining) {
                        if key_tag == 0x03 && key.len() == 33 && key[0] == 0 {
                            return key[1..].try_into().map_err(|_| {
                                invalid_data("invalid REALITY certificate public key")
                            });
                        }
                    }
                }
            }
        }
        cursor = remaining;
    }
    Err(invalid_data(
        "REALITY certificate has no Ed25519 public key",
    ))
}

fn verify_certificate_hmac(cert_der: &[u8], auth_key: &[u8; 32]) -> io::Result<[u8; 32]> {
    let public_key = certificate_public_key(cert_der)?;
    let (outer_tag, outer, _) = der_element(cert_der)?;
    if outer_tag != 0x30 {
        return Err(invalid_data("invalid REALITY certificate"));
    }
    let (_, _, rest) = der_element(outer)?;
    let (_, _, rest) = der_element(rest)?;
    let (signature_tag, signature, _) = der_element(rest)?;
    if signature_tag != 0x03 || signature.len() != 65 || signature[0] != 0 {
        return Err(invalid_data("invalid REALITY certificate signature"));
    }
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    hmac::verify(&key, &public_key, &signature[1..]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY certificate HMAC verification failed",
        )
    })?;
    Ok(public_key)
}

fn verify_certificate_verify(
    certificate_verify: &[u8],
    suite: CipherSuite,
    transcript: &[u8],
    public_key: &[u8; 32],
) -> io::Result<()> {
    if certificate_verify.len() < 8
        || certificate_verify[0] != 0x0f
        || read_u24(&certificate_verify[1..4]) != certificate_verify.len() - 4
    {
        return Err(invalid_data("invalid REALITY CertificateVerify message"));
    }
    if certificate_verify[4..6] != [0x08, 0x07] {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "REALITY CertificateVerify is not Ed25519",
        ));
    }
    let signature_length = usize::from(u16::from_be_bytes([
        certificate_verify[6],
        certificate_verify[7],
    ]));
    if signature_length != certificate_verify.len() - 8 {
        return Err(invalid_data("REALITY CertificateVerify length mismatch"));
    }
    let mut signed = vec![0x20; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0);
    signed.extend_from_slice(&suite.digest(transcript));
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&signed, &certificate_verify[8..])
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY CertificateVerify failed",
            )
        })
}

impl RealityStream {
    pub(super) fn connect(
        server: &str,
        port: u16,
        server_name: &str,
        settings: &XrayRealitySettings,
    ) -> io::Result<Self> {
        let stream = connect_tcp(server, port)?;
        let mut reality = Self {
            stream,
            cipher_suite: CipherSuite::Aes128GcmSha256,
            read_key: Vec::new(),
            read_iv: [0; 12],
            write_key: Vec::new(),
            write_iv: [0; 12],
            read_sequence: 0,
            write_sequence: 0,
            ciphertext: Vec::new(),
            plaintext: Vec::new(),
            write_pending: Vec::new(),
            pending_plaintext_len: None,
            nonblocking: false,
        };
        let hello = build_client_hello(settings, server_name)?;
        reality.stream.write_all(&hello.record)?;
        reality.complete_handshake(&hello)?;
        Ok(reality)
    }

    fn read_record(&mut self) -> io::Result<(u8, [u8; 5], Vec<u8>)> {
        loop {
            if self.ciphertext.len() >= 5 {
                let record_length =
                    usize::from(u16::from_be_bytes([self.ciphertext[3], self.ciphertext[4]]));
                if record_length > TLS_MAX_RECORD {
                    return Err(invalid_data("REALITY TLS record is too large"));
                }
                let total_length = 5 + record_length;
                if self.ciphertext.len() >= total_length {
                    let record = self.ciphertext.drain(..total_length).collect::<Vec<_>>();
                    let header: [u8; 5] = record[..5]
                        .try_into()
                        .map_err(|_| invalid_data("invalid REALITY record header"))?;
                    return Ok((header[0], header, record[5..].to_vec()));
                }
            }
            let mut buffer = [0u8; 16 * 1024];
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "REALITY peer closed during TLS record",
                    ));
                }
                Ok(length) => self.ciphertext.extend_from_slice(&buffer[..length]),
                Err(error) => return Err(error),
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn complete_handshake(&mut self, hello: &RealityClientHello) -> io::Result<()> {
        let (_, _, server_hello_record) = self.read_record()?;
        let server_hello_length = u16::try_from(server_hello_record.len())
            .map_err(|_| invalid_data("REALITY ServerHello is too large"))?;
        let mut server_hello_wire = Vec::with_capacity(5 + server_hello_record.len());
        server_hello_wire.extend_from_slice(&[
            TLS_HANDSHAKE_RECORD,
            TLS_LEGACY_VERSION[0],
            TLS_LEGACY_VERSION[1],
            server_hello_length.to_be_bytes()[0],
            server_hello_length.to_be_bytes()[1],
        ]);
        server_hello_wire.extend_from_slice(&server_hello_record);
        let server_hello = parse_server_hello_record(&server_hello_wire)?;
        let client_hello_handshake = hello
            .record
            .get(5..)
            .ok_or_else(|| invalid_data("REALITY ClientHello record is truncated"))?;
        let mut transcript =
            Vec::with_capacity(client_hello_handshake.len() + server_hello.handshake.len());
        transcript.extend_from_slice(client_hello_handshake);
        transcript.extend_from_slice(&server_hello.handshake);
        let client_secret = StaticSecret::from(hello.client_private_key);
        let shared_secret =
            client_secret.diffie_hellman(&PublicKey::from(server_hello.server_public_key));
        if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY server key produced an invalid shared secret",
            ));
        }
        let (client_hs_secret, server_hs_secret, master_secret) = derive_handshake_secrets(
            server_hello.cipher_suite,
            shared_secret.as_bytes(),
            &transcript,
        )?;
        let (server_hs_key, server_hs_iv) =
            derive_traffic_keys(server_hello.cipher_suite, &server_hs_secret)?;
        let (client_hs_key, client_hs_iv) =
            derive_traffic_keys(server_hello.cipher_suite, &client_hs_secret)?;

        let mut encrypted_handshake = Vec::new();
        let mut server_hs_sequence = 0u64;
        loop {
            let (record_type, header, payload) = self.read_record()?;
            if record_type == TLS_CHANGE_CIPHER_SPEC {
                continue;
            }
            if record_type != TLS_APPLICATION_RECORD {
                return Err(invalid_data(
                    "REALITY handshake did not use encrypted records",
                ));
            }
            let (inner_type, plaintext) = decrypt_tls_record(
                server_hello.cipher_suite,
                &server_hs_key,
                server_hs_iv,
                server_hs_sequence,
                header,
                &payload,
            )?;
            server_hs_sequence = server_hs_sequence
                .checked_add(1)
                .ok_or_else(|| invalid_data("REALITY handshake sequence overflow"))?;
            if inner_type != TLS_HANDSHAKE_RECORD {
                return Err(invalid_data(
                    "REALITY peer sent a non-handshake record during handshake",
                ));
            }
            encrypted_handshake.extend_from_slice(&plaintext);
            let Some(messages) = split_handshake_messages(&encrypted_handshake)? else {
                continue;
            };
            if messages.last().is_some_and(|message| message[0] == 0x14) {
                if messages.len() < 4 {
                    return Err(invalid_data("REALITY peer sent an incomplete handshake"));
                }
                let certificate = messages
                    .iter()
                    .find(|message| message[0] == 0x0b)
                    .ok_or_else(|| invalid_data("REALITY peer omitted Certificate"))?;
                let certificate_der = extract_certificate_der(certificate)?;
                let certificate_public_key =
                    verify_certificate_hmac(certificate_der, &hello.auth_key)?;
                let certificate_verify = messages
                    .iter()
                    .find(|message| message[0] == 0x0f)
                    .ok_or_else(|| invalid_data("REALITY peer omitted CertificateVerify"))?;
                let mut certificate_verify_transcript = transcript.clone();
                for message in &messages {
                    if message[0] == 0x0f {
                        break;
                    }
                    certificate_verify_transcript.extend_from_slice(message);
                }
                verify_certificate_verify(
                    certificate_verify,
                    server_hello.cipher_suite,
                    &certificate_verify_transcript,
                    &certificate_public_key,
                )?;
                let finished = messages
                    .last()
                    .ok_or_else(|| invalid_data("REALITY peer omitted Finished"))?;
                if finished.len() < 4 {
                    return Err(invalid_data("REALITY Finished message is truncated"));
                }
                let finished_transcript = [
                    transcript.as_slice(),
                    &encrypted_handshake[..encrypted_handshake.len() - finished.len()],
                ]
                .concat();
                verify_finished(
                    server_hello.cipher_suite,
                    &server_hs_secret,
                    &finished_transcript,
                    &finished[4..],
                )?;
                transcript.extend_from_slice(&encrypted_handshake);
                let client_verify = finished_verify_data(
                    server_hello.cipher_suite,
                    &client_hs_secret,
                    &transcript,
                )?;
                let client_finished = {
                    let mut message = vec![
                        0x14,
                        0,
                        0,
                        u8::try_from(client_verify.len())
                            .map_err(|_| invalid_data("REALITY Finished is too large"))?,
                    ];
                    message.extend_from_slice(&client_verify);
                    message
                };
                let record = encrypt_tls_record(
                    server_hello.cipher_suite,
                    &client_hs_key,
                    client_hs_iv,
                    0,
                    &client_finished,
                    TLS_HANDSHAKE_RECORD,
                )?;
                self.stream.write_all(&record)?;
                let (client_app_secret, server_app_secret) = derive_application_secrets(
                    server_hello.cipher_suite,
                    &master_secret,
                    &transcript,
                )?;
                let (write_key, write_iv) =
                    derive_traffic_keys(server_hello.cipher_suite, &client_app_secret)?;
                let (read_key, read_iv) =
                    derive_traffic_keys(server_hello.cipher_suite, &server_app_secret)?;
                self.cipher_suite = server_hello.cipher_suite;
                self.read_key = read_key;
                self.read_iv = read_iv;
                self.write_key = write_key;
                self.write_iv = write_iv;
                self.read_sequence = 0;
                self.write_sequence = 0;
                self.write_pending.clear();
                self.pending_plaintext_len = None;
                return Ok(());
            }
        }
    }

    pub(super) fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.nonblocking = nonblocking;
        self.stream.set_nonblocking(nonblocking)
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        while !self.write_pending.is_empty() {
            match self.stream.write(&self.write_pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "REALITY stream accepted zero bytes",
                    ));
                }
                Ok(length) => {
                    self.write_pending.drain(..length);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl Read for RealityStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.plaintext.is_empty() {
                let length = buffer.len().min(self.plaintext.len());
                buffer[..length].copy_from_slice(&self.plaintext[..length]);
                self.plaintext.drain(..length);
                return Ok(length);
            }
            let (record_type, header, payload) = self.read_record()?;
            if record_type != TLS_APPLICATION_RECORD {
                continue;
            }
            let (inner_type, plaintext) = decrypt_tls_record(
                self.cipher_suite,
                &self.read_key,
                self.read_iv,
                self.read_sequence,
                header,
                &payload,
            )?;
            self.read_sequence = self
                .read_sequence
                .checked_add(1)
                .ok_or_else(|| invalid_data("REALITY read sequence overflow"))?;
            match inner_type {
                TLS_APPLICATION_RECORD => self.plaintext.extend_from_slice(&plaintext),
                0x15 => return Ok(0),
                _ => return Err(invalid_data("unexpected REALITY post-handshake record")),
            }
        }
    }
}

impl Write for RealityStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if let Some(length) = self.pending_plaintext_len {
            self.flush_pending()?;
            if self.write_pending.is_empty() {
                self.pending_plaintext_len = None;
                return Ok(length);
            }
        }
        self.flush_pending()?;
        let length = buffer.len().min(16 * 1024);
        let record = encrypt_tls_record(
            self.cipher_suite,
            &self.write_key,
            self.write_iv,
            self.write_sequence,
            &buffer[..length],
            TLS_APPLICATION_RECORD,
        )?;
        self.write_pending.extend_from_slice(&record);
        self.pending_plaintext_len = Some(length);
        self.write_sequence = self
            .write_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_data("REALITY write sequence overflow"))?;
        self.flush_pending()?;
        self.pending_plaintext_len = None;
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()?;
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use ring::hmac;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{
        build_client_hello_with_material, decrypt_session_id, derive_application_secrets,
        derive_auth_key, derive_handshake_secrets, derive_traffic_keys, encrypt_tls_record,
        finished_verify_data, parse_client_hello_record, parse_server_hello_record,
        TLS_APPLICATION_RECORD, TLS_HANDSHAKE_RECORD,
    };
    use crate::xray::XrayRealitySettings;

    #[test]
    fn reality_client_hello_contains_authenticated_session_metadata() {
        let server_secret = StaticSecret::from([3u8; 32]);
        let server_public_key = PublicKey::from(&server_secret).to_bytes();
        let settings = XrayRealitySettings {
            public_key: server_public_key,
            short_id: vec![0x01, 0x23, 0x45, 0x67],
            fingerprint: "chrome".to_owned(),
            spider_x: "/".to_owned(),
            server_name: Some("www.example.com".to_owned()),
        };
        let client_random = [7u8; 32];
        let client_secret = [9u8; 32];
        let hello = build_client_hello_with_material(
            &settings,
            "www.example.com",
            client_random,
            client_secret,
            1_725_000_000,
        )
        .unwrap();
        let parsed = parse_client_hello_record(&hello.record).unwrap();

        assert_eq!(parsed.client_random, client_random);
        assert_eq!(parsed.server_name, "www.example.com");
        assert_eq!(
            parsed.client_public_key,
            PublicKey::from(&client_secret_for_test(&client_secret)).to_bytes()
        );

        let shared_secret = client_secret_for_test(&client_secret)
            .diffie_hellman(&server_public_key_for_test(&server_public_key));
        let auth_key = derive_auth_key(shared_secret.as_bytes(), &client_random);
        let mut aad = parsed.handshake.clone();
        aad[39..71].fill(0);
        let session_id = decrypt_session_id(
            &parsed.encrypted_session_id,
            &auth_key,
            &client_random[20..],
            &aad,
        )
        .unwrap();

        assert_eq!(&session_id[..3], &[1, 8, 0]);
        assert_eq!(&session_id[4..8], &1_725_000_000u32.to_be_bytes());
        assert_eq!(&session_id[8..12], &[0x01, 0x23, 0x45, 0x67]);
        assert!(session_id[12..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn reality_client_hello_rejects_invalid_record_shapes() {
        assert!(parse_client_hello_record(&[0x16, 0x03, 0x01, 0, 1]).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reality_stream_completes_a_local_encrypted_handshake() {
        let auth_secret = StaticSecret::from([3u8; 32]);
        let auth_public_key = PublicKey::from(&auth_secret).to_bytes();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let client_record = read_record_for_test(&mut stream);
            let client = parse_client_hello_record(&client_record).unwrap();
            let client_public_key = PublicKey::from(client.client_public_key);
            let auth_shared_secret = auth_secret.diffie_hellman(&client_public_key);
            let auth_key = derive_auth_key(auth_shared_secret.as_bytes(), &client.client_random);

            let tls_secret = StaticSecret::from([4u8; 32]);
            let tls_public_key = PublicKey::from(&tls_secret).to_bytes();
            let tls_shared_secret = tls_secret.diffie_hellman(&client_public_key);
            let server_random = [8u8; 32];
            let server_record = build_server_hello_record(
                server_random,
                &client.encrypted_session_id,
                tls_public_key,
            );
            let server = parse_server_hello_record(&server_record).unwrap();
            let transcript = [client.handshake.as_slice(), server.handshake.as_slice()].concat();
            let (_, server_hs_secret, master_secret) = derive_handshake_secrets(
                server.cipher_suite,
                tls_shared_secret.as_bytes(),
                &transcript,
            )
            .unwrap();
            let (server_hs_key, server_hs_iv) =
                derive_traffic_keys(server.cipher_suite, &server_hs_secret).unwrap();

            let signing_key = Ed25519KeyPair::from_seed_unchecked(&[5u8; 32]).unwrap();
            let certificate = build_fake_certificate(&signing_key, &auth_key);
            let encrypted_extensions = handshake_message(0x08, &[0, 0]);
            let certificate_message = build_certificate_message(&certificate);
            let certificate_transcript = [
                transcript.as_slice(),
                encrypted_extensions.as_slice(),
                certificate_message.as_slice(),
            ]
            .concat();
            let mut signed_content = vec![0x20; 64];
            signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
            signed_content.push(0);
            signed_content.extend_from_slice(&server.cipher_suite.digest(&certificate_transcript));
            let signature = signing_key.sign(&signed_content);
            let mut certificate_verify_body = vec![0x08, 0x07];
            certificate_verify_body.extend_from_slice(
                &u16::try_from(signature.as_ref().len())
                    .unwrap()
                    .to_be_bytes(),
            );
            certificate_verify_body.extend_from_slice(signature.as_ref());
            let certificate_verify = handshake_message(0x0f, &certificate_verify_body);
            let finished_transcript = [
                certificate_transcript.as_slice(),
                certificate_verify.as_slice(),
            ]
            .concat();
            let finished_verify =
                finished_verify_data(server.cipher_suite, &server_hs_secret, &finished_transcript)
                    .unwrap();
            let finished = handshake_message(0x14, &finished_verify);
            let encrypted_handshake = [
                encrypted_extensions.as_slice(),
                certificate_message.as_slice(),
                certificate_verify.as_slice(),
                finished.as_slice(),
            ]
            .concat();
            let encrypted_handshake_record = encrypt_tls_record(
                server.cipher_suite,
                &server_hs_key,
                server_hs_iv,
                0,
                &encrypted_handshake,
                TLS_HANDSHAKE_RECORD,
            )
            .unwrap();
            stream.write_all(&server_record).unwrap();
            stream.write_all(&encrypted_handshake_record).unwrap();

            let application_transcript =
                [transcript.as_slice(), encrypted_handshake.as_slice()].concat();
            let (_, server_app_secret) = derive_application_secrets(
                server.cipher_suite,
                &master_secret,
                &application_transcript,
            )
            .unwrap();
            let (server_app_key, server_app_iv) =
                derive_traffic_keys(server.cipher_suite, &server_app_secret).unwrap();
            let application_record = encrypt_tls_record(
                server.cipher_suite,
                &server_app_key,
                server_app_iv,
                0,
                b"pong",
                TLS_APPLICATION_RECORD,
            )
            .unwrap();
            stream.write_all(&application_record).unwrap();
        });

        let settings = XrayRealitySettings {
            public_key: auth_public_key,
            short_id: vec![0x01, 0x23, 0x45, 0x67],
            fingerprint: "chrome".to_owned(),
            spider_x: "/".to_owned(),
            server_name: Some("www.example.com".to_owned()),
        };
        let mut stream = super::RealityStream::connect(
            &address.ip().to_string(),
            address.port(),
            "www.example.com",
            &settings,
        )
        .unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        server_thread.join().unwrap();
    }

    fn read_record_for_test(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).unwrap();
        let mut record = header.to_vec();
        let mut payload = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        stream.read_exact(&mut payload).unwrap();
        record.extend_from_slice(&payload);
        record
    }

    fn build_server_hello_record(
        random: [u8; 32],
        session_id: &[u8; 32],
        public_key: [u8; 32],
    ) -> Vec<u8> {
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
        extensions.extend_from_slice(&public_key);
        let mut payload = vec![0x03, 0x03];
        payload.extend_from_slice(&random);
        payload.push(32);
        payload.extend_from_slice(session_id);
        payload.extend_from_slice(&[0x13, 0x01, 0x00]);
        payload.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(&extensions);
        let handshake = handshake_message(0x02, &payload);
        let mut record = vec![TLS_HANDSHAKE_RECORD, 0x03, 0x01];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn handshake_message(message_type: u8, body: &[u8]) -> Vec<u8> {
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut message = vec![message_type, length[1], length[2], length[3]];
        message.extend_from_slice(body);
        message
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128);
        let mut result = vec![tag, u8::try_from(content.len()).unwrap()];
        result.extend_from_slice(content);
        result
    }

    fn build_fake_certificate(key_pair: &Ed25519KeyPair, auth_key: &[u8; 32]) -> Vec<u8> {
        let algorithm = der(0x30, &[]);
        let mut public_key_bit_string = vec![0];
        public_key_bit_string.extend_from_slice(key_pair.public_key().as_ref());
        let public_key_bit_string = der(0x03, &public_key_bit_string);
        let spki = der(0x30, &[algorithm, public_key_bit_string].concat());
        let tbs = der(0x30, &spki);
        let signature_algorithm = der(0x30, &[]);
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA512, auth_key),
            key_pair.public_key().as_ref(),
        );
        let mut signature_bit_string = vec![0];
        signature_bit_string.extend_from_slice(signature.as_ref());
        let signature_bit_string = der(0x03, &signature_bit_string);
        der(
            0x30,
            &[tbs, signature_algorithm, signature_bit_string].concat(),
        )
    }

    fn build_certificate_message(certificate: &[u8]) -> Vec<u8> {
        let mut entry = Vec::with_capacity(3 + certificate.len() + 2);
        let length = u32::try_from(certificate.len()).unwrap().to_be_bytes();
        entry.extend_from_slice(&length[1..]);
        entry.extend_from_slice(certificate);
        entry.extend_from_slice(&[0, 0]);
        let list_length = u32::try_from(entry.len()).unwrap().to_be_bytes();
        let mut body = vec![0];
        body.extend_from_slice(&list_length[1..]);
        body.extend_from_slice(&entry);
        handshake_message(0x0b, &body)
    }

    fn client_secret_for_test(bytes: &[u8; 32]) -> StaticSecret {
        StaticSecret::from(*bytes)
    }

    fn server_public_key_for_test(bytes: &[u8; 32]) -> PublicKey {
        PublicKey::from(*bytes)
    }
}
