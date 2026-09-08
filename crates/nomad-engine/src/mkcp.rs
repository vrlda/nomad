use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::aead::{self, Aad, LessSafeKey, UnboundKey, AES_128_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

use super::XrayMkcpSettings;

const DATA_HEADER_LEN: usize = 18;
const ACK_HEADER_LEN: usize = 17;
const COMMAND_LEN: usize = 16;
const MAX_ACK_NUMBERS: usize = 128;
const RECEIVE_WINDOW: u32 = 128;
const MAX_RETRANSMITS: u8 = 20;

/// mKCP datagram security. Xray seals every UDP datagram (the concatenation
/// of one or more KCP segments) with either its legacy `SimpleAuthenticator`
/// (default) or an AES-128-GCM derived from `kcpSettings.seed`.
enum MkcpSecurity {
    Simple,
    Aes128Gcm { key: [u8; 16] },
}

impl MkcpSecurity {
    fn from_settings(settings: &XrayMkcpSettings) -> Self {
        match settings.seed.as_deref() {
            Some(seed) => {
                let digest = Sha256::digest(seed.as_bytes());
                let mut key = [0u8; 16];
                key.copy_from_slice(&digest[..16]);
                MkcpSecurity::Aes128Gcm { key }
            }
            None => MkcpSecurity::Simple,
        }
    }

    fn seal(&self, segments: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            MkcpSecurity::Simple => Ok(simple_authenticator_seal(segments)),
            MkcpSecurity::Aes128Gcm { key } => {
                let unbound = UnboundKey::new(&AES_128_GCM, key)
                    .map_err(|_| invalid_data("invalid mKCP seed key"))?;
                let key = LessSafeKey::new(unbound);
                let mut nonce = [0u8; NONCE_LEN];
                SystemRandom::new()
                    .fill(&mut nonce)
                    .map_err(|_| io::Error::other("failed to generate mKCP nonce"))?;
                let mut output = segments.to_vec();
                key.seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    &mut output,
                )
                .map_err(|_| io::Error::other("mKCP seed sealing failed"))?;
                let mut datagram = Vec::with_capacity(nonce.len() + output.len());
                datagram.extend_from_slice(&nonce);
                datagram.extend_from_slice(&output);
                Ok(datagram)
            }
        }
    }

    fn open(&self, datagram: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            MkcpSecurity::Simple => simple_authenticator_open(datagram),
            MkcpSecurity::Aes128Gcm { key } => {
                if datagram.len() < NONCE_LEN {
                    return Err(invalid_data("truncated mKCP seed datagram"));
                }
                let unbound = UnboundKey::new(&AES_128_GCM, key)
                    .map_err(|_| invalid_data("invalid mKCP seed key"))?;
                let key = LessSafeKey::new(unbound);
                let (nonce, ciphertext) = datagram.split_at(NONCE_LEN);
                let mut output = ciphertext.to_vec();
                let plaintext = key
                    .open_in_place(
                        aead::Nonce::try_assume_unique_for_key(nonce)
                            .map_err(|_| invalid_data("invalid mKCP seed nonce"))?,
                        Aad::empty(),
                        &mut output,
                    )
                    .map_err(|_| invalid_data("mKCP seed authentication failed"))?;
                Ok(plaintext.to_vec())
            }
        }
    }
}

/// Xray's legacy mKCP `SimpleAuthenticator`: a 4-byte FNV-1a hash over the
/// length-prefixed payload, followed by a forward word-wise XOR transform.
fn fnv1a32(value: &[u8]) -> u32 {
    value.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn xorfwd(x: &mut [u8]) {
    for i in 4..x.len() {
        x[i] ^= x[i - 4];
    }
}

fn xorbkd(x: &mut [u8]) {
    for i in (4..x.len()).rev() {
        x[i] ^= x[i - 4];
    }
}

fn simple_authenticator_seal(plain: &[u8]) -> Vec<u8> {
    let mut dst = vec![0u8; 6 + plain.len()];
    dst[4..6].copy_from_slice(&u16::try_from(plain.len()).unwrap_or(u16::MAX).to_be_bytes());
    dst[6..].copy_from_slice(plain);
    let expected_hash = fnv1a32(&dst[4..]);
    dst[0..4].copy_from_slice(&expected_hash.to_be_bytes());
    let dst_len = dst.len();
    let extra = (4 - dst_len % 4) % 4;
    if extra != 0 {
        dst.resize(dst_len + extra, 0);
    }
    xorfwd(&mut dst);
    dst.truncate(dst_len);
    dst
}

fn simple_authenticator_open(cipher: &[u8]) -> io::Result<Vec<u8>> {
    let mut dst = cipher.to_vec();
    let dst_len = dst.len();
    let extra = (4 - dst_len % 4) % 4;
    if extra != 0 {
        dst.resize(dst_len + extra, 0);
    }
    xorbkd(&mut dst);
    dst.truncate(dst_len);
    if dst.len() < 6 {
        return Err(invalid_data("truncated mKCP authenticated datagram"));
    }
    if dst[0..4] != fnv1a32(&dst[4..]).to_be_bytes() {
        return Err(invalid_data("mKCP datagram authentication failed"));
    }
    let length = usize::from(u16::from_be_bytes([dst[4], dst[5]]));
    if dst.len() - 6 != length {
        return Err(invalid_data("mKCP datagram length mismatch"));
    }
    Ok(dst[6..].to_vec())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MkcpSegment {
    Data {
        conv: u16,
        option: u8,
        timestamp: u32,
        number: u32,
        sending_next: u32,
        payload: Vec<u8>,
    },
    Ack {
        conv: u16,
        option: u8,
        receiving_window: u32,
        receiving_next: u32,
        timestamp: u32,
        numbers: Vec<u32>,
    },
    Command {
        conv: u16,
        command: u8,
        option: u8,
        sending_next: u32,
        receiving_next: u32,
        peer_rto: u32,
    },
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn encode_data(
    conv: u16,
    timestamp: u32,
    number: u32,
    sending_next: u32,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mKCP payload is too large"))?;
    let mut packet = Vec::with_capacity(DATA_HEADER_LEN + payload.len());
    packet.extend_from_slice(&conv.to_be_bytes());
    packet.extend_from_slice(&[1, 0]);
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&number.to_be_bytes());
    packet.extend_from_slice(&sending_next.to_be_bytes());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn encode_ack(
    conv: u16,
    receiving_window: u32,
    receiving_next: u32,
    timestamp: u32,
    numbers: &[(u32, u32)],
) -> io::Result<Vec<u8>> {
    if numbers.len() > MAX_ACK_NUMBERS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mKCP ACK contains too many sequence numbers",
        ));
    }
    let mut packet = Vec::with_capacity(ACK_HEADER_LEN + numbers.len() * 4);
    packet.extend_from_slice(&conv.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&receiving_window.to_be_bytes());
    packet.extend_from_slice(&receiving_next.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.push(
        u8::try_from(numbers.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mKCP ACK count overflow"))?,
    );
    for &(number, _) in numbers {
        packet.extend_from_slice(&number.to_be_bytes());
    }
    Ok(packet)
}

#[cfg(test)]
fn encode_command(
    conv: u16,
    command: u8,
    option: u8,
    sending_next: u32,
    receiving_next: u32,
    peer_rto: u32,
) -> io::Result<Vec<u8>> {
    if !matches!(command, 2 | 3) {
        return Err(invalid_data("invalid mKCP command"));
    }
    let mut packet = Vec::with_capacity(COMMAND_LEN);
    packet.extend_from_slice(&conv.to_be_bytes());
    packet.extend_from_slice(&[command, option]);
    packet.extend_from_slice(&sending_next.to_be_bytes());
    packet.extend_from_slice(&receiving_next.to_be_bytes());
    packet.extend_from_slice(&peer_rto.to_be_bytes());
    Ok(packet)
}

fn read_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| invalid_data("truncated mKCP segment"))
}

fn read_u32(packet: &[u8], offset: usize) -> io::Result<u32> {
    packet
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| invalid_data("truncated mKCP segment"))
}

fn decode_segments(mut packet: &[u8]) -> io::Result<Vec<MkcpSegment>> {
    let mut segments = Vec::new();
    while !packet.is_empty() {
        if packet.len() < 4 {
            return Err(invalid_data("truncated mKCP segment header"));
        }
        let conv = read_u16(packet, 0)?;
        let command = packet[2];
        let option = packet[3];
        match command {
            0 => {
                if packet.len() < ACK_HEADER_LEN {
                    return Err(invalid_data("truncated mKCP ACK segment"));
                }
                let count = usize::from(packet[16]);
                if count > MAX_ACK_NUMBERS {
                    return Err(invalid_data("mKCP ACK contains too many sequence numbers"));
                }
                let length = ACK_HEADER_LEN + count * 4;
                if packet.len() < length {
                    return Err(invalid_data("truncated mKCP ACK numbers"));
                }
                let mut numbers = Vec::with_capacity(count);
                for index in 0..count {
                    numbers.push(read_u32(packet, ACK_HEADER_LEN + index * 4)?);
                }
                segments.push(MkcpSegment::Ack {
                    conv,
                    option,
                    receiving_window: read_u32(packet, 4)?,
                    receiving_next: read_u32(packet, 8)?,
                    timestamp: read_u32(packet, 12)?,
                    numbers,
                });
                packet = &packet[length..];
            }
            1 => {
                if packet.len() < DATA_HEADER_LEN {
                    return Err(invalid_data("truncated mKCP data segment"));
                }
                let payload_length = usize::from(read_u16(packet, 16)?);
                let length = DATA_HEADER_LEN
                    .checked_add(payload_length)
                    .ok_or_else(|| invalid_data("mKCP payload length overflow"))?;
                if packet.len() < length {
                    return Err(invalid_data("truncated mKCP data payload"));
                }
                segments.push(MkcpSegment::Data {
                    conv,
                    option,
                    timestamp: read_u32(packet, 4)?,
                    number: read_u32(packet, 8)?,
                    sending_next: read_u32(packet, 12)?,
                    payload: packet[DATA_HEADER_LEN..length].to_vec(),
                });
                packet = &packet[length..];
            }
            2 | 3 => {
                if packet.len() < COMMAND_LEN {
                    return Err(invalid_data("truncated mKCP command segment"));
                }
                segments.push(MkcpSegment::Command {
                    conv,
                    command,
                    option,
                    sending_next: read_u32(packet, 4)?,
                    receiving_next: read_u32(packet, 8)?,
                    peer_rto: read_u32(packet, 12)?,
                });
                packet = &packet[COMMAND_LEN..];
            }
            _ => return Err(invalid_data("unknown mKCP segment command")),
        }
    }
    Ok(segments)
}

enum MkcpEvent {
    Data(Vec<u8>),
    Closed,
    Error(String),
}

struct PendingSegment {
    packet: Vec<u8>,
    last_sent: Instant,
    retransmits: u8,
}

struct MkcpSession {
    socket: UdpSocket,
    conv: u16,
    settings: XrayMkcpSettings,
    security: MkcpSecurity,
    next_send: u32,
    next_receive: u32,
    remote_window: u32,
    outstanding: BTreeMap<u32, PendingSegment>,
    queued: VecDeque<Vec<u8>>,
    received: BTreeMap<u32, Vec<u8>>,
    ack_numbers: Vec<(u32, u32)>,
    last_ack: Instant,
    events: SyncSender<MkcpEvent>,
}

impl MkcpSession {
    fn max_payload(&self) -> usize {
        usize::from(self.settings.mtu).saturating_sub(DATA_HEADER_LEN)
    }

    fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        let datagram = self.security.seal(packet)?;
        self.socket.send(&datagram).map(|_| ())
    }

    fn timestamp() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                u32::try_from(duration.as_millis() % (u128::from(u32::MAX) + 1)).unwrap_or_default()
            })
            .unwrap_or_default()
    }

    fn send_ack(&mut self) -> io::Result<()> {
        if self.ack_numbers.is_empty() {
            return Ok(());
        }
        let timestamp = Self::timestamp();
        for numbers in self.ack_numbers.chunks(MAX_ACK_NUMBERS) {
            let packet = encode_ack(
                self.conv,
                self.next_receive.saturating_add(RECEIVE_WINDOW),
                self.next_receive,
                timestamp,
                numbers,
            )?;
            self.send_packet(&packet)?;
        }
        self.ack_numbers.clear();
        self.last_ack = Instant::now();
        Ok(())
    }

    fn queue_command(&mut self, payload: Vec<u8>) {
        if !payload.is_empty() {
            self.queued.push_back(payload);
        }
    }

    fn send_queued(&mut self) -> io::Result<()> {
        let capacity = usize::try_from(self.settings.uplink_capacity.max(1))
            .unwrap_or(usize::MAX)
            .saturating_mul(2)
            .clamp(1, 64);
        let window = capacity.min(usize::try_from(self.remote_window.max(1)).unwrap_or(64));
        while self.outstanding.len() < window {
            let Some(mut payload) = self.queued.pop_front() else {
                break;
            };
            let length = payload.len().min(self.max_payload());
            let remainder = payload.split_off(length);
            if !remainder.is_empty() {
                self.queued.push_front(remainder);
            }
            let number = self.next_send;
            self.next_send = self.next_send.wrapping_add(1);
            let packet = encode_data(
                self.conv,
                Self::timestamp(),
                number,
                self.next_receive,
                &payload,
            )?;
            self.send_packet(&packet)?;
            self.outstanding.insert(
                number,
                PendingSegment {
                    packet,
                    last_sent: Instant::now(),
                    retransmits: 0,
                },
            );
        }
        Ok(())
    }

    fn handle_data(&mut self, number: u32, sending_next: u32, payload: Vec<u8>) -> io::Result<()> {
        self.remote_window = self.remote_window.max(1);
        if number >= self.next_receive
            && number.wrapping_sub(self.next_receive) < RECEIVE_WINDOW
            && !self.received.contains_key(&number)
        {
            self.received.insert(number, payload);
        }
        self.ack_numbers.push((number, sending_next));
        while let Some(payload) = self.received.remove(&self.next_receive) {
            self.next_receive = self.next_receive.wrapping_add(1);
            self.events
                .send(MkcpEvent::Data(payload))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mKCP reader closed"))?;
        }
        Ok(())
    }

    fn handle_segment(&mut self, segment: MkcpSegment) -> io::Result<()> {
        match segment {
            MkcpSegment::Data {
                conv,
                number,
                sending_next,
                payload,
                ..
            } if conv == self.conv => self.handle_data(number, sending_next, payload),
            MkcpSegment::Ack {
                conv,
                receiving_window,
                numbers,
                ..
            } if conv == self.conv => {
                self.remote_window = receiving_window.max(1);
                for number in numbers {
                    self.outstanding.remove(&number);
                }
                Ok(())
            }
            MkcpSegment::Command {
                conv,
                receiving_next,
                ..
            } if conv == self.conv => {
                self.remote_window = RECEIVE_WINDOW;
                for number in self
                    .outstanding
                    .keys()
                    .copied()
                    .filter(|number| *number < receiving_next)
                    .collect::<Vec<_>>()
                {
                    self.outstanding.remove(&number);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn retransmit(&mut self) -> io::Result<()> {
        let now = Instant::now();
        let rto = Duration::from_millis(200);
        let mut expired = Vec::new();
        for (&number, pending) in &mut self.outstanding {
            if now.duration_since(pending.last_sent) >= rto {
                if pending.retransmits >= MAX_RETRANSMITS {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "mKCP retransmission limit exceeded",
                    ));
                }
                pending.last_sent = now;
                pending.retransmits = pending.retransmits.saturating_add(1);
                expired.push((number, pending.packet.clone()));
            }
        }
        for (_, packet) in expired {
            self.send_packet(&packet)?;
        }
        Ok(())
    }

    fn run(mut self, commands: &Receiver<Vec<u8>>, startup: &SyncSender<io::Result<()>>) {
        let _ = startup.send(Ok(()));
        let poll_interval = Duration::from_millis(u64::from(self.settings.tti).clamp(10, 100));
        let mut buffer = vec![0u8; usize::from(self.settings.mtu).max(2048)];
        loop {
            loop {
                match commands.try_recv() {
                    Ok(payload) => self.queue_command(payload),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        let _ = self.events.send(MkcpEvent::Closed);
                        return;
                    }
                }
            }
            if let Err(error) = self.send_queued().and_then(|()| self.retransmit()) {
                let _ = self.events.send(MkcpEvent::Error(error.to_string()));
                return;
            }
            match self.socket.recv(&mut buffer) {
                Ok(length) => {
                    let opened = match self.security.open(&buffer[..length]) {
                        Ok(segments) => segments,
                        Err(error) => {
                            let _ = self.events.send(MkcpEvent::Error(error.to_string()));
                            return;
                        }
                    };
                    match decode_segments(&opened) {
                        Ok(segments) => {
                            for segment in segments {
                                if let Err(error) = self.handle_segment(segment) {
                                    let _ = self.events.send(MkcpEvent::Error(error.to_string()));
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            let _ = self.events.send(MkcpEvent::Error(error.to_string()));
                            return;
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => {
                    let _ = self.events.send(MkcpEvent::Error(error.to_string()));
                    return;
                }
            }
            if self.last_ack.elapsed() >= poll_interval {
                if let Err(error) = self.send_ack() {
                    let _ = self.events.send(MkcpEvent::Error(error.to_string()));
                    return;
                }
            }
        }
    }
}

pub(super) struct MkcpStream {
    commands: SyncSender<Vec<u8>>,
    events: Receiver<MkcpEvent>,
    plaintext: Vec<u8>,
    nonblocking: bool,
}

impl std::fmt::Debug for MkcpStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MkcpStream")
    }
}

impl MkcpStream {
    pub(super) fn connect(
        server: &str,
        port: u16,
        settings: &XrayMkcpSettings,
    ) -> io::Result<Self> {
        if let Some(header_type) = settings.header_type.as_deref() {
            if header_type != "none" {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "mKCP disguise header {header_type:?} is not implemented by the embedded core"
                    ),
                ));
            }
        }
        let address = (server, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "mKCP server has no address"))?;
        let bind_address = match address {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_address)?;
        socket.connect(address)?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        let mut conversation = [0u8; 2];
        SystemRandom::new()
            .fill(&mut conversation)
            .map_err(|_| io::Error::other("failed to generate mKCP conversation id"))?;
        let conv = u16::from_be_bytes(conversation).max(1);
        let (commands, command_rx) = mpsc::sync_channel(32);
        let (events_tx, events) = mpsc::sync_channel(32);
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let session = MkcpSession {
            socket,
            conv,
            settings: settings.clone(),
            security: MkcpSecurity::from_settings(settings),
            next_send: 0,
            next_receive: 0,
            remote_window: RECEIVE_WINDOW,
            outstanding: BTreeMap::new(),
            queued: VecDeque::new(),
            received: BTreeMap::new(),
            ack_numbers: Vec::new(),
            last_ack: Instant::now(),
            events: events_tx,
        };
        thread::Builder::new()
            .name("nomad-mkcp".to_owned())
            .spawn(move || session.run(&command_rx, &startup_tx))
            .map_err(|error| io::Error::other(format!("failed to start mKCP worker: {error}")))?;
        startup_rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mKCP worker stopped"))??;
        Ok(Self {
            commands,
            events,
            plaintext: Vec::new(),
            nonblocking: false,
        })
    }

    pub(super) fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }
}

impl Read for MkcpStream {
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
            let event = if self.nonblocking {
                match self.events.try_recv() {
                    Ok(event) => event,
                    Err(TryRecvError::Empty) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "mKCP read pending",
                        ));
                    }
                    Err(TryRecvError::Disconnected) => return Ok(0),
                }
            } else {
                self.events.recv().map_err(|_| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "mKCP worker stopped")
                })?
            };
            match event {
                MkcpEvent::Data(payload) => self.plaintext.extend_from_slice(&payload),
                MkcpEvent::Closed => return Ok(0),
                MkcpEvent::Error(message) => return Err(io::Error::other(message)),
            }
        }
    }
}

impl Write for MkcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let payload = buffer.to_vec();
        if self.nonblocking {
            match self.commands.try_send(payload) {
                Ok(()) => Ok(buffer.len()),
                Err(TrySendError::Full(_)) => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mKCP write queue is full",
                )),
                Err(TrySendError::Disconnected(_)) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mKCP worker stopped",
                )),
            }
        } else {
            self.commands
                .send(payload)
                .map(|()| buffer.len())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mKCP worker stopped"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    use super::{decode_segments, encode_ack, encode_command, encode_data, MkcpSegment};
    use super::{MkcpSecurity, MkcpStream, XrayMkcpSettings};

    #[test]
    fn test_mkcp_data_segment_matches_xray_wire_shape() {
        let packet = encode_data(0x1234, 7, 11, 13, b"hi").unwrap();

        assert_eq!(
            packet,
            vec![0x12, 0x34, 0x01, 0x00, 0, 0, 0, 7, 0, 0, 0, 11, 0, 0, 0, 13, 0, 2, b'h', b'i']
        );
        assert_eq!(
            decode_segments(&packet).unwrap(),
            vec![MkcpSegment::Data {
                conv: 0x1234,
                option: 0,
                timestamp: 7,
                number: 11,
                sending_next: 13,
                payload: b"hi".to_vec(),
            }]
        );
    }

    #[test]
    fn test_mkcp_ack_and_command_segments_round_trip() {
        let mut packet = encode_ack(0x1234, 128, 4, 21, &[(8, 20), (9, 21)]).unwrap();
        packet.extend_from_slice(&encode_command(0x1234, 3, 0, 4, 21, 200).unwrap());

        assert_eq!(
            decode_segments(&packet).unwrap(),
            vec![
                MkcpSegment::Ack {
                    conv: 0x1234,
                    option: 0,
                    receiving_window: 128,
                    receiving_next: 4,
                    timestamp: 21,
                    numbers: vec![8, 9],
                },
                MkcpSegment::Command {
                    conv: 0x1234,
                    command: 3,
                    option: 0,
                    sending_next: 4,
                    receiving_next: 21,
                    peer_rto: 200,
                },
            ]
        );
    }

    #[test]
    fn test_mkcp_decoder_rejects_truncated_or_oversized_segments() {
        assert!(decode_segments(&[0, 1, 1, 0]).is_err());

        let mut packet = encode_data(1, 0, 0, 0, b"payload").unwrap();
        packet[16..18].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode_segments(&packet).is_err());
    }

    #[test]
    fn test_mkcp_simple_authenticator_matches_xray_algorithm() {
        // Xray's SimpleAuthenticator: 4-byte FNV-1a hash, 2-byte length, payload,
        // padded to a 4-byte boundary, then word-wise forward XOR.
        let plain = b"hello";
        let sealed = MkcpSecurity::Simple.seal(plain).unwrap();
        // 6 + 5 = 11 bytes; padded to 12 during the transform, then stripped back.
        assert_eq!(sealed.len(), 11);
        assert_eq!(MkcpSecurity::Simple.open(&sealed).unwrap(), plain.to_vec());

        // Deterministic known vector: hash covers the length-prefixed payload and
        // the XOR transform starts at the fourth byte.
        let expected_hash = {
            let mut body = Vec::with_capacity(2 + plain.len());
            body.extend_from_slice(
                &u16::try_from(plain.len())
                    .expect("test payload fits u16")
                    .to_be_bytes(),
            );
            body.extend_from_slice(plain);
            let mut h = 0x811c_9dc5u32;
            for byte in &body {
                h = (h ^ u32::from(*byte)).wrapping_mul(0x0100_0193);
            }
            h
        };
        assert_eq!(
            u32::from_be_bytes([sealed[0], sealed[1], sealed[2], sealed[3]]),
            expected_hash
        );
        // Tampering with any byte must fail authentication (with high probability).
        let mut tampered = sealed.clone();
        tampered[0] ^= 0x01;
        assert!(MkcpSecurity::Simple.open(&tampered).is_err());
    }

    #[test]
    fn test_mkcp_seed_security_derives_aes_gcm_from_seed() {
        let settings = XrayMkcpSettings {
            seed: Some("nomad-seed".to_owned()),
            ..XrayMkcpSettings::default()
        };
        let security = MkcpSecurity::from_settings(&settings);
        let plain = b"segments";
        let sealed = security.seal(plain).unwrap();
        // 12-byte random nonce plus AES-128-GCM tag.
        assert_eq!(sealed.len(), plain.len() + 12 + 16);
        assert_ne!(sealed[..12], [0u8; 12]);
        assert_eq!(security.open(&sealed).unwrap(), plain.to_vec());

        let mut tampered = sealed.clone();
        tampered[12] ^= 0x40;
        assert!(security.open(&tampered).is_err());
    }

    #[test]
    fn test_mkcp_stream_round_trips_data_over_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let settings = XrayMkcpSettings::default();
        let server_security = MkcpSecurity::from_settings(&settings);
        let server_thread = thread::spawn(move || {
            let mut packet = [0u8; 2048];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            let opened = server_security.open(&packet[..length]).unwrap();
            let segments = decode_segments(&opened).unwrap();
            let MkcpSegment::Data {
                conv,
                timestamp,
                number,
                ..
            } = segments[0].clone()
            else {
                panic!("client did not send an mKCP data segment");
            };
            let ack = encode_ack(conv, 128, 0, timestamp, &[(number, timestamp)]).unwrap();
            server
                .send_to(&server_security.seal(&ack).unwrap(), peer)
                .unwrap();
            let response = encode_data(conv, timestamp, 0, 0, b"echo").unwrap();
            server
                .send_to(&server_security.seal(&response).unwrap(), peer)
                .unwrap();
        });

        let mut stream =
            MkcpStream::connect(&address.ip().to_string(), address.port(), &settings).unwrap();
        stream.write_all(b"hello").unwrap();
        let mut output = [0u8; 4];
        stream.read_exact(&mut output).unwrap();
        assert_eq!(&output, b"echo");
        drop(stream);
        server_thread.join().unwrap();
    }

    #[test]
    fn test_mkcp_rejects_non_none_disguise_headers() {
        let settings = XrayMkcpSettings {
            header_type: Some("srtp".to_owned()),
            header_seed: Some("noise".to_owned()),
            ..XrayMkcpSettings::default()
        };
        let error = MkcpStream::connect("127.0.0.1", 9, &settings).unwrap_err();
        assert!(error.to_string().contains("not implemented"));
    }
}
