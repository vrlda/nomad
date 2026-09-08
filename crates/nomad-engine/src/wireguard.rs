use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use super::WireGuardConfig;

const UDP_BUFFER_SIZE: usize = 65_535;
const TCP_BUFFER_SIZE: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_PORT: u16 = 53;

pub(super) struct WireGuardStream {
    device: WireGuardDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    socket_handle: Option<SocketHandle>,
    dns_servers: Vec<IpEndpoint>,
    nonblocking: bool,
}

struct WireGuardDevice {
    socket: UdpSocket,
    peer: SocketAddr,
    tunnel: Tunn,
    mtu: usize,
    receive_packet: Option<Vec<u8>>,
    error: Option<io::Error>,
}

struct WireGuardRxToken(Vec<u8>);

struct WireGuardTxToken<'a>(&'a mut WireGuardDevice);

impl WireGuardStream {
    pub(super) fn connect(
        config: &WireGuardConfig,
        target_host: &str,
        target_port: u16,
    ) -> io::Result<Self> {
        let peer = config.peers.first().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "WireGuard requires a peer")
        })?;
        let peer_endpoint = peer.endpoint.parse::<SocketAddr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WireGuard peer endpoint must use a numeric IP address",
            )
        })?;
        let addresses = config
            .addresses
            .iter()
            .map(|address| parse_cidr(address))
            .collect::<io::Result<Vec<_>>>()?;
        let local_address = addresses.first().map(IpCidr::address).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WireGuard requires at least one local address",
            )
        })?;
        let socket = UdpSocket::bind(match peer_endpoint {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })?;
        socket.connect(peer_endpoint)?;
        socket.set_nonblocking(true)?;
        let tunnel = Tunn::new(
            StaticSecret::from(config.secret_key),
            PublicKey::from(peer.public_key),
            peer.pre_shared_key,
            peer.persistent_keepalive,
            0,
            None,
        );
        let mut device = WireGuardDevice {
            socket,
            peer: peer_endpoint,
            tunnel,
            mtu: usize::from(config.mtu),
            receive_packet: None,
            error: None,
        };
        let mut interface_config = Config::new(HardwareAddress::Ip);
        interface_config.random_seed = random_seed();
        let mut interface = Interface::new(interface_config, &mut device, Instant::now());
        interface.set_any_ip(true);
        interface.update_ip_addrs(|ip_addrs| {
            for address in &addresses {
                let _ = ip_addrs.push(*address);
            }
        });
        add_default_route(&mut interface, local_address)?;

        let sockets = SocketSet::new(Vec::new());
        let mut stream = Self {
            device,
            interface,
            sockets,
            socket_handle: None,
            dns_servers: config
                .dns
                .iter()
                .map(|server| parse_dns_server(server))
                .collect::<io::Result<Vec<_>>>()?,
            nonblocking: false,
        };
        let target = match parse_target(target_host, target_port) {
            Ok(target) => target,
            Err(_error) if target_port != 0 => stream.resolve_target(target_host)?,
            Err(error) => return Err(error),
        };
        let tcp_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        );
        let socket_handle = stream.sockets.add(tcp_socket);
        stream
            .sockets
            .get_mut::<tcp::Socket>(socket_handle)
            .connect(stream.interface.context(), (target, target_port), 40_000)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        stream.socket_handle = Some(socket_handle);
        stream.wait_for_connection(StdInstant::now() + CONNECT_TIMEOUT)?;
        Ok(stream)
    }

    fn wait_for_connection(&mut self, deadline: StdInstant) -> io::Result<()> {
        loop {
            self.pump()?;
            let socket_handle = self
                .socket_handle
                .expect("WireGuard TCP socket is initialized");
            let state = self.sockets.get::<tcp::Socket>(socket_handle).state();
            if state == tcp::State::Established {
                return Ok(());
            }
            if state == tcp::State::Closed || StdInstant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "WireGuard TCP connection did not establish",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn pump(&mut self) -> io::Result<()> {
        self.device.tick_timers();
        self.interface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);
        self.device.take_error()
    }

    fn read_once(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let socket_handle = self
            .socket_handle
            .expect("WireGuard TCP socket is initialized");
        let socket = self.sockets.get_mut::<tcp::Socket>(socket_handle);
        if socket.can_recv() {
            return socket
                .recv(|data| {
                    let length = data.len().min(buffer.len());
                    buffer[..length].copy_from_slice(&data[..length]);
                    (length, Some(length))
                })
                .map_err(|error| io::Error::other(error.to_string()));
        }
        if !socket.may_recv() {
            return Ok(Some(0));
        }
        Ok(None)
    }

    fn write_once(&mut self, buffer: &[u8]) -> io::Result<Option<usize>> {
        let socket_handle = self
            .socket_handle
            .expect("WireGuard TCP socket is initialized");
        let socket = self.sockets.get_mut::<tcp::Socket>(socket_handle);
        if socket.can_send() {
            let length = buffer.len().min(self.device.mtu.saturating_sub(40).max(1));
            let written = socket
                .send_slice(&buffer[..length])
                .map_err(|error| io::Error::other(error.to_string()))?;
            return Ok(Some(written));
        }
        if !socket.may_send() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WireGuard TCP connection is closed",
            ));
        }
        Ok(None)
    }

    pub(super) fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    fn resolve_target(&mut self, host: &str) -> io::Result<IpAddress> {
        let server = self.dns_servers.first().copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WireGuard hostname targets require a numeric DNS server in settings.dns",
            )
        })?;
        let socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4 * 2048]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4 * 2048]),
        );
        let handle = self.sockets.add(socket);
        let local_port = 49_152 + u16::try_from(random_seed() % 1_000).unwrap_or(0);
        {
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            socket
                .bind(local_port)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        }
        let deadline = StdInstant::now() + DNS_TIMEOUT;
        let mut last_error = None;
        for (index, query_type) in [1u16, 28u16].into_iter().enumerate() {
            let query_id = u16::try_from(random_seed() & u64::from(u16::MAX))
                .unwrap_or(1)
                .wrapping_add(u16::try_from(index).unwrap_or(0));
            let query = build_dns_query(host, query_id, query_type)?;
            self.sockets
                .get_mut::<udp::Socket>(handle)
                .send_slice(&query, server)
                .map_err(|error| io::Error::other(error.to_string()))?;
            while StdInstant::now() < deadline {
                self.pump()?;
                let response = {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    if socket.can_recv() {
                        let (data, _) = socket
                            .recv()
                            .map_err(|error| io::Error::other(error.to_string()))?;
                        Some(data.to_vec())
                    } else {
                        None
                    }
                };
                if let Some(response) = response {
                    match parse_dns_response(&response, query_id, query_type) {
                        Ok(address) => return Ok(to_smoltcp_ip(address)),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            last_error = Some(error);
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            last_error = Some(error);
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "WireGuard DNS query timed out")
        }))
    }
}

impl Read for WireGuardStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.pump()?;
            if let Some(length) = self.read_once(buffer)? {
                return Ok(length);
            }
            if self.nonblocking {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "WireGuard read pending",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Write for WireGuardStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.pump()?;
            if let Some(length) = self.write_once(buffer)? {
                return Ok(length);
            }
            if self.nonblocking {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "WireGuard write pending",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pump()
    }
}

impl WireGuardDevice {
    fn tick_timers(&mut self) {
        let mut output = vec![0u8; self.mtu + 256];
        let result = self.tunnel.update_timers(&mut output);
        self.handle_tunnel_result(result);
    }

    fn handle_tunnel_result(&mut self, result: TunnResult<'_>) {
        match result {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(packet) => {
                if let Err(error) = self.socket.send(packet) {
                    self.error = Some(error);
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                self.receive_packet = Some(packet.to_vec());
            }
            TunnResult::Err(error) => {
                self.error = Some(io::Error::other(format!(
                    "WireGuard tunnel error: {error:?}"
                )));
            }
        }
    }

    fn receive_from_peer(&mut self) -> bool {
        let mut encrypted = vec![0u8; UDP_BUFFER_SIZE];
        let Ok((length, address)) = self.socket.recv_from(&mut encrypted) else {
            return false;
        };
        if address != self.peer {
            return false;
        }
        self.decapsulate_packet(address.ip(), &encrypted[..length])
    }

    fn decapsulate_packet(&mut self, source: IpAddr, encrypted: &[u8]) -> bool {
        let mut output = vec![0u8; UDP_BUFFER_SIZE];
        let result = self
            .tunnel
            .decapsulate(Some(source), encrypted, &mut output);
        self.handle_tunnel_result(result);
        if self.receive_packet.is_some() {
            return true;
        }
        loop {
            let result = self.tunnel.decapsulate(None, &[], &mut output);
            let queued_network_packet = matches!(result, TunnResult::WriteToNetwork(_));
            self.handle_tunnel_result(result);
            if self.receive_packet.is_some() {
                return true;
            }
            if self.error.is_some() {
                return false;
            }
            if !queued_network_packet {
                return false;
            }
        }
    }

    fn take_error(&mut self) -> io::Result<()> {
        self.error.take().map_or(Ok(()), Err)
    }
}

impl Device for WireGuardDevice {
    type RxToken<'a>
        = WireGuardRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = WireGuardTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.receive_packet.is_none() {
            self.receive_from_peer();
        }
        self.receive_packet
            .take()
            .map(|packet| (WireGuardRxToken(packet), WireGuardTxToken(self)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(WireGuardTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = Some(1);
        capabilities.medium = Medium::Ip;
        capabilities
    }
}

impl RxToken for WireGuardRxToken {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.0)
    }
}

impl TxToken for WireGuardTxToken<'_> {
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; length];
        let result = function(&mut packet);
        let mut output = vec![0u8; packet.len().saturating_add(256).max(148)];
        let tunnel_result = self.0.tunnel.encapsulate(&packet, &mut output);
        self.0.handle_tunnel_result(tunnel_result);
        result
    }
}

fn parse_target(host: &str, port: u16) -> io::Result<IpAddress> {
    let address = IpAddr::from_str(host).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard outbound requires a numeric target IP to avoid local DNS resolution",
        )
    })?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard target port cannot be zero",
        ));
    }
    Ok(to_smoltcp_ip(address))
}

fn parse_dns_server(value: &str) -> io::Result<IpEndpoint> {
    let address = IpAddr::from_str(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard DNS servers must use numeric IP addresses",
        )
    })?;
    if address.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard DNS server cannot be unspecified",
        ));
    }
    Ok(IpEndpoint::new(to_smoltcp_ip(address), DNS_PORT))
}

fn build_dns_query(host: &str, id: u16, query_type: u16) -> io::Result<Vec<u8>> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || host.bytes().any(|byte| byte == 0 || byte > 0x7f) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard DNS target is not a valid ASCII hostname",
        ));
    }
    let mut query = Vec::with_capacity(12 + host.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WireGuard DNS target contains an invalid label",
            ));
        }
        query.push(u8::try_from(label.len()).unwrap_or_default());
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn parse_dns_response(packet: &[u8], id: u16, query_type: u16) -> io::Result<IpAddr> {
    if packet.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard DNS response is truncated",
        ));
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard DNS response ID mismatch",
        ));
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard DNS response is not a response",
        ));
    }
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]);
    if question_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard DNS response has no question",
        ));
    }
    let mut offset = 12;
    for _ in 0..question_count {
        offset = skip_dns_name(packet, offset)?;
        offset = offset.checked_add(4).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard DNS question overflow",
            )
        })?;
        if offset > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard DNS question is truncated",
            ));
        }
    }
    for _ in 0..answer_count {
        offset = skip_dns_name(packet, offset)?;
        if offset.checked_add(10).is_none_or(|end| end > packet.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard DNS answer is truncated",
            ));
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let length = usize::from(u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]));
        offset += 10;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > packet.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard DNS record is truncated",
            ));
        }
        if record_type == query_type && class == 1 {
            match (query_type, length) {
                (1, 4) => {
                    return Ok(IpAddr::from([
                        packet[offset],
                        packet[offset + 1],
                        packet[offset + 2],
                        packet[offset + 3],
                    ]));
                }
                (28, 16) => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&packet[offset..offset + 16]);
                    return Ok(IpAddr::from(bytes));
                }
                _ => {}
            }
        }
        offset += length;
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "WireGuard DNS response contains no matching address",
    ))
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> io::Result<usize> {
    loop {
        let length = *packet.get(offset).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard DNS name is truncated",
            )
        })?;
        if length & 0xc0 == 0xc0 {
            if offset + 2 > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WireGuard DNS name pointer is truncated",
                ));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard DNS name has an invalid label",
            ));
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset.checked_add(usize::from(length)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "WireGuard DNS name overflow")
        })?;
        if offset > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard DNS name is truncated",
            ));
        }
    }
}

fn parse_cidr(value: &str) -> io::Result<IpCidr> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard address must be CIDR",
        )
    })?;
    let prefix = prefix.parse::<u8>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard address has invalid prefix",
        )
    })?;
    let address = IpAddr::from_str(address).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard address is not an IP",
        )
    })?;
    let max_prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard address prefix is too large",
        ));
    }
    Ok(IpCidr::new(to_smoltcp_ip(address), prefix))
}

fn add_default_route(interface: &mut Interface, address: IpAddress) -> io::Result<()> {
    match address {
        IpAddress::Ipv4(address) => interface
            .routes_mut()
            .add_default_ipv4_route(address)
            .map(|_| ())
            .map_err(|error| io::Error::other(error.to_string())),
        IpAddress::Ipv6(address) => interface
            .routes_mut()
            .add_default_ipv6_route(address)
            .map(|_| ())
            .map_err(|error| io::Error::other(error.to_string())),
    }
}

fn to_smoltcp_ip(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            IpAddress::v4(octets[0], octets[1], octets[2], octets[3])
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            IpAddress::v6(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )
        }
    }
}

fn random_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        });
    nanos ^ u64::from(std::process::id())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant as StdInstant};

    use boringtun::noise::Tunn;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

    use super::super::WireGuardPeer;
    use super::{
        build_dns_query, parse_cidr, parse_dns_response, parse_target, random_seed,
        WireGuardConfig, WireGuardDevice, WireGuardStream,
    };

    #[test]
    fn builds_and_parses_routed_dns_ipv4_response() {
        let query = build_dns_query("example.com", 0x1234, 1).unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(&query[12..], b"\x07example\x03com\0\0\x01\0\x01");

        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 203, 0, 113, 7,
        ]);
        assert_eq!(
            parse_dns_response(&response, 0x1234, 1).unwrap(),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_invalid_routed_dns_names() {
        assert!(build_dns_query("", 1, 1).is_err());
        assert!(build_dns_query("bad..example", 1, 1).is_err());
    }

    #[test]
    fn parses_ipv4_and_ipv6_cidrs() {
        assert_eq!(
            parse_cidr("10.0.0.2/32").unwrap(),
            IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)
        );
        assert_eq!(
            parse_cidr("2001:db8::2/128").unwrap(),
            IpCidr::new(IpAddress::v6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 128)
        );
    }

    #[test]
    fn rejects_hostname_targets_before_network_access() {
        assert!(parse_target("gateway.example", 443).is_err());
        assert!(parse_target("192.0.2.10", 0).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn wireguard_stream_bridges_a_tcp_socket_over_a_local_peer() {
        let server_secret = StaticSecret::from([2u8; 32]);
        let client_secret = [1u8; 32];
        let server_public_key = PublicKey::from(&server_secret).to_bytes();
        let client_public_key = PublicKey::from(&StaticSecret::from(client_secret)).to_bytes();
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut first_packet = vec![0u8; 2048];
            let (length, client_address) = server_socket.recv_from(&mut first_packet).unwrap();
            server_socket.connect(client_address).unwrap();
            let tunnel = Tunn::new(
                server_secret,
                PublicKey::from(client_public_key),
                None,
                None,
                0,
                None,
            );
            let mut device = WireGuardDevice {
                socket: server_socket,
                peer: client_address,
                tunnel,
                mtu: 1420,
                receive_packet: None,
                error: None,
            };
            device.socket.set_nonblocking(true).unwrap();
            device.decapsulate_packet(client_address.ip(), &first_packet[..length]);

            let mut interface_config = Config::new(HardwareAddress::Ip);
            interface_config.random_seed = random_seed();
            let mut interface = Interface::new(interface_config, &mut device, Instant::now());
            interface.set_any_ip(true);
            interface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 32))
                    .unwrap();
            });
            super::add_default_route(&mut interface, IpAddress::v4(10, 0, 0, 1)).unwrap();

            let mut sockets = SocketSet::new(Vec::new());
            let socket_handle = sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 4096]),
                tcp::SocketBuffer::new(vec![0; 4096]),
            ));
            sockets
                .get_mut::<tcp::Socket>(socket_handle)
                .listen(80)
                .unwrap();
            let deadline = StdInstant::now() + Duration::from_secs(5);
            let mut response_queued = false;
            while StdInstant::now() < deadline {
                device.tick_timers();
                interface.poll(Instant::now(), &mut device, &mut sockets);
                let socket = sockets.get_mut::<tcp::Socket>(socket_handle);
                if socket.can_recv() {
                    let received = socket.recv(|data| (data.len(), data.to_vec())).unwrap();
                    if received == b"ping" {
                        socket.send_slice(b"pong").unwrap();
                        response_queued = true;
                    }
                }
                if response_queued {
                    interface.poll(Instant::now(), &mut device, &mut sockets);
                    break;
                }
                if let Err(error) = device.take_error() {
                    panic!("WireGuard test peer failed: {error}");
                }
                thread::sleep(Duration::from_millis(1));
            }
        });

        let config = WireGuardConfig {
            secret_key: client_secret,
            addresses: vec!["10.0.0.2/32".to_owned()],
            dns: Vec::new(),
            peers: vec![WireGuardPeer {
                endpoint: server_address.to_string(),
                public_key: server_public_key,
                pre_shared_key: None,
                persistent_keepalive: None,
            }],
            mtu: 1420,
            no_kernel_tun: true,
        };
        let mut stream = WireGuardStream::connect(&config, "10.0.0.1", 80).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        server_thread.join().unwrap();
    }
}
