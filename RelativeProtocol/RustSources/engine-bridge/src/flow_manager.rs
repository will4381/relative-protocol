//! Tracks TCP/UDP flows owned by the engine.

use crate::device::{ParsedPacket, TcpPacket, TunDevice, UdpPacket};
use crate::dns::{parse_response, DnsMapping};
use crate::ffi::{BridgeCallbacks, FlowCounters, FlowStats};
use crate::logger::{self, BreadcrumbFlags};
use libc::{AF_INET, AF_INET6};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{
    tcp::{SendError as TcpSendError, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer},
    udp::{
        PacketBuffer, PacketMetadata, SendError as UdpSendError, Socket as UdpSocket, UdpMetadata,
    },
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::num::NonZeroU64;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant as StdInstant};
use tokio::sync::Notify;

pub struct FlowManager {
    callbacks: Option<BridgeCallbacks>,
    interface: Interface,
    sockets: SocketSet<'static>,
    device: TunDevice,
    tcp_pool: Vec<SocketHandle>,
    udp_pool: Vec<SocketHandle>,
    flow_keys: HashMap<FlowKey, FlowEntry>,
    handle_map: HashMap<u64, FlowKey>,
    next_flow_id: NonZeroU64,
    counters: FlowCounters,
    wake: Arc<Notify>,
    stats: FlowStats,
}

#[derive(Debug, Clone)]
struct FlowEntry {
    socket: SocketHandle,
    kind: FlowKind,
    handle: u64,
    ready: bool,
    pending_dial: bool,
    dial_attempts: u8,
    next_redial_at: Option<StdInstant>,
    last_activity: StdInstant,
    buffered: VecDeque<Vec<u8>>,
    buffered_bytes: usize,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
enum FlowKind {
    Tcp,
    Udp,
}

enum FlowStatus {
    Ok,
    Backpressure(&'static str),
    Closed(&'static str),
}

impl FlowManager {
    pub fn counters(&self) -> FlowCounters {
        self.counters
    }

    pub fn stats(&self) -> FlowStats {
        self.stats
    }
    fn finalize_closed_flows(&mut self, callbacks: BridgeCallbacks) {
        let closures: Vec<(u64, String)> = self
            .flow_keys
            .values()
            .filter_map(|entry| {
                if entry.kind != FlowKind::Tcp {
                    return None;
                }
                let socket = self.sockets.get::<TcpSocket>(entry.socket);
                let state = socket.state();
                let remote_closed = !socket.may_recv() && !socket.can_recv();
                if remote_closed || matches!(state, smoltcp::socket::tcp::State::Closed) {
                    let reason = if remote_closed {
                        "remote_fin".to_string()
                    } else {
                        format!("tcp_closed ({state})")
                    };
                    Some((entry.handle, reason))
                } else {
                    None
                }
            })
            .collect();

        for (handle, reason) in closures {
            self.notify_close(handle, FlowKind::Tcp, &reason, callbacks);
            self.stats.tcp_flush_events = self.stats.tcp_flush_events.saturating_add(1);
        }
    }

    pub fn new(device: TunDevice, wake: Arc<Notify>) -> Self {
        let (device, interface, sockets, tcp_pool, udp_pool) = build_interface_and_sockets(device);
        Self {
            callbacks: None,
            interface,
            sockets,
            device,
            tcp_pool,
            udp_pool,
            flow_keys: HashMap::new(),
            handle_map: HashMap::new(),
            next_flow_id: NonZeroU64::new(1).unwrap(),
            counters: FlowCounters::default(),
            wake,
            stats: FlowStats::default(),
        }
    }

    pub fn install_callbacks(&mut self, callbacks: BridgeCallbacks) {
        self.callbacks = Some(callbacks);
        self.dispatch_pending_dials(StdInstant::now());
    }

    pub fn process_packet(&mut self, packet: &ParsedPacket<'_>) {
        match packet {
            ParsedPacket::Tcp(tcp) => self.handle_tcp_packet(tcp),
            ParsedPacket::Udp(udp) => self.handle_udp_packet(udp),
        }
    }

    pub fn on_tcp_receive(&mut self, handle: u64, payload: &[u8]) -> bool {
        self.forward_remote_payload(handle, payload, FlowKind::Tcp)
    }

    pub fn on_udp_receive(&mut self, handle: u64, payload: &[u8]) -> bool {
        self.forward_remote_payload(handle, payload, FlowKind::Udp)
    }

    pub fn on_tcp_close(&mut self, handle: u64) {
        if let Some(key) = self.handle_map.get(&handle).cloned() {
            if let Some(entry) = self.flow_keys.get(&key) {
                let socket = self.sockets.get_mut::<TcpSocket>(entry.socket);
                socket.abort();
            }
        }
        self.remove_flow(handle);
        self.wake.notify_one();
    }

    pub fn on_udp_close(&mut self, handle: u64) {
        if let Some(key) = self.handle_map.get(&handle).cloned() {
            let _ = key;
        }
        self.remove_flow(handle);
        self.wake.notify_one();
    }

    fn handle_tcp_packet(&mut self, packet: &TcpPacket<'_>) {
        let key = FlowKey::from_tcp(packet);
        if let Some(entry) = self.flow_keys.get_mut(&key) {
            entry.last_activity = StdInstant::now();
            return;
        }
        if let Some(socket) = self.tcp_pool.pop() {
            let flow_id = self.new_flow_id();
            let tcp_socket = self.sockets.get_mut::<TcpSocket>(socket);
            let endpoint = IpListenEndpoint {
                addr: Some(key.dst_ip),
                port: key.dst_port,
            };
            let _ = tcp_socket.listen(endpoint);
            self.flow_keys.insert(
                key,
                FlowEntry {
                    socket,
                    kind: FlowKind::Tcp,
                    handle: flow_id,
                    ready: false,
                    pending_dial: false,
                    dial_attempts: 0,
                    next_redial_at: Some(StdInstant::now()),
                    last_activity: StdInstant::now(),
                    buffered: VecDeque::new(),
                    buffered_bytes: 0,
                },
            );
            self.handle_map.insert(flow_id, key);
            logger::breadcrumb(
                BreadcrumbFlags::FLOW,
                format!(
                    "TCP flow {}:{} -> {}:{} admitted (handle {})",
                    ip_string(key.src_ip),
                    key.src_port,
                    ip_string(key.dst_ip),
                    key.dst_port,
                    flow_id
                ),
            );
            self.dispatch_pending_dials(StdInstant::now());
        } else {
            self.counters.tcp_admission_fail += 1;
            logger::warn("FlowManager: TCP admission failed (pool exhausted)");
        }
    }

    fn handle_udp_packet(&mut self, packet: &UdpPacket<'_>) {
        self.observe_dns(packet);
        let key = FlowKey::from_udp(packet);
        if let Some(entry) = self.flow_keys.get_mut(&key) {
            entry.last_activity = StdInstant::now();
            return;
        }
        if let Some(socket) = self.udp_pool.pop() {
            let flow_id = self.new_flow_id();
            let udp_socket = self.sockets.get_mut::<UdpSocket>(socket);
            let endpoint = IpListenEndpoint {
                addr: Some(key.dst_ip),
                port: key.dst_port,
            };
            let _ = udp_socket.bind(endpoint);
            self.flow_keys.insert(
                key,
                FlowEntry {
                    socket,
                    kind: FlowKind::Udp,
                    handle: flow_id,
                    ready: false,
                    pending_dial: false,
                    dial_attempts: 0,
                    next_redial_at: Some(StdInstant::now()),
                    last_activity: StdInstant::now(),
                    buffered: VecDeque::new(),
                    buffered_bytes: 0,
                },
            );
            self.handle_map.insert(flow_id, key);
            logger::breadcrumb(
                BreadcrumbFlags::FLOW,
                format!(
                    "UDP flow {}:{} -> {}:{} admitted (handle {})",
                    ip_string(key.src_ip),
                    key.src_port,
                    ip_string(key.dst_ip),
                    key.dst_port,
                    flow_id
                ),
            );
            self.dispatch_pending_dials(StdInstant::now());
        } else {
            self.counters.udp_admission_fail += 1;
            logger::warn("FlowManager: UDP admission failed (pool exhausted)");
        }
    }

    fn observe_dns(&self, packet: &UdpPacket<'_>) {
        if packet.src_port != 53 && packet.dst_port != 53 {
            return;
        }
        let Some(callbacks) = self.callbacks else {
            return;
        };
        let mappings = parse_response(packet.payload);
        if mappings.is_empty() {
            return;
        }
        for mapping in mappings {
            self.emit_dns_mapping(callbacks, &mapping);
        }
    }

    fn emit_dns_mapping(&self, callbacks: BridgeCallbacks, mapping: &DnsMapping) {
        if mapping.addresses.is_empty() {
            return;
        }
        let ttl = mapping.ttl.unwrap_or(60).min(u32::MAX);
        let c_host = match CString::new(mapping.host.as_str()) {
            Ok(value) => value,
            Err(_) => return,
        };
        let mut c_addresses: Vec<CString> = Vec::with_capacity(mapping.addresses.len());
        let mut ptrs: Vec<*const i8> = Vec::with_capacity(mapping.addresses.len());
        for addr in &mapping.addresses {
            let addr_text = addr.to_string();
            if let Ok(c_string) = CString::new(addr_text.as_str()) {
                ptrs.push(c_string.as_ptr());
                c_addresses.push(c_string);
            }
        }
        if ptrs.is_empty() {
            return;
        }
        unsafe {
            (callbacks.record_dns)(
                c_host.as_ptr(),
                ptrs.as_ptr(),
                ptrs.len(),
                ttl,
                callbacks.context,
            );
        }
        logger::breadcrumb(
            BreadcrumbFlags::DNS,
            format!(
                "DNS {} -> {:?} (ttl {}s)",
                mapping.host,
                mapping
                    .addresses
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>(),
                ttl
            ),
        );
    }

    fn forward_remote_payload(&mut self, handle: u64, payload: &[u8], kind: FlowKind) -> bool {
        if payload.is_empty() {
            return true;
        }
        let Some(key) = self.handle_map.get(&handle).copied() else {
            return false;
        };

        let socket;
        let handle_id;
        if let Some(entry) = self.flow_keys.get_mut(&key) {
            if !entry.ready {
                if Self::buffer_payload(entry, payload) {
                    logger::breadcrumb(
                        BreadcrumbFlags::FLOW,
                        format!(
                            "Buffered {:?} payload for handle {} while dial completes",
                            kind, handle
                        ),
                    );
                    entry.last_activity = StdInstant::now();
                    return true;
                }
                logger::warn(format!(
                    "FlowManager: dropping {:?} payload for handle {} (buffer full before dial)",
                    kind, handle
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} payload dropped before dial for handle {} (buffer full)",
                        kind, handle
                    ),
                );
                return false;
            }
            socket = entry.socket;
            handle_id = entry.handle;
        } else {
            return false;
        }

        let status = match kind {
            FlowKind::Tcp => self.enqueue_remote_tcp(socket, payload),
            FlowKind::Udp => self.enqueue_remote_udp(socket, &key, payload),
        };
        match status {
            FlowStatus::Ok => {
                if let Some(entry_mut) = self.flow_keys.get_mut(&key) {
                    entry_mut.last_activity = StdInstant::now();
                }
                self.wake.notify_one();
                true
            }
            FlowStatus::Backpressure(reason) => {
                match kind {
                    FlowKind::Tcp => self.counters.tcp_backpressure_drops += 1,
                    FlowKind::Udp => self.counters.udp_backpressure_drops += 1,
                }
                logger::warn(format!(
                    "FlowManager: {:?} backpressure for handle {} ({reason})",
                    kind, handle_id
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} backpressure for handle {} ({reason})",
                        kind, handle_id
                    ),
                );
                self.wake.notify_one();
                if let Some(callbacks) = self.callbacks {
                    self.notify_close(handle_id, kind, reason, callbacks);
                }
                false
            }
            FlowStatus::Closed(reason) => {
                logger::warn(format!(
                    "FlowManager: {:?} closed for handle {} ({reason})",
                    kind, handle_id
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!("{:?} closed for handle {} ({reason})", kind, handle_id),
                );
                self.wake.notify_one();
                if let Some(callbacks) = self.callbacks {
                    self.notify_close(handle_id, kind, reason, callbacks);
                }
                false
            }
        }
    }

    pub fn on_dial_result(&mut self, handle: u64, success: bool, reason: Option<&str>) {
        let Some(key) = self.handle_map.get(&handle).cloned() else {
            logger::warn(format!(
                "FlowManager: dial result for unknown handle {}",
                handle
            ));
            return;
        };
        let mut close_params = None;
        if let Some(entry) = self.flow_keys.get_mut(&key) {
            entry.pending_dial = false;
            if success {
                entry.ready = true;
                entry.next_redial_at = None;
                entry.last_activity = StdInstant::now();
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!("{:?} dial ready for handle {}", entry.kind, entry.handle),
                );
                self.wake.notify_one();
                let _ = entry;
                self.flush_buffered_payloads(key);
                return;
            }

            if entry.dial_attempts < MAX_DIAL_ATTEMPTS {
                let delay = dial_backoff_delay(entry.dial_attempts);
                entry.next_redial_at = Some(StdInstant::now() + delay);
                let message = reason.unwrap_or("dial_failed");
                logger::warn(format!(
                    "FlowManager: {:?} dial attempt {} failed for handle {} ({message}), retrying in {:?}",
                    entry.kind,
                    entry.dial_attempts,
                    entry.handle,
                    delay
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} dial retry {} for handle {} ({message})",
                        entry.kind, entry.dial_attempts, entry.handle
                    ),
                );
                self.wake.notify_one();
                return;
            }

            close_params = Some((entry.handle, entry.kind));
        }

        if let Some((flow_handle, flow_kind)) = close_params {
            if let Some(callbacks) = self.callbacks {
                let message = reason.unwrap_or("dial_failed");
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} dial failed for handle {} ({message})",
                        flow_kind, flow_handle
                    ),
                );
                self.notify_close(flow_handle, flow_kind, message, callbacks);
            }
        }
    }

    fn remove_flow(&mut self, handle: u64) {
        if let Some(key) = self.handle_map.remove(&handle) {
            let entry = self.flow_keys.remove(&key);
            if let Some(entry) = entry {
                match entry.kind {
                    FlowKind::Tcp => self.tcp_pool.push(entry.socket),
                    FlowKind::Udp => self.udp_pool.push(entry.socket),
                }
            }
        }
    }

    fn request_dial(&self, handle: u64, ip: IpAddress, port: u16, kind: FlowKind) {
        let callbacks = match self.callbacks {
            Some(cb) => cb,
            None => return,
        };
        let host = ip_string(ip);
        if let Ok(c_host) = CString::new(host) {
            unsafe {
                match kind {
                    FlowKind::Tcp => (callbacks.request_tcp_dial)(
                        c_host.as_ptr(),
                        port,
                        handle,
                        callbacks.context,
                    ),
                    FlowKind::Udp => (callbacks.request_udp_dial)(
                        c_host.as_ptr(),
                        port,
                        handle,
                        callbacks.context,
                    ),
                }
            }
        }
    }

    fn dispatch_pending_dials(&mut self, now: StdInstant) -> bool {
        if self.callbacks.is_none() {
            return false;
        }
        let ready_keys: Vec<FlowKey> = self
            .flow_keys
            .iter()
            .filter_map(|(key, entry)| {
                let deadline = entry.next_redial_at?;
                if entry.ready || entry.pending_dial || entry.dial_attempts >= MAX_DIAL_ATTEMPTS {
                    return None;
                }
                if deadline <= now {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect();

        let mut dispatched = false;
        for key in ready_keys {
            let dispatch = if let Some(entry) = self.flow_keys.get_mut(&key) {
                if entry.ready || entry.pending_dial || entry.dial_attempts >= MAX_DIAL_ATTEMPTS {
                    None
                } else {
                    entry.pending_dial = true;
                    entry.dial_attempts = entry.dial_attempts.saturating_add(1);
                    entry.next_redial_at = None;
                    Some((entry.handle, entry.kind))
                }
            } else {
                None
            };

            if let Some((handle, kind)) = dispatch {
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "Requesting {:?} dial to {}:{} (handle {})",
                        kind,
                        ip_string(key.dst_ip),
                        key.dst_port,
                        handle
                    ),
                );
                self.request_dial(handle, key.dst_ip, key.dst_port, kind);
                dispatched = true;
            }
        }

        dispatched
    }

    fn new_flow_id(&mut self) -> u64 {
        let id = self.next_flow_id.get();
        let next = self.next_flow_id.get().wrapping_add(1);
        self.next_flow_id = NonZeroU64::new(next).unwrap_or(NonZeroU64::new(1).unwrap());
        id
    }

    pub fn poll(&mut self, now: Instant) -> bool {
        let callbacks = match self.callbacks {
            Some(cb) => cb,
            None => return false,
        };
        let mut did_work = false;
        self.stats.poll_iterations = self.stats.poll_iterations.saturating_add(1);
        if self
            .interface
            .poll(now, &mut self.device, &mut self.sockets)
        {
            did_work = true;
        }
        let frames = self.device.handle().drain_outbound();
        if !frames.is_empty() {
            did_work = true;
            let bytes: usize = frames.iter().map(|frame| frame.len()).sum();
            let frame_count = frames.len() as u64;
            emit_frames(callbacks, frames);
            self.stats.frames_emitted = self.stats.frames_emitted.saturating_add(frame_count);
            self.stats.bytes_emitted = self.stats.bytes_emitted.saturating_add(bytes as u64);
        }
        self.flush_outbound(callbacks);
        self.finalize_closed_flows(callbacks);
        if self.dispatch_pending_dials(StdInstant::now()) {
            did_work = true;
        }
        if self.prune_idle_udp_flows(StdInstant::now(), callbacks) {
            did_work = true;
        }
        did_work
    }

    fn prune_idle_udp_flows(&mut self, now: StdInstant, callbacks: BridgeCallbacks) -> bool {
        let mut pruned = false;
        let idle_keys: Vec<FlowKey> = self
            .flow_keys
            .iter()
            .filter_map(|(key, entry)| {
                if entry.kind == FlowKind::Udp
                    && Self::is_dns_flow(key)
                    && entry.ready
                    && now
                        .checked_duration_since(entry.last_activity)
                        .map(|elapsed| elapsed >= UDP_IDLE_TIMEOUT)
                        .unwrap_or(false)
                {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect();
        for key in idle_keys {
            if let Some(entry) = self.flow_keys.get(&key) {
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "UDP idle timeout for handle {} dst={} port={} (pool={})",
                        entry.handle,
                        ip_string(key.dst_ip),
                        key.dst_port,
                        self.udp_pool.len()
                    ),
                );
                self.notify_close(entry.handle, FlowKind::Udp, "udp_idle_timeout", callbacks);
                pruned = true;
            } else {
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "UDP idle timeout triggered but flow key missing (dst={} port={})",
                        ip_string(key.dst_ip),
                        key.dst_port
                    ),
                );
            }
        }
        pruned
    }

    fn is_dns_flow(key: &FlowKey) -> bool {
        key.src_port == 53 || key.dst_port == 53
    }
}

fn build_interface_and_sockets(
    mut device: TunDevice,
) -> (
    TunDevice,
    Interface,
    SocketSet<'static>,
    Vec<SocketHandle>,
    Vec<SocketHandle>,
) {
    let ipv4_addr = Ipv4Address::new(10, 0, 0, 1);
    let ipv6_addr = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    let mut config = IfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = 0;
    let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
    interface.set_any_ip(true);
    interface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        let _ = ip_addrs.push(IpCidr::new(IpAddress::Ipv4(ipv4_addr), 24));
        let _ = ip_addrs.push(IpCidr::new(IpAddress::Ipv6(ipv6_addr), 64));
    });
    {
        let routes = interface.routes_mut();
        routes.add_default_ipv4_route(ipv4_addr).ok();
        routes.add_default_ipv6_route(ipv6_addr).ok();
    }

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_pool = Vec::with_capacity(TCP_SOCKET_COUNT);
    for _ in 0..TCP_SOCKET_COUNT {
        let socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0; TCP_RX_BUFFER_SIZE]),
            TcpSocketBuffer::new(vec![0; TCP_TX_BUFFER_SIZE]),
        );
        let handle = sockets.add(socket);
        tcp_pool.push(handle);
    }

    let mut udp_pool = Vec::with_capacity(UDP_SOCKET_COUNT);
    for _ in 0..UDP_SOCKET_COUNT {
        let rx_meta = vec![PacketMetadata::EMPTY; UDP_PACKET_METADATA];
        let tx_meta = vec![PacketMetadata::EMPTY; UDP_PACKET_METADATA];
        let socket = UdpSocket::new(
            PacketBuffer::new(rx_meta, vec![0; UDP_BUFFER_SIZE]),
            PacketBuffer::new(tx_meta, vec![0; UDP_BUFFER_SIZE]),
        );
        let handle = sockets.add(socket);
        udp_pool.push(handle);
    }

    (device, interface, sockets, tcp_pool, udp_pool)
}

const TCP_SOCKET_COUNT: usize = 128;
const UDP_SOCKET_COUNT: usize = 128;
const TCP_RX_BUFFER_SIZE: usize = 16 * 1024;
const TCP_TX_BUFFER_SIZE: usize = 16 * 1024;
const UDP_PACKET_METADATA: usize = 64;
const UDP_BUFFER_SIZE: usize = 32 * 1024;
const MAX_DIAL_ATTEMPTS: u8 = 3;
const DIAL_BACKOFF_BASE_MS: u64 = 50;
const UDP_IDLE_TIMEOUT: StdDuration = StdDuration::from_secs(2);
const MAX_BUFFERED_PAYLOADS: usize = 8;
const MAX_BUFFERED_BYTES: usize = 64 * 1024;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct FlowKey {
    src_ip: IpAddress,
    src_port: u16,
    dst_ip: IpAddress,
    dst_port: u16,
    kind: FlowKind,
}

impl FlowKey {
    fn from_tcp(packet: &TcpPacket<'_>) -> Self {
        FlowKey {
            src_ip: ip_address_from_std(packet.src),
            src_port: packet.src_port,
            dst_ip: ip_address_from_std(packet.dst),
            dst_port: packet.dst_port,
            kind: FlowKind::Tcp,
        }
    }

    fn from_udp(packet: &UdpPacket<'_>) -> Self {
        FlowKey {
            src_ip: ip_address_from_std(packet.src),
            src_port: packet.src_port,
            dst_ip: ip_address_from_std(packet.dst),
            dst_port: packet.dst_port,
            kind: FlowKind::Udp,
        }
    }
}

fn ip_string(ip: IpAddress) -> String {
    match ip {
        IpAddress::Ipv4(addr) => addr.to_string(),
        IpAddress::Ipv6(addr) => addr.to_string(),
    }
}

fn ip_address_from_std(addr: std::net::IpAddr) -> IpAddress {
    match addr {
        std::net::IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets())),
        std::net::IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())),
    }
}

fn dial_backoff_delay(attempt: u8) -> StdDuration {
    let shift = attempt.saturating_sub(1).min(4) as u32;
    let multiplier = 1u64 << shift;
    StdDuration::from_millis(DIAL_BACKOFF_BASE_MS * multiplier)
}

fn emit_frames(callbacks: BridgeCallbacks, frames: Vec<Vec<u8>>) {
    if frames.is_empty() {
        return;
    }
    let mut packet_ptrs: Vec<*const u8> = Vec::with_capacity(frames.len());
    let mut sizes: Vec<usize> = Vec::with_capacity(frames.len());
    let mut protocols: Vec<u32> = Vec::with_capacity(frames.len());
    for frame in &frames {
        packet_ptrs.push(frame.as_ptr());
        sizes.push(frame.len());
        protocols.push(protocol_number(frame));
    }

    unsafe {
        (callbacks.emit_packets)(
            packet_ptrs.as_ptr(),
            sizes.as_ptr(),
            protocols.as_ptr(),
            packet_ptrs.len(),
            callbacks.context,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{TunDevice, DEFAULT_MTU};
    use std::ffi::{c_void, CStr};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    #[derive(Default)]
    struct TestHarness {
        dns: Mutex<Vec<(String, Vec<String>, u32)>>,
        dials: Mutex<Vec<(FlowKind, String, u16, u64)>>,
        closes: Mutex<Vec<(FlowKind, u64, String)>>,
    }

    impl TestHarness {
        fn record_dns(&self, host: String, addresses: Vec<String>, ttl: u32) {
            self.dns.lock().unwrap().push((host, addresses, ttl));
        }

        fn record_dial(&self, kind: FlowKind, host: String, port: u16, handle: u64) {
            self.dials.lock().unwrap().push((kind, host, port, handle));
        }

        fn record_close(&self, kind: FlowKind, handle: u64, message: String) {
            self.closes.lock().unwrap().push((kind, handle, message));
        }

        fn dns(&self) -> Vec<(String, Vec<String>, u32)> {
            self.dns.lock().unwrap().clone()
        }

        fn dials(&self) -> Vec<(FlowKind, String, u16, u64)> {
            self.dials.lock().unwrap().clone()
        }

        fn closes(&self) -> Vec<(FlowKind, u64, String)> {
            self.closes.lock().unwrap().clone()
        }
    }

    unsafe extern "C" fn noop_emit(
        _packets: *const *const u8,
        _sizes: *const usize,
        _protocols: *const u32,
        _count: usize,
        _context: *mut c_void,
    ) {
    }

    unsafe extern "C" fn test_request_tcp_dial(
        host: *const i8,
        port: u16,
        handle: u64,
        context: *mut c_void,
    ) {
        record_dial_callback(host, port, handle, context, FlowKind::Tcp);
    }

    unsafe extern "C" fn test_request_udp_dial(
        host: *const i8,
        port: u16,
        handle: u64,
        context: *mut c_void,
    ) {
        record_dial_callback(host, port, handle, context, FlowKind::Udp);
    }

    unsafe extern "C" fn noop_send(
        _handle: u64,
        _payload: *const u8,
        _length: usize,
        _context: *mut c_void,
    ) {
    }

    unsafe extern "C" fn test_udp_send(
        handle: u64,
        _payload: *const u8,
        length: usize,
        context: *mut c_void,
    ) {
        if context.is_null() {
            return;
        }
        let harness = unsafe { &*(context as *const TestHarness) };
        harness.record_close(FlowKind::Udp, handle, format!("udp_send size {}", length));
    }

    unsafe extern "C" fn test_record_dns(
        host: *const i8,
        addresses: *const *const i8,
        count: usize,
        ttl_seconds: u32,
        context: *mut c_void,
    ) {
        if host.is_null() || addresses.is_null() || context.is_null() {
            return;
        }
        let harness = unsafe { &*(context as *const TestHarness) };
        let host_str = unsafe { CStr::from_ptr(host) }
            .to_string_lossy()
            .to_string();
        let mut results = Vec::with_capacity(count);
        for index in 0..count {
            let ptr = unsafe { *addresses.add(index) };
            if ptr.is_null() {
                continue;
            }
            results.push(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().to_string());
        }
        if results.is_empty() {
            return;
        }
        harness.record_dns(host_str, results, ttl_seconds);
    }

    fn record_dial_callback(
        host: *const i8,
        port: u16,
        handle: u64,
        context: *mut c_void,
        kind: FlowKind,
    ) {
        if host.is_null() || context.is_null() {
            return;
        }
        let harness = unsafe { &*(context as *const TestHarness) };
        let host_str = unsafe { CStr::from_ptr(host) }
            .to_string_lossy()
            .to_string();
        harness.record_dial(kind, host_str, port, handle);
    }

    fn record_close_callback(
        handle: u64,
        message: *const i8,
        context: *mut c_void,
        kind: FlowKind,
    ) {
        if context.is_null() {
            return;
        }
        let harness = unsafe { &*(context as *const TestHarness) };
        let reason = if message.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(message) }
                .to_string_lossy()
                .to_string()
        };
        harness.record_close(kind, handle, reason);
    }

    fn test_callbacks(context: *mut c_void) -> BridgeCallbacks {
        BridgeCallbacks {
            emit_packets: noop_emit,
            request_tcp_dial: test_request_tcp_dial,
            request_udp_dial: test_request_udp_dial,
            tcp_send: noop_send,
            udp_send: test_udp_send,
            tcp_close: test_tcp_close,
            udp_close: test_udp_close,
            record_dns: test_record_dns,
            context,
        }
    }

    unsafe extern "C" fn test_tcp_close(handle: u64, message: *const i8, context: *mut c_void) {
        record_close_callback(handle, message, context, FlowKind::Tcp);
    }

    unsafe extern "C" fn test_udp_close(handle: u64, message: *const i8, context: *mut c_void) {
        record_close_callback(handle, message, context, FlowKind::Udp);
    }

    #[test]
    fn dns_packets_emit_mappings() {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let mut manager = FlowManager::new(device, Arc::clone(&wake));
        let harness = Box::new(TestHarness::default());
        let context = Box::into_raw(harness);
        manager.install_callbacks(test_callbacks(context as *mut c_void));

        let payload = build_dns_response("example.com", [203, 0, 113, 5], 120);
        let udp_packet = UdpPacket {
            src: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 53,
            dst_port: 1000,
            payload: payload.as_slice(),
        };
        let packet = ParsedPacket::Udp(udp_packet);
        manager.process_packet(&packet);

        let harness = unsafe { Box::from_raw(context) };
        let entries = harness.dns();
        assert_eq!(entries.len(), 1);
        let (host, addresses, ttl) = &entries[0];
        assert_eq!(host, "example.com");
        assert_eq!(addresses, &["203.0.113.5".to_string()]);
        assert_eq!(*ttl, 120);
    }

    #[test]
    fn tcp_dial_retries_eventually_close_flow() {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let mut manager = FlowManager::new(device, Arc::clone(&wake));
        let harness = Box::new(TestHarness::default());
        let context = Box::into_raw(harness);
        manager.install_callbacks(test_callbacks(context as *mut c_void));

        let tcp_packet = TcpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            src_port: 1000,
            dst_port: 443,
            payload: &[],
        };
        manager.process_packet(&ParsedPacket::Tcp(tcp_packet));
        thread::sleep(Duration::from_millis(10));
        manager.poll(Instant::from_millis(0));

        let harness_ref = unsafe { &*context };
        wait_for(&mut manager, harness_ref, Duration::from_millis(200), |h| {
            h.dials().len() >= 1
        });
        let recorded_handle = harness_ref.dials()[0].3;
        let (&handle, _) = manager
            .handle_map
            .iter()
            .next()
            .expect("expected flow handle");
        assert_eq!(handle, recorded_handle);

        for attempt in 0..MAX_DIAL_ATTEMPTS {
            manager.on_dial_result(handle, false, Some("network_down"));
            if attempt < MAX_DIAL_ATTEMPTS - 1 {
                let expected = (attempt as usize) + 2;
                wait_for(&mut manager, harness_ref, Duration::from_millis(500), |h| {
                    h.dials().len() >= expected
                });
            }
        }

        wait_for(&mut manager, harness_ref, Duration::from_millis(500), |h| {
            h.closes().len() >= 1
        });
        let closes = harness_ref.closes();
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].0, FlowKind::Tcp);
        assert_eq!(closes[0].1, handle);

        unsafe {
            drop(Box::from_raw(context));
        }
    }

    #[test]
    fn remote_payloads_buffer_until_dial_ready() {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let mut manager = FlowManager::new(device, Arc::clone(&wake));

        let tcp_packet = TcpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            src_port: 5000,
            dst_port: 443,
            payload: &[],
        };
        let key = FlowKey::from_tcp(&tcp_packet);
        let parsed = ParsedPacket::Tcp(tcp_packet);
        manager.process_packet(&parsed);

        let (&handle, _) = manager
            .handle_map
            .iter()
            .next()
            .expect("expected flow handle");

        // Remote payload arrives before dial ready – should be buffered.
        let payload = vec![1u8, 2, 3, 4];
        {
            let entry = manager.flow_keys.get_mut(&key).expect("flow entry missing");
            assert!(FlowManager::buffer_payload(entry, &payload));
            assert_eq!(entry.buffered.len(), 1);
            assert_eq!(entry.buffered_bytes, payload.len());
            assert!(!entry.ready);
        }

        // Mark dial ready; buffered payload should be flushed via on_dial_result.
        manager.on_dial_result(handle, true, None);
        if let Some(entry) = manager.flow_keys.get(&key) {
            assert!(entry.ready);
            assert_eq!(entry.buffered.len(), 0);
            assert_eq!(entry.buffered_bytes, 0);
        }
    }

    #[test]
    fn udp_backpressure_closes_flow() {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let mut manager = FlowManager::new(device, Arc::clone(&wake));
        let harness = Box::new(TestHarness::default());
        let context = Box::into_raw(harness);
        manager.install_callbacks(test_callbacks(context as *mut c_void));

        let udp_packet = UdpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
            src_port: 2000,
            dst_port: 5353,
            payload: &[0u8; 0],
        };
        manager.process_packet(&ParsedPacket::Udp(udp_packet));
        manager.poll(Instant::from_millis(0));

        let harness_ref = unsafe { &*context };
        wait_for(&mut manager, harness_ref, Duration::from_millis(200), |h| {
            h.dials().len() >= 1
        });
        let (kind, _, _, handle) = harness_ref.dials()[0];
        assert_eq!(kind, FlowKind::Udp);

        manager.on_dial_result(handle, true, None);

        // Saturate the UDP socket buffer by sending slices directly.
        let key = manager.handle_map.get(&handle).copied().unwrap();
        if let Some(entry) = manager.flow_keys.get(&key) {
            let socket_handle = entry.socket;
            let meta = UdpMetadata::from(IpEndpoint::new(key.dst_ip, key.dst_port));
            let socket = manager.sockets.get_mut::<UdpSocket>(socket_handle);
            for _ in 0..(UDP_PACKET_METADATA * 2) {
                let _ = socket.send_slice(&[0u8; 64], meta);
            }
        }

        // Trigger an additional write which should hit backpressure.
        let payload = vec![1u8; 128];
        manager.on_udp_receive(handle, &payload);

        wait_for(&mut manager, harness_ref, Duration::from_millis(200), |h| {
            h.closes().len() >= 1
        });
        let closes = harness_ref.closes();
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].0, FlowKind::Udp);
        assert_eq!(closes[0].1, handle);
        assert!(closes[0].2.contains("udp_send_buffer_full"));

        unsafe {
            drop(Box::from_raw(context));
        }
    }

    fn wait_for<F>(
        manager: &mut FlowManager,
        harness: &TestHarness,
        timeout: Duration,
        mut predicate: F,
    ) where
        F: FnMut(&TestHarness) -> bool,
    {
        let deadline = StdInstant::now() + timeout;
        while !predicate(harness) {
            if StdInstant::now() >= deadline {
                break;
            }
            manager.poll(Instant::from_millis(0));
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn build_dns_response(host: &str, addr: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x01]);
        payload.extend_from_slice(&[0x81, 0x80]);
        payload.extend_from_slice(&[0x00, 0x01]);
        payload.extend_from_slice(&[0x00, 0x01]);
        payload.extend_from_slice(&[0x00, 0x00]);
        payload.extend_from_slice(&[0x00, 0x00]);
        for label in host.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.push(0);
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        payload.extend_from_slice(&[0xC0, 0x0C]);
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        payload.extend_from_slice(&ttl.to_be_bytes());
        payload.extend_from_slice(&[0x00, 0x04]);
        payload.extend_from_slice(&addr);
        payload
    }
}

fn protocol_number(frame: &[u8]) -> u32 {
    if frame.first().map(|byte| (byte >> 4) == 6).unwrap_or(false) {
        AF_INET6 as u32
    } else {
        AF_INET as u32
    }
}

impl FlowManager {
    fn enqueue_remote_tcp(&mut self, socket: SocketHandle, payload: &[u8]) -> FlowStatus {
        if payload.is_empty() {
            return FlowStatus::Ok;
        }
        let socket = self.sockets.get_mut::<TcpSocket>(socket);
        match socket.send_slice(payload) {
            Ok(written) => {
                if written == payload.len() {
                    FlowStatus::Ok
                } else {
                    FlowStatus::Backpressure("tcp_send_buffer_full")
                }
            }
            Err(TcpSendError::InvalidState) => FlowStatus::Closed("tcp_invalid_state"),
        }
    }

    fn enqueue_remote_udp(
        &mut self,
        socket: SocketHandle,
        key: &FlowKey,
        payload: &[u8],
    ) -> FlowStatus {
        if payload.is_empty() {
            return FlowStatus::Ok;
        }
        let socket = self.sockets.get_mut::<UdpSocket>(socket);
        let meta = UdpMetadata::from(IpEndpoint::new(key.src_ip, key.src_port));
        match socket.send_slice(payload, meta) {
            Ok(()) => FlowStatus::Ok,
            Err(UdpSendError::BufferFull) => FlowStatus::Backpressure("udp_send_buffer_full"),
            Err(_) => FlowStatus::Closed("udp_invalid_state"),
        }
    }

    fn flush_outbound(&mut self, callbacks: BridgeCallbacks) {
        let snapshot: Vec<(FlowKind, SocketHandle, u64)> = self
            .flow_keys
            .values()
            .map(|entry| (entry.kind, entry.socket, entry.handle))
            .collect();
        for (kind, socket, handle) in snapshot {
            match kind {
                FlowKind::Tcp => self.flush_tcp(socket, handle, callbacks),
                FlowKind::Udp => self.flush_udp(socket, handle, callbacks),
            }
        }
    }

    fn flush_buffered_payloads(&mut self, key: FlowKey) {
        let Some(entry) = self.flow_keys.get_mut(&key) else {
            return;
        };
        if entry.buffered.is_empty() {
            return;
        }
        let handle = entry.handle;
        let kind = entry.kind;
        let mut buffered = VecDeque::new();
        std::mem::swap(&mut buffered, &mut entry.buffered);
        entry.buffered_bytes = 0;
        let _ = entry;

        for payload in buffered {
            if payload.is_empty() {
                continue;
            }
            if !self.forward_remote_payload(handle, payload.as_slice(), kind) {
                logger::warn(format!(
                    "FlowManager: failed to flush buffered {:?} payload for handle {}",
                    kind, handle
                ));
                break;
            }
        }
    }

    fn buffer_payload(entry: &mut FlowEntry, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return true;
        }
        if payload.len() > MAX_BUFFERED_BYTES {
            return false;
        }

        while entry.buffered.len() >= MAX_BUFFERED_PAYLOADS
            || entry.buffered_bytes + payload.len() > MAX_BUFFERED_BYTES
        {
            if let Some(evicted) = entry.buffered.pop_front() {
                entry.buffered_bytes = entry.buffered_bytes.saturating_sub(evicted.len());
            } else {
                break;
            }
        }

        if entry.buffered.len() >= MAX_BUFFERED_PAYLOADS
            || entry.buffered_bytes + payload.len() > MAX_BUFFERED_BYTES
        {
            return false;
        }

        entry.buffered.push_back(payload.to_vec());
        entry.buffered_bytes += payload.len();
        true
    }

    fn flush_tcp(&mut self, socket_handle: SocketHandle, handle: u64, callbacks: BridgeCallbacks) {
        let socket = self.sockets.get_mut::<TcpSocket>(socket_handle);
        while socket.can_recv() {
            let Ok(data) = socket.recv(|buffer| {
                let len = buffer.len();
                let mut chunk = Vec::with_capacity(len);
                chunk.extend_from_slice(buffer);
                (len, chunk)
            }) else {
                break;
            };
            if data.is_empty() {
                break;
            }
            unsafe {
                (callbacks.tcp_send)(handle, data.as_ptr(), data.len(), callbacks.context);
            }
            self.stats.tcp_flush_events = self.stats.tcp_flush_events.saturating_add(1);
            self.stats.bytes_emitted = self.stats.bytes_emitted.saturating_add(data.len() as u64);
        }
    }

    fn flush_udp(&mut self, socket_handle: SocketHandle, handle: u64, callbacks: BridgeCallbacks) {
        let socket = self.sockets.get_mut::<UdpSocket>(socket_handle);
        loop {
            match socket.recv() {
                Ok((payload, _meta)) => {
                    let mut chunk = Vec::with_capacity(payload.len());
                    chunk.extend_from_slice(payload);
                    unsafe {
                        (callbacks.udp_send)(
                            handle,
                            chunk.as_ptr(),
                            chunk.len(),
                            callbacks.context,
                        );
                    }
                    self.stats.udp_flush_events = self.stats.udp_flush_events.saturating_add(1);
                    self.stats.bytes_emitted =
                        self.stats.bytes_emitted.saturating_add(chunk.len() as u64);
                }
                Err(_) => break,
            }
        }
    }

    fn notify_close(
        &mut self,
        handle: u64,
        kind: FlowKind,
        reason: &str,
        callbacks: BridgeCallbacks,
    ) {
        if let Some(key) = self.handle_map.get(&handle).cloned() {
            logger::breadcrumb(
                BreadcrumbFlags::FLOW,
                format!(
                    "{:?} handle {} closing reason={} dst={} port={}",
                    kind,
                    handle,
                    reason,
                    ip_string(key.dst_ip),
                    key.dst_port
                ),
            );
        } else {
            logger::breadcrumb(
                BreadcrumbFlags::FLOW,
                format!(
                    "{:?} handle {} closing reason={} (destination unknown)",
                    kind, handle, reason
                ),
            );
        }
        let c_string = CString::new(reason).ok();
        let ptr = c_string
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr());
        unsafe {
            match kind {
                FlowKind::Tcp => (callbacks.tcp_close)(handle, ptr, callbacks.context),
                FlowKind::Udp => (callbacks.udp_close)(handle, ptr, callbacks.context),
            }
        }
        self.remove_flow(handle);
        self.wake.notify_one();
    }
}
