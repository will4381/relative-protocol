//! Tracks TCP/UDP flows owned by the engine.

mod dns;
mod interface;
mod state;
mod transport;

use crate::device::{ParsedPacket, TcpPacket, TunDevice, UdpPacket};
use crate::ffi::{BridgeCallbacks, FlowCounters, FlowStats};
use crate::logger::{self, BreadcrumbFlags};
use crate::policy::{PolicyDecision, PolicyManager, RuleAction, ShapingConfig};
use crate::telemetry::{
    PacketDirection, Telemetry, TelemetryEvent, TELEMETRY_FLAG_DNS, TELEMETRY_FLAG_DNS_RESPONSE,
    TELEMETRY_FLAG_POLICY_BLOCK, TELEMETRY_FLAG_POLICY_SHAPE,
};
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
use std::net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};
use std::num::NonZeroU64;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant as StdInstant};
use tokio::sync::Notify;

pub use state::FlowKind;

use interface::{build_interface_and_sockets, emit_frames};
use state::{
    dial_backoff_delay, ip_string, is_dns_flow, FlowEntry, FlowKey, FlowShaper, FlowStatus,
    MAX_DIAL_ATTEMPTS, UDP_IDLE_TIMEOUT,
};

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
    telemetry: Arc<Telemetry>,
    policy: Arc<PolicyManager>,
}

enum PolicyDisposition {
    Allow,
    Block,
    Shape(ShapingConfig),
}

impl FlowManager {
    pub fn new(
        device: TunDevice,
        wake: Arc<Notify>,
        telemetry: Arc<Telemetry>,
        policy: Arc<PolicyManager>,
    ) -> Self {
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
            telemetry,
            policy,
        }
    }

    pub fn counters(&self) -> FlowCounters {
        self.counters
    }

    pub fn stats(&self) -> FlowStats {
        self.stats
    }

    fn apply_policy_to_flow(&self, key: &FlowKey, kind: FlowKind) -> PolicyDisposition {
        let dst_ip = smolt_to_std_ip(key.dst_ip);
        if let Some(decision) = self.policy.decision_for_ip(&dst_ip) {
            return self.handle_policy_decision(key, kind, decision);
        }
        let literal = ip_string(key.dst_ip);
        if let Some(action) = self.policy.match_host(&literal) {
            return self.handle_policy_decision(
                key,
                kind,
                PolicyDecision {
                    host: literal,
                    action,
                },
            );
        }
        PolicyDisposition::Allow
    }

    fn handle_policy_decision(
        &self,
        key: &FlowKey,
        kind: FlowKind,
        decision: PolicyDecision,
    ) -> PolicyDisposition {
        let host = decision.host;
        let action = decision.action;
        self.record_policy_hit(key, kind, &host, &action);
        match action {
            RuleAction::Block => {
                let message = format!(
                    "{:?} flow {}:{} -> {}:{} blocked by policy (host={})",
                    kind,
                    ip_string(key.src_ip),
                    key.src_port,
                    ip_string(key.dst_ip),
                    key.dst_port,
                    host
                );
                logger::warn(message.as_str());
                logger::breadcrumb(BreadcrumbFlags::FLOW, message);
                PolicyDisposition::Block
            }
            RuleAction::Shape(config) => {
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} flow {}:{} -> {}:{} shaped by policy (host={}, latency={}ms jitter={}ms)",
                        kind,
                        ip_string(key.src_ip),
                        key.src_port,
                        ip_string(key.dst_ip),
                        key.dst_port,
                        host,
                        config.latency_ms,
                        config.jitter_ms
                    ),
                );
                PolicyDisposition::Shape(config)
            }
        }
    }

    fn record_policy_hit(&self, key: &FlowKey, kind: FlowKind, host: &str, action: &RuleAction) {
        let protocol = match kind {
            FlowKind::Tcp => 6,
            FlowKind::Udp => 17,
        };
        let src = smolt_to_std_ip(key.src_ip);
        let dst = smolt_to_std_ip(key.dst_ip);
        let mut event =
            TelemetryEvent::new(protocol, PacketDirection::ClientToNetwork, 0, src, dst);
        event.dns_qname = Some(host.to_string());
        match action {
            RuleAction::Block => event.flags |= TELEMETRY_FLAG_POLICY_BLOCK,
            RuleAction::Shape(_) => event.flags |= TELEMETRY_FLAG_POLICY_SHAPE,
        }
        self.telemetry.record(event);
    }

    pub fn install_callbacks(&mut self, callbacks: BridgeCallbacks) {
        self.callbacks = Some(callbacks);
        self.wake.notify_one();
    }
    fn finalize_closed_flows(&mut self, callbacks: BridgeCallbacks) {
        let closures: Vec<(u64, String)> = self
            .flow_keys
            .values()
            .filter_map(|entry| {
                if entry.kind != FlowKind::Tcp {
                    return None;
                }
                if entry.pending_dial {
                    return None;
                }
                let socket = self.sockets.get::<TcpSocket>(entry.socket);
                let state = socket.state();
                let remote_closed = matches!(
                    state,
                    smoltcp::socket::tcp::State::CloseWait
                        | smoltcp::socket::tcp::State::LastAck
                        | smoltcp::socket::tcp::State::TimeWait
                ) && entry.client_closed;
                let terminal = matches!(state, smoltcp::socket::tcp::State::Closed);
                if entry.ready && (remote_closed || terminal) {
                    logger::breadcrumb(
                        BreadcrumbFlags::FLOW,
                        format!(
                            "finalize tcp handle {} state={state:?} remote_closed={} pending_dial={}",
                            entry.handle, remote_closed, entry.pending_dial
                        ),
                    );
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

    pub fn process_packet(&mut self, packet: &ParsedPacket<'_>) {
        self.record_packet(packet);
        match packet {
            ParsedPacket::Tcp(tcp) => self.handle_tcp_packet(tcp),
            ParsedPacket::Udp(udp) => self.handle_udp_packet(udp),
            ParsedPacket::Other => {}
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
            if packet.flags.fin || packet.flags.rst {
                entry.client_closed = true;
            }
            return;
        }
        let mut shaping = None;
        match self.apply_policy_to_flow(&key, FlowKind::Tcp) {
            PolicyDisposition::Allow => {}
            PolicyDisposition::Block => return,
            PolicyDisposition::Shape(config) => {
                shaping = Some(FlowShaper::new(config));
            }
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
                    client_closed: packet.flags.fin || packet.flags.rst,
                    shaping,
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
        let mut shaping = None;
        match self.apply_policy_to_flow(&key, FlowKind::Udp) {
            PolicyDisposition::Allow => {}
            PolicyDisposition::Block => return,
            PolicyDisposition::Shape(config) => {
                shaping = Some(FlowShaper::new(config));
            }
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
                    client_closed: false,
                    shaping,
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

    fn drain_shaping_queues(&mut self, now: StdInstant) -> bool {
        let mut ready_payloads: Vec<(u64, FlowKind, Vec<u8>)> = Vec::new();
        for entry in self.flow_keys.values_mut() {
            if let Some(shaper) = entry.shaping.as_mut() {
                let handle = entry.handle;
                let kind = entry.kind;
                shaper.drain_ready(now, |payload| {
                    ready_payloads.push((handle, kind, payload));
                });
            }
        }
        let mut did_work = false;
        for (handle, kind, payload) in ready_payloads {
            if self.forward_remote_payload_inner(handle, payload.as_slice(), kind, true) {
                did_work = true;
            }
        }
        did_work
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
        if self.drain_shaping_queues(StdInstant::now()) {
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
                if entry.kind != FlowKind::Udp || !entry.ready {
                    return None;
                }
                if is_dns_flow(key) {
                    return None;
                }
                if now
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

    fn record_packet(&self, packet: &ParsedPacket<'_>) {
        let (protocol, payload_len, src, dst, dns_summary) = match packet {
            ParsedPacket::Tcp(pkt) => (6u8, pkt.payload.len() as u32, pkt.src, pkt.dst, None),
            ParsedPacket::Udp(pkt) => {
                let dns = if pkt.src_port == 53 || pkt.dst_port == 53 {
                    parse_dns_qname(pkt.payload)
                } else {
                    None
                };
                (17u8, pkt.payload.len() as u32, pkt.src, pkt.dst, dns)
            }
            ParsedPacket::Other => return,
        };

        let mut event = TelemetryEvent::new(
            protocol,
            PacketDirection::ClientToNetwork,
            payload_len,
            src,
            dst,
        );
        if let Some((qname, is_response)) = dns_summary {
            event.dns_qname = Some(qname);
            event.dns_response = is_response;
            event.flags |= TELEMETRY_FLAG_DNS;
            if is_response {
                event.flags |= TELEMETRY_FLAG_DNS_RESPONSE;
            }
        }
        self.telemetry.record(event);
    }
}

fn parse_dns_qname(payload: &[u8]) -> Option<(String, bool)> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12usize;
    let mut labels = Vec::new();
    while idx < payload.len() {
        let len = payload[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        if len > 63 || idx + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[idx..idx + len]).ok()?;
        labels.push(label.to_string());
        idx += len;
        if labels.len() >= 32 {
            break;
        }
    }
    if labels.is_empty() {
        return None;
    }
    let qname = labels.join(".");
    let is_response = (flags & 0x8000) != 0;
    Some((qname, is_response))
}

fn smolt_to_std_ip(addr: IpAddress) -> StdIpAddr {
    match addr {
        IpAddress::Ipv4(_) => ip_string(addr)
            .parse()
            .unwrap_or(StdIpAddr::V4(StdIpv4Addr::UNSPECIFIED)),
        IpAddress::Ipv6(_) => ip_string(addr)
            .parse()
            .unwrap_or(StdIpAddr::V6(StdIpv6Addr::UNSPECIFIED)),
    }
}

#[cfg(test)]
mod tests {
    use super::state;
    use super::state::UDP_PACKET_METADATA;
    use super::*;
    use crate::device::{TcpFlags, TunDevice, DEFAULT_MTU};
    use crate::telemetry::{Telemetry, TELEMETRY_FLAG_POLICY_BLOCK, TELEMETRY_FLAG_POLICY_SHAPE};
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
        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let mut manager = FlowManager::new(device, Arc::clone(&wake), telemetry, policy);
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
        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let mut manager = FlowManager::new(device, Arc::clone(&wake), telemetry, policy);
        let harness = Box::new(TestHarness::default());
        let context = Box::into_raw(harness);
        manager.install_callbacks(test_callbacks(context as *mut c_void));

        let tcp_packet = TcpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            src_port: 1000,
            dst_port: 443,
            payload: &[],
            flags: TcpFlags::default(),
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
        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let mut manager = FlowManager::new(device, Arc::clone(&wake), telemetry, policy);

        let tcp_packet = TcpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            src_port: 5000,
            dst_port: 443,
            payload: &[],
            flags: TcpFlags::default(),
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
            assert!(state::buffer_payload(entry, &payload));
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
        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let mut manager = FlowManager::new(device, Arc::clone(&wake), telemetry, policy);
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

    #[test]
    fn policy_block_prevents_tcp_flow() {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let mut manager = FlowManager::new(
            device,
            Arc::clone(&wake),
            Arc::clone(&telemetry),
            Arc::clone(&policy),
        );
        policy.install_rule("*.blocked.test", RuleAction::Block);
        let target_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55));
        policy.observe_dns_mapping("api.blocked.test", &[target_ip], None);

        let tcp_packet = TcpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            dst: target_ip,
            src_port: 4000,
            dst_port: 443,
            payload: &[],
            flags: TcpFlags::default(),
        };

        manager.process_packet(&ParsedPacket::Tcp(tcp_packet));
        assert!(manager.flow_keys.is_empty());
        let (events, _) = manager.telemetry.drain(16);
        assert!(
            events
                .iter()
                .any(|event| event.flags & TELEMETRY_FLAG_POLICY_BLOCK != 0),
            "expected policy block telemetry"
        );
    }

    #[test]
    fn policy_shape_attaches_config_to_flow() {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let mut manager = FlowManager::new(
            device,
            Arc::clone(&wake),
            Arc::clone(&telemetry),
            Arc::clone(&policy),
        );
        let shaping = ShapingConfig {
            latency_ms: 125,
            jitter_ms: 15,
        };
        policy.install_rule("video.example.com", RuleAction::Shape(shaping));
        let target_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
        policy.observe_dns_mapping("video.example.com", &[target_ip], Some(120));

        let udp_packet = UdpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            dst: target_ip,
            src_port: 5353,
            dst_port: 9000,
            payload: &[1, 2, 3, 4],
        };

        manager.process_packet(&ParsedPacket::Udp(udp_packet));
        assert_eq!(manager.flow_keys.len(), 1);
        let entry = manager
            .flow_keys
            .values()
            .next()
            .expect("flow entry missing");
        assert_eq!(entry.shaping.as_ref().map(|s| s.config), Some(shaping));

        let (events, _) = manager.telemetry.drain(16);
        assert!(
            events
                .iter()
                .any(|event| event.flags & TELEMETRY_FLAG_POLICY_SHAPE != 0),
            "expected policy shape telemetry"
        );
    }

    #[test]
    fn shaping_queue_delays_remote_payload_delivery() {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let mut manager = FlowManager::new(
            device,
            Arc::clone(&wake),
            Arc::clone(&telemetry),
            Arc::clone(&policy),
        );
        let shaping = ShapingConfig {
            latency_ms: 0,
            jitter_ms: 0,
        };
        policy.install_rule("delay.example", RuleAction::Shape(shaping));
        let target_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 42));
        policy.observe_dns_mapping("delay.example", &[target_ip], None);

        let udp_packet = UdpPacket {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
            dst: target_ip,
            src_port: 5500,
            dst_port: 8080,
            payload: &[0; 0],
        };
        manager.process_packet(&ParsedPacket::Udp(udp_packet));
        let (&handle, &key) = manager
            .handle_map
            .iter()
            .next()
            .expect("handle missing for shaping test");
        manager.on_dial_result(handle, true, None);
        let payload = vec![9u8, 8, 7];
        assert!(manager.forward_remote_payload(handle, &payload, FlowKind::Udp));
        {
            let entry = manager.flow_keys.get(&key).expect("flow missing");
            let shaper = entry.shaping.as_ref().expect("shaper missing");
            assert!(shaper.has_pending());
        }
        manager.drain_shaping_queues(StdInstant::now());
        {
            let entry = manager.flow_keys.get(&key).expect("flow missing");
            let shaper = entry.shaping.as_ref().expect("shaper missing");
            assert!(!shaper.has_pending());
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
