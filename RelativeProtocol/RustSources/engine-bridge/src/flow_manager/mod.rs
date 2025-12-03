//! Tracks TCP/UDP flows owned by the engine.

pub mod batch;
mod checksum;
mod dial;
mod dns;
mod interface;
mod maintenance;
mod packet_builder;
mod state;
mod transport;

#[cfg(test)]
mod tests;

use crate::device::{ParsedPacket, TcpPacket, TunDevice, UdpPacket};
use crate::ffi::{BridgeCallbacks, FlowCounters, FlowStats};
use crate::logger::{self, BreadcrumbFlags};
use crate::policy::{PolicyDecision, PolicyManager, RuleAction, ShapingConfig};
use crate::telemetry::{
    PacketDirection, Telemetry, TelemetryEvent, TELEMETRY_FLAG_DNS, TELEMETRY_FLAG_DNS_RESPONSE,
    TELEMETRY_FLAG_POLICY_BLOCK, TELEMETRY_FLAG_POLICY_SHAPE,
};
use crossbeam_channel::Receiver;
use libc::{AF_INET, AF_INET6};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{
    tcp::{SendError as TcpSendError, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer},
    udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket},
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use rustc_hash::FxHashMap;
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::CString;
use std::num::NonZeroU64;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant as StdInstant};
use tokio::sync::Notify;

use interface::{allocate_tcp_socket, allocate_udp_socket, build_interface, emit_frames};
use packet_builder::{build_icmp_block, build_tcp_reset, build_udp_response, smolt_to_std_ip};
use state::{
    ip_string, FlowEntry, FlowKey, FlowShaper, FlowStatus, MemoryTracker,
    TCP_BACKPRESSURE_RETRY_MS,
};

pub use batch::CallbackBatch;
pub use state::{FlowKind, SocketBudget};

pub struct FlowManager {
    callbacks: Option<BridgeCallbacks>,
    interface: Interface,
    sockets: SocketSet<'static>,
    device: TunDevice,
    memory: MemoryTracker,
    flow_keys: FxHashMap<FlowKey, FlowEntry>,
    handle_map: FxHashMap<u64, FlowKey>,
    next_flow_id: NonZeroU64,
    counters: FlowCounters,
    wake: Arc<Notify>,
    stats: FlowStats,
    telemetry: Arc<Telemetry>,
    policy: Arc<PolicyManager>,
    /// Reusable buffer for TCP flush operations to avoid allocations
    flush_buffer: Vec<u8>,
    /// Reusable scratch buffer for pending dial keys (avoids per-poll allocation)
    pending_dial_scratch: Vec<FlowKey>,
    /// Reusable scratch buffer for flow closures (avoids per-poll allocation)
    closure_scratch: Vec<(u64, String)>,
    /// Fast PRNG state for jitter calculation (avoids SystemTime::now syscall)
    /// Uses Cell for interior mutability to avoid borrow conflicts
    jitter_state: Cell<u32>,
    /// Lock-free channel receiver for packet ingress from FFI
    packet_rx: Receiver<Vec<u8>>,
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
        socket_budget: SocketBudget,
        packet_rx: Receiver<Vec<u8>>,
    ) -> Self {
        let (device, interface, sockets) = build_interface(device);
        let memory = MemoryTracker::new(socket_budget);
        // Pre-allocate HashMaps with reasonable initial capacity.
        // iOS: With 4MB budget and 8KB per socket, we can have ~500 sockets but want fewer.
        // Desktop: With 16MB budget and 32KB per socket, we can have ~500 sockets.
        #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
        let expected_flows = 64;
        #[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
        let expected_flows = 256;
        Self {
            callbacks: None,
            interface,
            sockets,
            device,
            memory,
            flow_keys: FxHashMap::with_capacity_and_hasher(expected_flows, Default::default()),
            handle_map: FxHashMap::with_capacity_and_hasher(expected_flows, Default::default()),
            next_flow_id: NonZeroU64::new(1).unwrap(),
            counters: FlowCounters::default(),
            wake,
            stats: FlowStats::default(),
            telemetry,
            policy,
            #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
            flush_buffer: Vec::with_capacity(4 * 1024),  // 4KB for iOS
            #[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
            flush_buffer: Vec::with_capacity(16 * 1024), // 16KB for desktop
            #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
            pending_dial_scratch: Vec::with_capacity(16),
            #[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
            pending_dial_scratch: Vec::with_capacity(64),
            #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
            closure_scratch: Vec::with_capacity(8),
            #[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
            closure_scratch: Vec::with_capacity(32),
            jitter_state: Cell::new(0xDEADBEEF), // Non-zero seed for xorshift
            packet_rx,
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

    fn emit_tcp_block_response(&self, packet: &TcpPacket<'_>) {
        let Some(callbacks) = self.callbacks else {
            return;
        };
        if let Some(frame) = build_tcp_reset(packet) {
            emit_frames(callbacks, vec![frame]);
        }
    }

    fn emit_udp_block_response(&self, packet: &UdpPacket<'_>) {
        let Some(callbacks) = self.callbacks else {
            return;
        };
        if let Some(frame) = build_icmp_block(packet) {
            emit_frames(callbacks, vec![frame]);
        }
    }

    pub fn install_callbacks(&mut self, callbacks: BridgeCallbacks) {
        logger::info("CALLBACKS_INSTALLED".to_string());
        self.callbacks = Some(callbacks);
        self.wake.notify_one();
    }
    fn finalize_closed_flows(&mut self, batch: &mut CallbackBatch) {
        // Reuse scratch buffer to avoid per-poll allocation
        self.closure_scratch.clear();
        for entry in self.flow_keys.values() {
            if entry.kind != FlowKind::Tcp {
                continue;
            }
            if entry.pending_dial {
                continue;
            }
            let socket = self.sockets.get::<TcpSocket>(entry.socket);
            let state = socket.state();
            // Client initiated close and socket is in close-related state
            let client_initiated_close = matches!(
                state,
                smoltcp::socket::tcp::State::CloseWait
                    | smoltcp::socket::tcp::State::LastAck
                    | smoltcp::socket::tcp::State::TimeWait
            ) && entry.client_closed;
            // Socket has reached terminal closed state
            let terminal = matches!(state, smoltcp::socket::tcp::State::Closed);
            // Server/bypass side closed and socket reached a finishable state
            let server_initiated_close = entry.server_closed && matches!(
                state,
                smoltcp::socket::tcp::State::FinWait1
                    | smoltcp::socket::tcp::State::FinWait2
                    | smoltcp::socket::tcp::State::Closing
                    | smoltcp::socket::tcp::State::TimeWait
                    | smoltcp::socket::tcp::State::Closed
            );
            if entry.ready && (client_initiated_close || terminal || server_initiated_close) {
                let reason = if client_initiated_close {
                    "client_fin".to_string()
                } else if server_initiated_close {
                    "server_closed".to_string()
                } else {
                    format!("tcp_closed ({state})")
                };
                // Log detailed TCP state for debugging "Operation canceled" issues
                logger::info(format!(
                    "TCP_FINALIZE handle={} state={:?} client_closed={} server_closed={} reason=\"{}\"",
                    entry.handle, state, entry.client_closed, entry.server_closed, reason
                ));
                self.closure_scratch.push((entry.handle, reason));
            }
        }

        // Take ownership of scratch buffer to avoid borrow conflict
        let closures = std::mem::take(&mut self.closure_scratch);
        for (handle, reason) in closures {
            // Add close notification to batch instead of calling callback directly
            batch.add_close(handle, &reason, FlowKind::Tcp);
            // Remove the flow - this cleans up the socket and flow entry
            self.remove_flow(handle);
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
            if let Some(entry) = self.flow_keys.get_mut(&key) {
                entry.server_closed = true;
                let socket = self.sockets.get_mut::<TcpSocket>(entry.socket);
                socket.close();
            }
        }
        self.wake.notify_one();
    }

    pub fn on_udp_close(&mut self, handle: u64) {
        self.remove_flow(handle);
        self.wake.notify_one();
    }

    /// Called when Swift's NWConnection.send() fails for a TCP connection.
    /// This indicates the real network connection has failed and we should
    /// immediately clean up the flow state.
    pub fn on_tcp_send_failed(&mut self, handle: u64, error: Option<&str>) {
        logger::breadcrumb(
            BreadcrumbFlags::FLOW,
            format!(
                "TCP send failed for handle={}, error={:?} - cleaning up flow",
                handle, error
            ),
        );
        // Mark as server closed and remove the flow
        if let Some(key) = self.handle_map.get(&handle).cloned() {
            if let Some(entry) = self.flow_keys.get_mut(&key) {
                entry.server_closed = true;
                // Abort the smoltcp socket to send RST
                let socket = self.sockets.get_mut::<TcpSocket>(entry.socket);
                socket.abort();
            }
        }
        self.remove_flow(handle);
        self.wake.notify_one();
    }

    /// Called when Swift's NWConnection.send() fails for a UDP connection.
    /// This indicates the real network connection has failed and we should
    /// immediately clean up the flow state.
    pub fn on_udp_send_failed(&mut self, handle: u64, error: Option<&str>) {
        logger::breadcrumb(
            BreadcrumbFlags::FLOW,
            format!(
                "UDP send failed for handle={}, error={:?} - cleaning up flow",
                handle, error
            ),
        );
        // Simply remove the flow - UDP has no connection state to manage
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
            PolicyDisposition::Block => {
                self.emit_tcp_block_response(packet);
                return;
            }
            PolicyDisposition::Shape(config) => {
                shaping = Some(FlowShaper::new(config));
            }
        }
        // Dynamic allocation: check memory budget before allocating
        if self.memory.can_allocate_tcp() {
            let socket = allocate_tcp_socket(&mut self.sockets, &self.memory.budget);
            self.memory.allocate_tcp();
            let flow_id = self.new_flow_id();
            let tcp_socket = self.sockets.get_mut::<TcpSocket>(socket);
            let endpoint = IpListenEndpoint {
                addr: Some(key.dst_ip),
                port: key.dst_port,
            };
            let _ = tcp_socket.listen(endpoint);
            let now = StdInstant::now();
            self.flow_keys.insert(
                key,
                FlowEntry {
                    socket,
                    kind: FlowKind::Tcp,
                    handle: flow_id,
                    ready: false,
                    pending_dial: false,
                    dial_attempts: 0,
                    next_redial_at: Some(now),
                    last_activity: now,
                    buffered: VecDeque::new(),
                    buffered_bytes: 0,
                    client_closed: packet.flags.fin || packet.flags.rst,
                    server_closed: false,
                    shaping,
                    backpressure_retry_at: None,
                    backpressure_cooldown_ms: TCP_BACKPRESSURE_RETRY_MS,
                    dial_started_at: None,
                    created_at: now,
                },
            );
            self.handle_map.insert(flow_id, key);
            self.dispatch_pending_dials(now);
        } else {
            self.counters.tcp_admission_fail += 1;
            self.emit_tcp_block_response(packet);
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
            PolicyDisposition::Block => {
                self.emit_udp_block_response(packet);
                return;
            }
            PolicyDisposition::Shape(config) => {
                shaping = Some(FlowShaper::new(config));
            }
        }
        // Dynamic allocation: check memory budget before allocating
        if self.memory.can_allocate_udp() {
            let socket = allocate_udp_socket(&mut self.sockets, &self.memory.budget);
            self.memory.allocate_udp();
            let flow_id = self.new_flow_id();
            let udp_socket = self.sockets.get_mut::<UdpSocket>(socket);
            let endpoint = IpListenEndpoint {
                addr: Some(key.dst_ip),
                port: key.dst_port,
            };
            let _ = udp_socket.bind(endpoint);
            let now = StdInstant::now();
            self.flow_keys.insert(
                key,
                FlowEntry {
                    socket,
                    kind: FlowKind::Udp,
                    handle: flow_id,
                    ready: false,
                    pending_dial: false,
                    dial_attempts: 0,
                    next_redial_at: Some(now),
                    last_activity: now,
                    buffered: VecDeque::new(),
                    buffered_bytes: 0,
                    client_closed: false,
                    server_closed: false,
                    shaping,
                    backpressure_retry_at: None,
                    backpressure_cooldown_ms: TCP_BACKPRESSURE_RETRY_MS,
                    dial_started_at: None,
                    created_at: now,
                },
            );
            self.handle_map.insert(flow_id, key);
            // Buffer the initial UDP payload so it gets sent when dial completes
            if let Some(entry) = self.flow_keys.get_mut(&key) {
                state::buffer_payload(entry, packet.payload);
            }
            self.dispatch_pending_dials(now);
        } else {
            self.counters.udp_admission_fail += 1;
            self.emit_udp_block_response(packet);
        }
    }


    fn remove_flow(&mut self, handle: u64) {
        if let Some(key) = self.handle_map.remove(&handle) {
            let entry = self.flow_keys.remove(&key);
            if let Some(entry) = entry {
                match entry.kind {
                    FlowKind::Tcp => {
                        let socket = self.sockets.get_mut::<TcpSocket>(entry.socket);
                        socket.abort();
                        self.sockets.remove(entry.socket);
                        self.memory.deallocate_tcp();
                    }
                    FlowKind::Udp => {
                        let socket = self.sockets.get_mut::<UdpSocket>(entry.socket);
                        socket.close();
                        self.sockets.remove(entry.socket);
                        self.memory.deallocate_udp();
                    }
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
        // Log close reason for debugging "Operation canceled" issues
        logger::info(format!(
            "CLOSE_NOTIFY {:?} handle={} reason=\"{}\"",
            kind, handle, reason
        ));

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

    fn new_flow_id(&mut self) -> u64 {
        let id = self.next_flow_id.get();
        let next = self.next_flow_id.get().wrapping_add(1);
        self.next_flow_id = NonZeroU64::new(next).unwrap_or(NonZeroU64::new(1).unwrap());
        id
    }

    /// Poll the flow manager and collect callbacks to execute.
    ///
    /// Returns `(did_work, batch)` where:
    /// - `did_work` indicates if any network activity occurred
    /// - `batch` contains all callbacks to execute (should be executed outside the lock)
    #[inline]
    pub fn poll(&mut self, now: Instant) -> (bool, CallbackBatch) {
        let mut batch = CallbackBatch::new();

        if self.callbacks.is_none() {
            return (false, batch);
        }

        let mut did_work = false;
        let now_std = StdInstant::now();
        self.stats.poll_iterations = self.stats.poll_iterations.saturating_add(1);

        // Drain packets from the lock-free ingress channel
        // These packets were pushed by handle_packet() from the FFI thread
        while let Ok(packet_data) = self.packet_rx.try_recv() {
            // Re-parse the packet (validation already done in handle_packet)
            if let Ok(parsed) = crate::device::parse_packet_validated(&packet_data) {
                self.process_packet(&parsed);
                did_work = true;
            }
        }

        let poll_result = self.interface.poll(now, &mut self.device, &mut self.sockets);
        if poll_result {
            did_work = true;
        }
        let frames = self.device.handle().drain_outbound();
        if !frames.is_empty() {
            did_work = true;
            let bytes: usize = frames.iter().map(|frame| frame.len()).sum();
            let frame_count = frames.len() as u64;
            batch.add_frames(frames);
            self.stats.frames_emitted = self.stats.frames_emitted.saturating_add(frame_count);
            self.stats.bytes_emitted = self.stats.bytes_emitted.saturating_add(bytes as u64);
        }
        self.flush_outbound(&mut batch);
        self.finalize_closed_flows(&mut batch);
        if self.dispatch_pending_dials_batched(now_std, &mut batch) {
            did_work = true;
        }
        if self.flush_ready_buffers(now_std) {
            did_work = true;
        }
        if self.drain_shaping_queues(now_std) {
            did_work = true;
        }
        if self.prune_idle_udp_flows_batched(now_std, &mut batch) {
            did_work = true;
        }
        // Prune flows with timed-out dial operations
        if self.prune_timed_out_dials_batched(now_std, &mut batch) {
            did_work = true;
        }
        // Prune TCP flows stuck in connecting state
        if self.prune_stale_tcp_flows_batched(now_std, &mut batch) {
            did_work = true;
        }
        (did_work, batch)
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
    let mut labels: smallvec::SmallVec<[String; 8]> = smallvec::SmallVec::new();
    let mut jumps = 0;
    const MAX_JUMPS: usize = 10; // Prevent infinite loops from malformed packets

    while idx < payload.len() {
        let len_byte = payload[idx];

        // Check for DNS compression pointer (RFC 1035 section 4.1.4)
        // Compression pointers start with 0xC0-0xFF (top two bits set)
        if (len_byte & 0xC0) == 0xC0 {
            // This is a compression pointer
            if idx + 1 >= payload.len() {
                return None;
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                // Too many jumps, likely malformed or malicious
                return None;
            }
            // Get the offset from the pointer
            let offset = (u16::from_be_bytes([len_byte & 0x3F, payload[idx + 1]])) as usize;
            if offset >= payload.len() || offset >= idx {
                // Invalid offset (must point backwards)
                return None;
            }
            idx = offset;
            continue;
        }

        let len = len_byte as usize;
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
