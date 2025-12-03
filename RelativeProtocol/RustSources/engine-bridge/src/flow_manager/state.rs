use super::*;
use crate::policy::ShapingConfig;
use std::collections::VecDeque;

pub(super) const UDP_PACKET_METADATA: usize = 32;
pub(super) const MAX_DIAL_ATTEMPTS: u8 = 3;
pub(super) const DIAL_BACKOFF_BASE_MS: u64 = 50;
pub(super) const UDP_IDLE_TIMEOUT: StdDuration = StdDuration::from_secs(10);
/// Per-flow buffering limits - reduced for iOS to prevent jetsam
#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
pub(super) const MAX_BUFFERED_PAYLOADS: usize = 4;
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
pub(super) const MAX_BUFFERED_PAYLOADS: usize = 8;

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
pub(super) const MAX_BUFFERED_BYTES: usize = 8 * 1024;   // 8KB for iOS
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
pub(super) const MAX_BUFFERED_BYTES: usize = 64 * 1024;  // 64KB for desktop

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
pub(super) const MAX_SHAPED_PAYLOADS: usize = 8;
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
pub(super) const MAX_SHAPED_PAYLOADS: usize = 32;

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
pub(super) const MAX_SHAPED_BYTES: usize = 32 * 1024;    // 32KB for iOS
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
pub(super) const MAX_SHAPED_BYTES: usize = 256 * 1024;   // 256KB for desktop
pub(super) const TCP_BACKPRESSURE_RETRY_MS: u64 = 10;
pub(super) const TCP_BACKPRESSURE_MAX_COOLDOWN_MS: u64 = 200;
/// Maximum time a dial operation can remain pending before being timed out (30 seconds)
pub(super) const DIAL_PENDING_TIMEOUT: StdDuration = StdDuration::from_secs(30);
/// Maximum time a TCP connection can stay in SYN_SENT state before being closed (15 seconds)
pub(super) const TCP_SYN_SENT_TIMEOUT: StdDuration = StdDuration::from_secs(15);

/// Default values for dynamic socket allocation
/// iOS Network Extensions have strict memory limits (15-50MB total).
/// We use conservative defaults to avoid jetsam kills.
/// Use `--features ios-memory-profile` to test iOS constraints on any platform.
#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
const DEFAULT_MEMORY_BUDGET: usize = 4 * 1024 * 1024;  // 4MB for iOS
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
const DEFAULT_MEMORY_BUDGET: usize = 16 * 1024 * 1024; // 16MB for desktop/server

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
const DEFAULT_TCP_RX_BUFFER: usize = 4 * 1024;         // 4KB for iOS
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
const DEFAULT_TCP_RX_BUFFER: usize = 16 * 1024;        // 16KB for desktop/server

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
const DEFAULT_TCP_TX_BUFFER: usize = 4 * 1024;         // 4KB for iOS
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
const DEFAULT_TCP_TX_BUFFER: usize = 32 * 1024;        // 32KB for desktop/server

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile"))]
const DEFAULT_UDP_BUFFER: usize = 4 * 1024;            // 4KB for iOS
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", feature = "ios-memory-profile")))]
const DEFAULT_UDP_BUFFER: usize = 16 * 1024;           // 16KB for desktop/server

/// Configuration for dynamic socket allocation with memory budget.
#[derive(Clone, Copy, Debug)]
pub struct SocketBudget {
    /// Total memory budget for socket buffers in bytes.
    pub memory_budget: usize,
    /// TCP receive buffer size per socket.
    pub tcp_rx_buffer_size: usize,
    /// TCP transmit buffer size per socket.
    pub tcp_tx_buffer_size: usize,
    /// UDP buffer size per socket (rx + tx combined).
    pub udp_buffer_size: usize,
}

impl SocketBudget {
    /// Create from BridgeConfig values. Uses defaults for zero values.
    pub fn from_config(
        memory_budget: u32,
        tcp_rx: u32,
        tcp_tx: u32,
        udp_buf: u32,
    ) -> Self {
        Self {
            memory_budget: if memory_budget == 0 { DEFAULT_MEMORY_BUDGET } else { memory_budget as usize },
            tcp_rx_buffer_size: if tcp_rx == 0 { DEFAULT_TCP_RX_BUFFER } else { tcp_rx as usize },
            tcp_tx_buffer_size: if tcp_tx == 0 { DEFAULT_TCP_TX_BUFFER } else { tcp_tx as usize },
            udp_buffer_size: if udp_buf == 0 { DEFAULT_UDP_BUFFER } else { udp_buf as usize },
        }
    }

    /// Memory cost for a single TCP socket.
    pub fn tcp_socket_cost(&self) -> usize {
        self.tcp_rx_buffer_size + self.tcp_tx_buffer_size
    }

    /// Memory cost for a single UDP socket.
    pub fn udp_socket_cost(&self) -> usize {
        // UDP uses rx + tx buffers plus metadata overhead
        self.udp_buffer_size * 2 + UDP_PACKET_METADATA * 16
    }
}

impl Default for SocketBudget {
    fn default() -> Self {
        Self {
            memory_budget: DEFAULT_MEMORY_BUDGET,
            tcp_rx_buffer_size: DEFAULT_TCP_RX_BUFFER,
            tcp_tx_buffer_size: DEFAULT_TCP_TX_BUFFER,
            udp_buffer_size: DEFAULT_UDP_BUFFER,
        }
    }
}

/// Tracks current memory usage for dynamic socket allocation.
#[derive(Debug, Default)]
pub struct MemoryTracker {
    pub current_usage: usize,
    pub budget: SocketBudget,
    pub tcp_socket_count: usize,
    pub udp_socket_count: usize,
}

impl MemoryTracker {
    pub fn new(budget: SocketBudget) -> Self {
        Self {
            current_usage: 0,
            budget,
            tcp_socket_count: 0,
            udp_socket_count: 0,
        }
    }

    /// Check if we can allocate a TCP socket within budget.
    pub fn can_allocate_tcp(&self) -> bool {
        self.current_usage + self.budget.tcp_socket_cost() <= self.budget.memory_budget
    }

    /// Check if we can allocate a UDP socket within budget.
    pub fn can_allocate_udp(&self) -> bool {
        self.current_usage + self.budget.udp_socket_cost() <= self.budget.memory_budget
    }

    /// Record TCP socket allocation.
    pub fn allocate_tcp(&mut self) {
        self.current_usage += self.budget.tcp_socket_cost();
        self.tcp_socket_count += 1;
    }

    /// Record UDP socket allocation.
    pub fn allocate_udp(&mut self) {
        self.current_usage += self.budget.udp_socket_cost();
        self.udp_socket_count += 1;
    }

    /// Record TCP socket deallocation.
    pub fn deallocate_tcp(&mut self) {
        self.current_usage = self.current_usage.saturating_sub(self.budget.tcp_socket_cost());
        self.tcp_socket_count = self.tcp_socket_count.saturating_sub(1);
    }

    /// Record UDP socket deallocation.
    pub fn deallocate_udp(&mut self) {
        self.current_usage = self.current_usage.saturating_sub(self.budget.udp_socket_cost());
        self.udp_socket_count = self.udp_socket_count.saturating_sub(1);
    }
}

#[derive(Debug, Clone)]
pub(super) struct FlowEntry {
    pub(super) socket: SocketHandle,
    pub(super) kind: FlowKind,
    pub(super) handle: u64,
    pub(super) ready: bool,
    pub(super) pending_dial: bool,
    pub(super) dial_attempts: u8,
    pub(super) next_redial_at: Option<StdInstant>,
    pub(super) last_activity: StdInstant,
    pub(super) buffered: VecDeque<Vec<u8>>,
    pub(super) buffered_bytes: usize,
    pub(super) client_closed: bool,
    /// Server/bypass side closed (NWTCPConnection closed)
    pub(super) server_closed: bool,
    pub(super) shaping: Option<FlowShaper>,
    pub(super) backpressure_retry_at: Option<StdInstant>,
    pub(super) backpressure_cooldown_ms: u64,
    /// When the current dial operation started (for timeout tracking)
    pub(super) dial_started_at: Option<StdInstant>,
    /// When the flow was created (for SYN_SENT timeout tracking)
    pub(super) created_at: StdInstant,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub enum FlowKind {
    Tcp,
    Udp,
}

pub enum FlowStatus {
    Ok,
    Backpressure(&'static str),
    Closed(&'static str),
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub(super) struct FlowKey {
    pub(super) src_ip: IpAddress,
    pub(super) src_port: u16,
    pub(super) dst_ip: IpAddress,
    pub(super) dst_port: u16,
    pub(super) kind: FlowKind,
}

impl FlowKey {
    pub(super) fn from_tcp(packet: &TcpPacket<'_>) -> Self {
        FlowKey {
            src_ip: ip_address_from_std(packet.src),
            src_port: packet.src_port,
            dst_ip: ip_address_from_std(packet.dst),
            dst_port: packet.dst_port,
            kind: FlowKind::Tcp,
        }
    }

    pub(super) fn from_udp(packet: &UdpPacket<'_>) -> Self {
        FlowKey {
            src_ip: ip_address_from_std(packet.src),
            src_port: packet.src_port,
            dst_ip: ip_address_from_std(packet.dst),
            dst_port: packet.dst_port,
            kind: FlowKind::Udp,
        }
    }
}

pub(super) fn ip_string(ip: IpAddress) -> String {
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

pub(super) fn dial_backoff_delay(attempt: u8) -> StdDuration {
    let shift = attempt.saturating_sub(1).min(4) as u32;
    let multiplier = 1u64 << shift;
    StdDuration::from_millis(DIAL_BACKOFF_BASE_MS * multiplier)
}

pub(super) fn buffer_payload(entry: &mut FlowEntry, payload: &[u8]) -> bool {
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

#[derive(Debug, Clone)]
pub(super) struct FlowShaper {
    pub(super) config: ShapingConfig,
    queue: VecDeque<ShapedPayload>,
    queued_bytes: usize,
}

#[derive(Debug, Clone)]
struct ShapedPayload {
    ready_at: StdInstant,
    payload: Vec<u8>,
}

impl FlowShaper {
    pub(super) fn new(config: ShapingConfig) -> Self {
        Self {
            config,
            queue: VecDeque::new(),
            queued_bytes: 0,
        }
    }

    pub(super) fn enqueue(&mut self, payload: &[u8], ready_at: StdInstant) -> bool {
        if payload.is_empty() {
            return true;
        }
        if payload.len() > MAX_SHAPED_BYTES {
            return false;
        }
        while self.queue.len() >= MAX_SHAPED_PAYLOADS
            || self.queued_bytes + payload.len() > MAX_SHAPED_BYTES
        {
            if let Some(evicted) = self.queue.pop_front() {
                self.queued_bytes = self.queued_bytes.saturating_sub(evicted.payload.len());
            } else {
                break;
            }
        }
        if self.queue.len() >= MAX_SHAPED_PAYLOADS
            || self.queued_bytes + payload.len() > MAX_SHAPED_BYTES
        {
            return false;
        }
        self.queue.push_back(ShapedPayload {
            ready_at,
            payload: payload.to_vec(),
        });
        self.queued_bytes += payload.len();
        true
    }

    pub(super) fn drain_ready<F>(&mut self, now: StdInstant, mut visitor: F)
    where
        F: FnMut(Vec<u8>),
    {
        while let Some(front) = self.queue.front() {
            if front.ready_at > now {
                break;
            }
            let payload = self.queue.pop_front().map(|item| item.payload).unwrap();
            self.queued_bytes = self.queued_bytes.saturating_sub(payload.len());
            visitor(payload);
        }
    }

    #[cfg(test)]
    pub(super) fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }
}
