use super::*;
use crate::policy::ShapingConfig;
use std::collections::VecDeque;

pub(super) const TCP_SOCKET_COUNT: usize = 128;
pub(super) const UDP_SOCKET_COUNT: usize = 128;
pub(super) const TCP_RX_BUFFER_SIZE: usize = 16 * 1024;
pub(super) const TCP_TX_BUFFER_SIZE: usize = 16 * 1024;
pub(super) const UDP_PACKET_METADATA: usize = 64;
pub(super) const UDP_BUFFER_SIZE: usize = 32 * 1024;
pub(super) const MAX_DIAL_ATTEMPTS: u8 = 3;
pub(super) const DIAL_BACKOFF_BASE_MS: u64 = 50;
pub(super) const UDP_IDLE_TIMEOUT: StdDuration = StdDuration::from_secs(10);
pub(super) const MAX_BUFFERED_PAYLOADS: usize = 8;
pub(super) const MAX_BUFFERED_BYTES: usize = 64 * 1024;
pub(super) const MAX_SHAPED_PAYLOADS: usize = 32;
pub(super) const MAX_SHAPED_BYTES: usize = 256 * 1024;

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
    pub(super) shaping: Option<FlowShaper>,
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

pub(super) fn is_dns_flow(key: &FlowKey) -> bool {
    key.src_port == 53 || key.dst_port == 53
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
