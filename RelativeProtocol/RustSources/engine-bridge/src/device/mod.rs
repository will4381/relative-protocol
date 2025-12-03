//! Shared TUN device abstraction backed by lock-free-ish ring buffers.
//! Provides both the smoltcp `Device` implementation used by the engine
//! thread and a lightweight handle Swift/Rust FFI paths can use to push
//! inbound packets or drain outbound frames.

use parking_lot::Mutex;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Notify;

pub const DEFAULT_MTU: usize = 1280;
pub const MAX_EMIT_BATCH: usize = 64;

/// Detailed error information for packet parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Packet is empty
    EmptyPacket,
    /// IP version is not 4 or 6
    UnsupportedIpVersion(u8),
    /// IPv4 header is malformed (too short, bad header length, etc.)
    MalformedIpv4Header,
    /// IPv6 header is malformed (too short, payload length mismatch, etc.)
    MalformedIpv6Header,
    /// TCP segment is malformed (too short, bad data offset, etc.)
    MalformedTcpSegment,
    /// UDP datagram is malformed (too short, length mismatch, etc.)
    MalformedUdpDatagram,
}

impl ParseError {
    /// Returns true if this is an IP-layer error (for counter classification).
    #[allow(dead_code)]
    pub fn is_ip_error(&self) -> bool {
        matches!(
            self,
            Self::EmptyPacket
                | Self::UnsupportedIpVersion(_)
                | Self::MalformedIpv4Header
                | Self::MalformedIpv6Header
        )
    }

    /// Returns true if this is a TCP error.
    #[allow(dead_code)]
    pub fn is_tcp_error(&self) -> bool {
        matches!(self, Self::MalformedTcpSegment)
    }

    /// Returns true if this is a UDP error.
    #[allow(dead_code)]
    pub fn is_udp_error(&self) -> bool {
        matches!(self, Self::MalformedUdpDatagram)
    }

    /// Returns a brief description for logging.
    pub fn description(&self) -> &'static str {
        match self {
            Self::EmptyPacket => "empty packet",
            Self::UnsupportedIpVersion(_) => "unsupported IP version",
            Self::MalformedIpv4Header => "malformed IPv4 header",
            Self::MalformedIpv6Header => "malformed IPv6 header",
            Self::MalformedTcpSegment => "malformed TCP segment",
            Self::MalformedUdpDatagram => "malformed UDP datagram",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParsedPacket<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Other,
}

#[derive(Debug, Clone)]
pub struct TcpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub flags: TcpFlags,
    #[allow(dead_code)]
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Debug, Clone)]
pub struct UdpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    #[allow(dead_code)]
    pub payload: &'a [u8],
}

struct SharedRing {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl SharedRing {
    fn new(capacity: usize) -> Self {
        Self {
            inbound: VecDeque::with_capacity(capacity),
            outbound: VecDeque::with_capacity(capacity),
            capacity,
        }
    }
}

/// Device exposed to smoltcp. All state lives inside the shared ring so the
/// device itself remains `Clone` + lightweight.
#[derive(Clone)]
pub struct TunDevice {
    inner: Arc<Mutex<SharedRing>>,
    wake: Arc<Notify>,
    mtu: usize,
}

/// Handle used by the FFI boundary to push inbound frames or drain outbound
/// frames without borrowing the smoltcp device mutably.
#[derive(Clone)]
pub struct TunHandle {
    inner: Arc<Mutex<SharedRing>>,
    wake: Arc<Notify>,
    mtu: usize,
}

impl TunDevice {
    pub fn new(mtu: usize, wake: Arc<Notify>, ring_capacity: usize) -> Self {
        let capacity = ring_capacity.max(16); // Minimum 16 for safety
        Self {
            inner: Arc::new(Mutex::new(SharedRing::new(capacity))),
            wake,
            mtu: mtu.max(576),
        }
    }

    pub fn handle(&self) -> TunHandle {
        TunHandle {
            inner: Arc::clone(&self.inner),
            wake: Arc::clone(&self.wake),
            mtu: self.mtu,
        }
    }

    pub fn device_capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

impl TunHandle {
    /// Pushes a copy of `packet` into the inbound ring. Returns `false` if the
    /// ring is full and the packet had to be dropped, or if the packet fails
    /// basic validation.
    pub fn push_inbound(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return true;
        }

        // Basic packet validation before enqueueing
        if !Self::validate_packet(packet) {
            return false;
        }

        let mut guard = self.inner.lock();
        if guard.inbound.len() >= guard.capacity {
            guard.inbound.pop_front();
        }
        let capped = packet.len().min(self.mtu);
        guard.inbound.push_back(packet[..capped].to_vec());
        drop(guard);
        self.wake.notify_one();
        true
    }

    /// Validates that a packet has a valid IP header structure.
    /// Returns `true` if the packet appears to be a valid IP packet.
    fn validate_packet(packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }

        let version = packet[0] >> 4;
        match version {
            4 => Self::validate_ipv4(packet),
            6 => Self::validate_ipv6(packet),
            _ => false, // Invalid IP version
        }
    }

    fn validate_ipv4(packet: &[u8]) -> bool {
        // Minimum IPv4 header is 20 bytes
        if packet.len() < 20 {
            return false;
        }

        let ihl = (packet[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        // IHL must be at least 5 (20 bytes)
        if ihl < 5 || header_len > packet.len() {
            return false;
        }

        // Total length field
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;

        // Total length must be at least the header length and not exceed packet
        if total_len < header_len || total_len > packet.len() {
            return false;
        }

        // Protocol field must be valid (not 0)
        // Actually protocol 0 (HOPOPT) is valid for IPv6, but not typically seen in IPv4
        // Allow any protocol since there are many valid ones

        true
    }

    fn validate_ipv6(packet: &[u8]) -> bool {
        // IPv6 header is always 40 bytes
        if packet.len() < 40 {
            return false;
        }

        // Payload length field
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;

        // Payload length should not exceed remaining packet length
        if 40 + payload_len > packet.len() {
            return false;
        }

        true
    }

    /// Drains up to `MAX_EMIT_BATCH` outbound frames. Intended to be called by
    /// the engine after smoltcp transmits frames so Swift can `emitPackets`
    /// without holding the smoltcp device lock.
    pub fn drain_outbound(&self) -> Vec<Vec<u8>> {
        let mut guard = self.inner.lock();
        let drain_count = MAX_EMIT_BATCH.min(guard.outbound.len());
        guard.outbound.drain(..drain_count).collect()
    }

    /// Returns the current number of packets in the inbound queue.
    pub fn inbound_queue_len(&self) -> usize {
        self.inner.lock().inbound.len()
    }
}

impl Device for TunDevice {
    type RxToken<'a>
        = TunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut guard = self.inner.lock();
        let capacity = guard.capacity;
        guard.inbound.pop_front().map(|packet| {
            let rx = TunRxToken { buffer: packet };
            let tx = TunTxToken {
                inner: Arc::clone(&self.inner),
                wake: Arc::clone(&self.wake),
                mtu: self.mtu,
                capacity,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let capacity = self.inner.lock().capacity;
        Some(TunTxToken {
            inner: Arc::clone(&self.inner),
            wake: Arc::clone(&self.wake),
            mtu: self.mtu,
            capacity,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.device_capabilities()
    }
}

pub struct TunRxToken {
    buffer: Vec<u8>,
}

pub struct TunTxToken {
    inner: Arc<Mutex<SharedRing>>,
    wake: Arc<Notify>,
    mtu: usize,
    capacity: usize,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self.buffer;
        f(&mut buffer)
    }
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len.min(self.mtu)];
        let result = f(&mut frame);

        // Strip ECN flags from outbound TCP SYN-ACK packets
        // iOS rejects SYN-ACK with ECE if ECN wasn't negotiated in the original SYN
        // Since smoltcp doesn't implement ECN negotiation, we defensively strip these flags
        if frame.len() >= 40 {
            let version = frame[0] >> 4;
            if version == 4 && frame[9] == 6 {
                let header_len = ((frame[0] & 0x0F) as usize) * 4;
                if frame.len() >= header_len + 20 {
                    let flags = frame[header_len + 13];
                    let is_syn_ack = (flags & 0x12) == 0x12; // SYN + ACK
                    let has_ecn = (flags & 0xC0) != 0; // ECE or CWR

                    if is_syn_ack && has_ecn {
                        // Strip ECE (0x40) and CWR (0x80) flags
                        frame[header_len + 13] &= !0xC0;
                        // Recalculate TCP checksum
                        recalculate_tcp_checksum_ipv4(&mut frame, header_len);
                    }
                }
            }
        }

        let mut guard = self.inner.lock();
        if guard.outbound.len() >= self.capacity {
            guard.outbound.pop_front();
        }
        guard.outbound.push_back(frame);
        self.wake.notify_one();
        result
    }
}

// ============================================================================
// Validated Parsing (with detailed error information)
// ============================================================================

/// Parse a packet with detailed error reporting.
/// Returns Ok(ParsedPacket) on success, or Err(ParseError) with specific failure reason.
pub fn parse_packet_validated<'a>(packet: &'a [u8]) -> Result<ParsedPacket<'a>, ParseError> {
    if packet.is_empty() {
        return Err(ParseError::EmptyPacket);
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_validated(packet),
        6 => parse_ipv6_validated(packet),
        _ => Err(ParseError::UnsupportedIpVersion(version)),
    }
}

fn parse_ipv4_validated<'a>(packet: &'a [u8]) -> Result<ParsedPacket<'a>, ParseError> {
    if packet.len() < 20 {
        return Err(ParseError::MalformedIpv4Header);
    }
    let header_len = usize::from(packet[0] & 0x0F) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err(ParseError::MalformedIpv4Header);
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len > packet.len() {
        return Err(ParseError::MalformedIpv4Header);
    }
    let protocol = packet[9];
    let src = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let payload = &packet[header_len..total_len];
    match protocol {
        6 => parse_tcp_validated(src, dst, payload),
        17 => parse_udp_validated(src, dst, payload),
        _ => Ok(ParsedPacket::Other),
    }
}

fn parse_ipv6_validated<'a>(packet: &'a [u8]) -> Result<ParsedPacket<'a>, ParseError> {
    if packet.len() < 40 {
        return Err(ParseError::MalformedIpv6Header);
    }
    let next_header = packet[6];
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if 40 + payload_len > packet.len() {
        return Err(ParseError::MalformedIpv6Header);
    }
    let src = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([packet[8], packet[9]]),
        u16::from_be_bytes([packet[10], packet[11]]),
        u16::from_be_bytes([packet[12], packet[13]]),
        u16::from_be_bytes([packet[14], packet[15]]),
        u16::from_be_bytes([packet[16], packet[17]]),
        u16::from_be_bytes([packet[18], packet[19]]),
        u16::from_be_bytes([packet[20], packet[21]]),
        u16::from_be_bytes([packet[22], packet[23]]),
    ));
    let dst = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([packet[24], packet[25]]),
        u16::from_be_bytes([packet[26], packet[27]]),
        u16::from_be_bytes([packet[28], packet[29]]),
        u16::from_be_bytes([packet[30], packet[31]]),
        u16::from_be_bytes([packet[32], packet[33]]),
        u16::from_be_bytes([packet[34], packet[35]]),
        u16::from_be_bytes([packet[36], packet[37]]),
        u16::from_be_bytes([packet[38], packet[39]]),
    ));
    let payload = &packet[40..40 + payload_len];
    match next_header {
        6 => parse_tcp_validated(src, dst, payload),
        17 => parse_udp_validated(src, dst, payload),
        _ => Ok(ParsedPacket::Other),
    }
}

fn parse_tcp_validated<'a>(
    src: IpAddr,
    dst: IpAddr,
    payload: &'a [u8],
) -> Result<ParsedPacket<'a>, ParseError> {
    if payload.len() < 20 {
        return Err(ParseError::MalformedTcpSegment);
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let seq_number = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ack_number = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let data_offset = usize::from(payload[12] >> 4) * 4;
    if data_offset < 20 || data_offset > payload.len() {
        return Err(ParseError::MalformedTcpSegment);
    }
    let flags_byte = payload[13];
    let flags = TcpFlags {
        syn: flags_byte & 0x02 != 0,
        ack: flags_byte & 0x10 != 0,
        fin: flags_byte & 0x01 != 0,
        rst: flags_byte & 0x04 != 0,
    };
    let segment = &payload[data_offset..];
    Ok(ParsedPacket::Tcp(TcpPacket {
        src,
        dst,
        src_port,
        dst_port,
        seq_number,
        ack_number,
        flags,
        payload: segment,
    }))
}

fn parse_udp_validated<'a>(
    src: IpAddr,
    dst: IpAddr,
    payload: &'a [u8],
) -> Result<ParsedPacket<'a>, ParseError> {
    if payload.len() < 8 {
        return Err(ParseError::MalformedUdpDatagram);
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if length < 8 || length > payload.len() {
        return Err(ParseError::MalformedUdpDatagram);
    }
    let datagram = &payload[8..length];
    Ok(ParsedPacket::Udp(UdpPacket {
        src,
        dst,
        src_port,
        dst_port,
        payload: datagram,
    }))
}

/// Recalculate TCP checksum for an IPv4 packet after modifying TCP header fields.
/// This function zeros the existing checksum, computes the new one, and writes it back.
fn recalculate_tcp_checksum_ipv4(packet: &mut [u8], ip_header_len: usize) {
    // Minimum sizes check
    if packet.len() < ip_header_len + 20 {
        return;
    }

    // TCP length = IP total length - IP header length
    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let tcp_len = ip_total_len.saturating_sub(ip_header_len);

    if tcp_len < 20 || packet.len() < ip_header_len + tcp_len {
        return;
    }

    // Zero the checksum field (offset 16-17 within TCP header)
    let checksum_offset = ip_header_len + 16;
    if packet.len() > checksum_offset + 1 {
        packet[checksum_offset] = 0;
        packet[checksum_offset + 1] = 0;
    }

    // Calculate pseudo-header sum
    let mut sum: u32 = 0;

    // Source IP (bytes 12-15)
    sum += u32::from(u16::from_be_bytes([packet[12], packet[13]]));
    sum += u32::from(u16::from_be_bytes([packet[14], packet[15]]));

    // Destination IP (bytes 16-19)
    sum += u32::from(u16::from_be_bytes([packet[16], packet[17]]));
    sum += u32::from(u16::from_be_bytes([packet[18], packet[19]]));

    // Protocol (TCP = 6)
    sum += 6u32;

    // TCP length
    sum += tcp_len as u32;

    // Sum TCP header + data (16-bit words)
    let tcp_start = ip_header_len;
    let mut i = tcp_start;
    while i + 1 < packet.len() && i + 1 < tcp_start + tcp_len {
        sum += u32::from(u16::from_be_bytes([packet[i], packet[i + 1]]));
        i += 2;
    }
    // Handle odd byte
    if i < packet.len() && i < tcp_start + tcp_len {
        sum += u32::from(packet[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    let checksum = !sum as u16;

    // Write checksum back
    let checksum_bytes = checksum.to_be_bytes();
    packet[checksum_offset] = checksum_bytes[0];
    packet[checksum_offset + 1] = checksum_bytes[1];
}

#[cfg(test)]
mod tests;
