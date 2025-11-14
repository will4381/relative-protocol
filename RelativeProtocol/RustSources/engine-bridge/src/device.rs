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
pub const RING_CAPACITY: usize = 1024;
pub const MAX_EMIT_BATCH: usize = 64;

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
    pub flags: TcpFlags,
    #[allow(dead_code)]
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
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

#[derive(Default)]
struct SharedRing {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
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
    pub fn new(mtu: usize, wake: Arc<Notify>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedRing::default())),
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

    #[allow(dead_code)]
    pub fn mtu(&self) -> usize {
        self.mtu
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
    /// ring is full and the packet had to be dropped.
    pub fn push_inbound(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return true;
        }
        let mut guard = self.inner.lock();
        if guard.inbound.len() >= RING_CAPACITY {
            guard.inbound.pop_front();
        }
        let capped = packet.len().min(self.mtu);
        guard.inbound.push_back(packet[..capped].to_vec());
        self.wake.notify_one();
        true
    }

    /// Drains up to `MAX_EMIT_BATCH` outbound frames. Intended to be called by
    /// the engine after smoltcp transmits frames so Swift can `emitPackets`
    /// without holding the smoltcp device lock.
    pub fn drain_outbound(&self) -> Vec<Vec<u8>> {
        let mut guard = self.inner.lock();
        let mut drained = Vec::new();
        for _ in 0..MAX_EMIT_BATCH.min(guard.outbound.len()) {
            if let Some(frame) = guard.outbound.pop_front() {
                drained.push(frame);
            } else {
                break;
            }
        }
        drained
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
        guard.inbound.pop_front().map(|packet| {
            let rx = TunRxToken { buffer: packet };
            let tx = TunTxToken {
                inner: Arc::clone(&self.inner),
                wake: Arc::clone(&self.wake),
                mtu: self.mtu,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            inner: Arc::clone(&self.inner),
            wake: Arc::clone(&self.wake),
            mtu: self.mtu,
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
        let mut guard = self.inner.lock();
        if guard.outbound.len() >= RING_CAPACITY {
            guard.outbound.pop_front();
        }
        guard.outbound.push_back(frame);
        self.wake.notify_one();
        result
    }
}

pub fn parse_packet<'a>(packet: &'a [u8]) -> Option<ParsedPacket<'a>> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4<'a>(packet: &'a [u8]) -> Option<ParsedPacket<'a>> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0F) * 4;
    if header_len < 20 || header_len > packet.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len > packet.len() {
        return None;
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
        6 => parse_tcp(src, dst, payload),
        17 => parse_udp(src, dst, payload),
        _ => Some(ParsedPacket::Other),
    }
}

fn parse_ipv6<'a>(packet: &'a [u8]) -> Option<ParsedPacket<'a>> {
    if packet.len() < 40 {
        return None;
    }
    let next_header = packet[6];
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if 40 + payload_len > packet.len() {
        return None;
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
        6 => parse_tcp(src, dst, payload),
        17 => parse_udp(src, dst, payload),
        _ => Some(ParsedPacket::Other),
    }
}

fn parse_tcp<'a>(src: IpAddr, dst: IpAddr, payload: &'a [u8]) -> Option<ParsedPacket<'a>> {
    if payload.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let data_offset = usize::from(payload[12] >> 4) * 4;
    if data_offset < 20 || data_offset > payload.len() {
        return None;
    }
    let flags_byte = payload[13];
    let flags = TcpFlags {
        fin: flags_byte & 0x01 != 0,
        rst: flags_byte & 0x04 != 0,
    };
    let segment = &payload[data_offset..];
    Some(ParsedPacket::Tcp(TcpPacket {
        src,
        dst,
        src_port,
        dst_port,
        flags,
        payload: segment,
    }))
}

fn parse_udp<'a>(src: IpAddr, dst: IpAddr, payload: &'a [u8]) -> Option<ParsedPacket<'a>> {
    if payload.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if length < 8 || length > payload.len() {
        return None;
    }
    let datagram = &payload[8..length];
    Some(ParsedPacket::Udp(UdpPacket {
        src,
        dst,
        src_port,
        dst_port,
        payload: datagram,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Notify;

    fn make_device() -> (TunDevice, TunHandle) {
        let wake = Arc::new(Notify::new());
        let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake));
        let handle = device.handle();
        (device, handle)
    }

    #[test]
    fn push_inbound_truncates_to_mtu() {
        let (mut device, handle) = make_device();
        let packet = vec![0x45; DEFAULT_MTU + 256];
        assert!(handle.push_inbound(&packet));

        let (rx, _) = device
            .receive(Instant::from_millis(0))
            .expect("rx token missing");
        let mut captured = Vec::new();
        rx.consume(|buffer| {
            captured.extend_from_slice(buffer);
        });
        assert_eq!(captured.len(), DEFAULT_MTU);
        assert!(captured.iter().all(|byte| *byte == 0x45));
    }

    #[test]
    fn outbound_drains_in_order() {
        let (mut device, handle) = make_device();

        let tx1 = device.transmit(Instant::from_millis(0)).unwrap();
        tx1.consume(16, |buffer| buffer.fill(0xAA));
        let tx2 = device.transmit(Instant::from_millis(0)).unwrap();
        tx2.consume(24, |buffer| buffer.fill(0xBB));

        let frames = handle.drain_outbound();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], vec![0xAA; 16]);
        assert_eq!(frames[1], vec![0xBB; 24]);
        assert!(handle.drain_outbound().is_empty());
    }

    #[test]
    fn inbound_ring_evicts_oldest_when_full() {
        let (mut device, handle) = make_device();
        for idx in 0..=RING_CAPACITY {
            let mut packet = vec![0x45, 0, 0, 0];
            packet.extend_from_slice(&(idx as u32).to_be_bytes());
            handle.push_inbound(&packet);
        }

        for expected in 1..=RING_CAPACITY as u32 {
            let (rx, _) = device
                .receive(Instant::from_millis(0))
                .expect("rx token missing");
            let mut value = [0u8; 4];
            rx.consume(|buffer| value.copy_from_slice(&buffer[4..8]));
            assert_eq!(u32::from_be_bytes(value), expected);
        }
        assert!(device.receive(Instant::from_millis(0)).is_none());
    }
}
