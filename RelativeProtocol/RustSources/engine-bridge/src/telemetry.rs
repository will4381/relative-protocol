use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::logger::{self, BreadcrumbFlags};

const MAX_EVENTS: usize = 4096;

pub const TELEMETRY_FLAG_DNS: u8 = 0x01;
pub const TELEMETRY_FLAG_DNS_RESPONSE: u8 = 0x02;
pub const TELEMETRY_FLAG_POLICY_BLOCK: u8 = 0x04;
pub const TELEMETRY_FLAG_POLICY_SHAPE: u8 = 0x08;

#[derive(Clone, Copy, Debug)]
pub enum PacketDirection {
    ClientToNetwork,
    #[allow(dead_code)]
    NetworkToClient,
}

#[derive(Clone, Debug)]
pub struct TelemetryEvent {
    pub timestamp_ms: u64,
    pub protocol: u8,
    pub direction: PacketDirection,
    pub payload_len: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dns_qname: Option<String>,
    pub dns_response: bool,
    pub flags: u8,
}

impl TelemetryEvent {
    pub fn new(
        protocol: u8,
        direction: PacketDirection,
        payload_len: u32,
        src: IpAddr,
        dst: IpAddr,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            timestamp_ms,
            protocol,
            direction,
            payload_len,
            src,
            dst,
            dns_qname: None,
            dns_response: false,
            flags: 0,
        }
    }
}

#[derive(Default)]
struct TelemetryInner {
    events: VecDeque<TelemetryEvent>,
    dropped: u64,
}

#[derive(Default)]
pub struct Telemetry {
    inner: Mutex<TelemetryInner>,
}

impl Telemetry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TelemetryInner {
                events: VecDeque::with_capacity(MAX_EVENTS),
                dropped: 0,
            }),
        }
    }

    pub fn record(&self, event: TelemetryEvent) {
        let mut guard = self.inner.lock().unwrap();
        if guard.events.len() >= MAX_EVENTS {
            guard.events.pop_front();
            guard.dropped = guard.dropped.saturating_add(1);
            logger::breadcrumb(
                BreadcrumbFlags::PACKET,
                "telemetry backlog saturated, dropping oldest event".to_string(),
            );
        }
        guard.events.push_back(event);
    }

    pub fn drain(&self, max_events: usize) -> (Vec<TelemetryEvent>, u64) {
        let mut guard = self.inner.lock().unwrap();
        let mut drained = Vec::with_capacity(max_events.min(guard.events.len()));
        while drained.len() < max_events {
            match guard.events.pop_front() {
                Some(event) => drained.push(event),
                None => break,
            }
        }
        let dropped = guard.dropped;
        guard.dropped = 0;
        (drained, dropped)
    }
}
