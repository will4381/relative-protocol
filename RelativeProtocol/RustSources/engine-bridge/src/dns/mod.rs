//! Engine-local DNS helpers that extract hostname/IP mappings from packets.

mod system;

pub use system::SystemResolver;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsMapping {
    pub host: String,
    pub addresses: Vec<IpAddr>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("unsupported hostname")]
    Unsupported,
    #[error("lookup failed: {0}")]
    LookupFailed(String),
}

pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str) -> Result<ResolveOutcome, ResolveError>;
}

#[derive(Debug, Clone)]
pub struct ResolveOutcome {
    pub addresses: Vec<String>,
    pub ttl: Duration,
}

/// Attempts to parse a DNS response payload and return hostname/IP pairs.
#[allow(dead_code)]
pub fn parse_response(payload: &[u8]) -> Vec<DnsMapping> {
    if payload.len() < 12 {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return Vec::new();
    }
    let qd_count = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let an_count = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let mut offset = 12;
    let mut questions: Vec<String> = Vec::with_capacity(qd_count);
    for _ in 0..qd_count {
        if let Some(name) = read_name(payload, &mut offset) {
            questions.push(name);
        } else {
            return Vec::new();
        }
        if offset + 4 > payload.len() {
            return Vec::new();
        }
        offset += 4; // type + class
    }
    let mut host_map: HashMap<String, DnsMapping> = HashMap::new();
    for _ in 0..an_count {
        let name = match read_name(payload, &mut offset) {
            Some(n) => n,
            None => return Vec::new(),
        };
        if offset + 10 > payload.len() {
            return Vec::new();
        }
        let record_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ttl = u32::from_be_bytes([
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > payload.len() {
            return Vec::new();
        }
        let rdata = &payload[offset..offset + rdlength];
        offset += rdlength;

        match record_type {
            1 => {
                if rdlength == 4 {
                    let addr = IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
                    insert_mapping(&mut host_map, &name, addr, ttl);
                }
            }
            28 => {
                if rdlength == 16 {
                    let addr = IpAddr::V6(Ipv6Addr::new(
                        u16::from_be_bytes([rdata[0], rdata[1]]),
                        u16::from_be_bytes([rdata[2], rdata[3]]),
                        u16::from_be_bytes([rdata[4], rdata[5]]),
                        u16::from_be_bytes([rdata[6], rdata[7]]),
                        u16::from_be_bytes([rdata[8], rdata[9]]),
                        u16::from_be_bytes([rdata[10], rdata[11]]),
                        u16::from_be_bytes([rdata[12], rdata[13]]),
                        u16::from_be_bytes([rdata[14], rdata[15]]),
                    ));
                    insert_mapping(&mut host_map, &name, addr, ttl);
                }
            }
            _ => continue,
        }
    }
    host_map.into_values().collect()
}

#[allow(dead_code)]
fn insert_mapping(map: &mut HashMap<String, DnsMapping>, name: &str, address: IpAddr, ttl: u32) {
    let entry = map.entry(name.to_string()).or_insert(DnsMapping {
        host: name.to_string(),
        addresses: Vec::new(),
        ttl: Some(ttl),
    });
    entry.addresses.push(address);
}

#[allow(dead_code)]
fn read_name(buf: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut position = *offset;
    let mut jumped = false;
    let mut guard = 0;
    while position < buf.len() && guard < buf.len() {
        guard += 1;
        let len = buf[position] as usize;
        if len == 0 {
            position += 1;
            if !jumped {
                *offset = position;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if position + 1 >= buf.len() {
                return None;
            }
            let pointer = (((len & 0x3F) as usize) << 8) | buf[position + 1] as usize;
            position = pointer;
            if !jumped {
                *offset += 2;
            }
            jumped = true;
            continue;
        }
        position += 1;
        if position + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[position..position + len]).to_string());
        position += len;
        if !jumped {
            *offset = position;
        }
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
