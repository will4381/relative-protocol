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
    let mut alias_roots: HashMap<String, Vec<String>> = HashMap::new();
    for question in &questions {
        alias_roots
            .entry(question.clone())
            .or_insert_with(|| vec![question.clone()]);
    }
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
        let rdata_start = offset;
        offset += rdlength;

        match record_type {
            1 => {
                if rdlength == 4 {
                    let addr = IpAddr::V4(Ipv4Addr::new(
                        payload[rdata_start],
                        payload[rdata_start + 1],
                        payload[rdata_start + 2],
                        payload[rdata_start + 3],
                    ));
                    let roots = lookup_roots(&alias_roots, &name);
                    for root in roots {
                        insert_mapping(&mut host_map, root.as_str(), addr, ttl);
                    }
                }
            }
            28 => {
                if rdlength == 16 {
                    let addr = IpAddr::V6(Ipv6Addr::new(
                        u16::from_be_bytes([payload[rdata_start], payload[rdata_start + 1]]),
                        u16::from_be_bytes([payload[rdata_start + 2], payload[rdata_start + 3]]),
                        u16::from_be_bytes([payload[rdata_start + 4], payload[rdata_start + 5]]),
                        u16::from_be_bytes([payload[rdata_start + 6], payload[rdata_start + 7]]),
                        u16::from_be_bytes([payload[rdata_start + 8], payload[rdata_start + 9]]),
                        u16::from_be_bytes([payload[rdata_start + 10], payload[rdata_start + 11]]),
                        u16::from_be_bytes([payload[rdata_start + 12], payload[rdata_start + 13]]),
                        u16::from_be_bytes([payload[rdata_start + 14], payload[rdata_start + 15]]),
                    ));
                    let roots = lookup_roots(&alias_roots, &name);
                    for root in roots {
                        insert_mapping(&mut host_map, root.as_str(), addr, ttl);
                    }
                }
            }
            5 => {
                let mut cname_offset = rdata_start;
                if let Some(target) = read_name(payload, &mut cname_offset) {
                    let roots = lookup_roots(&alias_roots, &name);
                    if !roots.is_empty() {
                        let entry = alias_roots.entry(target).or_insert_with(Vec::new);
                        for root in roots {
                            if !entry.iter().any(|existing| existing == &root) {
                                entry.push(root);
                            }
                        }
                    }
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

fn lookup_roots(alias_roots: &HashMap<String, Vec<String>>, name: &str) -> Vec<String> {
    alias_roots
        .get(name)
        .cloned()
        .unwrap_or_else(|| vec![name.to_string()])
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

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    #[test]
    fn parse_response_maps_addresses_to_question_name() {
        let question = "v16.us.tiktok.com";
        let cname = "edge.example.net";
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x12, 0x34]); // id
        payload.extend_from_slice(&[0x81, 0x80]); // standard response
        payload.extend_from_slice(&[0x00, 0x01]); // qdcount
        payload.extend_from_slice(&[0x00, 0x02]); // ancount
        payload.extend_from_slice(&[0x00, 0x00]); // nscount
        payload.extend_from_slice(&[0x00, 0x00]); // arcount
        payload.extend_from_slice(&encode_name(question));
        payload.extend_from_slice(&[0x00, 0x01]); // type A
        payload.extend_from_slice(&[0x00, 0x01]); // class IN
        payload.extend_from_slice(&encode_name(question)); // answer name
        payload.extend_from_slice(&[0x00, 0x05]); // CNAME
        payload.extend_from_slice(&[0x00, 0x01]); // class IN
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
        let cname_encoded = encode_name(cname);
        payload.extend_from_slice(&[
            ((cname_encoded.len() as u16) >> 8) as u8,
            (cname_encoded.len() as u16 & 0xFF) as u8,
        ]);
        payload.extend_from_slice(&cname_encoded);
        payload.extend_from_slice(&encode_name(cname));
        payload.extend_from_slice(&[0x00, 0x01]); // type A
        payload.extend_from_slice(&[0x00, 0x01]); // class IN
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
        payload.extend_from_slice(&[0x00, 0x04]); // rdlength
        payload.extend_from_slice(&[1, 2, 3, 4]); // IPv4 addr

        let mappings = parse_response(&payload);
        assert_eq!(mappings.len(), 1);
        let mapping = &mappings[0];
        assert_eq!(mapping.host, question);
        assert_eq!(
            mapping.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
    }
}
