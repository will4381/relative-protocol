//! Checksum calculation utilities for IP, TCP, UDP, and ICMPv6.

use std::net::{Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};

/// Compute the ones' complement checksum over a byte slice.
pub fn ones_complement(mut sum: u32, bytes: &[u8]) -> u16 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u16::from_be_bytes([byte, 0]) as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute IPv4 header checksum.
pub fn ipv4_header(header: &[u8]) -> u16 {
    ones_complement(0, header)
}

/// Compute TCP checksum over IPv4 pseudo-header + segment.
pub fn tcp_ipv4(src: StdIpv4Addr, dst: StdIpv4Addr, segment: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + segment.len());
    pseudo_header.extend_from_slice(&src.octets());
    pseudo_header.extend_from_slice(&dst.octets());
    pseudo_header.push(0);
    pseudo_header.push(6); // TCP
    pseudo_header.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo_header.extend_from_slice(segment);
    ones_complement(0, &pseudo_header)
}

/// Compute TCP checksum over IPv6 pseudo-header + segment.
pub fn tcp_ipv6(src: StdIpv6Addr, dst: StdIpv6Addr, segment: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + segment.len());
    pseudo_header.extend_from_slice(&src.octets());
    pseudo_header.extend_from_slice(&dst.octets());
    pseudo_header.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0u8, 0, 0, 6]); // next header = TCP
    pseudo_header.extend_from_slice(segment);
    ones_complement(0, &pseudo_header)
}

/// Compute ICMPv6 checksum over IPv6 pseudo-header + message.
pub fn icmpv6(src: StdIpv6Addr, dst: StdIpv6Addr, message: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + message.len());
    pseudo_header.extend_from_slice(&src.octets());
    pseudo_header.extend_from_slice(&dst.octets());
    pseudo_header.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0u8, 0, 0, 58]); // next header = ICMPv6
    pseudo_header.extend_from_slice(message);
    ones_complement(0, &pseudo_header)
}

/// Compute UDP checksum over IPv4 pseudo-header + segment.
pub fn udp_ipv4(src: StdIpv4Addr, dst: StdIpv4Addr, segment: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + segment.len());
    pseudo_header.extend_from_slice(&src.octets());
    pseudo_header.extend_from_slice(&dst.octets());
    pseudo_header.push(0);
    pseudo_header.push(17); // UDP
    pseudo_header.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo_header.extend_from_slice(segment);
    ones_complement(0, &pseudo_header)
}

/// Compute UDP checksum over IPv6 pseudo-header + segment.
pub fn udp_ipv6(src: StdIpv6Addr, dst: StdIpv6Addr, segment: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + segment.len());
    pseudo_header.extend_from_slice(&src.octets());
    pseudo_header.extend_from_slice(&dst.octets());
    pseudo_header.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0u8, 0, 0, 17]); // next header = UDP
    pseudo_header.extend_from_slice(segment);
    ones_complement(0, &pseudo_header)
}
