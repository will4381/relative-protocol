//! Packet building utilities for TCP resets, ICMP blocks, and UDP responses.

use super::checksum;
use super::state::FlowKey;
use crate::device::{TcpPacket, UdpPacket};
use smoltcp::wire::IpAddress;
use std::net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};

pub(super) fn smolt_to_std_ip(addr: IpAddress) -> StdIpAddr {
    match addr {
        IpAddress::Ipv4(v4) => StdIpAddr::V4(StdIpv4Addr::from(v4.0)),
        IpAddress::Ipv6(v6) => StdIpAddr::V6(StdIpv6Addr::from(v6.0)),
    }
}

pub(super) fn build_tcp_reset(packet: &TcpPacket<'_>) -> Option<Vec<u8>> {
    match (packet.src, packet.dst) {
        (StdIpAddr::V4(src), StdIpAddr::V4(dst)) => {
            Some(build_ipv4_tcp_reset(src, dst, packet))
        }
        (StdIpAddr::V6(src), StdIpAddr::V6(dst)) => {
            Some(build_ipv6_tcp_reset(src, dst, packet))
        }
        _ => None,
    }
}

pub(super) fn build_icmp_block(packet: &UdpPacket<'_>) -> Option<Vec<u8>> {
    match (packet.src, packet.dst) {
        (StdIpAddr::V4(src), StdIpAddr::V4(dst)) => {
            Some(build_ipv4_icmp_block(src, dst, packet))
        }
        (StdIpAddr::V6(src), StdIpAddr::V6(dst)) => {
            Some(build_ipv6_icmp_block(src, dst, packet))
        }
        _ => None,
    }
}

fn build_ipv4_tcp_reset(
    client: StdIpv4Addr,
    server: StdIpv4Addr,
    packet: &TcpPacket<'_>,
) -> Vec<u8> {
    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 20;
    let total_len = IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let mut buffer = vec![0u8; total_len];

    // IPv4 header
    buffer[0] = 0x45; // version + IHL
    buffer[1] = 0;
    buffer[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buffer[4..6].copy_from_slice(&0u16.to_be_bytes());
    buffer[6..8].copy_from_slice(&0u16.to_be_bytes());
    buffer[8] = 64; // TTL
    buffer[9] = 6; // TCP
    buffer[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    buffer[12..16].copy_from_slice(&server.octets());
    buffer[16..20].copy_from_slice(&client.octets());

    // TCP header
    let offset = IPV4_HEADER_LEN;
    buffer[offset..offset + 2].copy_from_slice(&packet.dst_port.to_be_bytes());
    buffer[offset + 2..offset + 4].copy_from_slice(&packet.src_port.to_be_bytes());
    let seq_number = if packet.flags.ack {
        packet.ack_number
    } else {
        0
    };
    let ack_number = tcp_ack_number(packet);
    buffer[offset + 4..offset + 8].copy_from_slice(&seq_number.to_be_bytes());
    buffer[offset + 8..offset + 12].copy_from_slice(&ack_number.to_be_bytes());
    buffer[offset + 12] = (5u8) << 4; // data offset
    buffer[offset + 13] = 0x14; // RST + ACK
    buffer[offset + 14..offset + 16].copy_from_slice(&0u16.to_be_bytes()); // window
    buffer[offset + 16..offset + 18].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    buffer[offset + 18..offset + 20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer

    let tcp_checksum = checksum::tcp_ipv4(server, client, &buffer[offset..]);
    buffer[offset + 16..offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    let ip_cksum = checksum::ipv4_header(&buffer[..IPV4_HEADER_LEN]);
    buffer[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    buffer
}

fn build_ipv6_tcp_reset(
    client: StdIpv6Addr,
    server: StdIpv6Addr,
    packet: &TcpPacket<'_>,
) -> Vec<u8> {
    const IPV6_HEADER_LEN: usize = 40;
    const TCP_HEADER_LEN: usize = 20;
    let payload_len = TCP_HEADER_LEN as u16;
    let mut buffer = vec![0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN];

    // IPv6 header
    buffer[0] = 0x60; // version
    buffer[1..4].copy_from_slice(&[0u8; 3]); // traffic class + flow label
    buffer[4..6].copy_from_slice(&payload_len.to_be_bytes());
    buffer[6] = 6; // next header TCP
    buffer[7] = 64; // hop limit
    buffer[8..24].copy_from_slice(&server.octets());
    buffer[24..40].copy_from_slice(&client.octets());

    let offset = IPV6_HEADER_LEN;
    buffer[offset..offset + 2].copy_from_slice(&packet.dst_port.to_be_bytes());
    buffer[offset + 2..offset + 4].copy_from_slice(&packet.src_port.to_be_bytes());
    let seq_number = if packet.flags.ack {
        packet.ack_number
    } else {
        0
    };
    let ack_number = tcp_ack_number(packet);
    buffer[offset + 4..offset + 8].copy_from_slice(&seq_number.to_be_bytes());
    buffer[offset + 8..offset + 12].copy_from_slice(&ack_number.to_be_bytes());
    buffer[offset + 12] = (5u8) << 4;
    buffer[offset + 13] = 0x14; // RST + ACK
    buffer[offset + 14..offset + 16].copy_from_slice(&0u16.to_be_bytes());
    buffer[offset + 16..offset + 18].copy_from_slice(&0u16.to_be_bytes());
    buffer[offset + 18..offset + 20].copy_from_slice(&0u16.to_be_bytes());

    let tcp_checksum = checksum::tcp_ipv6(server, client, &buffer[offset..]);
    buffer[offset + 16..offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    buffer
}

fn build_ipv4_icmp_block(
    client: StdIpv4Addr,
    server: StdIpv4Addr,
    packet: &UdpPacket<'_>,
) -> Vec<u8> {
    const IPV4_HEADER_LEN: usize = 20;
    const UDP_HEADER_LEN: usize = 8;
    const ICMP_HEADER_LEN: usize = 8;
    let quoted_payload = packet.payload.len().min(8);
    let quoted_udp_len = UDP_HEADER_LEN + quoted_payload;
    let mut original = vec![0u8; IPV4_HEADER_LEN + quoted_udp_len];
    let original_len = original.len() as u16;

    // Original (blocked) IPv4 header fragment.
    original[0] = 0x45;
    original[1] = 0;
    original[2..4].copy_from_slice(&original_len.to_be_bytes());
    original[4..6].copy_from_slice(&0u16.to_be_bytes());
    original[6..8].copy_from_slice(&0u16.to_be_bytes());
    original[8] = 64;
    original[9] = 17; // UDP
    original[12..16].copy_from_slice(&client.octets());
    original[16..20].copy_from_slice(&server.octets());
    let orig_checksum = checksum::ipv4_header(&original[..IPV4_HEADER_LEN]);
    original[10..12].copy_from_slice(&orig_checksum.to_be_bytes());

    let udp_start = IPV4_HEADER_LEN;
    original[udp_start..udp_start + 2].copy_from_slice(&packet.src_port.to_be_bytes());
    original[udp_start + 2..udp_start + 4].copy_from_slice(&packet.dst_port.to_be_bytes());
    original[udp_start + 4..udp_start + 6].copy_from_slice(&(quoted_udp_len as u16).to_be_bytes());
    original[udp_start + 6..udp_start + 8].copy_from_slice(&0u16.to_be_bytes()); // checksum not known
    if quoted_payload > 0 {
        original[udp_start + UDP_HEADER_LEN..udp_start + UDP_HEADER_LEN + quoted_payload]
            .copy_from_slice(&packet.payload[..quoted_payload]);
    }

    let icmp_payload_len = ICMP_HEADER_LEN + original.len();
    let total_len = IPV4_HEADER_LEN + icmp_payload_len;
    let mut buffer = vec![0u8; total_len];

    // Outer IPv4 header for ICMP
    buffer[0] = 0x45;
    buffer[1] = 0;
    buffer[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buffer[4..6].copy_from_slice(&0u16.to_be_bytes());
    buffer[6..8].copy_from_slice(&0u16.to_be_bytes());
    buffer[8] = 64;
    buffer[9] = 1; // ICMP
    buffer[12..16].copy_from_slice(&server.octets());
    buffer[16..20].copy_from_slice(&client.octets());

    // ICMP header + payload
    let icmp_offset = IPV4_HEADER_LEN;
    buffer[icmp_offset] = 3; // destination unreachable
    buffer[icmp_offset + 1] = 13; // communication administratively prohibited
    buffer[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    buffer[icmp_offset + 4..icmp_offset + 8].copy_from_slice(&0u32.to_be_bytes()); // unused
    buffer[icmp_offset + 8..icmp_offset + 8 + original.len()].copy_from_slice(&original);

    let icmp_checksum = checksum::ones_complement(0, &buffer[icmp_offset..icmp_offset + icmp_payload_len]);
    buffer[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ip_cksum = checksum::ipv4_header(&buffer[..IPV4_HEADER_LEN]);
    buffer[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    buffer
}

fn build_ipv6_icmp_block(
    client: StdIpv6Addr,
    server: StdIpv6Addr,
    packet: &UdpPacket<'_>,
) -> Vec<u8> {
    const IPV6_HEADER_LEN: usize = 40;
    const UDP_HEADER_LEN: usize = 8;
    const ICMPV6_HEADER_LEN: usize = 8;
    let quoted_payload = packet.payload.len().min(8);
    let quoted_udp_len = UDP_HEADER_LEN + quoted_payload;
    let mut original = vec![0u8; IPV6_HEADER_LEN + quoted_udp_len];

    // Original packet fragment (blocked) for context.
    original[0] = 0x60;
    original[4..6].copy_from_slice(&(quoted_udp_len as u16).to_be_bytes());
    original[6] = 17; // UDP
    original[7] = 64;
    original[8..24].copy_from_slice(&client.octets());
    original[24..40].copy_from_slice(&server.octets());

    let udp_start = IPV6_HEADER_LEN;
    original[udp_start..udp_start + 2].copy_from_slice(&packet.src_port.to_be_bytes());
    original[udp_start + 2..udp_start + 4].copy_from_slice(&packet.dst_port.to_be_bytes());
    original[udp_start + 4..udp_start + 6].copy_from_slice(&(quoted_udp_len as u16).to_be_bytes());
    original[udp_start + 6..udp_start + 8].copy_from_slice(&0u16.to_be_bytes());
    if quoted_payload > 0 {
        original[udp_start + UDP_HEADER_LEN..udp_start + UDP_HEADER_LEN + quoted_payload]
            .copy_from_slice(&packet.payload[..quoted_payload]);
    }

    let icmp_payload_len = ICMPV6_HEADER_LEN + original.len();
    let total_len = IPV6_HEADER_LEN + icmp_payload_len;
    let mut buffer = vec![0u8; total_len];

    // Outer IPv6 header (ICMPv6)
    buffer[0] = 0x60;
    buffer[4..6].copy_from_slice(&(icmp_payload_len as u16).to_be_bytes());
    buffer[6] = 58; // ICMPv6
    buffer[7] = 64;
    buffer[8..24].copy_from_slice(&server.octets());
    buffer[24..40].copy_from_slice(&client.octets());

    let icmp_offset = IPV6_HEADER_LEN;
    buffer[icmp_offset] = 1; // Destination Unreachable
    buffer[icmp_offset + 1] = 1; // Communication with destination administratively prohibited
    buffer[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&0u16.to_be_bytes());
    buffer[icmp_offset + 4..icmp_offset + 8].copy_from_slice(&0u32.to_be_bytes());
    buffer[icmp_offset + 8..icmp_offset + 8 + original.len()].copy_from_slice(&original);

    let icmp_checksum =
        checksum::icmpv6(server, client, &buffer[icmp_offset..icmp_offset + icmp_payload_len]);
    buffer[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    buffer
}

fn tcp_ack_number(packet: &TcpPacket<'_>) -> u32 {
    let payload = packet.payload.len() as u32;
    payload
        .wrapping_add(packet.seq_number)
        .wrapping_add(u32::from(packet.flags.syn))
        .wrapping_add(u32::from(packet.flags.fin))
}

/// Build a UDP response packet (server -> client) for the given flow key and payload.
/// The flow key has src = client, dst = server, so we swap them for the response.
pub(super) fn build_udp_response(key: &FlowKey, payload: &[u8]) -> Option<Vec<u8>> {
    match (key.src_ip, key.dst_ip) {
        (IpAddress::Ipv4(client), IpAddress::Ipv4(server)) => {
            let client_std = StdIpv4Addr::from(client.0);
            let server_std = StdIpv4Addr::from(server.0);
            Some(build_ipv4_udp_response(server_std, client_std, key.dst_port, key.src_port, payload))
        }
        (IpAddress::Ipv6(client), IpAddress::Ipv6(server)) => {
            let client_std = StdIpv6Addr::from(client.0);
            let server_std = StdIpv6Addr::from(server.0);
            Some(build_ipv6_udp_response(server_std, client_std, key.dst_port, key.src_port, payload))
        }
        _ => None, // Mixed IPv4/IPv6 not supported
    }
}

fn build_ipv4_udp_response(
    src: StdIpv4Addr,
    dst: StdIpv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    const IPV4_HEADER_LEN: usize = 20;
    const UDP_HEADER_LEN: usize = 8;

    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let mut buffer = vec![0u8; total_len];

    // IPv4 header
    buffer[0] = 0x45; // version 4, IHL 5
    buffer[1] = 0;    // DSCP/ECN
    buffer[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buffer[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    buffer[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags/fragment
    buffer[8] = 64;   // TTL
    buffer[9] = 17;   // UDP protocol
    buffer[12..16].copy_from_slice(&src.octets());
    buffer[16..20].copy_from_slice(&dst.octets());

    // UDP header
    let udp_offset = IPV4_HEADER_LEN;
    buffer[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    buffer[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    buffer[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum placeholder at offset + 6..8

    // UDP payload
    buffer[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    // Calculate UDP checksum
    let udp_checksum = checksum::udp_ipv4(src, dst, &buffer[udp_offset..]);
    buffer[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    // Calculate IPv4 header checksum
    let ip_cksum = checksum::ipv4_header(&buffer[..IPV4_HEADER_LEN]);
    buffer[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    buffer
}

fn build_ipv6_udp_response(
    src: StdIpv6Addr,
    dst: StdIpv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    const IPV6_HEADER_LEN: usize = 40;
    const UDP_HEADER_LEN: usize = 8;

    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV6_HEADER_LEN + udp_len;
    let mut buffer = vec![0u8; total_len];

    // IPv6 header
    buffer[0] = 0x60; // version 6
    buffer[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // payload length
    buffer[6] = 17;   // next header = UDP
    buffer[7] = 64;   // hop limit
    buffer[8..24].copy_from_slice(&src.octets());
    buffer[24..40].copy_from_slice(&dst.octets());

    // UDP header
    let udp_offset = IPV6_HEADER_LEN;
    buffer[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    buffer[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    buffer[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum placeholder at offset + 6..8

    // UDP payload
    buffer[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    // Calculate UDP checksum (required for IPv6)
    let udp_checksum = checksum::udp_ipv6(src, dst, &buffer[udp_offset..]);
    buffer[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    buffer
}
