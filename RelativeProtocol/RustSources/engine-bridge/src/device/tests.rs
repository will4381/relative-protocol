use super::*;
use tokio::sync::Notify;

const TEST_RING_CAPACITY: usize = 256;

fn make_device() -> (TunDevice, TunHandle) {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), TEST_RING_CAPACITY);
    let handle = device.handle();
    (device, handle)
}

/// Creates a valid IPv4 packet with the given payload size
fn make_valid_ipv4_packet(payload_size: usize) -> Vec<u8> {
    let total_len = 20 + payload_size; // 20 byte header + payload
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[1] = 0x00; // DSCP/ECN
    packet[2] = (total_len >> 8) as u8; // Total length (high byte)
    packet[3] = (total_len & 0xFF) as u8; // Total length (low byte)
    packet[4] = 0x00; // ID (high)
    packet[5] = 0x01; // ID (low)
    packet[6] = 0x00; // Flags/Fragment offset
    packet[7] = 0x00; // Fragment offset
    packet[8] = 64; // TTL
    packet[9] = 6; // Protocol (TCP)
    packet[10] = 0x00; // Header checksum (high)
    packet[11] = 0x00; // Header checksum (low)
    // Source IP: 10.0.0.1
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    // Dest IP: 10.0.0.2
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 2;
    // Fill payload with 0x45 for the test
    for byte in packet.iter_mut().take(total_len).skip(20) {
        *byte = 0x45;
    }
    packet
}

/// Creates a valid IPv4 packet with a custom tag in the payload (for eviction test)
fn make_valid_ipv4_with_tag(tag: u32) -> Vec<u8> {
    let mut packet = make_valid_ipv4_packet(8); // 8 bytes of payload
    // Store the tag in the payload portion (bytes 20-23)
    let tag_bytes = tag.to_be_bytes();
    packet[20] = tag_bytes[0];
    packet[21] = tag_bytes[1];
    packet[22] = tag_bytes[2];
    packet[23] = tag_bytes[3];
    packet
}

#[test]
fn push_inbound_truncates_to_mtu() {
    let (mut device, handle) = make_device();
    // Create a valid packet larger than MTU
    let packet = make_valid_ipv4_packet(DEFAULT_MTU + 256 - 20);
    assert!(handle.push_inbound(&packet));

    let (rx, _) = device
        .receive(Instant::from_millis(0))
        .expect("rx token missing");
    let mut captured = Vec::new();
    rx.consume(|buffer| {
        captured.extend_from_slice(buffer);
    });
    assert_eq!(captured.len(), DEFAULT_MTU);
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
    for idx in 0..=TEST_RING_CAPACITY {
        let packet = make_valid_ipv4_with_tag(idx as u32);
        handle.push_inbound(&packet);
    }

    for expected in 1..=TEST_RING_CAPACITY as u32 {
        let (rx, _) = device
            .receive(Instant::from_millis(0))
            .expect("rx token missing");
        let mut value = [0u8; 4];
        rx.consume(|buffer| value.copy_from_slice(&buffer[20..24])); // Tag is at offset 20
        assert_eq!(u32::from_be_bytes(value), expected);
    }
    assert!(device.receive(Instant::from_millis(0)).is_none());
}
