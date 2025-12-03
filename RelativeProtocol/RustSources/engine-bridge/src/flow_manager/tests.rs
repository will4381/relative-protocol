//! Tests for the flow_manager module.

use super::state;
use super::state::MAX_DIAL_ATTEMPTS;
use super::*;
use crate::device::{TcpFlags, TunDevice, DEFAULT_MTU};
use crate::telemetry::{
    PacketDirection, Telemetry, TELEMETRY_FLAG_POLICY_BLOCK, TELEMETRY_FLAG_POLICY_SHAPE,
};
use crossbeam_channel::Receiver;
use std::ffi::{c_void, CStr};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// Create a dummy packet receiver for tests.
/// The sender is dropped immediately since tests don't use the packet channel.
fn test_packet_rx() -> Receiver<Vec<u8>> {
    let (_, rx) = crossbeam_channel::bounded(1);
    rx
}

#[derive(Default)]
struct TestHarness {
    dns: Mutex<Vec<(String, Vec<String>, u32)>>,
    dials: Mutex<Vec<(FlowKind, String, u16, u64)>>,
    closes: Mutex<Vec<(FlowKind, u64, String)>>,
}

impl TestHarness {
    fn record_dns(&self, host: String, addresses: Vec<String>, ttl: u32) {
        self.dns.lock().unwrap().push((host, addresses, ttl));
    }

    fn record_dial(&self, kind: FlowKind, host: String, port: u16, handle: u64) {
        self.dials.lock().unwrap().push((kind, host, port, handle));
    }

    fn record_close(&self, kind: FlowKind, handle: u64, message: String) {
        self.closes.lock().unwrap().push((kind, handle, message));
    }

    fn dns(&self) -> Vec<(String, Vec<String>, u32)> {
        self.dns.lock().unwrap().clone()
    }

    fn dials(&self) -> Vec<(FlowKind, String, u16, u64)> {
        self.dials.lock().unwrap().clone()
    }

    fn closes(&self) -> Vec<(FlowKind, u64, String)> {
        self.closes.lock().unwrap().clone()
    }
}

unsafe extern "C" fn noop_emit(
    _packets: *const *const u8,
    _sizes: *const usize,
    _protocols: *const u32,
    _count: usize,
    _context: *mut c_void,
) {
}

unsafe extern "C" fn test_request_tcp_dial(
    host: *const i8,
    port: u16,
    handle: u64,
    context: *mut c_void,
) {
    record_dial_callback(host, port, handle, context, FlowKind::Tcp);
}

unsafe extern "C" fn test_request_udp_dial(
    host: *const i8,
    port: u16,
    handle: u64,
    context: *mut c_void,
) {
    record_dial_callback(host, port, handle, context, FlowKind::Udp);
}

unsafe extern "C" fn noop_send(
    _handle: u64,
    _payload: *const u8,
    _length: usize,
    _context: *mut c_void,
) {
}

unsafe extern "C" fn test_udp_send(
    handle: u64,
    _payload: *const u8,
    length: usize,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    let harness = unsafe { &*(context as *const TestHarness) };
    harness.record_close(FlowKind::Udp, handle, format!("udp_send size {}", length));
}

unsafe extern "C" fn test_record_dns(
    host: *const i8,
    addresses: *const *const i8,
    count: usize,
    ttl_seconds: u32,
    context: *mut c_void,
) {
    if host.is_null() || addresses.is_null() || context.is_null() {
        return;
    }
    let harness = unsafe { &*(context as *const TestHarness) };
    let host_str = unsafe { CStr::from_ptr(host) }
        .to_string_lossy()
        .to_string();
    let mut results = Vec::with_capacity(count);
    for index in 0..count {
        let ptr = unsafe { *addresses.add(index) };
        if ptr.is_null() {
            continue;
        }
        results.push(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().to_string());
    }
    if results.is_empty() {
        return;
    }
    harness.record_dns(host_str, results, ttl_seconds);
}

fn record_dial_callback(
    host: *const i8,
    port: u16,
    handle: u64,
    context: *mut c_void,
    kind: FlowKind,
) {
    if host.is_null() || context.is_null() {
        return;
    }
    let harness = unsafe { &*(context as *const TestHarness) };
    let host_str = unsafe { CStr::from_ptr(host) }
        .to_string_lossy()
        .to_string();
    harness.record_dial(kind, host_str, port, handle);
}

fn record_close_callback(
    handle: u64,
    message: *const i8,
    context: *mut c_void,
    kind: FlowKind,
) {
    if context.is_null() {
        return;
    }
    let harness = unsafe { &*(context as *const TestHarness) };
    let reason = if message.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .to_string()
    };
    harness.record_close(kind, handle, reason);
}

fn test_callbacks(context: *mut c_void) -> BridgeCallbacks {
    BridgeCallbacks {
        emit_packets: noop_emit,
        request_tcp_dial: test_request_tcp_dial,
        request_udp_dial: test_request_udp_dial,
        tcp_send: noop_send,
        udp_send: test_udp_send,
        tcp_close: test_tcp_close,
        udp_close: test_udp_close,
        record_dns: test_record_dns,
        context,
    }
}

unsafe extern "C" fn test_tcp_close(handle: u64, message: *const i8, context: *mut c_void) {
    record_close_callback(handle, message, context, FlowKind::Tcp);
}

unsafe extern "C" fn test_udp_close(handle: u64, message: *const i8, context: *mut c_void) {
    record_close_callback(handle, message, context, FlowKind::Udp);
}

#[test]
fn dns_packets_emit_mappings() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    let mut manager =
        FlowManager::new(device, Arc::clone(&wake), telemetry, policy, SocketBudget::default(), test_packet_rx());
    let harness = Box::new(TestHarness::default());
    let context = Box::into_raw(harness);
    manager.install_callbacks(test_callbacks(context as *mut c_void));

    let payload = build_dns_response("example.com", [203, 0, 113, 5], 120);
    let udp_packet = UdpPacket {
        src: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 53,
        dst_port: 1000,
        payload: payload.as_slice(),
    };
    let packet = ParsedPacket::Udp(udp_packet);
    manager.process_packet(&packet);

    let harness = unsafe { Box::from_raw(context) };
    let entries = harness.dns();
    assert_eq!(entries.len(), 1);
    let (host, addresses, ttl) = &entries[0];
    assert_eq!(host, "example.com");
    assert_eq!(addresses, &["203.0.113.5".to_string()]);
    assert_eq!(*ttl, 120);
}

#[test]
fn tcp_dial_retries_eventually_close_flow() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    let mut manager =
        FlowManager::new(device, Arc::clone(&wake), telemetry, policy, SocketBudget::default(), test_packet_rx());
    let harness = Box::new(TestHarness::default());
    let context = Box::into_raw(harness);
    manager.install_callbacks(test_callbacks(context as *mut c_void));

    let tcp_packet = TcpPacket {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        src_port: 1000,
        dst_port: 443,
        seq_number: 1,
        ack_number: 0,
        payload: &[],
        flags: TcpFlags::default(),
    };
    manager.process_packet(&ParsedPacket::Tcp(tcp_packet));
    thread::sleep(Duration::from_millis(10));
    manager.poll(Instant::from_millis(0));

    let harness_ref = unsafe { &*context };
    wait_for(&mut manager, harness_ref, Duration::from_millis(200), |h| {
        !h.dials().is_empty()
    });
    let recorded_handle = harness_ref.dials()[0].3;
    let (&handle, _) = manager
        .handle_map
        .iter()
        .next()
        .expect("expected flow handle");
    assert_eq!(handle, recorded_handle);

    for attempt in 0..MAX_DIAL_ATTEMPTS {
        manager.on_dial_result(handle, false, Some("network_down"));
        if attempt < MAX_DIAL_ATTEMPTS - 1 {
            let expected = (attempt as usize) + 2;
            wait_for(&mut manager, harness_ref, Duration::from_millis(500), |h| {
                h.dials().len() >= expected
            });
        }
    }

    wait_for(&mut manager, harness_ref, Duration::from_millis(500), |h| {
        !h.closes().is_empty()
    });
    let closes = harness_ref.closes();
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].0, FlowKind::Tcp);
    assert_eq!(closes[0].1, handle);

    unsafe {
        drop(Box::from_raw(context));
    }
}

#[test]
fn remote_payloads_buffer_until_dial_ready() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    let mut manager =
        FlowManager::new(device, Arc::clone(&wake), telemetry, policy, SocketBudget::default(), test_packet_rx());

    let tcp_packet = TcpPacket {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        src_port: 5000,
        dst_port: 443,
        seq_number: 1,
        ack_number: 0,
        payload: &[],
        flags: TcpFlags::default(),
    };
    let key = FlowKey::from_tcp(&tcp_packet);
    let parsed = ParsedPacket::Tcp(tcp_packet);
    manager.process_packet(&parsed);

    let (&handle, _) = manager
        .handle_map
        .iter()
        .next()
        .expect("expected flow handle");

    // Remote payload arrives before dial ready – should be buffered.
    let payload = vec![1u8, 2, 3, 4];
    {
        let entry = manager.flow_keys.get_mut(&key).expect("flow entry missing");
        // Simulate the dial being in progress (as would happen after dispatch_pending_dials)
        entry.pending_dial = true;
        entry.dial_started_at = Some(std::time::Instant::now());
        assert!(state::buffer_payload(entry, &payload));
        assert_eq!(entry.buffered.len(), 1);
        assert_eq!(entry.buffered_bytes, payload.len());
        assert!(!entry.ready);
    }

    // Mark dial ready; this will attempt to flush buffered payloads.
    // Note: In a test environment without a fully connected socket, the payload
    // may get re-buffered due to backpressure, but entry.ready should be true.
    manager.on_dial_result(handle, true, None);
    if let Some(entry) = manager.flow_keys.get(&key) {
        assert!(entry.ready, "entry should be marked ready after successful dial");
        // The pending_dial flag should be cleared
        assert!(!entry.pending_dial);
        // dial_started_at should be cleared
        assert!(entry.dial_started_at.is_none());
    }
}

// NOTE: udp_backpressure_closes_flow test was removed because UDP now bypasses
// smoltcp sockets entirely and emits packets directly via callbacks. There is
// no socket buffer to saturate, so the backpressure behavior no longer exists.

#[test]
fn policy_block_prevents_tcp_flow() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    let mut manager = FlowManager::new(
        device,
        Arc::clone(&wake),
        Arc::clone(&telemetry),
        Arc::clone(&policy),
        SocketBudget::default(),
        test_packet_rx(),
    );
    policy.install_rule("*.blocked.test", RuleAction::Block);
    let target_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55));
    policy.observe_dns_mapping("api.blocked.test", &[target_ip], None);

    let tcp_packet = TcpPacket {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        dst: target_ip,
        src_port: 4000,
        dst_port: 443,
        seq_number: 1,
        ack_number: 0,
        payload: &[],
        flags: TcpFlags::default(),
    };

    manager.process_packet(&ParsedPacket::Tcp(tcp_packet));
    assert!(manager.flow_keys.is_empty());
    let (events, _) = manager.telemetry.drain(16);
    assert!(
        events
            .iter()
            .any(|event| event.flags & TELEMETRY_FLAG_POLICY_BLOCK != 0),
        "expected policy block telemetry"
    );
}

#[test]
fn policy_shape_attaches_config_to_flow() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    let mut manager = FlowManager::new(
        device,
        Arc::clone(&wake),
        Arc::clone(&telemetry),
        Arc::clone(&policy),
        SocketBudget::default(),
        test_packet_rx(),
    );
    let shaping = ShapingConfig {
        latency_ms: 125,
        jitter_ms: 15,
    };
    policy.install_rule("video.example.com", RuleAction::Shape(shaping));
    let target_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    policy.observe_dns_mapping("video.example.com", &[target_ip], Some(120));

    let udp_packet = UdpPacket {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        dst: target_ip,
        src_port: 5353,
        dst_port: 9000,
        payload: &[1, 2, 3, 4],
    };

    manager.process_packet(&ParsedPacket::Udp(udp_packet));
    assert_eq!(manager.flow_keys.len(), 1);
    let entry = manager
        .flow_keys
        .values()
        .next()
        .expect("flow entry missing");
    assert_eq!(entry.shaping.as_ref().map(|s| s.config), Some(shaping));

    let (events, _) = manager.telemetry.drain(16);
    assert!(
        events
            .iter()
            .any(|event| event.flags & TELEMETRY_FLAG_POLICY_SHAPE != 0),
        "expected policy shape telemetry"
    );
}

#[test]
fn shaping_queue_delays_remote_payload_delivery() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    let mut manager = FlowManager::new(
        device,
        Arc::clone(&wake),
        Arc::clone(&telemetry),
        Arc::clone(&policy),
        SocketBudget::default(),
        test_packet_rx(),
    );
    let shaping = ShapingConfig {
        latency_ms: 0,
        jitter_ms: 0,
    };
    policy.install_rule("delay.example", RuleAction::Shape(shaping));
    let target_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 42));
    policy.observe_dns_mapping("delay.example", &[target_ip], None);

    let udp_packet = UdpPacket {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
        dst: target_ip,
        src_port: 5500,
        dst_port: 8080,
        payload: &[0; 0],
    };
    manager.process_packet(&ParsedPacket::Udp(udp_packet));
    let (&handle, &key) = manager
        .handle_map
        .iter()
        .next()
        .expect("handle missing for shaping test");
    manager.on_dial_result(handle, true, None);
    let payload = vec![9u8, 8, 7];
    assert!(manager.forward_remote_payload(handle, &payload, FlowKind::Udp));
    {
        let entry = manager.flow_keys.get(&key).expect("flow missing");
        let shaper = entry.shaping.as_ref().expect("shaper missing");
        assert!(shaper.has_pending());
    }
    manager.drain_shaping_queues(StdInstant::now());
    {
        let entry = manager.flow_keys.get(&key).expect("flow missing");
        let shaper = entry.shaping.as_ref().expect("shaper missing");
        assert!(!shaper.has_pending());
    }
}

#[test]
fn telemetry_records_network_to_client_payloads() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    let mut manager = FlowManager::new(
        device,
        Arc::clone(&wake),
        Arc::clone(&telemetry),
        policy,
        SocketBudget::default(),
        test_packet_rx(),
    );
    // UDP now emits packets via callbacks, so we must install them for on_udp_receive to work.
    let harness = Box::new(TestHarness::default());
    let context = Box::into_raw(harness);
    manager.install_callbacks(test_callbacks(context as *mut c_void));

    let udp_packet = UdpPacket {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
        dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12)),
        src_port: 1234,
        dst_port: 4321,
        payload: &[1, 2, 3],
    };
    manager.process_packet(&ParsedPacket::Udp(udp_packet));
    let (&handle, _) = manager.handle_map.iter().next().expect("handle missing");
    manager.on_dial_result(handle, true, None);
    let payload = vec![9u8, 8, 7, 6];
    assert!(manager.on_udp_receive(handle, &payload));
    let (events, _) = telemetry.drain(8);
    assert!(
        events
            .iter()
            .any(|event| event.direction == PacketDirection::NetworkToClient
                && event.payload_len == payload.len() as u32)
    );

    unsafe {
        drop(Box::from_raw(context));
    }
}

#[test]
fn dns_response_updates_policy_and_telemetry() {
    let wake = Arc::new(Notify::new());
    let device = TunDevice::new(DEFAULT_MTU, Arc::clone(&wake), 256);
    let telemetry = Arc::new(Telemetry::new());
    let policy = PolicyManager::new();
    policy.install_rule("*.blocked.test", RuleAction::Block);
    let mut manager = FlowManager::new(
        device,
        Arc::clone(&wake),
        Arc::clone(&telemetry),
        Arc::clone(&policy),
        SocketBudget::default(),
        test_packet_rx(),
    );
    let harness = Box::new(TestHarness::default());
    let context = Box::into_raw(harness);
    manager.install_callbacks(test_callbacks(context as *mut c_void));

    // Admit a DNS flow and mark it ready.
    let dns_query = UdpPacket {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        dst: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        src_port: 12345,
        dst_port: 53,
        payload: &[0u8; 0],
    };
    manager.process_packet(&ParsedPacket::Udp(dns_query));
    let (&handle, &_key) = manager.handle_map.iter().next().expect("handle missing");
    manager.on_dial_result(handle, true, None);

    // Feed a DNS response from the network side.
    let response =
        build_dns_response("api.blocked.test", [203, 0, 113, 99], DEFAULT_DNS_TTL_SECONDS);
    assert!(manager.on_udp_receive(handle, &response));

    // Policy should now map the resolved IP to the blocked host.
    let decision = policy
        .decision_for_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)))
        .expect("expected decision");
    assert_eq!(decision.host, "api.blocked.test");

    // Telemetry should mark the DNS response.
    let (events, _) = telemetry.drain(4);
    assert!(
        events
            .iter()
            .any(|event| event.flags & TELEMETRY_FLAG_DNS_RESPONSE != 0
                && event.dns_qname.as_deref() == Some("api.blocked.test")),
        "expected DNS response telemetry"
    );

    unsafe {
        drop(Box::from_raw(context));
    }
}

const DEFAULT_DNS_TTL_SECONDS: u32 = 60;

fn wait_for<F>(
    manager: &mut FlowManager,
    harness: &TestHarness,
    timeout: Duration,
    mut predicate: F,
) where
    F: FnMut(&TestHarness) -> bool,
{
    let deadline = StdInstant::now() + timeout;
    while !predicate(harness) {
        if StdInstant::now() >= deadline {
            break;
        }
        manager.poll(Instant::from_millis(0));
        thread::sleep(Duration::from_millis(10));
    }
}

fn build_dns_response(host: &str, addr: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x00, 0x01]);
    payload.extend_from_slice(&[0x81, 0x80]);
    payload.extend_from_slice(&[0x00, 0x01]);
    payload.extend_from_slice(&[0x00, 0x01]);
    payload.extend_from_slice(&[0x00, 0x00]);
    payload.extend_from_slice(&[0x00, 0x00]);
    for label in host.split('.') {
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    payload.extend_from_slice(&[0xC0, 0x0C]);
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    payload.extend_from_slice(&ttl.to_be_bytes());
    payload.extend_from_slice(&[0x00, 0x04]);
    payload.extend_from_slice(&addr);
    payload
}
