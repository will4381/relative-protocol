#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)] // FFI functions consumed by Swift, not Rust

mod device;
mod dns;
pub mod ffi;
mod flow_manager;
pub mod logger;
mod policy;
mod quic;
mod telemetry;

use crate::device::{ParseError, TunDevice, TunHandle, DEFAULT_MTU};
use crate::dns::{ResolveError, ResolveOutcome, Resolver, SystemResolver};
use crate::ffi::{
    BridgeCallbacks, BridgeConfig, BridgeHostRuleConfig, BridgeLogSink, BridgeResolveResult,
    BridgeTelemetryEvent, BridgeTelemetryIp, FlowCounters, FlowStats, BRIDGE_TELEMETRY_MAX_QNAME,
};
use crate::flow_manager::{FlowManager, SocketBudget};
use crate::logger::{rate_limited_error, BreadcrumbFlags, ErrorCategory};
use crate::policy::{PolicyManager, RuleAction, ShapingConfig};
use crate::telemetry::Telemetry;
use crossbeam_channel::{Sender, TrySendError};
use once_cell::sync::OnceCell;
use smoltcp::time::Instant as SmoltInstant;
use std::ffi::CStr;
use std::net::IpAddr;
use std::os::raw::c_char;
use std::ptr::NonNull;
use std::slice;
use std::sync::Arc;
use parking_lot::Mutex;
use std::time::Instant as StdInstant;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

/// Capacity of the lock-free packet ingress channel.
/// Sized for high-throughput scenarios while keeping memory bounded.
const PACKET_CHANNEL_CAPACITY: usize = 512;

const MIN_MTU: usize = 576;
const MAX_MTU: usize = 9000;
const DEFAULT_POLL_MIN_MS: u64 = 10; // iOS-optimized for battery
const DEFAULT_POLL_MAX_MS: u64 = 250;

/// Opaque engine handle shared with Swift/ObjC.
pub struct BridgeEngine {
    callbacks: OnceCell<BridgeCallbacks>,
    runtime: Runtime,
    state: Arc<Mutex<EngineState>>,
    resolver: SystemResolver,
    flows: Arc<Mutex<FlowManager>>,
    tun_handle: TunHandle,
    poll_task: Mutex<Option<JoinHandle<()>>>,
    wake: Arc<Notify>,
    telemetry: Arc<Telemetry>,
    policy: Arc<PolicyManager>,
    poll_min_interval: Duration,
    poll_max_interval: Duration,
    /// Lock-free channel for packet ingress from FFI to poll loop.
    /// Packets are pushed here by handle_packet() and drained in poll().
    packet_tx: Sender<Vec<u8>>,
}

struct EngineState {
    running: bool,
}

impl BridgeEngine {
    fn new(config: BridgeConfig) -> anyhow::Result<Self> {
        // Use multi_thread runtime to ensure poll loop runs in background
        // Enable both time AND io for async network operations
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .enable_io()
            .build()?;

        let wake = Arc::new(Notify::new());
        let mtu = normalize_mtu(config.mtu);
        let ring_capacity = if config.ring_capacity == 0 {
            256 // iOS-optimized default
        } else {
            config.ring_capacity as usize
        };
        let device = TunDevice::new(mtu, Arc::clone(&wake), ring_capacity);
        let tun_handle = device.handle();

        let telemetry = Arc::new(Telemetry::new());
        let policy = PolicyManager::new();
        let poll_min_ms = if config.poll_min_interval_ms == 0 {
            DEFAULT_POLL_MIN_MS as u32
        } else {
            config.poll_min_interval_ms.max(1)
        };
        let mut poll_max_ms = if config.poll_max_interval_ms == 0 {
            DEFAULT_POLL_MAX_MS as u32
        } else {
            config.poll_max_interval_ms
        };
        poll_max_ms = poll_max_ms.max(poll_min_ms);
        let poll_min = Duration::from_millis(poll_min_ms as u64);
        let poll_max = Duration::from_millis(poll_max_ms as u64);
        let socket_budget = SocketBudget::from_config(
            config.socket_memory_budget,
            config.tcp_rx_buffer_size,
            config.tcp_tx_buffer_size,
            config.udp_buffer_size,
        );

        // Create lock-free channel for packet ingress
        let (packet_tx, packet_rx) = crossbeam_channel::bounded(PACKET_CHANNEL_CAPACITY);

        let engine = Self {
            callbacks: OnceCell::new(),
            runtime,
            state: Arc::new(Mutex::new(EngineState { running: false })),
            resolver: SystemResolver::default(),
            flows: Arc::new(Mutex::new(FlowManager::new(
                device,
                Arc::clone(&wake),
                Arc::clone(&telemetry),
                Arc::clone(&policy),
                socket_budget,
                packet_rx,
            ))),
            tun_handle,
            poll_task: Mutex::new(None),
            wake,
            telemetry,
            policy,
            poll_min_interval: poll_min,
            poll_max_interval: poll_max,
            packet_tx,
        };

        logger::breadcrumb(
            BreadcrumbFlags::DEVICE,
            format!(
                "BridgeEngine initialized (mtu={}, ring_cap={}, mem_budget={}MB, tcp_buf={}KB)",
                mtu,
                ring_capacity,
                socket_budget.memory_budget / (1024 * 1024),
                socket_budget.tcp_rx_buffer_size / 1024
            ),
        );

        Ok(engine)
    }

    fn start(&self, callbacks: BridgeCallbacks) -> anyhow::Result<()> {
        logger::breadcrumb(
            BreadcrumbFlags::DEVICE,
            "BridgeEngine start requested".to_string(),
        );
        self.callbacks
            .set(callbacks)
            .map_err(|_| anyhow::anyhow!("callbacks already installed"))?;

        {
            let mut state = self.state.lock();
            state.running = true;
        }

        {
            let mut flows = self.flows.lock();
            flows.install_callbacks(*self.callbacks.get().expect("callbacks missing"));
        }

        logger::breadcrumb(
            BreadcrumbFlags::DEVICE,
            "BridgeEngine callbacks installed".to_string(),
        );

        self.start_poll_loop();

        logger::breadcrumb(
            BreadcrumbFlags::DEVICE,
            "BridgeEngine poll loop running".to_string(),
        );

        Ok(())
    }

    fn stop(&self) {
        logger::breadcrumb(
            BreadcrumbFlags::DEVICE,
            "BridgeEngine stop requested".to_string(),
        );
        {
            let mut state = self.state.lock();
            state.running = false;
        }
        // Wake up the poll task so it can exit gracefully
        self.wake.notify_waiters();

        // Try to wait for the poll task to exit gracefully first
        let task_handle = {
            let mut task = self.poll_task.lock();
            task.take()
        };

        if let Some(handle) = task_handle {
            // Give the task a brief moment to exit gracefully
            let wait_result = self.runtime.block_on(async {
                tokio::select! {
                    result = handle => {
                        match result {
                            Ok(()) => true,
                            Err(e) if e.is_cancelled() => {
                                logger::breadcrumb(
                                    BreadcrumbFlags::DEVICE,
                                    "Poll task was cancelled".to_string(),
                                );
                                true
                            }
                            Err(e) => {
                                logger::warn(format!("Poll task exited with error: {:?}", e));
                                true
                            }
                        }
                    }
                    _ = time::sleep(Duration::from_millis(500)) => {
                        logger::breadcrumb(
                            BreadcrumbFlags::DEVICE,
                            "Poll task did not exit in time, forcing abort".to_string(),
                        );
                        false
                    }
                }
            });

            if !wait_result {
                logger::warn("BridgeEngine: poll task did not exit gracefully");
            }
        }

        logger::breadcrumb(BreadcrumbFlags::DEVICE, "BridgeEngine stopped".to_string());
    }

    fn handle_packet(&self, packet: &[u8], _protocol: u32) -> bool {
        // Validate packet without holding any locks
        match crate::device::parse_packet_validated(packet) {
            Ok(_) => {
                // Valid packet - push to lock-free channel for processing in poll loop
                match self.packet_tx.try_send(packet.to_vec()) {
                    Ok(()) => {
                        // Wake the poll loop to process the packet
                        self.wake.notify_one();
                        true
                    }
                    Err(TrySendError::Full(_)) => {
                        // Channel full - packet will be dropped
                        // This is rare under normal conditions with PACKET_CHANNEL_CAPACITY=512
                        logger::breadcrumb(
                            BreadcrumbFlags::DEVICE,
                            "Packet channel full, dropping packet".to_string(),
                        );
                        false
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        // Channel disconnected - engine is shutting down
                        false
                    }
                }
            }
            Err(err) => {
                // Invalid packet - log error (counters updated during poll)
                // Rate-limited logging to prevent log flooding
                let category = match err {
                    ParseError::MalformedTcpSegment => ErrorCategory::PacketInvalidTcp,
                    ParseError::MalformedUdpDatagram => ErrorCategory::PacketInvalidUdp,
                    _ => ErrorCategory::PacketInvalidIp,
                };
                rate_limited_error(
                    category,
                    format!("{} (len={})", err.description(), packet.len()),
                );
                false
            }
        }
    }

    fn on_tcp_receive(&self, handle: u64, payload: &[u8]) -> bool {
        let mut flows = self.flows.lock();
        flows.on_tcp_receive(handle, payload)
    }

    fn on_udp_receive(&self, handle: u64, payload: &[u8]) -> bool {
        let mut flows = self.flows.lock();
        flows.on_udp_receive(handle, payload)
    }

    fn on_tcp_close(&self, handle: u64) {
        let mut flows = self.flows.lock();
        flows.on_tcp_close(handle);
    }

    fn on_udp_close(&self, handle: u64) {
        let mut flows = self.flows.lock();
        flows.on_udp_close(handle);
    }

    fn on_tcp_send_failed(&self, handle: u64, error: Option<&str>) {
        logger::breadcrumb(
            BreadcrumbFlags::FLOW,
            format!("TCP send failed handle={} error={:?}", handle, error),
        );
        let mut flows = self.flows.lock();
        flows.on_tcp_send_failed(handle, error);
    }

    fn on_udp_send_failed(&self, handle: u64, error: Option<&str>) {
        logger::breadcrumb(
            BreadcrumbFlags::FLOW,
            format!("UDP send failed handle={} error={:?}", handle, error),
        );
        let mut flows = self.flows.lock();
        flows.on_udp_send_failed(handle, error);
    }

    fn enqueue_frame(&self, packet: &[u8]) -> bool {
        // Log TCP packets being enqueued for smoltcp processing
        if packet.len() >= 40 {
            let version = packet[0] >> 4;
            if version == 4 && packet[9] == 6 {
                let header_len = ((packet[0] & 0x0F) as usize) * 4;
                if packet.len() >= header_len + 20 {
                    let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
                    let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
                    let flags = packet[header_len + 13];
                    let flags_str = format!(
                        "{}{}{}{}",
                        if flags & 0x02 != 0 { "S" } else { "" },
                        if flags & 0x10 != 0 { "A" } else { "" },
                        if flags & 0x01 != 0 { "F" } else { "" },
                        if flags & 0x04 != 0 { "R" } else { "" }
                    );
                    let data_off = ((packet[header_len + 12] >> 4) as usize) * 4;
                    let tcp_payload = packet.len().saturating_sub(header_len + data_off);
                    logger::breadcrumb(
                        BreadcrumbFlags::DEVICE,
                        format!(
                            "ENQUEUE_FRAME tcp {}:{} flags=[{}] payload={} queue_len={}",
                            src_port, dst_port, flags_str, tcp_payload,
                            self.tun_handle.inbound_queue_len()
                        ),
                    );
                }
            }
        }
        self.tun_handle.push_inbound(packet)
    }

    fn resolve_host(&self, host: &str) -> Result<ResolveOutcome, ResolveError> {
        self.resolver.resolve(host)
    }

    fn on_dial_result(&self, handle: u64, success: bool, reason: Option<&str>) {
        let mut flows = self.flows.lock();
        flows.on_dial_result(handle, success, reason);
    }

    fn copy_counters(&self) -> FlowCounters {
        self.flows.lock().counters()
    }

    fn copy_stats(&self) -> FlowStats {
        self.flows.lock().stats()
    }

    fn drain_telemetry(&self, max_events: usize) -> (Vec<crate::telemetry::TelemetryEvent>, u64) {
        self.telemetry.drain(max_events)
    }

    fn install_host_rule(&self, pattern: &str, action: RuleAction) -> u64 {
        self.policy.install_rule(pattern, action)
    }

    fn remove_host_rule(&self, id: u64) -> bool {
        self.policy.remove_rule(id)
    }

    fn start_poll_loop(&self) {
        let flows = Arc::clone(&self.flows);
        let state = Arc::clone(&self.state);
        let wake = Arc::clone(&self.wake);
        let min_delay = self.poll_min_interval;
        let max_delay = self.poll_max_interval;
        // Clone callbacks for use in poll loop - they're Copy so this is cheap
        let callbacks = *self.callbacks.get().expect("callbacks not installed");
        let handle = self.runtime.spawn(async move {
            let epoch = StdInstant::now();
            let mut delay = min_delay;
            loop {
                let mut reset_delay = false;
                tokio::select! {
                    _ = time::sleep(delay) => {}
                    _ = wake.notified() => {
                        reset_delay = true;
                    }
                };
                let running = {
                    let guard = state.lock();
                    guard.running
                };
                if !running {
                    break;
                }
                let now = epoch.elapsed();
                let millis = now.as_millis().min(i64::MAX as u128) as i64;

                // Poll under lock, then execute callbacks outside lock
                let (did_work, batch) = {
                    let mut flows = flows.lock();
                    flows.poll(SmoltInstant::from_millis(millis))
                };
                // Lock is now released - execute callbacks without blocking FFI handlers
                batch.execute(callbacks);

                if did_work || reset_delay {
                    delay = min_delay;
                } else {
                    let doubled = delay.checked_mul(2).unwrap_or(max_delay);
                    delay = if doubled > max_delay { max_delay } else { doubled };
                }
            }
        });
        let mut slot = self.poll_task.lock();
        *slot = Some(handle);
    }
}

fn normalize_mtu(value: u32) -> usize {
    let clamped = value.max(MIN_MTU as u32).min(MAX_MTU as u32);
    usize::try_from(clamped).unwrap_or(DEFAULT_MTU)
}

#[no_mangle]
pub unsafe extern "C" fn BridgeNewEngine(config: *const BridgeConfig) -> *mut BridgeEngine {
    let config = if let Some(cfg) = NonNull::new(config as *mut BridgeConfig) {
        unsafe { *cfg.as_ptr() }
    } else {
        BridgeConfig::default()
    };

    match BridgeEngine::new(config) {
        Ok(engine) => Box::into_raw(Box::new(engine)),
        Err(error) => {
            crate::logger::error(format!("BridgeNewEngine failed: {error:?}"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn BridgeFreeEngine(engine: *mut BridgeEngine) {
    if let Some(engine) = NonNull::new(engine) {
        unsafe {
            drop(Box::from_raw(engine.as_ptr()));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineStart(
    engine: *mut BridgeEngine,
    callbacks: *const BridgeCallbacks,
) -> i32 {
    let Some(engine) = NonNull::new(engine) else {
        return -1;
    };
    let Some(callbacks) = NonNull::new(callbacks as *mut BridgeCallbacks) else {
        return -2;
    };

    match unsafe { engine.as_ref() }.start(unsafe { *callbacks.as_ref() }) {
        Ok(_) => 0,
        Err(error) => {
            crate::logger::error(format!("BridgeEngineStart error: {error:?}"));
            -3
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineStop(engine: *mut BridgeEngine) {
    if let Some(engine) = NonNull::new(engine) {
        unsafe { engine.as_ref() }.stop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn BridgeSetLogSink(
    sink: *const BridgeLogSink,
    level: *const c_char,
    _error: *mut *mut std::ffi::c_void,
) -> bool {
    let sink_ref = unsafe { sink.as_ref() };
    let level_str = if level.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(level) }.to_str().ok()
    };
    crate::logger::install_sink(sink_ref, level_str).is_ok()
}

#[no_mangle]
pub extern "C" fn BridgeSetBreadcrumbMask(mask: u32) {
    crate::logger::set_breadcrumb_mask(mask);
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineHandlePacket(
    engine: *mut BridgeEngine,
    packet: *const u8,
    length: usize,
    protocol: u32,
) -> bool {
    let Some(engine) = NonNull::new(engine) else {
        return false;
    };
    if packet.is_null() || length == 0 {
        return false;
    }
    // Safety: caller guarantees `packet` points to `length` bytes of readable memory.
    let slice = unsafe { slice::from_raw_parts(packet, length) };
    let engine_ref = unsafe { engine.as_ref() };
    // IMPORTANT: Create socket/flow BEFORE enqueueing the packet.
    // This prevents a race where the poll loop processes the packet before
    // the socket exists, causing the first packet (e.g., DNS query) to be dropped.
    let result = engine_ref.handle_packet(slice, protocol);
    engine_ref.enqueue_frame(slice);
    result
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineOnTcpReceive(
    engine: *mut BridgeEngine,
    handle: u64,
    payload: *const u8,
    length: usize,
) -> bool {
    let Some(engine) = NonNull::new(engine) else {
        return false;
    };
    if payload.is_null() || length == 0 {
        return true;
    }
    let slice = unsafe { slice::from_raw_parts(payload, length) };
    unsafe { engine.as_ref() }.on_tcp_receive(handle, slice)
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineOnUdpReceive(
    engine: *mut BridgeEngine,
    handle: u64,
    payload: *const u8,
    length: usize,
) -> bool {
    let Some(engine) = NonNull::new(engine) else {
        return false;
    };
    if payload.is_null() || length == 0 {
        return true;
    }
    let slice = unsafe { slice::from_raw_parts(payload, length) };
    unsafe { engine.as_ref() }.on_udp_receive(handle, slice)
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineOnTcpClose(engine: *mut BridgeEngine, handle: u64) {
    if let Some(engine) = NonNull::new(engine) {
        unsafe { engine.as_ref() }.on_tcp_close(handle);
    }
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineOnUdpClose(engine: *mut BridgeEngine, handle: u64) {
    if let Some(engine) = NonNull::new(engine) {
        unsafe { engine.as_ref() }.on_udp_close(handle);
    }
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineOnTcpSendFailed(
    engine: *mut BridgeEngine,
    handle: u64,
    error: *const c_char,
) {
    let Some(engine) = NonNull::new(engine) else {
        return;
    };
    let error_str = if error.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(error) }.to_str().ok()
    };
    unsafe { engine.as_ref() }.on_tcp_send_failed(handle, error_str);
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineOnUdpSendFailed(
    engine: *mut BridgeEngine,
    handle: u64,
    error: *const c_char,
) {
    let Some(engine) = NonNull::new(engine) else {
        return;
    };
    let error_str = if error.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(error) }.to_str().ok()
    };
    unsafe { engine.as_ref() }.on_udp_send_failed(handle, error_str);
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineOnDialResult(
    engine: *mut BridgeEngine,
    handle: u64,
    success: bool,
    message: *const c_char,
) {
    let Some(engine) = NonNull::new(engine) else {
        return;
    };
    let reason = if message.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(message) }.to_str().ok()
    };
    unsafe { engine.as_ref() }.on_dial_result(handle, success, reason);
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineGetCounters(
    engine: *mut BridgeEngine,
    out: *mut FlowCounters,
) -> bool {
    let Some(engine) = NonNull::new(engine) else {
        return false;
    };
    let Some(out) = (unsafe { out.as_mut() }) else {
        return false;
    };
    *out = unsafe { engine.as_ref() }.copy_counters();
    true
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineGetStats(
    engine: *mut BridgeEngine,
    out: *mut FlowStats,
) -> bool {
    let Some(engine) = NonNull::new(engine) else {
        return false;
    };
    let Some(out) = (unsafe { out.as_mut() }) else {
        return false;
    };
    *out = unsafe { engine.as_ref() }.copy_stats();
    true
}

#[no_mangle]
pub unsafe extern "C" fn BridgeTelemetryDrain(
    engine: *mut BridgeEngine,
    out_events: *mut BridgeTelemetryEvent,
    max_events: usize,
    dropped_out: *mut u64,
) -> usize {
    let Some(engine) = NonNull::new(engine) else {
        return 0;
    };
    if out_events.is_null() || max_events == 0 {
        return 0;
    }
    let (events, dropped) = unsafe { engine.as_ref() }.drain_telemetry(max_events);
    if let Some(ptr) = unsafe { dropped_out.as_mut() } {
        *ptr = dropped;
    }
    let out_slice = unsafe { slice::from_raw_parts_mut(out_events, max_events) };
    for (idx, event) in events.iter().enumerate() {
        out_slice[idx] = bridge_event_from(event);
    }
    events.len()
}

#[no_mangle]
pub unsafe extern "C" fn BridgeEngineResolveHost(
    engine: *mut BridgeEngine,
    host: *const c_char,
    result: *mut BridgeResolveResult,
) -> i32 {
    let Some(engine) = NonNull::new(engine) else {
        return -1;
    };
    let Some(result) = (unsafe { result.as_mut() }) else {
        return -2;
    };
    result.reset();
    if host.is_null() {
        return -3;
    }
    let host = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(value) => value,
        Err(_) => return -4,
    };
    match unsafe { engine.as_ref() }.resolve_host(host) {
        Ok(outcome) => {
            if outcome.addresses.is_empty() {
                return -5;
            }
            let ttl = outcome.ttl.as_secs().min(u64::from(u32::MAX)) as u32;
            if result.populate(&outcome.addresses, ttl).is_err() {
                return -6;
            }
            0
        }
        Err(ResolveError::Unsupported) => -7,
        Err(ResolveError::LookupFailed(_)) => -8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn BridgeResolveResultFree(result: *mut BridgeResolveResult) {
    if let Some(result) = unsafe { result.as_mut() } {
        result.reset();
    }
}

#[no_mangle]
pub extern "C" fn BridgeEnsureLinked() -> bool {
    true
}

#[no_mangle]
pub unsafe extern "C" fn BridgeHostRuleAdd(
    engine: *mut BridgeEngine,
    config: *const BridgeHostRuleConfig,
    out_id: *mut u64,
) -> bool {
    let Some(engine) = NonNull::new(engine) else {
        return false;
    };
    let Some(cfg) = (unsafe { config.as_ref() }) else {
        return false;
    };
    if cfg.pattern.is_null() {
        return false;
    }
    let pattern = match unsafe { CStr::from_ptr(cfg.pattern) }.to_str() {
        Ok(p) if !p.is_empty() => p,
        _ => return false,
    };
    let action = if cfg.block {
        RuleAction::Block
    } else {
        RuleAction::Shape(ShapingConfig {
            latency_ms: cfg.latency_ms,
            jitter_ms: cfg.jitter_ms,
        })
    };
    let id = unsafe { engine.as_ref() }.install_host_rule(pattern, action);
    if let Some(out) = unsafe { out_id.as_mut() } {
        *out = id;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn BridgeHostRuleRemove(engine: *mut BridgeEngine, rule_id: u64) -> bool {
    let Some(engine) = NonNull::new(engine) else {
        return false;
    };
    unsafe { engine.as_ref() }.remove_host_rule(rule_id)
}

#[allow(clippy::field_reassign_with_default)]
fn bridge_event_from(event: &crate::telemetry::TelemetryEvent) -> BridgeTelemetryEvent {
    let mut out = BridgeTelemetryEvent::default();
    out.timestamp_ms = event.timestamp_ms;
    out.payload_len = event.payload_len;
    out.protocol = event.protocol;
    out.direction = match event.direction {
        crate::telemetry::PacketDirection::ClientToNetwork => 0,
        crate::telemetry::PacketDirection::NetworkToClient => 1,
    };
    out.flags = event.flags;
    out.src_ip = encode_ip(&event.src);
    out.dst_ip = encode_ip(&event.dst);
    if let Some(qname) = &event.dns_qname {
        let bytes = qname.as_bytes();
        let max_len = BRIDGE_TELEMETRY_MAX_QNAME.saturating_sub(1);
        let len = bytes.len().min(max_len);
        for (idx, byte) in bytes.iter().take(len).enumerate() {
            out.dns_qname[idx] = *byte as c_char;
        }
        out.dns_qname[len] = 0;
        out.dns_qname_len = len as u8;
        out.flags |= crate::telemetry::TELEMETRY_FLAG_DNS;
    }
    if event.dns_response {
        out.flags |= crate::telemetry::TELEMETRY_FLAG_DNS_RESPONSE;
    }
    out
}

fn encode_ip(addr: &IpAddr) -> BridgeTelemetryIp {
    match addr {
        IpAddr::V4(v4) => {
            let mut out = BridgeTelemetryIp { family: 4, ..Default::default() };
            out.bytes[..4].copy_from_slice(&v4.octets());
            out
        }
        IpAddr::V6(v6) => {
            let mut out = BridgeTelemetryIp { family: 6, ..Default::default() };
            out.bytes.copy_from_slice(&v6.octets());
            out
        }
    }
}
