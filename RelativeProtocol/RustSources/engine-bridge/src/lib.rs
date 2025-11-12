#![deny(unsafe_op_in_unsafe_fn)]

mod device;
mod dns;
pub mod ffi;
mod flow_manager;
mod logger;
mod quic;

use crate::device::{TunDevice, TunHandle, DEFAULT_MTU, RING_CAPACITY};
use crate::dns::{ResolveError, ResolveOutcome, Resolver, SystemResolver};
use crate::ffi::{
    BridgeCallbacks, BridgeConfig, BridgeLogSink, BridgeResolveResult, FlowCounters, FlowStats,
};
use crate::flow_manager::FlowManager;
use crate::logger::BreadcrumbFlags;
use once_cell::sync::OnceCell;
use smoltcp::time::Instant as SmoltInstant;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::NonNull;
use std::slice;
use std::sync::{Arc, Mutex};
use std::time::Instant as StdInstant;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

const MIN_MTU: usize = 576;
const MAX_MTU: usize = 9000;

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
}

struct EngineState {
    running: bool,
}

impl BridgeEngine {
    fn new(config: BridgeConfig) -> anyhow::Result<Self> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_time()
            .build()?;

        let wake = Arc::new(Notify::new());
        let mtu = normalize_mtu(config.mtu);
        let device = TunDevice::new(mtu, Arc::clone(&wake));
        let tun_handle = device.handle();

        let engine = Self {
            callbacks: OnceCell::new(),
            runtime,
            state: Arc::new(Mutex::new(EngineState { running: false })),
            resolver: SystemResolver::default(),
            flows: Arc::new(Mutex::new(FlowManager::new(device, Arc::clone(&wake)))),
            tun_handle,
            poll_task: Mutex::new(None),
            wake,
        };

        logger::breadcrumb(
            BreadcrumbFlags::DEVICE,
            format!(
                "BridgeEngine initialized (mtu={}, ring_cap={})",
                mtu, RING_CAPACITY
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
            let mut state = self.state.lock().expect("state lock poisoned");
            state.running = true;
        }

        {
            let mut flows = self.flows.lock().expect("flows lock poisoned");
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
            let mut state = self.state.lock().expect("state lock poisoned");
            state.running = false;
        }
        self.wake.notify_waiters();
        if let Ok(mut task) = self.poll_task.lock() {
            if let Some(handle) = task.take() {
                handle.abort();
            }
        }

        logger::breadcrumb(BreadcrumbFlags::DEVICE, "BridgeEngine stopped".to_string());
    }

    fn handle_packet(&self, packet: &[u8], protocol: u32) -> bool {
        let Some(parsed) = crate::device::parse_packet(packet) else {
            logger::breadcrumb(
                BreadcrumbFlags::DEVICE,
                format!(
                    "Dropped packet (len={}, proto=0x{:x}) – unsupported L3 header",
                    packet.len(),
                    protocol
                ),
            );
            return false;
        };
        if let Ok(mut flows) = self.flows.lock() {
            flows.process_packet(&parsed);
        }
        true
    }

    fn on_tcp_receive(&self, handle: u64, payload: &[u8]) -> bool {
        if let Ok(mut flows) = self.flows.lock() {
            return flows.on_tcp_receive(handle, payload);
        }
        false
    }

    fn on_udp_receive(&self, handle: u64, payload: &[u8]) -> bool {
        if let Ok(mut flows) = self.flows.lock() {
            return flows.on_udp_receive(handle, payload);
        }
        false
    }

    fn on_tcp_close(&self, handle: u64) {
        if let Ok(mut flows) = self.flows.lock() {
            flows.on_tcp_close(handle);
        }
    }

    fn on_udp_close(&self, handle: u64) {
        if let Ok(mut flows) = self.flows.lock() {
            flows.on_udp_close(handle);
        }
    }

    fn enqueue_frame(&self, packet: &[u8]) -> bool {
        self.tun_handle.push_inbound(packet)
    }

    fn resolve_host(&self, host: &str) -> Result<ResolveOutcome, ResolveError> {
        self.resolver.resolve(host)
    }

    fn on_dial_result(&self, handle: u64, success: bool, reason: Option<&str>) {
        if let Ok(mut flows) = self.flows.lock() {
            flows.on_dial_result(handle, success, reason);
        }
    }

    fn copy_counters(&self) -> FlowCounters {
        self.flows
            .lock()
            .map(|flows| flows.counters())
            .unwrap_or_default()
    }

    fn copy_stats(&self) -> FlowStats {
        self.flows
            .lock()
            .map(|flows| flows.stats())
            .unwrap_or_default()
    }

    fn start_poll_loop(&self) {
        let flows = Arc::clone(&self.flows);
        let state = Arc::clone(&self.state);
        let wake = Arc::clone(&self.wake);
        let handle = self.runtime.spawn(async move {
            let epoch = StdInstant::now();
            let mut ticker = time::interval(Duration::from_millis(5));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = wake.notified() => {}
                }
                let running = {
                    let guard = state.lock().expect("state lock poisoned");
                    guard.running
                };
                if !running {
                    break;
                }
                let now = epoch.elapsed();
                let millis = now.as_millis().min(i64::MAX as u128) as i64;
                if let Ok(mut flows) = flows.lock() {
                    flows.poll(SmoltInstant::from_millis(millis));
                }
            }
        });
        let mut slot = self.poll_task.lock().expect("poll task lock poisoned");
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

    match unsafe { engine.as_ref() }.start(unsafe { callbacks.as_ref().clone() }) {
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
        match unsafe { CStr::from_ptr(level) }.to_str() {
            Ok(value) => Some(value),
            Err(_) => None,
        }
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
    engine_ref.enqueue_frame(slice);
    engine_ref.handle_packet(slice, protocol)
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
