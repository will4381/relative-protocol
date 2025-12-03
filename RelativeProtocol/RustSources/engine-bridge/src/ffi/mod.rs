use std::ffi::{c_char, c_void, CString};
use std::ptr;
use std::slice;

pub type EmitPacketsFn = unsafe extern "C" fn(
    packets: *const *const u8,
    sizes: *const usize,
    protocols: *const u32,
    count: usize,
    context: *mut c_void,
);
pub type DialFn =
    unsafe extern "C" fn(host: *const i8, port: u16, handle: u64, context: *mut c_void);
pub type SendFn =
    unsafe extern "C" fn(handle: u64, payload: *const u8, length: usize, context: *mut c_void);
pub type CloseFn = unsafe extern "C" fn(handle: u64, message: *const i8, context: *mut c_void);
pub type RecordDnsFn = unsafe extern "C" fn(
    host: *const i8,
    addresses: *const *const i8,
    count: usize,
    ttl_seconds: u32,
    context: *mut c_void,
);

/// Mirror of the `BridgeConfig` struct defined in `include/bridge.h`.
/// Optimized defaults for iOS Network Extensions (50MB jetsam limit).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BridgeConfig {
    pub mtu: u32,
    pub packet_pool_bytes: u32,
    pub per_flow_bytes: u32,
    pub poll_min_interval_ms: u32,
    pub poll_max_interval_ms: u32,
    /// Memory budget for socket buffers in bytes. Default: 16MB.
    /// Sockets are allocated dynamically up to this limit.
    pub socket_memory_budget: u32,
    /// TCP receive buffer size per socket in bytes. Default: 16384 (16KB).
    pub tcp_rx_buffer_size: u32,
    /// TCP transmit buffer size per socket in bytes. Default: 16384 (16KB).
    pub tcp_tx_buffer_size: u32,
    /// UDP buffer size per socket in bytes. Default: 16384 (16KB).
    pub udp_buffer_size: u32,
    /// Ring buffer capacity for inbound/outbound packets. Default: 512.
    pub ring_capacity: u32,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            mtu: 1280,
            packet_pool_bytes: 4 * 1_048_576,   // 4MB
            per_flow_bytes: 64 * 1_024,          // 64KB
            poll_min_interval_ms: 10,
            poll_max_interval_ms: 250,
            socket_memory_budget: 16 * 1_048_576, // 16MB for socket buffers
            tcp_rx_buffer_size: 16 * 1024,        // 16KB per socket
            tcp_tx_buffer_size: 16 * 1024,        // 16KB per socket
            udp_buffer_size: 16 * 1024,           // 16KB per socket
            ring_capacity: 512,
        }
    }
}

/// Callbacks installed by Swift so the engine can interact with the adapter.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BridgeCallbacks {
    pub emit_packets: EmitPacketsFn,
    pub request_tcp_dial: DialFn,
    pub request_udp_dial: DialFn,
    pub tcp_send: SendFn,
    pub udp_send: SendFn,
    pub tcp_close: CloseFn,
    pub udp_close: CloseFn,
    pub record_dns: RecordDnsFn,
    pub context: *mut c_void,
}

unsafe impl Send for BridgeCallbacks {}
unsafe impl Sync for BridgeCallbacks {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FlowStats {
    pub poll_iterations: u64,
    pub frames_emitted: u64,
    pub bytes_emitted: u64,
    pub tcp_flush_events: u64,
    pub udp_flush_events: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct BridgeResolveResult {
    pub addresses: *mut *mut c_char,
    pub count: usize,
    pub storage: *mut c_void,
    pub ttl_seconds: u32,
}

impl Default for BridgeResolveResult {
    fn default() -> Self {
        Self {
            addresses: ptr::null_mut(),
            count: 0,
            storage: ptr::null_mut(),
            ttl_seconds: 0,
        }
    }
}

#[repr(C)]
pub struct BridgeLogSink {
    pub log: Option<
        unsafe extern "C" fn(
            level: *const c_char,
            message: *const c_char,
            breadcrumbs: u32,
            context: *mut c_void,
        ),
    >,
    pub context: *mut c_void,
    pub enabled_breadcrumbs: u32,
}

impl BridgeResolveResult {
    pub fn reset(&mut self) {
        unsafe {
            if !self.storage.is_null() {
                let mut vec = Box::from_raw(self.storage as *mut Vec<*mut c_char>);
                for entry in vec.drain(..) {
                    if !entry.is_null() {
                        drop(CString::from_raw(entry));
                    }
                }
            } else if !self.addresses.is_null() && self.count > 0 {
                let slice = slice::from_raw_parts_mut(self.addresses, self.count);
                for entry in slice.iter_mut() {
                    if !entry.is_null() {
                        drop(CString::from_raw(*entry));
                        *entry = ptr::null_mut();
                    }
                }
            }
        }
        self.addresses = ptr::null_mut();
        self.count = 0;
        self.storage = ptr::null_mut();
        self.ttl_seconds = 0;
    }

    #[allow(clippy::result_unit_err)]
    pub fn populate(&mut self, values: &[String], ttl_seconds: u32) -> Result<(), ()> {
        self.reset();
        if values.is_empty() {
            return Ok(());
        }
        let mut pointers: Vec<*mut c_char> = Vec::with_capacity(values.len());
        for value in values {
            let c_string = CString::new(value.as_str()).map_err(|_| ())?;
            pointers.push(c_string.into_raw());
        }
        let mut boxed_vec = Box::new(pointers);
        self.count = boxed_vec.len();
        self.addresses = boxed_vec.as_mut_ptr();
        self.storage = Box::into_raw(boxed_vec) as *mut c_void;
        self.ttl_seconds = ttl_seconds;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowCounters {
    pub tcp_admission_fail: u64,
    pub udp_admission_fail: u64,
    pub tcp_backpressure_drops: u64,
    pub udp_backpressure_drops: u64,
    /// Count of invalid IP packets (malformed headers, bad version, etc.)
    pub invalid_ip_packets: u64,
    /// Count of invalid TCP packets (bad checksums, truncated, etc.)
    pub invalid_tcp_packets: u64,
    /// Count of invalid UDP packets (bad checksums, truncated, etc.)
    pub invalid_udp_packets: u64,
}

pub const BRIDGE_TELEMETRY_MAX_QNAME: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BridgeTelemetryIp {
    pub family: u8,
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BridgeTelemetryEvent {
    pub timestamp_ms: u64,
    pub payload_len: u32,
    pub protocol: u8,
    pub direction: u8,
    pub flags: u8,
    pub src_ip: BridgeTelemetryIp,
    pub dst_ip: BridgeTelemetryIp,
    pub dns_qname_len: u8,
    pub dns_qname: [c_char; BRIDGE_TELEMETRY_MAX_QNAME],
}

impl Default for BridgeTelemetryEvent {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            payload_len: 0,
            protocol: 0,
            direction: 0,
            flags: 0,
            src_ip: BridgeTelemetryIp::default(),
            dst_ip: BridgeTelemetryIp::default(),
            dns_qname_len: 0,
            dns_qname: [0; BRIDGE_TELEMETRY_MAX_QNAME],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BridgeHostRuleConfig {
    pub pattern: *const c_char,
    pub block: bool,
    pub latency_ms: u32,
    pub jitter_ms: u32,
}

#[cfg(test)]
mod tests;
