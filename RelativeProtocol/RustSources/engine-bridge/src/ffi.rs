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
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BridgeConfig {
    pub mtu: u32,
    pub packet_pool_bytes: u32,
    pub per_flow_bytes: u32,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            packet_pool_bytes: 8 * 1_048_576,
            per_flow_bytes: 128 * 1_024,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn populate_sets_addresses_and_ttl() {
        let mut result = BridgeResolveResult::default();
        let values = vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()];
        assert!(result.populate(&values, 42).is_ok());
        assert_eq!(result.count, 2);
        assert_eq!(result.ttl_seconds, 42);
        unsafe {
            let slice = std::slice::from_raw_parts(result.addresses, result.count);
            for ptr in slice {
                assert!(!ptr.is_null());
                let text = std::ffi::CStr::from_ptr(*ptr);
                assert!(!text.to_string_lossy().is_empty());
            }
        }
        result.reset();
        assert_eq!(result.count, 0);
        assert!(result.addresses.is_null());
        assert_eq!(result.ttl_seconds, 0);
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowCounters {
    pub tcp_admission_fail: u64,
    pub udp_admission_fail: u64,
    pub tcp_backpressure_drops: u64,
    pub udp_backpressure_drops: u64,
}
