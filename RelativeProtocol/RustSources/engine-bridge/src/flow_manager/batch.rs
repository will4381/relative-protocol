//! Callback batching for lock-free execution.
//!
//! Collects all callback requests during poll() so they can be executed
//! after releasing the FlowManager lock, eliminating callback contention.

use crate::ffi::BridgeCallbacks;
use libc::{AF_INET, AF_INET6};
use smallvec::SmallVec;
use smoltcp::wire::IpAddress;
use std::ffi::CString;
use std::net::IpAddr;

use super::state::FlowKind;

/// A dial request to be sent to Swift.
pub struct DialRequest {
    pub handle: u64,
    pub host: CString,
    pub port: u16,
    pub kind: FlowKind,
}

/// A close notification to be sent to Swift.
pub struct CloseRequest {
    pub handle: u64,
    pub reason: CString,
    pub kind: FlowKind,
}

/// Data to be sent on a flow.
pub struct SendRequest {
    pub handle: u64,
    pub payload: Vec<u8>,
    #[allow(dead_code)]
    pub kind: FlowKind,
}

/// A DNS mapping to record.
pub struct DnsRecord {
    pub host: CString,
    pub addresses: Vec<CString>,
    pub ttl_seconds: u32,
}

/// Batched callbacks collected during poll() for execution outside the lock.
///
/// This struct collects all callback requests so they can be executed
/// after releasing the FlowManager mutex, significantly reducing lock hold time.
#[derive(Default)]
pub struct CallbackBatch {
    /// Frames to emit back to the iOS tunnel (IP packets).
    pub frames: Vec<Vec<u8>>,
    /// TCP data to send to bypass connections.
    pub tcp_sends: SmallVec<[SendRequest; 16]>,
    /// UDP data to send to bypass connections.
    pub udp_sends: SmallVec<[SendRequest; 16]>,
    /// Close notifications.
    pub closes: SmallVec<[CloseRequest; 8]>,
    /// Dial requests.
    pub dials: SmallVec<[DialRequest; 8]>,
    /// DNS mappings to record.
    pub dns_records: SmallVec<[DnsRecord; 4]>,
}

// Thread-local buffers for emit_frames to avoid repeated allocations
thread_local! {
    static EMIT_PTRS: std::cell::RefCell<Vec<*const u8>> = const { std::cell::RefCell::new(Vec::new()) };
    static EMIT_SIZES: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
    static EMIT_PROTOCOLS: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
    static DNS_ADDR_PTRS: std::cell::RefCell<Vec<*const i8>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl CallbackBatch {
    /// Create a new empty callback batch with pre-allocated capacity.
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(32),
            tcp_sends: SmallVec::new(),
            udp_sends: SmallVec::new(),
            closes: SmallVec::new(),
            dials: SmallVec::new(),
            dns_records: SmallVec::new(),
        }
    }

    /// Check if any work was batched.
    #[inline]
    #[allow(dead_code)]
    pub fn has_work(&self) -> bool {
        !self.frames.is_empty()
            || !self.tcp_sends.is_empty()
            || !self.udp_sends.is_empty()
            || !self.closes.is_empty()
            || !self.dials.is_empty()
            || !self.dns_records.is_empty()
    }

    /// Add frames to emit.
    #[inline]
    pub fn add_frames(&mut self, frames: Vec<Vec<u8>>) {
        self.frames.extend(frames);
    }

    /// Add a single frame to emit.
    #[inline]
    #[allow(dead_code)]
    pub fn add_frame(&mut self, frame: Vec<u8>) {
        self.frames.push(frame);
    }

    /// Add a TCP send request.
    #[inline]
    pub fn add_tcp_send(&mut self, handle: u64, payload: Vec<u8>) {
        self.tcp_sends.push(SendRequest {
            handle,
            payload,
            kind: FlowKind::Tcp,
        });
    }

    /// Add a UDP send request.
    #[inline]
    pub fn add_udp_send(&mut self, handle: u64, payload: Vec<u8>) {
        self.udp_sends.push(SendRequest {
            handle,
            payload,
            kind: FlowKind::Udp,
        });
    }

    /// Add a close notification.
    #[inline]
    pub fn add_close(&mut self, handle: u64, reason: &str, kind: FlowKind) {
        if let Ok(c_reason) = CString::new(reason) {
            self.closes.push(CloseRequest {
                handle,
                reason: c_reason,
                kind,
            });
        }
    }

    /// Add a dial request.
    #[inline]
    pub fn add_dial(&mut self, handle: u64, ip: IpAddress, port: u16, kind: FlowKind) {
        let host = super::state::ip_string(ip);
        if let Ok(c_host) = CString::new(host) {
            self.dials.push(DialRequest {
                handle,
                host: c_host,
                port,
                kind,
            });
        }
    }

    /// Add a DNS mapping to record.
    #[inline]
    #[allow(dead_code)]
    pub fn add_dns_record(&mut self, host: &str, addresses: &[IpAddr], ttl_seconds: u32) {
        let Ok(c_host) = CString::new(host) else { return };
        let c_addrs: Vec<CString> = addresses
            .iter()
            .filter_map(|addr| CString::new(addr.to_string()).ok())
            .collect();
        if c_addrs.is_empty() {
            return;
        }
        self.dns_records.push(DnsRecord {
            host: c_host,
            addresses: c_addrs,
            ttl_seconds,
        });
    }

    /// Execute all batched callbacks. This should be called outside the FlowManager lock.
    ///
    /// # Safety
    /// The callbacks must be valid function pointers and the context must be valid.
    pub fn execute(self, callbacks: BridgeCallbacks) {
        // 1. Emit frames first (highest priority - packet responses)
        if !self.frames.is_empty() {
            Self::execute_emit_frames(&self.frames, callbacks);
        }

        // 2. Execute dial requests (before sends, so connections can be established)
        for dial in &self.dials {
            unsafe {
                match dial.kind {
                    FlowKind::Tcp => (callbacks.request_tcp_dial)(
                        dial.host.as_ptr(),
                        dial.port,
                        dial.handle,
                        callbacks.context,
                    ),
                    FlowKind::Udp => (callbacks.request_udp_dial)(
                        dial.host.as_ptr(),
                        dial.port,
                        dial.handle,
                        callbacks.context,
                    ),
                }
            }
        }

        // 3. Execute TCP sends
        for send in &self.tcp_sends {
            unsafe {
                (callbacks.tcp_send)(
                    send.handle,
                    send.payload.as_ptr(),
                    send.payload.len(),
                    callbacks.context,
                );
            }
        }

        // 4. Execute UDP sends
        for send in &self.udp_sends {
            unsafe {
                (callbacks.udp_send)(
                    send.handle,
                    send.payload.as_ptr(),
                    send.payload.len(),
                    callbacks.context,
                );
            }
        }

        // 5. Execute close notifications
        for close in &self.closes {
            unsafe {
                match close.kind {
                    FlowKind::Tcp => (callbacks.tcp_close)(
                        close.handle,
                        close.reason.as_ptr(),
                        callbacks.context,
                    ),
                    FlowKind::Udp => (callbacks.udp_close)(
                        close.handle,
                        close.reason.as_ptr(),
                        callbacks.context,
                    ),
                }
            }
        }

        // 6. Record DNS mappings
        for dns in &self.dns_records {
            Self::execute_dns_record(&dns, callbacks);
        }
    }

    fn execute_emit_frames(frames: &[Vec<u8>], callbacks: BridgeCallbacks) {
        EMIT_PTRS.with(|ptrs| {
            EMIT_SIZES.with(|sizes| {
                EMIT_PROTOCOLS.with(|protocols| {
                    let mut ptrs = ptrs.borrow_mut();
                    let mut sizes = sizes.borrow_mut();
                    let mut protocols = protocols.borrow_mut();

                    ptrs.clear();
                    sizes.clear();
                    protocols.clear();

                    for frame in frames {
                        ptrs.push(frame.as_ptr());
                        sizes.push(frame.len());
                        protocols.push(Self::protocol_number(frame));
                    }

                    unsafe {
                        (callbacks.emit_packets)(
                            ptrs.as_ptr(),
                            sizes.as_ptr(),
                            protocols.as_ptr(),
                            ptrs.len(),
                            callbacks.context,
                        );
                    }
                });
            });
        });
    }

    fn execute_dns_record(dns: &DnsRecord, callbacks: BridgeCallbacks) {
        DNS_ADDR_PTRS.with(|ptrs| {
            let mut ptrs = ptrs.borrow_mut();
            ptrs.clear();
            for addr in &dns.addresses {
                ptrs.push(addr.as_ptr());
            }
            unsafe {
                (callbacks.record_dns)(
                    dns.host.as_ptr(),
                    ptrs.as_ptr(),
                    ptrs.len(),
                    dns.ttl_seconds,
                    callbacks.context,
                );
            }
        });
    }

    #[inline]
    fn protocol_number(frame: &[u8]) -> u32 {
        if frame.first().map(|byte| (byte >> 4) == 6).unwrap_or(false) {
            AF_INET6 as u32
        } else {
            AF_INET as u32
        }
    }
}
