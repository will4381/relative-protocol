//! Dial management for flow connections.
//!
//! Handles connection dial requests, retries, and backoff logic.

use super::*;
use batch::CallbackBatch;
use state::{dial_backoff_delay, ip_string, MAX_DIAL_ATTEMPTS, TCP_BACKPRESSURE_RETRY_MS};
use std::ffi::CString;
use std::time::Instant as StdInstant;

impl FlowManager {
    pub fn on_dial_result(&mut self, handle: u64, success: bool, reason: Option<&str>) {
        logger::info(format!(
            "ON_DIAL_RESULT handle={} success={} reason={} (handle_map size={})",
            handle,
            success,
            reason.unwrap_or(""),
            self.handle_map.len()
        ));
        logger::breadcrumb(
            BreadcrumbFlags::FLOW,
            format!(
                "on_dial_result handle={} success={} reason={}",
                handle,
                success,
                reason.unwrap_or("")
            ),
        );
        let Some(key) = self.handle_map.get(&handle).cloned() else {
            let existing_handles: Vec<u64> = self.handle_map.keys().copied().collect();
            logger::warn(format!(
                "FlowManager: dial result for unknown handle {} (existing handles: {:?})",
                handle, existing_handles
            ));
            return;
        };

        if let Some(entry) = self.flow_keys.get(&key) {
            if !entry.pending_dial {
                logger::warn(format!(
                    "FlowManager: dial result for handle {} but not pending_dial (ready={}, dial_attempts={})",
                    handle, entry.ready, entry.dial_attempts
                ));
            }
        }

        let mut close_params = None;
        if let Some(entry) = self.flow_keys.get_mut(&key) {
            entry.pending_dial = false;
            entry.dial_started_at = None;
            if success {
                entry.ready = true;
                entry.next_redial_at = None;
                entry.last_activity = StdInstant::now();
                entry.backpressure_cooldown_ms = TCP_BACKPRESSURE_RETRY_MS;
                entry.backpressure_retry_at = None;
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!("{:?} dial ready for handle {}", entry.kind, entry.handle),
                );
                self.wake.notify_one();
                let _ = entry;
                self.flush_buffered_payloads(key);
                return;
            }

            if entry.dial_attempts < MAX_DIAL_ATTEMPTS {
                let delay = dial_backoff_delay(entry.dial_attempts);
                entry.next_redial_at = Some(StdInstant::now() + delay);
                let message = reason.unwrap_or("dial_failed");
                logger::warn(format!(
                    "FlowManager: {:?} dial attempt {} failed for handle {} ({message}), retrying in {:?}",
                    entry.kind, entry.dial_attempts, entry.handle, delay
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} dial retry {} for handle {} ({message})",
                        entry.kind, entry.dial_attempts, entry.handle
                    ),
                );
                self.wake.notify_one();
                return;
            }

            close_params = Some((entry.handle, entry.kind));
        }

        if let Some((flow_handle, flow_kind)) = close_params {
            if let Some(callbacks) = self.callbacks {
                let message = reason.unwrap_or("dial_failed");
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!("{:?} dial failed for handle {} ({message})", flow_kind, flow_handle),
                );
                self.notify_close(flow_handle, flow_kind, message, callbacks);
            }
        }
    }

    pub(super) fn request_dial(&self, handle: u64, ip: IpAddress, port: u16, kind: FlowKind) {
        let callbacks = match self.callbacks {
            Some(cb) => cb,
            None => {
                logger::warn(format!(
                    "request_dial skipped - no callbacks (handle={} kind={:?})",
                    handle, kind
                ));
                return;
            }
        };
        let host = ip_string(ip);
        logger::info(format!(
            "DIAL_REQUEST kind={:?} handle={} dst={}:{}",
            kind, handle, host, port
        ));
        logger::breadcrumb(
            BreadcrumbFlags::FLOW,
            format!(
                "request_dial kind={:?} handle={} host={} port={}",
                kind, handle, host, port
            ),
        );
        if let Ok(c_host) = CString::new(host) {
            unsafe {
                match kind {
                    FlowKind::Tcp => (callbacks.request_tcp_dial)(
                        c_host.as_ptr(),
                        port,
                        handle,
                        callbacks.context,
                    ),
                    FlowKind::Udp => (callbacks.request_udp_dial)(
                        c_host.as_ptr(),
                        port,
                        handle,
                        callbacks.context,
                    ),
                }
            }
        }
    }

    pub(super) fn dispatch_pending_dials(&mut self, now: StdInstant) -> bool {
        if self.callbacks.is_none() {
            return false;
        }
        // Reuse scratch buffer to avoid per-poll allocation
        self.pending_dial_scratch.clear();
        for (key, entry) in self.flow_keys.iter() {
            if let Some(deadline) = entry.next_redial_at {
                if !entry.ready && !entry.pending_dial && entry.dial_attempts < MAX_DIAL_ATTEMPTS {
                    if deadline <= now {
                        self.pending_dial_scratch.push(*key);
                    }
                }
            }
        }

        let mut dispatched = false;
        for i in 0..self.pending_dial_scratch.len() {
            let key = self.pending_dial_scratch[i];
            let dispatch = if let Some(entry) = self.flow_keys.get_mut(&key) {
                if entry.ready || entry.pending_dial || entry.dial_attempts >= MAX_DIAL_ATTEMPTS {
                    None
                } else {
                    entry.pending_dial = true;
                    entry.dial_attempts = entry.dial_attempts.saturating_add(1);
                    entry.next_redial_at = None;
                    entry.dial_started_at = Some(now);
                    Some((entry.handle, entry.kind))
                }
            } else {
                None
            };

            if let Some((handle, kind)) = dispatch {
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "Requesting {:?} dial to {}:{} (handle {})",
                        kind,
                        ip_string(key.dst_ip),
                        key.dst_port,
                        handle
                    ),
                );
                self.request_dial(handle, key.dst_ip, key.dst_port, kind);
                dispatched = true;
            }
        }

        dispatched
    }

    /// Dispatch pending dials, batching callbacks for later execution.
    pub(super) fn dispatch_pending_dials_batched(
        &mut self,
        now: StdInstant,
        batch: &mut CallbackBatch,
    ) -> bool {
        if self.callbacks.is_none() {
            return false;
        }
        // Reuse scratch buffer to avoid per-poll allocation
        self.pending_dial_scratch.clear();
        for (key, entry) in self.flow_keys.iter() {
            if let Some(deadline) = entry.next_redial_at {
                if !entry.ready && !entry.pending_dial && entry.dial_attempts < MAX_DIAL_ATTEMPTS {
                    if deadline <= now {
                        self.pending_dial_scratch.push(*key);
                    }
                }
            }
        }

        let mut dispatched = false;
        for i in 0..self.pending_dial_scratch.len() {
            let key = self.pending_dial_scratch[i];
            let dispatch = if let Some(entry) = self.flow_keys.get_mut(&key) {
                if entry.ready || entry.pending_dial || entry.dial_attempts >= MAX_DIAL_ATTEMPTS {
                    None
                } else {
                    entry.pending_dial = true;
                    entry.dial_attempts = entry.dial_attempts.saturating_add(1);
                    entry.next_redial_at = None;
                    entry.dial_started_at = Some(now);
                    Some((entry.handle, entry.kind))
                }
            } else {
                None
            };

            if let Some((handle, kind)) = dispatch {
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "Requesting {:?} dial to {}:{} (handle {})",
                        kind,
                        ip_string(key.dst_ip),
                        key.dst_port,
                        handle
                    ),
                );
                // Add dial request to batch instead of calling callback directly
                batch.add_dial(handle, key.dst_ip, key.dst_port, kind);
                dispatched = true;
            }
        }

        dispatched
    }
}
