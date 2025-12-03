//! Flow maintenance and cleanup operations.
//!
//! Handles pruning of idle/stale flows, buffer flushing, and shaping queue draining.

use super::*;
use batch::CallbackBatch;
use state::{
    ip_string, FlowKey, DIAL_PENDING_TIMEOUT, TCP_SYN_SENT_TIMEOUT, UDP_IDLE_TIMEOUT,
};
use std::time::Instant as StdInstant;

impl FlowManager {
    pub(super) fn drain_shaping_queues(&mut self, now: StdInstant) -> bool {
        let mut ready_payloads: smallvec::SmallVec<[(u64, FlowKind, Vec<u8>); 16]> =
            smallvec::SmallVec::new();
        for entry in self.flow_keys.values_mut() {
            if let Some(shaper) = entry.shaping.as_mut() {
                let handle = entry.handle;
                let kind = entry.kind;
                shaper.drain_ready(now, |payload| {
                    ready_payloads.push((handle, kind, payload));
                });
            }
        }
        let mut did_work = false;
        for (handle, kind, payload) in ready_payloads {
            if self.forward_remote_payload_inner(handle, payload.as_slice(), kind, true) {
                did_work = true;
            }
        }
        did_work
    }

    pub(super) fn flush_ready_buffers(&mut self, now: StdInstant) -> bool {
        let ready_keys: Vec<FlowKey> = self
            .flow_keys
            .iter()
            .filter_map(|(key, entry)| {
                if entry.ready
                    && !entry.buffered.is_empty()
                    && entry
                        .backpressure_retry_at
                        .map(|deadline| deadline <= now)
                        .unwrap_or(true)
                {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect();
        let mut did_work = false;
        for key in ready_keys {
            if let Some(entry) = self.flow_keys.get_mut(&key) {
                entry.backpressure_retry_at = None;
            }
            self.flush_buffered_payloads(key);
            did_work = true;
        }
        did_work
    }

    // ==================== BATCHED VERSIONS ====================
    // These versions add callbacks to a batch instead of executing directly.

    /// Prune idle UDP flows, adding close notifications to batch.
    pub(super) fn prune_idle_udp_flows_batched(
        &mut self,
        now: StdInstant,
        batch: &mut CallbackBatch,
    ) -> bool {
        let mut pruned = false;
        let idle_keys: Vec<FlowKey> = self
            .flow_keys
            .iter()
            .filter_map(|(key, entry)| {
                if entry.kind != FlowKind::Udp || !entry.ready {
                    return None;
                }
                if now
                    .checked_duration_since(entry.last_activity)
                    .map(|elapsed| elapsed >= UDP_IDLE_TIMEOUT)
                    .unwrap_or(false)
                {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect();
        for key in idle_keys {
            let should_close = if let Some(entry) = self.flow_keys.get(&key) {
                now.checked_duration_since(entry.last_activity)
                    .map(|elapsed| elapsed >= UDP_IDLE_TIMEOUT)
                    .unwrap_or(false)
            } else {
                false
            };

            if should_close {
                if let Some(entry) = self.flow_keys.get(&key) {
                    logger::breadcrumb(
                        BreadcrumbFlags::FLOW,
                        format!(
                            "UDP idle timeout for handle {} dst={} port={} (active={})",
                            entry.handle,
                            ip_string(key.dst_ip),
                            key.dst_port,
                            self.memory.udp_socket_count
                        ),
                    );
                    let handle = entry.handle;
                    batch.add_close(handle, "udp_idle_timeout", FlowKind::Udp);
                    self.remove_flow(handle);
                    pruned = true;
                }
            } else {
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "UDP idle timeout skipped - flow became active (dst={} port={})",
                        ip_string(key.dst_ip),
                        key.dst_port
                    ),
                );
            }
        }
        pruned
    }

    /// Close flows where the dial operation has been pending too long, batching callbacks.
    pub(super) fn prune_timed_out_dials_batched(
        &mut self,
        now: StdInstant,
        batch: &mut CallbackBatch,
    ) -> bool {
        let mut pruned = false;
        let timed_out: Vec<(u64, FlowKind)> = self
            .flow_keys
            .values()
            .filter_map(|entry| {
                if !entry.pending_dial {
                    return None;
                }
                let started = entry.dial_started_at?;
                if now
                    .checked_duration_since(started)
                    .map(|elapsed| elapsed >= DIAL_PENDING_TIMEOUT)
                    .unwrap_or(false)
                {
                    Some((entry.handle, entry.kind))
                } else {
                    None
                }
            })
            .collect();

        for (handle, kind) in timed_out {
            logger::info(format!(
                "PRUNE_DIAL_TIMEOUT handle={} kind={:?}",
                handle, kind
            ));
            logger::warn(format!(
                "FlowManager: {:?} dial timeout for handle {} (pending > {:?})",
                kind, handle, DIAL_PENDING_TIMEOUT
            ));
            logger::breadcrumb(
                BreadcrumbFlags::FLOW,
                format!(
                    "{:?} dial timeout for handle {} (Swift never called on_dial_result)",
                    kind, handle
                ),
            );
            batch.add_close(handle, "dial_timeout", kind);
            self.remove_flow(handle);
            pruned = true;
        }
        pruned
    }

    /// Close TCP flows that have been waiting for connection establishment too long, batching callbacks.
    pub(super) fn prune_stale_tcp_flows_batched(
        &mut self,
        now: StdInstant,
        batch: &mut CallbackBatch,
    ) -> bool {
        let mut pruned = false;
        let stale: Vec<u64> = self
            .flow_keys
            .values()
            .filter_map(|entry| {
                if entry.kind != FlowKind::Tcp || entry.ready {
                    return None;
                }
                if now
                    .checked_duration_since(entry.created_at)
                    .map(|elapsed| elapsed >= TCP_SYN_SENT_TIMEOUT)
                    .unwrap_or(false)
                {
                    Some(entry.handle)
                } else {
                    None
                }
            })
            .collect();

        for handle in stale {
            logger::info(format!("PRUNE_STALE_TCP handle={}", handle));
            logger::warn(format!(
                "FlowManager: TCP flow timeout for handle {} (not ready after {:?})",
                handle, TCP_SYN_SENT_TIMEOUT
            ));
            logger::breadcrumb(
                BreadcrumbFlags::FLOW,
                format!(
                    "TCP flow timeout for handle {} (connection not established)",
                    handle
                ),
            );
            batch.add_close(handle, "connection_timeout", FlowKind::Tcp);
            self.remove_flow(handle);
            pruned = true;
        }
        pruned
    }
}
