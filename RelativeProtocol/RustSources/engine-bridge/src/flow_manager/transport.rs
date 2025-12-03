use super::*;
use crate::dns::parse_response;
use batch::CallbackBatch;
use state::{
    buffer_payload, TCP_BACKPRESSURE_MAX_COOLDOWN_MS, TCP_BACKPRESSURE_RETRY_MS,
};
use std::collections::VecDeque;
use std::time::{Duration as StdDuration, Instant as StdInstant};

impl FlowManager {
    #[inline]
    pub(super) fn forward_remote_payload(
        &mut self,
        handle: u64,
        payload: &[u8],
        kind: FlowKind,
    ) -> bool {
        self.forward_remote_payload_inner(handle, payload, kind, false)
    }

    #[inline]
    pub(super) fn forward_remote_payload_inner(
        &mut self,
        handle: u64,
        payload: &[u8],
        kind: FlowKind,
        bypass_shaping: bool,
    ) -> bool {
        if payload.is_empty() {
            return true;
        }
        let Some(key) = self.handle_map.get(&handle).copied() else {
            return false;
        };
        let dns_qname = if kind == FlowKind::Udp && (key.src_port == 53 || key.dst_port == 53) {
            self.record_dns_response(&key, payload)
        } else {
            None
        };

        // Record telemetry for traffic flowing from the network back toward the client.
        let protocol = match kind {
            FlowKind::Tcp => 6u8,
            FlowKind::Udp => 17u8,
        };
        let mut event = TelemetryEvent::new(
            protocol,
            PacketDirection::NetworkToClient,
            payload.len() as u32,
            smolt_to_std_ip(key.dst_ip),
            smolt_to_std_ip(key.src_ip),
        );
        if let Some(host) = dns_qname.as_ref() {
            event.dns_qname = Some(host.clone());
            event.dns_response = true;
            event.flags |= TELEMETRY_FLAG_DNS | TELEMETRY_FLAG_DNS_RESPONSE;
        }
        if let Some(entry) = self.flow_keys.get(&key) {
            if let Some(shaper) = entry.shaping.as_ref() {
                // Shaping still applies, but we want to preserve that policy context on the event.
                if matches!(shaper.config, ShapingConfig { .. }) {
                    event.flags |= TELEMETRY_FLAG_POLICY_SHAPE;
                }
            }
        }
        self.telemetry.record(event);

        let socket;
        let handle_id;
        {
            let Some(entry) = self.flow_keys.get_mut(&key) else {
                return false;
            };
            if !entry.ready {
                if buffer_payload(entry, payload) {
                    entry.last_activity = StdInstant::now();
                    return true;
                }
                return false;
            }
            if !bypass_shaping {
                if let Some(shaper) = entry.shaping.as_mut() {
                    // Copy config to avoid borrow conflict with self.compute_shaping_delay
                    let config = shaper.config;
                    let _ = entry; // End the mutable borrow of entry
                    let delay = self.compute_shaping_delay(&config);
                    // Re-borrow entry for shaper access
                    let entry = self.flow_keys.get_mut(&key).unwrap();
                    let shaper = entry.shaping.as_mut().unwrap();
                    let ready_at = StdInstant::now() + delay;
                    if shaper.enqueue(payload, ready_at) {
                        entry.last_activity = StdInstant::now();
                        self.wake.notify_one();
                        return true;
                    }
                    return false;
                }
            }
            socket = entry.socket;
            handle_id = entry.handle;
        }

        let status = match kind {
            FlowKind::Tcp => self.enqueue_remote_tcp(socket, payload),
            FlowKind::Udp => self.enqueue_remote_udp(socket, &key, payload),
        };
        match status {
            FlowStatus::Ok => {
                if let Some(entry_mut) = self.flow_keys.get_mut(&key) {
                    entry_mut.backpressure_retry_at = None;
                    entry_mut.backpressure_cooldown_ms = TCP_BACKPRESSURE_RETRY_MS;
                    entry_mut.last_activity = StdInstant::now();
                }
                self.wake.notify_one();
                true
            }
            FlowStatus::Backpressure(reason) => {
                // Log backpressure events for debugging "Operation canceled" issues
                logger::info(format!(
                    "BACKPRESSURE {:?} handle={} reason=\"{}\"",
                    kind, handle_id, reason
                ));
                match kind {
                    FlowKind::Tcp => self.counters.tcp_backpressure_drops += 1,
                    FlowKind::Udp => self.counters.udp_backpressure_drops += 1,
                }
                self.wake.notify_one();
                if kind == FlowKind::Tcp {
                    if let Some(entry) = self.flow_keys.get_mut(&key) {
                        if buffer_payload(entry, payload) {
                            let cooldown = entry
                                .backpressure_cooldown_ms
                                .min(TCP_BACKPRESSURE_MAX_COOLDOWN_MS);
                            entry.backpressure_retry_at =
                                Some(StdInstant::now() + StdDuration::from_millis(cooldown));
                            entry.backpressure_cooldown_ms = (entry.backpressure_cooldown_ms * 2)
                                .min(TCP_BACKPRESSURE_MAX_COOLDOWN_MS);
                            entry.last_activity = StdInstant::now();
                            self.wake.notify_one();
                            return true;
                        }
                    }
                } else if let Some(callbacks) = self.callbacks {
                    self.notify_close(handle_id, kind, reason, callbacks);
                }
                false
            }
            FlowStatus::Closed(reason) => {
                // Log flow closure from enqueue for debugging "Operation canceled" issues
                logger::info(format!(
                    "FLOW_CLOSED_ON_ENQUEUE {:?} handle={} reason=\"{}\"",
                    kind, handle_id, reason
                ));
                self.wake.notify_one();
                if let Some(callbacks) = self.callbacks {
                    self.notify_close(handle_id, kind, reason, callbacks);
                }
                false
            }
        }
    }

    fn compute_shaping_delay(&self, config: &ShapingConfig) -> StdDuration {
        let mut delay = StdDuration::from_millis(config.latency_ms as u64);
        if config.jitter_ms > 0 {
            // Fast xorshift32 PRNG - avoids expensive SystemTime::now() syscall
            let jitter = self.fast_jitter(config.jitter_ms);
            delay += StdDuration::from_millis(jitter as u64);
        }
        delay
    }

    /// Fast xorshift32 PRNG for jitter calculation.
    /// Much faster than SystemTime::now() syscall.
    /// Uses Cell for interior mutability to avoid borrow conflicts.
    #[inline]
    fn fast_jitter(&self, max: u32) -> u32 {
        // xorshift32 algorithm
        let mut x = self.jitter_state.get();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.jitter_state.set(x);
        x % (max + 1)
    }

    fn enqueue_remote_tcp(&mut self, socket: SocketHandle, payload: &[u8]) -> FlowStatus {
        if payload.is_empty() {
            return FlowStatus::Ok;
        }
        let socket = self.sockets.get_mut::<TcpSocket>(socket);
        if !socket.can_send() {
            return FlowStatus::Backpressure("tcp_send_buffer_full");
        }
        match socket.send_slice(payload) {
            Ok(written) => {
                if written == payload.len() {
                    FlowStatus::Ok
                } else {
                    FlowStatus::Backpressure("tcp_send_buffer_full")
                }
            }
            Err(TcpSendError::InvalidState) => FlowStatus::Closed("tcp_invalid_state"),
        }
    }

    fn enqueue_remote_udp(
        &mut self,
        _socket: SocketHandle,
        key: &FlowKey,
        payload: &[u8],
    ) -> FlowStatus {
        if payload.is_empty() {
            return FlowStatus::Ok;
        }
        // Build UDP packet with correct 5-tuple directly instead of using smoltcp socket.
        // This fixes the port mapping issue where smoltcp delivers to wrong socket
        // because all UDP flows to the same destination share the same endpoint binding.
        if let Some(packet) = super::build_udp_response(key, payload) {
            if let Some(callbacks) = self.callbacks {
                super::interface::emit_frames(callbacks, vec![packet]);
                FlowStatus::Ok
            } else {
                FlowStatus::Closed("no_callbacks")
            }
        } else {
            FlowStatus::Closed("udp_build_failed")
        }
    }

    /// Record DNS response data flowing from the network so host-based policy and telemetry
    /// can see mappings even when queries traverse the tunnel.
    fn record_dns_response(&self, _key: &FlowKey, payload: &[u8]) -> Option<String> {
        let mappings = parse_response(payload);
        if mappings.is_empty() {
            return None;
        }
        for mapping in &mappings {
            self.policy
                .observe_dns_mapping(mapping.host.as_str(), &mapping.addresses, mapping.ttl);
        }
        if let Some(callbacks) = self.callbacks {
            for mapping in &mappings {
                self.emit_dns_mapping(callbacks, mapping);
            }
        }
        mappings.first().map(|m| m.host.clone())
    }

    /// Flush outbound data from sockets, batching callbacks for later execution.
    #[inline]
    pub(super) fn flush_outbound(&mut self, batch: &mut CallbackBatch) {
        // Collect socket handles first to avoid borrow issues, but use a small stack array
        // for common case (< 64 flows) to avoid heap allocation.
        // Filter unready flows early to avoid unnecessary work.
        let mut tcp_handles: smallvec::SmallVec<[(SocketHandle, u64); 32]> = smallvec::SmallVec::new();
        let mut udp_handles: smallvec::SmallVec<[(SocketHandle, u64); 32]> = smallvec::SmallVec::new();

        for entry in self.flow_keys.values() {
            if !entry.ready {
                continue; // Early filter: skip unready flows
            }
            match entry.kind {
                FlowKind::Tcp => tcp_handles.push((entry.socket, entry.handle)),
                FlowKind::Udp => udp_handles.push((entry.socket, entry.handle)),
            }
        }

        for (socket, handle) in tcp_handles {
            self.flush_tcp_batched(socket, handle, batch);
        }
        for (socket, handle) in udp_handles {
            self.flush_udp_batched(socket, handle, batch);
        }
    }

    pub(super) fn flush_buffered_payloads(&mut self, key: FlowKey) {
        let Some(entry) = self.flow_keys.get_mut(&key) else {
            return;
        };
        if entry.buffered.is_empty() {
            return;
        }
        let handle = entry.handle;
        let kind = entry.kind;
        let mut buffered = VecDeque::new();
        std::mem::swap(&mut buffered, &mut entry.buffered);
        entry.buffered_bytes = 0;
        let _ = entry;

        // Get callbacks for sending to the network
        let callbacks = match self.callbacks {
            Some(cb) => cb,
            None => return,
        };

        for payload in buffered {
            if payload.is_empty() {
                continue;
            }
            // Buffered payloads are CLIENT data going TO the network.
            // Use callbacks to send them out, not forward_remote_payload
            // which is for NETWORK data going back to the client.
            match kind {
                FlowKind::Tcp => unsafe {
                    (callbacks.tcp_send)(
                        handle,
                        payload.as_ptr(),
                        payload.len(),
                        callbacks.context,
                    );
                },
                FlowKind::Udp => unsafe {
                    (callbacks.udp_send)(
                        handle,
                        payload.as_ptr(),
                        payload.len(),
                        callbacks.context,
                    );
                },
            }
        }
    }

    /// Flush TCP socket data into the batch for later callback execution.
    #[inline]
    fn flush_tcp_batched(
        &mut self,
        socket_handle: SocketHandle,
        handle: u64,
        batch: &mut CallbackBatch,
    ) {
        let socket = self.sockets.get_mut::<TcpSocket>(socket_handle);
        while socket.can_recv() {
            self.flush_buffer.clear();
            match socket.recv(|payload| {
                self.flush_buffer.extend_from_slice(payload);
                (payload.len(), ())
            }) {
                Ok(()) => {
                    if self.flush_buffer.is_empty() {
                        break;
                    }
                    // Add to batch instead of calling callback directly
                    batch.add_tcp_send(handle, self.flush_buffer.clone());
                    self.stats.tcp_flush_events = self.stats.tcp_flush_events.saturating_add(1);
                    self.stats.bytes_emitted = self
                        .stats
                        .bytes_emitted
                        .saturating_add(self.flush_buffer.len() as u64);
                }
                Err(_) => break,
            }
        }
    }

    /// Flush UDP socket data into the batch for later callback execution.
    #[inline]
    fn flush_udp_batched(
        &mut self,
        socket_handle: SocketHandle,
        handle: u64,
        batch: &mut CallbackBatch,
    ) {
        let socket = self.sockets.get_mut::<UdpSocket>(socket_handle);
        while let Ok((payload, _meta)) = socket.recv() {
            // Add to batch instead of calling callback directly
            batch.add_udp_send(handle, payload.to_vec());
            self.stats.udp_flush_events = self.stats.udp_flush_events.saturating_add(1);
            self.stats.bytes_emitted =
                self.stats.bytes_emitted.saturating_add(payload.len() as u64);
        }
    }
}
