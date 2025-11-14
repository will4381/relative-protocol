use super::*;
use state::buffer_payload;
use std::collections::VecDeque;
use std::time::{Duration as StdDuration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

impl FlowManager {
    pub(super) fn forward_remote_payload(
        &mut self,
        handle: u64,
        payload: &[u8],
        kind: FlowKind,
    ) -> bool {
        self.forward_remote_payload_inner(handle, payload, kind, false)
    }

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

        let socket;
        let handle_id;
        {
            let Some(entry) = self.flow_keys.get_mut(&key) else {
                return false;
            };
            if !entry.ready {
                if buffer_payload(entry, payload) {
                    logger::breadcrumb(
                        BreadcrumbFlags::FLOW,
                        format!(
                            "Buffered {:?} payload for handle {} while dial completes",
                            kind, handle
                        ),
                    );
                    entry.last_activity = StdInstant::now();
                    return true;
                }
                logger::warn(format!(
                    "FlowManager: dropping {:?} payload for handle {} (buffer full before dial)",
                    kind, handle
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} payload dropped before dial for handle {} (buffer full)",
                        kind, handle
                    ),
                );
                return false;
            }
            if !bypass_shaping {
                if let Some(shaper) = entry.shaping.as_mut() {
                    let ready_at = StdInstant::now() + Self::compute_shaping_delay(&shaper.config);
                    if shaper.enqueue(payload, ready_at) {
                        logger::breadcrumb(
                            BreadcrumbFlags::FLOW,
                            format!(
                                "{:?} payload queued for handle {} (latency={}ms jitter={}ms)",
                                kind, handle, shaper.config.latency_ms, shaper.config.jitter_ms
                            ),
                        );
                        entry.last_activity = StdInstant::now();
                        self.wake.notify_one();
                        return true;
                    }
                    logger::warn(format!(
                        "FlowManager: {:?} payload for handle {} dropped (shaping queue full)",
                        kind, handle
                    ));
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
                    entry_mut.last_activity = StdInstant::now();
                }
                self.wake.notify_one();
                true
            }
            FlowStatus::Backpressure(reason) => {
                match kind {
                    FlowKind::Tcp => self.counters.tcp_backpressure_drops += 1,
                    FlowKind::Udp => self.counters.udp_backpressure_drops += 1,
                }
                logger::warn(format!(
                    "FlowManager: {:?} backpressure for handle {} ({reason})",
                    kind, handle_id
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!(
                        "{:?} backpressure for handle {} ({reason})",
                        kind, handle_id
                    ),
                );
                self.wake.notify_one();
                if let Some(callbacks) = self.callbacks {
                    self.notify_close(handle_id, kind, reason, callbacks);
                }
                false
            }
            FlowStatus::Closed(reason) => {
                logger::warn(format!(
                    "FlowManager: {:?} closed for handle {} ({reason})",
                    kind, handle_id
                ));
                logger::breadcrumb(
                    BreadcrumbFlags::FLOW,
                    format!("{:?} closed for handle {} ({reason})", kind, handle_id),
                );
                self.wake.notify_one();
                if let Some(callbacks) = self.callbacks {
                    self.notify_close(handle_id, kind, reason, callbacks);
                }
                false
            }
        }
    }

    fn compute_shaping_delay(config: &ShapingConfig) -> StdDuration {
        let mut delay = StdDuration::from_millis(config.latency_ms as u64);
        if config.jitter_ms > 0 {
            let jitter_source = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| StdDuration::from_secs(0));
            let jitter_range = u64::from(config.jitter_ms) + 1;
            let jitter = (jitter_source.subsec_nanos() as u64) % jitter_range;
            delay += StdDuration::from_millis(jitter);
        }
        delay
    }

    fn enqueue_remote_tcp(&mut self, socket: SocketHandle, payload: &[u8]) -> FlowStatus {
        if payload.is_empty() {
            return FlowStatus::Ok;
        }
        let socket = self.sockets.get_mut::<TcpSocket>(socket);
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
        socket: SocketHandle,
        key: &FlowKey,
        payload: &[u8],
    ) -> FlowStatus {
        if payload.is_empty() {
            return FlowStatus::Ok;
        }
        let socket = self.sockets.get_mut::<UdpSocket>(socket);
        let meta = UdpMetadata::from(IpEndpoint::new(key.src_ip, key.src_port));
        match socket.send_slice(payload, meta) {
            Ok(()) => FlowStatus::Ok,
            Err(UdpSendError::BufferFull) => FlowStatus::Backpressure("udp_send_buffer_full"),
            Err(_) => FlowStatus::Closed("udp_invalid_state"),
        }
    }

    pub(super) fn flush_outbound(&mut self, callbacks: BridgeCallbacks) {
        let snapshot: Vec<(FlowKind, SocketHandle, u64, bool)> = self
            .flow_keys
            .values()
            .map(|entry| (entry.kind, entry.socket, entry.handle, entry.ready))
            .collect();
        for (kind, socket, handle, ready) in snapshot {
            match kind {
                FlowKind::Tcp => self.flush_tcp(socket, handle, ready, callbacks),
                FlowKind::Udp => self.flush_udp(socket, handle, ready, callbacks),
            }
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

        for payload in buffered {
            if payload.is_empty() {
                continue;
            }
            if !self.forward_remote_payload(handle, payload.as_slice(), kind) {
                logger::warn(format!(
                    "FlowManager: failed to flush buffered {:?} payload for handle {}",
                    kind, handle
                ));
                break;
            }
        }
    }

    fn flush_tcp(
        &mut self,
        socket_handle: SocketHandle,
        handle: u64,
        ready: bool,
        callbacks: BridgeCallbacks,
    ) {
        if !ready {
            return;
        }
        let socket = self.sockets.get_mut::<TcpSocket>(socket_handle);
        let mut drained = Vec::new();
        while socket.can_recv() {
            match socket.recv(|payload| {
                drained.clear();
                drained.extend_from_slice(payload);
                (payload.len(), ())
            }) {
                Ok(()) => {
                    if drained.is_empty() {
                        break;
                    }
                    unsafe {
                        (callbacks.tcp_send)(
                            handle,
                            drained.as_ptr(),
                            drained.len(),
                            callbacks.context,
                        );
                    }
                    self.stats.tcp_flush_events = self.stats.tcp_flush_events.saturating_add(1);
                    self.stats.bytes_emitted = self
                        .stats
                        .bytes_emitted
                        .saturating_add(drained.len() as u64);
                }
                Err(_) => break,
            }
        }
    }

    fn flush_udp(
        &mut self,
        socket_handle: SocketHandle,
        handle: u64,
        ready: bool,
        callbacks: BridgeCallbacks,
    ) {
        if !ready {
            return;
        }
        let socket = self.sockets.get_mut::<UdpSocket>(socket_handle);
        loop {
            match socket.recv() {
                Ok((payload, _meta)) => {
                    let mut chunk = Vec::with_capacity(payload.len());
                    chunk.extend_from_slice(payload);
                    unsafe {
                        (callbacks.udp_send)(
                            handle,
                            chunk.as_ptr(),
                            chunk.len(),
                            callbacks.context,
                        );
                    }
                    self.stats.udp_flush_events = self.stats.udp_flush_events.saturating_add(1);
                    self.stats.bytes_emitted =
                        self.stats.bytes_emitted.saturating_add(chunk.len() as u64);
                }
                Err(_) => break,
            }
        }
    }
}
