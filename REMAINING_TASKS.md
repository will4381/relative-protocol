# Engine Integration Tasks

Tracking the work still required to reach a fully functional smoltcp-based engine.

## 1. Flow Manager & smoltcp sockets

- [ ] Bind each TCP/UDP socket to a flow key (local/remote IP + port) once parsed from inbound packets.
- [ ] Move data between smoltcp sockets and Swift callbacks (`tcp_send`, `udp_send`) instead of returning raw packets immediately.
- [ ] Feed remote payloads received via `BridgeEngineOnTcpReceive/OnUdpReceive` into the appropriate smoltcp sockets so ACK/data frames are emitted back to the OS.
- [ ] Enforce admission limits (128 TCP, 128 UDP) and update counters (`tcp_admission_fail`, `udp_admission_fail`).
- [ ] Implement idle timers and backpressure handling (mark flows send-paused when Swift reports blocked writes).
- [ ] Track flow → Swift connection IDs so close/error events reach the right `NWConnection`.

## 2. Engine poll loop

- [ ] Replace the current synchronous parsing with a single-thread Tokio task that:
  - polls `Interface::poll(now)` every 5 ms,
  - wakes immediately when inbound frames or remote data arrive,
  - drains outbound frames from `TunHandle::drain_outbound()` and batches them via `emitPackets`.
- [ ] Ensure `BridgeEngineHandlePacket` enqueues frames into the device ring; only the poll loop should call smoltcp.

## 3. Swift bridge updates

- [ ] Route every NWConnection read into `BridgeEngineOnTcpReceive/OnUdpReceive`; stop bypassing TCP semantics.
- [ ] Maintain per-handle state (connection ID, backpressure, closures) so Rust can drive FIN/RST/EOF correctly.
- [ ] Surface errors and path changes back to Rust via the new close callbacks.

## 4. DNS resolver / metadata

- [ ] Flesh out `dns/system.rs` so the engine can perform resolutions when Swift does not provide a hook, and emit host/IP metadata back through the callback surface.

## 5. Diagnostics & metrics

- [ ] Add counters for admission failures, backpressure drops, idle timeouts, and dial errors.
- [ ] Expose those metrics through the existing `BridgeConfig` or log sink.

## 6. Testing & harness

- [ ] Create a Rust-only mock dialer (simulates Swift callbacks) so flows can be tested end-to-end without Swift.
- [ ] Add capture-replay tests that inject synthetic IP frames and assert the emitted packets, dial requests, and flow closures.
- [ ] Performance sanity tests (multiple TCP streams, UDP bursts) to ensure the poll loop keeps up.

---

**Note on socket creation:** right now `FlowManager::handle_tcp_packet` / `handle_udp_packet` pull preallocated smoltcp socket handles from pools but do not yet bind or open them. Real socket creation (listen/connect, attaching to the interface) will be part of the tasks above when smoltcp is fully integrated.
