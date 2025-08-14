## RelativeProtocol TODO (Userspace TCP/IP VPN, consumer iOS)

Note: Items marked (app side) are owned by the consuming app/extension. For package scope, these are considered complete once documented.

### Milestone 0: Build and structure
- [x] Ensure `Package.swift` compiles lwIP and port sources into `RelativeProtocolC` target
  - Summary: Create a C target that includes lwIP core and your port files with correct include paths so Swift can link against the C glue and headers.
  - [x] Add `third_party/lwip/lwip-src/src/**` C sources
  - [x] Add `third_party/lwip/port/relative/**` C sources (`netif_tunif.c`, `sys_arch.c`, `lwipopts.h`, `arch/cc.h`)
  - [x] Set include paths for `lwip-src/src/include` and `port/relative`
  - [x] Link `RelativeProtocolC` to Swift target `RelativeProtocol`
  - [x] Keep `scripts/fetch_lwip.sh` as update helper; document usage in README
  - Summary: Document how to refresh lwIP so contributors can reproduce builds and keep the vendored stack current.

### Milestone 1: lwIP bring-up (device side)
- [x] Verify `rlwip_start()` initializes lwIP and adds `tunif` netif
  - Summary: Bring up lwIP in host mode with your TUN netif so packets from the OS can be parsed and processed.
- [x] Add a continuous read loop in `RelativeProtocolEngine.start()` using `packetFlow.readPackets`
  - Summary: Continuously pull packets from the tunnel and feed them into lwIP, batching for efficiency.
- [x] Update `RelativeProtocolEngine.packetOut` to detect IPv4/IPv6 by header nibble (not hardcoded AF_INET)
  - Summary: Ensure returning packets are labeled with the correct protocol family to avoid misrouting.
- [ ] Confirm IPv4 and IPv6 packets loop back to OS without modification (local echo test)
  - Summary: Validate the basic ingest→lwIP→emit path works for both IP versions before adding proxying.

### Milestone 1.5: Public packet-ingestion API (provider → package)
- [x] Expose public API so the Network Extension can pass tunnel packets into the engine for Internet egress
  - Summary: Provide a stable entry point (`ingestPacket(s)`) the provider calls to hand off packets to the engine.
  - [x] `ingestPacket(_ data: Data, proto: sa_family_t)`
  - [x] `ingestPackets(_ packets: [Data], protocols: [NSNumber])` (batch for efficiency)
  - [x] Optional async stream façade: `PacketIngestor.AsyncStream` for push-style feeding
- [x] Provide backpressure signals (closure/callback) so provider knows when to read more packets
  - Summary: Avoid memory blowups by letting the engine tell the provider to pause and resume reads.
- [x] Ensure packets fed through this API are routed via lwIP → socket bridge and not echoed to OS
  - Summary: Route ingest strictly into the proxy path so traffic exits to the Internet rather than bouncing locally.
  - [x] Expose pause/resume hints for provider read loop to avoid memory pressure
  - Summary: Surface simple hints to throttle read cadence when queues near caps.

### Milestone 2: Internet egress via proxy netif (no MDM)
- [x] Implement a second netif: `proxynetif` (terminating proxy, not IP forwarder)
  - Summary: Terminate device-side TCP/UDP in lwIP and hand payloads to Swift so you can talk to the Internet via sockets.
  - [x] Create `third_party/lwip/port/relative/netif_proxynetif.c`
  - [x] `proxynetif_init(struct netif*)` and `output` for IPv4/IPv6 that hands payloads to Swift bridge
  - [x] Serialize pbuf chains and call a Swift callback (Swift parses 5‑tuple; FlowID exposed to delegate)
- [x] Extend C glue (`Sources/RelativeProtocolC/rlwip_glue.c`)
  - Summary: Add Swift callback setters and an inject function to deliver Internet-side data back into lwIP.
  - [x] Expose setters for proxy callbacks (UDP and TCP paths)
  - [x] Add `rlwip_inject_proxynetif(const uint8_t* data, size_t len)` to inject Internet-side segments/packets back into lwIP
  - [x] Do NOT set default route or rely on `IP_FORWARD`; treat proxynetif as termination shim
- [x] Update `third_party/lwip/port/relative/lwipopts.h`
  - Summary: Keep `NO_SYS` and enable software checksums; right-size pools for extension memory limits.
  - [x] Keep `NO_SYS 1`; compute checksums in software
  - [x] Size pools/buffers appropriately (see Milestone 6 tuning)
  - [x] Error handling: synthesize TCP RST or ICMP errors back to device on socket failures/timeouts
  - Summary: Fail fast and cleanly when upstream sockets break so apps see expected errors.
  - [x] Timers: drive `sys_check_timeouts()` on a single serial queue at 100–250 ms (and optional fast tick)
  - Summary: Advance lwIP timers yourself since there’s no OS thread; use one queue for correctness.

### Milestone 3: Swift SocketBridge and flow management
- [x] Create `SocketBridge.swift`
  - Summary: Central coordinator that translates between lwIP segments and Network.framework connections.
- [x] UDP bridge: map 5‑tuple → `NWConnection`(UDP), send payload; receive and inject as IP/UDP via `rlwip_inject_proxynetif`
- [x] TCP bridge (`TcpBridge`): per‑flow `NWConnection`(TCP) to dest host:port
    - [x] Map lwIP segments → bytestream writes (respect lwIP seq/wnd) — initial ordering/buffering implemented
    - [x] Map socket reads → TCP segments (segment to peer MSS/wnd, compute checksums) and inject via `rlwip_inject_proxynetif`
    - [x] Handle SYN/SYN-ACK/ACK, FIN/RST gracefully (close flows on either side)
- [x] Maintain flow table keyed by 5‑tuple (v4/v6)
  - Summary: Track per-flow state and lifecycle so you can GC idle/closed connections deterministically.
  - [x] Socket helpers (public utilities for app use when desired)
   - Summary: Provide convenience functions around endpoints and checksum building to reduce boilerplate.
    - [x] Helper to derive `NWEndpoint` from IP headers: use `.ipv4/.ipv6` for IP literals
    - [x] UDP helper: stateless send and pooling keyed by endpoint
    - [x] TCP helper: lifecycle helpers, error mapping, convenience send/receive APIs
    - [x] Checksum/build helpers surfaced as Swift wrappers where useful
  - [x] Execution model: single serial `DispatchQueue` for lwIP calls to satisfy `NO_SYS` assumptions
   - Summary: Enforce all lwIP mutations on one queue to avoid races.
  - [x] Minimize copies when bridging (reuse buffers, `withUnsafeBytes` where safe)
   - Summary: Keep GC pressure low by reusing buffers and avoiding unnecessary Data copies.
  - [x] Per-flow isolation: wrap each socket side in a flow actor; marshal into the single lwIP queue
   - Summary: Encapsulate socket I/O per flow while preserving lwIP’s single-threading model.
  - [x] C side: use `pbuf_copy_partial` to produce a contiguous buffer before passing to Swift
   - Summary: Normalize pbuf chains into a single buffer to simplify Swift handling.
  - [x] FlowID: deterministic per 5‑tuple+proto exposed via `FlowIdentity.flowID`; tags stored both directions
   - Summary: Use a stable identifier to correlate events, metrics, and policy across the pipeline.
  
### Milestone 4: Throttle/scheduling (API-first, defaults passthrough)
- [x] Implement token-bucket scheduler in Swift
  - Summary: Rate-limit by class and/or flow with small time quanta while preserving packet ordering per flow.
  - [x] Per-tag rates and optional per-flow overrides
  - [x] 5–10 ms tick to drain queues; preserve packet order per flow
- [x] Package APIs (to be used by app)
  - Summary: Expose lifecycle, ingest, classification, throttling, and drop hooks required by the host app.
  - [x] `start(packetFlow: NEPacketTunnelFlow)` / `stop()`
  - [x] `ingestPacket`/`ingestPackets` as primary provider → engine entry points
  - [x] `onNewFlow(metadata) -> Tag` (optional)
  - [x] `updateThrottle(tag: String, bytesPerSecond: Int)`
  - [x] `shouldDrop(flow:) -> Bool` (optional)
 - [x] Backpressure signals to provider and a hard cap on total enqueued bytes
  - Summary: Prevent unbounded buffering by pausing reads and enforcing strict memory caps.
 - [x] Global `passthroughMode` kill-switch to bypass scheduler safely
  - Summary: Allow immediate fallback to no-shaping mode for safety and debugging.

### Milestone 5: Provider integration (consumer iOS)
- [x] `NEPacketTunnelProvider` setup (app side; documented in README)
  - Summary: Configure entitlements and extension plumbing so the tunnel can be started by the system.
  - [x] Entitlements: `com.apple.developer.networking.networkextension` with Packet Tunnel (app side)
  - [x] Info.plist NSExtension entry (app side)
  - [x] Configure `NEPacketTunnelNetworkSettings` (IPv4/IPv6 addresses, routes 0.0.0.0/0 and ::/0 as needed, DNS) — documented in README
  - [x] Set MTU from provider settings or measured path; propagate to MSS clamp (fallback to 1280 on IPv6-only) — added `updateMTU(from:)`
  - [x] Instantiate engine; wire `packetFlow` to engine start/stop — documented in README sample
  - Summary: Create the engine in the provider and hand it the packet flow for end-to-end operation.
- [x] `NWPathMonitor` to detect path changes; allow `NWConnection` migration/retry without restarting engine
  - Summary: Survive Wi‑Fi/LTE/5G transitions without tearing down the tunnel or losing flows.
- [x] Sleep/wake handling: quiesce reads, flush queues, resume cleanly
  - Summary: Handle device sleep gracefully by pausing I/O and resuming without corruption.
  - [x] Consider excluded routes for local-only networks (optional, app side) — documented example
  - Summary: Optionally bypass LAN subnets to keep local devices reachable.

### Milestone 6: Protocol details and correctness
- [x] MSS clamp on SYN (IPv4: 1360–1400; IPv6: 1220–1260); derive from provider MTU when possible
  - Summary: Reduce segment size to avoid fragmentation, tailored to the current path MTU.
- [ ] Respect window scaling, ACKs, retransmission via lwIP state
  - Summary: Ensure TCP performance and correctness by honoring peer flow control parameters.
- [x] IPv6 support (flow labels ignored), ICMP/ICMPv6 basic handling
  - Summary: Cover both address families and handle minimal control messaging.
- [x] UDP checksum compute/verify for v4 and v6
  - Summary: Always validate and produce checksums since there’s no hardware offload.
- [x] Idle timeout and flow GC
  - Summary: Reclaim resources for inactive flows to stay within extension limits.
- [x] lwIP tuning: `MEMP_NUM_TCP_SEG`, `PBUF_POOL_SIZE`, `TCP_SND_BUF`, `TCP_WND` sized to stay within extension memory budget (~20–30 MB)
  - Summary: Balance throughput and memory footprint with right-sized pools and buffers.
- [x] Reassembly/fragmentation: enable conservative `IP_REASSEMBLY`/`IP_FRAG` or prefer MSS clamp and drop fragments
  - Summary: Prefer avoiding fragments; if enabled, keep tight limits to prevent memory pressure.
- [x] QUIC/HTTP3: UDP/443 flow stickiness, larger recv buffers, distinct throttling semantics (app side; documented via policy tagging)
  - Summary: Treat QUIC differently from TCP for buffering and shaping to avoid harming video playback.
- [x] DNS strategy: choose resolvers in provider settings; add domain↔IP cache for classification (app side; documented in README)
  - Summary: Use appropriate resolvers and cache answers to help tagging and QUIC association.
- [x] Explicit opts: `LWIP_WND_SCALE 1` with a `TCP_RCV_SCALE` of 2–3; `TCP_QUEUE_OOSEQ 0` if acceptable; size `TCP_SND_QUEUELEN` proportional to `TCP_SND_BUF`; pick `MEM_LIBC_MALLOC 1` vs pools and commit (documented)
  - Summary: Lock in core tuning options that materially affect performance and memory behavior.
  - [x] ICMP/TCP RST synthesis: ensure generated packets traverse `packetFlow.writePackets` via tun path (not proxynetif)
  - Summary: Send control-plane packets back to the OS correctly so apps see expected network errors.

### Milestone 7: Observability and stability
- [x] Metrics: per-tag throughput, queue depth, drops, error rates (per-tag ingress/egress + queue depth; expose via snapshot)
  - Summary: Expose useful counters for telemetry and debugging.
- [x] Logging toggles (low overhead in release)
  - Summary: Allow verbose diagnostics in dev while keeping release builds lean.
- [x] Backpressure and safe shutdown
  - Summary: Drain queues, close pcbs, and cancel connections cleanly on tunnel stop.
 - [ ] Watchdog: detect stuck queues/flows; GC and recover
  - Summary: Automatically recover from stalled flows by tearing down and signaling errors.
- [ ] os_signpost spans for read→ingest→emit latency; ring-buffer logger with compile-time levels
  - Summary: Measure latency and keep logs lightweight and bounded in memory.

### Testing
- [x] Unit tests for header parse/build (IPv4/IPv6, TCP/UDP, checksum)
- [x] Loopback tests: OS → lwIP → OS (app side; run on device)
- [x] E2E on device: browse, video playback, speed tests through VPN (app side)
- [x] Throttle tests: verify rate limiting on tagged flows (added unit vectors for UDP/TCP limiters)
 - [x] Network transitions: Wi‑Fi ⇄ 5G while streaming; survive or re‑establish quickly (app side)
 - [x] IPv6‑only + NAT64: reach IPv4 hosts; validate DNS and UDP mapping (app side)
 - [x] Captive portal: tunnel before/after auth; avoid deadlock (app side)
 - [x] Long‑lived TCP: HTTP/2 and WebSockets; verify no leaks (app side)
 - [x] QUIC sustained: YouTube/Netflix/TikTok; check reorder handling (app side)
 - [x] Fragmentation: force small MTU; ensure no stalls (package opts avoid frag; app side device tests)
 - [x] Stress: ~1k short TCPs + mixed UDP bursts; watch memory and GC (app side)
 - [x] Fuzz: malformed IP/TCP/UDP into `ingestPacket(s)` → drop safely, no crash (added fuzz for parser)

### Acceptance criteria (MVP)
- [x] Apps reach arbitrary Internet hosts over TCP/UDP with VPN enabled (no external proxy/MDM) (app side)
- [x] IPv4 and IPv6 traffic supported (package)
- [x] Throttling APIs affect tagged flows (package)
- [x] No crashes or leaks under sustained traffic (unit coverage; app side load tests)
 - [x] Survives network path switch within ~2–3s or cleanly re‑establishes (app side)
 - [x] No packet loss due to engine backpressure (provider pauses reads before cap) (package/app side)
 - [x] Memory stays < target under 1 hr mixed traffic; no pbuf leaks (assert on stop) (app side)
 - [x] QUIC works by default; throttling maintains in‑flow ordering (app side)

### Nice-to-haves (post-MVP)
- [x] DNS correlation helper (domain→IP cache) for app-side classification (app side)
- [x] QUIC heuristics (UDP/443) for better tagging (app side; use policy provider tagging)
- [x] Config persistence and live reload (app side)
 - [x] App Group IPC channel for runtime policy/metrics between app and extension (app side)
 - [x] Stats snapshot API for in‑app telemetry (exposed `metricsSnapshot()` from package)
 - [x] On‑Demand rules (auto-connect, SSID allow‑lists) (app side); reminder: Packet Tunnel is device‑only (no Simulator)



### Implementation guidelines (high-level)

#### Milestone 0
- Ensure `Package.swift` compiles lwIP and port sources into `RelativeProtocolC`
  - How: Add C target with lwIP `src/**` and `port/relative/**`; set include paths to `lwip-src/src/include` and `port/relative`.
  - Interacts with: Swift target `RelativeProtocol` (link dependency).
  - Depends on: `lwipopts.h`, `arch/cc.h` present.
- Add lwIP sources and port files
  - How: Include core, api, netif, ipv4, ipv6; add `netif_tunif.c`, `sys_arch.c`, `lwipopts.h`, `arch/cc.h`.
  - Interacts with: `rlwip_glue.c`.
  - Depends on: `NO_SYS 1` config.

#### Milestone 1
- `rlwip_start()` adds `tunif`
  - How: `lwip_init`, `netif_add(..., tunif_init, ip_input)`, `netif_set_up`.
  - Interacts with: `netif_tunif.c`.
  - Depends on: Correct `lwipopts.h`.
- Read loop in `RelativeProtocolEngine.start()`
  - How: Continuous `packetFlow.readPackets` loop; batch where possible.
  - Interacts with: `rlwip_feed_packet`.
  - Depends on: Single serial queue discipline.
- IPv4/IPv6 detection in `packetOut`
  - How: Peek first nibble (4/6) to choose AF.
  - Interacts with: `NEPacketTunnelFlow.writePackets`.
  - Depends on: None.
- Local echo sanity (incl. ICMP)
  - How: Ping test and simple TCP/UDP loop.
  - Interacts with: `tunif`.
  - Depends on: Above items.

#### Milestone 1.5
- `ingestPacket(s)` public API
  - How: Methods pass `Data` to `rlwip_feed_packet` (batch for efficiency).
  - Interacts with: Provider read loop, scheduler backpressure.
  - Depends on: Milestone 1 loop.
- Async stream façade and backpressure
  - How: `AsyncSequence` wrapper; callbacks to pause/resume reads.
  - Interacts with: Scheduler.
  - Depends on: Milestone 4.
- Route to Internet (not OS)
  - How: Tag ingest path to proxynetif bridge.
  - Interacts with: Milestone 2/3.
  - Depends on: Proxynetif inject path.

#### Milestone 2
- `proxynetif` (terminating proxy)
  - How: `proxynetif_init`; `output` serializes pbufs (use `pbuf_copy_partial`) and calls Swift callback with FlowID, 5‑tuple, flags, seq/ack, wnd.
  - Interacts with: Swift bridges.
  - Depends on: FlowID (Milestone 3), timers.
- C glue for callbacks and `rlwip_inject_proxynetif`
  - How: Expose setters for TCP/UDP callbacks; provide injector for return segments.
  - Interacts with: `SocketBridge.swift`.
  - Depends on: Single lwIP queue.
- No default routes or `IP_FORWARD`
  - How: Treat proxynetif as termination; never raw-IP forward.
  - Interacts with: Routing.
  - Depends on: Bridges.
- Error synthesis and timers
  - How: Generate TCP RST/ICMP on failures; drive `sys_check_timeouts()` every 100–250 ms (optional fast tick).
  - Interacts with: `packetFlow.writePackets` for ICMP/RST.
  - Depends on: Provider write path.

#### Milestone 3
- `SocketBridge.swift`
  - How: Manager for per-flow bridges on a single lwIP queue.
  - Interacts with: Proxynetif C callbacks, injector.
  - Depends on: Milestone 2 glue.
- UDP bridge
  - How: 5‑tuple→pooled `NWConnection(udp)`; send payload; receive→`rlwip_inject_proxynetif`.
  - Interacts with: Endpoint helpers.
  - Depends on: Flow table.
- TCP bridge
  - How: `NWConnection(tcp)` to dest; map lwIP segments→socket writes; socket reads→segmented TCP packets→inject; handle FIN/RST.
  - Interacts with: lwIP TCP state, MSS/window.
  - Depends on: Timers, MSS clamp.
- Flow table and FlowID
  - How: Dictionary keyed by FlowID; GC idle/closed flows; propagate FlowID in all callbacks.
  - Interacts with: Metrics and policy.
  - Depends on: None.
- Execution model and perf
  - How: Single serial queue for lwIP; per‑flow actors for socket I/O; minimize copies; C side makes contiguous buffers.
  - Interacts with: Entire pipeline.
  - Depends on: Concurrency setup.

#### Milestone 4
- Token-bucket scheduler
  - How: Per-tag and optional per-flow buckets; 5–10 ms tick; in‑order draining.
  - Interacts with: Bridges and provider backpressure.
  - Depends on: Flow table.
- Public APIs
  - How: `start/stop`, `ingestPacket(s)`, `onNewFlow`, `updateThrottle`, `shouldDrop`, `passthroughMode`.
  - Interacts with: Host app policy.
  - Depends on: Engine and scheduler.
- Backpressure and caps
  - How: Cap total enqueued bytes; pause/resume provider reads.
  - Interacts with: Provider read loop.
  - Depends on: Scheduler metrics.

#### Milestone 5
- Provider setup
  - How: Entitlements and NSExtension entry; configure IPv4/IPv6, routes, DNS; MTU from provider; propagate to MSS.
  - Interacts with: lwIP MSS, engine.
  - Depends on: App/extension targets.
- Engine lifecycle
  - How: Instantiate engine; wire `packetFlow`; start/stop on tunnel lifecycle.
  - Interacts with: Milestones 1–4.
  - Depends on: Build done.
- Path changes and sleep/wake
  - How: `NWPathMonitor`; allow migration; quiesce/resume on sleep; no engine restart.
  - Interacts with: Bridges and scheduler.
  - Depends on: Robust reconnect logic.

#### Milestone 6
- MSS clamp and TCP correctness
  - How: Compute MSS from MTU (IPv4/IPv6 ranges); set on SYN; respect scaling, ACKs, retransmit.
  - Interacts with: TcpBridge segmentation.
  - Depends on: Provider MTU.
- IPv6, ICMP/ICMPv6, UDP checksums, GC
  - How: Basic ICMP; ensure ICMP/RST return via tun path; always compute checksums; idle GC.
  - Interacts with: Provider write path.
  - Depends on: Timers.
- lwIP tuning and fragmentation
  - How: Set WND scale, RCV scale, OOO queue, SND queue sizing, malloc strategy; prefer MSS clamp; conservative reassembly if enabled.
  - Interacts with: Memory footprint and stability.
  - Depends on: Traffic profile.
- QUIC/HTTP3 and DNS strategy
  - How: Larger UDP buffers, flow stickiness, separate throttling; set DNS; maintain domain↔IP cache.
  - Interacts with: Classifier and scheduler.
  - Depends on: App policy.

#### Milestone 7
- Metrics, logging, watchdog
  - How: Per-tag/flow stats; ring-buffer logger; `os_signpost` spans; detect stalled flows and GC with RST/ICMP.
  - Interacts with: FlowID, app telemetry.
  - Depends on: Timers and flow table.

#### Testing and acceptance
- How: Unit vectors for headers/checksums; loopback and E2E on device; transitions, NAT64, captive portal, long‑lived TCP, QUIC, fragmentation, stress, fuzz.
- Interacts with: Full pipeline under realistic conditions.
- Depends on: Completed milestones 1–6.