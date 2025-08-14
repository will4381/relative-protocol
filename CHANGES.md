## 2025-08-13

### Package.swift: add lwIP core/port sources and configure headers
- Added `RelativeProtocolC` target to compile lwIP minimal core (`core/*`, `ipv4/*`, `ipv6/*`) plus port files (`sys_arch.c`, `netif_tunif.c`).
- Configured header search paths to pick up `lwipopts.h` and `arch/cc.h` from `third_party/lwip/port/relative` and lwIP public headers from `lwip-src/src/include`.
- Linked `RelativeProtocol` Swift target against `RelativeProtocolC` and added required iOS frameworks (NetworkExtension, Network, CoreTelephony).

### RelativeProtocolEngine: start read loop, IPv6-aware packetOut, and queueing
- Introduced `readLoopArmed` and `armReadLoopIfNeeded()` to continuously drain `NEPacketTunnelFlow.readPackets` and feed lwIP.
- Wrapped `handleInboundTunnelPacket(_:)` in the engine’s serial queue to satisfy lwIP `NO_SYS` single-threaded assumptions.
- Updated `packetOut` to detect IP version from the first nibble and pass the correct protocol (`AF_INET` or `AF_INET6`) to `writePackets`.

### RelativeProtocolEngine: public packet ingestion APIs
- Added `ingestPacket(_:, proto:)` as a simple entry point for the provider to hand a single tunnel packet to the engine.
- Added `ingestPackets(_:, protocols:)` batched variant to reduce call overhead when the provider reads multiple packets at once.
- Both APIs route into the same serialized path (`handleInboundTunnelPacket`) to keep lwIP interactions single-threaded.

### Proxynetif and C glue for terminating proxy path
- Added `third_party/lwip/port/relative/netif_proxynetif.c` implementing a terminating proxy netif that serializes pbuf chains and forwards them to Swift via a trampoline.
- Extended `Sources/RelativeProtocolC/rlwip_glue.c` with:
  - `rlwip_set_proxy_output` to register the Swift proxy output callback
  - `rlwip_proxynetif_trampoline_output` to invoke the Swift callback
  - `rlwip_inject_proxynetif` to inject Internet-side data back into lwIP
- Updated `Package.swift` to compile `netif_proxynetif.c` into `RelativeProtocolC`.

### lwIP multi-netif bring-up and timers
- Split single `g_netif` into `g_tunif` (OS side) and `g_proxynetif` (terminating proxy side) and initialize both in `rlwip_start()`.
- Injected proxynetif input via `g_proxynetif.input` instead of default netif.
- Exposed `rlwip_drive_timeouts()` and added a periodic tick in `RelativeProtocolEngine` to call `sys_check_timeouts()` on the engine queue.
### Swift SocketBridge (UDP path scaffolding)
- Added `Sources/RelativeProtocol/SocketBridge.swift` with a singleton `SocketBridge` to process packets from `proxynetif`.
- Implemented minimal IPv4/IPv6 parsing to detect UDP flows, derive 5‑tuple, and send payloads via `NWConnection(udp)` to destination.
- Deferred TCP handling to a later milestone; currently a no-op for TCP packets.
- Wired `RelativeProtocolEngine` to register a `proxynetif` output callback that forwards packets into `SocketBridge.shared.handleOutgoingIPPacket`.
 - Added UDP receive path: read messages from `NWConnection` and synthesize IPv4/IPv6 UDP packets (with checksums) back into lwIP via `rlwip_inject_proxynetif`.
 - Added stable flow keys for UDP (v4/v6) based on 5‑tuple to pool and reuse `NWConnection` instances.

### Packet scheduler (initial)
- Added `PacketScheduler` with token-bucket rate control, 10 ms tick, batching, and basic backpressure signaling.
- Integrated scheduler lifecycle into `RelativeProtocolEngine` (start/stop). Currently direct-writes are used for `packetOut`; scheduler hook will be connected per-tag later.
### Swift SocketBridge (TCP scaffolding)
- Added per-flow TCP metadata and flow table with pooled `NWConnection(tcp)`.
- Parse TCP flags and payload from outgoing IP packets and forward payload to the socket; handle RST/FIN cleanup.
- Implemented initial TCP return path: synthesize IPv4/IPv6 TCP segments (ACK and data) with sequence/ack tracking and inject via `rlwip_inject_proxynetif`. Handshake SYN→SYN-ACK is synthesized locally.

### Engine policy/backpressure controls
- Added `PolicyProvider` protocol and `FlowMetadata` struct placeholders for future classification hooks.
- Added passthrough mode toggle and global throttle API in `RelativeProtocolEngine`.
- Backpressure from scheduler now suppresses re-arming the provider read loop to avoid over-buffering.

### lwIP tuning options
- Adjusted `lwipopts.h` for better consumer performance within extension limits:
  - `TCP_SND_QUEUELEN 128`, `TCP_SND_BUF 96KB`, `TCP_WND 96KB`
  - Enabled `LWIP_WND_SCALE` with `TCP_RCV_SCALE 2`
  - Disabled `TCP_QUEUE_OOSEQ` to reduce memory pressure; kept `LWIP_TCP_SACK_OUT 1`

### MSS clamp in SYN-ACK synthesis and adjustable clamps
- Added MSS option to SYN-ACK packets synthesized by `SocketBridge` to avoid fragmentation on common cellular paths.
- Introduced adjustable MSS clamp defaults (IPv4 1360, IPv6 1220) and a setter to tune at runtime based on provider MTU.

### TCP error synthesis and cleanup
- Added RST synthesis on `NWConnection` failure/cancel to promptly signal errors back into the device-side TCP via lwIP.

### UDP ICMP synthesis on errors
- Track last outbound UDP header per flow and synthesize IPv4 ICMP Destination Unreachable (code 0) back into lwIP on UDP socket failure/cancel.

### MTU→MSS clamp propagation API
- Added `RelativeProtocolEngine.updateMTU(ipv4MTU:ipv6MTU:)` to compute and propagate MSS clamps to `SocketBridge` based on provider MTU, with IPv6 fallback if unspecified.

### TODO progress
- Milestone 0/1/1.5: Completed core wiring (build, read loop, IPv6 detection, public ingest APIs).
- Milestone 2/3: Implemented proxynetif, UDP and initial TCP bridging, timers, error synthesis.
- Milestone 4: Added initial scheduler and backpressure plumbing; passthrough + throttle API stubs.

### Metrics scaffolding
- Added `Metrics` singleton with counters for tunnel in/out, network egress/ingress, flow counts, and synthesized control packets; hooked increments at key I/O points.

### Flow lifecycle and GC (initial)
- Flow metadata now tracks last-activity timestamps; UDP/TCP flow counts updated on create/remove.
- Prepared groundwork for idle GC; to be finalized with a periodic timer in a later step.

### Idle GC timer
- Started a periodic GC timer in `SocketBridge` to evict idle UDP (120s) and TCP (300s) flows and synthesize RSTs for stale TCP.

### ICMPv6 synthesis on UDP errors
- Added ICMPv6 Destination Unreachable (Type 1) synthesis with proper IPv6 pseudo-header checksum for UDP IPv6 flows when socket errors occur.

### Flow classification hook scaffolding
- Introduced `SocketBridge.Delegate` and `FlowIdentity` to classify new flows; `RelativeProtocolEngine` implements delegate and forwards to `PolicyProvider`.

### Per-tag UDP limiter scaffolding
- Added a simple per-tag UDP token-bucket limiter inside `SocketBridge` and a public setter; `RelativeProtocolEngine.updateThrottle` now wires through to update the limiter.
 - UDP sends for tagged flows now enqueue into the limiter backlog and are drained on a periodic tick.

### Per-tag TCP limiter scaffolding
- Added a parallel per-tag token-bucket limiter for TCP write pacing in `SocketBridge` with a setter; engine’s `updateThrottle` updates both UDP and TCP rates.

### TCP close handling (initial)
- On TCP receive completion or error, synthesize FIN|ACK back into lwIP and retire the flow to keep device-side stacks consistent.

### README
- Added a README with quick-start wiring for a Packet Tunnel, usage of `RelativeProtocolEngine`, policy hooks, and throttling controls.

### TagStore and OS-bound per-tag prep
- Introduced `TagStore` to remember flow tags in both directions based on 5‑tuple; used to optionally route OS-bound packets per-tag later.
- Bridge records tags for new UDP/TCP flows so device→OS packets can be associated with the same tag.

### Per-tag OS-bound scheduling and backpressure callback
- Engine now creates per-tag schedulers for OS-bound packets using tags from `TagStore`. A global scheduler remains as default.
- Added `onBackpressureChanged` callback and aggregated backpressure handling to pause provider reads when any scheduler is under pressure.

### Metrics snapshot API
- Added `RelativeProtocolEngine.metricsSnapshot()` to expose counters to host apps for telemetry and debugging.

### Lightweight logging
- Added `Logger` with adjustable log levels (error→trace) and convenience functions; defaults to .warn in release, .info in debug.

### Provider-side path and sleep/wake hooks
- Engine enables `NWPathMonitor` to observe path changes and exposes `quiesce()`/`resume()` to handle sleep/wake by pausing and resuming read loops.

## 2025-08-14

### Control-plane routing via OS tunnel
- Added `RelativeProtocolEngine.emitToTun(_:)` helper to send synthesized control-plane packets directly to the OS via `NEPacketTunnelFlow.writePackets`.
- Updated `SocketBridge` to route TCP RST/FIN synthesis and ICMPv4/ICMPv6 error packets to the OS path on iOS builds. macOS unit tests continue to use the proxynetif injection stub.

### Endpoint construction from IP literals
- Switched `SocketBridge` to create `NWEndpoint` using `.ipv4(IPv4Address)` / `.ipv6(IPv6Address)` when the destination is an IP literal to avoid unnecessary DNS lookups and improve NAT64/CLAT behavior. Falls back to `.name` if parsing fails.

### Per-flow tag propagation to TagStore
- When a new UDP/TCP flow is classified and tagged, the tag is now written into `TagStore` for both directions (5‑tuple + proto). This enables OS-bound scheduler lookups by tag.

### TCP segmentation bound by MSS and advertised window
- TCP receive path now segments return data by `min(MSS clamp, tcpAdvertisedWindowBytes)` to better respect peer flow control and avoid oversized segments. Added documentation in code and kept adjustable clamps via engine’s `updateMTU`.

### Async packet ingestion façade
- Added `PacketIngestor.AsyncStream` wrapper for `NEPacketTunnelFlow.readPackets` that yields `(data, proto)` tuples for push-style ingestion.

### lwIP tuning defaults (conservative)
- Updated `lwipopts.h` to increase memory and pool sizes to safer defaults for on-device throughput while staying within extension limits:
  - `MEM_SIZE 2MB`, `MEMP_NUM_TCP_SEG 4096`, `PBUF_POOL_SIZE 4096`, `PBUF_POOL_BUFSIZE 1600`.
  - Kept TCP window and scaling opts as previously set.

### Docs
- README now documents `scripts/fetch_lwip.sh` and the new async ingestion façade usage.
 - Added provider integration docs: Entitlements and Info.plist examples, DNS and excluded routes guidance, and convenience MTU→MSS propagation usage.

### FlowID propagation
- Introduced a deterministic `FlowID` (existing 5‑tuple encoding) and exposed it via `SocketBridge.FlowIdentity` to classification delegates.
- Stored per-flow tags in `TagStore` for both directions when a new flow is tagged, enabling consistent tag lookups for OS-bound scheduling.
 - Extended `RelativeProtocolEngine.FlowMetadata` to include `flowID` for host app visibility.

### Per-flow isolation and helpers
- Introduced per-flow serial queues for TCP and UDP connections; TCP sends and FIN now dispatch on the flow queue.
- Added `SocketHelpers.endpointForIPLiteral(...)` to create `.ipv4/.ipv6` endpoints from IP bytes.
- Added `UDPHelper` (pooled sender) and `TCPHelper` (lightweight connection wrapper) for app-level utilities.

### TCP device-side segment ordering
- Implemented basic handling for lwIP→socket mapping that respects device sequence ordering:
  - Drops fully duplicate segments, trims overlapping leading bytes, buffers future segments by seq, emits in-order data, and flushes buffered contiguous segments.

### Milestone 6 tuning
- lwIP opts: disabled `IP_REASSEMBLY` and `IP_FRAG` (prefer MSS clamp) to reduce memory pressure.
- Reduced `TCP_SND_BUF`/`TCP_WND` defaults to 64KB for better extension memory balance.
- Added simple sender-side TCP window (`tcpSenderWindowBytes`, default 64KB) enforced in TCP mapping to throttle device→network pacing.

### Provider MTU→MSS helper
- Added `RelativeProtocolEngine.updateMTU(from settings:)` to derive and propagate MSS clamps from `NEPacketTunnelNetworkSettings`.

### Source layout cleanup
- Moved helpers into `Sources/RelativeProtocol/Helpers/` (`SocketHelpers.swift`, `TCPHelper.swift`, `UDPHelper.swift`).
- Grouped observability under `Sources/RelativeProtocol/Observability/` (`Logger.swift`, `Metrics.swift`, `Observability.swift`).

### Milestone 7: Observability and stability
- Metrics: Added per-tag counters and queue depth snapshots for UDP/TCP limiters; surfaced via `Metrics.snapshot().perTag`.
- Added lightweight `os_signpost` hooks (guarded) for key stages: engine start, read loop, IPv4/IPv6 parse, UDP/TCP receive, and bridge outgoing handling.
- Prepared a simple watchdog foundation by exposing queue depths and flow counts; full auto-recovery can build on these metrics (future work).