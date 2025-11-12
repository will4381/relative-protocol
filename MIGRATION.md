# Rust Engine Migration Plan

This document captures the implementation roadmap for replacing the current bundled engine binary with a smoltcp-based Rust core while keeping every Swift boundary listed in `ENGINE_SURFACES.md` intact. The goal is a tun2socks-style engine that consumes raw IP packets from `RelativeProtocolTunnel.EngineAdapter` (`RelativeProtocol/Sources/RelativeProtocolTunnel/EngineAdapter.swift`) and drives all outbound sockets through the Swift-provided factories so Network Extension policies, metrics, and hooks keep working.

## Guiding Requirements

1. **Preserve Swift surfaces:** `Engine.start/stop`, the `EngineCallbacks` bundle, `BridgeNetworkProtocol` semantics, and the lifecycle described in `ENGINE_SURFACES.md` cannot change. Swift must remain the source of truth for tunnel configuration, metrics, traffic shaping, packet taps, host tracking, and the sole creator of outbound sockets via the provider’s `NEPacketTunnelProvider` factories.
2. **Full traffic coverage:** All iOS TCP and UDP traffic (DNS, QUIC, TLS, HTTP/3, custom UDP apps) must traverse the Rust core without loss while honoring MTU/memory budgets from `RelativeProtocol.Configuration.Provider` (`RelativeProtocol/Sources/RelativeProtocolCore/Configuration.swift`).
3. **Swift DNS hook stays:** `RelativeProtocol.Configuration.Hooks.dnsResolver` remains available. If the host supplies a closure, Swift uses it before dialing; otherwise the Rust resolver provides defaults. This keeps existing apps and examples working while letting the engine collect its own DNS/SNI metadata.
4. **Observability parity:** `ForwardHostTracker`, `TrafficShaper`, metrics, and hook callbacks continue to see the same (or richer) data. The engine must surface QUIC/TLS identifiers when Swift cannot parse them.

## Target Architecture

### FFI & Packaging

- Add a Rust workspace under `RelativeProtocol/RustSources/` producing a C-compatible static library that exports the existing bridge API (`BridgeNewEngine`, `BridgeSetLogSink`, `BridgeEngine.start/stop/handlePacket`, and the `BridgeNetworkProtocol` callbacks). Use `cbindgen` to emit headers consumed by Swift.
- `Scripts/build.sh` becomes the entry point for compiling the Rust crate for all Apple targets (iOS arm64, iOS simulator arm64/x86_64, macOS arm64/x86_64), lipo’ing, and packaging into `RelativeProtocol/Binary/Engine.xcframework`. `Package.swift` keeps pointing to that binary target so consumers do not change their integration story.

### Runtime Components

- **Packet queues:** Implement a `TunDevice` abstraction that mirrors `EngineAdapter`’s expectations. Swift feeds outbound packets via `startPacketReadLoop`; the device buffers them for smoltcp’s `iface::Interface`. Packets emitted by smoltcp are copied back into Swift through `callbacks.emitPackets`, preserving `[Data] + [NSNumber]` batches while using slab or ring buffers internally to avoid extra ARC traffic across the FFI boundary.
- **smoltcp interface:** Use a single `smoltcp::iface::Interface` with IPv4 + IPv6 support, fed by the virtual device. Poll it on a dedicated runtime thread (e.g. async executor or manual loop) that:
  - Drains Swift-provided IP frames into smoltcp.
  - Serves socket timers via `smoltcp::time::Instant`.
  - Flushes generated frames back to Swift.
  - Tunes smoltcp buffer/window limits to handle large QUIC/HTTP‑3 bursts despite the stack lacking SACK/timestamps; the remote leg still uses Apple’s TCP via NWConnection so missing features have minimal impact.
- **Flow manager:** Track each TCP and UDP socket with metadata that ties smoltcp sockets to Swift-managed handles (returned by `BridgeNetworkProtocol.tcpDial/udpDial`, which themselves call `NEPacketTunnelProvider.makeTCPConnection`/`makeUDPConnection`). Responsibilities mirror the current `ManagedTCPConnection` / `ManagedUDPConnection` classes in `BundledEngine.swift`:
  - Respect MTU/per-flow caps (`RelativeProtocol.Configuration.MemoryBudget`).
  - Apply backpressure with send windows (`maxConcurrentNetworkSends` equivalent).
  - Call `tcpDidReceive`, `tcpDidClose`, `udpDidReceive`, `udpDidClose` as remote data arrives or sockets terminate.
- **Dialer bridge:** Provide a Rust-side shim for `BridgeNetworkProtocol` so the engine can synchronously request new sockets but handle async readiness (mirroring `waitUntilReady` in Swift). Errors bubble back to the engine so it can RST/ICMP as needed.
- **Logging & metrics:** Forward engine log lines into `BridgeSetLogSink` so Swift’s `Logger` receives structured events. Track counters (packets, bytes, flow states) to continue feeding `MetricsCollector` through the existing Swift path.

### DNS & SNI Strategy

- **Default resolver in Rust:** Implement a lightweight DNS client (system or recursive) that the engine can invoke when it needs to resolve hostnames before dialing. When Swift does *not* supply `hooks.dnsResolver`, expose this resolver through the existing hook signature so the adapter still calls a closure—now backed by Rust via FFI rather than `swift-async-dns-resolver`.
- **Swift override honored:** If Swift provides `hooks.dnsResolver`, the adapter continues to call it first. Swift code can, as today, push the resulting host/IP pairs into `ForwardHostTracker.record(...)` (`RelativeProtocol/Sources/RelativeProtocolTunnel/ForwardHostTracker.swift:33-55`). The engine should detect when Swift returns a set of addresses so it can pin sockets to those IPs without making redundant DNS queries.
- **Packet-derived metadata:** The engine inspects DNS responses and QUIC/TLS ClientHello packets it processes. Forward these mappings over a new optional callback so Swift’s tracker receives SNI + IP information even when DNS lookups happen elsewhere (e.g. cached). This augments the current Swift-only TLS parser and improves attribution for CDNs.
- **Tunnel DNS advertisement:** Assign an internal RFC1918/CGNAT IP (never TEST-NET space) to the TUN interface and publish it via `NEDNSSettings`. iOS will send UDP/53 toward the engine, which can answer from the Rust resolver or forward upstream—no need to bind `127.0.0.1` inside the extension.
- **Platform-aware fallback order:** When Swift supplies a resolver hook (typically backed by the system resolver and enterprise DNS policies), prefer its answers before invoking the Rust resolver; document this order so integrators know how captive portals and encrypted DNS interact with the engine.

### Platform Networking Considerations

- **Provider-centric sockets:** The engine must always dial through `NEPacketTunnelProvider`’s factories (via `BridgeNetworkProtocol`) so traffic egresses outside the tunnel and path changes propagate automatically; never instantiate raw `NWConnection` objects inside Rust.
- **Routing for full coverage:** Recommend `includeAllNetworks = true` and `enforceRoutes = true` on `NETunnelProviderProtocol` when integrators expect device-wide interception, with explicit opt-outs for APNs/local networks to handle Apple’s documented edge cases. Document this guidance alongside a reminder to test each OS release.
- **Safe address space:** Default interface helpers should stick to RFC1918 or 100.64.0.0/10 addressing, avoiding TEST-NET blocks reserved for documentation.
- **Path change resilience:** Expect Wi‑Fi/cellular churn; ensure FlowManager cooperates with Swift so sockets re-dial through the current `NWPath` when the provider reports a change or when Apple’s connections surface `waiting`/`failed` transitions.

## Planned File Additions

### Swift

- `RelativeProtocol/Sources/RelativeProtocolTunnel/RustEngine.swift` – `Engine` protocol conformer that loads the Rust bridge symbols, wires `EngineCallbacks`, forwards lifecycle events, and replaces `BundledEngine` as the default implementation when the xcframework is present.
- `RelativeProtocol/Sources/RelativeProtocolTunnel/RustEngineMetadataBridge.swift` – Receives DNS/QUIC metadata structs pushed over FFI, normalizes them, and feeds `ForwardHostTracker`, `TrafficShaper`, and any hook consumers without touching the adapter code.
- `RelativeProtocol/Sources/RelativeProtocolTunnel/RustDNSResolverAdapter.swift` – Provides the default `RelativeProtocol.Configuration.DNSResolver` closure backed by the Rust resolver, keeping the hook optional while removing the dependency on `swift-async-dns-resolver`.
- `RelativeProtocol/Tests/RelativeProtocolTunnelTests/RustEngineTests.swift` – Adds integration tests that mock the FFI layer to ensure the Swift bridge reacts correctly to packet callbacks, log sinks, and resolver fallbacks.

### Rust Workspace (`RelativeProtocol/RustSources/engine-bridge/`)

- `Cargo.toml` – Defines the workspace crate (name, features, dependencies on `smoltcp`, `tokio`, etc.) and build profiles for iOS/macOS targets.
- `build.rs` – Emits cfg flags and triggers `cbindgen` so the generated header always matches the exposed ABI.
- `src/lib.rs` – Entry point exporting `BridgeNewEngine`, `BridgeSetLogSink`, and the `BridgeEngine` object that mirrors the legacy C/ObjC interface.
- `src/ffi.rs` – Houses all `#[repr(C)]` structs/enums plus the glue translating between Swift callbacks and Rust channels.
- `src/device.rs` – Implements the virtual tun device and packet queues that feed `smoltcp::iface::Interface`.
- `src/flow_manager.rs` – Owns TCP/UDP socket bookkeeping, dial requests, send windows, and maps between smoltcp handles and Swift-provided connection IDs.
- `src/dns/mod.rs` & `src/dns/system.rs` – Async resolver implementation (system-backed or recursive) plus caching and the bridge that surfaces resolved addresses to Swift when no custom hook is installed.
- `src/quic.rs` – Lightweight QUIC Initial / TLS ClientHello parser that extracts SNI + ALPN for analytics before passing payloads through untouched.
- `src/logger.rs` – Formats Rust log events and routes them through the `BridgeLogSinkProtocol` Swift installs via `BridgeSetLogSink`.
- `include/bridge.h` – Auto-generated header consumed by Swift, declaring the FFI surface (`BridgeEngine`, callback typedefs, configuration structs).

### Tooling & Packaging

- `Scripts/build.sh` – Rewritten to install/update Rust toolchains, compile the engine for each Apple triple, run `cbindgen`, and package everything into `RelativeProtocol/Binary/Engine.xcframework`.
- `RelativeProtocol/Binary/Engine.xcframework` – New artifact produced by the build script containing the Rust-generated static libraries plus the public header for Xcode/SPM consumers.

## Delivery Phases

1. **FFI Contract & Stubs**
   - Define the Rust structs/functions matching today’s Objective‑C bridge symbols.
   - Update `ENGINE_SURFACES.md` with any new optional callbacks (e.g. QUIC metadata) so Swift owners know what to expect.
   - Provide stub implementations (no-op packet reflection) that let Swift compile while Rust functionality is incomplete.

2. **Build & Packaging Tooling**
   - Extend `Scripts/build.sh` to install Rust toolchains, invoke cargo for each target, and assemble the xcframework.
   - Document environment requirements (rustup, cbindgen) inside the script and README.

3. **Core smoltcp Loop**
   - Implement the virtual device, interface configuration (IPv4/IPv6 addresses, MTU), and polling loop.
   - Add unit tests in Rust that inject IP frames and verify they emerge unchanged, ensuring `emitPackets` fidelity.

4. **TCP/UDP Flow Plumbing**
   - Build the FlowManager, dialer bridge, and remote callback handlers. Validate with integration tests that simulate SYN/FIN and UDP exchanges, ensuring correct invocation of `BridgeNetworkProtocol` methods and `tcpDidReceive`/`udpDidReceive`.

5. **DNS Resolver & Metadata**
   - Implement the Rust resolver and expose it through the Swift hook fallback.
   - Forward DNS/QUIC findings back to Swift so `ForwardHostTracker` benefits even when traffic is encrypted or cached.
   - Remove the `swift-async-dns-resolver` dependency once the new resolver path is in place, keeping the hook surface unchanged for Swift overrides.

6. **Observability & Performance**
   - Surface counters (drops, retransmits, dial failures) so Swift metrics remain accurate.
   - Run existing `RelativeProtocolPerformanceTests` plus new capture-replay tests that include TLS, QUIC, DNS, and mixed TCP/UDP flows.

## Open Questions

- **System DNS vs recursive:** Should the Rust resolver rely on platform APIs (safer, respects device policies) or ship its own recursive stub (full control, works without system DNS)? Decision affects entitlements and battery impact.
- **QUIC metadata path:** decide whether QUIC SNI extraction lives in Rust or should be reimplemented in Swift for consistency with the TLS parser.
- **Cache coordination:** When both Swift and Rust perform resolutions, how do we deduplicate host/IP mappings to avoid stale entries in `ForwardHostTracker`?

Address these before implementation to avoid churn across the Swift ↔ Rust boundary.
