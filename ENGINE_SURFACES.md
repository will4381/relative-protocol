# Engine Surface Map

Relative Protocol is an on-device VPN/proxy stack meant for workloads like ad blocking, observability, or screen-time enforcement. The Swift side (Packet Tunnel Extension + host helpers) owns every interaction with Apple’s `NEPacketTunnelProvider`: it loads configuration, installs hooks/filters, gathers metrics, enforces shaping/block policies, and—crucially—opens all outbound TCP/UDP sockets through `NWConnection`. The Rust engine focuses purely on packet processing: it consumes the IP frames Swift hands it, applies its own core logic, and uses the Swift-provided callbacks whenever it needs to read from the virtual interface or push payloads back out over sockets. Keeping those roles separate ensures integrators can extend behavior via Swift hooks/streams without touching the Rust data plane.

This document enumerates every boundary we currently have between Swift and the vendored engine implementation. Use it as a checklist while replacing the legacy bridge with the Rust stack.

## Swift → Engine entrypoints

- `Engine.start(callbacks:)` (`RelativeProtocol/Sources/RelativeProtocolTunnel/EngineAdapter.swift:152`): invoked once the adapter has prepared memory budgets, shaping queues, and event hooks. The engine must synchronously throw if bootstrap fails so `RelativeProtocolTunnel.ProviderController` can surface a `RelativeProtocol.PackageError.engineStartFailed`.
- `Engine.stop()` (`EngineAdapter.swift:185`): Swift calls this during tunnel teardown before tearing down queues.
- `BridgeConfig` (`BundledEngine.swift:41`): Swift provides MTU and any other runtime knobs the engine exposes through this config struct before calling `start`.

## Callbacks the Engine must invoke

These come from `EngineCallbacks` (`EngineAdapter.swift:23`) and are passed into `start`.

- `startPacketReadLoop(_ handler)` (`EngineAdapter.swift:161`): Engine receives a closure that it must call exactly once to install its packet handler. The handler is invoked on Swift’s queue whenever the adapter delivers outbound packets.
- `emitPackets(_ packets:_ protocols:)` (`EngineAdapter.swift:165`): Engine uses this to send processed packets back to the provider. Swift performs metrics, taps, shaping, and eventually writes to `NEPacketTunnelFlow`.
- `makeTCPConnection(_ endpoint)` / `makeUDPConnection(_ endpoint)` (`EngineAdapter.swift:168`): Engine requests outbound sockets exclusively via these factories so Swift can enforce block lists and log policy violations.

## Network lifecycle API (Rust → Swift)

Swift implements `BridgeNetworkProtocol` in `NetworkAdapter` (`BundledEngine.swift:205`). The Rust core must call the following methods to manage sockets:

- `tcpDial(host, port, timeoutMillis) -> handle` (`BundledEngine.swift:244`): Requests a new TCP flow. Swift creates an `NWConnection`, waits for readiness, stores it under a numeric handle, and returns that handle to the engine.
- `tcpWrite(handle, payload) -> bytesWritten` (`BundledEngine.swift:284`): Writes application data. Swift enforces MTU/per-flow caps and send windows before sending.
- `tcpClose(handle)` (`BundledEngine.swift:300`): Releases the Swift-managed connection.
- `udpDial(host, port) -> handle` (`BundledEngine.swift:305`)
- `udpWrite(handle, payload) -> bytesWritten` (`BundledEngine.swift:266` of `ManagedUDPConnection`)
- `udpClose(handle)` (`BundledEngine.swift:287`)

Swift notifies the engine about socket events via the callbacks the legacy bridge already expects:

- `tcpDidReceive(handle, payload)` / `udpDidReceive(handle, payload)` (`BundledEngine.swift:540`, `BundledEngine.swift:689`)
- `tcpDidClose(handle, message)` / `udpDidClose(handle, message)` (`BundledEngine.swift:565`, `BundledEngine.swift:712`)

The Rust implementation must keep these function signatures (or provide compatible shims) so the existing Swift call sites remain valid.

## Logging & diagnostics

- `BridgeSetLogSink` (`BundledEngine.swift:55`): Engine should accept a log sink that Swift installs so `os_log` receives structured messages (`LogSinkAdapter`).
- Event notifications: Swift surfaces `.willStart`, `.didStart`, `.didStop`, `.didFail` through `hooks.eventSink` (`EngineAdapter.swift:153`). Ensure the Rust stack triggers the corresponding callbacks via `EngineCallbacks.emitPackets`/`startPacketReadLoop` error propagation so Swift can continue invoking these hooks at the right times.

## Data pumped through the adapter

- Packet batches handed to the engine are already memory-budgeted and annotated with protocol numbers (`EngineAdapter.swift:248`). The Rust side only needs to consume `[Data]` + `[NSNumber]` pairs.
- Return packets must be raw IP frames paired with protocol numbers so Swift can run taps, analyzers, shaping, and write to the tunnel (`EngineAdapter.swift:385`).
- Configuration context (addresses, routes, DNS, policies, hooks) lives in `RelativeProtocol.Configuration` and drives how Swift schedules reads/writes. The Rust engine only needs MTU and whatever extra knobs you expose via `BridgeConfig`.

Keep this list close when designing the Rust FFI so nothing falls through the cracks while we swap out the underlying implementation.
