# VPNBridgeTunnel (Clean-Room Rebuild)

This package is a clean-room tunnel architecture split into first-party Swift modules plus a minimal C dataplane bridge to vendored HEV.

## Module Topology

- `HevSocks5Tunnel` (vendored C dataplane, non-strict warning policy)
- `DataplaneFFI` (first-party C/Swift bridge and ABI guard)
- `TunnelRuntime` (framework-agnostic actor state machine + deterministic primitives)
- `PacketRelay` (`NWConnection`/`NWPathMonitor` relay orchestration)
- `Analytics` (metrics ring/store, packet stream, signatures, flow/burst, path sampler, perf baseline schema)
- `Observability` (structured envelope logging, signposts, JSONL sink with rotation)
- `TunnelControl` (Network Extension shell and profile settings)
- `HostClient` (app-facing diagnostics API)
- `HarnessLocal` (deterministic local scenario runner)

## Strictness Policy

`Package.swift` defines:

- `strictSwiftSettings` for all first-party Swift targets + first-party test targets
- `strictCSettings` for first-party C bridge target only (`DataplaneFFICBridge`)
- No `-Werror` escalation on vendored `HevSocks5Tunnel`

## Locked Contracts

- C ABI/API contract is defined in `Sources/DataplaneFFI/Bridge/include/rp_dataplane.h`
- JSONL sink root path injection + rotation policy is in `Sources/Observability/JSONLLogSink.swift`
- Immutable perf baseline schema is in `Sources/Analytics/PerfBaseline.swift`
- Baseline file is `Config/PerfBaseline.json`

## Local Gates

Run:

```bash
Scripts/quality-gate.sh
```

This enforces:

- `swift build`
- `swift test`
- first-party warning scan
- optional perf baseline evaluation (`PERF_MEASUREMENTS_PATH`, `PERF_FAIL_MODE`)
