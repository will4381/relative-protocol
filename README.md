<!--
Created by Will Kusch, Relative Companies, Inc.
Copyright (c) 2026 Relative Companies, Inc.
Licensed for personal, non-commercial use only. See LICENSE for terms.
-->

# relative-protocol

`relative-protocol` is a Swift package for packet-tunnel VPN products that need:

1. a real `NEPacketTunnelProvider` dataplane
2. a bounded foreground telemetry tap
3. durable, pluggable traffic detectors that run inside the tunnel extension

The package is detector-first, not packet-log-first. The tunnel extension owns runtime detection and persists compact detector outputs. The containing app reads foreground snapshots and durable summaries when it is active.

## Current Status

- Packet tunnel runtime, relay, telemetry, and detector execution are package-owned.
- The detector stream includes sparse lifecycle/window records plus exact `packetCue` records controlled by generic `PacketCueEmissionPolicy` knobs.
- `packetCue` records expose packet length, payload length, TCP flags, ACK/PSH booleans, endpoint fields, flow id, host/domain association, cue reason, and canonical flow identity.
- Optional rich packet JSONL logging is available through `RichPacketLogPolicy`; it is disabled by default, bounded, and intended for debug/research builds.
- Detector records expose remote endpoint, owner key, app-supplied role labels, app-injected address scope, session context, source-app attribution fields, health/liveness, and typed fire audit records.
- The package does not ship named platform-specific role/scope logic. Product-specific classification belongs in the containing app or app-supplied catalogs.
- Source-app bundle attribution requires a separate host-app Content Filter extension target. The package has the `sourceAppFlow` record contract, but it does not create or install the `NEFilterDataProvider` target for you.

## Quick Start

1. Add this package through Swift Package Manager.
2. Link package products into your app and packet tunnel extension targets.
3. Subclass `PacketTunnelProviderShell` in your packet tunnel extension.
4. Build and persist a `TunnelProfile` from the containing app.
5. Override `makeDetectors(...)` if you need custom detectors.
6. Use `TunnelTelemetryClient` for foreground snapshots and `TunnelDetectionStore` / `TunnelStopStore` for durable recovery.

Minimal provider:

```swift
import TunnelControl

final class PacketTunnelProvider: PacketTunnelProviderShell {}
```

Minimal detector registration:

```swift
import Analytics
import Observability
import TunnelControl

final class PacketTunnelProvider: PacketTunnelProviderShell {
    override func makeDetectors(
        profile: TunnelProfile,
        analyticsRootURL: URL,
        logger: StructuredLogger
    ) async throws -> [any TrafficDetector] {
        [MyDetector()]
    }
}
```

## Documentation

Start here:

- [Docs Index](Docs/README.md)
- [Getting Started](Docs/GettingStarted.md)
- [Architecture](Docs/Architecture.md)
- [Detector Stream and Custom Detectors](Docs/DetectorStream.md)
- [Reference](Docs/Reference.md)
- [Operations and Debugging](Docs/Operations.md)
- [Local Tunnel Harness](Docs/LocalTunnelHarness.md)
- [Changelog and Migration Notes](Docs/Changelog.md)
- [License and Usage Notes](Docs/LicenseAndUsage.md)

## Public Integration Surface

Most host apps interact with these types:

- `TunnelProfile`
- `TunnelProfileManager`
- `PacketTunnelProviderShell`
- `TunnelTelemetryClient`
- `TunnelDetectionStore`
- `TunnelStopStore`
- `TrafficDetector`
- `DetectorRequirements`
- `DetectorFeatureFamily`
- `PacketCueEmissionPolicy`
- `RichPacketLogPolicy`
- `TelemetryDegradationPolicy`
- `DetectorArmingStateMachine`
- `DetectionEvent`
- `DetectionSnapshot`

## Package Layout

- `Sources/Analytics`
  - packet summarization, sparse detector stream, rolling tap, detector protocol, detector store, app-message payloads
- `Sources/TunnelControl`
  - `NEPacketTunnelProvider` shell, profile decoding, tunnel/app messaging, startup/shutdown wiring
- `Sources/PacketRelay`
  - SOCKS5 TCP/UDP relay, tunnel bridge, packet forwarding
- `Sources/TunnelRuntime`
  - dataplane runtime orchestration and deterministic test helpers
- `Sources/DataplaneFFI`
  - Swift/C bridge into the bundled dataplane runtime
- `Sources/HostClient`
  - host-app snapshot client and persisted store readers, including optional rich packet log reads
- `Sources/Observability`
  - structured logging, JSONL/OSLog sinks, signposts
- `Sources/HarnessLocal`
  - local harness for replay and package-level testing

## What This Package Does

- runs a packet tunnel using `NEPacketTunnelProvider`
- bridges packets into a local SOCKS relay and dataplane
- emits a bounded in-memory rolling telemetry window
- runs one or more detectors inside the tunnel extension
- persists compact detector outputs and stop breadcrumbs to the App Group container
- optionally writes bounded rich packet metadata JSONL for debug builds
- exposes foreground snapshots through `NETunnelProviderSession.sendProviderMessage`

## What This Package Does Not Do

- continuously persist packet history to disk by default
- assume the containing app can stay awake forever in the background
- force one product-specific detector vocabulary on all package users
- classify traffic as a named third-party app/platform from domains or IP prefixes
- infer foreground app-open timing on its own
- infer another app's bundle identifier from `NEPacketTunnelProvider` packet data alone
- install a Content Filter extension target for source-app attribution

## Verification

Recommended checks before shipping package changes:

```bash
swift test
xcodebuild -project Example/Example.xcodeproj -scheme Example -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build
Scripts/quality-gate.sh
```

Known non-blocking local build note:

Some local `swift test` runs and iOS Simulator builds of the Example target may emit this linker warning even when the command succeeds:

```text
ld: warning: reducing alignment of section __DATA,__common from 0x8000 to 0x4000 because it exceeds segment maximum alignment
```

Treat this specific linker warning as non-blocking for now when it is the only build warning and the command exits successfully. It is tracked as cleanup work, not a release blocker. Swift compiler warnings, test failures, or any new linker warnings should still be investigated before shipping.

Use the Example app's stress matrix and load drill before releasing changes that touch tunnel startup, DNS, MTU, relay behavior, telemetry, UDP, QUIC, or path transitions.
