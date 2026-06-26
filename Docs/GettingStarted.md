<!--
Created by Will Kusch, Relative Companies, Inc.
Copyright (c) 2026 Relative Companies, Inc.
Licensed for personal, non-commercial use only. See LICENSE for terms.
-->

# Getting Started

This guide covers the normal host-app integration path for `relative-protocol`.

## Package Products

The package exposes these products:

- `Analytics`
- `DataplaneFFI`
- `HostClient`
- `Observability`
- `PacketRelay`
- `TunnelControl`
- `TunnelRuntime`

## Typical Target Wiring

Most apps should link products like this:

- containing app target
  - `HostClient`
  - `TunnelControl`
- packet tunnel extension target
  - `Analytics`
  - `TunnelControl`
  - `PacketRelay`
  - `TunnelRuntime`
  - `Observability`
  - `DataplaneFFI`

The app mainly:

- installs and updates the VPN profile
- starts and stops the tunnel
- reads foreground snapshots
- reads persisted detections and stop records

The extension mainly:

- runs the tunnel
- runs detectors
- persists durable detector outputs
- exposes the live tap through provider messages

## Define a Tunnel Provider

Subclass `PacketTunnelProviderShell` inside your Network Extension target.

```swift
import TunnelControl

final class PacketTunnelProvider: PacketTunnelProviderShell {}
```

That is enough for the default runtime. If you want custom detectors, override `makeDetectors(...)`.

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

## Build and Persist a TunnelProfile

The containing app supplies provider configuration through `NETunnelProviderProtocol.providerConfiguration`.

Important fields in `TunnelProfile`:

- `appGroupID`
- `tunnelRemoteAddress`
- `mtu`
- `mtuStrategy`
- `ipv6Enabled`
- `tcpMultipathHandoverEnabled`
- `dnsServers`
- `dnsStrategy`
- `engineSocksPort`
- `engineLogLevel`
- `telemetryEnabled`
- `liveTapEnabled`
- `liveTapIncludeFlowSlices`
- `liveTapIncludePacketCues`
- `liveTapIncludeValidationRecords`
- `liveTapMaxBytes`
- `packetCuePolicy`
- `addressScopePrefixes`
- `richPacketLogPolicy`
- `signatureFileName`
- `relayEndpoint`
- `dataplaneConfigJSON`

`telemetryEnabled = true` enables:

- sparse packet analytics
- in-extension detectors
- durable detection persistence

`liveTapEnabled = true` enables:

- the rolling live tap
- foreground packet/event snapshots

`liveTapIncludeFlowSlices = true` opts the app-facing live tap into detector-grade `flowSlice` records. Keep this off for normal product reads and enable it only when you intentionally want a richer debug surface.

`liveTapIncludePacketCues = true` opts the app-facing live tap into configured packet-level cue records. It only emits cues that match `packetCuePolicy`.

`liveTapIncludeValidationRecords = true` adds validation-grade debug records to foreground snapshots. Use it for scoring and QA, not as an always-on raw packet export.

`richPacketLogPolicy` enables a separate bounded JSONL packet metadata stream under the App Group for debugging or external analysis. Keep it `.disabled` for normal production builds.

`liveTapEnabled` only has effect when `telemetryEnabled` is also `true`.

Example:

```swift
let profile = TunnelProfile(
    appGroupID: "group.com.example.vpn",
    tunnelRemoteAddress: "127.0.0.1",
    mtu: 1_280,
    mtuStrategy: .fixed(1_280),
    ipv6Enabled: true,
    tcpMultipathHandoverEnabled: true,
    ipv4Address: "10.0.0.2",
    ipv4SubnetMask: "255.255.255.0",
    ipv4Router: "10.0.0.1",
    ipv6Address: "fd00:1::2",
    ipv6PrefixLength: 64,
    dnsServers: [],
    dnsStrategy: .noOverride,
    engineSocksPort: 0,
    engineLogLevel: "info",
    telemetryEnabled: true,
    liveTapEnabled: true,
    liveTapIncludeFlowSlices: false,
    liveTapIncludePacketCues: false,
    liveTapIncludeValidationRecords: false,
    liveTapMaxBytes: 1_048_576,
    packetCuePolicy: .disabled,
    telemetryDegradationPolicy: .default,
    richPacketLogPolicy: .disabled,
    signatureFileName: "app_signatures.json",
    relayEndpoint: RelayEndpoint(host: "127.0.0.1", port: 1080, useUDP: false),
    dataplaneConfigJSON: "{}"
)
```

Recommended host-app policies:

- generic compatibility default: `mtuStrategy = .fixed(1280)`
- protocol-aware UDP tunnel: `mtuStrategy = .automaticTunnelOverhead(80)` when you know your encapsulation overhead
- package full-tunnel DNS default: `dnsStrategy = .recommendedDefault`
- system resolver compatibility opt-out: `dnsStrategy = .noOverride`
- mobility-sensitive app traffic: `tcpMultipathHandoverEnabled = true`
- collision-resistant local relay: `engineSocksPort = 0`

## Configure NETunnelProviderManager

The package does not install the VPN profile for you automatically. Your app still owns:

- creating a `NETunnelProviderManager`
- assigning a `NETunnelProviderProtocol`
- writing `TunnelProfile` into `providerConfiguration`
- saving/loading preferences
- starting and stopping the connection

`TunnelProfileManager.configure(...)` exists to keep profile encoding consistent.

## Start the Tunnel

Use `NETunnelProviderManager` / `NEVPNManager` from the containing app. `PacketTunnelProviderShell` handles:

- network settings install
- SOCKS relay startup
- dataplane startup
- packet read/write loops
- app-message handling

## Foreground App Reads

Use `TunnelTelemetryClient` while the app is active.

```swift
import HostClient
import NetworkExtension

let client = TunnelTelemetryClient()
let snapshot = try await client.snapshot(from: manager.connection, packetLimit: 96)
```

Available operations:

- `snapshot(from:packetLimit:)`
- `clearRecentEvents(from:)`
- `clearDetections(from:)`
- `flushTelemetry(from:)`

This uses Apple's tunnel-provider messaging path rather than a shared file tail.

## Background Recovery

When the app resumes after a long background period, read persisted detector outputs instead of depending on the live tap.

```swift
import HostClient

let store = TunnelDetectionStore(appGroupID: "group.com.example.vpn")
let detections = try store.load() ?? .empty
let lastStop = try TunnelStopStore(appGroupID: "group.com.example.vpn").load()
```

Use the live tap for recent context. Use the persisted store for durable correctness.
