<!--
Created by Will Kusch, Relative Companies, Inc.
Copyright (c) 2026 Relative Companies, Inc.
Licensed for personal, non-commercial use only. See LICENSE for terms.
-->

# Reference

This is the quick lookup page for package products, public types, detector fields, profile knobs, artifacts, and verification commands.

For narrative setup, use [Getting Started](GettingStarted.md). For detector design details, use [Detector Stream and Custom Detectors](DetectorStream.md).

## Package Products

| Product | Primary Use |
| --- | --- |
| `Analytics` | Packet summarization, sparse detector stream, rolling tap, detectors, detection persistence |
| `DataplaneFFI` | Swift/C bridge into the bundled dataplane runtime |
| `HostClient` | Containing-app reads for telemetry snapshots, detections, and stop records |
| `Observability` | Structured logging, JSONL/OSLog sinks, signposts |
| `PacketRelay` | SOCKS5 TCP/UDP relay and packet forwarding |
| `TunnelControl` | `NEPacketTunnelProvider` shell, profile decoding, tunnel/app messaging |
| `TunnelRuntime` | Dataplane runtime orchestration and deterministic helpers |

## Target Wiring

| Target | Products |
| --- | --- |
| Containing app | `HostClient`, `TunnelControl` |
| Packet tunnel extension | `Analytics`, `TunnelControl`, `PacketRelay`, `TunnelRuntime`, `Observability`, `DataplaneFFI` |
| Optional Content Filter extension | host-app owned; package provides source-app attribution record types but not the extension target |

## Core Public Types

| Type | Module | Purpose |
| --- | --- | --- |
| `TunnelProfile` | `TunnelControl` | Runtime profile decoded by the provider |
| `TunnelProfileManager` | `TunnelControl` | Host-app profile encoding/configuration helper |
| `PacketTunnelProviderShell` | `TunnelControl` | Base provider implementation for packet tunnel extensions |
| `TunnelTelemetryClient` | `HostClient` | Foreground app reads through provider messages |
| `TunnelDetectionStore` | `HostClient` | Reads persisted detection snapshots |
| `TunnelStopStore` | `HostClient` | Reads last-stop breadcrumbs |
| `TrafficDetector` | `Analytics` | Detector protocol |
| `DetectorRequirements` | `Analytics` | Declares needed record kinds/features |
| `DetectorFeatureFamily` | `Analytics` | Feature family option set |
| `DetectorRecordCollection` | `Analytics` | Projected detector batch |
| `DetectorRecord` | `Analytics` | Detector-facing sparse record |
| `DetectionEvent` | `Analytics` | Durable detector output |
| `DetectorFireRecord` | `Analytics` | Optional typed fire audit payload |
| `DetectionSnapshot` | `Analytics` | Durable aggregate detection state |
| `PacketSample` | `Analytics` | Foreground live-tap sample |
| `DetectorSessionContext` | `Analytics` | Host-supplied app/session timing |
| `AddressScopeClassifier` | `Analytics` | Optional prefix classifier for coarse network family |
| `SourceAppFlowAttribution` | `Analytics` | Source-app attribution payload for Content Filter integration |

## Detector Record Kinds

| Kind | Meaning | Default Foreground Live Tap |
| --- | --- | --- |
| `flowOpen` | First lifecycle marker for a tracked flow | Yes |
| `flowSlice` | Fixed-cadence per-flow aggregate | No |
| `flowClose` | Lifecycle end marker | Yes |
| `metadata` | Host/DNS/TLS/QUIC enrichment boundary | Yes |
| `burst` | Completed burst boundary with shape counters | Yes |
| `activitySample` | Coarse low-frequency activity rollup | Contextual only |
| `packetCue` | Exact packet-level detector cue | No |
| `sourceAppFlow` | Optional Content Filter source-app attribution record | Yes, when emitted |

## Detector Feature Families

| Feature Family | Enables |
| --- | --- |
| `packetShape` | Packet-size and protocol-mix counters |
| `controlSignals` | TCP/QUIC control counters |
| `burstShape` | Burst onset and burst-shape counters |
| `hostHints` | DNS/TLS/domain/classification hints |
| `quicIdentity` | QUIC version, packet type, connection IDs |
| `stringAddresses` | Source/destination address strings |
| `dnsAnswerAddresses` | DNS answer address arrays |
| `dnsAssociation` | Best-effort DNS-to-flow association |
| `lineage` | Flow lineage/reuse fields |
| `pathRegime` | `NWPathMonitor`-derived path regime |
| `serviceAttribution` | Fused service-family attribution |
| `packetDetails` | Packet length, payload length, TCP flags, ACK/PSH |
| `sessionContext` | Host-supplied session/app timing fields |
| `remoteEndpoint` | Remote endpoint and owner fields |
| `roleAttribution` | Normalized role string |
| `addressScope` | Coarse family/scope attribution |
| `eventAudit` | Typed detector fire audit support |
| `sourceAppAttribution` | Source-app attribution fields |

## Packet Cue Must-Have Fields

`packetCue` records automatically project these fields:

| Field | Purpose |
| --- | --- |
| `timestampMs` | Millisecond timestamp for sequence logic |
| `direction` | Inbound/outbound direction |
| `protocolHint` / `transportProtocol` | TCP/UDP identity |
| `packetLength` | Full IP packet length |
| `transportPayloadLength` | TCP or UDP payload length |
| `tcpFlags` | Raw TCP flag byte |
| `tcpAck` | Parsed TCP ACK flag |
| `tcpPsh` | Parsed TCP PSH flag |
| `sourceAddress`, `sourcePort` | Local/source endpoint fields |
| `destinationAddress`, `destinationPort` | Destination endpoint fields |
| `flowId` | Stable 5-tuple-ish flow id |
| `remoteAddress`, `remotePort`, `remoteEndpoint` | Non-phone side of flow |
| `ownerKey` | Stable owner bucket |
| `role` | Normalized host/service role |
| `tlsServerName`, `registrableDomain`, `associatedDomain`, `dnsQueryName`, `dnsCname` | Host/domain gates |

## DetectorRecord Field Groups

| Group | Fields |
| --- | --- |
| Flow/lifecycle | `kind`, `timestamp`, `timestampMs`, `direction`, `flowHash`, `flowId`, `flowPacketCount`, `flowByteCount`, `closeReason` |
| Volume/shape | `bytes`, `packetCount`, `largePacketCount`, `smallPacketCount` |
| Protocol/control | `protocolHint`, `transportProtocol`, `transportProtocolNumber`, `ipVersion`, `udpPacketCount`, `tcpPacketCount`, `quicInitialCount`, `tcpSynCount`, `tcpFinCount`, `tcpRstCount` |
| Endpoints/host | `sourceAddress`, `sourcePort`, `destinationAddress`, `destinationPort`, `remoteAddress`, `remotePort`, `remoteEndpoint`, `ownerKey`, `role`, `registrableDomain`, `dnsQueryName`, `dnsCname`, `dnsAnswerAddresses`, `tlsServerName`, `classification` |
| Packet details | `packetLength`, `transportPayloadLength`, `tcpFlags`, `tcpAck`, `tcpPsh` |
| DNS association | `associatedDomain`, `associationSource`, `associationAgeMs`, `associationConfidence` |
| QUIC | `quicVersion`, `quicPacketType`, `quicDestinationConnectionId`, `quicSourceConnectionId` |
| Lineage | `lineageID`, `lineageGeneration`, `lineageAgeMs`, `lineageReuseGapMs`, `lineageReopenCount`, `lineageSiblingCount` |
| Path regime | `pathEpoch`, `pathInterfaceClass`, `pathIsExpensive`, `pathIsConstrained`, `pathSupportsDNS`, `pathChangedRecently` |
| Service attribution | `serviceFamily`, `serviceFamilyConfidence`, `serviceAttributionSourceMask` |
| Address scope | `addressScopeFamily`, `addressScopeSource`, `addressScopeConfidence` |
| Session context | `sessionId`, `packetStreamStartedAtMs`, `foregroundReadyAtMs`, `appOpenAtMs`, `targetApp` |
| Source-app attribution | `sourceAppIdentifier`, `sourceAppUniqueIdentifierHash`, `sourceAppVersion`, `attributionFlowId`, `attributionSource`, `attributionObservedAtMs`, `localEndpoint`, `remoteHostname` |
| Burst shape | `burstDurationMs`, `burstPacketCount`, `leadingBytes200ms`, `leadingPackets200ms`, `leadingBytes600ms`, `leadingPackets600ms`, `burstLargePacketCount`, `burstUdpPacketCount`, `burstTcpPacketCount`, `burstQuicInitialCount` |

## DetectionEvent Fields

| Field | Meaning |
| --- | --- |
| `id` | Unique event id |
| `detectorIdentifier` | Detector namespace |
| `signal` | Stable detector-defined signal |
| `target` | Optional detector-defined subject bucket |
| `timestamp` | Fire time |
| `confidence` | Detector confidence |
| `trigger` | Detector-defined evidence label |
| `flowId` | Optional related flow id |
| `host` | Optional related host |
| `classification` | Optional classifier label |
| `bytes` | Optional related byte count |
| `packetCount` | Optional related packet count |
| `durationMs` | Optional related duration |
| `metadata` | Optional detector-specific compact metadata |
| `fireRecord` | Optional typed fire audit payload |

## TunnelProfile Knobs

| Field | Purpose |
| --- | --- |
| `appGroupID` | Shared App Group id |
| `tunnelRemoteAddress` | Tunnel remote address presented to NetworkExtension |
| `mtu` | Local buffer/MTU hint |
| `mtuStrategy` | Fixed MTU or automatic tunnel overhead |
| `ipv6Enabled` | Enables IPv6 route/settings support |
| `tcpMultipathHandoverEnabled` | Enables TCP multipath handover policy |
| `dnsServers` | Legacy cleartext resolver list |
| `dnsStrategy` | Explicit DNS policy |
| `engineSocksPort` | Local SOCKS listener port, `0` for ephemeral |
| `engineLogLevel` | Dataplane/engine log level |
| `telemetryEnabled` | Sparse analytics, detectors, persistence |
| `liveTapEnabled` | Foreground live tap |
| `liveTapIncludeFlowSlices` | Includes `flowSlice` in app-facing snapshots |
| `liveTapMaxBytes` | Bounds live tap memory |
| `signatureFileName` | Signature file under App Group analytics root |
| `relayEndpoint` | Relay metadata and UDP/TCP egress mode |
| `dataplaneConfigJSON` | Raw dataplane configuration JSON |

## App Group Artifacts

| Path | Purpose |
| --- | --- |
| `<AppGroup>/Analytics/Detections/detections.json` | Durable detection snapshot |
| `<AppGroup>/Analytics/last-stop.json` | Last provider stop breadcrumb |
| `<AppGroup>/Analytics/AppSignatures/<signatureFileName>` | Optional signature classifier file |
| `<AppGroup>/Logs/events.current.jsonl` | Tunnel JSONL log |
| `<AppGroup>/Logs/events.<timestamp>.<sequence>.jsonl` | Rotated tunnel JSONL log |
| `<AppGroup>/Logs/events.example.current.jsonl` | Example app diagnostic log |
| `<AppGroup>/StressReports/stress-<timestamp>.json` | Example app stress report |

## Verification Commands

| Command | Use |
| --- | --- |
| `swift test` | Full package tests |
| `swift test --filter AnalyticsTests` | Analytics/detector-focused tests |
| `xcodebuild -project Example/Example.xcodeproj -scheme Example -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build` | Example app compile check |
| `Scripts/quality-gate.sh` | Package quality gate and perf baseline schema |
| `swift run HarnessLocal <scenario.json>` | Synthetic local replay |
| `swift run HarnessLocal --pcap capture.pcap --max-packets 500` | PCAP replay |

Some local `swift test` runs and Example simulator builds may emit this known non-blocking linker warning while still compiling successfully:

```text
ld: warning: reducing alignment of section __DATA,__common from 0x8000 to 0x4000 because it exceeds segment maximum alignment
```

Treat that exact warning as accepted for now when it is the only warning and the command exits successfully. New compiler warnings, test failures, or additional linker warnings are not covered by this exception.

## Apple API References

| API | Package Use |
| --- | --- |
| [`NEPacketTunnelProvider`](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider) | Packet tunnel extension runtime |
| [`NETunnelProviderSession.sendProviderMessage`](https://developer.apple.com/documentation/networkextension/netunnelprovidersession/sendprovidermessage(_:responsehandler:)) | Foreground app/provider telemetry requests |
| [`NETunnelProvider.handleAppMessage`](https://developer.apple.com/documentation/networkextension/netunnelprovider/handleappmessage(_:completionhandler:)) | Provider-side app message handling |
| [`NEFilterDataProvider`](https://developer.apple.com/documentation/networkextension/nefilterdataprovider) | Optional host-app Content Filter source-app attribution |
| [`NEFilterManager`](https://developer.apple.com/documentation/networkextension/nefiltermanager) | Optional Content Filter configuration |
| [`NWPathMonitor`](https://developer.apple.com/documentation/network/nwpathmonitor) | Path-regime tracking |
| [`ProcessInfo.thermalState`](https://developer.apple.com/documentation/foundation/processinfo/thermalstate) | Thermal policy |
| [`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`](https://developer.apple.com/documentation/foundation/filemanager/containerurl(forsecurityapplicationgroupidentifier:)) | App Group artifact root |
