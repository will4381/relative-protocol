<!--
Created by Will Kusch, Relative Companies, Inc.
Copyright (c) 2026 Relative Companies, Inc.
Licensed for personal, non-commercial use only. See LICENSE for terms.
-->

# Detector Stream and Custom Detectors

This guide documents the detector-facing telemetry contract.

The package emits sparse, typed records. Detectors consume those records inside the tunnel extension and emit compact `DetectionEvent` values.

## Adding a Detector

```swift
import Analytics

final class MyDetector: TrafficDetector {
    let identifier = "my-detector"
    let requirements = DetectorRequirements(
        recordKinds: [.flowOpen, .packetCue, .metadata],
        featureFamilies: [.remoteEndpoint, .addressScope]
    )

    func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent] {
        // Inspect sparse records and emit durable detections.
        []
    }

    func reset() {}
}
```

Register detectors by overriding `PacketTunnelProviderShell.makeDetectors(profile:analyticsRootURL:logger:)` in the packet tunnel extension.

## Detector Requirements

Every detector can declare the exact record kinds and feature families it needs.

Record kinds:

- `flowOpen`
- `flowSlice`
- `flowClose`
- `metadata`
- `burst`
- `activitySample`
- `packetCue`
- `sourceAppFlow`

Feature families:

- `packetShape`
- `controlSignals`
- `burstShape`
- `hostHints`
- `quicIdentity`
- `stringAddresses`
- `dnsAnswerAddresses`
- `dnsAssociation`
- `lineage`
- `pathRegime`
- `serviceAttribution`
- `packetDetails`
- `sessionContext`
- `remoteEndpoint`
- `roleAttribution`
- `addressScope`
- `eventAudit`
- `sourceAppAttribution`

The worker computes the union once across installed detectors.
That means expensive enrichment is only activated when some detector asks for it, and each detector receives a projected lazy view rather than the full raw batch.

If a detector does not declare requirements explicitly, the package uses a compatibility default matching the older detector surface.

## Packet Cue Records

Use `packetCue` when a detector needs exact packet facts rather than `200 ms` flow/window aggregates.

`packetCue` records are the production detector stream for rules that depend on one packet length, payload length, or TCP flag combination.

```swift
let requirements = DetectorRequirements(
    recordKinds: [.packetCue],
    featureFamilies: [.addressScope]
)
```

For `packetCue` records, `DetectorRecord` automatically projects:

- `timestampMs`
- `direction`
- `protocolHint`
- `transportProtocol`
- `packetLength`
- `transportPayloadLength`
- `tcpFlags`
- `tcpAck`
- `tcpPsh`
- `packetCueReason`
- `sourceAddress`
- `sourcePort`
- `destinationAddress`
- `destinationPort`
- `flowId`
- `flowIdentity`
- `remoteAddress`
- `remotePort`
- `remoteEndpoint`
- `ownerKey`
- `role` when supplied by the app or detector integration
- `tlsServerName`
- `registrableDomain`
- `associatedDomain`
- `dnsQueryName`
- `dnsCname`

`timestampMs` is the detector clock domain used for packet sequencing, Content Filter attribution windows, session context, and fire records. In production, `SystemClock` anchors once to wall time and advances this value from monotonic uptime so later wall-clock changes do not reorder the detector stream.

`packetCue` emission is intentionally sparse and configurable. The package does not hardcode product-specific packet ranges.

Use `PacketCueEmissionPolicy` to choose the generic packet shapes your app wants:

```swift
let packetCuePolicy = PacketCueEmissionPolicy(
    tcpPayloadLengthRange: PacketLengthRange(0...800),
    udpPacketLengthRange: PacketLengthRange(500...1_300),
    directions: [.outbound],
    requireTcpAck: true,
    requireTcpPsh: true,
    includeHostAssociatedPackets: true,
    maxHostAssociatedPacketLength: 1_500,
    emitMetadataRefreshCues: true
)
```

Possible `packetCueReason` values are:

- `tcpAckPshPayloadRange`
- `udpPacketLengthRange`
- `hostAssociatedPacket`
- `metadataRefresh`
- `explicitPolicyMatch`

This lets detectors distinguish exact packet sequences such as `896` then `904`, instead of only seeing an aggregate like `bytes = 1800, packetCount = 2`.

The foreground live tap intentionally does not publish `packetCue` records by default. To expose packet cues to an app-side detector, enable the live-tap flag and pass a generic policy:

```swift
let profile = TunnelProfile(
    // existing profile fields...
    telemetryEnabled: true,
    liveTapEnabled: true,
    liveTapIncludeFlowSlices: false,
    liveTapIncludePacketCues: true,
    liveTapIncludeValidationRecords: true,
    liveTapMaxBytes: 1_048_576,
    packetCuePolicy: packetCuePolicy,
    // remaining profile fields...
)
```

Foreground snapshots also include stream health and liveness:

- `TelemetryHealthRecord`
  - `availableFeatureFamilies`
  - `missingFeatureFamilies`
  - `degradedReason`
  - `droppedRecordCount`
  - `lastPacketTimestampMs`
- `TelemetryStreamLiveness`
  - `streamStartedAtMs`
  - `lastRecordAtMs`
  - `sequenceNumber`
  - `droppedSequenceCount`
  - `sessionId`
  - `writerProcess`

Use these fields before scoring app-side detectors. If a feature family is missing because of low power mode, thermal pressure, or configuration, the app should treat absent fields as degraded data rather than negative evidence.

Low-power and thermal reductions are controlled independently through `TelemetryDegradationPolicy`. The defaults preserve production backoff; validation runs can disable either `reduceOnLowPowerMode` or `reduceOnThermalPressure` when stable packet fields are more important than reducing telemetry cost.

`TunnelTelemetryMessageCodec` preserves packet-cue `timestampMs`, packet fields, validation records, and liveness sequence fields across the host-visible JSON response.

## Rich Packet Debug JSONL

Use `RichPacketLogPolicy` when you need a durable packet-metadata file for debugging, offline scoring, or building a separate analysis app. This is not enabled by default and is intentionally separate from the production detector stream.

When enabled, the tunnel writes JSONL records under:

```text
<AppGroup>/Analytics/RichPacketLogs/<filePrefix>.current.jsonl
<AppGroup>/Analytics/RichPacketLogs/<filePrefix>.<timestamp>.<sequence>.jsonl
```

Each `RichPacketLogRecord` includes:

- sequence number, timestamp, timestamp milliseconds, writer process, and session context
- direction, IP version, protocol, packet length, and transport payload length
- source/destination addresses and ports
- local/remote addresses and ports, `remoteEndpoint`, `flowId`, and canonical `flowIdentity`
- TCP flags plus ACK/PSH/SYN/FIN/RST booleans
- DNS/TLS/QUIC metadata when parser budget allows
- optional packet byte prefix hex, off by default

Example profile policy:

```swift
let richLogPolicy = RichPacketLogPolicy(
    isEnabled: true,
    directions: [.outbound],
    includeParsedMetadata: true,
    includeDNSAnswerAddresses: true,
    includeQUICConnectionIDs: true,
    includePacketBytePrefix: false,
    maxPacketLength: 1_500,
    maxRecordsPerBatch: 256,
    metadataProbeLimitPerBatch: 16,
    filePrefix: "rich-packets",
    maxBytesPerFile: 4_194_304,
    maxFileCount: 8,
    maxTotalBytes: 33_554_432
)
```

Attach it to `TunnelProfile`:

```swift
let profile = TunnelProfile(
    // existing profile fields...
    packetCuePolicy: packetCuePolicy,
    telemetryDegradationPolicy: .default,
    richPacketLogPolicy: richLogPolicy,
    // remaining profile fields...
)
```

Read it from a host app or a separate App Group-enabled utility app:

```swift
import HostClient

let store = TunnelRichPacketLogStore(appGroupID: "group.com.example.vpn")
let recentRecords = try store.readRecords(limit: 500)
```

Privacy/cost rules:

- keep `RichPacketLogPolicy.disabled` for normal production builds
- byte-prefix logging is off by default because it can retain payload bytes
- metadata parsing is bounded by `metadataProbeLimitPerBatch`
- file retention is bounded by `maxBytesPerFile`, `maxFileCount`, and `maxTotalBytes`
- rich logging can keep the telemetry worker alive even when no detector or live tap is installed

## Remote Endpoint and Owner

Detectors should use package-derived owner fields instead of re-deriving endpoint identity everywhere:

- `remoteAddress`
- `remotePort`
- `remoteEndpoint`
- `ownerKey`

Remote means the non-phone side of the flow:

- outbound: destination address and port
- inbound: source address and port

`remoteEndpoint` is formatted as:

```text
<protocol>://<remoteAddress>:<remotePort>
```

IPv6 addresses are bracketed in the endpoint string.

`ownerKey` falls back in this order:

1. `sourceBundleId`
2. legacy `sourceAppIdentifier`
3. remote endpoint
4. flow id

The package exposes raw host facts such as `tlsServerName`, `registrableDomain`, `associatedDomain`, `dnsQueryName`, and `dnsCname`.
It does not decide that those facts belong to a particular company, app, or platform. Product-specific role classification belongs in the containing app or in app-supplied signature catalogs.

## Address Scope

Use `.addressScope` when a detector needs coarse app-owned or prefix-owned family labels even when host strings are missing.

The package supports:

- app-injected string families such as `"video-cdn"` or `"example-service"`
- source markers: `.prefix`, `.host`, `.dns`, `.contentFilter`, `.appProvided`
- optional prefix-based classification through `AddressScopeClassifier`
- provider configuration through `TunnelProfile.addressScopePrefixes`

There are no built-in platform families. The app owns catalogs and labels.

```swift
let classifier = AddressScopeClassifier(prefixes: [
    AddressScopePrefix(cidr: "203.0.113.0/24", family: "video-cdn", confidence: 0.88)!
])

let pipeline = PacketAnalyticsPipeline(
    clock: clock,
    burstTracker: BurstTracker(thresholdMs: 350),
    signatureClassifier: signatureClassifier,
    addressScopeClassifier: classifier
)
```

Prefix classification is only activated when some detector requests `.addressScope`.

Containing apps can pass the same data through provider configuration:

```swift
let providerConfiguration: [String: Any] = [
    "addressScopePrefixes": [
        [
            "cidr": "203.0.113.0/24",
            "family": "video-cdn",
            "confidence": 0.88
        ]
    ]
]
```

## Session Context

The VPN cannot infer app-open or foreground-readiness timing by itself.
If a detector needs app-session timing, the host app must supply it:

```swift
await telemetryWorker.updateSessionContextAndWait(
    DetectorSessionContext(
        sessionId: "session-123",
        packetStreamStartedAtMs: Date().timeIntervalSince1970 * 1000,
        foregroundReadyAtMs: nil,
        appOpenAtMs: nil,
        sessionTarget: "example-session"
    )
)
```

Detectors must request `.sessionContext` to receive:

- `sessionId`
- `packetStreamStartedAtMs`
- `foregroundReadyAtMs`
- `appOpenAtMs`
- `sessionTarget`

These fields are stamped onto future records after the worker receives the update.

## Source-App Attribution and Content Filter

`NEPacketTunnelProvider` packet data does not expose the originating app bundle id.

For source-app attribution, a host app needs a separate Content Filter Network Extension target.

Minimum architecture:

1. main app enables/configures the filter with `NEFilterManager`
2. Content Filter extension subclasses `NEFilterDataProvider`
3. the filter reads `NEFilterFlow.sourceAppIdentifier` when available
4. for socket flows, the filter reads endpoint information when available
5. the filter emits a compact `SourceAppFlowAttribution` / `sourceAppFlow` record to the host package integration
6. the filter returns `.allow()` so it remains passive and does not block traffic

The package currently provides the detector record contract:

- `PacketSampleKind.sourceAppFlow`
- `SourceAppFlowAttribution`
- `SourceAppAttributionSource`
- `SourceAppAttributionMode`
- `sourceBundleId`
- `sourceAppIdentifier`
- `sourceAppUniqueIdentifierHash`
- `sourceAppVersion`
- `attributionFlowId`
- `attributionSource`
- `attributionObservedAtMs`
- `attributionStartTimeMs`
- `attributionEndTimeMs`
- `attributionConfidence`
- `flowTuple`
- `localEndpoint`
- `remoteEndpoint`
- `remoteHostname`

It does not create the Content Filter target. That target belongs to the containing app because it needs its own extension bundle id, provisioning profile, and Network Extensions capability entry.

## Detector Surfaces

The main runtime input surface is:

- `TrafficDetector`
- `DetectorRequirements`
- `DetectorFeatureFamily`
- `DetectorRecordCollection`
- `DetectorRecord`

Use this when you want to:

- inspect sparse traffic features
- build rolling detector state
- score rules or ML features
- emit durable `DetectionEvent` values

## Typed Field Inventory

These typed fields are available on `DetectorRecord`, depending on the detector's requirements:

- flow/lifecycle
  - `kind`
  - `timestamp`
  - `timestampMs`
  - `direction`
  - `flowHash`
  - `flowId`
  - `flowIdentity`
  - `flowPacketCount`
  - `flowByteCount`
  - `closeReason`
- volume and packet shape
  - `bytes`
  - `packetCount`
  - `largePacketCount`
  - `smallPacketCount`
- protocol/control mix
  - `protocolHint`
  - `ipVersion`
  - `transportProtocol`
  - `transportProtocolNumber`
  - `udpPacketCount`
  - `tcpPacketCount`
  - `quicInitialCount`
  - `tcpSynCount`
  - `tcpFinCount`
  - `tcpRstCount`
- endpoint and host enrichment
  - `sourceAddress`
  - `sourcePort`
  - `destinationAddress`
  - `destinationPort`
  - `remoteAddress`
  - `remotePort`
  - `remoteEndpoint`
  - `ownerKey`
  - `role`
  - `registrableDomain`
  - `dnsQueryName`
  - `dnsCname`
  - `dnsAnswerAddresses`
  - `tlsServerName`
  - `classification`
- packet-level cues
  - `packetLength`
  - `transportPayloadLength`
  - `tcpFlags`
  - `tcpAck`
  - `tcpPsh`
  - `packetCueReason`
- DNS association
  - `associatedDomain`
  - `associationSource`
  - `associationAgeMs`
  - `associationConfidence`
- QUIC enrichment
  - `quicVersion`
  - `quicPacketType`
  - `quicDestinationConnectionId`
  - `quicSourceConnectionId`
- flow lineage
  - `lineageID`
  - `lineageGeneration`
  - `lineageAgeMs`
  - `lineageReuseGapMs`
  - `lineageReopenCount`
  - `lineageSiblingCount`
- path regime
  - `pathEpoch`
  - `pathInterfaceClass`
  - `pathIsExpensive`
  - `pathIsConstrained`
  - `pathSupportsDNS`
  - `pathChangedRecently`
- service attribution
  - `serviceFamily`
  - `serviceFamilyConfidence`
  - `serviceAttributionSourceMask`
- address scope
  - `addressScopeFamily`
  - `addressScopeSource`
  - `addressScopeConfidence`
- session context
  - `sessionId`
  - `packetStreamStartedAtMs`
  - `foregroundReadyAtMs`
  - `appOpenAtMs`
  - `sessionTarget`
- source-app attribution
  - `sourceBundleId`
  - `sourceAppIdentifier`
  - `sourceAppUniqueIdentifierHash`
  - `sourceAppVersion`
  - `attributionFlowId`
  - `attributionSource`
  - `attributionObservedAtMs`
  - `attributionStartTimeMs`
  - `attributionEndTimeMs`
  - `attributionConfidence`
  - `localEndpoint`
  - `remoteHostname`
- burst-shape fields
  - `burstDurationMs`
  - `burstPacketCount`
  - `leadingBytes200ms`
  - `leadingPackets200ms`
  - `leadingBytes600ms`
  - `leadingPackets600ms`
  - `burstLargePacketCount`
  - `burstUdpPacketCount`
  - `burstTcpPacketCount`
  - `burstQuicInitialCount`

## Detection Events and Fire Audit

Detectors emit `DetectionEvent` values. These are what the package persists and surfaces to the app.

String-field contract:

- `detectorIdentifier` is the primary namespace
- `signal` is a stable detector-defined event identifier
- `target` is an optional stable detector-defined subject bucket
- `trigger` is a stable detector-defined cause label

Use `DetectorFireRecord` when a detector needs a stable audit contract for why it fired. It can carry:

- detector name
- config id
- fire time
- source packet time
- source packet time in milliseconds
- reason
- owner key
- optional app-supplied role
- packet cue reason
- packet length
- payload length
- flow id
- flow identity
- lineage id

## Detector Persistence Model

`DetectionSnapshot` is the durable aggregate returned to the app. It includes:

- `updatedAt`
- `totalDetectionCount`
- `countsByDetector`
- `countsByTarget`
- `recentEvents`

Recommended persistence split:

- live tap
  - short-lived evidence/debug context
  - intentionally leaner than the full detector-facing sparse stream
  - debug surface, not detector system of record
- `DetectionSnapshot`
  - durable product state
- your own auxiliary detector store
  - only if your product truly needs detector-specific durable state

## Signatures

`SignatureClassifier` can optionally load a signature file from:

```text
<AppGroup>/Analytics/AppSignatures/<signatureFileName>
```

Current JSON shape:

```json
{
  "version": 1,
  "updatedAt": "2026-03-04T00:00:00Z",
  "signatures": [
    {
      "label": "social-video",
      "domains": ["video-cdn.example", "media-edge.example"]
    }
  ]
}
```

The analytics pipeline uses signatures as low-cost classification input.

## Hot-Path Rules

`TrafficDetector.ingest(_:)` runs inline on the single telemetry worker.

Do:

- process `DetectorRecordCollection` in linear time
- keep bounded memory
- use stable `signal`, `target`, and `trigger` strings
- degrade gracefully when some records are skipped or shed
- persist only compact detector output

Do not:

- perform blocking file I/O
- perform network requests
- sleep or wait on cross-process work
- allocate unbounded state from packet input
- perform large per-record model inference

For ML-backed detection, load the model once, build compact feature vectors from detector records, score synchronously and cheaply, and emit normal `DetectionEvent` values.
