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
        featureFamilies: [.remoteEndpoint, .roleAttribution, .addressScope]
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
- `sourceAddress`
- `sourcePort`
- `destinationAddress`
- `destinationPort`
- `flowId`
- `remoteAddress`
- `remotePort`
- `remoteEndpoint`
- `ownerKey`
- `role`
- `tlsServerName`
- `registrableDomain`
- `associatedDomain`
- `dnsQueryName`
- `dnsCname`

`packetCue` emission is intentionally sparse. The tunnel emits it for likely useful packets:

- outbound TCP with ACK + PSH and payload length `<= 800`
- outbound UDP with packet length `500...1300`
- packets associated with useful host/domain metadata

This lets detectors distinguish exact packet sequences such as `896` then `904`, instead of only seeing an aggregate like `bytes = 1800, packetCount = 2`.

The foreground live tap intentionally does not publish `packetCue` records by default. They are detector-facing records, not raw packet capture.

## Remote Endpoint, Owner, and Role

Detectors should use package-derived owner fields instead of re-deriving endpoint identity everywhere:

- `remoteAddress`
- `remotePort`
- `remoteEndpoint`
- `ownerKey`
- `role`

Remote means the non-phone side of the flow:

- outbound: destination address and port
- inbound: source address and port

`remoteEndpoint` is formatted as:

```text
<protocol>://<remoteAddress>:<remotePort>
```

IPv6 addresses are bracketed in the endpoint string.

`ownerKey` falls back in this order:

1. source app id
2. normalized role
3. remote endpoint
4. flow id

`role` is a normalized package-owned label derived from service attribution, associated domain, registrable domain, TLS SNI, DNS name, CNAME, or classification. The original source fields are still exposed when requested.

## Address Scope

Use `.addressScope` when a detector needs coarse family attribution even when host strings are missing.

The package supports:

- role/host token scope derivation
- source-app token scope derivation for `sourceAppFlow`
- optional prefix-based classification through `AddressScopeClassifier`

```swift
let classifier = AddressScopeClassifier(prefixes: [
    AddressScopePrefix(cidr: "157.240.0.0/16", family: .meta, confidence: 0.88)!
])

let pipeline = PacketAnalyticsPipeline(
    clock: clock,
    burstTracker: BurstTracker(thresholdMs: 350),
    signatureClassifier: signatureClassifier,
    addressScopeClassifier: classifier
)
```

Prefix classification is only activated when some detector requests `.addressScope`.

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
        targetApp: "instagram"
    )
)
```

Detectors must request `.sessionContext` to receive:

- `sessionId`
- `packetStreamStartedAtMs`
- `foregroundReadyAtMs`
- `appOpenAtMs`
- `targetApp`

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
- `sourceAppIdentifier`
- `sourceAppUniqueIdentifierHash`
- `sourceAppVersion`
- `attributionFlowId`
- `attributionSource`
- `attributionObservedAtMs`
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
  - `direction`
  - `flowHash`
  - `flowId`
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
  - `timestampMs`
  - `packetLength`
  - `transportPayloadLength`
  - `tcpFlags`
  - `tcpAck`
  - `tcpPsh`
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
  - `targetApp`
- source-app attribution
  - `sourceAppIdentifier`
  - `sourceAppUniqueIdentifierHash`
  - `sourceAppVersion`
  - `attributionFlowId`
  - `attributionSource`
  - `attributionObservedAtMs`
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
- reason
- owner key
- role
- packet length
- payload length
- flow id
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
