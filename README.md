# Relative Protocol

Relative Protocol provides a Packet Tunnel + tun2socks stack with packet metadata sampling, burst analytics, and optional app signature classification. It’s split into three SwiftPM libraries:

- **RelativeProtocolCore** — packet parsing, packet samples, metrics store, burst tracking, signature validation/classification.
- **RelativeProtocolTunnel** — `NEPacketTunnelProvider` implementation + tun2socks engine + sampling.
- **RelativeProtocolHost** — host-side helpers for configuring and controlling the tunnel.

## Requirements

- iOS 15+ (Network Extension / Packet Tunnel)
- App Group shared between the app and tunnel extension
- Network Extension entitlements

## Quick Start

1) **App Group**

Add the same App Group to both the host app and the tunnel extension (e.g. `group.com.example.vpn`).

2) **Host app setup (NEVPNManager)**

You configure the tunnel in the host app using `NEVPNManager` + `NETunnelProviderProtocol`. The `localizedDescription` becomes the VPN name shown in Settings. `serverAddress` is required by the API but not used by the tunnel.

```swift
import NetworkExtension

let manager = NEVPNManager.shared()
manager.loadFromPreferences { error in
    guard error == nil else { return }

    let proto = NETunnelProviderProtocol()
    proto.providerBundleIdentifier = "com.example.app.Example-Tunnel"
    proto.serverAddress = "127.0.0.1" // Required by NEVPNManager
    proto.providerConfiguration = [
        "appGroupID": "group.com.example.vpn",
        "relayMode": "tun2socks",
        "mtu": 1500,
        "ipv6Enabled": true,
        "dnsServers": ["1.1.1.1", "8.8.8.8"],
        "signatureFileName": "app_signatures.json",
        "packetStreamEnabled": true,
        "packetStreamMaxBytes": 5_000_000,
        "metricsEnabled": true,
        "metricsSnapshotInterval": 1.0,
        "metricsStoreFormat": "json", // or "ndjson"
        // Addressing used by the tunnel interface:
        "ipv4Address": "10.0.0.2",
        "ipv4SubnetMask": "255.255.255.0",
        "ipv4Router": "10.0.0.1",
        "ipv6Address": "fd00:1:1:1::2",
        "ipv6PrefixLength": 64,
        "tunnelRemoteAddress": "127.0.0.1"
    ]

    manager.protocolConfiguration = proto
    manager.localizedDescription = "Example VPN"
    manager.isEnabled = true

    manager.saveToPreferences { _ in }
}
```

Optional: configure On-Demand rules via `manager.onDemandRules` and `manager.isOnDemandEnabled`.

3) **Provider configuration keys**

Set `NETunnelProviderProtocol.providerConfiguration` with the keys you need. Defaults are applied when a key is omitted.

Common keys:

- `appGroupID` (String, required)
- `relayMode` (String, default `tun2socks`)
- `mtu` (Int, default `1500`)
- `ipv6Enabled` (Bool, default `true`)
- `dnsServers` ([String], default `[]`)
- `metricsEnabled` (Bool, default `true`)
- `metricsRingBufferSize` (Int, default `2048`)
- `metricsSnapshotInterval` (Double, default `1.0`)
- `metricsStoreFormat` (String, default `json`, options: `json`, `ndjson`)
- `burstThresholdMs` (Int, default `350`)
- `flowTTLSeconds` (Int, default `300`)
- `maxTrackedFlows` (Int, default `2048`)
- `maxPendingAnalytics` (Int, default `512`)
- `packetStreamEnabled` (Bool, default `false`)
- `packetStreamMaxBytes` (Int, default `5_000_000`)
- `signatureFileName` (String, default `app_signatures.json`)

There are additional engine tuning keys (buffer sizes, socks port, etc.) in `TunnelConfiguration`.

4) **App signatures file**

Create an app signature JSON file in the app group container. The tunnel loads this to classify traffic. Use `AppSignatureStore.writeIfMissing` on the host side.

Location (app group container):

```
AppSignatures/<signatureFileName>
```

Example JSON:

```json
{
  "version": 1,
  "updatedAt": "2026-01-24T12:00:00Z",
  "signatures": [
    {
      "label": "short_form_video",
      "domains": [
        "example.com",
        "video.example.com"
      ]
    },
    {
      "label": "social",
      "domains": [
        "social.example",
        "images.example"
      ]
    }
  ]
}
```

### Signature validation rules

`AppSignatureStore.validate` enforces:

- non-empty signature list
- non-empty labels (labels are case-insensitive for uniqueness)
- non-empty domain list
- domains are lowercase/trimmed, contain a dot, no scheme (`://`), no `/`, no spaces, no leading/trailing `.`
- wildcard `*` is allowed inside domains (glob-style match). Wildcards are applied per-label and do not cross dots.

On load, the tunnel uses `loadValidated`. Invalid files are ignored.

## Metrics and Packet Stream

### Metrics

`MetricsStore` writes snapshots to:

```
MetricsStore/metrics.snapshots.json
```

If `metricsStoreFormat` is set to `ndjson`, each snapshot is written as one line of JSON for easier streaming/debugging.

Snapshots are bounded by:

- `maxSnapshots` (ring buffer behavior)
- `maxBytes` (file size cap)

### Packet sample stream

`PacketSampleStreamWriter` writes NDJSON to:

```
PacketStream/<key>.ndjson
```

The file is capped by `packetStreamMaxBytes` and is reset when it exceeds the limit.
Use `PacketStreamCursor` with `PacketSampleStreamReader.readNew(cursor:)` to safely resume across rotations.

Each `PacketSample` includes DNS/TLS/QUIC metadata (including `quicPacketType`) and burst/classification fields when available.

## Diagnostics

The Example app ships with a diagnostics screen that reads metrics + the packet stream, showing recent packet samples, DNS/TLS/QUIC metadata, burst metrics, and classification.

## Public API Surface (Core)

- `PacketParser`, `PacketMetadata`, `PacketSample`, `PacketSampleStreamWriter`, `PacketSampleStreamReader`
- `PacketStreamCursor`, `PacketStreamFileSignature`
- `MetricsStore`, `MetricsSnapshot`, `MetricsRingBuffer`, `MetricsStoreFormat`
- `BurstTracker`, `BurstMetrics`
- `TrafficClassifier`, `AppSignatureStore`, `AppSignatureValidationError`

## Tests

Run unit tests:

```
swift test
```

Generate coverage reports:

```
swift test --enable-code-coverage
./Scripts/coverage.sh
```

Coverage outputs:

- `.build/coverage/coverage.txt` (human-readable table)
- `.build/coverage/coverage.json` (`llvm-cov` export)
- `.build/coverage/source_summary.txt` (source-only totals + lowest covered files)

## Changelog

### 2/11/26

- Hardened tunnel/runtime performance paths in core flow tracking, burst tracking, metrics persistence, packet stream handling, and classification logic to reduce unnecessary work and long-run memory pressure.
- Added safety guards in tunnel-side components (`RelativePacketTunnelProvider`, SOCKS codec/server/relay, tun2socks engine, and tunnel socket bridge) to improve resilience under sustained traffic and edge conditions.
- Preserved classification/data quality behavior while tightening parsing and buffering code paths to avoid regressions in metadata capture and downstream model inputs.
- Expanded the test suite with broad edge-case coverage across core and tunnel modules (including parser/stream/flow/classifier/tunnel/SOCKS paths).
- Added coverage tooling in `Scripts/coverage.sh` and documented coverage report outputs for repeatable coverage checks.

## Notes

- Classification matches exact domains or subdomains (e.g. `api.tiktok.com` matches `tiktok.com`, but `notiktok.com` does not).
- Signature domains can include `*` wildcards (e.g. `p*.tiktokcdn*.com`) and are matched against the full hostname using per-label matching.
- QUIC packet types are surfaced (`initial`, `zeroRTT`, `handshake`, `retry`). SNI extraction is only attempted on Initial packets; 0‑RTT is not decrypted.
- The tunnel only uses metadata (DNS/TLS/QUIC headers and flow timing). No payload capture is performed.

## Troubleshooting

- **App Group container not found / `client is not entitled`**
  - Ensure the App Group entitlement is added to both the app target and the tunnel extension.
  - Verify the App Group ID string matches exactly.
  - On device, uninstall/reinstall the app after changing entitlements.

- **VPN name not showing in Settings**
  - Set `NEVPNManager.localizedDescription` before saving preferences.
  - Call `saveToPreferences` and wait for completion.

- **Tunnel connects but no traffic**
  - Confirm `providerBundleIdentifier` matches the tunnel extension bundle ID.
  - Ensure `NEPacketTunnelProvider` is in the extension and the extension is in the app bundle.
  - Check the `ipv4Address`, `ipv4SubnetMask`, and `ipv4Router` settings.

- **Packet stream file not appearing**
  - `packetStreamEnabled` must be `true` in providerConfiguration.
  - App Group entitlement must be valid.
  - File is written to `AppGroup/PacketStream/<key>.ndjson` with size cap.

- **Signature classification not working**
  - Confirm `signatureFileName` matches the file in `AppGroup/AppSignatures/`.
  - Validate JSON format and domains (see validation rules above).

- **On‑Demand reconnects**
  - If `isOnDemandEnabled` is true, the system may reconnect automatically on network changes.
