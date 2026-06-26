<!--
Created by Will Kusch, Relative Companies, Inc.
Copyright (c) 2026 Relative Companies, Inc.
Licensed for personal, non-commercial use only. See LICENSE for terms.
-->

# Changelog and Migration Notes

This file tracks high-level package changes and migration guidance. It is not a substitute for git history, but it gives integrators a stable place to check compatibility notes.

## Current Development Snapshot

### Detector Stream Contract

- added `packetCue` records for exact detector-facing packet signals without dumping every packet into the foreground live tap
- packet cues expose typed packet length, transport payload length, TCP flags, ACK/PSH booleans, endpoint fields, flow id, canonical flow identity, cue reason, and host/domain association
- added `PacketCueEmissionPolicy` so packet-cue ranges, directions, ACK/PSH requirements, host-associated packets, and metadata refresh cues are app-configured rather than hardcoded
- added optional app-visible packet cues through `liveTapIncludePacketCues` plus validation records through `liveTapIncludeValidationRecords`
- added opt-in `RichPacketLogPolicy`, `RichPacketLogRecord`, and `TunnelRichPacketLogStore` for bounded rich packet metadata JSONL debugging under the App Group
- added `TelemetryHealthRecord` and `TelemetryStreamLiveness` to foreground snapshots so apps can detect degraded/missing feature families and stream liveness
- added `TelemetryDegradationPolicy` plus `telemetryReduceOnLowPowerMode` and `telemetryReduceOnThermalPressure` profile keys so low-power and thermal telemetry reduction can be controlled independently
- added explicit remote endpoint, owner key, app-supplied role, app-injected address-scope, and app/session context fields for detector records
- added `addressScopePrefixes` provider configuration so apps can inject generic CIDR-to-family labels into tunnel-side detector records
- changed session context target wording to generic `sessionTarget`
- kept `role` and `addressScopeFamily` as opaque app-provided strings, with neutral package docs/tests such as `"video-cdn"` and `"example-service"`
- added `sourceAppFlow` records as the package contract for optional Content Filter based source-app attribution, including source bundle id, canonical flow tuple, time window, and confidence
- added `DetectorFireRecord` for typed detector fire audit metadata, including source packet milliseconds, cue reason, and canonical flow identity
- removed built-in platform-specific role/scope derivation; the package now emits packet facts, flow facts, timing facts, attribution facts, and health facts while apps own company/app/platform meaning
- added package tests for packet cue projection, host JSON export of packet cues with timestamps/liveness sequence, remote endpoint derivation, topology owner fields, address scope, source-app attribution projection, and fire-record round trips

### Detector Requirements

- detectors declare required record kinds and feature families through `DetectorRequirements`
- the worker computes one runtime union plan and only activates requested enrichments
- detector-facing sparse records can be richer than the foreground live tap
- `flowSlice` remains detector-only by default unless a host opts into exposing it in the live tap
- `packetCue` remains detector-facing by default unless a host opts into app-visible packet cues

### Transport and Production Hardening

- runtime provider configuration fails closed for malformed IP addresses, subnet masks, relay hosts, DNS resolvers, DNS-over-TLS server names, and DNS-over-HTTPS URLs
- encrypted DNS configuration no longer silently downgrades to cleartext when `serverName` or `serverURL` is missing
- SOCKS5 request parsing rejects invalid reserved bytes and returns command/address-specific failure codes
- UDP ASSOCIATE pins relay traffic to the original localhost client endpoint
- HEV `FWD_UDP` is supported so TCP-carried UDP works when a profile disables UDP-over-UDP
- dataplane bridge lifecycle fields and stats updates are protected by one synchronization boundary
- lwIP random source ports and TCP initial sequence numbers use first-party secure randomness hooks
- `Scripts/quality-gate.sh` validates `Config/PerfBaseline.json` and can compare metrics through `VPN_BRIDGE_PERF_RESULTS`
- documented the known non-blocking local linker alignment warning so successful `swift test` and Example simulator builds are not mistaken for failures

### Recovery and Concurrency

- outbound TCP uses bounded connect attempts with retry for stalled `NWConnection.State.preparing`
- outbound UDP sessions preserve recoverable `waiting` sessions, remove failed sessions, and lazily rotate after better-path or not-viable signals
- synthesized HEV configs omit `udp: 'udp'` when `relayEndpoint.useUDP == false`
- isolated UDP oversize / PMTU drops no longer tear down the whole relay immediately
- `engineSocksPort = 0` round-trips through provider configuration
- per-connection relay work runs off dedicated queues instead of one shared queue

### Policy Surface

- added `TunnelMTUStrategy` for fixed MTU or automatic `tunnelOverheadBytes`
- added `TunnelDNSStrategy` for cleartext DNS, DNS-over-TLS, DNS-over-HTTPS, or no DNS override
- provider-configuration defaults are explicit package policy instead of hidden hardcoded values
- host apps that care about Wi-Fi/cellular continuity should strongly consider `tcpMultipathHandoverEnabled`

### QUIC and Test Coverage

- QUIC Initial header protection uses CommonCrypto AES
- RFC 9001 Appendix A.2 known-answer vector covers the full decrypt chain
- fuzz suites cover SOCKS5 codec and deep packet parser edge cases
- telemetry worker lifecycle, relay ordering, logger level-gate, bridge stop/write, DNS association, lineage, path regime, and detector projection tests were expanded

## Migration From Earlier Releases

Transport recovery improvements do not require host-app changes. If you upgrade the package, you automatically get:

- bounded TCP connect timeout and retry
- UDP session replacement on bad-path signals
- TCP-carried UDP fallback when `relayEndpoint.useUDP == false`
- better-path-aware outbound TCP connect policy
- isolated UDP PMTU / oversize drops no longer kill the whole UDP relay path
- preservation of `engineSocksPort = 0` when decoding `providerConfiguration`

Network policy defaults do change if your extension relies on `TunnelProfile.from(providerConfiguration:)` with missing keys.

Migration rules:

1. If your app constructs `TunnelProfile(...)` directly and already passes `mtu` and `dnsServers`, behavior stays backward-compatible.
2. If your extension decodes sparse `providerConfiguration` and relied on package defaults, be explicit. The package default policy is `mtuStrategy = .fixed(1280)` and `dnsStrategy = .recommendedDefault`.
3. If you want the previous compatibility-first system-resolver behavior, set `dnsStrategy = .noOverride`.
4. If you know your tunnel encapsulation overhead, prefer `mtuStrategy = .automaticTunnelOverhead(...)`.
5. If your product needs better continuity across Wi-Fi/cellular transitions, enable `tcpMultipathHandoverEnabled = true`.
6. If you run multiple local profiles, test harnesses, or extension builds on the same device, prefer `engineSocksPort = 0`.
7. If you configure encrypted DNS, provide complete resolver IPs plus the required DoT `serverName` or DoH `serverURL`.
8. If your profile sets `relayEndpoint.useUDP = false`, the synthesized HEV config now uses TCP-carried UDP.

Recommended migration profiles:

- package full-tunnel default
  - `mtuStrategy = .fixed(1280)`
  - `dnsStrategy = .recommendedDefault`
  - `tcpMultipathHandoverEnabled = true` for mobility-sensitive clients
  - `engineSocksPort = 0`
- system-resolver compatibility opt-out
  - `mtuStrategy = .fixed(1280)`
  - `dnsStrategy = .noOverride`
  - `tcpMultipathHandoverEnabled = true` for mobility-sensitive clients
  - `engineSocksPort = 0`
- explicit public-DNS full tunnel
  - `mtuStrategy = .fixed(1280)`
  - `dnsStrategy = .cleartext(servers: TunnelDNSStrategy.defaultPublicResolvers)`
  - `tcpMultipathHandoverEnabled = true` for mobility-sensitive clients
  - `engineSocksPort = 0`
- protocol-aware UDP tunnel
  - `mtuStrategy = .automaticTunnelOverhead(80)`
  - choose `dnsStrategy` explicitly
  - `tcpMultipathHandoverEnabled = true` when you expect network transitions during long-lived TCP sessions
  - `engineSocksPort = 0`

## Recent Production-Candidate Baseline

- Wi-Fi Adaptive: `PASS`, `1143` probes, `0` failed
- Cellular/5G Adaptive: `PASS`, `1176` probes, `0` failed
- Wi-Fi to cellular transition: `PASS`, `1037` probes, `0` failed
- Cellular to Wi-Fi transition: `PASS`, `1282` probes, `0` failed

Blocked rows in that baseline were expected environment gates, not failed tunnel probes.
