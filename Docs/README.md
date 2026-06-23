<!--
Created by Will Kusch, Relative Companies, Inc.
Copyright (c) 2026 Relative Companies, Inc.
Licensed for personal, non-commercial use only. See LICENSE for terms.
-->

# Documentation Index

This directory holds the detailed docs for `relative-protocol`. The root [README](../README.md) is intentionally short; use this index when you need implementation details.

## Main Guides

- [Getting Started](GettingStarted.md)
  - target wiring
  - provider subclass setup
  - `TunnelProfile` configuration
  - foreground reads and background recovery

- [Architecture](Architecture.md)
  - runtime model
  - package layout
  - App Group artifacts
  - live tap vs durable detections

- [Detector Stream and Custom Detectors](DetectorStream.md)
  - `TrafficDetector`
  - `DetectorRequirements`
  - `packetCue`
  - remote endpoint / role / address scope
  - session context
  - optional Content Filter source-app attribution
  - detection event audit contract

- [Reference](Reference.md)
  - package products
  - core public types
  - detector record kinds and feature families
  - detector field inventory
  - profile knobs
  - App Group artifacts
  - verification commands

- [Operations and Debugging](Operations.md)
  - production defaults
  - DNS, MTU, lifecycle, UDP, and QUIC guidance
  - thermal policy
  - stress matrix, fault injection, and real load drill
  - release checklist

- [Local Tunnel Harness](LocalTunnelHarness.md)
  - synthetic replay
  - PCAP replay
  - Linux TUN runtime checks
  - physical-device release gate

- [Changelog and Migration Notes](Changelog.md)
  - recent package changes
  - migration rules for network policy and detector stream changes

- [License and Usage Notes](LicenseAndUsage.md)
  - custom non-commercial license status
  - commercial, redistribution, and AI-assisted copying restrictions
  - privacy and App Review notes
  - source-app attribution cautions

## Common Questions

### Where do I start if I am adding this to an app?

Use [Getting Started](GettingStarted.md).

### Where do I add custom detector logic?

Use [Detector Stream and Custom Detectors](DetectorStream.md), then override `PacketTunnelProviderShell.makeDetectors(...)`.

### Where do I verify exact packet fields for TikTok or Instagram-style detectors?

Use the `packetCue` and typed field sections in [Detector Stream and Custom Detectors](DetectorStream.md).

### Where is the quick API and field lookup?

Use [Reference](Reference.md).

### Where is the Content Filter / bundle-id attribution plan?

Use [Detector Stream and Custom Detectors](DetectorStream.md#source-app-attribution-and-content-filter). Bundle-id attribution requires a separate `NEFilterDataProvider` extension target in the containing app.

### Where are production release checks?

Use [Operations and Debugging](Operations.md#stability-checklist).
