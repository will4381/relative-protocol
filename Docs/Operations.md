# Operations and Debugging

This guide covers production policy, observability, debugging, and release checks.

## Production Best Practices

The safest production posture is explicit policy plus observability.
Do not let VPN-critical behavior depend on sparse provider configuration, hidden defaults, or foreground-only app state.

Recommended baseline:

- use `TunnelProfileManager.configure(...)` to write provider configuration
- set `engineSocksPort = 0` so the local SOCKS listener uses an ephemeral free port
- set `mtuStrategy = .fixed(1280)` unless you know the exact encapsulation overhead
- set `dnsStrategy` explicitly for your product and network environment
- enable `tcpMultipathHandoverEnabled = true` for consumer mobile products that should survive Wi-Fi/cellular handoff
- keep `telemetryEnabled = true` in production so detectors, stop breadcrumbs, health samples, and bounded logs exist when something goes wrong
- keep `liveTapEnabled = true` for support/debug builds
- keep `liveTapIncludeFlowSlices = false` unless you are intentionally collecting richer foreground diagnostics
- read `TunnelStopStore` and JSONL logs after every unexpected disconnect before changing tunnel behavior

## DNS Policy

- `.recommendedDefault` installs full-tunnel public resolvers for all DNS queries and avoids relying on an ambient system resolver path for VPN-covered traffic.
- `.noOverride` preserves the system resolver path, but it is an explicit compatibility opt-out.
- `.cleartext(servers:allowFailover:)` is appropriate when the product needs a specific full-tunnel resolver set and accepts that some networks block or intercept public DNS.
- `.tls(...)` and `.https(...)` should only be used with fully specified resolver IPs plus server name or URL.
- Do not rely on `dnsServers` alone as a production contract; encode `dnsStrategy`.
- If a host app offers Adaptive DNS, make it observable: show the selected mode, active installed strategy, and current path DNS support.

## MTU Policy

- fixed `1280` is the conservative compatibility default for iPhone deployments
- automatic `tunnelOverheadBytes` is useful only when the host app knows the real encapsulation overhead
- keep NetworkExtension settings, bridge buffers, and dataplane buffers aligned
- investigate dropped packets, repeated UDP oversize failures, or sustained QUIC failures before raising MTU

## Lifecycle Policy

- start NetworkExtension settings, relay, dataplane, and packet loops as one ordered runtime
- stop the dataplane before closing TUN, bridge, or listener resources
- treat dataplane startup timeout as a failed start that must clean up state and clear the active handle
- do not fail provider startup just because an initial path sample is transiently unsatisfied
- make reconnect idempotent

## UDP and QUIC Policy

- do not replace UDP sessions just because Network.framework reports `waiting`
- schedule UDP session replacement on better-path or not-viable signals, then rotate on the next datagram
- keep isolated datagram-too-large failures from tearing down the whole UDP relay
- prefer TCP-carried UDP for consumer profiles unless you have proof UDP-over-UDP is consistently accepted
- treat each SOCKS UDP ASSOCIATE as owned by its original localhost client endpoint
- monitor QUIC separately from TCP

## Operational Defaults

Current package defaults:

- live tap retention window: `10s`
- foreground packet snapshot cap: `96`
- telemetry queue cap: `2` batches / `256 KB`
- detector `flowSlice` cadence: `250 ms`
- default live tap publishes `flowOpen`, `metadata`, `burst`, and `flowClose`
- default live tap does not publish `flowSlice`
- default live tap does not publish `packetCue`
- default `liveTapIncludeFlowSlices`: `false`
- health sample interval: `60s`
- more aggressive telemetry backoff at elevated thermal states

These defaults bias toward tunnel stability and battery efficiency over exhaustive logging.

## Thermal Model

The worker reads:

- `ProcessInfo.thermalState`
- `ProcessInfo.isLowPowerModeEnabled`

Policy shape:

- `nominal`
  - detector-side `flowSlice` enabled
  - sparse activity samples enabled
  - limited deep metadata allowed
- `fair`
  - detector-side `flowSlice` still enabled
  - deep metadata off
  - activity samples off
- `serious` / `critical` / low power mode
  - detector-side `flowSlice` off
  - deep metadata off
  - activity samples off

The package degrades telemetry cost before the tunnel becomes thermally unsafe.

## Structured Logs

The package logs through `StructuredLogger` and the `Observability` module.
By default, high-value lifecycle and fault events are retained while hot-path noise stays reduced.

Important files:

- `Sources/Observability/StructuredLogger.swift`
- `Sources/Observability/JSONLLogSink.swift`
- `Sources/Observability/OSLogSink.swift`
- `Sources/Observability/LogEnvelope.swift`

Watch these event families:

- `start-success`
- `stop`
- `health-sample`
- `connect-timeout`
- `connect-overall-timeout`
- `outbound-connect-failed`
- `outbound-read-failed`
- `session-replacement-scheduled`
- telemetry shedding events

Alert on sustained `packet_batches_dropped`, nonzero `pending_outbound_packets`, bridge backpressure, repeated TCP overall timeouts, and unexpected stop reasons.

## Last Stop Reason

The provider persists a small stop breadcrumb to:

```text
<AppGroup>/Analytics/last-stop.json
```

Read it through `TunnelStopStore` when debugging unexpected exits.

## Detector Debugging

Inspect both:

1. live tap snapshots from `TunnelTelemetryClient`
2. persisted detection summaries from `TunnelDetectionStore`

That split matters:

- live tap explains the last few seconds
- persisted detections explain long background spans

Useful questions:

1. did the tunnel see the expected sparse records?
2. did the detector emit at the right boundary?
3. did confidence match the evidence strength?
4. did the detection persist across app suspension?
5. did shed mode materially affect the detector?

If a foreground snapshot shows `0` `flowSlice` rows, that is expected with default package policy.

## On-Device Stress Matrix

The Example app includes a real-device stress matrix under `Example/`.
Use it before releasing changes that touch tunnel startup, DNS, MTU, relay behavior, telemetry, UDP, QUIC, or path transitions.

Recommended test order:

1. install the Example app and tunnel extension on a physical iPhone
2. choose `Adaptive` DNS unless testing a specific resolver policy
3. run the matrix on normal Wi-Fi
4. run on cellular/5G
5. run Wi-Fi to cellular transition
6. run cellular to Wi-Fi transition
7. repeat on known-problem networks when available

Healthy run indicators:

- `failedProbes = 0`
- blocked probes only for environments that were not actually present
- `effectiveDNS` matches the active installed profile
- `packet_batches_dropped = 0` or stops climbing after a short burst
- `packet_batches_inflight = 0` after the run settles
- `pending_outbound_packets = 0`
- `bridge_backpressured = false`
- no sustained `connect-overall-timeout`
- no repeated `outbound-connect-failed`

Artifacts:

```text
<AppGroup>/StressReports/stress-<timestamp>.json
<AppGroup>/Logs/events.current.jsonl
<AppGroup>/Logs/events.<timestamp>.<sequence>.jsonl
<AppGroup>/Logs/events.example.current.jsonl
<AppGroup>/Logs/events.example.<timestamp>.<sequence>.jsonl
<AppGroup>/Analytics/last-stop.json
```

## Fault Injection

The Example app includes a local fault-injection runner for deterministic relay recovery behavior.

The runner forces:

- repeated outbound TCP `waiting` events with default no-restart recovery
- outbound TCP `waiting` timeout and retry
- opt-in bounded TCP waiting restart budget
- direct UDP `waiting`, failed-session recreation, and better-path replacement
- TCP-carried UDP `waiting` and better-path replacement

A healthy run reports `PASS` for every row.

## Real Load Drill

The Example app includes a focused real-network load drill for quicker checks than the full matrix.

The drill runs:

- concurrent UDP DNS round trips against public resolvers
- concurrent HTTP/3 QUIC handshakes on UDP `443`
- concurrent HTTPS requests
- concurrent larger HTTPS downloads
- concurrent TCP `443` opens
- a mixed row that runs DNS, QUIC, HTTPS, large HTTPS, and TCP together

A healthy run reports `PASS`, `failedProbes = 0`, and reasonable p50/p95 latency for the current network.

## Profiling Guidance

Use Instruments in separate passes.
Do not stack heavy templates for long runs unless chasing a specific issue.

Recommended order:

1. `Energy Log`
2. `VM Tracker`
3. `Time Profiler` only if a thermal or CPU issue remains

## Stability Checklist

Before calling a build production-ready, validate:

1. `swift test`
2. iOS app/tunnel-extension build with signing disabled or a real development profile
3. `Scripts/quality-gate.sh`
4. physical-device stress matrix on Wi-Fi
5. physical-device stress matrix on cellular/5G
6. Wi-Fi to cellular transition during the matrix
7. cellular to Wi-Fi transition during the matrix
8. `30-60 min` soak with no unexpected tunnel exits
9. background correctness with the containing app suspended
10. persisted detector outputs remain correct after resume
11. no steady memory climb in `VM Tracker`
12. normal usage stays `Nominal` in `Energy Log`
13. no sustained telemetry shedding, bridge backpressure, or pending outbound queue growth
14. no repeated TCP overall timeouts or UDP waiting loops after path changes

Known Example simulator linker warning:

```text
ld: warning: reducing alignment of section __DATA,__common from 0x8000 to 0x4000 because it exceeds segment maximum alignment
```

This warning is currently accepted as non-blocking when the Example app build succeeds and no other warnings are present. Keep it visible in release notes and fix it when practical, but do not treat it as a package regression by itself.

`Scripts/quality-gate.sh` always validates the perf baseline schema.
To enforce real perf numbers, set `VPN_BRIDGE_PERF_RESULTS` to a JSON file containing either a metrics object or a metrics array with `name` and `value` fields.

## Apple API References

- [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [NETunnelProvider](https://developer.apple.com/documentation/networkextension/netunnelprovider)
- [NETunnelProviderSession.sendProviderMessage(_:responseHandler:)](https://developer.apple.com/documentation/networkextension/netunnelprovidersession/sendprovidermessage(_:responsehandler:))
- [NETunnelProvider.handleAppMessage(_:completionHandler:)](https://developer.apple.com/documentation/networkextension/netunnelprovider/handleappmessage(_:completionhandler:))
- [FileManager.containerURL(forSecurityApplicationGroupIdentifier:)](https://developer.apple.com/documentation/foundation/filemanager/containerurl(forsecurityapplicationgroupidentifier:))
- [ProcessInfo.thermalState](https://developer.apple.com/documentation/foundation/processinfo/thermalstate)
- [ProcessInfo.isLowPowerModeEnabled](https://developer.apple.com/documentation/foundation/processinfo/islowpowermodeenabled)
- [Data.write(to:options:)](https://developer.apple.com/documentation/foundation/data/write(to:options:))
