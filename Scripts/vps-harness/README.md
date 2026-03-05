# VPS Harness

Off-device synthetic soak harness for VPN bridge regression testing.

## Components

- `harness.py`: orchestrates local `Standalone`, droplet impairment profiles, traffic scenarios, and regression gates.
- `release_gate.py`: runs staged rollout gates (`smoke`, `stress`, `soak`) and fails fast on first gate failure.
- `droplet_netem.py`: applies/clears Linux `tc/netem` shaping and `nftables` stack mode rules.
- `droplet_services.py`: deploys and manages synthetic remote services (TCP/UDP echo, DNS, QUIC-like UDP echo).
- `droplet_telemetry.py`: captures kernel/proc/eBPF telemetry per case (retransmits, drops, socket pressure deltas).

## Suites

- `smoke`: fast sanity across `wifi/lte/5g` in `dual_stack`.
- `stress-matrix`: `wifi/lte/5g/dirty` x `dual_stack/ipv4_only/ipv6_only`.
- `soak`: long-running manual duration run (`30m`, `60m`, `120m`).

## Quick Start

```bash
python3 Scripts/vps-harness/harness.py \
  --suite smoke \
  --vps-host 203.0.113.10 \
  --vps-host-v6 2001:db8::10 \
  --vps-user root \
  --vps-interface eth0 \
  --enable-telemetry \
  --enable-realistic-traffic \
  --enable-fuzz-lane
```

## Soak Example

```bash
python3 Scripts/vps-harness/harness.py \
  --suite soak \
  --soak-duration 60m \
  --vps-host 203.0.113.10 \
  --vps-host-v6 2001:db8::10 \
  --vps-user root \
  --vps-interface eth0 \
  --case-seconds 45
```

## Release Gate Example

```bash
python3 Scripts/vps-harness/release_gate.py \
  --vps-host 203.0.113.10 \
  --vps-host-v6 2001:db8::10 \
  --phases smoke,stress,soak30 \
  --strict-v6
```

## History / Baseline

By default, results are appended to:

`/Users/willkusch/Documents/Projects/VPN-Bridge/.tmp/vps-harness-history.jsonl`

The harness computes rolling medians over the last 10 passing runs per
`suite/scenario/profile/stack_mode` for regression deltas.

Baselines are version-scoped (`harness_baseline_version`) so major harness
changes do not compare against incompatible historical data.

## Regression Gates

Fails when any of the following occur:

- Core success rate `< 99%` (TCP/UDP/DNS/QUIC/realistic lanes + restart; fuzz lane reported separately)
- P50 latency regression `> 20%` vs baseline
- P95 latency regression `> 30%` vs baseline
- Dual-stack scenario loses both IPv4 and IPv6 reachability
- Reconnect loop detector trips

Optional stricter gate:

- `--require-ipv6-data-plane` fails when the IPv6 host is missing UDP/DNS/QUIC
  preflight reachability (and HTTP reachability when realistic traffic is enabled).

## Trace-Driven Replay

`--trace-profile-file` lets you replay capture-derived impairments inside each case.

Example schema:

```json
{
  "traces": {
    "commute": [
      { "timestamp_s": 0, "profile": "wifi" },
      { "timestamp_s": 18, "rate_mbit": 42, "ceil_mbit": 60, "latency_ms": 70, "jitter_ms": 18, "loss_pct": 0.8 },
      { "timestamp_s": 45, "profile": "5g" }
    ]
  }
}
```

Use with:

```bash
python3 Scripts/vps-harness/harness.py \
  --suite soak \
  --soak-duration 60m \
  --vps-host 203.0.113.10 \
  --vps-host-v6 2001:db8::10 \
  --trace-profile-file Scripts/vps-harness/example-traces.json \
  --trace-name commute
```

If no trace file is provided, you can still enable in-case transitions via:

`--handover-script default|aggressive|commute-loop`

This applies Wi-Fi/LTE/5G profile changes during one case (not just between cases).

Each case uses lane-level runtime budgeting so combined protocol lanes stay close to
the configured `--case-seconds` target instead of multiplying runtime by lane count.

## Realistic Traffic Lanes

Enable with `--enable-realistic-traffic`:

- HLS/DASH segment churn (`/hls` + `/dash` endpoints), with optional `ffmpeg`/`yt-dlp` pulls when available.
- Mixed HTTP/2 + HTTP/3-like concurrency (`httpx` lane + `aioquic` stream-pattern lane).
- DNS resolver-style parallel queries with retries + exponential backoff.

Enable fuzzing with `--enable-fuzz-lane`:

- `scapy` malformed DNS/UDP/QUIC-like payload mutation.
- `boofuzz` availability is detected and recorded in fuzz metrics.

Enable kernel telemetry with `--enable-telemetry`:

- Proc/net deltas (`Tcp.RetransSegs`, UDP errors, socket pressure).
- Optional `bpftrace` / BCC collectors when installed on the droplet.

Enable lifecycle churn with `--enable-lifecycle-churn`:

- Periodically executes `reload-config`, `flush-metrics`, and `status` while
  traffic is active.
- Add `--lifecycle-restarts` to include periodic `restart-relay` actions for
  dedicated reconnect-loop stress runs.
- Simulates background/foreground-style control-plane churn and catches unstable
  restart behavior under load.
- Gate with `--lifecycle-max-failures` (default `1`).

Standalone runtime fidelity knobs:

- `--standalone-enable-metrics` turns on parser/metrics pipeline in `Standalone`.
- `--standalone-enable-packet-stream` turns on packet sample stream writes.
- `--standalone-keepalive-interval-seconds <s>` enables standalone keepalive probes.

Memory/pressure gate:

- `--memory-rss-limit-mb <mb>` enforces a sustained RSS ceiling from live
  standalone status telemetry.
- `--memory-rss-grace-seconds` controls how long RSS may exceed the limit before
  failing a case.
- `--memory-sample-interval-ms` controls memory polling cadence.

## Dependencies

Python packages expected:

- `httpx`
- `PySocks`
- `dnspython`
- `aioquic`
- `scapy`
- `boofuzz`
- `numpy`

Use `--allow-missing-deps` to downgrade missing package failures to warnings.
