# VPS Harness

Off-device synthetic soak harness for VPN bridge regression testing.

## Components

- `harness.py`: orchestrates local `Standalone`, droplet impairment profiles, traffic scenarios, and regression gates.
- `droplet_netem.py`: applies/clears Linux `tc/netem` shaping and `nftables` stack mode rules.
- `droplet_services.py`: deploys and manages synthetic remote services (TCP/UDP echo, DNS, QUIC-like UDP echo).

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
  --vps-interface eth0
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

## History / Baseline

By default, results are appended to:

`/Users/willkusch/Documents/Projects/VPN-Bridge/.tmp/vps-harness-history.jsonl`

The harness computes rolling medians over the last 10 passing runs per
`suite/scenario/profile/stack_mode` for regression deltas.

## Regression Gates

Fails when any of the following occur:

- Success rate `< 99%`
- P50 latency regression `> 20%` vs baseline
- P95 latency regression `> 30%` vs baseline
- Dual-stack scenario loses both IPv4 and IPv6 reachability
- Reconnect loop detector trips

## Dependencies

Python packages expected:

- `httpx`
- `PySocks`
- `dnspython`
- `aioquic`
- `scapy`
- `numpy`

Use `--allow-missing-deps` to downgrade missing package failures to warnings.
