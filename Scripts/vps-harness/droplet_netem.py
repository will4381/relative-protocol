#!/usr/bin/env python3
"""Droplet network impairment management for VPN harness."""

from __future__ import annotations

import argparse
import dataclasses
import subprocess
from typing import Dict, List


@dataclasses.dataclass(frozen=True)
class Profile:
    rate_mbit: int
    ceil_mbit: int
    latency_ms: int
    jitter_ms: int
    loss_pct: float
    reorder_pct: float = 0.0
    reorder_corr_pct: float = 0.0
    corrupt_pct: float = 0.0
    duplicate_pct: float = 0.0


PROFILES: Dict[str, Profile] = {
    "wifi": Profile(rate_mbit=220, ceil_mbit=260, latency_ms=22, jitter_ms=4, loss_pct=0.08),
    "lte": Profile(rate_mbit=45, ceil_mbit=60, latency_ms=58, jitter_ms=12, loss_pct=0.55),
    "5g": Profile(rate_mbit=140, ceil_mbit=200, latency_ms=34, jitter_ms=8, loss_pct=0.30),
    "dirty": Profile(
        rate_mbit=28,
        ceil_mbit=35,
        latency_ms=95,
        jitter_ms=45,
        loss_pct=2.4,
        reorder_pct=2.2,
        reorder_corr_pct=40.0,
        corrupt_pct=0.6,
        duplicate_pct=0.3,
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage tc/netem + nft stack modes")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--dry-run", action="store_true")

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    p_apply = subparsers.add_parser("apply", help="Apply impairment profile")
    p_apply.add_argument("--profile", choices=sorted(PROFILES), required=True)

    p_stack = subparsers.add_parser("stack", help="Set IP stack mode")
    p_stack.add_argument("--mode", choices=["dual_stack", "ipv4_only", "ipv6_only"], required=True)

    subparsers.add_parser("clear", help="Clear impairments and nft filters")
    return parser.parse_args()


def run_ssh(user: str, host: str, script: str, dry_run: bool) -> None:
    target = f"{user}@{host}"
    if dry_run:
        print(f"[DRY-RUN] ssh {target} <<'SH'\n{script}\nSH")
        return
    subprocess.run(["ssh", target, script], check=True)


def netem_clause(profile: Profile) -> str:
    parts: List[str] = [f"delay {profile.latency_ms}ms {profile.jitter_ms}ms distribution normal"]
    if profile.loss_pct > 0:
        parts.append(f"loss {profile.loss_pct:.3f}%")
    if profile.reorder_pct > 0:
        if profile.reorder_corr_pct > 0:
            parts.append(f"reorder {profile.reorder_pct:.3f}% {profile.reorder_corr_pct:.3f}%")
        else:
            parts.append(f"reorder {profile.reorder_pct:.3f}%")
    if profile.corrupt_pct > 0:
        parts.append(f"corrupt {profile.corrupt_pct:.3f}%")
    if profile.duplicate_pct > 0:
        parts.append(f"duplicate {profile.duplicate_pct:.3f}%")
    return " ".join(parts)


def apply_profile(args: argparse.Namespace) -> None:
    profile = PROFILES[args.profile]
    clause = netem_clause(profile)
    script = f"""
set -e
sudo tc qdisc del dev {args.iface} root 2>/dev/null || true
sudo tc qdisc add dev {args.iface} root handle 1: htb default 10
sudo tc class add dev {args.iface} parent 1: classid 1:10 htb rate {profile.rate_mbit}mbit ceil {profile.ceil_mbit}mbit
sudo tc qdisc add dev {args.iface} parent 1:10 handle 10: netem {clause}
""".strip()
    run_ssh(args.user, args.host, script, args.dry_run)


def set_stack_mode(args: argparse.Namespace) -> None:
    if args.mode == "dual_stack":
        rules = "sudo nft delete table inet vpn_harness 2>/dev/null || true"
    elif args.mode == "ipv4_only":
        rules = """
sudo nft add table inet vpn_harness
sudo nft 'add chain inet vpn_harness output { type filter hook output priority 0; policy accept; }' 2>/dev/null || true
sudo nft flush chain inet vpn_harness output
SSH_CLIENT_IP="$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')"
if [ -n "$SSH_CLIENT_IP" ]; then
  if printf '%s' "$SSH_CLIENT_IP" | grep -q ':'; then
    sudo nft add rule inet vpn_harness output ip6 daddr "$SSH_CLIENT_IP" accept
  fi
fi
sudo nft add rule inet vpn_harness output ip6 daddr ::/0 drop
""".strip()
    else:  # ipv6_only
        rules = """
sudo nft add table inet vpn_harness
sudo nft 'add chain inet vpn_harness output { type filter hook output priority 0; policy accept; }' 2>/dev/null || true
sudo nft flush chain inet vpn_harness output
SSH_CLIENT_IP="$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')"
if [ -n "$SSH_CLIENT_IP" ]; then
  if ! printf '%s' "$SSH_CLIENT_IP" | grep -q ':'; then
    sudo nft add rule inet vpn_harness output ip daddr "$SSH_CLIENT_IP" accept
  fi
fi
sudo nft add rule inet vpn_harness output ip daddr 0.0.0.0/0 drop
""".strip()

    script = f"""
set -e
{rules}
""".strip()
    run_ssh(args.user, args.host, script, args.dry_run)


def clear(args: argparse.Namespace) -> None:
    script = f"""
set -e
sudo tc qdisc del dev {args.iface} root 2>/dev/null || true
sudo nft delete table inet vpn_harness 2>/dev/null || true
""".strip()
    run_ssh(args.user, args.host, script, args.dry_run)


def main() -> int:
    args = parse_args()
    if args.cmd == "apply":
        apply_profile(args)
    elif args.cmd == "stack":
        set_stack_mode(args)
    elif args.cmd == "clear":
        clear(args)
    else:
        raise RuntimeError(f"unsupported command: {args.cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
