#!/usr/bin/env python3
"""Collect droplet telemetry snapshots and optional eBPF traces."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from typing import Dict, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect droplet telemetry for VPN harness cases")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--iface", default="eth0")  # compatibility with harness runner
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tool", choices=["auto", "proc", "bpftrace", "bcc"], default="auto")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("action", choices=["start", "stop"])
    return parser.parse_args()


def run_ssh(target: str, script: str, dry_run: bool, capture: bool = False) -> str:
    if dry_run:
        print(f"[DRY-RUN] ssh {target} <<'SH'\n{script}\nSH")
        return ""
    if capture:
        out = subprocess.check_output(["ssh", target, script], text=True)
        return out
    subprocess.run(["ssh", target, script], check=True)
    return ""


def safe_diff(before: Dict[str, int], after: Dict[str, int], key: str) -> int:
    return int(after.get(key, 0) - before.get(key, 0))


def parse_proc_kv(content: str) -> Dict[str, int]:
    rows = [line.strip() for line in content.splitlines() if line.strip()]
    parsed: Dict[str, int] = {}
    idx = 0
    while idx + 1 < len(rows):
        left = rows[idx].split()
        right = rows[idx + 1].split()
        idx += 2
        if not left or not right or left[0].rstrip(":") != right[0].rstrip(":"):
            continue
        prefix = left[0].rstrip(":")
        for name, value in zip(left[1:], right[1:]):
            try:
                parsed[f"{prefix}.{name}"] = int(value)
            except ValueError:
                continue
    return parsed


def parse_sockstat(content: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        prefix, rest = line.split(":", 1)
        fields = rest.strip().split()
        i = 0
        while i + 1 < len(fields):
            key = fields[i]
            value = fields[i + 1]
            i += 2
            if not value.isdigit():
                continue
            result[f"{prefix}.{key}"] = int(value)
    return result


def sum_log_numbers(content: str) -> int:
    return sum(int(match) for match in re.findall(r"(\d+)", content))


def telemetry_dir(run_id: str) -> str:
    return f"/tmp/vpn_harness_telemetry/{run_id}"


def start(args: argparse.Namespace, target: str) -> None:
    run_dir = telemetry_dir(args.run_id)
    script = f"""
set -e
RUN_DIR="{run_dir}"
mkdir -p "$RUN_DIR"
cat /proc/net/snmp > "$RUN_DIR/before.snmp" 2>/dev/null || true
cat /proc/net/netstat > "$RUN_DIR/before.netstat" 2>/dev/null || true
cat /proc/net/sockstat > "$RUN_DIR/before.sockstat" 2>/dev/null || true
ss -s > "$RUN_DIR/before.ss" 2>/dev/null || true
echo "{args.tool}" > "$RUN_DIR/tool.txt"

if [ "{args.tool}" = "auto" ] || [ "{args.tool}" = "bpftrace" ]; then
  if command -v bpftrace >/dev/null 2>&1; then
    nohup sudo bpftrace -e 'tracepoint:tcp:tcp_retransmit_skb {{ @retrans = count(); }} interval:s:5 {{ print(@retrans); clear(@retrans); }}' \
      > "$RUN_DIR/bpftrace-retrans.log" 2>&1 &
    echo $! > "$RUN_DIR/bpftrace-retrans.pid"

    nohup sudo bpftrace -e 'tracepoint:skb:kfree_skb {{ @drops = count(); }} interval:s:5 {{ print(@drops); clear(@drops); }}' \
      > "$RUN_DIR/bpftrace-drop.log" 2>&1 &
    echo $! > "$RUN_DIR/bpftrace-drop.pid"
  fi
fi

if [ "{args.tool}" = "auto" ] || [ "{args.tool}" = "bcc" ]; then
  if command -v tcpretrans >/dev/null 2>&1; then
    nohup sudo tcpretrans -l > "$RUN_DIR/bcc-tcpretrans.log" 2>&1 &
    echo $! > "$RUN_DIR/bcc-tcpretrans.pid"
  fi
fi
""".strip()
    run_ssh(target, script, args.dry_run, capture=False)
    print(json.dumps({"ok": True, "run_id": args.run_id, "action": "start"}))


def remote_cat(target: str, path: str, dry_run: bool) -> str:
    if dry_run:
        return ""
    try:
        return subprocess.check_output(["ssh", target, f"cat {path} 2>/dev/null || true"], text=True)
    except subprocess.CalledProcessError:
        return ""


def stop(args: argparse.Namespace, target: str) -> None:
    run_dir = telemetry_dir(args.run_id)
    script = f"""
set -e
RUN_DIR="{run_dir}"
for pid_file in "$RUN_DIR/bpftrace-retrans.pid" "$RUN_DIR/bpftrace-drop.pid" "$RUN_DIR/bcc-tcpretrans.pid"; do
  if [ -f "$pid_file" ]; then
    kill "$(cat "$pid_file")" 2>/dev/null || true
    rm -f "$pid_file"
  fi
done
cat /proc/net/snmp > "$RUN_DIR/after.snmp" 2>/dev/null || true
cat /proc/net/netstat > "$RUN_DIR/after.netstat" 2>/dev/null || true
cat /proc/net/sockstat > "$RUN_DIR/after.sockstat" 2>/dev/null || true
ss -s > "$RUN_DIR/after.ss" 2>/dev/null || true
""".strip()
    run_ssh(target, script, args.dry_run, capture=False)

    before_snmp = parse_proc_kv(remote_cat(target, f"{run_dir}/before.snmp", args.dry_run))
    after_snmp = parse_proc_kv(remote_cat(target, f"{run_dir}/after.snmp", args.dry_run))
    before_netstat = parse_proc_kv(remote_cat(target, f"{run_dir}/before.netstat", args.dry_run))
    after_netstat = parse_proc_kv(remote_cat(target, f"{run_dir}/after.netstat", args.dry_run))
    before_sock = parse_sockstat(remote_cat(target, f"{run_dir}/before.sockstat", args.dry_run))
    after_sock = parse_sockstat(remote_cat(target, f"{run_dir}/after.sockstat", args.dry_run))

    bpftrace_retrans = sum_log_numbers(remote_cat(target, f"{run_dir}/bpftrace-retrans.log", args.dry_run))
    bpftrace_drop = sum_log_numbers(remote_cat(target, f"{run_dir}/bpftrace-drop.log", args.dry_run))
    bcc_tcpretrans = sum_log_numbers(remote_cat(target, f"{run_dir}/bcc-tcpretrans.log", args.dry_run))

    summary = {
        "ok": True,
        "run_id": args.run_id,
        "action": "stop",
        "tcp_retrans_segs": safe_diff(before_snmp, after_snmp, "Tcp.RetransSegs"),
        "tcp_out_rsts": safe_diff(before_snmp, after_snmp, "Tcp.OutRsts"),
        "udp_in_errors": safe_diff(before_snmp, after_snmp, "Udp.InErrors"),
        "udp_no_ports": safe_diff(before_snmp, after_snmp, "Udp.NoPorts"),
        "ip_in_discards": safe_diff(before_snmp, after_snmp, "Ip.InDiscards"),
        "tcpext_timeouts": safe_diff(before_netstat, after_netstat, "TcpExt.TCPTimeouts"),
        "tcpext_retrans_fail": safe_diff(before_netstat, after_netstat, "TcpExt.TCPRetransFail"),
        "sock_tcp_inuse_delta": safe_diff(before_sock, after_sock, "TCP.inuse"),
        "sock_tcp_orphan_delta": safe_diff(before_sock, after_sock, "TCP.orphan"),
        "sock_tcp_mem_delta": safe_diff(before_sock, after_sock, "TCP.mem"),
        "bpftrace_retrans_events": bpftrace_retrans,
        "bpftrace_drop_events": bpftrace_drop,
        "bcc_tcpretrans_lines": bcc_tcpretrans,
    }
    print(json.dumps(summary, sort_keys=True))


def main() -> int:
    args = parse_args()
    _ = args.iface
    target = f"{args.user}@{args.host}"
    if args.action == "start":
        start(args, target)
    else:
        stop(args, target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
