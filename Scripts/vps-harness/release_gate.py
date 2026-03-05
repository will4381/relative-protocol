#!/usr/bin/env python3
"""Run multi-phase harness gates for rollout readiness."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]

PHASES: Dict[str, Dict[str, str]] = {
    "smoke": {"suite": "smoke"},
    "stress": {"suite": "stress-matrix"},
    "soak30": {"suite": "soak", "soak_duration": "30m"},
    "soak60": {"suite": "soak", "soak_duration": "60m"},
    "soak120": {"suite": "soak", "soak_duration": "120m"},
}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run staged release gate suites for VPN harness")
    parser.add_argument("--vps-host", required=True)
    parser.add_argument("--vps-host-v6", default="")
    parser.add_argument("--vps-user", default="root")
    parser.add_argument("--vps-interface", default="eth0")
    parser.add_argument("--history-file", default="")
    parser.add_argument("--phases", default="smoke,stress,soak30")
    parser.add_argument("--case-seconds", type=int, default=20)
    parser.add_argument("--soak-case-seconds", type=int, default=30)
    parser.add_argument("--socks-port-base", type=int, default=19300)
    parser.add_argument("--control-port-base", type=int, default=19400)
    parser.add_argument("--http-port", type=int, default=7080)
    parser.add_argument("--standalone-enable-metrics", action="store_true")
    parser.add_argument("--standalone-enable-packet-stream", action="store_true")
    parser.add_argument("--standalone-keepalive-interval-seconds", type=int, default=0)
    parser.add_argument("--memory-rss-limit-mb", type=float, default=0.0)
    parser.add_argument("--memory-rss-grace-seconds", type=float, default=3.0)
    parser.add_argument("--memory-sample-interval-ms", type=int, default=500)
    parser.add_argument("--trace-profile-file", default="")
    parser.add_argument("--trace-name", default="")
    parser.add_argument("--handover-script", default="none")
    parser.add_argument("--strict-v6", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-services", action="store_true")
    parser.add_argument("--allow-missing-deps", action="store_true")
    parser.add_argument("--disable-telemetry", action="store_true")
    parser.add_argument("--disable-realistic-traffic", action="store_true")
    parser.add_argument("--disable-fuzz-lane", action="store_true")
    parser.add_argument("--disable-lifecycle-churn", action="store_true")
    parser.add_argument("--lifecycle-restarts", action="store_true")
    parser.add_argument("--lifecycle-interval-ms", type=int, default=1800)
    parser.add_argument("--lifecycle-max-failures", type=int, default=1)
    parser.add_argument("--lifecycle-restart-every", type=int, default=8)
    return parser.parse_args(argv)


def parse_phase_names(raw: str) -> List[str]:
    names = [item.strip() for item in raw.split(",") if item.strip()]
    if not names:
        raise RuntimeError("no phases selected")
    unknown = [name for name in names if name not in PHASES]
    if unknown:
        raise RuntimeError(f"unknown phases: {','.join(sorted(unknown))}")
    return names


def build_phase_command(args: argparse.Namespace, phase_name: str, index: int) -> List[str]:
    phase = PHASES[phase_name]
    cmd = [
        sys.executable,
        str(REPO_ROOT / "Scripts" / "vps-harness" / "harness.py"),
        "--suite",
        phase["suite"],
        "--vps-host",
        args.vps_host,
        "--vps-host-v6",
        args.vps_host_v6,
        "--vps-user",
        args.vps_user,
        "--vps-interface",
        args.vps_interface,
        "--socks-port",
        str(args.socks_port_base + index),
        "--control-port",
        str(args.control_port_base + index),
        "--http-port",
        str(args.http_port),
    ]
    if args.history_file:
        cmd.extend(["--history-file", args.history_file])
    if args.trace_profile_file:
        cmd.extend(["--trace-profile-file", args.trace_profile_file])
    if args.trace_name:
        cmd.extend(["--trace-name", args.trace_name])
    if args.handover_script and args.handover_script != "none":
        cmd.extend(["--handover-script", args.handover_script])
    if args.strict_v6:
        cmd.append("--require-ipv6-data-plane")
    if args.standalone_enable_metrics:
        cmd.append("--standalone-enable-metrics")
    if args.standalone_enable_packet_stream:
        cmd.append("--standalone-enable-packet-stream")
    if args.standalone_keepalive_interval_seconds > 0:
        cmd.extend(
            [
                "--standalone-keepalive-interval-seconds",
                str(args.standalone_keepalive_interval_seconds),
            ]
        )
    if args.memory_rss_limit_mb > 0:
        cmd.extend(["--memory-rss-limit-mb", str(args.memory_rss_limit_mb)])
        cmd.extend(["--memory-rss-grace-seconds", str(args.memory_rss_grace_seconds)])
        cmd.extend(["--memory-sample-interval-ms", str(args.memory_sample_interval_ms)])
    if args.skip_build:
        cmd.append("--skip-build")
    if args.skip_services:
        cmd.append("--skip-services")
    if args.allow_missing_deps:
        cmd.append("--allow-missing-deps")
    if not args.disable_telemetry:
        cmd.append("--enable-telemetry")
    if not args.disable_realistic_traffic:
        cmd.append("--enable-realistic-traffic")
    if not args.disable_fuzz_lane:
        cmd.append("--enable-fuzz-lane")
    if not args.disable_lifecycle_churn:
        cmd.append("--enable-lifecycle-churn")
        if args.lifecycle_restarts:
            cmd.append("--lifecycle-restarts")
        cmd.extend(["--lifecycle-interval-ms", str(args.lifecycle_interval_ms)])
        cmd.extend(["--lifecycle-max-failures", str(args.lifecycle_max_failures)])
        cmd.extend(["--lifecycle-restart-every", str(args.lifecycle_restart_every)])
    if phase["suite"] == "soak":
        cmd.extend(["--soak-duration", phase["soak_duration"]])
        cmd.extend(["--case-seconds", str(args.soak_case_seconds)])
    else:
        cmd.extend(["--case-seconds", str(args.case_seconds)])
    return cmd


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    phase_names = parse_phase_names(args.phases)
    results: List[Dict[str, object]] = []

    print(f"[RELEASE-GATE] phases={','.join(phase_names)}", flush=True)
    for index, phase_name in enumerate(phase_names):
        cmd = build_phase_command(args, phase_name, index)
        started = time.monotonic()
        print(f"[RELEASE-GATE] start phase={phase_name}", flush=True)
        print(f"[RELEASE-GATE] cmd={' '.join(cmd)}", flush=True)
        proc = subprocess.run(cmd, cwd=REPO_ROOT)
        duration_s = round(time.monotonic() - started, 1)
        passed = proc.returncode == 0
        result = {
            "phase": phase_name,
            "returncode": proc.returncode,
            "duration_s": duration_s,
            "pass": passed,
        }
        results.append(result)
        print(
            f"[RELEASE-GATE] done phase={phase_name} pass={passed} returncode={proc.returncode} duration_s={duration_s}",
            flush=True,
        )
        if not passed:
            break

    failures = [item for item in results if not item["pass"]]
    summary = {
        "pass": len(failures) == 0 and len(results) == len(phase_names),
        "phase_count": len(results),
        "requested_phase_count": len(phase_names),
        "results": results,
    }
    print("[RELEASE-GATE] summary=" + json.dumps(summary, sort_keys=True), flush=True)
    return 0 if summary["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
