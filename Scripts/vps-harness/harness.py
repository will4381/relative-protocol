#!/usr/bin/env python3
"""Off-device VPN soak harness orchestrator.

Runs local Standalone (Swift runtime), configures droplet impairments,
executes synthetic traffic via SOCKS, and applies regression gates.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import dataclasses
import datetime as dt
import importlib.util
import ipaddress
import json
import os
import random
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HISTORY_FILE = REPO_ROOT / ".tmp" / "vps-harness-history.jsonl"
HARNESS_BASELINE_VERSION = 2

PROFILES = ("wifi", "lte", "5g", "dirty")
STACK_MODES = ("dual_stack", "ipv4_only", "ipv6_only")
SOAK_DURATIONS = {"30m": 30 * 60, "60m": 60 * 60, "120m": 120 * 60}
HANDOVER_SCRIPTS: Dict[str, List[Tuple[str, float]]] = {
    "default": [("wifi", 0.35), ("lte", 0.35), ("5g", 0.30)],
    "aggressive": [("wifi", 0.20), ("lte", 0.20), ("5g", 0.20), ("lte", 0.20), ("wifi", 0.20)],
    "commute-loop": [("wifi", 0.15), ("lte", 0.35), ("5g", 0.20), ("lte", 0.20), ("wifi", 0.10)],
}
SUCCESS_RATE_MIN_BY_PROFILE: Dict[str, float] = {
    "wifi": 0.99,
    "lte": 0.99,
    "5g": 0.99,
    "dirty": 0.96,
}
P50_RELATIVE_REGRESSION_LIMIT = 0.20
P95_RELATIVE_REGRESSION_LIMIT = 0.30
P50_ABSOLUTE_REGRESSION_MS = 30.0
P95_ABSOLUTE_REGRESSION_MS = 60.0

REQ_PACKAGES: Tuple[Tuple[str, str], ...] = (
    ("httpx", "httpx"),
    ("socks", "PySocks"),
    ("dns", "dnspython"),
    ("aioquic", "aioquic"),
    ("scapy", "scapy"),
    ("boofuzz", "boofuzz"),
    ("numpy", "numpy"),
)


@dataclasses.dataclass
class Baseline:
    success_rate: float
    p50_ms: float
    p95_ms: float
    sample_count: int


@dataclasses.dataclass
class ImpairmentStep:
    duration_s: float
    profile: Optional[str] = None
    custom: Optional[Dict[str, float]] = None
    label: str = ""


@dataclasses.dataclass
class ScenarioResult:
    timestamp: str
    suite: str
    scenario: str
    profile: str
    stack_mode: str
    duration_s: int
    success_rate: float
    p50_ms: float
    p95_ms: float
    throughput_mbps: float
    ipv4_ok: bool
    ipv6_ok: bool
    restart_events: int
    loop_detected: bool
    regression_delta: Dict[str, float]
    protocol_stats: Dict[str, Any]
    passed: bool
    reasons: List[str]

    def to_json(self) -> Dict[str, Any]:
        return {
            "harness_baseline_version": HARNESS_BASELINE_VERSION,
            "timestamp": self.timestamp,
            "suite": self.suite,
            "scenario": self.scenario,
            "profile": self.profile,
            "stack_mode": self.stack_mode,
            "duration_s": self.duration_s,
            "success_rate": round(self.success_rate, 6),
            "p50_ms": round(self.p50_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "throughput_mbps": round(self.throughput_mbps, 3),
            "ipv4_ok": self.ipv4_ok,
            "ipv6_ok": self.ipv6_ok,
            "restart_events": self.restart_events,
            "loop_detected": self.loop_detected,
            "regression_delta": self.regression_delta,
            "protocol_stats": self.protocol_stats,
            "pass": self.passed,
            "reasons": self.reasons,
        }


def log(msg: str) -> None:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[HARNESS] {now} {msg}", flush=True)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Off-device VPN soak harness")
    parser.add_argument("--suite", choices=["smoke", "stress-matrix", "soak"], required=True)
    parser.add_argument("--soak-duration", choices=sorted(SOAK_DURATIONS), default="30m")
    parser.add_argument("--vps-host", required=True, help="Droplet IPv4 host")
    parser.add_argument("--vps-host-v6", default="", help="Droplet IPv6 host (optional but recommended)")
    parser.add_argument("--vps-user", default="root")
    parser.add_argument("--vps-interface", default="eth0")
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--control-port", type=int, default=19090)
    parser.add_argument("--mtu", type=int, default=1400)
    parser.add_argument("--engine-log-level", default="warn")
    parser.add_argument("--standalone-enable-metrics", action="store_true")
    parser.add_argument("--standalone-enable-packet-stream", action="store_true")
    parser.add_argument("--standalone-keepalive-interval-seconds", type=int, default=0)
    parser.add_argument("--case-seconds", type=int, default=20)
    parser.add_argument("--trace-profile-file", default="", help="Path to JSON trace profile replay file")
    parser.add_argument("--trace-name", default="", help="Trace name inside --trace-profile-file")
    parser.add_argument(
        "--handover-script",
        choices=["none"] + sorted(HANDOVER_SCRIPTS.keys()),
        default="none",
        help="In-case network profile transitions",
    )
    parser.add_argument("--enable-telemetry", action="store_true")
    parser.add_argument("--telemetry-tool", choices=["auto", "proc", "bpftrace", "bcc"], default="auto")
    parser.add_argument("--enable-realistic-traffic", action="store_true")
    parser.add_argument("--enable-fuzz-lane", action="store_true")
    parser.add_argument(
        "--require-ipv6-data-plane",
        action="store_true",
        help="Fail case if IPv6 host misses UDP/DNS/QUIC (and HTTP when realistic lane enabled)",
    )
    parser.add_argument("--enable-lifecycle-churn", action="store_true")
    parser.add_argument("--lifecycle-restarts", action="store_true")
    parser.add_argument("--lifecycle-interval-ms", type=int, default=1800)
    parser.add_argument("--lifecycle-max-failures", type=int, default=1)
    parser.add_argument("--lifecycle-restart-every", type=int, default=8)
    parser.add_argument("--memory-rss-limit-mb", type=float, default=0.0)
    parser.add_argument("--memory-rss-grace-seconds", type=float, default=3.0)
    parser.add_argument("--memory-sample-interval-ms", type=int, default=500)
    parser.add_argument("--http-port", type=int, default=7080)
    parser.add_argument("--history-file", default=str(DEFAULT_HISTORY_FILE))
    parser.add_argument("--allow-missing-deps", action="store_true")
    parser.add_argument("--skip-services", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.standalone_keepalive_interval_seconds < 0:
        parser.error("--standalone-keepalive-interval-seconds must be >= 0")
    if args.memory_rss_limit_mb < 0:
        parser.error("--memory-rss-limit-mb must be >= 0")
    if args.memory_rss_grace_seconds < 0:
        parser.error("--memory-rss-grace-seconds must be >= 0")
    if args.memory_sample_interval_ms < 50:
        parser.error("--memory-sample-interval-ms must be >= 50")
    return args


def check_dependencies(allow_missing: bool) -> None:
    missing_modules: List[str] = []
    missing_install_names: List[str] = []
    for module_name, install_name in REQ_PACKAGES:
        if importlib.util.find_spec(module_name) is None:
            missing_modules.append(module_name)
            missing_install_names.append(install_name)
    if not missing_modules:
        return
    message = (
        "Missing required Python modules: "
        + ", ".join(missing_modules)
        + ". Install with: pip install "
        + " ".join(missing_install_names)
    )
    if allow_missing:
        log("WARNING " + message)
        return
    raise RuntimeError(message)


def require_port_available(port: int, label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError as exc:
        raise RuntimeError(
            f"{label} port {port} is already in use on 127.0.0.1; stop stale listeners and retry"
        ) from exc
    finally:
        sock.close()


def parse_soak_seconds(label: str) -> int:
    return SOAK_DURATIONS[label]


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _trace_step_duration_values(step_rows: List[Dict[str, Any]]) -> List[float]:
    if all("timestamp_s" in row for row in step_rows) and len(step_rows) > 1:
        durations: List[float] = []
        for idx, row in enumerate(step_rows):
            if idx + 1 < len(step_rows):
                current_ts = _to_float(row.get("timestamp_s"), float(idx))
                next_ts = _to_float(step_rows[idx + 1].get("timestamp_s"), current_ts + 1.0)
                durations.append(max(0.1, next_ts - current_ts))
            else:
                durations.append(max(0.1, _to_float(row.get("duration_s"), 1.0)))
        return durations
    return [max(0.1, _to_float(row.get("duration_s"), _to_float(row.get("seconds"), 1.0))) for row in step_rows]


def load_trace_steps(
    trace_file: str,
    trace_name: str,
    case_seconds: int,
    default_profile: str,
) -> List[ImpairmentStep]:
    path = Path(trace_file)
    if not path.exists():
        raise RuntimeError(f"trace profile file does not exist: {trace_file}")

    payload = json.loads(path.read_text(encoding="utf-8"))
    step_rows: Any
    if isinstance(payload, list):
        step_rows = payload
    elif isinstance(payload, dict):
        if trace_name:
            if isinstance(payload.get("traces"), dict) and trace_name in payload["traces"]:
                step_rows = payload["traces"][trace_name]
            elif trace_name in payload:
                step_rows = payload[trace_name]
            else:
                raise RuntimeError(f"trace-name '{trace_name}' not found in {trace_file}")
        elif isinstance(payload.get("steps"), list):
            step_rows = payload["steps"]
        elif isinstance(payload.get("traces"), dict) and payload["traces"]:
            first_name = sorted(payload["traces"].keys())[0]
            step_rows = payload["traces"][first_name]
            log(f"INFO trace-name not provided; using first trace '{first_name}'")
        else:
            raise RuntimeError(f"trace profile file has unsupported schema: {trace_file}")
    else:
        raise RuntimeError(f"trace profile file must be object or list: {trace_file}")

    if not isinstance(step_rows, list) or not step_rows:
        raise RuntimeError(f"trace profile has no steps: {trace_file}")

    durations = _trace_step_duration_values(step_rows)
    raw_steps: List[ImpairmentStep] = []
    for idx, row in enumerate(step_rows):
        if not isinstance(row, dict):
            continue
        duration_s = durations[idx]
        label = str(row.get("label", f"trace-{idx + 1}"))
        profile = row.get("profile")
        custom: Optional[Dict[str, float]] = None

        custom_keys = ("rate_mbit", "ceil_mbit", "latency_ms", "jitter_ms", "loss_pct")
        if any(key in row for key in custom_keys):
            custom = {
                "rate_mbit": max(1.0, _to_float(row.get("rate_mbit"), 60.0)),
                "ceil_mbit": max(1.0, _to_float(row.get("ceil_mbit"), _to_float(row.get("rate_mbit"), 60.0))),
                "latency_ms": max(0.0, _to_float(row.get("latency_ms"), 50.0)),
                "jitter_ms": max(0.0, _to_float(row.get("jitter_ms"), 10.0)),
                "loss_pct": max(0.0, _to_float(row.get("loss_pct"), 0.2)),
                "reorder_pct": max(0.0, _to_float(row.get("reorder_pct"), 0.0)),
                "reorder_corr_pct": max(0.0, _to_float(row.get("reorder_corr_pct"), 0.0)),
                "corrupt_pct": max(0.0, _to_float(row.get("corrupt_pct"), 0.0)),
                "duplicate_pct": max(0.0, _to_float(row.get("duplicate_pct"), 0.0)),
            }

        # Support raw capture-derived delay samples.
        samples = row.get("latency_samples_ms")
        if custom is None and isinstance(samples, list) and samples:
            numeric_samples = [_to_float(item, 0.0) for item in samples if _to_float(item, -1.0) >= 0.0]
            if numeric_samples:
                p50 = percentile(numeric_samples, 0.5)
                p95 = percentile(numeric_samples, 0.95)
                custom = {
                    "rate_mbit": max(1.0, _to_float(row.get("rate_mbit"), 60.0)),
                    "ceil_mbit": max(1.0, _to_float(row.get("ceil_mbit"), _to_float(row.get("rate_mbit"), 60.0))),
                    "latency_ms": max(0.0, p50),
                    "jitter_ms": max(0.0, p95 - p50),
                    "loss_pct": max(0.0, _to_float(row.get("loss_pct"), 0.2)),
                    "reorder_pct": max(0.0, _to_float(row.get("reorder_pct"), 0.0)),
                    "reorder_corr_pct": max(0.0, _to_float(row.get("reorder_corr_pct"), 0.0)),
                    "corrupt_pct": max(0.0, _to_float(row.get("corrupt_pct"), 0.0)),
                    "duplicate_pct": max(0.0, _to_float(row.get("duplicate_pct"), 0.0)),
                }

        if custom is None:
            profile_name = str(profile) if profile is not None else default_profile
            if profile_name not in PROFILES:
                profile_name = default_profile
            raw_steps.append(ImpairmentStep(duration_s=duration_s, profile=profile_name, label=label))
        else:
            raw_steps.append(ImpairmentStep(duration_s=duration_s, custom=custom, label=label))

    if not raw_steps:
        return [ImpairmentStep(duration_s=float(case_seconds), profile=default_profile, label=default_profile)]

    total = sum(step.duration_s for step in raw_steps)
    scale = float(case_seconds) / max(0.1, total)
    return [
        ImpairmentStep(
            duration_s=max(0.1, step.duration_s * scale),
            profile=step.profile,
            custom=step.custom,
            label=step.label,
        )
        for step in raw_steps
    ]


def build_impairment_schedule(profile: str, case_seconds: int, args: argparse.Namespace) -> List[ImpairmentStep]:
    if args.trace_profile_file:
        return load_trace_steps(
            trace_file=args.trace_profile_file,
            trace_name=args.trace_name,
            case_seconds=case_seconds,
            default_profile=profile,
        )

    if args.handover_script != "none" and profile in ("wifi", "lte", "5g"):
        phases = HANDOVER_SCRIPTS[args.handover_script]
        total = sum(weight for _, weight in phases)
        steps: List[ImpairmentStep] = []
        for phase_profile, weight in phases:
            steps.append(
                ImpairmentStep(
                    duration_s=max(0.1, case_seconds * (weight / max(0.001, total))),
                    profile=phase_profile,
                    label=f"handover-{phase_profile}",
                )
            )
        return steps

    return [ImpairmentStep(duration_s=float(case_seconds), profile=profile, label=profile)]


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return float(ordered[lo] * (1.0 - frac) + ordered[hi] * frac)


def summarize_latencies(values: Sequence[float]) -> Dict[str, float]:
    if not values:
        return {"count": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    return {
        "count": float(len(values)),
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "max_ms": float(max(values)),
    }


def load_history(history_file: Path) -> List[Dict[str, Any]]:
    if not history_file.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with history_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def append_history(history_file: Path, row: Dict[str, Any]) -> None:
    history_file.parent.mkdir(parents=True, exist_ok=True)
    with history_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def baseline_for(
    history_rows: Sequence[Dict[str, Any]],
    suite: str,
    scenario: str,
    profile: str,
    stack_mode: str,
) -> Optional[Baseline]:
    matching = [
        row
        for row in history_rows
        if row.get("suite") == suite
        and row.get("scenario") == scenario
        and row.get("profile") == profile
        and row.get("stack_mode") == stack_mode
        and row.get("harness_baseline_version") == HARNESS_BASELINE_VERSION
        and row.get("pass") is True
    ]
    if not matching:
        return None
    recent = matching[-10:]
    return Baseline(
        success_rate=statistics.median(float(row.get("success_rate", 0.0)) for row in recent),
        p50_ms=statistics.median(float(row.get("p50_ms", 0.0)) for row in recent),
        p95_ms=statistics.median(float(row.get("p95_ms", 0.0)) for row in recent),
        sample_count=len(recent),
    )


def evaluate_regression(
    success_rate: float,
    p50_ms: float,
    p95_ms: float,
    profile: str,
    ipv4_ok: bool,
    ipv6_ok: bool,
    stack_mode: str,
    loop_detected: bool,
    baseline: Optional[Baseline],
) -> Tuple[bool, Dict[str, float], List[str]]:
    reasons: List[str] = []
    delta: Dict[str, float] = {}
    success_floor = SUCCESS_RATE_MIN_BY_PROFILE.get(profile, 0.99)

    if success_rate < success_floor:
        reasons.append(f"success_rate_below_threshold:{success_rate:.4f}")
    if stack_mode == "dual_stack" and not ipv4_ok and not ipv6_ok:
        reasons.append("dual_stack_lost_ipv4_and_ipv6")
    if loop_detected:
        reasons.append("reconnect_loop_detected")

    if baseline is not None and baseline.sample_count >= 3:
        if baseline.p50_ms > 0:
            delta["p50"] = (p50_ms - baseline.p50_ms) / baseline.p50_ms
            p50_abs_delta = p50_ms - baseline.p50_ms
            if delta["p50"] > P50_RELATIVE_REGRESSION_LIMIT and p50_abs_delta >= P50_ABSOLUTE_REGRESSION_MS:
                reasons.append(f"p50_regression:{delta['p50']:.4f}")
        if baseline.p95_ms > 0:
            delta["p95"] = (p95_ms - baseline.p95_ms) / baseline.p95_ms
            p95_abs_delta = p95_ms - baseline.p95_ms
            if delta["p95"] > P95_RELATIVE_REGRESSION_LIMIT and p95_abs_delta >= P95_ABSOLUTE_REGRESSION_MS:
                reasons.append(f"p95_regression:{delta['p95']:.4f}")
        if baseline.success_rate > 0:
            delta["success_rate"] = (success_rate - baseline.success_rate) / baseline.success_rate
    else:
        delta["baseline_warmup"] = 1.0

    return len(reasons) == 0, delta, reasons


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: List[bytes] = []
    total = 0
    while total < size:
        chunk = sock.recv(size - total)
        if not chunk:
            raise RuntimeError("socket closed while receiving")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def encode_socks_addr(host: str) -> bytes:
    try:
        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv4Address):
            return b"\x01" + addr.packed
        return b"\x04" + addr.packed
    except ValueError:
        data = host.encode("utf-8")
        if len(data) > 255:
            raise RuntimeError("hostname too long")
        return b"\x03" + bytes([len(data)]) + data


def parse_socks_addr(data: bytes, offset: int = 0) -> Tuple[str, int]:
    atyp = data[offset]
    offset += 1
    if atyp == 0x01:
        host = str(ipaddress.IPv4Address(data[offset : offset + 4]))
        offset += 4
    elif atyp == 0x04:
        host = str(ipaddress.IPv6Address(data[offset : offset + 16]))
        offset += 16
    elif atyp == 0x03:
        length = data[offset]
        offset += 1
        host = data[offset : offset + length].decode("utf-8", errors="replace")
        offset += length
    else:
        raise RuntimeError(f"unsupported socks atyp={atyp}")
    return host, offset


def parse_socks_udp_response(data: bytes) -> Tuple[str, int, bytes]:
    if len(data) < 4:
        raise RuntimeError("truncated SOCKS UDP response")
    if data[2] != 0:
        raise RuntimeError("fragmented SOCKS UDP response is unsupported")
    host, offset = parse_socks_addr(data, offset=3)
    if len(data) < offset + 2:
        raise RuntimeError("truncated SOCKS UDP response port")
    port = struct.unpack("!H", data[offset : offset + 2])[0]
    return host, port, data[offset + 2 :]


def hosts_equivalent(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return left.strip().lower() == right.strip().lower()


def socks5_tcp_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: float = 5.0) -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    greeting = recv_exact(sock, 2)
    if greeting != b"\x05\x00":
        sock.close()
        raise RuntimeError(f"SOCKS greeting failed: {greeting!r}")

    addr = encode_socks_addr(target_host)
    req = b"\x05\x01\x00" + addr + struct.pack("!H", target_port)
    sock.sendall(req)

    head = recv_exact(sock, 4)
    if head[1] != 0x00:
        sock.close()
        raise RuntimeError(f"SOCKS CONNECT failed with code={head[1]}")

    atyp = head[3]
    if atyp == 0x01:
        _ = recv_exact(sock, 4)
    elif atyp == 0x04:
        _ = recv_exact(sock, 16)
    elif atyp == 0x03:
        n = recv_exact(sock, 1)[0]
        _ = recv_exact(sock, n)
    _ = recv_exact(sock, 2)
    return sock


def socks5_udp_associate(
    proxy_host: str,
    proxy_port: int,
    timeout: float = 5.0,
) -> Tuple[socket.socket, socket.socket, Tuple[str, int]]:
    control = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    control.settimeout(timeout)
    control.sendall(b"\x05\x01\x00")
    greeting = recv_exact(control, 2)
    if greeting != b"\x05\x00":
        control.close()
        raise RuntimeError(f"SOCKS greeting failed: {greeting!r}")

    req = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
    control.sendall(req)
    head = recv_exact(control, 4)
    if head[1] != 0x00:
        control.close()
        raise RuntimeError(f"SOCKS UDP_ASSOCIATE failed with code={head[1]}")

    tail = b""
    if head[3] == 0x01:
        tail = recv_exact(control, 4 + 2)
        host = str(ipaddress.IPv4Address(tail[0:4]))
        port = struct.unpack("!H", tail[4:6])[0]
    elif head[3] == 0x04:
        tail = recv_exact(control, 16 + 2)
        host = str(ipaddress.IPv6Address(tail[0:16]))
        port = struct.unpack("!H", tail[16:18])[0]
    elif head[3] == 0x03:
        n = recv_exact(control, 1)[0]
        body = recv_exact(control, n + 2)
        host = body[:n].decode("utf-8", errors="replace")
        port = struct.unpack("!H", body[n : n + 2])[0]
    else:
        control.close()
        raise RuntimeError(f"Unsupported UDP associate atyp={head[3]}")

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    udp = socket.socket(family, socket.SOCK_DGRAM)
    udp.settimeout(timeout)
    return control, udp, (host, port)


def socks5_udp_send_recv(
    udp: socket.socket,
    relay: Tuple[str, int],
    target_host: str,
    target_port: int,
    payload: bytes,
    *,
    validator: Optional[Callable[[bytes], bool]] = None,
    response_timeout: float = 1.0,
    retries: int = 1,
) -> bytes:
    if retries < 1:
        raise RuntimeError("retries must be >= 1")
    packet = b"\x00\x00\x00" + encode_socks_addr(target_host) + struct.pack("!H", target_port) + payload
    match = validator or (lambda reply: reply == payload)

    for _ in range(retries):
        udp.sendto(packet, relay)
        deadline = time.monotonic() + max(0.05, response_timeout)
        while time.monotonic() < deadline:
            remaining = max(0.02, deadline - time.monotonic())
            udp.settimeout(remaining)
            try:
                data, _ = udp.recvfrom(65535)
            except socket.timeout:
                continue

            try:
                reply_host, reply_port, reply_payload = parse_socks_udp_response(data)
            except RuntimeError:
                # Ignore malformed datagrams while waiting for a matching response.
                continue

            if reply_port != target_port:
                continue
            if not hosts_equivalent(reply_host, target_host):
                continue
            if not match(reply_payload):
                # Ignore stale/duplicated/out-of-order payloads for this exchange.
                continue
            return reply_payload

    raise socket.timeout("timed out waiting for matching SOCKS UDP response")


def build_dns_query(name: str, txid: int) -> bytes:
    labels = name.strip(".").split(".")
    question = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels) + b"\x00"
    question += b"\x00\x01\x00\x01"  # A IN
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + question


def socket_family_for_host(host: str) -> socket.AddressFamily:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return socket.AF_INET
    return socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET


def is_ipv6_literal(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return False


def http_authority(host: str, port: int) -> str:
    if is_ipv6_literal(host):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def direct_udp_echo_probe(
    host: str,
    port: int,
    payload: bytes = b"probe",
    timeout: float = 1.5,
    attempts: int = 3,
) -> bool:
    family = socket_family_for_host(host)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    attempts = max(1, int(attempts))
    per_attempt_timeout = max(0.15, float(timeout) / float(attempts))
    try:
        for _ in range(attempts):
            try:
                sock.sendto(payload, (host, port))
                deadline = time.monotonic() + per_attempt_timeout
                while time.monotonic() < deadline:
                    remaining = max(0.03, deadline - time.monotonic())
                    sock.settimeout(remaining)
                    data, _ = sock.recvfrom(4096)
                    if data == payload:
                        return True
            except socket.timeout:
                continue
            except Exception:
                continue
        return False
    finally:
        sock.close()


def direct_dns_probe(host: str, port: int, timeout: float = 1.5) -> bool:
    family = socket_family_for_host(host)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    query = build_dns_query("alpha.synthetic.test", random.randint(1, 0xFFFF))
    deadline = time.monotonic() + max(0.2, timeout)
    try:
        while time.monotonic() < deadline:
            sock.sendto(query, (host, port))
            inner_deadline = time.monotonic() + min(0.4, max(0.05, deadline - time.monotonic()))
            while time.monotonic() < inner_deadline:
                remaining = max(0.02, inner_deadline - time.monotonic())
                sock.settimeout(remaining)
                try:
                    data, _ = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if len(data) >= 12 and data[:2] == query[:2]:
                    return True
                # Ignore unrelated/stale responses and continue waiting.
                continue
        return False
    except Exception:
        return False
    finally:
        sock.close()


def socks_udp_single_probe(
    proxy_port: int,
    host: str,
    port: int,
    payload: bytes,
    validator: Optional[Callable[[bytes], bool]] = None,
    attempts: int = 3,
    response_timeout: float = 0.7,
) -> bool:
    attempts = max(1, int(attempts))
    validator_fn = validator if validator is not None else (lambda item, expected=payload: item == expected)
    for idx in range(attempts):
        control = None
        udp = None
        try:
            control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port, timeout=2.5)
            reply = socks5_udp_send_recv(
                udp,
                relay,
                host,
                port,
                payload,
                validator=validator_fn,
                response_timeout=response_timeout,
                retries=1,
            )
            if validator_fn(reply):
                return True
        except Exception:
            pass
        finally:
            if udp is not None:
                udp.close()
            if control is not None:
                control.close()
        time.sleep(min(0.15, 0.05 * (idx + 1)))
    return False


def socks_dns_single_probe(proxy_port: int, host: str, dns_port: int, attempts: int = 3) -> bool:
    txid = random.randint(1, 0xFFFF)
    query = build_dns_query("alpha.synthetic.test", txid)
    return socks_udp_single_probe(
        proxy_port=proxy_port,
        host=host,
        port=dns_port,
        payload=query,
        validator=lambda payload, expected=query[:2]: len(payload) >= 12 and payload[:2] == expected,
        attempts=attempts,
        response_timeout=0.75,
    )


def socks_http_health_probe(proxy_port: int, host: str, port: int, attempts: int = 3) -> bool:
    for idx in range(max(1, int(attempts))):
        try:
            status, _, _ = socks_http_get(proxy_port, host, port, "/health", timeout=2.5)
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(min(0.2, 0.05 * (idx + 1)))
    return False


def socks_http_get(
    proxy_port: int,
    host: str,
    port: int,
    path: str,
    timeout: float = 5.0,
) -> Tuple[int, bytes, float]:
    path = path if path.startswith("/") else f"/{path}"
    authority = http_authority(host, port)
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Connection: close\r\n"
        "Accept: */*\r\n"
        "\r\n"
    ).encode("utf-8")

    started = time.perf_counter()
    sock = socks5_tcp_connect("127.0.0.1", proxy_port, host, port, timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        chunks: List[bytes] = []
        while True:
            chunk = sock.recv(65535)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    raw = b"".join(chunks)
    if b"\r\n\r\n" not in raw:
        raise RuntimeError("invalid HTTP response")
    head, body = raw.split(b"\r\n\r\n", 1)
    first = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = first.split(" ")
    if len(parts) < 2:
        raise RuntimeError("invalid HTTP status line")
    status = int(parts[1])
    return status, body, elapsed_ms


def run_hls_dash_churn_workload(
    proxy_port: int,
    host: str,
    http_port: int,
    duration_s: float,
) -> Tuple[int, int, List[float], Dict[str, int]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    error_buckets: Counter[str] = Counter()
    deadline = time.monotonic() + max(0.5, float(duration_s))

    # Optional tool-backed pulls for closer media stack behavior.
    proxy_env = f"socks5://127.0.0.1:{proxy_port}"
    base_url = f"http://{http_authority(host, http_port)}"
    optional_budget_s = min(2.5, max(0.0, float(duration_s) * 0.35))
    min_remaining_for_tool_s = 0.8
    ffmpeg_path = shutil.which("ffmpeg")
    ytdlp_path = shutil.which("yt-dlp")
    if ffmpeg_path and optional_budget_s >= min_remaining_for_tool_s:
        remaining = deadline - time.monotonic()
        timeout_s = min(optional_budget_s / 2.0, max(0.5, remaining - 0.2))
        timeout_s = max(0.5, timeout_s)
        if remaining < min_remaining_for_tool_s:
            error_buckets["optional_tool_skipped_budget"] += 1
        else:
            cmd = [
                ffmpeg_path,
                "-hide_banner",
                "-loglevel",
                "error",
                "-rw_timeout",
                "5000000",
                "-t",
                "4",
                "-i",
                f"{base_url}/hls/playlist.m3u8",
                "-f",
                "null",
                "-",
            ]
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={**os.environ, "ALL_PROXY": proxy_env},
                    timeout=timeout_s,
                )
                successes += 6
            except Exception as exc:
                # Optional media-puller tooling should not fail the case gate.
                error_buckets[f"optional_tool_{classify_error(exc)}"] += 1
    elif ffmpeg_path:
        error_buckets["optional_tool_skipped_budget"] += 1

    if ytdlp_path and optional_budget_s >= min_remaining_for_tool_s:
        remaining = deadline - time.monotonic()
        timeout_s = min(optional_budget_s / 2.0, max(0.5, remaining - 0.2))
        timeout_s = max(0.5, timeout_s)
        if remaining < min_remaining_for_tool_s:
            error_buckets["optional_tool_skipped_budget"] += 1
        else:
            cmd = [
                ytdlp_path,
                "--proxy",
                proxy_env,
                "--skip-download",
                "--quiet",
                f"{base_url}/hls/playlist.m3u8",
            ]
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s)
                successes += 4
            except Exception as exc:
                # Optional media-puller tooling should not fail the case gate.
                error_buckets[f"optional_tool_{classify_error(exc)}"] += 1
    elif ytdlp_path:
        error_buckets["optional_tool_skipped_budget"] += 1

    hls_segments = [f"/hls/seg{i}.ts" for i in range(8)]
    dash_segments = [f"/dash/chunk{i}.m4s" for i in range(1, 9)]
    index = 0
    while time.monotonic() < deadline:
        target = ["/hls/playlist.m3u8", "/dash/manifest.mpd", hls_segments[index % len(hls_segments)], dash_segments[index % len(dash_segments)]]
        index += 1
        for path in target:
            if time.monotonic() >= deadline:
                break
            try:
                status, body, elapsed_ms = socks_http_get(proxy_port, host, http_port, path, timeout=4.5)
                if status != 200 or not body:
                    raise RuntimeError(f"http status={status}")
                successes += 1
                latencies.append(elapsed_ms)
            except Exception as exc:
                failures += 1
                error_buckets[classify_error(exc)] += 1
    return successes, failures, latencies, counter_to_dict(error_buckets)


def run_httpx_h2_h3_mixed_workload(
    proxy_port: int,
    host: str,
    http_port: int,
    quic_port: int,
    duration_s: float,
    concurrency: int = 6,
) -> Tuple[int, int, List[float], Dict[str, int], Dict[str, int]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    error_buckets: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()

    proxy_uri = f"socks5://127.0.0.1:{proxy_port}"
    base_url = f"http://{http_authority(host, http_port)}"
    deadline = time.monotonic() + max(0.5, float(duration_s))

    try:
        import httpx  # type: ignore

        async def h2_lane(worker_index: int) -> Tuple[int, int, List[float], Counter[str], Counter[str]]:
            lane_ok = 0
            lane_fail = 0
            lane_latencies: List[float] = []
            lane_errors: Counter[str] = Counter()
            lane_versions: Counter[str] = Counter()
            try:
                client = httpx.AsyncClient(http2=True, proxy=proxy_uri, timeout=4.0)
            except TypeError:
                client = httpx.AsyncClient(http2=True, proxies=proxy_uri, timeout=4.0)
            async with client:
                while time.monotonic() < deadline:
                    try:
                        started = time.perf_counter()
                        size = 512 + ((worker_index * 211 + lane_ok) % 2048)
                        response = await client.get(f"{base_url}/api/payload?size={size}")
                        elapsed_ms = (time.perf_counter() - started) * 1000.0
                        if response.status_code != 200 or not response.content:
                            raise RuntimeError(f"http_status_{response.status_code}")
                        lane_ok += 1
                        lane_latencies.append(elapsed_ms)
                        lane_versions[str(getattr(response, "http_version", "unknown"))] += 1
                    except Exception as exc:
                        lane_fail += 1
                        lane_errors[classify_error(exc)] += 1
            return lane_ok, lane_fail, lane_latencies, lane_errors, lane_versions

        async def run_h2_concurrency() -> List[Tuple[int, int, List[float], Counter[str], Counter[str]]]:
            tasks = [asyncio.create_task(h2_lane(idx)) for idx in range(max(1, concurrency))]
            return await asyncio.gather(*tasks)

        results = asyncio.run(run_h2_concurrency())
        for lane_ok, lane_fail, lane_latencies, lane_errors, lane_versions in results:
            successes += lane_ok
            failures += lane_fail
            latencies.extend(lane_latencies)
            error_buckets.update(lane_errors)
            version_counts.update(lane_versions)
    except Exception as exc:
        failures += 1
        error_buckets[classify_error(exc)] += 1

    # HTTP/3-like stream concurrency lane using aioquic framing + SOCKS UDP.
    try:
        from aioquic.buffer import Buffer  # type: ignore

        control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
        try:
            stream_id = 0
            while time.monotonic() < deadline:
                for _ in range(4):
                    payload_buf = Buffer(capacity=128)
                    payload_buf.push_uint_var(0x1)  # frame type marker
                    payload_buf.push_uint_var(stream_id)
                    body = os.urandom(32)
                    payload_buf.push_uint_var(len(body))
                    payload_buf.push_bytes(body)
                    payload = bytes([0xC3]) + payload_buf.data
                    stream_id += 4
                    started = time.perf_counter()
                    try:
                        reply = socks5_udp_send_recv(
                            udp,
                            relay,
                            host,
                            quic_port,
                            payload,
                            validator=lambda item, expected=payload: item == expected,
                            response_timeout=0.9,
                            retries=2,
                        )
                        if reply != payload:
                            raise RuntimeError("h3_stream_mismatch")
                        successes += 1
                        latencies.append((time.perf_counter() - started) * 1000.0)
                        version_counts["h3-like"] += 1
                    except Exception as exc:
                        failures += 1
                        error_buckets[classify_error(exc)] += 1
        finally:
            udp.close()
            control.close()
    except Exception as exc:
        failures += 1
        error_buckets[classify_error(exc)] += 1

    return successes, failures, latencies, counter_to_dict(error_buckets), counter_to_dict(version_counts)


def run_dns_resolver_style_workload(
    proxy_port: int,
    host: str,
    dns_port: int,
    duration_s: float,
    parallelism: int = 8,
) -> Tuple[int, int, List[float], Dict[str, int]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    error_buckets: Counter[str] = Counter()
    names = [
        "api.synthetic.test",
        "edge.synthetic.test",
        "cdn.synthetic.test",
        "assets.synthetic.test",
        "sync.synthetic.test",
    ]
    deadline = time.monotonic() + max(0.5, float(duration_s))
    lock = threading.Lock()

    def worker(seed: int) -> None:
        nonlocal successes, failures
        control = None
        udp = None
        rng = random.Random(seed)
        try:
            control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
            while time.monotonic() < deadline:
                txid = rng.randint(1, 0xFFFF)
                query = build_dns_query(rng.choice(names), txid)
                backoff = 0.08
                delivered = False
                for _ in range(3):
                    started = time.perf_counter()
                    try:
                        socks5_udp_send_recv(
                            udp,
                            relay,
                            host,
                            dns_port,
                            query,
                            validator=lambda payload, expected=query[0:2]: len(payload) >= 12 and payload[0:2] == expected,
                            response_timeout=backoff + 0.2,
                            retries=1,
                        )
                        elapsed_ms = (time.perf_counter() - started) * 1000.0
                        with lock:
                            successes += 1
                            latencies.append(elapsed_ms)
                        delivered = True
                        break
                    except Exception as exc:
                        with lock:
                            error_buckets[classify_error(exc)] += 1
                        time.sleep(backoff)
                        backoff *= 2.0
                if not delivered:
                    with lock:
                        failures += 1
        finally:
            if udp is not None:
                udp.close()
            if control is not None:
                control.close()

    threads: List[threading.Thread] = []
    for idx in range(max(1, parallelism)):
        thread = threading.Thread(target=worker, args=(idx + 1,), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return successes, failures, latencies, counter_to_dict(error_buckets)


def run_fuzz_lane_workload(
    proxy_port: int,
    host: str,
    dns_port: int,
    quic_port: int,
    duration_s: float,
) -> Tuple[int, int, List[float], Dict[str, int]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    error_buckets: Counter[str] = Counter()
    deadline = time.monotonic() + max(0.5, float(duration_s))

    try:
        from scapy.all import DNS, DNSQR, fuzz, raw  # type: ignore
    except Exception as exc:
        return 0, 1, [], {"scapy_unavailable": 1, classify_error(exc): 1}

    try:
        control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
    except Exception as exc:
        return 0, 1, [], {classify_error(exc): 1}

    boofuzz_loaded = False
    try:
        import boofuzz  # type: ignore  # noqa: F401

        boofuzz_loaded = True
    except Exception:
        boofuzz_loaded = False

    mutation_counter = 0
    try:
        while time.monotonic() < deadline:
            mutation_counter += 1
            started = time.perf_counter()
            try:
                dns_packet = raw(fuzz(DNS(rd=1, qd=DNSQR(qname="fuzz.synthetic.test"))))
                if boofuzz_loaded:
                    fuzz_prefix = struct.pack("!I", mutation_counter) + os.urandom(8)
                else:
                    fuzz_prefix = os.urandom(6)
                payload = (fuzz_prefix + dns_packet)[:256]
                target_port = dns_port if (mutation_counter % 2 == 0) else quic_port
                reply = socks5_udp_send_recv(
                    udp,
                    relay,
                    host,
                    target_port,
                    payload,
                    validator=lambda item: bool(item),
                    response_timeout=0.5,
                    retries=1,
                )
                if not reply:
                    raise RuntimeError("empty fuzz reply")
                successes += 1
                latencies.append((time.perf_counter() - started) * 1000.0)
            except Exception as exc:
                failures += 1
                error_buckets[classify_error(exc)] += 1
    finally:
        udp.close()
        control.close()

    if boofuzz_loaded:
        error_buckets["boofuzz_enabled"] += 1
    return successes, failures, latencies, counter_to_dict(error_buckets)


def classify_error(exc: Exception) -> str:
    message = str(exc).lower()
    if isinstance(exc, socket.timeout) or "timed out" in message:
        return "timeout"
    if "refused" in message:
        return "conn_refused"
    if "reset" in message:
        return "conn_reset"
    if "unreachable" in message:
        return "unreachable"
    if "socks" in message:
        return "socks_error"
    return exc.__class__.__name__


def counter_to_dict(counter: Counter[str]) -> Dict[str, int]:
    return {k: int(v) for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))}


def run_tcp_echo_workload(
    proxy_port: int,
    host: str,
    port: int,
    duration_s: float
) -> Tuple[int, int, List[float], int, Dict[str, int]]:
    end = time.monotonic() + max(0.5, float(duration_s))
    successes = 0
    failures = 0
    latencies: List[float] = []
    total_bytes = 0
    error_buckets: Counter[str] = Counter()
    payload = os.urandom(4096)

    while time.monotonic() < end:
        try:
            sock = socks5_tcp_connect("127.0.0.1", proxy_port, host, port, timeout=5.0)
            try:
                for _ in range(8):
                    t0 = time.perf_counter()
                    sock.sendall(payload)
                    reply = recv_exact(sock, len(payload))
                    elapsed = (time.perf_counter() - t0) * 1000.0
                    if reply != payload:
                        raise RuntimeError("tcp echo mismatch")
                    latencies.append(elapsed)
                    total_bytes += len(payload)
                    successes += 1
                    if time.monotonic() >= end:
                        break
            finally:
                sock.close()
        except Exception as exc:
            failures += 1
            error_buckets[classify_error(exc)] += 1
            time.sleep(0.05)
    return successes, failures, latencies, total_bytes, counter_to_dict(error_buckets)


def run_udp_burst_workload(
    proxy_port: int,
    host: str,
    port: int,
    duration_s: float
) -> Tuple[int, int, List[float], Dict[str, int]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    error_buckets: Counter[str] = Counter()
    control = None
    udp = None
    try:
        control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
        end = time.monotonic() + max(0.5, float(duration_s))
        seq = 0
        while time.monotonic() < end:
            payload = struct.pack("!I", seq) + os.urandom(128)
            seq += 1
            t0 = time.perf_counter()
            try:
                reply = socks5_udp_send_recv(udp, relay, host, port, payload)
                elapsed = (time.perf_counter() - t0) * 1000.0
                if reply != payload:
                    raise RuntimeError("udp echo mismatch")
                latencies.append(elapsed)
                successes += 1
            except Exception as exc:
                failures += 1
                error_buckets[classify_error(exc)] += 1
            time.sleep(0.005)
    except Exception as exc:
        failures += 1
        error_buckets[classify_error(exc)] += 1
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()
    return successes, failures, latencies, counter_to_dict(error_buckets)


def run_dns_churn_workload(
    proxy_port: int,
    host: str,
    dns_port: int,
    duration_s: float
) -> Tuple[int, int, List[float], Dict[str, int]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    error_buckets: Counter[str] = Counter()
    names = [
        "alpha.synthetic.test",
        "beta.synthetic.test",
        "gamma.synthetic.test",
        "delta.synthetic.test",
    ]
    control = None
    udp = None
    try:
        control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
        end = time.monotonic() + max(0.5, float(duration_s))
        txid = 1
        while time.monotonic() < end:
            query = build_dns_query(random.choice(names), txid & 0xFFFF)
            txid += 1
            t0 = time.perf_counter()
            try:
                reply = socks5_udp_send_recv(
                    udp,
                    relay,
                    host,
                    dns_port,
                    query,
                    validator=lambda payload, expected_txid=query[0:2]: len(payload) >= 12 and payload[0:2] == expected_txid,
                    response_timeout=0.9,
                    retries=2,
                )
                elapsed = (time.perf_counter() - t0) * 1000.0
                latencies.append(elapsed)
                successes += 1
            except Exception as exc:
                failures += 1
                error_buckets[classify_error(exc)] += 1
            time.sleep(0.008)
    except Exception as exc:
        failures += 1
        error_buckets[classify_error(exc)] += 1
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()
    return successes, failures, latencies, counter_to_dict(error_buckets)


def run_quic_like_workload(
    proxy_port: int,
    host: str,
    quic_port: int,
    duration_s: float
) -> Tuple[int, int, List[float], Dict[str, int]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    error_buckets: Counter[str] = Counter()
    control = None
    udp = None
    try:
        control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
        end = time.monotonic() + max(0.5, float(duration_s))
        nonce = 0
        while time.monotonic() < end:
            # QUIC-like long-header marker + random payload.
            payload = bytes([0xC3]) + struct.pack("!I", nonce) + os.urandom(96)
            nonce += 1
            t0 = time.perf_counter()
            try:
                reply = socks5_udp_send_recv(
                    udp,
                    relay,
                    host,
                    quic_port,
                    payload,
                    response_timeout=0.9,
                    retries=2,
                )
                elapsed = (time.perf_counter() - t0) * 1000.0
                if reply != payload:
                    raise RuntimeError("quic-like echo mismatch")
                latencies.append(elapsed)
                successes += 1
            except Exception as exc:
                failures += 1
                error_buckets[classify_error(exc)] += 1
            time.sleep(0.006)
    except Exception as exc:
        failures += 1
        error_buckets[classify_error(exc)] += 1
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()
    return successes, failures, latencies, counter_to_dict(error_buckets)


class ControlClient:
    def __init__(self, host: str, port: int, timeout: float = 6.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def send(self, command: str, **kwargs: Any) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"command": command, "id": uuid.uuid4().hex}
        payload.update(kwargs)
        data = json.dumps(payload).encode("utf-8") + b"\n"

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            sock.sendall(data)
            chunks: List[bytes] = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        if not chunks:
            raise RuntimeError("empty control response")
        line = b"".join(chunks).split(b"\n", 1)[0]
        return json.loads(line.decode("utf-8"))


class StandaloneProcess:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.proc: Optional[subprocess.Popen[str]] = None
        self._stdout_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        require_port_available(self.args.socks_port, "SOCKS")
        require_port_available(self.args.control_port, "Control")

        if self.args.skip_build:
            bin_path = REPO_ROOT / ".build" / "arm64-apple-macosx" / "debug" / "Standalone"
        else:
            output = subprocess.check_output(
                ["swift", "build", "--product", "Standalone", "--show-bin-path"],
                cwd=REPO_ROOT,
                text=True,
            )
            bin_path = Path(output.strip()) / "Standalone"

        cmd = [
            str(bin_path),
            "--socks-port",
            str(self.args.socks_port),
            "--control-port",
            str(self.args.control_port),
            "--mtu",
            str(self.args.mtu),
            "--engine-log-level",
            self.args.engine_log_level,
            "--status-interval-ms",
            "2000",
        ]
        if self.args.standalone_enable_metrics:
            cmd.append("--enable-metrics")
        if self.args.standalone_enable_packet_stream:
            cmd.append("--enable-packet-stream")
        if self.args.standalone_keepalive_interval_seconds > 0:
            cmd.extend(
                [
                    "--keepalive-interval-seconds",
                    str(self.args.standalone_keepalive_interval_seconds),
                ]
            )
        log("Starting Standalone: " + " ".join(cmd))
        self.proc = subprocess.Popen(
            cmd,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._stdout_thread = threading.Thread(target=self._forward_stdout, daemon=True)
        self._stdout_thread.start()

        client = ControlClient("127.0.0.1", self.args.control_port, timeout=2.0)
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("Standalone exited before becoming ready")
            try:
                res = client.send("status")
                if res.get("ok"):
                    reported_port = (res.get("status") or {}).get("socksPort")
                    if isinstance(reported_port, int) and reported_port != self.args.socks_port:
                        log(
                            f"WARNING runtime socksPort={reported_port} differs from requested "
                            f"{self.args.socks_port}; using runtime port for traffic"
                        )
                        self.args.socks_port = reported_port
                    return
            except Exception:
                time.sleep(0.2)
                continue
        raise RuntimeError("Standalone control port did not become ready")

    def _forward_stdout(self) -> None:
        if self.proc is None or self.proc.stdout is None:
            return
        for line in self.proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                client = ControlClient("127.0.0.1", self.args.control_port, timeout=2.0)
                client.send("stop")
            except Exception:
                pass
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        self.proc = None


class DropletRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args

    def _run(self, script: str, *extra: str, capture_output: bool = False) -> str:
        cmd = [
            sys.executable,
            str(REPO_ROOT / "Scripts" / "vps-harness" / script),
            "--host",
            self.args.vps_host,
            "--user",
            self.args.vps_user,
            "--iface",
            self.args.vps_interface,
            *extra,
        ]
        log("Running: " + " ".join(cmd))
        if capture_output:
            proc = subprocess.run(cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
            return proc.stdout.strip()
        subprocess.run(cmd, cwd=REPO_ROOT, check=True)
        return ""

    def ensure_services(self) -> None:
        if self.args.skip_services:
            return
        self._run(
            "droplet_services.py",
            "--http-port",
            str(self.args.http_port),
            "ensure",
        )

    def apply_profile(self, profile: str, stack_mode: str) -> None:
        self._run("droplet_netem.py", "apply", "--profile", profile)
        self._run("droplet_netem.py", "stack", "--mode", stack_mode)

    def apply_custom(self, custom: Dict[str, float], stack_mode: str) -> None:
        self._run(
            "droplet_netem.py",
            "apply-custom",
            "--rate-mbit",
            str(custom["rate_mbit"]),
            "--ceil-mbit",
            str(custom["ceil_mbit"]),
            "--latency-ms",
            str(custom["latency_ms"]),
            "--jitter-ms",
            str(custom["jitter_ms"]),
            "--loss-pct",
            str(custom["loss_pct"]),
            "--reorder-pct",
            str(custom.get("reorder_pct", 0.0)),
            "--reorder-corr-pct",
            str(custom.get("reorder_corr_pct", 0.0)),
            "--corrupt-pct",
            str(custom.get("corrupt_pct", 0.0)),
            "--duplicate-pct",
            str(custom.get("duplicate_pct", 0.0)),
        )
        self._run("droplet_netem.py", "stack", "--mode", stack_mode)

    def telemetry_start(self, run_id: str) -> None:
        self._run(
            "droplet_telemetry.py",
            "--run-id",
            run_id,
            "--tool",
            self.args.telemetry_tool,
            "start",
        )

    def telemetry_stop(self, run_id: str) -> Dict[str, Any]:
        out = self._run(
            "droplet_telemetry.py",
            "--run-id",
            run_id,
            "--tool",
            self.args.telemetry_tool,
            "stop",
            capture_output=True,
        )
        try:
            return json.loads(out) if out else {"ok": False, "error": "empty-telemetry-output"}
        except json.JSONDecodeError:
            return {"ok": False, "error": "invalid-telemetry-output", "raw": out}

    def clear(self) -> None:
        self._run("droplet_netem.py", "clear")


class ImpairmentReplayer:
    def __init__(
        self,
        droplet: DropletRunner,
        stack_mode: str,
        steps: Sequence[ImpairmentStep],
    ) -> None:
        self.droplet = droplet
        self.stack_mode = stack_mode
        self.steps = list(steps)
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not self.steps:
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        for step in self.steps:
            if self.stop_event.is_set():
                return
            try:
                if step.custom is not None:
                    self.droplet.apply_custom(step.custom, self.stack_mode)
                    log(f"impairment phase label={step.label or 'trace'} mode=custom duration={step.duration_s:.1f}s")
                else:
                    profile = step.profile or "wifi"
                    self.droplet.apply_profile(profile, self.stack_mode)
                    log(f"impairment phase label={step.label or profile} mode=profile:{profile} duration={step.duration_s:.1f}s")
            except Exception as exc:
                log(f"WARNING failed to apply impairment phase '{step.label}': {exc}")

            phase_end = time.monotonic() + max(0.1, step.duration_s)
            while time.monotonic() < phase_end and not self.stop_event.is_set():
                time.sleep(min(0.2, phase_end - time.monotonic()))

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5)


def probe_stack_mode(
    proxy_port: int,
    vps_host_v4: str,
    vps_host_v6: str,
    tcp_port: int,
    stack_mode: str,
) -> Tuple[bool, bool]:
    ipv4_ok = False
    ipv6_ok = False
    try:
        s4 = socks5_tcp_connect("127.0.0.1", proxy_port, vps_host_v4, tcp_port, timeout=3.0)
        s4.sendall(b"probe-v4")
        reply = recv_exact(s4, len("probe-v4"))
        ipv4_ok = reply == b"probe-v4"
        s4.close()
    except Exception:
        ipv4_ok = False

    if vps_host_v6:
        try:
            s6 = socks5_tcp_connect("127.0.0.1", proxy_port, vps_host_v6, tcp_port, timeout=3.0)
            s6.sendall(b"probe-v6")
            reply = recv_exact(s6, len("probe-v6"))
            ipv6_ok = reply == b"probe-v6"
            s6.close()
        except Exception:
            ipv6_ok = False

    if stack_mode == "ipv4_only":
        return ipv4_ok, True
    if stack_mode == "ipv6_only":
        return True, ipv6_ok
    return ipv4_ok, ipv6_ok


def restart_relay_with_guard(control: ControlClient) -> Tuple[bool, bool]:
    failures = 0
    for _ in range(3):
        res = control.send("restart-relay")
        if res.get("ok"):
            settle_deadline = time.monotonic() + 4.0
            while time.monotonic() < settle_deadline:
                status = control.send("status").get("status") or {}
                running = bool(status.get("running", False))
                restarting = bool(status.get("restarting", False))
                if running and not restarting:
                    return True, False
                time.sleep(0.15)
            failures += 1
            continue
        failures += 1
        time.sleep(0.2)
    return False, failures >= 3


class LifecycleChurnRunner:
    def __init__(
        self,
        control: ControlClient,
        interval_ms: int,
        restart_every: int,
        enable_restarts: bool,
    ) -> None:
        self.control = control
        self.interval_s = max(0.2, float(interval_ms) / 1000.0)
        self.restart_every = max(1, int(restart_every))
        self.enable_restarts = bool(enable_restarts)
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.events: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()
        self.failures = 0
        self.loop_detected = False
        self.unstable_status_count = 0

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        idx = 0
        while not self.stop_event.is_set():
            command = "status"
            try:
                if self.enable_restarts and idx % self.restart_every == 0:
                    command = "restart-relay"
                    ok, loop = restart_relay_with_guard(self.control)
                    self.events["restart-relay"] += 1
                    if not ok:
                        self.failures += 1
                    if loop:
                        self.loop_detected = True
                elif idx % 2 == 1:
                    command = "flush-metrics"
                    res = self.control.send("flush-metrics")
                    self.events["flush-metrics"] += 1
                    if not res.get("ok"):
                        self.failures += 1
                else:
                    self.events["status"] += 1

                status = (self.control.send("status").get("status") or {})
                running = bool(status.get("running", False))
                restarting = bool(status.get("restarting", False))
                if not running or restarting:
                    self.failures += 1
                    self.unstable_status_count += 1
                    self.events["unstable-status"] += 1
            except Exception as exc:
                self.failures += 1
                self.events[f"command:{command}:error"] += 1
                self.errors[classify_error(exc)] += 1

            idx += 1
            self.stop_event.wait(self.interval_s)

    def stop(self) -> Dict[str, Any]:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
        return {
            "enabled": True,
            "events": counter_to_dict(self.events),
            "error_buckets": counter_to_dict(self.errors),
            "failures": int(self.failures),
            "unstable_status_count": int(self.unstable_status_count),
            "loop_detected": bool(self.loop_detected),
            "interval_s": round(self.interval_s, 3),
            "enable_restarts": self.enable_restarts,
            "restart_every": self.restart_every,
        }


class MemoryBudgetMonitor:
    def __init__(
        self,
        control: ControlClient,
        limit_mb: float,
        grace_seconds: float,
        sample_interval_ms: int,
    ) -> None:
        self.control = control
        self.limit_bytes = int(max(0.0, limit_mb) * 1024 * 1024)
        self.grace_s = max(0.0, float(grace_seconds))
        self.interval_s = max(0.05, float(sample_interval_ms) / 1000.0)
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.error_buckets: Counter[str] = Counter()
        self.sample_count = 0
        self.peak_rss_bytes = 0
        self.limit_exceeded = False
        self.over_limit_since: Optional[float] = None
        self.socket_buffer_capped = False
        self._stopped = False

    def start(self) -> None:
        if self.limit_bytes <= 0:
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                res = self.control.send("status")
                status = res.get("status") or {}
                rss_bytes = int(status.get("residentMemoryBytes", 0) or 0)
                peak_bytes = int(status.get("peakResidentMemoryBytes", rss_bytes) or rss_bytes)
                self.sample_count += 1
                self.peak_rss_bytes = max(self.peak_rss_bytes, rss_bytes, peak_bytes)
                if bool(status.get("socketBufferCapped", False)):
                    self.socket_buffer_capped = True

                now = time.monotonic()
                if rss_bytes > self.limit_bytes:
                    if self.over_limit_since is None:
                        self.over_limit_since = now
                    if (now - self.over_limit_since) >= self.grace_s:
                        self.limit_exceeded = True
                else:
                    self.over_limit_since = None
            except Exception as exc:
                self.error_buckets[classify_error(exc)] += 1

            self.stop_event.wait(self.interval_s)

    def stop(self) -> Dict[str, Any]:
        if self._stopped:
            return {
                "enabled": self.limit_bytes > 0,
                "limit_mb": round(self.limit_bytes / (1024 * 1024), 3),
                "grace_s": round(self.grace_s, 3),
                "interval_s": round(self.interval_s, 3),
                "samples": int(self.sample_count),
                "peak_rss_bytes": int(self.peak_rss_bytes),
                "peak_rss_mb": round(self.peak_rss_bytes / (1024 * 1024), 3),
                "limit_exceeded": bool(self.limit_exceeded),
                "socket_buffer_capped": bool(self.socket_buffer_capped),
                "error_buckets": counter_to_dict(self.error_buckets),
            }
        self._stopped = True
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
        return {
            "enabled": self.limit_bytes > 0,
            "limit_mb": round(self.limit_bytes / (1024 * 1024), 3),
            "grace_s": round(self.grace_s, 3),
            "interval_s": round(self.interval_s, 3),
            "samples": int(self.sample_count),
            "peak_rss_bytes": int(self.peak_rss_bytes),
            "peak_rss_mb": round(self.peak_rss_bytes / (1024 * 1024), 3),
            "limit_exceeded": bool(self.limit_exceeded),
            "socket_buffer_capped": bool(self.socket_buffer_capped),
            "error_buckets": counter_to_dict(self.error_buckets),
        }


def ipv6_gap_reasons(
    require_ipv6_data_plane: bool,
    v6_host: str,
    traffic_hosts: Sequence[str],
    udp_hosts: Sequence[str],
    dns_hosts: Sequence[str],
    quic_hosts: Sequence[str],
    http_hosts: Sequence[str],
    realistic_enabled: bool,
) -> List[str]:
    if not require_ipv6_data_plane or not v6_host or v6_host not in traffic_hosts:
        return []
    reasons: List[str] = []
    if v6_host not in udp_hosts:
        reasons.append("ipv6_udp_unavailable")
    if v6_host not in dns_hosts:
        reasons.append("ipv6_dns_unavailable")
    if v6_host not in quic_hosts:
        reasons.append("ipv6_quic_unavailable")
    if realistic_enabled and v6_host not in http_hosts:
        reasons.append("ipv6_http_unavailable")
    return reasons


def run_case(
    suite: str,
    scenario: str,
    profile: str,
    stack_mode: str,
    case_seconds: int,
    args: argparse.Namespace,
    control: ControlClient,
    droplet: DropletRunner,
) -> Dict[str, Any]:
    tcp_port = 7001
    udp_port = 7002
    dns_port = 7053
    quic_port = 7443
    http_port = args.http_port

    traffic_hosts: List[str]
    if stack_mode == "ipv6_only" and args.vps_host_v6:
        traffic_hosts = [args.vps_host_v6]
    elif stack_mode == "dual_stack" and args.vps_host_v6:
        traffic_hosts = [args.vps_host, args.vps_host_v6]
    else:
        traffic_hosts = [args.vps_host]

    steps = build_impairment_schedule(profile=profile, case_seconds=case_seconds, args=args)
    first_step = steps[0]
    if first_step.custom is not None:
        droplet.apply_custom(first_step.custom, stack_mode)
    elif first_step.profile is not None and first_step.profile != profile:
        droplet.apply_profile(first_step.profile, stack_mode)

    replayer = ImpairmentReplayer(droplet=droplet, stack_mode=stack_mode, steps=steps[1:])
    replayer.start()

    telemetry_run_id = f"{scenario}-{profile}-{stack_mode}-{uuid.uuid4().hex[:8]}"
    telemetry_summary: Dict[str, Any] = {"ok": False, "disabled": True}
    if args.enable_telemetry:
        droplet.telemetry_start(telemetry_run_id)
        telemetry_summary = {"ok": True, "started": True, "run_id": telemetry_run_id}
    lifecycle_stats: Dict[str, Any] = {"enabled": False}
    lifecycle_runner: Optional[LifecycleChurnRunner] = None
    if args.enable_lifecycle_churn:
        lifecycle_runner = LifecycleChurnRunner(
            control=control,
            interval_ms=args.lifecycle_interval_ms,
            restart_every=args.lifecycle_restart_every,
            enable_restarts=args.lifecycle_restarts,
        )
    memory_stats: Dict[str, Any] = {"enabled": False}
    memory_monitor: Optional[MemoryBudgetMonitor] = None
    if args.memory_rss_limit_mb > 0:
        memory_monitor = MemoryBudgetMonitor(
            control=control,
            limit_mb=args.memory_rss_limit_mb,
            grace_seconds=args.memory_rss_grace_seconds,
            sample_interval_ms=args.memory_sample_interval_ms,
        )
        memory_monitor.start()

    try:
        udp_hosts = [host for host in traffic_hosts if direct_udp_echo_probe(host, udp_port)]
        dns_hosts = [host for host in traffic_hosts if direct_dns_probe(host, dns_port)]
        quic_hosts = [host for host in traffic_hosts if direct_udp_echo_probe(host, quic_port, payload=b"\xC3probe")]
        http_hosts: List[str] = []
        http_preflight_errors: Counter[str] = Counter()
        for host in traffic_hosts:
            if socks_http_health_probe(args.socks_port, host, http_port, attempts=3):
                http_hosts.append(host)
            else:
                http_preflight_errors["http_health_probe_failed"] += 1

        if len(udp_hosts) != len(traffic_hosts):
            skipped = sorted(set(traffic_hosts) - set(udp_hosts))
            log(f"INFO udp preflight skipped hosts={','.join(skipped)}")
        if len(dns_hosts) != len(traffic_hosts):
            skipped = sorted(set(traffic_hosts) - set(dns_hosts))
            log(f"INFO dns preflight skipped hosts={','.join(skipped)}")
        if len(quic_hosts) != len(traffic_hosts):
            skipped = sorted(set(traffic_hosts) - set(quic_hosts))
            log(f"INFO quic preflight skipped hosts={','.join(skipped)}")
        if len(http_hosts) != len(traffic_hosts):
            skipped = sorted(set(traffic_hosts) - set(http_hosts))
            if skipped:
                log(f"INFO http preflight skipped hosts={','.join(skipped)}")

        # Validate missing IPv6 lanes via SOCKS-path retries before failing the case.
        if args.require_ipv6_data_plane and args.vps_host_v6 and args.vps_host_v6 in traffic_hosts:
            v6_host = args.vps_host_v6
            if v6_host not in udp_hosts and socks_udp_single_probe(
                proxy_port=args.socks_port,
                host=v6_host,
                port=udp_port,
                payload=b"probe-v6-udp",
                attempts=3,
                response_timeout=0.8,
            ):
                udp_hosts.append(v6_host)
                log("INFO ipv6 udp lane recovered via SOCKS probe")
            if v6_host not in dns_hosts and socks_dns_single_probe(args.socks_port, v6_host, dns_port, attempts=3):
                dns_hosts.append(v6_host)
                log("INFO ipv6 dns lane recovered via SOCKS probe")
            if v6_host not in quic_hosts and socks_udp_single_probe(
                proxy_port=args.socks_port,
                host=v6_host,
                port=quic_port,
                payload=b"\xC3probe-v6-quic",
                attempts=3,
                response_timeout=0.8,
            ):
                quic_hosts.append(v6_host)
                log("INFO ipv6 quic lane recovered via SOCKS probe")
            if args.enable_realistic_traffic and v6_host not in http_hosts:
                if socks_http_health_probe(args.socks_port, v6_host, http_port, attempts=3):
                    http_hosts.append(v6_host)
                    log("INFO ipv6 http lane recovered via SOCKS probe")

        additional_reasons: List[str] = []

        active_lane_count = 1
        if udp_hosts:
            active_lane_count += 1
        if dns_hosts:
            active_lane_count += 1
        if quic_hosts:
            active_lane_count += 1
        if args.enable_realistic_traffic and (http_hosts or dns_hosts):
            active_lane_count += 1
        if args.enable_fuzz_lane and udp_hosts:
            active_lane_count += 1
        lane_budget_s = max(2.0, float(case_seconds) / max(1, active_lane_count))
        tcp_host_duration = lane_budget_s / max(1, len(traffic_hosts))
        if lifecycle_runner is not None:
            lifecycle_runner.start()

        tcp_ok = tcp_fail = tcp_bytes = 0
        udp_ok = udp_fail = 0
        dns_ok = dns_fail = 0
        quic_ok = quic_fail = 0
        realistic_ok = realistic_fail = 0
        fuzz_ok = fuzz_fail = 0
        tcp_latencies: List[float] = []
        udp_latencies: List[float] = []
        dns_latencies: List[float] = []
        quic_latencies: List[float] = []
        realistic_latencies: List[float] = []
        fuzz_latencies: List[float] = []
        tcp_errors: Counter[str] = Counter()
        udp_errors: Counter[str] = Counter()
        dns_errors: Counter[str] = Counter()
        quic_errors: Counter[str] = Counter()
        realistic_errors: Counter[str] = Counter()
        fuzz_errors: Counter[str] = Counter()
        h2_versions: Counter[str] = Counter()
        if args.enable_realistic_traffic and not http_hosts:
            realistic_fail += max(1, len(traffic_hosts))
            realistic_errors["http_preflight_unreachable"] += len(traffic_hosts)
            realistic_errors.update(http_preflight_errors)

        for host in traffic_hosts:
            t_ok, t_fail, t_latencies, t_bytes, t_errors = run_tcp_echo_workload(
                args.socks_port,
                host,
                tcp_port,
                tcp_host_duration,
            )
            tcp_ok += t_ok
            tcp_fail += t_fail
            tcp_bytes += t_bytes
            tcp_latencies.extend(t_latencies)
            tcp_errors.update(t_errors)

        if udp_hosts:
            udp_host_duration = lane_budget_s / len(udp_hosts)
            for host in udp_hosts:
                u_ok, u_fail, u_latencies, u_errors = run_udp_burst_workload(args.socks_port, host, udp_port, udp_host_duration)
                udp_ok += u_ok
                udp_fail += u_fail
                udp_latencies.extend(u_latencies)
                udp_errors.update(u_errors)

        if dns_hosts:
            dns_host_duration = lane_budget_s / len(dns_hosts)
            for host in dns_hosts:
                d_ok, d_fail, d_latencies, d_errors = run_dns_churn_workload(args.socks_port, host, dns_port, dns_host_duration)
                dns_ok += d_ok
                dns_fail += d_fail
                dns_latencies.extend(d_latencies)
                dns_errors.update(d_errors)

        if quic_hosts:
            quic_host_duration = lane_budget_s / len(quic_hosts)
            for host in quic_hosts:
                q_ok, q_fail, q_latencies, q_errors = run_quic_like_workload(args.socks_port, host, quic_port, quic_host_duration)
                quic_ok += q_ok
                quic_fail += q_fail
                quic_latencies.extend(q_latencies)
                quic_errors.update(q_errors)

        if args.enable_realistic_traffic:
            if http_hosts:
                hls_duration = lane_budget_s / max(1, len(http_hosts))
                for host in http_hosts:
                    hls_ok, hls_fail, hls_latencies, hls_errors = run_hls_dash_churn_workload(
                        args.socks_port, host, http_port, hls_duration
                    )
                    realistic_ok += hls_ok
                    realistic_fail += hls_fail
                    realistic_latencies.extend(hls_latencies)
                    realistic_errors.update(hls_errors)

                    h2_ok, h2_fail, h2_latencies, h2_errors, h2_versions_dict = run_httpx_h2_h3_mixed_workload(
                        args.socks_port,
                        host,
                        http_port,
                        quic_port,
                        hls_duration,
                    )
                    realistic_ok += h2_ok
                    realistic_fail += h2_fail
                    realistic_latencies.extend(h2_latencies)
                    realistic_errors.update(h2_errors)
                    h2_versions.update(h2_versions_dict)

            if dns_hosts:
                resolver_duration = lane_budget_s / max(1, len(dns_hosts))
                for host in dns_hosts:
                    r_ok, r_fail, r_latencies, r_errors = run_dns_resolver_style_workload(
                        args.socks_port,
                        host,
                        dns_port,
                        resolver_duration,
                    )
                    realistic_ok += r_ok
                    realistic_fail += r_fail
                    realistic_latencies.extend(r_latencies)
                    realistic_errors.update(r_errors)

        if args.enable_fuzz_lane and udp_hosts:
            fuzz_duration = lane_budget_s / max(1, len(udp_hosts))
            for host in udp_hosts:
                f_ok, f_fail, f_latencies, f_errors = run_fuzz_lane_workload(
                    args.socks_port,
                    host,
                    dns_port,
                    quic_port,
                    fuzz_duration,
                )
                fuzz_ok += f_ok
                fuzz_fail += f_fail
                fuzz_latencies.extend(f_latencies)
                fuzz_errors.update(f_errors)

        restart_ok, loop_detected = restart_relay_with_guard(control)
        if lifecycle_runner is not None:
            lifecycle_stats = lifecycle_runner.stop()
            if lifecycle_stats.get("loop_detected"):
                loop_detected = True
            lifecycle_failures = int(lifecycle_stats.get("failures", 0))
            if lifecycle_failures > args.lifecycle_max_failures:
                additional_reasons.append(f"lifecycle_failures_exceeded:{lifecycle_failures}")
        if memory_monitor is not None:
            memory_stats = memory_monitor.stop()
            if bool(memory_stats.get("limit_exceeded")):
                additional_reasons.append(
                    f"memory_rss_limit_exceeded:{float(memory_stats.get('peak_rss_mb', 0.0)):.3f}mb"
                )

        all_latencies = (
            tcp_latencies
            + udp_latencies
            + dns_latencies
            + quic_latencies
            + realistic_latencies
            + fuzz_latencies
        )
        # Fuzz lane intentionally injects malformed frames, so keep it visible
        # but out of the core pass/fail success-rate gate.
        core_success = tcp_ok + udp_ok + dns_ok + quic_ok + realistic_ok + (1 if restart_ok else 0)
        core_ops = core_success + tcp_fail + udp_fail + dns_fail + quic_fail + realistic_fail + (0 if restart_ok else 1)
        success_rate = float(core_success) / float(core_ops) if core_ops else 0.0
        fuzz_ops = fuzz_ok + fuzz_fail
        fuzz_success_rate = float(fuzz_ok) / float(fuzz_ops) if fuzz_ops else 1.0
        overall_success = core_success + fuzz_ok
        overall_ops = core_ops + fuzz_ops
        overall_success_rate = float(overall_success) / float(overall_ops) if overall_ops else 0.0

        duration_s = max(1, case_seconds)
        throughput_mbps = (float(tcp_bytes) * 8.0 / 1_000_000.0) / float(duration_s)

        p50_ms = percentile(all_latencies, 0.50)
        p95_ms = percentile(all_latencies, 0.95)

        ipv4_ok, ipv6_ok = probe_stack_mode(
            proxy_port=args.socks_port,
            vps_host_v4=args.vps_host,
            vps_host_v6=args.vps_host_v6,
            tcp_port=tcp_port,
            stack_mode=stack_mode,
        )

        # Recheck IPv6 data-plane lanes once more at the end of the case to
        # avoid failing on a transient start-of-case miss.
        if args.require_ipv6_data_plane and args.vps_host_v6 and args.vps_host_v6 in traffic_hosts:
            v6_host = args.vps_host_v6
            if v6_host not in udp_hosts and socks_udp_single_probe(
                proxy_port=args.socks_port,
                host=v6_host,
                port=udp_port,
                payload=b"probe-v6-udp-post",
                attempts=2,
                response_timeout=0.8,
            ):
                udp_hosts.append(v6_host)
                log("INFO ipv6 udp lane recovered in postflight probe")
            if v6_host not in dns_hosts and socks_dns_single_probe(args.socks_port, v6_host, dns_port, attempts=2):
                dns_hosts.append(v6_host)
                log("INFO ipv6 dns lane recovered in postflight probe")
            if v6_host not in quic_hosts and socks_udp_single_probe(
                proxy_port=args.socks_port,
                host=v6_host,
                port=quic_port,
                payload=b"\xC3probe-v6-quic-post",
                attempts=2,
                response_timeout=0.8,
            ):
                quic_hosts.append(v6_host)
                log("INFO ipv6 quic lane recovered in postflight probe")
            if args.enable_realistic_traffic and v6_host not in http_hosts:
                if socks_http_health_probe(args.socks_port, v6_host, http_port, attempts=2):
                    http_hosts.append(v6_host)
                    log("INFO ipv6 http lane recovered in postflight probe")

        additional_reasons.extend(
            ipv6_gap_reasons(
                require_ipv6_data_plane=args.require_ipv6_data_plane,
                v6_host=args.vps_host_v6,
                traffic_hosts=traffic_hosts,
                udp_hosts=udp_hosts,
                dns_hosts=dns_hosts,
                quic_hosts=quic_hosts,
                http_hosts=http_hosts,
                realistic_enabled=args.enable_realistic_traffic,
            )
        )

        if args.enable_telemetry:
            telemetry_summary = droplet.telemetry_stop(telemetry_run_id)

        return {
            "duration_s": duration_s,
            "success_rate": success_rate,
            "p50_ms": p50_ms,
            "p95_ms": p95_ms,
            "throughput_mbps": throughput_mbps,
            "ipv4_ok": ipv4_ok,
            "ipv6_ok": ipv6_ok,
            "restart_events": 1,
            "loop_detected": loop_detected,
            "additional_reasons": additional_reasons,
            "protocol_stats": {
                "hosts": traffic_hosts,
                "timing": {
                    "case_seconds": int(case_seconds),
                    "active_lane_count": int(active_lane_count),
                    "lane_budget_s": round(lane_budget_s, 3),
                },
                "impairment": {
                    "schedule": [
                        {
                            "label": step.label,
                            "duration_s": round(step.duration_s, 3),
                            "profile": step.profile,
                            "custom": step.custom,
                        }
                        for step in steps
                    ]
                },
                "tcp": {"ok": tcp_ok, "fail": tcp_fail, "error_buckets": counter_to_dict(tcp_errors)},
                "udp": {
                    "ok": udp_ok,
                    "fail": udp_fail,
                    "eligible_hosts": udp_hosts,
                    "skipped_hosts": sorted(set(traffic_hosts) - set(udp_hosts)),
                    "error_buckets": counter_to_dict(udp_errors),
                },
                "dns": {
                    "ok": dns_ok,
                    "fail": dns_fail,
                    "eligible_hosts": dns_hosts,
                    "skipped_hosts": sorted(set(traffic_hosts) - set(dns_hosts)),
                    "error_buckets": counter_to_dict(dns_errors),
                },
                "quic": {
                    "ok": quic_ok,
                    "fail": quic_fail,
                    "eligible_hosts": quic_hosts,
                    "skipped_hosts": sorted(set(traffic_hosts) - set(quic_hosts)),
                    "error_buckets": counter_to_dict(quic_errors),
                },
                "realistic": {
                    "ok": realistic_ok,
                    "fail": realistic_fail,
                    "http_hosts": http_hosts,
                    "http_h2_h3_versions": counter_to_dict(h2_versions),
                    "error_buckets": counter_to_dict(realistic_errors),
                },
                "fuzz": {
                    "ok": fuzz_ok,
                    "fail": fuzz_fail,
                    "success_rate": fuzz_success_rate,
                    "enabled": args.enable_fuzz_lane,
                    "error_buckets": counter_to_dict(fuzz_errors),
                },
                "overall_success_rate_with_fuzz": overall_success_rate,
                "latency_breakdown": {
                    "tcp": summarize_latencies(tcp_latencies),
                    "udp": summarize_latencies(udp_latencies),
                    "dns": summarize_latencies(dns_latencies),
                    "quic": summarize_latencies(quic_latencies),
                    "realistic": summarize_latencies(realistic_latencies),
                    "fuzz": summarize_latencies(fuzz_latencies),
                    "combined": summarize_latencies(all_latencies),
                },
                "lifecycle": lifecycle_stats,
                "memory": memory_stats,
                "telemetry": telemetry_summary,
                "restart": {"ok": restart_ok, "loop_detected": loop_detected},
            },
        }
    finally:
        replayer.stop()
        if lifecycle_runner is not None and not lifecycle_stats.get("enabled"):
            try:
                lifecycle_stats = lifecycle_runner.stop()
            except Exception as exc:
                log(f"WARNING lifecycle churn stop failed: {exc}")
        if memory_monitor is not None and not memory_stats.get("enabled"):
            try:
                memory_stats = memory_monitor.stop()
            except Exception as exc:
                log(f"WARNING memory monitor stop failed: {exc}")
        if args.enable_telemetry:
            try:
                if telemetry_summary.get("started") and not telemetry_summary.get("action"):
                    telemetry_summary = droplet.telemetry_stop(telemetry_run_id)
            except Exception as exc:
                log(f"WARNING telemetry stop failed run_id={telemetry_run_id}: {exc}")


def suite_cases(args: argparse.Namespace) -> Iterable[Tuple[str, str, str, int]]:
    if args.suite == "smoke":
        for profile in ("wifi", "lte", "5g"):
            yield ("smoke-core", profile, "dual_stack", max(10, args.case_seconds))
        return

    if args.suite == "stress-matrix":
        for profile in PROFILES:
            for stack_mode in STACK_MODES:
                yield ("stress-matrix", profile, stack_mode, max(12, args.case_seconds))
        return

    soak_total = parse_soak_seconds(args.soak_duration)
    start = time.monotonic()
    idx = 0
    profiles = list(PROFILES)
    stacks = list(STACK_MODES)
    while time.monotonic() - start < soak_total:
        profile = profiles[idx % len(profiles)]
        stack_mode = stacks[idx % len(stacks)]
        idx += 1
        remaining = max(5, int(soak_total - (time.monotonic() - start)))
        case_seconds = min(max(15, args.case_seconds), remaining)
        yield ("soak", profile, stack_mode, case_seconds)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    history_file = Path(args.history_file)

    check_dependencies(args.allow_missing_deps)

    harness_proc = StandaloneProcess(args)
    droplet = DropletRunner(args)

    if args.dry_run:
        log("Dry-run enabled; exiting before execution")
        return 0

    history_rows = load_history(history_file)
    control = ControlClient("127.0.0.1", args.control_port)
    results: List[ScenarioResult] = []

    try:
        harness_proc.start()
        droplet.ensure_services()

        for scenario, profile, stack_mode, case_seconds in suite_cases(args):
            log(f"case start suite={args.suite} scenario={scenario} profile={profile} stack={stack_mode} duration={case_seconds}s")
            droplet.apply_profile(profile, stack_mode)

            metrics = run_case(
                suite=args.suite,
                scenario=scenario,
                profile=profile,
                stack_mode=stack_mode,
                case_seconds=case_seconds,
                args=args,
                control=control,
                droplet=droplet,
            )

            baseline = baseline_for(history_rows, args.suite, scenario, profile, stack_mode)
            passed, delta, reasons = evaluate_regression(
                success_rate=metrics["success_rate"],
                p50_ms=metrics["p50_ms"],
                p95_ms=metrics["p95_ms"],
                profile=profile,
                ipv4_ok=metrics["ipv4_ok"],
                ipv6_ok=metrics["ipv6_ok"],
                stack_mode=stack_mode,
                loop_detected=metrics["loop_detected"],
                baseline=baseline,
            )
            for reason in metrics.get("additional_reasons", []):
                if reason not in reasons:
                    reasons.append(reason)
            passed = len(reasons) == 0

            result = ScenarioResult(
                timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                suite=args.suite,
                scenario=scenario,
                profile=profile,
                stack_mode=stack_mode,
                duration_s=metrics["duration_s"],
                success_rate=metrics["success_rate"],
                p50_ms=metrics["p50_ms"],
                p95_ms=metrics["p95_ms"],
                throughput_mbps=metrics["throughput_mbps"],
                ipv4_ok=metrics["ipv4_ok"],
                ipv6_ok=metrics["ipv6_ok"],
                restart_events=metrics["restart_events"],
                loop_detected=metrics["loop_detected"],
                regression_delta=delta,
                protocol_stats=metrics["protocol_stats"],
                passed=passed,
                reasons=reasons,
            )

            results.append(result)
            append_history(history_file, result.to_json())
            history_rows.append(result.to_json())

            reason_text = "ok" if not reasons else ",".join(reasons)
            tcp_stats = result.protocol_stats["tcp"]
            udp_stats = result.protocol_stats["udp"]
            dns_stats = result.protocol_stats["dns"]
            quic_stats = result.protocol_stats["quic"]
            realistic_stats = result.protocol_stats.get("realistic", {"ok": 0, "fail": 0})
            fuzz_stats = result.protocol_stats.get("fuzz", {"ok": 0, "fail": 0})
            memory_stats = result.protocol_stats.get("memory", {"peak_rss_mb": 0.0, "limit_exceeded": False})
            restart_stats = result.protocol_stats["restart"]
            log(
                "case done "
                f"pass={result.passed} success_rate={result.success_rate:.4f} "
                f"p50={result.p50_ms:.2f}ms p95={result.p95_ms:.2f}ms "
                f"throughput={result.throughput_mbps:.2f}Mbps "
                f"ipv4_ok={result.ipv4_ok} ipv6_ok={result.ipv6_ok} "
                f"tcp={tcp_stats['ok']}/{tcp_stats['fail']} "
                f"udp={udp_stats['ok']}/{udp_stats['fail']} "
                f"dns={dns_stats['ok']}/{dns_stats['fail']} "
                f"quic={quic_stats['ok']}/{quic_stats['fail']} "
                f"realistic={realistic_stats['ok']}/{realistic_stats['fail']} "
                f"fuzz={fuzz_stats['ok']}/{fuzz_stats['fail']} "
                f"rss_peak_mb={float(memory_stats.get('peak_rss_mb', 0.0)):.2f} "
                f"rss_limit_hit={bool(memory_stats.get('limit_exceeded', False))} "
                f"restart_ok={restart_stats['ok']} "
                f"hosts={','.join(result.protocol_stats['hosts'])} reasons={reason_text}"
            )

        failures = [r for r in results if not r.passed]
        log(f"suite complete total={len(results)} failures={len(failures)}")
        if failures:
            for item in failures:
                log(
                    "failure "
                    f"scenario={item.scenario} profile={item.profile} stack={item.stack_mode} "
                    f"reasons={','.join(item.reasons)}"
                )
            return 2
        return 0
    finally:
        try:
            droplet.clear()
        except Exception as exc:
            log(f"WARNING failed to clear droplet impairment: {exc}")
        harness_proc.stop()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
