#!/usr/bin/env python3
"""Off-device VPN soak harness orchestrator.

Runs local Standalone (Swift runtime), configures droplet impairments,
executes synthetic traffic via SOCKS, and applies regression gates.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import importlib.util
import ipaddress
import json
import os
import random
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HISTORY_FILE = REPO_ROOT / ".tmp" / "vps-harness-history.jsonl"

PROFILES = ("wifi", "lte", "5g", "dirty")
STACK_MODES = ("dual_stack", "ipv4_only", "ipv6_only")
SOAK_DURATIONS = {"30m": 30 * 60, "60m": 60 * 60, "120m": 120 * 60}

REQ_PACKAGES: Tuple[Tuple[str, str], ...] = (
    ("httpx", "httpx"),
    ("socks", "PySocks"),
    ("dns", "dnspython"),
    ("aioquic", "aioquic"),
    ("scapy", "scapy"),
    ("numpy", "numpy"),
)


@dataclasses.dataclass
class Baseline:
    success_rate: float
    p50_ms: float
    p95_ms: float
    sample_count: int


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
    passed: bool
    reasons: List[str]

    def to_json(self) -> Dict[str, Any]:
        return {
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
    parser.add_argument("--case-seconds", type=int, default=20)
    parser.add_argument("--history-file", default=str(DEFAULT_HISTORY_FILE))
    parser.add_argument("--allow-missing-deps", action="store_true")
    parser.add_argument("--skip-services", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


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


def parse_soak_seconds(label: str) -> int:
    return SOAK_DURATIONS[label]


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
    ipv4_ok: bool,
    ipv6_ok: bool,
    stack_mode: str,
    loop_detected: bool,
    baseline: Optional[Baseline],
) -> Tuple[bool, Dict[str, float], List[str]]:
    reasons: List[str] = []
    delta: Dict[str, float] = {}

    if success_rate < 0.99:
        reasons.append(f"success_rate_below_threshold:{success_rate:.4f}")
    if stack_mode == "dual_stack" and not ipv4_ok and not ipv6_ok:
        reasons.append("dual_stack_lost_ipv4_and_ipv6")
    if loop_detected:
        reasons.append("reconnect_loop_detected")

    if baseline is not None and baseline.sample_count >= 3:
        if baseline.p50_ms > 0:
            delta["p50"] = (p50_ms - baseline.p50_ms) / baseline.p50_ms
            if delta["p50"] > 0.20:
                reasons.append(f"p50_regression:{delta['p50']:.4f}")
        if baseline.p95_ms > 0:
            delta["p95"] = (p95_ms - baseline.p95_ms) / baseline.p95_ms
            if delta["p95"] > 0.30:
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
) -> bytes:
    packet = b"\x00\x00\x00" + encode_socks_addr(target_host) + struct.pack("!H", target_port) + payload
    udp.sendto(packet, relay)
    data, _ = udp.recvfrom(65535)
    if len(data) < 4:
        raise RuntimeError("truncated SOCKS UDP response")
    if data[2] != 0:
        raise RuntimeError("fragmented SOCKS UDP response is unsupported")
    _, offset = parse_socks_addr(data, offset=3)
    offset += 2
    return data[offset:]


def build_dns_query(name: str, txid: int) -> bytes:
    labels = name.strip(".").split(".")
    question = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels) + b"\x00"
    question += b"\x00\x01\x00\x01"  # A IN
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + question


def run_tcp_echo_workload(proxy_port: int, host: str, port: int, duration_s: int) -> Tuple[int, int, List[float], int]:
    end = time.monotonic() + max(2, duration_s)
    successes = 0
    failures = 0
    latencies: List[float] = []
    total_bytes = 0
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
        except Exception:
            failures += 1
            time.sleep(0.05)
    return successes, failures, latencies, total_bytes


def run_udp_burst_workload(proxy_port: int, host: str, port: int, duration_s: int) -> Tuple[int, int, List[float]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    control = None
    udp = None
    try:
        control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
        end = time.monotonic() + max(2, duration_s)
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
            except Exception:
                failures += 1
            time.sleep(0.005)
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()
    return successes, failures, latencies


def run_dns_churn_workload(proxy_port: int, host: str, dns_port: int, duration_s: int) -> Tuple[int, int, List[float]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
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
        end = time.monotonic() + max(2, duration_s)
        txid = 1
        while time.monotonic() < end:
            query = build_dns_query(random.choice(names), txid & 0xFFFF)
            txid += 1
            t0 = time.perf_counter()
            try:
                reply = socks5_udp_send_recv(udp, relay, host, dns_port, query)
                elapsed = (time.perf_counter() - t0) * 1000.0
                if len(reply) < 12:
                    raise RuntimeError("dns reply too short")
                if reply[0:2] != query[0:2]:
                    raise RuntimeError("dns txid mismatch")
                latencies.append(elapsed)
                successes += 1
            except Exception:
                failures += 1
            time.sleep(0.008)
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()
    return successes, failures, latencies


def run_quic_like_workload(proxy_port: int, host: str, quic_port: int, duration_s: int) -> Tuple[int, int, List[float]]:
    successes = 0
    failures = 0
    latencies: List[float] = []
    control = None
    udp = None
    try:
        control, udp, relay = socks5_udp_associate("127.0.0.1", proxy_port)
        end = time.monotonic() + max(2, duration_s)
        nonce = 0
        while time.monotonic() < end:
            # QUIC-like long-header marker + random payload.
            payload = bytes([0xC3]) + struct.pack("!I", nonce) + os.urandom(96)
            nonce += 1
            t0 = time.perf_counter()
            try:
                reply = socks5_udp_send_recv(udp, relay, host, quic_port, payload)
                elapsed = (time.perf_counter() - t0) * 1000.0
                if reply != payload:
                    raise RuntimeError("quic-like echo mismatch")
                latencies.append(elapsed)
                successes += 1
            except Exception:
                failures += 1
            time.sleep(0.006)
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()
    return successes, failures, latencies


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

    def _run(self, script: str, *extra: str) -> None:
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
        subprocess.run(cmd, cwd=REPO_ROOT, check=True)

    def ensure_services(self) -> None:
        if self.args.skip_services:
            return
        self._run("droplet_services.py", "ensure")

    def apply_profile(self, profile: str, stack_mode: str) -> None:
        self._run("droplet_netem.py", "apply", "--profile", profile)
        self._run("droplet_netem.py", "stack", "--mode", stack_mode)

    def clear(self) -> None:
        self._run("droplet_netem.py", "clear")


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
            status = control.send("status").get("status") or {}
            running = bool(status.get("running", False))
            restarting = bool(status.get("restarting", False))
            return running and not restarting, False
        failures += 1
        time.sleep(0.2)
    return False, failures >= 3


def run_case(
    suite: str,
    scenario: str,
    profile: str,
    stack_mode: str,
    case_seconds: int,
    args: argparse.Namespace,
    control: ControlClient,
) -> Dict[str, Any]:
    tcp_port = 7001
    udp_port = 7002
    dns_port = 7053
    quic_port = 7443

    tcp_ok, tcp_fail, tcp_latencies, tcp_bytes = run_tcp_echo_workload(args.socks_port, args.vps_host, tcp_port, case_seconds)
    udp_ok, udp_fail, udp_latencies = run_udp_burst_workload(args.socks_port, args.vps_host, udp_port, case_seconds)
    dns_ok, dns_fail, dns_latencies = run_dns_churn_workload(args.socks_port, args.vps_host, dns_port, case_seconds)
    quic_ok, quic_fail, quic_latencies = run_quic_like_workload(args.socks_port, args.vps_host, quic_port, case_seconds)

    restart_ok, loop_detected = restart_relay_with_guard(control)

    all_latencies = tcp_latencies + udp_latencies + dns_latencies + quic_latencies
    total_success = tcp_ok + udp_ok + dns_ok + quic_ok + (1 if restart_ok else 0)
    total_ops = total_success + tcp_fail + udp_fail + dns_fail + quic_fail + (0 if restart_ok else 1)
    success_rate = float(total_success) / float(total_ops) if total_ops else 0.0

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
    }


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
            )

            baseline = baseline_for(history_rows, args.suite, scenario, profile, stack_mode)
            passed, delta, reasons = evaluate_regression(
                success_rate=metrics["success_rate"],
                p50_ms=metrics["p50_ms"],
                p95_ms=metrics["p95_ms"],
                ipv4_ok=metrics["ipv4_ok"],
                ipv6_ok=metrics["ipv6_ok"],
                stack_mode=stack_mode,
                loop_detected=metrics["loop_detected"],
                baseline=baseline,
            )

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
                passed=passed,
                reasons=reasons,
            )

            results.append(result)
            append_history(history_file, result.to_json())
            history_rows.append(result.to_json())

            reason_text = "ok" if not reasons else ",".join(reasons)
            log(
                "case done "
                f"pass={result.passed} success_rate={result.success_rate:.4f} "
                f"p50={result.p50_ms:.2f}ms p95={result.p95_ms:.2f}ms "
                f"throughput={result.throughput_mbps:.2f}Mbps "
                f"ipv4_ok={result.ipv4_ok} ipv6_ok={result.ipv6_ok} reasons={reason_text}"
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
