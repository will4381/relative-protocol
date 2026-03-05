#!/usr/bin/env python3
"""Manage synthetic traffic services on the Ubuntu droplet."""

from __future__ import annotations

import argparse
import subprocess


SERVICE_SCRIPT_PATH = "/tmp/vpn_harness_services.py"
SERVICE_PID_PATH = "/tmp/vpn_harness_services.pid"
SERVICE_LOG_PATH = "/tmp/vpn_harness_services.log"

SERVICE_SCRIPT = r'''#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import os
import random
import signal
import socket
import struct
from urllib.parse import parse_qs, urlparse


def build_dns_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    txid = query[0:2]
    flags = b"\x81\x80"
    qdcount = query[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    offset = 12
    while offset < len(query) and query[offset] != 0:
        offset += query[offset] + 1
    if offset + 5 > len(query):
        return b""

    qname = query[12 : offset + 1]
    qtype = query[offset + 1 : offset + 3]
    qclass = query[offset + 3 : offset + 5]
    question = qname + qtype + qclass

    name_ptr = b"\xc0\x0c"
    ttl = struct.pack("!I", 30)

    if qtype == b"\x00\x1c":  # AAAA
        rdata = ipaddress.IPv6Address("2001:db8::10").packed
        rr = name_ptr + b"\x00\x1c\x00\x01" + ttl + struct.pack("!H", len(rdata)) + rdata
    else:  # default A
        rdata = ipaddress.IPv4Address("203.0.113.10").packed
        rr = name_ptr + b"\x00\x01\x00\x01" + ttl + struct.pack("!H", len(rdata)) + rdata

    return txid + flags + qdcount + ancount + nscount + arcount + question + rr


class UDPEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


class DNSResponder(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        reply = build_dns_response(data)
        if reply:
            self.transport.sendto(reply, addr)


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65535)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


def http_response(
    status: int,
    body: bytes,
    content_type: str = "application/octet-stream",
    headers: dict[str, str] | None = None,
) -> bytes:
    reason = {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        405: "Method Not Allowed",
    }.get(status, "OK")
    lines = [
        f"HTTP/1.1 {status} {reason}",
        f"Content-Length: {len(body)}",
        f"Content-Type: {content_type}",
        "Connection: close",
        "Cache-Control: no-store",
    ]
    if headers:
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body


def build_hls_playlist(segment_count: int = 8) -> bytes:
    lines = [
        "#EXTM3U",
        "#EXT-X-VERSION:3",
        "#EXT-X-TARGETDURATION:4",
        "#EXT-X-MEDIA-SEQUENCE:0",
    ]
    for idx in range(segment_count):
        lines.append("#EXTINF:4.000,")
        lines.append(f"/hls/seg{idx}.ts")
    lines.append("#EXT-X-ENDLIST")
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_dash_mpd(segment_count: int = 8) -> bytes:
    xml = f"""<?xml version="1.0"?>
<MPD type="static" mediaPresentationDuration="PT32S" minBufferTime="PT2S" xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period id="1" duration="PT32S">
    <AdaptationSet mimeType="video/mp4" codecs="avc1.42E01E" segmentAlignment="true">
      <Representation id="1" bandwidth="800000" width="640" height="360">
        <SegmentTemplate timescale="1" media="/dash/chunk$Number$.m4s" initialization="/dash/init.mp4" startNumber="1" duration="4"/>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""
    _ = segment_count
    return xml.encode("utf-8")


def segment_bytes(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(0, 256) for _ in range(size))


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3.0)
    except Exception:
        writer.write(http_response(400, b"bad-request", "text/plain"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return

    head = raw.decode("latin-1", errors="replace")
    first_line = head.split("\r\n", 1)[0]
    parts = first_line.split(" ")
    if len(parts) < 3:
        writer.write(http_response(400, b"bad-request", "text/plain"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return

    method, target, _ = parts[0], parts[1], parts[2]
    if method not in ("GET", "HEAD"):
        writer.write(http_response(405, b"method-not-allowed", "text/plain"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return

    parsed = urlparse(target)
    path = parsed.path or "/"
    query = parse_qs(parsed.query)

    body: bytes
    content_type = "application/octet-stream"
    status = 200
    extra_headers = {}

    if path == "/health":
        body = b"ok"
        content_type = "text/plain"
    elif path == "/api/payload":
        size = int(query.get("size", ["1024"])[0])
        size = max(64, min(2_000_000, size))
        body = segment_bytes(size, size)
        content_type = "application/octet-stream"
    elif path == "/hls/playlist.m3u8":
        body = build_hls_playlist()
        content_type = "application/vnd.apple.mpegurl"
    elif path.startswith("/hls/seg") and path.endswith(".ts"):
        try:
            idx = int(path.removeprefix("/hls/seg").removesuffix(".ts"))
        except ValueError:
            idx = 0
        body = segment_bytes(10_000 + idx, 188 * 400)
        content_type = "video/mp2t"
    elif path == "/dash/manifest.mpd":
        body = build_dash_mpd()
        content_type = "application/dash+xml"
    elif path == "/dash/init.mp4":
        body = segment_bytes(20_000, 2048)
        content_type = "video/mp4"
    elif path.startswith("/dash/chunk") and path.endswith(".m4s"):
        try:
            idx = int(path.removeprefix("/dash/chunk").removesuffix(".m4s"))
        except ValueError:
            idx = 1
        body = segment_bytes(30_000 + idx, 16_384)
        content_type = "video/iso.segment"
    else:
        status = 404
        body = b"not-found"
        content_type = "text/plain"

    if method == "HEAD":
        body = b""
    resp = http_response(status, body, content_type, extra_headers)
    writer.write(resp)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic droplet services")
    parser.add_argument("--tcp-port", type=int, default=7001)
    parser.add_argument("--udp-port", type=int, default=7002)
    parser.add_argument("--dns-port", type=int, default=7053)
    parser.add_argument("--quic-port", type=int, default=7443)
    parser.add_argument("--http-port", type=int, default=7080)
    args = parser.parse_args()

    loop = asyncio.get_running_loop()

    tcp_servers = []
    for host in ("0.0.0.0", "::"):
        try:
            server = await asyncio.start_server(handle_tcp, host=host, port=args.tcp_port)
            tcp_servers.append(server)
        except OSError:
            continue
    if not tcp_servers:
        raise RuntimeError("Failed to bind TCP service on IPv4 or IPv6")

    http_servers = []
    for host in ("0.0.0.0", "::"):
        try:
            server = await asyncio.start_server(handle_http, host=host, port=args.http_port)
            http_servers.append(server)
        except OSError:
            continue
    if not http_servers:
        raise RuntimeError("Failed to bind HTTP service on IPv4 or IPv6")

    async def bind_datagram(protocol_factory, port):
        transports = []
        bindings = (("0.0.0.0", socket.AF_INET), ("::", socket.AF_INET6))
        for host, family in bindings:
            local_addr = (host, port)
            sock = None
            try:
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(local_addr)
                transport, _ = await loop.create_datagram_endpoint(
                    protocol_factory,
                    sock=sock,
                )
                transports.append(transport)
            except (OSError, TypeError, ValueError):
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                continue
        if not transports:
            raise RuntimeError(f"Failed to bind UDP service on IPv4 or IPv6 for port {port}")
        return transports

    udp_transports = await bind_datagram(UDPEcho, args.udp_port)
    dns_transports = await bind_datagram(DNSResponder, args.dns_port)
    quic_transports = await bind_datagram(UDPEcho, args.quic_port)

    stop = asyncio.Event()

    def _stop(*_):
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _stop)

    await stop.wait()

    for server in tcp_servers:
        server.close()
    for server in tcp_servers:
        await server.wait_closed()
    for server in http_servers:
        server.close()
    for server in http_servers:
        await server.wait_closed()
    for transport in udp_transports:
        transport.close()
    for transport in dns_transports:
        transport.close()
    for transport in quic_transports:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage droplet synthetic services")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--iface", default="eth0")  # kept for interface compatibility
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--tcp-port", type=int, default=7001)
    parser.add_argument("--udp-port", type=int, default=7002)
    parser.add_argument("--dns-port", type=int, default=7053)
    parser.add_argument("--quic-port", type=int, default=7443)
    parser.add_argument("--http-port", type=int, default=7080)
    parser.add_argument("action", choices=["deploy", "start", "stop", "status", "ensure"])
    return parser.parse_args()


def ssh(target: str, command: str, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY-RUN] ssh {target} <<'SH'\n{command}\nSH")
        return
    subprocess.run(["ssh", target, command], check=True)


def ssh_with_stdin(target: str, command: str, payload: str, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY-RUN] ssh {target} {command} <payload-bytes={len(payload.encode('utf-8'))}>")
        return
    subprocess.run(["ssh", target, command], input=payload, text=True, check=True)


def deploy(args: argparse.Namespace, target: str) -> None:
    ssh_with_stdin(target, f"cat > {SERVICE_SCRIPT_PATH}", SERVICE_SCRIPT, args.dry_run)
    ssh(target, f"chmod +x {SERVICE_SCRIPT_PATH}", args.dry_run)


def start(args: argparse.Namespace, target: str) -> None:
    cmd = f"""
set -e
if [ -f {SERVICE_PID_PATH} ] && kill -0 $(cat {SERVICE_PID_PATH}) 2>/dev/null; then
  if python3 - <<'PY'
import socket
import sys

tcp_ports = [{args.tcp_port}, {args.http_port}]
udp_echo_ports = [{args.udp_port}, {args.quic_port}]
dns_port = {args.dns_port}

def tcp_reachable(port: int) -> bool:
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            sock.connect((host, port))
            sock.close()
            return True
        except Exception:
            continue
    return False

def udp_echo_ok(host: str, family: int, port: int, payload: bytes) -> bool:
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(0.6)
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(256)
        sock.close()
        return data == payload
    except Exception:
        return False

def dns_ok(host: str, family: int, port: int) -> bool:
    query = b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x05alpha\\x09synthetic\\x04test\\x00\\x00\\x01\\x00\\x01"
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        return len(data) >= 12 and data[:2] == b"\\x12\\x34"
    except Exception:
        return False

for port in tcp_ports:
    if not tcp_reachable(port):
        raise SystemExit(1)
for port in udp_echo_ports:
    if not udp_echo_ok("127.0.0.1", socket.AF_INET, port, b"probe4"):
        raise SystemExit(1)
if not dns_ok("127.0.0.1", socket.AF_INET, dns_port):
    raise SystemExit(1)
if socket.has_ipv6:
    for port in udp_echo_ports:
        if not udp_echo_ok("::1", socket.AF_INET6, port, b"probe6"):
            raise SystemExit(1)
    if not dns_ok("::1", socket.AF_INET6, dns_port):
        raise SystemExit(1)
raise SystemExit(0)
PY
  then
    exit 0
  fi
  PID=$(cat {SERVICE_PID_PATH})
  kill $PID 2>/dev/null || true
  rm -f {SERVICE_PID_PATH}
fi
nohup python3 {SERVICE_SCRIPT_PATH} \\
  --tcp-port {args.tcp_port} \\
  --udp-port {args.udp_port} \\
  --dns-port {args.dns_port} \\
  --quic-port {args.quic_port} \\
  --http-port {args.http_port} \\
  > {SERVICE_LOG_PATH} 2>&1 &
echo $! > {SERVICE_PID_PATH}
READY=0
for _ in $(seq 1 40); do
  if python3 - <<'PY'
import socket
import sys

tcp_ports = [{args.tcp_port}, {args.http_port}]
udp_echo_ports = [{args.udp_port}, {args.quic_port}]
dns_port = {args.dns_port}

def tcp_reachable(port: int) -> bool:
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            sock.connect((host, port))
            sock.close()
            return True
        except Exception:
            continue
    return False

def udp_echo_ok(host: str, family: int, port: int, payload: bytes) -> bool:
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(0.6)
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(256)
        sock.close()
        return data == payload
    except Exception:
        return False

def dns_ok(host: str, family: int, port: int) -> bool:
    query = b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x05alpha\\x09synthetic\\x04test\\x00\\x00\\x01\\x00\\x01"
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        return len(data) >= 12 and data[:2] == b"\\x12\\x34"
    except Exception:
        return False

for port in tcp_ports:
    if not tcp_reachable(port):
        raise SystemExit(1)
for port in udp_echo_ports:
    if not udp_echo_ok("127.0.0.1", socket.AF_INET, port, b"probe4"):
        raise SystemExit(1)
if not dns_ok("127.0.0.1", socket.AF_INET, dns_port):
    raise SystemExit(1)
if socket.has_ipv6:
    for port in udp_echo_ports:
        if not udp_echo_ok("::1", socket.AF_INET6, port, b"probe6"):
            raise SystemExit(1)
    if not dns_ok("::1", socket.AF_INET6, dns_port):
        raise SystemExit(1)
raise SystemExit(0)
PY
  then
    READY=1
    break
  fi
  sleep 0.25
done
if [ "$READY" -ne 1 ]; then
  echo "service readiness check failed" >&2
  exit 1
fi
""".strip()
    ssh(target, cmd, args.dry_run)


def stop(args: argparse.Namespace, target: str) -> None:
    cmd = f"""
set -e
if [ -f {SERVICE_PID_PATH} ]; then
  PID=$(cat {SERVICE_PID_PATH})
  kill $PID 2>/dev/null || true
  rm -f {SERVICE_PID_PATH}
fi
""".strip()
    ssh(target, cmd, args.dry_run)


def status(args: argparse.Namespace, target: str) -> None:
    cmd = f"""
set -e
if [ -f {SERVICE_PID_PATH} ] && kill -0 $(cat {SERVICE_PID_PATH}) 2>/dev/null; then
  echo running
  exit 0
fi
echo stopped
exit 1
""".strip()
    ssh(target, cmd, args.dry_run)


def main() -> int:
    args = parse_args()
    target = f"{args.user}@{args.host}"

    if args.action == "deploy":
        deploy(args, target)
        return 0
    if args.action == "start":
        start(args, target)
        return 0
    if args.action == "stop":
        stop(args, target)
        return 0
    if args.action == "status":
        status(args, target)
        return 0

    deploy(args, target)
    start(args, target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
