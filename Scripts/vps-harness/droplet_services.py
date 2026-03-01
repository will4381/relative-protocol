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
import signal
import socket
import struct


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
    if offset + 5 >= len(query):
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


async def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic droplet services")
    parser.add_argument("--tcp-port", type=int, default=7001)
    parser.add_argument("--udp-port", type=int, default=7002)
    parser.add_argument("--dns-port", type=int, default=7053)
    parser.add_argument("--quic-port", type=int, default=7443)
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

    async def bind_datagram(protocol_factory, port):
        transports = []
        bindings = (("0.0.0.0", socket.AF_INET), ("::", socket.AF_INET6))
        for host, family in bindings:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    protocol_factory,
                    local_addr=(host, port),
                    family=family,
                )
                transports.append(transport)
            except OSError:
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
  exit 0
fi
nohup python3 {SERVICE_SCRIPT_PATH} \\
  --tcp-port {args.tcp_port} \\
  --udp-port {args.udp_port} \\
  --dns-port {args.dns_port} \\
  --quic-port {args.quic_port} \\
  > {SERVICE_LOG_PATH} 2>&1 &
echo $! > {SERVICE_PID_PATH}
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
