# Local Tunnel Harness

This package cannot exactly emulate iOS `NEPacketTunnelProvider` on Linux or in a normal local process. Apple owns the real provider lifecycle, VPN preference store, tunnel network settings install, route and DNS application, background lifecycle, App Group access, and `NEPacketTunnelFlow` packet delivery.

The local harness is therefore a test ladder, not an iPhone replacement:

| Layer | Command | What it proves | What it cannot prove |
| --- | --- | --- | --- |
| Synthetic replay | `swift run HarnessLocal <scenario.json>` | deterministic runtime, telemetry pressure, and replay plumbing | real packet routing, DNS, path changes |
| PCAP replay | `swift run HarnessLocal --pcap capture.pcap --max-packets 500` | repeatable packet-shape samples from captured traffic without privileges | live routing, `NEPacketTunnelFlow`, iOS energy/background behavior |
| Linux TUN runtime | `sudo swift run HarnessLocal --tun --name rp0 --duration 30 --socks-port 1080` | dataplane startup against a real `/dev/net/tun` file descriptor | Apple Network Extension preference/session behavior |
| Physical iPhone | Example app + extension on device | `NETunnelProviderManager`, `setTunnelNetworkSettings`, DNS/routes, Wi-Fi/cellular transitions, App Group logs | deterministic CI speed |

## Source-Grounded Design

- Apple documents `NEPacketTunnelProvider` as an app-extension provider with lifecycle methods, a `packetFlow`, and tunnel-created TCP/UDP connections. That is why the local harness does not pretend to be the provider process. Source: [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider).
- Apple documents `NEPacketTunnelFlow` as the object used to read and write packets to the tunnel interface. PCAP replay and Linux TUN only approximate this packet boundary; they do not provide Apple’s flow object. Source: [NEPacketTunnelFlow](https://developer.apple.com/documentation/networkextension/nepackettunnelflow).
- Apple’s tunnel settings API is session scoped through `setTunnelNetworkSettings`, and profile ownership is through `NETunnelProviderManager`. Those remain physical-device release gates. Sources: [setTunnelNetworkSettings](https://developer.apple.com/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:)) and [NETunnelProviderManager](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager).
- Wireshark separates privileged capture from normal analysis; its developer guide describes packet capture through libpcap/Npcap and isolates privileged capture work in `dumpcap`. The harness follows the same idea: PCAP replay is unprivileged, while Linux TUN creation is explicit and privileged. Source: [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html/).
- Wireshark's `extcap` model treats unusual capture sources as external binaries. The harness uses the same boundary concept by keeping local packet sources behind adapters instead of coupling them to production tunnel control. Source: [extcap(4)](https://www.wireshark.org/docs/man-pages/extcap.html).
- `dumpcap` defaults to pcapng but can write classic pcap. The first replay implementation supports classic pcap because it is small, deterministic, and easy to parse safely in Swift; pcapng remains a documented future extension. Source: [dumpcap(1)](https://www.wireshark.org/docs/man-pages/dumpcap.html).
- NGINX and libuv both center networking around event loops and non-blocking I/O. The harness keeps packet sources adapter-owned and bounded so production-style backpressure remains visible rather than hiding it behind unbounded thread-per-packet work. Sources: [NGINX development guide](https://nginx.org/en/docs/dev/development_guide.html), [NGINX connection methods](https://nginx.org/en/docs/events.html), and [libuv design overview](https://docs.libuv.org/en/stable/design.html).
- Linux documents `/dev/net/tun` as a user-space packet device created with `TUNSETIFF`, with TUN carrying IP packets rather than Ethernet frames. The Linux harness uses `IFF_TUN` and defaults to `IFF_NO_PI` so packets look like the IP packets seen by `NEPacketTunnelFlow`. Source: [Linux TUN/TAP documentation](https://docs.kernel.org/networking/tuntap.html).

## PCAP Replay

PCAP replay accepts classic PCAP files with these link types:

- Ethernet (`LINKTYPE_ETHERNET = 1`), skipping IPv4/IPv6 Ethernet headers
- Raw IP (`LINKTYPE_RAW = 101`)
- IPv4 (`LINKTYPE_IPV4 = 228`)
- IPv6 (`LINKTYPE_IPV6 = 229`)

PCAPNG currently fails with a specific error instead of silently parsing partial data. Convert captures to classic pcap before replaying:

```sh
tshark -F pcap -r capture.pcapng -w capture.pcap
swift run HarnessLocal --pcap capture.pcap --max-packets 500
```

## Linux TUN Runtime

The Linux TUN mode opens a TUN file descriptor and passes it to `TunnelRuntime`. It does not configure routes, DNS, interface addresses, or a SOCKS server for you. That is intentional: on iOS those responsibilities belong to Network Extension settings and the host app, while on Linux they are operating-system setup.

Typical local flow:

```sh
# terminal 1: run a local SOCKS5 server or relay on 127.0.0.1:1080

# terminal 2: start the package dataplane against a real TUN fd
sudo swift run HarnessLocal --tun --name rp0 --duration 30 --socks-port 1080

# terminal 3: configure rp0 and route selected test traffic while the harness is running
sudo ip addr add 10.90.0.2/24 dev rp0
sudo ip link set rp0 up
```

Use the iPhone Example app for final validation of `providerConfiguration`, DNS strategy, MTU strategy, background reconnects, and path transitions.
