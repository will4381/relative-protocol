RelativeProtocol
================

A Swift Package that embeds a userspace TCP/IP stack (lwIP) and a socket bridge to forward TUN packets to the Internet on consumer iOS via NEPacketTunnelProvider. Includes hooks for flow classification and per-tag throttling (UDP and TCP), plus basic metrics.

Quick start (Packet Tunnel Provider)
-----------------------------------

1) Entitlements/extension
- Add Network Extension entitlement for Packet Tunnel.
- Create a Packet Tunnel extension target and configure NSExtension in Info.plist.

Entitlements (in your extension target .entitlements)
```xml
<dict>
  <key>com.apple.developer.networking.networkextension</key>
  <array>
    <string>packet-tunnel-provider</string>
  </array>
</dict>
```

Info.plist (in your extension target)
```xml
<key>NSExtension</key>
<dict>
  <key>NSExtensionPointIdentifier</key>
  <string>com.apple.networkextension.packet-tunnel</string>
  <key>NSExtensionPrincipalClass</key>
  <string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
  <!-- Optional: NSExtensionAttributes for on-demand rules -->
</dict>
```

2) Provider wiring
```swift
import NetworkExtension
import RelativeProtocol

final class PacketTunnelProvider: NEPacketTunnelProvider, RelativeProtocolEngine.PolicyProvider {
    private var engine: RelativeProtocolEngine?

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "100.64.0.1")
        settings.ipv4Settings = NEIPv4Settings(addresses: ["100.64.0.2"], subnetMasks: ["255.255.255.0"]) 
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.ipv6Settings = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
        settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
        settings.mtu = 1500
        // DNS servers and match domains
        let dns = NEDNSSettings(servers: ["1.1.1.1", "2606:4700:4700::1111"]) 
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        // Optional: keep local LAN reachable by excluding private ranges
        settings.ipv4Settings?.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0")
        ]

        setTunnelNetworkSettings(settings) { [weak self] err in
            guard let self = self, err == nil else { completionHandler(err); return }
            let eng = RelativeProtocolEngine(packetFlow: self.packetFlow)
            eng.policyProvider = self
            if #available(iOS 12.0, *) { eng.updateMTU(from: settings) }
            eng.start()
            self.engine = eng
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        engine?.stop()
        completionHandler()
    }

    // PolicyProvider: classify flows and set throttles
     func onNewFlow(metadata: RelativeProtocolEngine.FlowMetadata) -> String? {
        // Example: tag UDP/443 as "quic"
        if metadata.transport == "UDP" && metadata.destinationPort == 443 { return "quic" }
        return nil
    }

    func updateThrottle(tag: String, bytesPerSecond: Int) {
        engine?.updateThrottle(tag: tag, bytesPerSecond: bytesPerSecond)
    }

    func shouldDrop(flow: RelativeProtocolEngine.FlowMetadata) -> Bool { false }
}
```

3) Optional runtime control & logging
- Call `engine?.updateThrottle(tag: "quic", bytesPerSecond: 200_000)` to slow QUIC.
- Toggle passthrough (no shaping): `engine?.setPassthroughMode(true)`.
- Sleep/wake: `engine?.quiesce()` before sleep and `engine?.resume()` on wake.
- Path changes: engine observes `NWPathMonitor`; adjust MSS with `updateMTU` if provider MTU changes.
- Logging API (enable/disable and levels):
  - Set level programmatically: `Logger.shared.setLevel(.trace | .debug | .info | .warn | .error)`
  - Or from a string (e.g., app message/arguments): `Logger.shared.setLevel(from: "DEBUG")`
  - Enable/disable all output (useful for perf): `Logger.shared.setEnabled(true/false)`
  - Logs appear as: `[RelativeProtocol][<ISO8601_Timestamp>][LEVEL] Message`
  - `SocketBridge` emits connection state transitions for TCP/UDP to help diagnose egress issues

Testing notes
-------------
- Unit tests run on macOS and stub the lwIP C symbols; on-device builds link the full lwIP core.
- Use a real device to test the `NEPacketTunnelProvider` flow; Simulator does not support Packet Tunnel.

Capabilities
------------
- lwIP host-mode stack with custom netifs: `tunif` (OS side) and `proxynetif` (terminating proxy).
- Internet egress over Network.framework sockets (TCP/UDP). No raw IP.
- UDP and TCP return-path synthesis (IPv4/IPv6), incl. ICMP/ICMPv6 for UDP errors.
- Per-tag throttling (UDP and TCP) via token-bucket limiters.
- MTU→MSS clamp propagation to reduce fragmentation on cellular paths.
- Configurable TCP advertised window via `SocketBridge.setTCPWindow(bytes:)`.
- Basic metrics counters with snapshot API.

Notes
-----
- This repo targets consumer iOS. Testing must be done on device (Simulator not supported for Packet Tunnel).
- Start with permissive throttles and iterate; aggressive shaping can impact app UX (especially QUIC video).
- The TCP bridge implements initial correctness; further tuning for window/close behavior is planned.
- Provider can configure excluded routes (e.g., local LAN subnets) via `NEPacketTunnelNetworkSettings` as needed.
- QUIC/HTTP3: For UDP/443, prefer tagging flows (e.g., "quic") via `PolicyProvider` and apply distinct throttling via `updateThrottle(tag:bytesPerSecond:)`. Increase UDP receive buffers in the host app if needed; package pacing remains per-tag.
- DNS strategy: Choose resolvers in the provider settings (`NEDNSSettings`) and optionally maintain a domain→IP cache in the host app for classification (app side). The package exposes `FlowMetadata` and `FlowID` to correlate.

Roadmap / Future enhancements
-----------------------------
- Token bucket unification: internal refactor to share a single `TokenBucketLimiter` for UDP/TCP pacing.
- Watchdog: detect stalled flows (no activity over N seconds), log, and optionally prune with RST/ICMP.
- Window tuning: optional faster timer tick under load and adaptive sender window derived from lwIP state.
- Buffer pooling: small slab/ring buffers for C netifs to reduce malloc/free churn.
- os_signpost instrumentation: expand spans around critical paths (ingest→parse→bridge→inject) for profiling.
- Provider docs: NAT64/IPv6-only examples, QUIC heuristics via tagging, and DNS policy patterns.

lwIP updates
------------
- To refresh the vendored lwIP sources, use the helper script:
  - `scripts/fetch_lwip.sh`
  - Documented to fetch/update the subtree under `third_party/lwip/` in a reproducible way.

Async packet ingestion (optional)
---------------------------------
- For push-style consumption of tunnel packets, you can use the async façade:
  - `for await packet in PacketIngestor.packets(from: packetFlow) { engine.ingestPacket(packet.data, proto: packet.proto) }`
  - The engine still supports direct `ingestPacket(s)` calls.


