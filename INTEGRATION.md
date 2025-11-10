# Integration Guide

This guide walks through adding Relative Protocol to a new or existing iOS/macOS app with a Packet Tunnel Extension.

## Overview

- Host app depends on `RelativeProtocolCore` for configuration primitives and `RelativeProtocolHost` for high-level tunnel lifecycle, control messaging, and diagnostics.
- Packet Tunnel Extension depends on `RelativeProtocolCore` and `RelativeProtocolTunnel`. The extension delegates tunnel lifecycle to `ProviderController`.
- The Engine binary is bundled via a binary target; no separate build steps are required for consumers.

## 1) Add the Package (SPM)

- Xcode → File → Add Package Dependencies…
  - URL: `https://github.com/will4381/relative-protocol`
  - Version: select the latest release tag
  - Products to add:
    - Host app target: `RelativeProtocolCore`, `RelativeProtocolHost`
    - Packet Tunnel Extension target: `RelativeProtocolCore` and `RelativeProtocolTunnel`

## 2) Create Targets

- Host App: your existing iOS or macOS app target.
- Packet Tunnel Extension: Xcode → File → New → Target… → Network Extension → Packet Tunnel Extension.
  - Name it e.g. `PacketTunnelProvider`.

## 3) Capabilities & Entitlements

- Host app
  - Capabilities → Network Extensions → enable “Packet Tunnel”.
  - Link `RelativeProtocolHost` to use the provided controller and diagnostics helpers.

- Packet Tunnel Extension
  - Capabilities → Network Extensions → enable “Packet Tunnel”.
  - Ensure `NSExtension` in the extension’s Info contains:
    - `NSExtensionPointIdentifier`: `com.apple.networkextension.packet-tunnel`

Note: Distribution on the App Store requires Apple VPN entitlements. For internal use and development, developer profiles suffice.

## 4) Implement the Packet Tunnel Extension

In your extension target, adopt the high-level controller from `RelativeProtocolTunnel`.

```swift
import NetworkExtension
import RelativeProtocolCore
import RelativeProtocolTunnel

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var controller = RelativeProtocolTunnel.ProviderController(provider: self)

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // Load configuration passed from the host app
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let configuration = RelativeProtocol.Configuration.load(from: providerConfig)
        controller.start(configuration: configuration, completion: completionHandler)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        controller.stop(reason: reason, completion: completionHandler)
    }
}
```

## 5) Configure the Tunnel from the Host App

`RelativeProtocolHost.Controller` wraps `NETunnelProviderManager` so the host can focus on configuration and control-plane messaging.

```swift
import Combine
import NetworkExtension
import RelativeProtocolCore
import RelativeProtocolHost

@MainActor
final class TunnelCoordinator: ObservableObject {
    private let controller = RelativeProtocolHost.Controller()
    private var cancellables = Set<AnyCancellable>()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastError: String?

    init() {
        controller.$status
            .sink { [weak self] in self?.status = $0 }
            .store(in: &cancellables)
        controller.$lastError
            .sink { [weak self] in self?.lastError = $0 }
            .store(in: &cancellables)
    }

    func prepareIfNeeded() async throws {
        let interface = RelativeProtocol.Configuration.Interface(
            address: "10.0.0.2",
            subnetMask: "255.255.255.0",
            remoteAddress: "198.51.100.1"
        )

        let configuration = RelativeProtocol.Configuration.fullTunnel(
            interface: interface,
            dnsServers: ["1.1.1.1", "8.8.8.8"],
            includeAllNetworks: false,
            excludeLocalNetworks: false,
            excludedIPv4Routes: [
                .destination("17.0.0.0", subnetMask: "255.0.0.0")
            ],
            ipv6: .init(
                addresses: ["fd00:1::2"],
                networkPrefixLengths: [64],
                excludedRoutes: [
                    .destination("2403:300::", prefixLength: 32),
                    .destination("2620:149::", prefixLength: 32)
                ]
            ),
            policies: .init(blockedHosts: ["example.com"]),
            hooks: .init(eventSink: { print("Tunnel event: \($0)") })
        )

        let descriptor = RelativeProtocolHost.TunnelDescriptor(
            providerBundleIdentifier: "<your.extension.bundle.identifier>",
            localizedDescription: "Relative Protocol",
            configuration: configuration,
            includeAllNetworks: false,
            excludeLocalNetworks: false,
            excludeAPNs: true,
            validateConfiguration: true
        )

        try await controller.prepareIfNeeded(descriptor: descriptor)
    }

    func connect() async throws {
        try await controller.connect()
    }

    func disconnect() {
        controller.disconnect()
    }

    func fetchEvents(limit: Int = 50) async throws -> [String] {
        struct Command: Encodable { var command = "events"; var limit: Int }
        struct Response: Decodable { var sites: [String] }
        return try await controller.controlChannel
            .send(Command(limit: limit), expecting: Response.self)
            .sites
    }

    func runProbes() async {
        let tcp = await RelativeProtocolHost.Probe.tcp(host: "1.1.1.1", port: 443)
        print("TCP probe:", tcp.message)
        let https = await RelativeProtocolHost.Probe.https(url: URL(string: "https://www.apple.com")!)
        print("HTTPS probe:", https.message)
    }
}
```

`RelativeProtocol.Configuration.fullTunnel` and `splitTunnel` helper functions provide concise presets, while `RelativeProtocol.DNSClient` can supplement analytics with forward/reverse lookups when needed.

## 6) Optional Hooks & Metrics

- Packet taps
  - `packetTap` receives individual packets with direction, payload, and protocol metadata.
- Use `dnsResolver` and `connectionPolicy` to override network behaviour; these closures can perform async work.
- Packet analysis
  - Provide `packetStreamBuilder` to buffer packets for the built-in filter pipeline.
  - Use `trafficEventBusBuilder` to observe normalized `TrafficEvent` output sent from the extension.
  - Access `providerController.forwardHostTracker` to map CDN edges back to the original service hostname; the tracker caches mappings for 10 minutes and coalesces duplicate lookups.
- Event sink
  - Receive `.willStart`, `.didStart`, `.didStop`, `.didFail` from the tunnel.
- Policies
- Use `policies.blockedHosts` to block specific domains; host matching is optimized for label-boundary checks.

### Filter Pipeline

Inside your `NEPacketTunnelProvider`, configure the coordinator before calling `start`:

```swift
controller.setFilterConfiguration(.init(evaluationInterval: 1.0))
controller.configureFilters { coordinator in
    coordinator.register(MyCustomFilter())
}
```

Filters conform to `TrafficFilter` and analyze buffered packets to emit normalized events:

```swift
struct MyCustomFilter: TrafficFilter {
    let identifier = "com.example.custom-filter"

    func evaluate(snapshot: UnsafeBufferPointer<RelativeProtocol.PacketSample>, emit: @escaping @Sendable (RelativeProtocol.TrafficEvent) -> Void) {
        let outbound = snapshot.lazy.filter { $0.direction == .outbound }
        let totalBytes = outbound.reduce(0) { $0 + $1.byteCount }
        guard totalBytes > 250_000 else { return }
        emit(RelativeProtocol.TrafficEvent(
            category: .observation,
            confidence: .medium,
            details: ["outboundBytes": String(totalBytes)]
        ))
    }
}
```

## 7) Exchanging Messages (Optional)

The extension implements `handleAppMessage(_:completionHandler:)`. From the host, send messages via `manager.connection as? NETunnelProviderSession`:

```swift
func pingExtension(_ manager: NETunnelProviderManager) throws {
    guard let session = manager.connection as? NETunnelProviderSession else { return }
    try session.sendProviderMessage(Data("ping".utf8)) { reply in
        // reply is Data("ack") in the sample implementation
        _ = reply
    }
}
```

## 8) Build & Test

- Build the host app and extension.
- Start the tunnel from the host app (or Settings if you expose a VPN configuration).
- Use the performance tests as references for expected latency of hot paths.

## Troubleshooting

- Missing entitlement errors
  - Ensure both targets have the Network Extensions capability with Packet Tunnel enabled.
- Extension not starting
  - Verify `providerBundleIdentifier` matches the extension’s bundle identifier and that `serverAddress` is non-empty.
- SPM import fails
  - Ensure you reference the repository URL and pick a tagged release.
