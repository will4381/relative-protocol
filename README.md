# Relative Protocol

Portable tunnel components for iOS Network Extension projects. Built to deliver fully on-device VPN/proxy experiences using Apple’s `NEPacketTunnelProvider` API. `RelativeProtocolCore` defines configuration and hook primitives; `RelativeProtocolTunnel` hosts the Network Extension facade and bundles the gomobile-generated Tun2Socks xcframework.

## Performance

When running on-device VPN-style proxies it’s imperative that the tunnel remains lightweight so battery life and latency stay acceptable. Latest results (October 24, 2025):

| Benchmark | Avg Time | Relative Std. Dev. | Notes |
|-----------|----------|--------------------|-------|
| `testAdapterReadLoopPerformance` | 0.0012 s (≈1.2 ms) | 6.6% | NoOp engine; 200 iterations of single 128 B packet reads. |
| `testBlockedHostLookupPerformance` | 1.283 s | 1.7% | 5k blocked-host patterns evaluated against 5k candidate hostnames. |
| `testConfigurationSerializationPerformance` | 0.0370 s (≈37 ms) | 32.6% | 1k round-trips through `providerConfigurationDictionary()`. |
| `testConfigurationValidationPerformance` | 0.0044 s (≈4.4 ms) | 22.6% | 500 calls to `validateOrThrow()` on a warm configuration. |
| `testMetricsCollectorConnectionTrackingPerformance` | 0.0100 s (≈10 ms) | 20.3% | 10k TCP/UDP adjustments with periodic synthetic error logging. |
| `testMetricsCollectorRecordPerformance` | 0.0232 s (≈23 ms) | 13.7% | 5k inbound/outbound record pairs on the metrics queue. |

## Modules

- `RelativeProtocolCore`
  - `RelativeProtocol.Configuration`
    - **Purpose**: describe tunnel runtime parameters.
    - **Inputs**: MTU (`Int`), IPv4 settings (`IPv4`), DNS servers/search domains (`DNS`), metrics options (`MetricsOptions`), policies (`Policies`), hooks (`Hooks`).
    - **Output**: validated configuration passed to `ProviderController.start`.
    - **Use when**: preparing a tunnel session or serialising data to/from `NETunnelProviderProtocol.providerConfiguration`.
    - Call `validateOrThrow()` to receive `[ValidationMessage]`; throws `RelativeProtocol.PackageError.invalidConfiguration` on fatal issues.
    - Helpers: `RelativeProtocol.Configuration.fullTunnel(...)` and `splitTunnel(...)` provide convenient presets when building standard configurations, with `RelativeProtocol.Configuration.Interface` describing the virtual interface and `RelativeProtocol.Configuration.Route.destination(_:subnetMask:)` for custom route entries.
  - `RelativeProtocol.Configuration.LoggingOptions`
    - **Purpose**: toggle debug logging across the tunnel stack.
    - **Inputs**: `enableDebug` (`Bool`) defaulting to `false`.
    - **Use when**: enabling verbose diagnostics for development or performance testing.
  - `RelativeProtocol.Configuration.Hooks`
    - **Purpose**: inject custom behaviour.
    - **Inputs**: optional closures `packetTap(context)`, `dnsResolver(host) async throws -> [String]`, `connectionPolicy(endpoint) async -> ConnectionDecision`, `latencyInjector(endpoint) async -> Int?`, `eventSink(event)`.
    - **Output**: callbacks invoked by the tunnel runtime (packet inspection, DNS overrides, connection policy decisions, latency shaping, lifecycle reporting).
    - **Use when**: you need to observe packet flow, provide custom DNS answers, enforce allow/deny lists, inject synthetic latency, or surface tunnel state changes to the host app.
  - `RelativeProtocol.Configuration.ValidationMessage`
    - **Properties**: `message: String`, `isError: Bool`, `severityLabel: "warning" | "error"`.
    - **Use when**: presenting validation results to the caller.
  - `RelativeProtocol.MetricsSnapshot`
    - **Purpose**: convey periodic counters.
    - **Fields**: `timestamp`, `inbound`/`outbound` counters (`packets`, `bytes`), `activeTCP`, `activeUDP`, and collected `ErrorEvent`s.
    - **Use when**: metrics sink is supplied via configuration.
  - `RelativeProtocol.DNSClient`
    - **Purpose**: perform lightweight forward (`resolve(host:)`) and reverse (`reverseLookup(address:)`) DNS lookups using the platform resolver.
    - **Use when**: supplementing packet analytics with hostname data in both host apps and the tunnel.
- `RelativeProtocolTunnel`
  - `RelativeProtocolTunnel.ProviderController`
    - **Purpose**: drive an `NEPacketTunnelProvider` using RelativeProtocol abstractions.
    - **Inputs**: `start(configuration:completion:)`, `stop(reason:completion:)`, `handleAppMessage(_:completionHandler:)`.
    - **Output**: manages lifecycle of the gomobile engine, applies network settings, pushes metrics, invokes hooks.
    - **Use when**: implementing the Network Extension target.
  - Internal adapters wrap the vendored Tun2Socks bridge; no public surface beyond the controller.
- `RelativeProtocolHost`
  - `RelativeProtocolHost.Controller`
    - **Purpose**: manage `NETunnelProviderManager` lifecycle from the host app.
    - **Inputs**: `prepareIfNeeded(descriptor:)`, `configure(descriptor:)`, `connect()`, `disconnect()`.
    - **Outputs**: `@Published` properties for `status`, `isBusy`, `isConfigured`, `lastError`; exposes a `ControlChannel` for in-tunnel messaging.
    - **Use when**: you want a high-level tunnel facade without rewriting manager persistence, status observation, and connection orchestration.
  - `RelativeProtocolHost.ControlChannel`
    - **Purpose**: send typed control messages to the tunnel using async/await.
    - **Inputs**: Encodable requests, optional Decodable response types.
    - **Use when**: fetching metrics, clearing caches, or invoking custom commands exposed by your `NEPacketTunnelProvider`.
  - `RelativeProtocolHost.Probe`
    - **Purpose**: built-in TCP and HTTPS probes for diagnostics.
    - **Use when**: quickly verifying outbound reachability without adding bespoke NWConnection or URLSession code in every host.

## Host Integration

```swift
import Combine
import RelativeProtocolCore
import RelativeProtocolHost

@MainActor
final class TunnelViewModel: ObservableObject {
    private let controller = RelativeProtocolHost.Controller()
    private var cancellables = Set<AnyCancellable>()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var isBusy = false
    @Published private(set) var lastError: String?

    init() {
        controller.$status
            .sink { [weak self] in self?.status = $0 }
            .store(in: &cancellables)
        controller.$isBusy
            .sink { [weak self] in self?.isBusy = $0 }
            .store(in: &cancellables)
        controller.$lastError
            .sink { [weak self] in self?.lastError = $0 }
            .store(in: &cancellables)
    }

    func prepare() async throws {
        let interface = RelativeProtocol.Configuration.Interface(
            address: "10.0.0.2",
            subnetMask: "255.255.255.0",
            remoteAddress: "198.51.100.1"
        )
        let configuration = RelativeProtocol.Configuration.fullTunnel(
            interface: interface,
            dnsServers: ["1.1.1.1", "8.8.8.8"],
            policies: .init(blockedHosts: ["example.com"]),
            hooks: .init(eventSink: { print("Tunnel event: \($0)") })
        )

        let descriptor = RelativeProtocolHost.TunnelDescriptor(
            providerBundleIdentifier: "com.example.MyApp.Tunnel",
            localizedDescription: "MyApp Tunnel",
            configuration: configuration,
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

    func fetchSites() async throws -> [String] {
        struct Command: Encodable { var command = "events"; var limit = 50 }
        struct Response: Decodable { var sites: [String] }
        let response = try await controller.controlChannel.send(Command(), expecting: Response.self)
        return response.sites
    }
}
```

## Packet Tunnel Integration

```swift
import RelativeProtocolTunnel
import RelativeProtocolCore

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var controller = RelativeProtocolTunnel.ProviderController(provider: self)

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let configuration = RelativeProtocol.Configuration.load(from: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration)
        controller.setFilterConfiguration(.init(evaluationInterval: 1.0))
        controller.configureFilters { coordinator in
            coordinator.register(MyBurstFilter())
        }
        controller.start(configuration: configuration, completion: completionHandler)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        controller.stop(reason: reason, completion: completionHandler)
    }
}

struct MyBurstFilter: TrafficFilter {
    let identifier = "demo.burst"

    func evaluate(snapshot: [RelativeProtocol.PacketSample], emit: @escaping @Sendable (RelativeProtocol.TrafficEvent) -> Void) {
        let inboundBytes = snapshot
            .filter { $0.direction == .inbound }
            .reduce(0) { $0 + $1.byteCount }
        guard inboundBytes > 1_000_000 else { return }
        let event = RelativeProtocol.TrafficEvent(
            category: .burst,
            confidence: .medium,
            details: [
                "bytes": String(inboundBytes),
                "window": "120"
            ]
        )
        emit(event)
    }
}
```

### Example App

The bundled Example app now exposes a Traffic Analysis panel:
- Fetch recent `TrafficEvent` bursts from the tunnel and inspect their metadata.
- Adjust the burst detector threshold (in MB) and push updates to the filter pipeline.
- Clear the tunnel-side event buffer to start fresh during demos.
- Tune the global latency injector (0–500 ms) to visualise the impact of artificial delay on traffic.
- View resolved remote IPs and hostnames for each detected burst for quick triage.



## Add via Swift Package Manager

You can consume Relative Protocol as an SPM dependency.

- Xcode
  - File → Add Package Dependencies…
  - Enter URL: `https://github.com/will4381/relative-protocol`
  - Choose the latest release tag (v1.0 or newer)
  - Add products you need: `RelativeProtocolCore`, `RelativeProtocolHost`, and/or `RelativeProtocolTunnel`

- Package.swift

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "YourApp",
    platforms: [ .iOS(.v15), .macOS(.v14) ],
    dependencies: [
        .package(url: "https://github.com/will4381/relative-protocol", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "YourApp",
            dependencies: [
                .product(name: "RelativeProtocolCore", package: "relative-protocol"),
                .product(name: "RelativeProtocolHost", package: "relative-protocol"),
                .product(name: "RelativeProtocolTunnel", package: "relative-protocol"),
            ]
        ),
    ]
)
```

## Rebuilding Tun2Socks

Run `./Scripts/build.sh` after modifying the Go sources in `ThirdParty/tun2socks/`. The script regenerates `RelativeProtocol/Binary/Tun2Socks.xcframework` using local Go caches; commit the refreshed binary.

## Licensing

Project code is offered for personal, non-commercial use under the terms in `LICENSE`.
Upstream licensing for the vendored bridge is preserved in `ThirdParty/tun2socks/LICENSE`.
