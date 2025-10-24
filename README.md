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
- `RelativeProtocolTunnel`
  - `RelativeProtocolTunnel.ProviderController`
    - **Purpose**: drive an `NEPacketTunnelProvider` using RelativeProtocol abstractions.
    - **Inputs**: `start(configuration:completion:)`, `stop(reason:completion:)`, `handleAppMessage(_:completionHandler:)`.
    - **Output**: manages lifecycle of the gomobile engine, applies network settings, pushes metrics, invokes hooks.
    - **Use when**: implementing the Network Extension target.
  - Internal adapters wrap the vendored Tun2Socks bridge; no public surface beyond the controller.

## Host Integration

```swift
import RelativeProtocolCore

let configuration = RelativeProtocol.Configuration(
    provider: .init(
        mtu: 1500,
        ipv4: .init(
            address: "10.0.0.2",
            subnetMask: "255.255.255.0",
            remoteAddress: "198.51.100.1"
        ),
        dns: .init(servers: ["1.1.1.1", "8.8.8.8"]),
        metrics: .init(isEnabled: true, reportingInterval: 5.0),
        policies: .init(blockedHosts: ["example.com"])
    ),
    hooks: .init(
        packetTap: { context in
            // Observe packets in/out of the tunnel (context.direction, payload, protocolNumber).
        },
        dnsResolver: { host in
            // Optionally supply synthetic DNS answers.
            [host, "2001:db8::1"]
        },
        connectionPolicy: { endpoint in
            // Block clear-text HTTP, allow everything else.
            endpoint.transport == .tcp && endpoint.port == 80
                ? .block(reason: "HTTP disallowed")
                : .allow
        },
        latencyInjector: { endpoint in
            // Inject 200 ms latency for a specific domain.
            endpoint.host.hasSuffix(".slow.example") ? 200 : nil
        },
        eventSink: { event in
            // lifecycle: willStart/didStart/didStop/didFail
            print("Tunnel event: \(event)")
        }
    ),
    logging: .init(enableDebug: true)
)

let warnings = try configuration.validateOrThrow()
warnings.filter { !$0.isError }.forEach { warning in
    print("Relative Protocol warning: \(warning.message)")
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
        controller.start(configuration: configuration, completion: completionHandler)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        controller.stop(reason: reason, completion: completionHandler)
    }
}
```



## Add via Swift Package Manager

You can consume Relative Protocol as an SPM dependency.

- Xcode
  - File → Add Package Dependencies…
  - Enter URL: `https://github.com/will4381/relative-protocol`
  - Choose the latest release tag (v1.0 or newer)
  - Add products you need: `RelativeProtocolCore` and/or `RelativeProtocolTunnel`

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
