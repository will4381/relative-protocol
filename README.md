# Relative Protocol

Portable tunnel components for iOS Network Extension projects. Built to deliver fully on-device VPN/proxy experiences using Apple’s `NEPacketTunnelProvider` API. `RelativeProtocolCore` defines configuration and hook primitives; `RelativeProtocolTunnel` hosts the Network Extension facade and bundles the gomobile-generated Tun2Socks xcframework.

## Performance

When running on-device VPN-style proxies it’s imperative that the tunnel remains lightweight so battery life and latency stay acceptable. Baselines collected on October 22nd 2025:

| Benchmark | Avg Time | Relative Std. Dev. | Notes |
|-----------|----------|--------------------|-------|
| `testAdapterReadLoopPerformance` | ~6 ms | ~8% | NoOp engine, hooks + debug logging enabled, 200 burst iterations. |
| `testConfigurationValidationPerformance` | ~4 ms | ~20% | Repeated validation of full configuration payload. |
| `testMetricsCollectorRecordPerformance` | ~23 ms (10k ops) | ~14% | Aggregation and log emission every 5k in/out records. |

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
    - **Inputs**: optional closures `packetTap(context)`, `dnsResolver(host) async -> [String]`, `connectionPolicy(endpoint) async -> ConnectionDecision`, `latencyInjector(endpoint) async -> Int?`, `eventSink(event)`.
    - **Output**: callbacks invoked by the tunnel runtime.
    - **Use when**: observing packet flow, implementing DNS overrides, enforcing block/latency policies, or tracking lifecycle events.
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
            // observe packets in/out of the tunnel
        },
        latencyInjector: { endpoint in
            // Inject 200 ms latency for specific hosts, else nil
            if endpoint.transport == .tcp && endpoint.host.hasSuffix(".slow.example") {
                return 200
            }
            return nil
        },
        eventSink: { event in
            // lifecycle: willStart/didStart/didStop/didFail
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

## Rebuilding Tun2Socks

Run `./Scripts/build.sh` after modifying the Go sources in `ThirdParty/tun2socks/`. The script regenerates `RelativeProtocol/Binary/Tun2Socks.xcframework` using local Go caches; commit the refreshed binary.

## Licensing

Project code is offered for personal, non-commercial use under the terms in `LICENSE`.
Upstream licensing for the vendored bridge is preserved in `ThirdParty/tun2socks/LICENSE`.
