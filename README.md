# Relative Protocol

Portable tunnel components for iOS Network Extension projects. Built to deliver fully on-device VPN/proxy experiences using Apple’s `NEPacketTunnelProvider` API. `RelativeProtocolCore` defines configuration and hook primitives; `RelativeProtocolTunnel` hosts the Network Extension facade and bundles the gomobile-generated Tun2Socks xcframework.

## Performance

When running on-device VPN-style proxies it’s imperative that the tunnel remains lightweight so battery life and latency stay acceptable. Latest results (October 23, 2025):

| Benchmark | Avg Time | Relative Std. Dev. | Notes |
|-----------|----------|--------------------|-------|
| `testAdapterReadLoopPerformance` | 0.005 s (≈5 ms) | 14.1% | NoOp engine; 200 iterations of 1×128B packet reads. |
| `testBlockedHostCacheRebuildPerformance` | 0.000 s (≈0.03 ms) | 59.0% | Append 64 hosts to a 320-host baseline; incremental cache update. |
| `testBlockedHostMatchingPerformance` | 0.013 s (≈13 ms) | 25.6% | 10k hostname checks against a 256-entry block list (warm cache). |
| `testConfigurationLoadPerformance` | 0.019 s (≈19 ms) | 42.0% | 1k loads from `providerConfigurationDictionary()` (JSON round-trip). |
| `testConfigurationValidationPerformance` | 0.004 s (≈4 ms) | 21.9% | Re-validate full configuration repeatedly. |
| `testGoBridgeHandlePacketPerformance` | 0.100 s (≈100 ms) | 32.1% | Swift→Go path using Tun2Socks; 100 iterations of 64×128B packet bursts. |
| `testMetricsCollectorRecordPerformance` | 0.003 s (≈3 ms) | 18.4% | ~10k `record` calls under unfair lock (in/out). |
| `testProviderConfigurationDictionaryPerformance` | 0.001 s (≈1 ms) | 14.6% | 1k serialisations to `providerConfigurationDictionary()` (warm cache). |

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
