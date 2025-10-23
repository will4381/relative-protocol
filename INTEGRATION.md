# Integration Guide

This guide walks through adding Relative Protocol to a new or existing iOS/macOS app with a Packet Tunnel Extension.

## Overview

- Host app depends on `RelativeProtocolCore` to build and validate configuration and to serialize it for the extension.
- Packet Tunnel Extension depends on `RelativeProtocolCore` and `RelativeProtocolTunnel`. The extension delegates tunnel lifecycle to `ProviderController`.
- The Tun2Socks engine is bundled via a binary target; no separate build steps are required for consumers.

## 1) Add the Package (SPM)

- Xcode → File → Add Package Dependencies…
  - URL: `https://github.com/will4381/relative-protocol`
  - Version: select the latest release tag
  - Products to add:
    - Host app target: `RelativeProtocolCore`
    - Packet Tunnel Extension target: `RelativeProtocolCore` and `RelativeProtocolTunnel`

## 2) Create Targets

- Host App: your existing iOS or macOS app target.
- Packet Tunnel Extension: Xcode → File → New → Target… → Network Extension → Packet Tunnel Extension.
  - Name it e.g. `PacketTunnelProvider`.

## 3) Capabilities & Entitlements

- Host app
  - Capabilities → Network Extensions → enable “Packet Tunnel”.
  - The host app does not need `RelativeProtocolTunnel` — only `RelativeProtocolCore` is required.

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

## 5) Build a Configuration in the Host App

Create a `RelativeProtocol.Configuration`, validate it, and serialize it into the `NETunnelProviderProtocol` for the extension.

```swift
import NetworkExtension
import RelativeProtocolCore

func makeConfiguration() -> RelativeProtocol.Configuration {
    let provider = RelativeProtocol.Configuration.Provider(
        mtu: 1500,
        ipv4: .init(
            address: "10.0.0.2",
            subnetMask: "255.255.255.0",
            remoteAddress: "198.51.100.1"
        ),
        dns: .init(servers: ["1.1.1.1", "8.8.8.8"]),
        metrics: .init(isEnabled: true, reportingInterval: 5),
        policies: .init(blockedHosts: ["example.com"]) // optional
    )

    var hooks = RelativeProtocol.Configuration.Hooks()
    hooks.packetTapBatch = { contexts in
        // Observe bursts with low overhead (optional)
        _ = contexts.count
    }

    let configuration = RelativeProtocol.Configuration(
        provider: provider,
        hooks: hooks,
        logging: .init(enableDebug: false)
    )

    // Validate and return
    _ = try? configuration.validateOrThrow()
    return configuration
}

/// Install or update a NETunnelProviderManager and start the tunnel.
func installAndStartTunnel(completion: @escaping (Error?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, _ in
        let manager = managers?.first ?? NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "<your.extension.bundle.identifier>"
        proto.serverAddress = "RelativeProtocol" // Required placeholder

        // Serialize Relative Protocol configuration for the extension
        let cfg = makeConfiguration()
        proto.providerConfiguration = cfg.providerConfigurationDictionary()

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Relative Protocol"
        manager.isEnabled = true

        manager.saveToPreferences { error in
            guard error == nil else { return completion(error) }
            manager.loadFromPreferences { _ in
                do {
                    try manager.connection.startVPNTunnel()
                    completion(nil)
                } catch {
                    completion(error)
                }
            }
        }
    }
}
```

## 6) Optional Hooks & Metrics

- Packet taps
  - Prefer `packetTapBatch` to reduce overhead for high packet rates.
- Event sink
  - Receive `.willStart`, `.didStart`, `.didStop`, `.didFail` from the tunnel.
- Policies
  - Use `policies.blockedHosts` to block specific domains; host matching is optimized for label-boundary checks.

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

