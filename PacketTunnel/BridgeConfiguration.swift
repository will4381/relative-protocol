//
//  BridgeConfiguration.swift
//  PacketTunnel
//
//  Defines the prototype configuration surface for the tun2socks bridge.
//

import Foundation

/// Runtime configuration for the prototype bridge.
struct BridgeConfiguration: Codable, Equatable {
    var mtu: Int
    var remoteAddress: String
    var ipv4Address: String
    var ipv4SubnetMask: String
    var dnsServers: [String]
    var enableMetrics: Bool
    var blockedHosts: [String]

    /// Fallback configuration used when the host app has not provided one.
    static let `default` = BridgeConfiguration(
        mtu: 1500,
        remoteAddress: "198.51.100.1", // TEST-NET-2 placeholder
        ipv4Address: "10.0.0.2",
        ipv4SubnetMask: "255.255.255.0",
        dnsServers: ["1.1.1.1", "8.8.8.8"],
        enableMetrics: true,
        blockedHosts: []
    )
}

extension BridgeConfiguration {
    /// Serialises the configuration into an `NEPacketTunnelProvider` dictionary.
    var providerConfiguration: [String: NSObject] {
        guard let data = try? JSONEncoder().encode(self),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: NSObject] else {
            return [:]
        }
        return json
    }

    /// Attempts to decode a configuration payload supplied by the host app.
    static func load(from providerConfiguration: [String: NSObject]?) -> BridgeConfiguration {
        guard
            let providerConfiguration,
            JSONSerialization.isValidJSONObject(providerConfiguration),
            let data = try? JSONSerialization.data(withJSONObject: providerConfiguration),
            let configuration = try? JSONDecoder().decode(BridgeConfiguration.self, from: data)
        else {
            return .default
        }
        return configuration
    }

    func matchesBlocklist(host: String) -> Bool {
        blockedHosts.contains(where: { host.localizedCaseInsensitiveContains($0) })
    }
}
