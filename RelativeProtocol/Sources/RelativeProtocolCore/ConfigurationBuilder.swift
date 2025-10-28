//
//  ConfigurationBuilder.swift
//  RelativeProtocolCore
//
//  Created by Codex on 10/27/25.
//

import Foundation

public extension RelativeProtocol.Configuration {
    struct Interface: Sendable, Equatable {
        public var address: String
        public var subnetMask: String
        public var remoteAddress: String

        public init(address: String, subnetMask: String, remoteAddress: String) {
            self.address = address
            self.subnetMask = subnetMask
            self.remoteAddress = remoteAddress
        }
    }

    /// Convenience builder for constructing common configuration profiles.
    static func fullTunnel(
        interface: Interface,
        dnsServers: [String],
        mtu: Int = 1500,
        metrics: RelativeProtocol.Configuration.MetricsOptions = .default,
        policies: RelativeProtocol.Configuration.Policies = .default,
        hooks: RelativeProtocol.Configuration.Hooks = .init(),
        logging: RelativeProtocol.Configuration.LoggingOptions = .default
    ) -> RelativeProtocol.Configuration {
        RelativeProtocol.Configuration(
            provider: .init(
                mtu: mtu,
                ipv4: .init(
                    address: interface.address,
                    subnetMask: interface.subnetMask,
                    remoteAddress: interface.remoteAddress,
                    includedRoutes: [.default]
                ),
                dns: .init(servers: dnsServers),
                metrics: metrics,
                policies: policies
            ),
            hooks: hooks,
            logging: logging
        )
    }

    static func splitTunnel(
        interface: Interface,
        routes: [RelativeProtocol.Configuration.Route],
        dnsServers: [String],
        mtu: Int = 1500,
        metrics: RelativeProtocol.Configuration.MetricsOptions = .default,
        policies: RelativeProtocol.Configuration.Policies = .default,
        hooks: RelativeProtocol.Configuration.Hooks = .init(),
        logging: RelativeProtocol.Configuration.LoggingOptions = .default
    ) -> RelativeProtocol.Configuration {
        RelativeProtocol.Configuration(
            provider: .init(
                mtu: mtu,
                ipv4: .init(
                    address: interface.address,
                    subnetMask: interface.subnetMask,
                    remoteAddress: interface.remoteAddress,
                    includedRoutes: routes
                ),
                dns: .init(servers: dnsServers),
                metrics: metrics,
                policies: policies
            ),
            hooks: hooks,
            logging: logging
        )
    }
}

public extension RelativeProtocol.Configuration.Route {
    static func destination(_ address: String, subnetMask: String) -> Self {
        Self(destinationAddress: address, subnetMask: subnetMask)
    }
}
