//
//  ConfigurationBuilder.swift
//  RelativeProtocolCore
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/27/2025.
//
//  Provides convenience constructors that assemble common `RelativeProtocol.Configuration`
//  presets (full tunnel and split tunnel) from lightweight value types.
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
        includeAllNetworks: Bool = true,
        excludeLocalNetworks: Bool = false,
        excludedIPv4Routes: [RelativeProtocol.Configuration.Route] = [],
        ipv6: RelativeProtocol.Configuration.IPv6? = nil,
        metrics: RelativeProtocol.Configuration.MetricsOptions = .default,
        policies: RelativeProtocol.Configuration.Policies = .default,
        memory: RelativeProtocol.Configuration.MemoryBudget = .default,
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
                    includedRoutes: [.default],
                    excludedRoutes: excludedIPv4Routes
                ),
                ipv6: ipv6,
                includeAllNetworks: includeAllNetworks,
                excludeLocalNetworks: excludeLocalNetworks,
                dns: .init(servers: dnsServers),
                metrics: metrics,
                policies: policies,
                memory: memory
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
        includeAllNetworks: Bool = false,
        excludeLocalNetworks: Bool = false,
        excludedIPv4Routes: [RelativeProtocol.Configuration.Route] = [],
        ipv6: RelativeProtocol.Configuration.IPv6? = nil,
        metrics: RelativeProtocol.Configuration.MetricsOptions = .default,
        policies: RelativeProtocol.Configuration.Policies = .default,
        memory: RelativeProtocol.Configuration.MemoryBudget = .default,
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
                    includedRoutes: routes,
                    excludedRoutes: excludedIPv4Routes
                ),
                ipv6: ipv6,
                includeAllNetworks: includeAllNetworks,
                excludeLocalNetworks: excludeLocalNetworks,
                dns: .init(servers: dnsServers),
                metrics: metrics,
                policies: policies,
                memory: memory
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

public extension RelativeProtocol.Configuration.IPv6Route {
    static func destination(_ address: String, prefixLength: Int) -> Self {
        Self(destinationAddress: address, networkPrefixLength: prefixLength)
    }
}
