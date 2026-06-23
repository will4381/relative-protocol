// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
import NetworkExtension

/// One IPv4 route installed on the packet-tunnel interface.
public struct TunnelIPv4Route: Sendable, Equatable {
    public let destinationAddress: String
    public let subnetMask: String

    public init(destinationAddress: String, subnetMask: String) {
        self.destinationAddress = destinationAddress
        self.subnetMask = subnetMask
    }
}

/// IPv4 routing policy for the packet tunnel.
public enum TunnelIPv4RouteStrategy: Sendable, Equatable {
    /// Routes all IPv4 traffic through the tunnel.
    case defaultRoute
    /// Routes only the specified IPv4 destinations through the tunnel.
    case includedRoutes([TunnelIPv4Route])

    public static let defaultFullTunnel = TunnelIPv4RouteStrategy.defaultRoute

    var providerConfiguration: [String: Any] {
        switch self {
        case .defaultRoute:
            return [:]
        case .includedRoutes(let routes):
            let encodedRoutes = routes.map { route in
                [
                    "destinationAddress": route.destinationAddress,
                    "subnetMask": route.subnetMask
                ]
            }
            return [TunnelProviderConfigurationKey.ipv4IncludedRoutes: encodedRoutes]
        }
    }

    var includedRoutes: [NEIPv4Route] {
        switch self {
        case .defaultRoute:
            return [NEIPv4Route.default()]
        case .includedRoutes(let routes):
            return routes.map { route in
                NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
            }
        }
    }

    func normalized() -> TunnelIPv4RouteStrategy {
        switch self {
        case .defaultRoute:
            return .defaultRoute
        case .includedRoutes(let routes) where routes.isEmpty:
            return .defaultRoute
        case .includedRoutes:
            return self
        }
    }
}
