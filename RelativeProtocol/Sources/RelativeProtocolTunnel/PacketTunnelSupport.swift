//
//  PacketTunnelSupport.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Defines small adapter protocols so the tunnel logic can be exercised without
//  depending directly on Network Extension types in unit tests. Concrete NE
//  types adopt these protocols below.
//

import Foundation
import Network
import NetworkExtension

/// Abstraction over `NEPacketTunnelFlow`.
protocol PacketFlowing: AnyObject {
    func readPackets(_ handler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
    func writePackets(_ packets: [Data], protocols: [NSNumber])
}

/// Abstraction over `NEPacketTunnelProvider`, allowing dependency injection and
/// mocking in tests.
protocol PacketTunnelProviding: AnyObject {
    var flow: PacketFlowing { get }
    func makeTCPConnection(to remoteEndpoint: Network.NWEndpoint) -> Network.NWConnection
    func makeUDPConnection(
        to remoteEndpoint: Network.NWEndpoint,
        from localEndpoint: Network.NWEndpoint?
    ) -> Network.NWConnection
}

extension NEPacketTunnelFlow: PacketFlowing {
    /// Bridges the closure-based interface into the protocol.
    func readPackets(_ handler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        readPackets(completionHandler: handler)
    }

    func writePackets(_ packets: [Data], protocols: [NSNumber]) {
        writePackets(packets, withProtocols: protocols)
    }
}

extension NEPacketTunnelProvider: PacketTunnelProviding {
    var flow: PacketFlowing { packetFlow }

    func makeTCPConnection(to remoteEndpoint: Network.NWEndpoint) -> Network.NWConnection {
        let parameters = Network.NWParameters(tls: nil, tcp: Network.NWProtocolTCP.Options())
        parameters.allowLocalEndpointReuse = true
        parameters.prohibitedInterfaceTypes = [.loopback, .other]
        return Network.NWConnection(to: remoteEndpoint, using: parameters)
    }

    func makeUDPConnection(
        to remoteEndpoint: Network.NWEndpoint,
        from localEndpoint: Network.NWEndpoint?
    ) -> Network.NWConnection {
        let parameters = Network.NWParameters(dtls: nil, udp: Network.NWProtocolUDP.Options())
        parameters.allowLocalEndpointReuse = true
        parameters.prohibitedInterfaceTypes = [.loopback, .other]
        if let localEndpoint {
            parameters.requiredLocalEndpoint = localEndpoint
        }
        return Network.NWConnection(to: remoteEndpoint, using: parameters)
    }
}
