//
//  PacketTunnelSupport.swift
//  RelativeProtocolTunnel
//
//  Lightweight protocols that make the adapter testable without Network Extension hosts.
//

import Foundation
import Network
import NetworkExtension

protocol PacketFlowing: AnyObject {
    func readPackets(_ handler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
    func writePackets(_ packets: [Data], protocols: [NSNumber])
}

protocol PacketTunnelProviding: AnyObject {
    var flow: PacketFlowing { get }
    func makeTCPConnection(to remoteEndpoint: Network.NWEndpoint) -> Network.NWConnection
    func makeUDPConnection(
        to remoteEndpoint: Network.NWEndpoint,
        from localEndpoint: Network.NWEndpoint?
    ) -> Network.NWConnection
}

extension NEPacketTunnelFlow: PacketFlowing {
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
