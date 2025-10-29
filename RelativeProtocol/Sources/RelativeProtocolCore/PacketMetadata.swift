//
//  PacketMetadata.swift
//  RelativeProtocolCore
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only.
//

import Foundation
import Darwin

public extension RelativeProtocol {
    struct PacketMetadata: Sendable {
        public enum Network: Sendable {
            case ipv4
            case ipv6
        }

        public enum Transport: Sendable {
            case tcp(sourcePort: UInt16, destinationPort: UInt16)
            case udp(sourcePort: UInt16, destinationPort: UInt16)
            case other(number: UInt8)

            public var sourcePort: UInt16? {
                switch self {
                case let .tcp(port, _), let .udp(port, _):
                    return port
                case .other:
                    return nil
                }
            }

            public var destinationPort: UInt16? {
                switch self {
                case let .tcp(_, port), let .udp(_, port):
                    return port
                case .other:
                    return nil
                }
            }
        }

        public var network: Network
        public var sourceAddress: String
        public var destinationAddress: String
        public var transport: Transport

        public func remoteAddress(for direction: RelativeProtocol.Direction) -> String {
            switch direction {
            case .inbound:
                return sourceAddress
            case .outbound:
                return destinationAddress
            }
        }

        public func localAddress(for direction: RelativeProtocol.Direction) -> String {
            switch direction {
            case .inbound:
                return destinationAddress
            case .outbound:
                return sourceAddress
            }
        }
    }
}

enum PacketMetadataParser {
    static func parse(packet: Data, hintProtocolNumber: Int32?) -> RelativeProtocol.PacketMetadata? {
        guard let firstByte = packet.first else { return nil }
        let version = firstByte >> 4
        switch version {
        case 4:
            return parseIPv4(packet: packet, hintProtocolNumber: hintProtocolNumber)
        case 6:
            return parseIPv6(packet: packet, hintProtocolNumber: hintProtocolNumber)
        default:
            return nil
        }
    }

    private static func parseIPv4(packet: Data, hintProtocolNumber: Int32?) -> RelativeProtocol.PacketMetadata? {
        guard packet.count >= 20 else { return nil }
        let ihl = Int(packet[0] & 0x0F) * 4
        guard ihl >= 20, packet.count >= ihl else { return nil }
        let protocolNumber = packet[9]
        let srcIP = ipv4String(packet[12..<16])
        let dstIP = ipv4String(packet[16..<20])

        let payloadStart = ihl
        let transport = parseTransport(
            protocolNumber: protocolNumber,
            payload: packet[payloadStart...],
            fallback: hintProtocolNumber
        )

        return RelativeProtocol.PacketMetadata(
            network: .ipv4,
            sourceAddress: srcIP,
            destinationAddress: dstIP,
            transport: transport
        )
    }

    private static func parseIPv6(packet: Data, hintProtocolNumber: Int32?) -> RelativeProtocol.PacketMetadata? {
        let headerLength = 40
        guard packet.count >= headerLength else { return nil }
        let nextHeader = packet[6]
        let srcIP = ipv6String(packet[8..<24])
        let dstIP = ipv6String(packet[24..<40])
        let payloadStart = headerLength

        let transport = parseTransport(
            protocolNumber: nextHeader,
            payload: packet[payloadStart...],
            fallback: hintProtocolNumber
        )

        return RelativeProtocol.PacketMetadata(
            network: .ipv6,
            sourceAddress: srcIP,
            destinationAddress: dstIP,
            transport: transport
        )
    }

    private static func parseTransport(
        protocolNumber: UInt8,
        payload: Data.SubSequence,
        fallback: Int32?
    ) -> RelativeProtocol.PacketMetadata.Transport {
        switch protocolNumber {
        case 6: // TCP
            guard payload.count >= 4 else { return .other(number: protocolNumber) }
            let source = readUInt16(payload, offset: 0)
            let destination = readUInt16(payload, offset: 2)
            return .tcp(sourcePort: source, destinationPort: destination)
        case 17: // UDP
            guard payload.count >= 4 else { return .other(number: protocolNumber) }
            let source = readUInt16(payload, offset: 0)
            let destination = readUInt16(payload, offset: 2)
            return .udp(sourcePort: source, destinationPort: destination)
        default:
            if let fallback, fallback != 0 {
                let value = UInt8(truncatingIfNeeded: fallback)
                return .other(number: value)
            }
            return .other(number: protocolNumber)
        }
    }

    private static func ipv4String(_ bytes: Data.SubSequence) -> String {
        return bytes.map { String($0) }.joined(separator: ".")
    }

    private static func ipv6String(_ bytes: Data.SubSequence) -> String {
        return bytes.withUnsafeBytes { rawBuffer -> String in
            guard let baseAddress = rawBuffer.baseAddress else { return "" }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            if inet_ntop(AF_INET6, baseAddress, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                return String(cString: buffer)
            }
            return ""
        }
    }

    private static func readUInt16(_ data: Data.SubSequence, offset: Int) -> UInt16 {
        let index0 = data.index(data.startIndex, offsetBy: offset)
        let index1 = data.index(data.startIndex, offsetBy: offset + 1)
        return (UInt16(data[index0]) << 8) | UInt16(data[index1])
    }
}
