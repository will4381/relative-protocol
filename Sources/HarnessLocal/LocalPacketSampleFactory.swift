// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Analytics
import Foundation

enum LocalPacketSampleFactory {
    static func makeSample(
        packet: Data,
        timestamp: Date,
        direction: String,
        sequence: Int
    ) -> PacketSample {
        let metadata = PacketMetadata(packet: packet)
        return PacketSample(
            timestamp: timestamp,
            direction: direction,
            flowId: metadata.flowID(sequence: sequence, packet: packet),
            bytes: packet.count,
            packetCount: 1,
            flowPacketCount: 1,
            flowByteCount: packet.count,
            protocolHint: metadata.protocolHint,
            ipVersion: metadata.ipVersion,
            transportProtocolNumber: metadata.transportProtocolNumber,
            sourceAddress: metadata.sourceAddress,
            sourcePort: metadata.sourcePort,
            destinationAddress: metadata.destinationAddress,
            destinationPort: metadata.destinationPort
        )
    }
}

private struct PacketMetadata {
    private static let maxIPv6Extensions = 8
    private static let ipv6ExtensionHeaders: Set<UInt8> = [0, 43, 44, 51, 60]

    let ipVersion: UInt8?
    let transportProtocolNumber: UInt8?
    let sourceAddress: String?
    let sourcePort: UInt16?
    let destinationAddress: String?
    let destinationPort: UInt16?

    init(packet: Data) {
        let bytes = [UInt8](packet)
        guard let first = bytes.first else {
            ipVersion = nil
            transportProtocolNumber = nil
            sourceAddress = nil
            sourcePort = nil
            destinationAddress = nil
            destinationPort = nil
            return
        }

        switch first >> 4 {
        case 4:
            let parsed = Self.parseIPv4(bytes)
            ipVersion = parsed.ipVersion
            transportProtocolNumber = parsed.transportProtocolNumber
            sourceAddress = parsed.sourceAddress
            sourcePort = parsed.sourcePort
            destinationAddress = parsed.destinationAddress
            destinationPort = parsed.destinationPort
        case 6:
            let parsed = Self.parseIPv6(bytes)
            ipVersion = parsed.ipVersion
            transportProtocolNumber = parsed.transportProtocolNumber
            sourceAddress = parsed.sourceAddress
            sourcePort = parsed.sourcePort
            destinationAddress = parsed.destinationAddress
            destinationPort = parsed.destinationPort
        default:
            ipVersion = nil
            transportProtocolNumber = nil
            sourceAddress = nil
            sourcePort = nil
            destinationAddress = nil
            destinationPort = nil
        }
    }

    var protocolHint: String {
        switch transportProtocolNumber {
        case 1:
            return "icmp"
        case 6:
            return "tcp"
        case 17:
            return "udp"
        case 58:
            return "icmpv6"
        case .some:
            return "ip"
        case nil:
            return "unknown"
        }
    }

    func flowID(sequence: Int, packet: Data) -> String {
        var hash = UInt64(14_695_981_039_346_656_037)
        func mix(_ byte: UInt8) {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }

        if let ipVersion {
            mix(ipVersion)
        }
        if let transportProtocolNumber {
            mix(transportProtocolNumber)
        }
        for scalar in [sourceAddress, destinationAddress].compactMap({ $0 }) {
            scalar.utf8.forEach(mix)
        }
        for port in [sourcePort, destinationPort].compactMap({ $0 }) {
            mix(UInt8(port >> 8))
            mix(UInt8(port & 0x00ff))
        }
        if sourceAddress == nil, destinationAddress == nil {
            packet.prefix(96).forEach(mix)
            mix(UInt8(sequence & 0x00ff))
        }
        return "flow-\(String(hash, radix: 16))"
    }

    private static func parseIPv4(_ bytes: [UInt8]) -> PacketMetadata {
        guard bytes.count >= 20 else {
            return PacketMetadata.empty(ipVersion: 4)
        }
        let headerLength = Int(bytes[0] & 0x0f) * 4
        guard headerLength >= 20, bytes.count >= headerLength else {
            return PacketMetadata.empty(ipVersion: 4)
        }
        let declaredLength = Int(readUInt16(bytes, offset: 2))
        guard declaredLength >= headerLength, declaredLength <= bytes.count else {
            return PacketMetadata.empty(ipVersion: 4)
        }
        let packet = declaredLength == bytes.count ? bytes : Array(bytes.prefix(declaredLength))
        let transport = packet[9]
        let fragmentField = readUInt16(packet, offset: 6)
        let fragmentOffset = fragmentField & 0x1fff
        let ports: (source: UInt16?, destination: UInt16?) = fragmentOffset == 0
            ? parsePorts(packet, offset: headerLength, transport: transport)
            : (nil, nil)
        return PacketMetadata(
            ipVersion: 4,
            transportProtocolNumber: transport,
            sourceAddress: packet[12 ..< 16].map(String.init).joined(separator: "."),
            sourcePort: ports.source,
            destinationAddress: packet[16 ..< 20].map(String.init).joined(separator: "."),
            destinationPort: ports.destination
        )
    }

    private static func parseIPv6(_ bytes: [UInt8]) -> PacketMetadata {
        guard bytes.count >= 40 else {
            return PacketMetadata.empty(ipVersion: 6)
        }
        let payloadLength = Int(readUInt16(bytes, offset: 4))
        let declaredLength = payloadLength == 0 ? bytes.count : 40 + payloadLength
        guard declaredLength >= 40, declaredLength <= bytes.count else {
            return PacketMetadata.empty(ipVersion: 6)
        }
        let packet = declaredLength == bytes.count ? bytes : Array(bytes.prefix(declaredLength))
        let transportInfo = parseIPv6TransportInfo(packet)
        let transport = transportInfo.transport
        let ports: (source: UInt16?, destination: UInt16?) = transportInfo.hasInitialFragment
            ? parsePorts(packet, offset: transportInfo.offset, transport: transport)
            : (nil, nil)
        return PacketMetadata(
            ipVersion: 6,
            transportProtocolNumber: transport,
            sourceAddress: ipv6String(packet[8 ..< 24]),
            sourcePort: ports.source,
            destinationAddress: ipv6String(packet[24 ..< 40]),
            destinationPort: ports.destination
        )
    }

    private static func parseIPv6TransportInfo(_ bytes: [UInt8]) -> (transport: UInt8, offset: Int, hasInitialFragment: Bool) {
        var nextHeader = bytes[6]
        var offset = 40
        var extensionCount = 0

        while ipv6ExtensionHeaders.contains(nextHeader), extensionCount < maxIPv6Extensions {
            guard bytes.count >= offset + 2 else {
                return (nextHeader, offset, false)
            }

            let currentHeader = nextHeader
            nextHeader = bytes[offset]
            let headerLength: Int
            if currentHeader == 44 {
                guard bytes.count >= offset + 8 else {
                    return (nextHeader, offset, false)
                }
                let fragmentField = readUInt16(bytes, offset: offset + 2)
                if fragmentField & 0xfff8 != 0 {
                    return (nextHeader, offset + 8, false)
                }
                headerLength = 8
            } else if currentHeader == 51 {
                headerLength = (Int(bytes[offset + 1]) + 2) * 4
            } else {
                headerLength = (Int(bytes[offset + 1]) + 1) * 8
            }

            guard headerLength > 0, bytes.count >= offset + headerLength else {
                return (nextHeader, offset, false)
            }
            offset += headerLength
            extensionCount += 1
        }

        return (nextHeader, offset, true)
    }

    private static func parsePorts(_ bytes: [UInt8], offset: Int, transport: UInt8) -> (source: UInt16?, destination: UInt16?) {
        guard transport == 6 || transport == 17, bytes.count >= offset + 4 else {
            return (nil, nil)
        }
        let source = readUInt16(bytes, offset: offset)
        let destination = readUInt16(bytes, offset: offset + 2)
        return (source, destination)
    }

    private static func readUInt16(_ bytes: [UInt8], offset: Int) -> UInt16 {
        (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }

    private static func ipv6String(_ bytes: ArraySlice<UInt8>) -> String {
        let groups = stride(from: bytes.startIndex, to: bytes.endIndex, by: 2).map { index -> String in
            let value = (UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1])
            return String(value, radix: 16)
        }
        return groups.joined(separator: ":")
    }

    private static func empty(ipVersion: UInt8) -> PacketMetadata {
        PacketMetadata(
            ipVersion: ipVersion,
            transportProtocolNumber: nil,
            sourceAddress: nil,
            sourcePort: nil,
            destinationAddress: nil,
            destinationPort: nil
        )
    }

    private init(
        ipVersion: UInt8?,
        transportProtocolNumber: UInt8?,
        sourceAddress: String?,
        sourcePort: UInt16?,
        destinationAddress: String?,
        destinationPort: UInt16?
    ) {
        self.ipVersion = ipVersion
        self.transportProtocolNumber = transportProtocolNumber
        self.sourceAddress = sourceAddress
        self.sourcePort = sourcePort
        self.destinationAddress = destinationAddress
        self.destinationPort = destinationPort
    }
}
