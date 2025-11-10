//
//  TLSClientHelloParser.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/22/2025.
//
//  Parses TLS ClientHello packets to extract hostname/IP mappings used by the
//  forward host tracker.
//

import Foundation
import Darwin

enum TLSClientHelloParser {
    struct Mapping {
        var host: String
        var address: String
    }

    static func extractMapping(from ipPacket: Data) -> Mapping? {
        guard let firstByte = byte(ipPacket, offset: 0) else { return nil }
        let version = firstByte >> 4

        switch version {
        case 4:
            return parseIPv4(packet: ipPacket)
        case 6:
            return parseIPv6(packet: ipPacket)
        default:
            return nil
        }
    }

    private static func parseIPv4(packet: Data) -> Mapping? {
        guard let firstByte = byte(packet, offset: 0) else { return nil }
        let ihl = Int(firstByte & 0x0F) * 4
        guard ihl >= 20, packet.count >= ihl else { return nil }
        guard let proto = byte(packet, offset: 9), proto == 6 else { return nil }
        guard let destinationIP = ipv4String(packet, offset: 16) else { return nil }
        return parseTCP(packet: packet, payloadOffset: ihl, remoteIP: destinationIP)
    }

    private static func parseIPv6(packet: Data) -> Mapping? {
        let headerLength = 40
        guard packet.count >= headerLength else { return nil }
        guard let nextHeader = byte(packet, offset: 6), nextHeader == 6 else { return nil }
        guard let destinationIP = ipv6String(packet, offset: 24) else { return nil }
        return parseTCP(packet: packet, payloadOffset: headerLength, remoteIP: destinationIP)
    }

    private static func parseTCP(packet: Data, payloadOffset: Int, remoteIP: String) -> Mapping? {
        guard payloadOffset + 20 <= packet.count else { return nil }
        guard let dataOffsetByte = byte(packet, offset: payloadOffset + 12) else { return nil }
        let headerLength = Int((dataOffsetByte >> 4) * 4)
        guard headerLength >= 20, payloadOffset + headerLength <= packet.count else { return nil }
        let payloadStart = payloadOffset + headerLength
        guard payloadStart < packet.count else { return nil }
        let payload = packet[payloadStart..<packet.count]
        guard !payload.isEmpty else { return nil }
        let tcpPayload = Data(payload)
        guard let serverName = extractServerName(fromTLSRecord: tcpPayload) else { return nil }
        return Mapping(host: serverName, address: remoteIP)
    }

    private static func extractServerName(fromTLSRecord payload: Data) -> String? {
        guard payload.count >= 5 else { return nil }
        guard let contentType = byte(payload, offset: 0), contentType == 0x16 else { return nil }
        guard let recordLength = uint16(payload, offset: 3) else { return nil }
        let recordBodyEnd = 5 + Int(recordLength)
        guard recordBodyEnd <= payload.count else { return nil }

        guard let handshakeType = byte(payload, offset: 5), handshakeType == 0x01 else { return nil }
        guard let handshakeLength = uint24(payload, offset: 6) else { return nil }
        let handshakeStart = 9
        let handshakeEnd = handshakeStart + Int(handshakeLength)
        guard handshakeEnd <= recordBodyEnd, handshakeEnd <= payload.count else { return nil }

        var cursor = handshakeStart
        cursor += 2 // client_version
        cursor += 32 // random
        guard let sessionLengthByte = byte(payload, offset: cursor) else { return nil }
        let sessionLength = Int(sessionLengthByte)
        cursor += 1 + sessionLength
        guard cursor + 2 <= handshakeEnd else { return nil }

        guard let cipherSuitesLength = uint16(payload, offset: cursor) else { return nil }
        cursor += 2 + Int(cipherSuitesLength)
        guard cursor + 1 <= handshakeEnd else { return nil }

        guard let compressionMethodsLength = byte(payload, offset: cursor) else { return nil }
        cursor += 1 + Int(compressionMethodsLength)
        guard cursor + 2 <= handshakeEnd else { return nil }

        guard let extensionsLength = uint16(payload, offset: cursor) else { return nil }
        cursor += 2
        let extensionsEnd = cursor + Int(extensionsLength)
        guard extensionsEnd <= handshakeEnd else { return nil }

        while cursor + 4 <= extensionsEnd {
            guard let extensionType = uint16(payload, offset: cursor) else { return nil }
            guard let extensionLength = uint16(payload, offset: cursor + 2) else { return nil }
            let extensionDataStart = cursor + 4
            let extensionDataEnd = extensionDataStart + Int(extensionLength)
            guard extensionDataEnd <= extensionsEnd else { return nil }

            if extensionType == 0x0000 {
                return parseServerNameExtension(payload, offset: extensionDataStart, length: Int(extensionLength))
            }

            cursor = extensionDataEnd
        }

        return nil
    }

    private static func parseServerNameExtension(_ data: Data, offset: Int, length: Int) -> String? {
        guard let listLength = uint16(data, offset: offset) else { return nil }
        var cursor = offset + 2
        let listEnd = cursor + Int(listLength)
        guard listEnd <= offset + length else { return nil }

        while cursor + 3 <= listEnd {
            guard let nameType = byte(data, offset: cursor) else { return nil }
            cursor += 1
            guard let nameLength = uint16(data, offset: cursor) else { return nil }
            cursor += 2
            let nameEnd = cursor + Int(nameLength)
            guard nameEnd <= listEnd else { return nil }
            if nameType == 0, let slice = slice(data, offset: cursor, length: Int(nameLength)) {
                return String(bytes: slice, encoding: .utf8)
            }
            cursor = nameEnd
        }

        return nil
    }

    private static func byte(_ data: Data, offset: Int) -> UInt8? {
        guard offset >= 0, offset < data.count else { return nil }
        return data[data.index(data.startIndex, offsetBy: offset)]
    }

    private static func uint16(_ data: Data, offset: Int) -> UInt16? {
        guard offset >= 0, offset + 1 < data.count else { return nil }
        let high = UInt16(data[data.index(data.startIndex, offsetBy: offset)])
        let low = UInt16(data[data.index(data.startIndex, offsetBy: offset + 1)])
        return (high << 8) | low
    }

    private static func uint24(_ data: Data, offset: Int) -> UInt32? {
        guard offset >= 0, offset + 2 < data.count else { return nil }
        let b0 = UInt32(data[data.index(data.startIndex, offsetBy: offset)])
        let b1 = UInt32(data[data.index(data.startIndex, offsetBy: offset + 1)])
        let b2 = UInt32(data[data.index(data.startIndex, offsetBy: offset + 2)])
        return (b0 << 16) | (b1 << 8) | b2
    }

    private static func slice(_ data: Data, offset: Int, length: Int) -> Data? {
        guard length >= 0, offset >= 0, offset + length <= data.count else { return nil }
        let start = data.index(data.startIndex, offsetBy: offset)
        let end = data.index(start, offsetBy: length)
        return Data(data[start..<end])
    }

    private static func ipv4String(_ data: Data, offset: Int) -> String? {
        guard let bytes = slice(data, offset: offset, length: 4) else { return nil }
        let segments = bytes.map { String($0) }
        return segments.joined(separator: ".")
    }

    private static func ipv6String(_ data: Data, offset: Int) -> String? {
        guard let bytes = slice(data, offset: offset, length: 16) else { return nil }
        return bytes.withUnsafeBytes { raw -> String? in
            guard let base = raw.baseAddress else { return nil }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            if inet_ntop(AF_INET6, base, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                return String(cString: buffer)
            }
            return nil
        }
    }
}
