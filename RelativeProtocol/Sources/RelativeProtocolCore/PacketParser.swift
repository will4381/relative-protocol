// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import CryptoKit
import Darwin
import Foundation

public enum PacketParser {
    private static let dnsPort: UInt16 = 53
    private static let maxIPv6Extensions = 8

    public static func parse(_ data: Data, ipVersionHint: Int32?) -> PacketMetadata? {
        guard data.count >= 1 else { return nil }
        let version = data[data.startIndex] >> 4
        if version == 4 {
            return parseIPv4(data)
        }
        if version == 6 {
            return parseIPv6(data)
        }
        if ipVersionHint == AF_INET {
            return parseIPv4(data)
        }
        if ipVersionHint == AF_INET6 {
            return parseIPv6(data)
        }
        return nil
    }

    private static func parseIPv4(_ data: Data) -> PacketMetadata? {
        guard data.count >= 20 else { return nil }
        let versionAndIHL = data[data.startIndex]
        let version = versionAndIHL >> 4
        guard version == 4 else { return nil }
        let ihl = Int(versionAndIHL & 0x0F) * 4
        guard ihl >= 20, data.count >= ihl else { return nil }

        let protocolByte = data[data.startIndex + 9]
        let transport = TransportProtocol(rawValue: protocolByte)
        guard let srcAddress = readIPAddress(data, offset: 12, length: 4),
              let dstAddress = readIPAddress(data, offset: 16, length: 4) else {
            return nil
        }

        var srcPort: UInt16?
        var dstPort: UInt16?
        var dnsQuery: String?
        var dnsCname: String?
        var dnsAnswers: [IPAddress]?
        var registrableDomain: String?
        var tlsServerName: String?
        var quicVersion: UInt32?
        var quicPacketType: QuicPacketType?
        var quicDestinationConnectionId: String?
        var quicSourceConnectionId: String?

        if transport == .tcp || transport == .udp {
            guard data.count >= ihl + 4 else { return nil }
            srcPort = readUInt16(data, offset: ihl)
            dstPort = readUInt16(data, offset: ihl + 2)

            if transport == .udp {
                if let srcPort, let dstPort, (srcPort == dnsPort || dstPort == dnsPort) {
                    let payloadOffset = ihl + 8
                    if data.count > payloadOffset {
                        let dnsInfo = parseDNSInfo(data, payloadOffset: payloadOffset)
                        dnsQuery = dnsInfo.query
                        dnsCname = dnsInfo.cname
                        dnsAnswers = dnsInfo.answers.isEmpty ? nil : dnsInfo.answers
                    }
                }

                if let srcPort, let dstPort, (srcPort == 443 || dstPort == 443) {
                    let payloadOffset = ihl + 8
                    if data.count > payloadOffset, let quicInfo = parseQuicHeader(data, payloadOffset: payloadOffset) {
                        quicVersion = quicInfo.version
                        quicPacketType = mapQuicPacketType(version: quicInfo.version, packetType: quicInfo.packetType)
                        quicDestinationConnectionId = quicInfo.dcid
                        quicSourceConnectionId = quicInfo.scid
                        if tlsServerName == nil,
                           quicPacketType == .initial,
                           let quicVersion = quicInfo.version,
                           let dcidData = quicInfo.dcidData {
                            tlsServerName = decryptQuicInitialServerName(
                                data,
                                payloadOffset: payloadOffset,
                                version: quicVersion,
                                dcid: dcidData
                            )
                        }
                    }
                }
            } else if transport == .tcp {
                if data.count > ihl + 13 {
                    let dataOffset = Int((data[data.startIndex + ihl + 12] >> 4) * 4)
                    let payloadOffset = ihl + dataOffset
                    if dataOffset >= 20, data.count > payloadOffset {
                        tlsServerName = parseTLSServerName(data, payloadOffset: payloadOffset)
                    }
                }
            }
        }

        registrableDomain = DomainNormalizer.registrableDomain(from: dnsQuery ?? dnsCname ?? tlsServerName)

        return PacketMetadata(
            ipVersion: .v4,
            transport: transport,
            srcAddress: srcAddress,
            dstAddress: dstAddress,
            srcPort: srcPort,
            dstPort: dstPort,
            length: data.count,
            dnsQueryName: dnsQuery,
            dnsCname: dnsCname,
            dnsAnswerAddresses: dnsAnswers,
            registrableDomain: registrableDomain,
            tlsServerName: tlsServerName,
            quicVersion: quicVersion,
            quicPacketType: quicPacketType,
            quicDestinationConnectionId: quicDestinationConnectionId,
            quicSourceConnectionId: quicSourceConnectionId
        )
    }

    private static func parseIPv6(_ data: Data) -> PacketMetadata? {
        guard data.count >= 40 else { return nil }
        let version = data[data.startIndex] >> 4
        guard version == 6 else { return nil }

        var nextHeader = data[data.startIndex + 6]
        var offset = 40

        guard let srcAddress = readIPAddress(data, offset: 8, length: 16),
              let dstAddress = readIPAddress(data, offset: 24, length: 16) else {
            return nil
        }

        var extensionsSeen = 0
        while isIPv6ExtensionHeader(nextHeader) && extensionsSeen < maxIPv6Extensions {
            guard data.count >= offset + 2 else { return nil }
            let currentHeader = nextHeader
            nextHeader = data[data.startIndex + offset]
            let lengthField = data[data.startIndex + offset + 1]

            let headerLength: Int
            switch currentHeader {
            case 44: // Fragment
                headerLength = 8
            case 51: // AH
                headerLength = (Int(lengthField) + 2) * 4
            case 50: // ESP
                return PacketMetadata(
                    ipVersion: .v6,
                    transport: TransportProtocol(rawValue: currentHeader),
                    srcAddress: srcAddress,
                    dstAddress: dstAddress,
                    srcPort: nil,
                    dstPort: nil,
                    length: data.count,
                    dnsQueryName: nil,
                    dnsCname: nil,
                    dnsAnswerAddresses: nil,
                    registrableDomain: nil,
                    tlsServerName: nil,
                    quicVersion: nil,
                    quicPacketType: nil,
                    quicDestinationConnectionId: nil,
                    quicSourceConnectionId: nil
                )
            default:
                headerLength = (Int(lengthField) + 1) * 8
            }

            offset += headerLength
            extensionsSeen += 1
            guard data.count >= offset else { return nil }
        }

        let transport = TransportProtocol(rawValue: nextHeader)
        var srcPort: UInt16?
        var dstPort: UInt16?
        var dnsQuery: String?
        var dnsCname: String?
        var dnsAnswers: [IPAddress]?
        var registrableDomain: String?
        var tlsServerName: String?
        var quicVersion: UInt32?
        var quicPacketType: QuicPacketType?
        var quicDestinationConnectionId: String?
        var quicSourceConnectionId: String?

        if transport == .tcp || transport == .udp {
            guard data.count >= offset + 4 else { return nil }
            srcPort = readUInt16(data, offset: offset)
            dstPort = readUInt16(data, offset: offset + 2)

            if transport == .udp {
                if let srcPort, let dstPort, (srcPort == dnsPort || dstPort == dnsPort) {
                    let payloadOffset = offset + 8
                    if data.count > payloadOffset {
                        let dnsInfo = parseDNSInfo(data, payloadOffset: payloadOffset)
                        dnsQuery = dnsInfo.query
                        dnsCname = dnsInfo.cname
                        dnsAnswers = dnsInfo.answers.isEmpty ? nil : dnsInfo.answers
                    }
                }

                if let srcPort, let dstPort, (srcPort == 443 || dstPort == 443) {
                    let payloadOffset = offset + 8
                    if data.count > payloadOffset, let quicInfo = parseQuicHeader(data, payloadOffset: payloadOffset) {
                        quicVersion = quicInfo.version
                        quicPacketType = mapQuicPacketType(version: quicInfo.version, packetType: quicInfo.packetType)
                        quicDestinationConnectionId = quicInfo.dcid
                        quicSourceConnectionId = quicInfo.scid
                        if tlsServerName == nil,
                           quicPacketType == .initial,
                           let quicVersion = quicInfo.version,
                           let dcidData = quicInfo.dcidData {
                            tlsServerName = decryptQuicInitialServerName(
                                data,
                                payloadOffset: payloadOffset,
                                version: quicVersion,
                                dcid: dcidData
                            )
                        }
                    }
                }
            } else if transport == .tcp {
                if data.count > offset + 13 {
                    let dataOffset = Int((data[data.startIndex + offset + 12] >> 4) * 4)
                    let payloadOffset = offset + dataOffset
                    if dataOffset >= 20, data.count > payloadOffset {
                        tlsServerName = parseTLSServerName(data, payloadOffset: payloadOffset)
                    }
                }
            }
        }

        registrableDomain = DomainNormalizer.registrableDomain(from: dnsQuery ?? dnsCname ?? tlsServerName)

        return PacketMetadata(
            ipVersion: .v6,
            transport: transport,
            srcAddress: srcAddress,
            dstAddress: dstAddress,
            srcPort: srcPort,
            dstPort: dstPort,
            length: data.count,
            dnsQueryName: dnsQuery,
            dnsCname: dnsCname,
            dnsAnswerAddresses: dnsAnswers,
            registrableDomain: registrableDomain,
            tlsServerName: tlsServerName,
            quicVersion: quicVersion,
            quicPacketType: quicPacketType,
            quicDestinationConnectionId: quicDestinationConnectionId,
            quicSourceConnectionId: quicSourceConnectionId
        )
    }

    private static func isIPv6ExtensionHeader(_ header: UInt8) -> Bool {
        switch header {
        case 0, 43, 44, 50, 51, 60:
            return true
        default:
            return false
        }
    }

    private static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        let upper = UInt16(data[data.startIndex + offset]) << 8
        let lower = UInt16(data[data.startIndex + offset + 1])
        return upper | lower
    }

    private static func readUInt24(_ data: Data, offset: Int) -> Int {
        let byte1 = Int(data[data.startIndex + offset]) << 16
        let byte2 = Int(data[data.startIndex + offset + 1]) << 8
        let byte3 = Int(data[data.startIndex + offset + 2])
        return byte1 | byte2 | byte3
    }

    private static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        let byte1 = UInt32(data[data.startIndex + offset]) << 24
        let byte2 = UInt32(data[data.startIndex + offset + 1]) << 16
        let byte3 = UInt32(data[data.startIndex + offset + 2]) << 8
        let byte4 = UInt32(data[data.startIndex + offset + 3])
        return byte1 | byte2 | byte3 | byte4
    }

    private struct QuicParseResult {
        let version: UInt32?
        let dcid: String?
        let scid: String?
        let dcidData: Data?
        let scidData: Data?
        let isLongHeader: Bool
        let packetType: UInt8?
    }

    private static func parseQuicHeader(_ data: Data, payloadOffset: Int) -> QuicParseResult? {
        guard data.count > payloadOffset else { return nil }
        let firstByte = data[data.startIndex + payloadOffset]
        let isLongHeader = (firstByte & 0x80) != 0
        let packetType = isLongHeader ? (firstByte & 0x30) >> 4 : nil
        guard isLongHeader else {
            return QuicParseResult(
                version: nil,
                dcid: nil,
                scid: nil,
                dcidData: nil,
                scidData: nil,
                isLongHeader: false,
                packetType: nil
            )
        }
        guard data.count >= payloadOffset + 6 else { return nil }
        let version = readUInt32(data, offset: payloadOffset + 1)
        let dcidLength = Int(data[data.startIndex + payloadOffset + 5])
        var index = payloadOffset + 6
        guard data.count >= index + dcidLength + 1 else { return nil }
        guard let dcidData = copyDataSlice(data, offset: index, length: dcidLength) else { return nil }
        index += dcidLength
        let scidLength = Int(data[data.startIndex + index])
        index += 1
        guard data.count >= index + scidLength else { return nil }
        guard let scidData = copyDataSlice(data, offset: index, length: scidLength) else { return nil }
        return QuicParseResult(
            version: version,
            dcid: hexString(dcidData),
            scid: hexString(scidData),
            dcidData: dcidData,
            scidData: scidData,
            isLongHeader: true,
            packetType: packetType
        )
    }

    private static func mapQuicPacketType(version: UInt32?, packetType: UInt8?) -> QuicPacketType? {
        guard let version, let packetType else { return nil }
        switch version {
        case quicV1Version:
            switch packetType {
            case 0: return .initial
            case 1: return .zeroRTT
            case 2: return .handshake
            case 3: return .retry
            default: return nil
            }
        case quicV2Version:
            // QUIC v2 long header mapping: 0=Retry, 1=Initial, 2=0-RTT, 3=Handshake
            switch packetType {
            case 0: return .retry
            case 1: return .initial
            case 2: return .zeroRTT
            case 3: return .handshake
            default: return nil
            }
        default:
            return nil
        }
    }

    private static func parseTLSServerName(_ data: Data, payloadOffset: Int) -> String? {
        guard data.count >= payloadOffset + 5 else { return nil }
        let contentType = data[data.startIndex + payloadOffset]
        guard contentType == 22 else { return nil }
        let recordLength = Int(readUInt16(data, offset: payloadOffset + 3))
        let recordEnd = payloadOffset + 5 + recordLength
        guard data.count >= recordEnd else { return nil }

        let handshakeOffset = payloadOffset + 5
        guard data.count >= handshakeOffset + 4 else { return nil }
        let handshakeType = data[data.startIndex + handshakeOffset]
        guard handshakeType == 1 else { return nil }
        let handshakeLength = readUInt24(data, offset: handshakeOffset + 1)
        guard handshakeLength > 0 else { return nil }
        let handshakeEnd = handshakeOffset + 4 + handshakeLength
        guard handshakeEnd <= recordEnd else { return nil }

        var index = handshakeOffset + 4
        guard data.count >= index + 2 + 32 + 1 else { return nil }
        index += 2 + 32

        let sessionIdLength = Int(data[data.startIndex + index])
        index += 1
        guard data.count >= index + sessionIdLength + 2 else { return nil }
        index += sessionIdLength

        let cipherSuitesLength = Int(readUInt16(data, offset: index))
        index += 2
        guard data.count >= index + cipherSuitesLength + 1 else { return nil }
        index += cipherSuitesLength

        let compressionMethodsLength = Int(data[data.startIndex + index])
        index += 1
        guard data.count >= index + compressionMethodsLength + 2 else { return nil }
        index += compressionMethodsLength

        let extensionsLength = Int(readUInt16(data, offset: index))
        index += 2
        guard extensionsLength > 0 else { return nil }
        let extensionsEnd = index + extensionsLength
        guard extensionsEnd <= data.count, extensionsEnd <= handshakeEnd else { return nil }

        while index + 4 <= extensionsEnd {
            let extType = readUInt16(data, offset: index)
            index += 2
            let extLen = Int(readUInt16(data, offset: index))
            index += 2
            guard index + extLen <= extensionsEnd else { return nil }

            if extType == 0 {
                guard extLen >= 2 else { return nil }
                var nameIndex = index
                let listLength = Int(readUInt16(data, offset: nameIndex))
                nameIndex += 2
                let listEnd = min(index + extLen, nameIndex + listLength)
                while nameIndex + 3 <= listEnd {
                    let nameType = data[data.startIndex + nameIndex]
                    nameIndex += 1
                    let nameLength = Int(readUInt16(data, offset: nameIndex))
                    nameIndex += 2
                    guard nameIndex + nameLength <= listEnd else { break }
                    if nameType == 0 {
                        return decodeUTF8(data, start: nameIndex, length: nameLength)
                    }
                    nameIndex += nameLength
                }
            }

            index += extLen
        }

        return nil
    }

    private static func parseTLSClientHelloServerName(_ data: Data) -> String? {
        guard data.count >= 4 else { return nil }
        guard data[data.startIndex] == 1 else { return nil }
        let handshakeLength = readUInt24(data, offset: 1)
        guard handshakeLength > 0 else { return nil }
        let handshakeEnd = 4 + handshakeLength
        guard handshakeEnd <= data.count else { return nil }

        var index = 4
        guard data.count >= index + 2 + 32 + 1 else { return nil }
        index += 2 + 32

        let sessionIdLength = Int(data[data.startIndex + index])
        index += 1
        guard index + sessionIdLength + 2 <= handshakeEnd else { return nil }
        index += sessionIdLength

        let cipherSuitesLength = Int(readUInt16(data, offset: index))
        index += 2
        guard index + cipherSuitesLength + 1 <= handshakeEnd else { return nil }
        index += cipherSuitesLength

        let compressionMethodsLength = Int(data[data.startIndex + index])
        index += 1
        guard index + compressionMethodsLength + 2 <= handshakeEnd else { return nil }
        index += compressionMethodsLength

        let extensionsLength = Int(readUInt16(data, offset: index))
        index += 2
        guard extensionsLength > 0 else { return nil }
        let extensionsEnd = min(handshakeEnd, index + extensionsLength)

        while index + 4 <= extensionsEnd {
            let extType = readUInt16(data, offset: index)
            index += 2
            let extLen = Int(readUInt16(data, offset: index))
            index += 2
            guard index + extLen <= extensionsEnd else { return nil }

            if extType == 0 {
                guard extLen >= 2 else { return nil }
                var nameIndex = index
                let listLength = Int(readUInt16(data, offset: nameIndex))
                nameIndex += 2
                let listEnd = min(index + extLen, nameIndex + listLength)
                while nameIndex + 3 <= listEnd {
                    let nameType = data[data.startIndex + nameIndex]
                    nameIndex += 1
                    let nameLength = Int(readUInt16(data, offset: nameIndex))
                    nameIndex += 2
                    guard nameIndex + nameLength <= listEnd else { break }
                    if nameType == 0 {
                        return decodeUTF8(data, start: nameIndex, length: nameLength)
                    }
                    nameIndex += nameLength
                }
            }

            index += extLen
        }

        return nil
    }

    private static let quicV1Version: UInt32 = 0x00000001
    private static let quicV2Version: UInt32 = 0x6b3343cf

    private static let quicV1InitialSalt: [UInt8] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    ]
    private static let quicV2InitialSalt: [UInt8] = [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
    ]

    private struct QuicInitialSecrets {
        let clientKey: Data
        let clientIv: Data
        let clientHp: Data
        let serverKey: Data
        let serverIv: Data
        let serverHp: Data
    }

    private static func deriveQuicInitialSecrets(version: UInt32, dcid: Data) -> QuicInitialSecrets? {
        let salt: Data
        let labelPrefix: String
        if version == quicV1Version {
            salt = Data(quicV1InitialSalt)
            labelPrefix = "quic"
        } else if version == quicV2Version {
            salt = Data(quicV2InitialSalt)
            labelPrefix = "quicv2"
        } else {
            return nil
        }
        let initialSecret = hkdfExtract(salt: salt, ikm: dcid)
        let clientSecret = hkdfExpandLabel(secret: initialSecret, label: "client in", length: 32)
        let serverSecret = hkdfExpandLabel(secret: initialSecret, label: "server in", length: 32)

        let clientKey = hkdfExpandLabel(secret: SymmetricKey(data: clientSecret), label: "\(labelPrefix) key", length: 16)
        let clientIv = hkdfExpandLabel(secret: SymmetricKey(data: clientSecret), label: "\(labelPrefix) iv", length: 12)
        let clientHp = hkdfExpandLabel(secret: SymmetricKey(data: clientSecret), label: "\(labelPrefix) hp", length: 16)

        let serverKey = hkdfExpandLabel(secret: SymmetricKey(data: serverSecret), label: "\(labelPrefix) key", length: 16)
        let serverIv = hkdfExpandLabel(secret: SymmetricKey(data: serverSecret), label: "\(labelPrefix) iv", length: 12)
        let serverHp = hkdfExpandLabel(secret: SymmetricKey(data: serverSecret), label: "\(labelPrefix) hp", length: 16)

        return QuicInitialSecrets(
            clientKey: clientKey,
            clientIv: clientIv,
            clientHp: clientHp,
            serverKey: serverKey,
            serverIv: serverIv,
            serverHp: serverHp
        )
    }

    private static func hkdfExtract(salt: Data, ikm: Data) -> SymmetricKey {
        let key = SymmetricKey(data: salt)
        let prk = HMAC<SHA256>.authenticationCode(for: ikm, using: key)
        return SymmetricKey(data: Data(prk))
    }

    private static func hkdfExpandLabel(secret: SymmetricKey, label: String, length: Int) -> Data {
        let fullLabel = "tls13 " + label
        var info = Data()
        var lengthBytes = UInt16(length).bigEndian
        withUnsafeBytes(of: &lengthBytes) { info.append(contentsOf: $0) }
        info.append(UInt8(fullLabel.utf8.count))
        info.append(contentsOf: fullLabel.utf8)
        info.append(0)
        return hkdfExpand(secret: secret, info: info, length: length)
    }

    private static func hkdfExpand(secret: SymmetricKey, info: Data, length: Int) -> Data {
        var output = Data()
        var previous = Data()
        var counter: UInt8 = 1
        while output.count < length {
            var data = Data()
            data.append(previous)
            data.append(info)
            data.append(counter)
            let block = HMAC<SHA256>.authenticationCode(for: data, using: secret)
            previous = Data(block)
            output.append(previous)
            counter &+= 1
        }
        return output.prefix(length)
    }

    private static func aes128EncryptBlock(key: Data, block: Data) -> Data? {
        guard key.count == 16, block.count == 16 else { return nil }
        let expandedKey = aes128ExpandKey(Array(key))
        var state = Array(block)
        addRoundKey(&state, roundKey: expandedKey, round: 0)
        for round in 1..<10 {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, roundKey: expandedKey, round: round)
        }
        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, roundKey: expandedKey, round: 10)
        return Data(state)
    }

    private static func aes128ExpandKey(_ key: [UInt8]) -> [UInt8] {
        var expanded = key
        expanded.reserveCapacity(176)
        var bytesGenerated = key.count
        var rconIteration: UInt8 = 1
        var temp: [UInt8] = Array(repeating: 0, count: 4)

        while bytesGenerated < 176 {
            for i in 0..<4 {
                temp[i] = expanded[bytesGenerated - 4 + i]
            }
            if bytesGenerated % 16 == 0 {
                temp = rotWord(temp)
                temp = subWord(temp)
                temp[0] ^= rcon(rconIteration)
                rconIteration &+= 1
            }
            for i in 0..<4 {
                let next = expanded[bytesGenerated - 16 + i] ^ temp[i]
                expanded.append(next)
            }
            bytesGenerated += 4
        }
        return expanded
    }

    private static func rotWord(_ word: [UInt8]) -> [UInt8] {
        [word[1], word[2], word[3], word[0]]
    }

    private static func subWord(_ word: [UInt8]) -> [UInt8] {
        word.map { aesSBox[Int($0)] }
    }

    private static func rcon(_ iteration: UInt8) -> UInt8 {
        var value: UInt8 = 1
        if iteration == 0 { return 0 }
        for _ in 1..<iteration {
            value = xtime(value)
        }
        return value
    }

    private static func addRoundKey(_ state: inout [UInt8], roundKey: [UInt8], round: Int) {
        let start = round * 16
        for i in 0..<16 {
            state[i] ^= roundKey[start + i]
        }
    }

    private static func subBytes(_ state: inout [UInt8]) {
        for i in 0..<16 {
            state[i] = aesSBox[Int(state[i])]
        }
    }

    private static func shiftRows(_ state: inout [UInt8]) {
        let tmp = state
        state[0] = tmp[0]
        state[4] = tmp[4]
        state[8] = tmp[8]
        state[12] = tmp[12]

        state[1] = tmp[5]
        state[5] = tmp[9]
        state[9] = tmp[13]
        state[13] = tmp[1]

        state[2] = tmp[10]
        state[6] = tmp[14]
        state[10] = tmp[2]
        state[14] = tmp[6]

        state[3] = tmp[15]
        state[7] = tmp[3]
        state[11] = tmp[7]
        state[15] = tmp[11]
    }

    private static func mixColumns(_ state: inout [UInt8]) {
        for column in 0..<4 {
            let index = column * 4
            let s0 = state[index]
            let s1 = state[index + 1]
            let s2 = state[index + 2]
            let s3 = state[index + 3]

            let m0 = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
            let m1 = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
            let m2 = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
            let m3 = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)

            state[index] = m0
            state[index + 1] = m1
            state[index + 2] = m2
            state[index + 3] = m3
        }
    }

    private static func xtime(_ value: UInt8) -> UInt8 {
        let shifted = value << 1
        return (value & 0x80) != 0 ? shifted ^ 0x1b : shifted
    }

    private static let aesSBox: [UInt8] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    private static func decryptQuicInitialServerName(
        _ data: Data,
        payloadOffset: Int,
        version: UInt32,
        dcid: Data
    ) -> String? {
        guard let secrets = deriveQuicInitialSecrets(version: version, dcid: dcid) else { return nil }
        guard data.count > payloadOffset else { return nil }

        var index = payloadOffset
        let firstByte = data[data.startIndex + index]
        let isLongHeader = (firstByte & 0x80) != 0
        guard isLongHeader else { return nil }
        index += 1
        guard data.count >= index + 4 else { return nil }
        index += 4 // version
        guard data.count > index else { return nil }
        let dcidLength = Int(data[data.startIndex + index])
        index += 1
        guard data.count >= index + dcidLength + 1 else { return nil }
        index += dcidLength
        let scidLength = Int(data[data.startIndex + index])
        index += 1
        guard data.count >= index + scidLength else { return nil }
        index += scidLength

        guard let tokenLengthInfo = readQuicVarInt(data, offset: index) else { return nil }
        index = tokenLengthInfo.nextIndex
        let tokenLength = tokenLengthInfo.value
        guard data.count >= index + tokenLength else { return nil }
        index += tokenLength

        guard let lengthInfo = readQuicVarInt(data, offset: index) else { return nil }
        index = lengthInfo.nextIndex
        let lengthValue = lengthInfo.value

        let pnOffset = index
        guard data.count >= pnOffset + 4 + 16 else { return nil }
        let sampleOffset = pnOffset + 4
        guard data.count >= sampleOffset + 16 else { return nil }
        guard let sample = copyDataSlice(data, offset: sampleOffset, length: 16) else { return nil }

        if let serverName = decryptQuicInitial(
            data,
            payloadOffset: payloadOffset,
            pnOffset: pnOffset,
            lengthValue: lengthValue,
            firstByte: firstByte,
            sample: sample,
            key: secrets.clientKey,
            iv: secrets.clientIv,
            hp: secrets.clientHp
        ) {
            return serverName
        }

        return decryptQuicInitial(
            data,
            payloadOffset: payloadOffset,
            pnOffset: pnOffset,
            lengthValue: lengthValue,
            firstByte: firstByte,
            sample: sample,
            key: secrets.serverKey,
            iv: secrets.serverIv,
            hp: secrets.serverHp
        )
    }

    private static func decryptQuicInitial(
        _ data: Data,
        payloadOffset: Int,
        pnOffset: Int,
        lengthValue: Int,
        firstByte: UInt8,
        sample: Data,
        key: Data,
        iv: Data,
        hp: Data
    ) -> String? {
        guard let mask = aes128EncryptBlock(key: hp, block: sample) else { return nil }
        let headerFirstByte = firstByte ^ (mask[0] & 0x0f)
        let pnLength = Int(headerFirstByte & 0x03) + 1
        guard data.count >= pnOffset + pnLength else { return nil }
        guard var pnBytes = copyBytes(data, offset: pnOffset, length: pnLength) else { return nil }
        for i in 0..<pnLength {
            pnBytes[i] ^= mask[i + 1]
        }

        let payloadLength = lengthValue - pnLength
        guard payloadLength > 0 else { return nil }
        let payloadStart = pnOffset + pnLength
        let payloadEnd = payloadStart + payloadLength
        guard data.count >= payloadEnd else { return nil }

        guard var aad = copyDataSlice(data, offset: payloadOffset, length: payloadStart - payloadOffset) else { return nil }
        if !aad.isEmpty {
            aad[aad.startIndex] = headerFirstByte
            for i in 0..<pnLength {
                aad[aad.startIndex + (payloadStart - payloadOffset - pnLength) + i] = pnBytes[i]
            }
        }

        guard let ciphertextAndTag = copyDataSlice(data, offset: payloadStart, length: payloadEnd - payloadStart) else { return nil }
        guard ciphertextAndTag.count > 16 else { return nil }
        let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)

        var packetNumber: UInt64 = 0
        for byte in pnBytes {
            packetNumber = (packetNumber << 8) | UInt64(byte)
        }

        var nonce = [UInt8](iv)
        guard nonce.count == 12 else { return nil }
        var pnBytesFull = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            pnBytesFull[7 - i] = UInt8((packetNumber >> (UInt64(i) * 8)) & 0xff)
        }
        for i in 0..<8 {
            nonce[nonce.count - 8 + i] ^= pnBytesFull[i]
        }

        guard let gcmNonce = try? AES.GCM.Nonce(data: Data(nonce)) else { return nil }
        guard let sealedBox = try? AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag) else { return nil }
        guard let plaintext = try? AES.GCM.open(sealedBox, using: SymmetricKey(data: key), authenticating: aad) else { return nil }
        return parseQuicFramesForServerName(plaintext)
    }

    private static func readQuicVarInt(_ data: Data, offset: Int) -> (value: Int, nextIndex: Int)? {
        guard offset < data.count else { return nil }
        let first = data[data.startIndex + offset]
        let prefix = first >> 6
        let length = 1 << prefix
        guard offset + length <= data.count else { return nil }
        var value = Int(first & 0x3f)
        if length > 1 {
            for i in 1..<length {
                value = (value << 8) | Int(data[data.startIndex + offset + i])
            }
        }
        return (value, offset + length)
    }

    private static func parseQuicFramesForServerName(_ data: Data) -> String? {
        var index = 0
        let end = data.count
        while index < end {
            guard let typeInfo = readQuicVarInt(data, offset: index) else { return nil }
            index = typeInfo.nextIndex
            let frameType = typeInfo.value
            if frameType == 0x06 {
                guard let offsetInfo = readQuicVarInt(data, offset: index) else { return nil }
                index = offsetInfo.nextIndex
                guard let lengthInfo = readQuicVarInt(data, offset: index) else { return nil }
                index = lengthInfo.nextIndex
                let cryptoLength = lengthInfo.value
                guard cryptoLength >= 4, index + cryptoLength <= end else { return nil }
                if offsetInfo.value == 0 {
                    guard let cryptoData = copyDataSlice(data, offset: index, length: cryptoLength) else { return nil }
                    return parseTLSClientHelloServerName(cryptoData)
                }
                index += cryptoLength
            } else if frameType == 0x00 || frameType == 0x01 {
                continue
            } else {
                // Skip unknown frame using length if present (best-effort).
                if let lengthInfo = readQuicVarInt(data, offset: index) {
                    index = lengthInfo.nextIndex + lengthInfo.value
                } else {
                    return nil
                }
            }
        }
        return nil
    }

    private static func hexString(_ data: Data) -> String? {
        guard !data.isEmpty else { return nil }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private struct DNSParseResult {
        let query: String?
        let cname: String?
        let answers: [IPAddress]
    }

    private static func parseDNSInfo(_ data: Data, payloadOffset: Int) -> DNSParseResult {
        guard data.count >= payloadOffset + 12 else { return DNSParseResult(query: nil, cname: nil, answers: []) }
        let flags = readUInt16(data, offset: payloadOffset + 2)
        let qdCount = readUInt16(data, offset: payloadOffset + 4)
        let anCount = readUInt16(data, offset: payloadOffset + 6)
        let isResponse = (flags & 0x8000) != 0

        var index = payloadOffset + 12
        var queryName: String?
        if qdCount > 0 {
            if let name = readDNSName(data, offset: &index, messageStart: payloadOffset, depth: 0) {
                queryName = name
            }
            if index + 4 <= data.count {
                index += 4
            } else {
                return DNSParseResult(query: queryName, cname: nil, answers: [])
            }
        }

        guard isResponse, anCount > 0 else {
            return DNSParseResult(query: queryName, cname: nil, answers: [])
        }

        var cname: String?
        var answers: [IPAddress] = []
        var answersParsed = 0
        while answersParsed < anCount, index < data.count {
            _ = readDNSName(data, offset: &index, messageStart: payloadOffset, depth: 0)
            guard index + 10 <= data.count else { break }
            let type = readUInt16(data, offset: index)
            index += 2
            _ = readUInt16(data, offset: index) // class
            index += 2
            index += 4 // ttl
            let rdLength = Int(readUInt16(data, offset: index))
            index += 2
            guard index + rdLength <= data.count else { break }

            if type == 5 { // CNAME
                var rdataOffset = index
                if let cnameName = readDNSName(data, offset: &rdataOffset, messageStart: payloadOffset, depth: 0) {
                    cname = cnameName
                }
            } else if type == 1, rdLength == 4 { // A
                if let ip = readIPAddress(data, offset: index, length: 4) {
                    answers.append(ip)
                }
            } else if type == 28, rdLength == 16 { // AAAA
                if let ip = readIPAddress(data, offset: index, length: 16) {
                    answers.append(ip)
                }
            }

            index += rdLength
            answersParsed += 1
        }

        return DNSParseResult(query: queryName, cname: cname, answers: answers)
    }

    private static func readDNSName(_ data: Data, offset: inout Int, messageStart: Int, depth: Int) -> String? {
        guard depth < 8 else { return nil }
        var labels: [String] = []
        var index = offset
        var jumped = false

        while index < data.count {
            let length = Int(data[data.startIndex + index])
            if length == 0 {
                index += 1
                if !jumped {
                    offset = index
                }
                break
            }

            if length & 0xC0 == 0xC0 {
                guard index + 1 < data.count else { return nil }
                let pointerByte = Int(data[data.startIndex + index + 1])
                let pointer = ((length & 0x3F) << 8) | pointerByte
                var pointerOffset = messageStart + pointer
                guard pointerOffset < data.count else { return nil }
                if !jumped {
                    offset = index + 2
                }
                jumped = true
                if let suffix = readDNSName(data, offset: &pointerOffset, messageStart: messageStart, depth: depth + 1) {
                    if labels.isEmpty {
                        return suffix
                    }
                    labels.append(contentsOf: suffix.split(separator: ".").map(String.init))
                    return labels.joined(separator: ".")
                }
                return nil
            }

            index += 1
            guard index + length <= data.count else { return nil }
            guard let label = decodeASCII(data, start: index, length: length) else { return nil }
            labels.append(label)
            index += length
        }

        guard !labels.isEmpty else { return nil }
        if !jumped {
            offset = index
        }
        return labels.joined(separator: ".")
    }

    private static func decodeASCII(_ data: Data, start: Int, length: Int) -> String? {
        guard length > 0, start >= 0, data.count >= start + length else { return nil }
        return data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            let pointer = base.advanced(by: start)
            let buffer = UnsafeBufferPointer(start: pointer, count: length)
            return String(bytes: buffer, encoding: .ascii)
        }
    }

    private static func decodeUTF8(_ data: Data, start: Int, length: Int) -> String? {
        guard length > 0, start >= 0, data.count >= start + length else { return nil }
        return data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            let pointer = base.advanced(by: start)
            let buffer = UnsafeBufferPointer(start: pointer, count: length)
            return String(decoding: buffer, as: UTF8.self)
        }
    }

    private static func readIPAddress(_ data: Data, offset: Int, length: Int) -> IPAddress? {
        guard length == 4 || length == 16 else { return nil }
        guard let slice = copyDataSlice(data, offset: offset, length: length) else { return nil }
        return IPAddress(bytes: slice)
    }

    private static func copyDataSlice(_ data: Data, offset: Int, length: Int) -> Data? {
        guard offset >= 0, length >= 0, data.count >= offset + length else { return nil }
        if length == 0 { return Data() }
        return data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            return Data(bytes: base.advanced(by: offset), count: length)
        }
    }

    private static func copyBytes(_ data: Data, offset: Int, length: Int) -> [UInt8]? {
        guard offset >= 0, length >= 0, data.count >= offset + length else { return nil }
        if length == 0 { return [] }
        return data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            let buffer = UnsafeBufferPointer(start: base.advanced(by: offset), count: length)
            return Array(buffer)
        }
    }
}
