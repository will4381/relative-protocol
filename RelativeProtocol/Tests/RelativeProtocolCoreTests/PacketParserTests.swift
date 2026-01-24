// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import CryptoKit
import Darwin
import XCTest
import RelativeProtocolCore

final class PacketParserTests: XCTestCase {
    func testParseIPv4UDPDns() {
        let payload = makeDNSQueryPayload(hostname: "example.com")
        let packet = makeIPv4UDPPacket(
            src: [192, 168, 0, 2],
            dst: [1, 1, 1, 1],
            srcPort: 5353,
            dstPort: 53,
            payload: payload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.ipVersion, .v4)
        XCTAssertEqual(metadata?.transport, .udp)
        XCTAssertEqual(metadata?.srcPort, 5353)
        XCTAssertEqual(metadata?.dstPort, 53)
        XCTAssertEqual(metadata?.dnsQueryName, "example.com")
    }

    func testParseIPv6UDP() {
        let payload = [UInt8](repeating: 0x11, count: 12)
        let packet = makeIPv6UDPPacket(
            src: Array(repeating: 0, count: 15) + [1],
            dst: Array(repeating: 0, count: 15) + [2],
            srcPort: 40000,
            dstPort: 443,
            payload: payload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET6)
        XCTAssertEqual(metadata?.ipVersion, .v6)
        XCTAssertEqual(metadata?.transport, .udp)
        XCTAssertEqual(metadata?.srcPort, 40000)
        XCTAssertEqual(metadata?.dstPort, 443)
    }

    func testParseQuicV1InitialExtractsSNI() {
        let quicPayload = makeQuicV1InitialPacket(hostname: "example.com")
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 1],
            dst: [1, 1, 1, 1],
            srcPort: 12345,
            dstPort: 443,
            payload: quicPayload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.quicVersion, 0x00000001)
        XCTAssertEqual(metadata?.quicDestinationConnectionId, "8394c8f03e515708")
        XCTAssertEqual(metadata?.tlsServerName, "example.com")
    }

    func testParseQuicV1ZeroRTTDoesNotDecrypt() {
        let quicPayload = makeQuicLongHeader(
            version: 0x00000001,
            packetType: 0x01,
            dcid: [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04],
            scid: [0xaa, 0xbb, 0xcc, 0xdd]
        )
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 2],
            dst: [1, 1, 1, 1],
            srcPort: 23456,
            dstPort: 443,
            payload: quicPayload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.quicVersion, 0x00000001)
        XCTAssertEqual(metadata?.quicDestinationConnectionId, "deadbeef01020304")
        XCTAssertNil(metadata?.tlsServerName)
    }

    func testParseQuicV2InitialHeader() {
        let quicPayload = makeQuicLongHeader(
            version: 0x6b3343cf,
            packetType: 0x01,
            dcid: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            scid: [0x99, 0xaa, 0xbb, 0xcc]
        )
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 3],
            dst: [1, 1, 1, 1],
            srcPort: 34567,
            dstPort: 443,
            payload: quicPayload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.quicVersion, 0x6b3343cf)
        XCTAssertEqual(metadata?.quicDestinationConnectionId, "1122334455667788")
        XCTAssertNil(metadata?.tlsServerName)
    }

    func testParseQuicV2ZeroRTTDoesNotDecrypt() {
        let quicPayload = makeQuicLongHeader(
            version: 0x6b3343cf,
            packetType: 0x02,
            dcid: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11],
            scid: [0x22, 0x33, 0x44, 0x55]
        )
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 4],
            dst: [1, 1, 1, 1],
            srcPort: 45678,
            dstPort: 443,
            payload: quicPayload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.quicVersion, 0x6b3343cf)
        XCTAssertEqual(metadata?.quicDestinationConnectionId, "0a0b0c0d0e0f1011")
        XCTAssertNil(metadata?.tlsServerName)
    }

    private func makeIPv4UDPPacket(src: [UInt8], dst: [UInt8], srcPort: UInt16, dstPort: UInt16, payload: [UInt8]) -> Data {
        var packet: [UInt8] = []
        let totalLength = 20 + 8 + payload.count
        packet.append(0x45)
        packet.append(0x00)
        packet.append(UInt8((totalLength >> 8) & 0xFF))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(64)
        packet.append(17)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: src)
        packet.append(contentsOf: dst)

        packet.append(UInt8((srcPort >> 8) & 0xFF))
        packet.append(UInt8(srcPort & 0xFF))
        packet.append(UInt8((dstPort >> 8) & 0xFF))
        packet.append(UInt8(dstPort & 0xFF))
        let udpLength = 8 + payload.count
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: payload)

        return Data(packet)
    }

    private func makeIPv6UDPPacket(src: [UInt8], dst: [UInt8], srcPort: UInt16, dstPort: UInt16, payload: [UInt8]) -> Data {
        var packet: [UInt8] = []
        let payloadLength = 8 + payload.count
        packet.append(0x60)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(UInt8((payloadLength >> 8) & 0xFF))
        packet.append(UInt8(payloadLength & 0xFF))
        packet.append(17)
        packet.append(64)
        packet.append(contentsOf: src)
        packet.append(contentsOf: dst)

        packet.append(UInt8((srcPort >> 8) & 0xFF))
        packet.append(UInt8(srcPort & 0xFF))
        packet.append(UInt8((dstPort >> 8) & 0xFF))
        packet.append(UInt8(dstPort & 0xFF))
        packet.append(UInt8((payloadLength >> 8) & 0xFF))
        packet.append(UInt8(payloadLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: payload)

        return Data(packet)
    }

    private func makeDNSQueryPayload(hostname: String) -> [UInt8] {
        var payload: [UInt8] = []
        payload.append(0x12)
        payload.append(0x34)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)

        let labels = hostname.split(separator: ".")
        for label in labels {
            payload.append(UInt8(label.count))
            payload.append(contentsOf: label.utf8)
        }
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x01)
        return payload
    }

    private func makeQuicLongHeader(version: UInt32, packetType: UInt8, dcid: [UInt8], scid: [UInt8]) -> [UInt8] {
        var payload: [UInt8] = []
        let firstByte = UInt8(0xC0) | ((packetType & 0x03) << 4)
        payload.append(firstByte)
        payload.append(UInt8((version >> 24) & 0xFF))
        payload.append(UInt8((version >> 16) & 0xFF))
        payload.append(UInt8((version >> 8) & 0xFF))
        payload.append(UInt8(version & 0xFF))
        payload.append(UInt8(dcid.count))
        payload.append(contentsOf: dcid)
        payload.append(UInt8(scid.count))
        payload.append(contentsOf: scid)
        return payload
    }

    private func makeQuicV1InitialPacket(hostname: String) -> [UInt8] {
        let dcid: [UInt8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        let scid: [UInt8] = []
        let token: [UInt8] = []
        let handshake = makeTLSClientHello(hostname: hostname)
        let cryptoFrame = [UInt8(0x06)] + encodeVarInt(0) + encodeVarInt(handshake.count) + handshake

        let pnLength = 4
        let packetNumber: UInt32 = 1
        let payloadLength = cryptoFrame.count + 16
        let lengthField = encodeVarInt(pnLength + payloadLength)

        var header: [UInt8] = []
        header.append(0xC0 | UInt8(pnLength - 1))
        header.append(contentsOf: [0x00, 0x00, 0x00, 0x01])
        header.append(UInt8(dcid.count))
        header.append(contentsOf: dcid)
        header.append(UInt8(scid.count))
        header.append(contentsOf: scid)
        header.append(contentsOf: encodeVarInt(token.count))
        header.append(contentsOf: token)
        header.append(contentsOf: lengthField)

        let pnOffset = header.count
        var packet: [UInt8] = header
        packet.append(contentsOf: [
            UInt8((packetNumber >> 24) & 0xff),
            UInt8((packetNumber >> 16) & 0xff),
            UInt8((packetNumber >> 8) & 0xff),
            UInt8(packetNumber & 0xff)
        ])

        let secrets = deriveQuicInitialSecrets(dcid: Data(dcid))
        let aad = Data(packet)
        let nonce = makeQuicNonce(iv: secrets.clientIv, packetNumber: packetNumber)
        let sealed = try? AES.GCM.seal(
            Data(cryptoFrame),
            using: secrets.clientKey,
            nonce: nonce,
            authenticating: aad
        )
        guard let sealed else { return packet }
        packet.append(contentsOf: sealed.ciphertext)
        packet.append(contentsOf: sealed.tag)

        let sampleOffset = pnOffset + pnLength
        guard packet.count >= sampleOffset + 16 else { return packet }
        let sample = Data(packet[sampleOffset..<(sampleOffset + 16)])
        if let mask = aes128EncryptBlock(key: secrets.clientHp, block: sample) {
            packet[0] ^= mask[0] & 0x0f
            for i in 0..<pnLength {
                packet[pnOffset + i] ^= mask[i + 1]
            }
        }

        return packet
    }

    private func makeTLSClientHello(hostname: String) -> [UInt8] {
        let hostBytes = [UInt8](hostname.utf8)
        let sniListLength = 1 + 2 + hostBytes.count
        let sniExtensionLength = 2 + sniListLength
        let extensionsLength = 4 + sniExtensionLength

        var body: [UInt8] = []
        body.append(contentsOf: [0x03, 0x03])
        body.append(contentsOf: [UInt8](repeating: 0, count: 32))
        body.append(0x00)
        body.append(contentsOf: [0x00, 0x02, 0x13, 0x01])
        body.append(0x01)
        body.append(0x00)
        body.append(contentsOf: [
            UInt8((extensionsLength >> 8) & 0xff),
            UInt8(extensionsLength & 0xff)
        ])
        body.append(contentsOf: [0x00, 0x00])
        body.append(contentsOf: [
            UInt8((sniExtensionLength >> 8) & 0xff),
            UInt8(sniExtensionLength & 0xff)
        ])
        body.append(contentsOf: [
            UInt8((sniListLength >> 8) & 0xff),
            UInt8(sniListLength & 0xff)
        ])
        body.append(0x00)
        body.append(contentsOf: [
            UInt8((hostBytes.count >> 8) & 0xff),
            UInt8(hostBytes.count & 0xff)
        ])
        body.append(contentsOf: hostBytes)

        var handshake: [UInt8] = []
        handshake.append(0x01)
        let length = body.count
        handshake.append(UInt8((length >> 16) & 0xff))
        handshake.append(UInt8((length >> 8) & 0xff))
        handshake.append(UInt8(length & 0xff))
        handshake.append(contentsOf: body)
        return handshake
    }

    private func encodeVarInt(_ value: Int) -> [UInt8] {
        if value < (1 << 6) {
            return [UInt8(value & 0x3f)]
        }
        if value < (1 << 14) {
            let v = value | 0x4000
            return [UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
        }
        if value < (1 << 30) {
            let v = value | 0x80000000
            return [
                UInt8((v >> 24) & 0xff),
                UInt8((v >> 16) & 0xff),
                UInt8((v >> 8) & 0xff),
                UInt8(v & 0xff)
            ]
        }
        let v = UInt64(value) | 0xC000000000000000
        return [
            UInt8((v >> 56) & 0xff),
            UInt8((v >> 48) & 0xff),
            UInt8((v >> 40) & 0xff),
            UInt8((v >> 32) & 0xff),
            UInt8((v >> 24) & 0xff),
            UInt8((v >> 16) & 0xff),
            UInt8((v >> 8) & 0xff),
            UInt8(v & 0xff)
        ]
    }

    private func deriveQuicInitialSecrets(dcid: Data) -> (clientKey: SymmetricKey, clientIv: Data, clientHp: Data) {
        let salt = Data([
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
        ])
        let initialSecret = hkdfExtract(salt: salt, ikm: dcid)
        let clientSecret = hkdfExpandLabel(secret: initialSecret, label: "client in", length: 32)
        let clientKey = SymmetricKey(data: hkdfExpandLabel(secret: SymmetricKey(data: clientSecret), label: "quic key", length: 16))
        let clientIv = hkdfExpandLabel(secret: SymmetricKey(data: clientSecret), label: "quic iv", length: 12)
        let clientHp = hkdfExpandLabel(secret: SymmetricKey(data: clientSecret), label: "quic hp", length: 16)
        return (clientKey, clientIv, clientHp)
    }

    private func hkdfExtract(salt: Data, ikm: Data) -> SymmetricKey {
        let key = SymmetricKey(data: salt)
        let prk = HMAC<SHA256>.authenticationCode(for: ikm, using: key)
        return SymmetricKey(data: Data(prk))
    }

    private func hkdfExpandLabel(secret: SymmetricKey, label: String, length: Int) -> Data {
        let fullLabel = "tls13 " + label
        var info = Data()
        var lengthBytes = UInt16(length).bigEndian
        withUnsafeBytes(of: &lengthBytes) { info.append(contentsOf: $0) }
        info.append(UInt8(fullLabel.utf8.count))
        info.append(contentsOf: fullLabel.utf8)
        info.append(0)
        return hkdfExpand(secret: secret, info: info, length: length)
    }

    private func hkdfExpand(secret: SymmetricKey, info: Data, length: Int) -> Data {
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

    private func makeQuicNonce(iv: Data, packetNumber: UInt32) -> AES.GCM.Nonce {
        var nonce = [UInt8](iv)
        var pnBytes = [UInt8](repeating: 0, count: 8)
        pnBytes[4] = UInt8((packetNumber >> 24) & 0xff)
        pnBytes[5] = UInt8((packetNumber >> 16) & 0xff)
        pnBytes[6] = UInt8((packetNumber >> 8) & 0xff)
        pnBytes[7] = UInt8(packetNumber & 0xff)
        for i in 0..<8 {
            nonce[nonce.count - 8 + i] ^= pnBytes[i]
        }
        return try! AES.GCM.Nonce(data: Data(nonce))
    }

    private func aes128EncryptBlock(key: Data, block: Data) -> Data? {
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

    private func aes128ExpandKey(_ key: [UInt8]) -> [UInt8] {
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

    private func rotWord(_ word: [UInt8]) -> [UInt8] {
        [word[1], word[2], word[3], word[0]]
    }

    private func subWord(_ word: [UInt8]) -> [UInt8] {
        word.map { aesSBox[Int($0)] }
    }

    private func rcon(_ iteration: UInt8) -> UInt8 {
        var value: UInt8 = 1
        if iteration == 0 { return 0 }
        for _ in 1..<iteration {
            value = xtime(value)
        }
        return value
    }

    private func addRoundKey(_ state: inout [UInt8], roundKey: [UInt8], round: Int) {
        let start = round * 16
        for i in 0..<16 {
            state[i] ^= roundKey[start + i]
        }
    }

    private func subBytes(_ state: inout [UInt8]) {
        for i in 0..<16 {
            state[i] = aesSBox[Int(state[i])]
        }
    }

    private func shiftRows(_ state: inout [UInt8]) {
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

    private func mixColumns(_ state: inout [UInt8]) {
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

    private func xtime(_ value: UInt8) -> UInt8 {
        let shifted = value << 1
        return (value & 0x80) != 0 ? shifted ^ 0x1b : shifted
    }

    private let aesSBox: [UInt8] = [
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
}
