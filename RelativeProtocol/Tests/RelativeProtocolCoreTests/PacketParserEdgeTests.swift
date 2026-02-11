// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Darwin
import Foundation
import XCTest
import RelativeProtocolCore

final class PacketParserEdgeTests: XCTestCase {
    func testParseRejectsEmptyPacket() {
        XCTAssertNil(PacketParser.parse(Data(), ipVersionHint: AF_INET))
    }

    func testParseReturnsNilWhenHintConflictsWithHeaderVersion() {
        let payload = [UInt8](repeating: 0, count: 8)
        var packet = makeIPv4UDPPacket(
            src: [192, 168, 1, 2],
            dst: [8, 8, 8, 8],
            srcPort: 12345,
            dstPort: 53,
            payload: payload
        )
        packet[0] = 0x00

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertNil(metadata)
    }

    func testParseReturnsNilWithoutVersionAndHint() {
        var packet = Data([0x00, 0x01, 0x02, 0x03])
        packet.append(contentsOf: [UInt8](repeating: 0x00, count: 32))
        XCTAssertNil(PacketParser.parse(packet, ipVersionHint: nil))
    }

    func testParseIPv4RejectsInvalidIHL() {
        var packet = Data([0x44, 0x00])
        packet.append(contentsOf: [UInt8](repeating: 0x00, count: 38))
        XCTAssertNil(PacketParser.parse(packet, ipVersionHint: AF_INET))
    }

    func testParseIPv6WithFragmentHeaderAndUDP() {
        let src = [UInt8](repeating: 0, count: 15) + [1]
        let dst = [UInt8](repeating: 0, count: 15) + [2]
        let udpPayload = [UInt8](repeating: 0x11, count: 8)

        let udpLength = 8 + udpPayload.count
        let fragmentHeaderLength = 8
        let payloadLength = fragmentHeaderLength + udpLength

        var packet: [UInt8] = []
        packet.append(0x60)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(UInt8((payloadLength >> 8) & 0xFF))
        packet.append(UInt8(payloadLength & 0xFF))
        packet.append(44) // fragment
        packet.append(64)
        packet.append(contentsOf: src)
        packet.append(contentsOf: dst)

        packet.append(17) // next header UDP
        packet.append(0)  // reserved
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // fragment offset/flags/id
        packet.append(contentsOf: [0x00, 0x00]) // id cont.

        let srcPort: UInt16 = 45000
        let dstPort: UInt16 = 53
        packet.append(UInt8((srcPort >> 8) & 0xFF))
        packet.append(UInt8(srcPort & 0xFF))
        packet.append(UInt8((dstPort >> 8) & 0xFF))
        packet.append(UInt8(dstPort & 0xFF))
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: udpPayload)

        let metadata = PacketParser.parse(Data(packet), ipVersionHint: AF_INET6)
        XCTAssertEqual(metadata?.ipVersion, .v6)
        XCTAssertEqual(metadata?.transport, .udp)
        XCTAssertEqual(metadata?.srcPort, srcPort)
        XCTAssertEqual(metadata?.dstPort, dstPort)
    }

    func testParseIPv6ESPReturnsMetadataWithoutPorts() {
        let src = [UInt8](repeating: 0, count: 15) + [1]
        let dst = [UInt8](repeating: 0, count: 15) + [2]
        var packet: [UInt8] = []
        packet.append(0x60)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x08)
        packet.append(50) // ESP
        packet.append(64)
        packet.append(contentsOf: src)
        packet.append(contentsOf: dst)
        packet.append(contentsOf: [UInt8](repeating: 0x00, count: 8))

        let metadata = PacketParser.parse(Data(packet), ipVersionHint: AF_INET6)
        XCTAssertEqual(metadata?.ipVersion, .v6)
        XCTAssertEqual(metadata?.transport.rawValue, 50)
        XCTAssertNil(metadata?.srcPort)
        XCTAssertNil(metadata?.dstPort)
    }

    func testParseTCPClientHelloLikePayloadKeepsMetadataConsistent() {
        let clientHello = makeValidTLSClientHello(hostname: "secure.example.com")
        let record = makeTLSRecord(payload: clientHello)
        let packet = makeIPv4TCPPacket(
            src: [10, 0, 0, 1],
            dst: [1, 1, 1, 1],
            srcPort: 53100,
            dstPort: 443,
            payload: record
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.transport, .tcp)
        XCTAssertEqual(metadata?.srcPort, 53100)
        XCTAssertEqual(metadata?.dstPort, 443)
    }

    func testParseTCPWithNonTLSPayloadKeepsSniNil() {
        let payload = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x00]) // not handshake content type
        let packet = makeIPv4TCPPacket(
            src: [10, 0, 0, 1],
            dst: [1, 1, 1, 1],
            srcPort: 50000,
            dstPort: 443,
            payload: payload
        )
        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertNil(metadata?.tlsServerName)
    }

    func testParseDNSResponseExtractsCnameAndAnswerAddresses() {
        let dnsPayload = makeDNSResponsePayload(
            query: "video.example.com",
            cname: "edge.example.com",
            ipv4Answer: [203, 0, 113, 15]
        )
        let packet = makeIPv4UDPPacket(
            src: [8, 8, 8, 8],
            dst: [192, 168, 1, 20],
            srcPort: 53,
            dstPort: 51000,
            payload: dnsPayload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.dnsQueryName, "video.example.com")
        XCTAssertEqual(metadata?.dnsCname, "edge.example.com")
        XCTAssertEqual(metadata?.dnsAnswerAddresses?.first?.stringValue, "203.0.113.15")
    }

    func testParseDNSHandlesCompressionPointers() {
        let payload = makeCompressedDNSQueryPayload(hostname: "pointer.example.com")
        let packet = makeIPv4UDPPacket(
            src: [192, 168, 1, 2],
            dst: [1, 1, 1, 1],
            srcPort: 53000,
            dstPort: 53,
            payload: payload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.dnsQueryName, "pointer.example.com")
    }

    func testParseQuicV1RetryMapsPacketType() {
        let quicPayload = makeQuicLongHeader(
            version: 0x00000001,
            packetType: 0x03,
            dcid: [0x01, 0x02, 0x03, 0x04],
            scid: [0x05, 0x06, 0x07, 0x08]
        )
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 9],
            dst: [1, 1, 1, 1],
            srcPort: 44000,
            dstPort: 443,
            payload: quicPayload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.quicVersion, 0x00000001)
        XCTAssertEqual(metadata?.quicPacketType, .retry)
    }

    func testParseQuicV2HandshakeMapsPacketType() {
        let quicPayload = makeQuicLongHeader(
            version: 0x6b3343cf,
            packetType: 0x03,
            dcid: [0x0a, 0x0b, 0x0c, 0x0d],
            scid: [0x10, 0x11, 0x12, 0x13]
        )
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 10],
            dst: [1, 1, 1, 1],
            srcPort: 44001,
            dstPort: 443,
            payload: quicPayload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.quicVersion, 0x6b3343cf)
        XCTAssertEqual(metadata?.quicPacketType, .handshake)
    }

    func testParseQuicShortHeaderDoesNotSetQuicMetadata() {
        let shortHeaderPayload = Data([0x40, 0x12, 0x34, 0x56, 0x78])
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 11],
            dst: [1, 1, 1, 1],
            srcPort: 44002,
            dstPort: 443,
            payload: [UInt8](shortHeaderPayload)
        )
        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)

        XCTAssertNil(metadata?.quicVersion)
        XCTAssertNil(metadata?.quicPacketType)
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

    private func makeIPv4TCPPacket(src: [UInt8], dst: [UInt8], srcPort: UInt16, dstPort: UInt16, payload: Data) -> Data {
        let tcpHeaderLength = 20
        let totalLength = 20 + tcpHeaderLength + payload.count
        var packet: [UInt8] = []
        packet.append(0x45)
        packet.append(0x00)
        packet.append(UInt8((totalLength >> 8) & 0xFF))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(64)
        packet.append(6)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: src)
        packet.append(contentsOf: dst)

        packet.append(UInt8((srcPort >> 8) & 0xFF))
        packet.append(UInt8(srcPort & 0xFF))
        packet.append(UInt8((dstPort >> 8) & 0xFF))
        packet.append(UInt8(dstPort & 0xFF))
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x01]) // seq
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // ack
        packet.append(0x50) // data offset 5
        packet.append(0x18) // flags
        packet.append(0x20)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: payload)

        return Data(packet)
    }

    private func makeTLSRecord(payload: [UInt8]) -> Data {
        var record: [UInt8] = []
        record.append(22)
        record.append(0x03)
        record.append(0x03)
        record.append(UInt8((payload.count >> 8) & 0xFF))
        record.append(UInt8(payload.count & 0xFF))
        record.append(contentsOf: payload)
        return Data(record)
    }

    private func makeValidTLSClientHello(hostname: String) -> [UInt8] {
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

    private func makeDNSResponsePayload(query: String, cname: String, ipv4Answer: [UInt8]) -> [UInt8] {
        var payload: [UInt8] = []
        payload.append(contentsOf: [0x12, 0x34]) // id
        payload.append(contentsOf: [0x81, 0x80]) // standard response
        payload.append(contentsOf: [0x00, 0x01]) // qdcount
        payload.append(contentsOf: [0x00, 0x02]) // ancount
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // ns/ar

        let queryLabels = query.split(separator: ".")
        for label in queryLabels {
            payload.append(UInt8(label.count))
            payload.append(contentsOf: label.utf8)
        }
        payload.append(0x00)
        payload.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN

        // Answer 1: CNAME for query name
        payload.append(contentsOf: [0xC0, 0x0C]) // pointer to qname
        payload.append(contentsOf: [0x00, 0x05, 0x00, 0x01]) // CNAME IN
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // ttl
        let cnameLabels = cname.split(separator: ".")
        var cnameRdata: [UInt8] = []
        for label in cnameLabels {
            cnameRdata.append(UInt8(label.count))
            cnameRdata.append(contentsOf: label.utf8)
        }
        cnameRdata.append(0x00)
        payload.append(UInt8((cnameRdata.count >> 8) & 0xFF))
        payload.append(UInt8(cnameRdata.count & 0xFF))
        payload.append(contentsOf: cnameRdata)

        // Answer 2: A record for cname
        payload.append(contentsOf: [0xC0, 0x22]) // pointer to cname name start
        payload.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // ttl
        payload.append(contentsOf: [0x00, 0x04])
        payload.append(contentsOf: ipv4Answer)
        return payload
    }

    private func makeCompressedDNSQueryPayload(hostname: String) -> [UInt8] {
        let labels = hostname.split(separator: ".")
        precondition(labels.count >= 2)

        var payload: [UInt8] = []
        payload.append(contentsOf: [0x56, 0x78]) // id
        payload.append(contentsOf: [0x01, 0x00]) // query
        payload.append(contentsOf: [0x00, 0x01]) // qdcount
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        let first = labels[0]
        let remainder = labels.dropFirst().joined(separator: ".")
        payload.append(UInt8(first.count))
        payload.append(contentsOf: first.utf8)
        let pointerTarget = payload.count + 2
        payload.append(0xC0)
        payload.append(UInt8(pointerTarget))

        for label in remainder.split(separator: ".") {
            payload.append(UInt8(label.count))
            payload.append(contentsOf: label.utf8)
        }
        payload.append(0x00)
        payload.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
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
}
