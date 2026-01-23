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
}
