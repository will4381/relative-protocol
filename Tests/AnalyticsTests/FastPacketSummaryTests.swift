@testable import Analytics
import Darwin
import Foundation
import XCTest

final class FastPacketSummaryTests: XCTestCase {
    func testParsesIPv4TCPSummaryAndFlags() {
        let packet = makeIPv4TCPPacket(
            sourceAddress: [10, 0, 0, 2],
            destinationAddress: [1, 1, 1, 1],
            sourcePort: 50_000,
            destinationPort: 443,
            tcpFlags: 0x02,
            payload: [22, 3, 3, 0, 5]
        )

        let summary = FastPacketSummary(data: Data(packet), ipVersionHint: nil)
        XCTAssertNotNil(summary)
        XCTAssertEqual(summary?.ipVersion, 4)
        XCTAssertEqual(summary?.transportProtocolNumber, 6)
        XCTAssertEqual(summary?.sourcePort, 50_000)
        XCTAssertEqual(summary?.destinationPort, 443)
        XCTAssertEqual(summary?.protocolHint, "tcp")
        XCTAssertTrue(summary?.hasPorts == true)
        XCTAssertTrue(summary?.isTLSClientHelloCandidate == true)
        XCTAssertEqual(addressString(high: summary?.sourceAddressHigh, low: summary?.sourceAddressLow, length: summary?.sourceAddressLength), "10.0.0.2")
        XCTAssertEqual(addressString(high: summary?.destinationAddressHigh, low: summary?.destinationAddressLow, length: summary?.destinationAddressLength), "1.1.1.1")
        XCTAssertNotEqual(summary?.flowHash, 0)
        XCTAssertNotEqual(summary?.reverseFlowHash, 0)
    }

    func testParsesIPv6QUICLongHeaderSummary() {
        let packet = makeIPv6UDPPacket(
            sourceAddress: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1
            ],
            destinationAddress: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 2
            ],
            sourcePort: 50_001,
            destinationPort: 443,
            payload: [
                0xc0,
                0x00, 0x00, 0x00, 0x01,
                0x08,
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                0x04,
                0xfa, 0xce, 0xb0, 0x0c,
            ]
        )

        let summary = FastPacketSummary(data: Data(packet), ipVersionHint: nil)
        XCTAssertNotNil(summary)
        XCTAssertEqual(summary?.ipVersion, 6)
        XCTAssertEqual(summary?.transportProtocolNumber, 17)
        XCTAssertEqual(summary?.sourcePort, 50_001)
        XCTAssertEqual(summary?.destinationPort, 443)
        XCTAssertEqual(summary?.quicVersion, 1)
        XCTAssertEqual(summary?.quicPacketType, .initial)
        XCTAssertEqual(hexString(summary?.quicDestinationConnectionID), "deadbeefdeadbeef")
        XCTAssertEqual(hexString(summary?.quicSourceConnectionID), "faceb00c")
        XCTAssertTrue(summary?.isQUICCandidate == true)
        XCTAssertTrue(summary?.isQUICLongHeader == true)
        XCTAssertTrue(summary?.isQUICInitialCandidate == true)
        XCTAssertEqual(summary?.protocolHint, "udp")
    }

    private func makeIPv4TCPPacket(
        sourceAddress: [UInt8],
        destinationAddress: [UInt8],
        sourcePort: UInt16,
        destinationPort: UInt16,
        tcpFlags: UInt8,
        payload: [UInt8]
    ) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 20 + 20 + payload.count)
        packet[0] = 0x45
        packet[2] = UInt8(packet.count >> 8)
        packet[3] = UInt8(packet.count & 0xff)
        packet[8] = 64
        packet[9] = 6
        packet[12..<16] = sourceAddress[0..<4]
        packet[16..<20] = destinationAddress[0..<4]

        let tcpOffset = 20
        packet[tcpOffset] = UInt8(sourcePort >> 8)
        packet[tcpOffset + 1] = UInt8(sourcePort & 0xff)
        packet[tcpOffset + 2] = UInt8(destinationPort >> 8)
        packet[tcpOffset + 3] = UInt8(destinationPort & 0xff)
        packet[tcpOffset + 12] = 0x50
        packet[tcpOffset + 13] = tcpFlags
        packet[(tcpOffset + 20)...] = payload[0...]
        return packet
    }

    private func makeIPv6UDPPacket(
        sourceAddress: [UInt8],
        destinationAddress: [UInt8],
        sourcePort: UInt16,
        destinationPort: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 40 + 8 + payload.count)
        packet[0] = 0x60
        let payloadLength = 8 + payload.count
        packet[4] = UInt8(payloadLength >> 8)
        packet[5] = UInt8(payloadLength & 0xff)
        packet[6] = 17
        packet[7] = 64
        packet[8..<24] = sourceAddress[0..<16]
        packet[24..<40] = destinationAddress[0..<16]

        let udpOffset = 40
        packet[udpOffset] = UInt8(sourcePort >> 8)
        packet[udpOffset + 1] = UInt8(sourcePort & 0xff)
        packet[udpOffset + 2] = UInt8(destinationPort >> 8)
        packet[udpOffset + 3] = UInt8(destinationPort & 0xff)
        packet[udpOffset + 4] = UInt8(payloadLength >> 8)
        packet[udpOffset + 5] = UInt8(payloadLength & 0xff)
        packet[(udpOffset + 8)...] = payload[0...]
        return packet
    }

    private func addressString(high: UInt64?, low: UInt64?, length: UInt8?) -> String? {
        guard let high, let low, let length, length == 4 || length == 16 else {
            return nil
        }

        var bytes = [UInt8](repeating: 0, count: 16)
        var highBE = high.bigEndian
        var lowBE = low.bigEndian
        withUnsafeBytes(of: &highBE) { bytes.replaceSubrange(0..<8, with: $0) }
        withUnsafeBytes(of: &lowBE) { bytes.replaceSubrange(8..<16, with: $0) }

        if length == 4 {
            var address = in_addr()
            _ = bytes.withUnsafeBytes { rawBuffer in
                memcpy(&address, rawBuffer.baseAddress!.advanced(by: 12), 4)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            let result = withUnsafePointer(to: &address) {
                inet_ntop(AF_INET, UnsafeRawPointer($0), &buffer, socklen_t(INET_ADDRSTRLEN))
            }
            return result == nil ? nil : String(cString: buffer)
        }

        var address = in6_addr()
        _ = bytes.withUnsafeBytes { rawBuffer in
            memcpy(&address, rawBuffer.baseAddress!, 16)
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = withUnsafePointer(to: &address) {
            inet_ntop(AF_INET6, UnsafeRawPointer($0), &buffer, socklen_t(INET6_ADDRSTRLEN))
        }
        return result == nil ? nil : String(cString: buffer)
    }

    private func hexString(_ data: Data?) -> String? {
        guard let data else {
            return nil
        }
        return data.map { String(format: "%02x", $0) }.joined()
    }
}
