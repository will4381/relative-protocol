// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation
import XCTest
@testable import RelativeProtocolTunnel

final class Socks5CodecEdgeTests: XCTestCase {
    func testParseGreetingRejectsWrongVersion() {
        var buffer = Data([0x04, 0x01, 0x00])
        XCTAssertNil(Socks5Codec.parseGreeting(&buffer))
        XCTAssertEqual(buffer, Data([0x04, 0x01, 0x00]))
    }

    func testParseGreetingRequiresFullMethodList() {
        var buffer = Data([0x05, 0x02, 0x00])
        XCTAssertNil(Socks5Codec.parseGreeting(&buffer))
        XCTAssertEqual(buffer, Data([0x05, 0x02, 0x00]))
    }

    func testParseRequestRejectsWrongVersion() {
        var buffer = Data([0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        XCTAssertNil(Socks5Codec.parseRequest(&buffer))
        XCTAssertEqual(buffer.count, 10)
    }

    func testParseRequestRejectsUnknownCommand() {
        var buffer = Data([0x05, 0x09, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        XCTAssertNil(Socks5Codec.parseRequest(&buffer))
    }

    func testParseRequestRejectsTruncatedIPv4Address() {
        var buffer = Data([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 0x00, 0x50])
        XCTAssertNil(Socks5Codec.parseRequest(&buffer))
    }

    func testParseRequestRejectsTruncatedDomainAddress() {
        var buffer = Data([0x05, 0x01, 0x00, 0x03, 0x05, 0x65, 0x78, 0x61, 0x00, 0x50]) // "exa" but length 5
        XCTAssertNil(Socks5Codec.parseRequest(&buffer))
    }

    func testParseRequestRejectsMissingPort() {
        var buffer = Data([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00])
        XCTAssertNil(Socks5Codec.parseRequest(&buffer))
    }

    func testParseUDPPacketRejectsUnknownAddressType() {
        let packet = Data([0x00, 0x00, 0x00, 0x02, 0x00, 0x35, 0x01])
        XCTAssertNil(Socks5Codec.parseUDPPacket(packet))
    }

    func testParseUDPPacketRejectsTruncatedIPv6Address() {
        var packet = Data([0x00, 0x00, 0x00, 0x04])
        packet.append(contentsOf: [UInt8](repeating: 0x20, count: 8)) // needs 16
        packet.append(contentsOf: [0x00, 0x35])
        XCTAssertNil(Socks5Codec.parseUDPPacket(packet))
    }

    func testUnsafeBufferUDPParserRoundTripIPv6() {
        let payload = Data([0xde, 0xad, 0xbe, 0xef])
        let packet = Socks5Codec.buildUDPPacket(address: .ipv6("2001:db8::1"), port: 5353, payload: payload)

        let parsed = packet.withUnsafeBytes { raw -> Socks5UDPPacket? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            let buffer = UnsafeBufferPointer(start: base, count: packet.count)
            return Socks5Codec.parseUDPPacket(buffer, count: packet.count)
        }

        XCTAssertEqual(parsed?.address, .ipv6("2001:db8::1"))
        XCTAssertEqual(parsed?.port, 5353)
        XCTAssertEqual(parsed?.payload, payload)
    }

    func testUnsafeBufferParserHonorsExplicitCount() {
        let validPayload = Data([0x01, 0x02, 0x03])
        let validPacket = Socks5Codec.buildUDPPacket(address: .ipv4("8.8.8.8"), port: 53, payload: validPayload)
        let originalCount = validPacket.count
        var extended = validPacket
        extended.append(contentsOf: [0xff, 0xee, 0xdd, 0xcc])

        let parsed = extended.withUnsafeBytes { raw -> Socks5UDPPacket? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            let buffer = UnsafeBufferPointer(start: base, count: extended.count)
            return Socks5Codec.parseUDPPacket(buffer, count: originalCount)
        }

        XCTAssertEqual(parsed?.address, .ipv4("8.8.8.8"))
        XCTAssertEqual(parsed?.port, 53)
        XCTAssertEqual(parsed?.payload, validPayload)
    }

    func testBuildReplyFallsBackToZeroAddressForInvalidIPv4String() {
        let reply = Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("not-an-ip"), bindPort: 8080)
        XCTAssertEqual(reply.count, 10)
        XCTAssertEqual(reply[3], 0x01)
        XCTAssertEqual(Array(reply[4...7]), [0, 0, 0, 0])
    }
}
