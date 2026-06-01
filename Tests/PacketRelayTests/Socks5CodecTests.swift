import Foundation
@testable import PacketRelay
import XCTest

final class Socks5CodecTests: XCTestCase {
    func testBuildReplyEncodesIPv4AddressBytesPrecisely() {
        XCTAssertEqual(
            Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("127.0.0.1"), bindPort: 53_000),
            Data([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0xCF, 0x08])
        )
    }

    func testBuildUDPPacketEncodesIPv4AddressBytesPrecisely() {
        XCTAssertEqual(
            Socks5Codec.buildUDPPacket(address: .ipv4("1.2.3.4"), port: 53, payload: Data([0xAA])),
            Data([0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35, 0xAA])
        )
    }

    func testBuildersRejectInvalidAddresses() {
        XCTAssertNil(Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("999.0.0.1"), bindPort: 53))
        XCTAssertNil(Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv6("not-ipv6"), bindPort: 53))
        XCTAssertNil(Socks5Codec.buildUDPPacket(address: .domain(""), port: 53, payload: Data()))
        XCTAssertNil(
            Socks5Codec.buildUDPPacket(
                address: .domain(String(repeating: "a", count: 256)),
                port: 53,
                payload: Data()
            )
        )
    }

    func testTCPForwardUDPFrameRoundTripsAndReportsConsumedBytes() throws {
        let firstPayload = Data([0x01, 0x02, 0x03])
        let secondPayload = Data([0x04, 0x05])
        let firstFrame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .domain("i.instagram.com"),
                port: 443,
                payload: firstPayload
            )
        )
        let secondFrame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .ipv4("1.1.1.1"),
                port: 53,
                payload: secondPayload
            )
        )

        var stream = firstFrame
        stream.append(secondFrame)

        guard case .packet(let firstPacket, let consumedBytes) = Socks5Codec.parseTCPForwardUDPPacket(stream) else {
            XCTFail("Expected complete first TCP-carried UDP frame")
            return
        }

        XCTAssertEqual(
            firstPacket,
            Socks5UDPPacket(address: .domain("i.instagram.com"), port: 443, payload: firstPayload)
        )
        XCTAssertEqual(consumedBytes, firstFrame.count)

        let remaining = Data(stream.dropFirst(consumedBytes))
        guard case .packet(let secondPacket, let secondConsumedBytes) = Socks5Codec.parseTCPForwardUDPPacket(remaining) else {
            XCTFail("Expected complete second TCP-carried UDP frame")
            return
        }

        XCTAssertEqual(
            secondPacket,
            Socks5UDPPacket(address: .ipv4("1.1.1.1"), port: 53, payload: secondPayload)
        )
        XCTAssertEqual(secondConsumedBytes, secondFrame.count)
    }

    func testTCPForwardUDPParserWaitsForIncompleteHeaderAndPayload() {
        XCTAssertEqual(Socks5Codec.parseTCPForwardUDPPacket(Data([0x00])), .needsMoreData)

        let incompletePayload = Data([
            0x00, 0x03, 0x0A,
            0x01, 0x01, 0x01, 0x01, 0x01,
            0x00, 0x35,
            0xAA
        ])
        XCTAssertEqual(Socks5Codec.parseTCPForwardUDPPacket(incompletePayload), .needsMoreData)
    }

    func testTCPForwardUDPParserRejectsInvalidHeaderLength() {
        let invalidHeaderLength = Data([0x00, 0x00, 0x06, 0x01, 0x01, 0x01])

        XCTAssertEqual(Socks5Codec.parseTCPForwardUDPPacket(invalidHeaderLength), .invalid)
    }

    func testTCPForwardUDPParserRejectsMalformedAddressType() {
        let invalidAddressType = Data([
            0x00, 0x00, 0x07,
            0x09, 0x00, 0x00, 0x00
        ])

        XCTAssertEqual(Socks5Codec.parseTCPForwardUDPPacket(invalidAddressType), .invalid)
    }

    func testTCPForwardUDPParserRejectsEmptyDomainAddress() {
        let emptyDomain = Data([
            0x00, 0x00, 0x06,
            0x03, 0x00, 0x01, 0xbb
        ])

        XCTAssertEqual(Socks5Codec.parseTCPForwardUDPPacket(emptyDomain), .invalid)
    }

    func testSocksRequestParserRejectsEmptyDomainAddress() {
        var request = Data([
            0x05, 0x01, 0x00, 0x03,
            0x00,
            0x01, 0xbb
        ])

        XCTAssertNil(Socks5Codec.parseRequest(&request))
    }

    func testRequestFailureReplyCodeRejectsEmptyDomainAddress() {
        let request = Data([
            0x05, 0x01, 0x00, 0x03,
            0x00,
            0x01, 0xbb
        ])

        XCTAssertEqual(Socks5Codec.requestFailureReplyCode(request), 0x08)
    }

    func testUDPPacketParserRejectsEmptyDomainAddress() {
        let packet = Data([
            0x00, 0x00, 0x00, 0x03,
            0x00,
            0x00, 0x35
        ])

        let parsed = packet.withUnsafeBytes { rawBuffer -> Socks5UDPPacket? in
            let bytes = rawBuffer.bindMemory(to: UInt8.self)
            guard let baseAddress = bytes.baseAddress else {
                return nil
            }
            return Socks5Codec.parseUDPPacket(
                UnsafeBufferPointer(start: baseAddress, count: packet.count),
                count: packet.count
            )
        }
        XCTAssertNil(parsed)
    }

    func testGreetingPrefixValidationRejectsNonSocksVersion() {
        XCTAssertFalse(Socks5Codec.hasInvalidGreetingPrefix(Data()))
        XCTAssertFalse(Socks5Codec.hasInvalidGreetingPrefix(Data([0x05])))
        XCTAssertTrue(Socks5Codec.hasInvalidGreetingPrefix(Data([0x04])))
    }

    func testTCPForwardUDPParserRejectsAddressHeaderWithoutCompletePort() {
        let missingPortByte = Data([
            0x00, 0x00, 0x09,
            0x01, 0x01, 0x01, 0x01, 0x01,
            0x00
        ])

        XCTAssertEqual(Socks5Codec.parseTCPForwardUDPPacket(missingPortByte), .invalid)
    }

    func testTCPForwardUDPBuilderRejectsFramesThatCannotFitHEVHeader() {
        let oversizedPayload = Data(repeating: 0xAB, count: Int(UInt16.max) + 1)
        XCTAssertNil(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .ipv4("1.1.1.1"),
                port: 53,
                payload: oversizedPayload
            )
        )

        let overlongDomain = String(repeating: "a", count: 249)
        XCTAssertNil(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .domain(overlongDomain),
                port: 443,
                payload: Data()
            )
        )

        XCTAssertNil(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .domain(""),
                port: 443,
                payload: Data()
            )
        )
    }
}
