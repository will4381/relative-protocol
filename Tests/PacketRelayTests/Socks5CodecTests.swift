import Foundation
@testable import PacketRelay
import XCTest

final class Socks5CodecTests: XCTestCase {
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
    }
}
