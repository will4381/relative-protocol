import XCTest
@testable import RelativeProtocolTunnel

final class Socks5CodecTests: XCTestCase {
    func testParseGreeting() {
        var buffer = Data([0x05, 0x01, 0x00])
        let methods = Socks5Codec.parseGreeting(&buffer)
        XCTAssertEqual(methods, [0x00])
        XCTAssertTrue(buffer.isEmpty)
    }

    func testParseIPv4ConnectRequest() {
        var buffer = Data([
            0x05, 0x01, 0x00, 0x01,
            0x7F, 0x00, 0x00, 0x01,
            0x1F, 0x90
        ])
        let request = Socks5Codec.parseRequest(&buffer)
        XCTAssertEqual(request?.command, .connect)
        XCTAssertEqual(request?.address, .ipv4("127.0.0.1"))
        XCTAssertEqual(request?.port, 8080)
        XCTAssertTrue(buffer.isEmpty)
    }

    func testParseIPv6ConnectRequest() {
        var buffer = Data([
            0x05, 0x01, 0x00, 0x04,
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0xBB
        ])
        let request = Socks5Codec.parseRequest(&buffer)
        XCTAssertEqual(request?.command, .connect)
        XCTAssertEqual(request?.address, .ipv6("2001:db8::1"))
        XCTAssertEqual(request?.port, 443)
        XCTAssertTrue(buffer.isEmpty)
    }

    func testParseDomainConnectRequest() {
        let domain = "example.com"
        var buffer = Data([0x05, 0x01, 0x00, 0x03, UInt8(domain.count)])
        buffer.append(contentsOf: domain.utf8)
        buffer.append(contentsOf: [0x00, 0x50])

        let request = Socks5Codec.parseRequest(&buffer)
        XCTAssertEqual(request?.command, .connect)
        XCTAssertEqual(request?.address, .domain(domain))
        XCTAssertEqual(request?.port, 80)
        XCTAssertTrue(buffer.isEmpty)
    }

    func testUDPCodecRoundTrip() {
        let payload = Data([0x01, 0x02, 0x03])
        let packet = Socks5Codec.buildUDPPacket(address: .ipv4("8.8.8.8"), port: 53, payload: payload)
        let parsed = Socks5Codec.parseUDPPacket(packet)
        XCTAssertEqual(parsed?.address, .ipv4("8.8.8.8"))
        XCTAssertEqual(parsed?.port, 53)
        XCTAssertEqual(parsed?.payload, payload)
    }

    func testUDPRejectsNonZeroFragment() {
        var packet = Data([0x00, 0x00, 0x01, 0x01])
        packet.append(contentsOf: [0x08, 0x08, 0x08, 0x08])
        packet.append(contentsOf: [0x00, 0x35, 0x01])
        XCTAssertNil(Socks5Codec.parseUDPPacket(packet))
    }

    func testUDPRejectsNonZeroReserved() {
        var packet = Data([0x00, 0x01, 0x00, 0x01])
        packet.append(contentsOf: [0x08, 0x08, 0x08, 0x08])
        packet.append(contentsOf: [0x00, 0x35, 0x01])
        XCTAssertNil(Socks5Codec.parseUDPPacket(packet))
    }
}
