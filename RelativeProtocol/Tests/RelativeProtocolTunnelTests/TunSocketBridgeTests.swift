// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import XCTest
@testable import RelativeProtocolTunnel

final class TunSocketBridgeTests: XCTestCase {
    func testWritePacketPrefixesFamilyHeader() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.test.write"))
        defer { bridge.stop() }

        let payload = Data([0x45, 0x00, 0x00, 0x00])
        XCTAssertTrue(bridge.writePacket(payload, ipVersionHint: Int32(AF_INET)))

        let received = try readDatagram(fd: bridge.engineFD, maxSize: 64)
        XCTAssertEqual(received.count, payload.count + 4)
        XCTAssertEqual(readFamily(from: received), Int32(AF_INET))
        XCTAssertEqual(received.dropFirst(4), payload)
    }

    func testWritePacketInfersIPv6FromPayload() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.test.infer"))
        defer { bridge.stop() }

        let payload = Data([0x60, 0x00, 0x00, 0x00])
        XCTAssertTrue(bridge.writePacket(payload, ipVersionHint: 0))

        let received = try readDatagram(fd: bridge.engineFD, maxSize: 64)
        XCTAssertEqual(readFamily(from: received), Int32(AF_INET6))
    }

    func testReadLoopDeliversPayloadAndInferredFamily() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.test.read"))
        defer { bridge.stop() }

        let expectation = XCTestExpectation(description: "read loop")
        let payload = Data([0x60, 0x00, 0x00, 0x00, 0x01])

        bridge.startReadLoop { packets, families in
            XCTAssertEqual(packets.first, payload)
            XCTAssertEqual(families.first, Int32(AF_INET6))
            expectation.fulfill()
        }

        var header = UInt32(0).bigEndian
        var packet = Data()
        withUnsafeBytes(of: &header) { packet.append(contentsOf: $0) }
        packet.append(payload)
        try sendDatagram(fd: bridge.engineFD, data: packet)

        wait(for: [expectation], timeout: 1.0)
    }
}

private func readDatagram(fd: Int32, maxSize: Int, timeout: TimeInterval = 1.0) throws -> Data {
    var buffer = [UInt8](repeating: 0, count: maxSize)
    let deadline = Date().addingTimeInterval(timeout)
    while true {
        let bytesRead = recv(fd, &buffer, buffer.count, 0)
        if bytesRead > 0 {
            return Data(buffer[0..<bytesRead])
        }
        if bytesRead == 0 {
            throw POSIXError(.ECONNRESET)
        }
        if errno == EAGAIN || errno == EWOULDBLOCK {
            if Date() > deadline {
                throw POSIXError(.ETIMEDOUT)
            }
            usleep(1_000)
            continue
        }
        throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
    }
}

private func sendDatagram(fd: Int32, data: Data) throws {
    let result = data.withUnsafeBytes { buffer -> ssize_t in
        guard let base = buffer.baseAddress else { return -1 }
        return send(fd, base, buffer.count, 0)
    }
    guard result == data.count else {
        throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
    }
}

private func readFamily(from data: Data) -> Int32 {
    var raw: UInt32 = 0
    _ = withUnsafeMutableBytes(of: &raw) { rawBuffer in
        data.prefix(4).copyBytes(to: rawBuffer)
    }
    let value = UInt32(bigEndian: raw)
    return Int32(value)
}
