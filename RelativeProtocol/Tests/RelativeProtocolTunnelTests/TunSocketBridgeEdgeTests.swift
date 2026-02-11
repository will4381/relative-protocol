// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Darwin
import Foundation
import XCTest
@testable import RelativeProtocolTunnel

final class TunSocketBridgeEdgeTests: XCTestCase {
    func testWritePacketRespectsExplicitFamilyHint() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.hint"))
        defer { bridge.stop() }

        let payload = Data([0x45, 0x00, 0x00, 0x00]) // IPv4-like payload
        XCTAssertTrue(bridge.writePacket(payload, ipVersionHint: Int32(AF_INET6)))

        let datagram = try readDatagramFromBridge(fd: bridge.engineFD, maxSize: 64)
        XCTAssertEqual(readFamilyFromDatagram(datagram), Int32(AF_INET6))
    }

    func testWritePacketDefaultsToIPv4WhenPayloadIsEmpty() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.empty"))
        defer { bridge.stop() }

        XCTAssertTrue(bridge.writePacket(Data(), ipVersionHint: 0))
        let datagram = try readDatagramFromBridge(fd: bridge.engineFD, maxSize: 64)
        XCTAssertEqual(datagram.count, 4)
        XCTAssertEqual(readFamilyFromDatagram(datagram), Int32(AF_INET))
    }

    func testReadLoopInfersIPv4ForUnknownHeaderFamily() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.unknown-family"))
        defer { bridge.stop() }

        let expectation = XCTestExpectation(description: "read")
        let payload = Data([0x45, 0x00, 0x00, 0x01]) // IPv4 version nibble

        bridge.startReadLoop { packets, families in
            XCTAssertEqual(packets.first, payload)
            XCTAssertEqual(families.first, Int32(AF_INET))
            expectation.fulfill()
        }

        var header = UInt32(999).bigEndian
        var packet = Data()
        withUnsafeBytes(of: &header) { packet.append(contentsOf: $0) }
        packet.append(payload)
        try sendDatagramToBridge(fd: bridge.engineFD, data: packet)

        wait(for: [expectation], timeout: 1.0)
    }

    func testWriteAfterStopFailsGracefully() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.stop-write"))
        bridge.stop()

        XCTAssertFalse(bridge.writePacket(Data([0x45, 0x00]), ipVersionHint: Int32(AF_INET)))
    }

    func testStopIsIdempotent() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.stop-idempotent"))
        bridge.stop()
        bridge.stop()
    }

    func testBackpressureIsInitiallyFalse() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.backpressure"))
        defer { bridge.stop() }
        XCTAssertFalse(bridge.isBackpressured())
    }

    func testDebugEnqueueAndDrainWritableFlushesQueuedDatagram() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.drain"))
        defer { bridge.stop() }

        let queued = Data([0x01, 0x02, 0x03, 0x04])
        bridge._test_seedPendingWrites([queued])
        XCTAssertEqual(bridge._test_pendingWriteCount, 1)
        XCTAssertEqual(bridge._test_pendingBytes, queued.count)

        bridge._test_drainWritable()

        XCTAssertEqual(bridge._test_pendingWriteCount, 0)
        XCTAssertEqual(bridge._test_pendingBytes, 0)

        let datagram = try readDatagramFromBridge(fd: bridge.engineFD, maxSize: 64)
        XCTAssertEqual(datagram, queued)
    }

    func testDebugEnqueueRejectsOversizedPayload() throws {
        let bridge = try TunSocketBridge(mtu: 1500, queue: DispatchQueue(label: "tun.edge.oversized"))
        defer { bridge.stop() }

        let tooLarge = Data(repeating: 0xFF, count: bridge._test_maxPendingBytes + 1)
        XCTAssertFalse(bridge._test_enqueueWrite(tooLarge))
        XCTAssertEqual(bridge._test_droppedWrites, 1)
    }
}

private func readDatagramFromBridge(fd: Int32, maxSize: Int, timeout: TimeInterval = 1.0) throws -> Data {
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

private func sendDatagramToBridge(fd: Int32, data: Data) throws {
    let result = data.withUnsafeBytes { buffer -> ssize_t in
        guard let base = buffer.baseAddress else { return -1 }
        return send(fd, base, buffer.count, 0)
    }
    guard result == data.count else {
        throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
    }
}

private func readFamilyFromDatagram(_ data: Data) -> Int32 {
    var raw: UInt32 = 0
    _ = withUnsafeMutableBytes(of: &raw) { dst in
        data.prefix(4).copyBytes(to: dst)
    }
    return Int32(UInt32(bigEndian: raw))
}
