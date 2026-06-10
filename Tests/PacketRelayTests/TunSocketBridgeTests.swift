import Darwin
import Foundation
import Observability
@testable import PacketRelay
import XCTest

final class TunSocketBridgeTests: XCTestCase {
    func testWritePacketRejectsPacketLargerThanBridgeFrameLimit() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.bridge.oversized-outbound")
        let bridge = try TunSocketBridge(
            mtu: 1500,
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        defer { bridge.stop() }

        let result = bridge.writePacket(Data(repeating: 0xAB, count: 65_536), ipVersionHint: AF_INET)
        XCTAssertEqual(result, .failed(errorCode: EMSGSIZE))
    }

    func testReadLoopDoesNotTruncateDataplanePacketLargerThanMTUHint() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.bridge.large-inbound")
        let bridge = try TunSocketBridge(
            mtu: 512,
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        defer { bridge.stop() }

        let capture = BridgeReadCapture()
        bridge.startReadLoop { packets, families in
            capture.record(packets: packets, families: families)
        }

        let payload = Data(repeating: 0xAB, count: 2_048)
        let frame = Self.bridgeFrame(payload: payload, family: AF_INET)
        let written = frame.withUnsafeBytes { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return write(bridge.engineFD, base, frame.count)
        }
        XCTAssertEqual(written, frame.count)

        XCTAssertEqual(capture.wait(timeoutSeconds: 1.0), .success)
        let snapshot = capture.snapshot()
        XCTAssertEqual(snapshot.packets, [payload])
        XCTAssertEqual(snapshot.families, [AF_INET])
    }

    private static func bridgeFrame(payload: Data, family: Int32) -> Data {
        var header = UInt32(family).bigEndian
        var frame = Data(capacity: MemoryLayout<UInt32>.size + payload.count)
        withUnsafeBytes(of: &header) { headerPtr in
            frame.append(headerPtr.bindMemory(to: UInt8.self))
        }
        frame.append(payload)
        return frame
    }
}

private final class BridgeReadCapture: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var storedPackets: [Data] = []
    private var storedFamilies: [Int32] = []

    func record(packets: [Data], families: [Int32]) {
        lock.lock()
        storedPackets = packets
        storedFamilies = families
        lock.unlock()
        semaphore.signal()
    }

    func wait(timeoutSeconds: TimeInterval) -> DispatchTimeoutResult {
        semaphore.wait(timeout: .now() + timeoutSeconds)
    }

    func snapshot() -> (packets: [Data], families: [Int32]) {
        lock.lock()
        defer { lock.unlock() }
        return (storedPackets, storedFamilies)
    }
}

extension TunSocketBridgeTests {
    /// Regression: `stop()` must coordinate write-source suspend/resume balance on the bridge queue.
    /// Concurrent writers racing a stop previously risked cancelling a suspended dispatch source or
    /// over-resuming an active one, both of which crash in libdispatch.
    func testStopWhileConcurrentWritesInFlightDoesNotCrash() throws {
        for round in 0..<8 {
            let queue = DispatchQueue(label: "com.vpnbridge.tests.bridge.stop-race.\(round)")
            let bridge = try TunSocketBridge(
                mtu: 1_500,
                queue: queue,
                logger: StructuredLogger(sink: InMemoryLogSink())
            )
            bridge.startReadLoop { _, _ in }

            let packet = Data(repeating: 0x45, count: 1_200)
            let group = DispatchGroup()
            for worker in 0..<4 {
                DispatchQueue.global().async(group: group) {
                    for _ in 0..<100 {
                        _ = bridge.writePacket(packet, ipVersionHint: AF_INET)
                    }
                    _ = worker
                }
            }
            DispatchQueue.global().async(group: group) {
                bridge.stop()
            }

            XCTAssertEqual(group.wait(timeout: .now() + 10), .success, "round \(round)")
            bridge.stop()
        }
    }

    /// `stop()` must be idempotent and safe before the read loop ever starts.
    func testStopBeforeReadLoopStartIsSafe() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.bridge.early-stop")
        let bridge = try TunSocketBridge(
            mtu: 1_500,
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        bridge.stop()
        bridge.stop()
        XCTAssertEqual(bridge.writePacket(Data([0x45]), ipVersionHint: AF_INET), .failed(errorCode: EBADF))
    }
}
