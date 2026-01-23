import XCTest
import RelativeProtocolCore

final class MetricsRingBufferTests: XCTestCase {
    func testRingBufferOverwritesOldest() {
        let buffer = MetricsRingBuffer(capacity: 3)
        buffer.append(makeSample(id: 1))
        buffer.append(makeSample(id: 2))
        buffer.append(makeSample(id: 3))
        buffer.append(makeSample(id: 4))

        let snapshot = buffer.snapshot()
        XCTAssertEqual(snapshot.count, 3)
        XCTAssertEqual(snapshot.first?.flowId, 2)
        XCTAssertEqual(snapshot.last?.flowId, 4)
    }

    func testClearEmptiesBuffer() {
        let buffer = MetricsRingBuffer(capacity: 2)
        buffer.append(makeSample(id: 1))
        buffer.clear()
        XCTAssertTrue(buffer.snapshot().isEmpty)
    }

    private func makeSample(id: UInt64) -> PacketSample {
        PacketSample(
            timestamp: 1,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 64,
            flowId: id,
            burstId: 0,
            srcPort: 1234,
            dstPort: 53,
            dnsQueryName: nil
        )
    }
}
