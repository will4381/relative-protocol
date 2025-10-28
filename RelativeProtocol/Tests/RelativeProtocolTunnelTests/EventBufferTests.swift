import XCTest
import RelativeProtocolCore

final class EventBufferTests: XCTestCase {
    func testFlushTriggeredByCapacity() {
        let configuration = RelativeProtocol.EventBuffer.Configuration(capacity: 2, flushInterval: 10)
        let buffer = RelativeProtocol.EventBuffer(configuration: configuration)

        let first = RelativeProtocol.TrafficEvent(category: .observation, details: ["index": "1"])
        let second = RelativeProtocol.TrafficEvent(category: .observation, details: ["index": "2"])

        XCTAssertFalse(buffer.append(first))
        XCTAssertTrue(buffer.append(second), "Second append should trigger flush by capacity")

        let drained = buffer.drain()
        XCTAssertEqual(drained.count, 2)
        XCTAssertTrue(drained.contains(where: { $0.details["index"] == "1" }))
        XCTAssertTrue(drained.contains(where: { $0.details["index"] == "2" }))
    }

    func testFlushTriggeredByInterval() {
        let configuration = RelativeProtocol.EventBuffer.Configuration(capacity: 10, flushInterval: 0.001)
        let buffer = RelativeProtocol.EventBuffer(configuration: configuration)

        // Wait long enough for the flush interval to elapse.
        let first = RelativeProtocol.TrafficEvent(category: .observation, details: ["index": "1"])
        XCTAssertFalse(buffer.append(first))

        Thread.sleep(forTimeInterval: 0.02)

        let second = RelativeProtocol.TrafficEvent(category: .observation, details: ["index": "2"])
        XCTAssertTrue(buffer.append(second), "Elapsed interval should request a flush")

        let drained = buffer.drain()
        XCTAssertEqual(drained.count, 2)
        XCTAssertTrue(drained.contains(where: { $0.details["index"] == "1" }))
        XCTAssertTrue(drained.contains(where: { $0.details["index"] == "2" }))
    }
}
