import XCTest
import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class TrafficAnalyzerTests: XCTestCase {
    func testPublishAppliesRedaction() {
        let stream = RelativeProtocol.PacketStream(configuration: .init(bufferDuration: 60))
        let bus = RelativeProtocol.TrafficEventBus()
        let redactor = RelativeProtocol.TrafficRedactor(
            shouldStripPayloads: true,
            shouldRedactHosts: true,
            redactionToken: "***"
        )

        let analyzer = TrafficAnalyzer(stream: stream, eventBus: bus, configuration: .init(redactor: redactor))

        let expectation = expectation(description: "redacted event published")
        let token = bus.addListener { event in
            XCTAssertNil(event.details["payload"], "Payload should be removed")
            XCTAssertEqual(event.details["host"], "***")
            expectation.fulfill()
        }

        analyzer.publish(event: RelativeProtocol.TrafficEvent(
            category: .observation,
            confidence: .medium,
            details: [
                "payload": "body",
                "host": "sensitive.example"
            ]
        ))

        wait(for: [expectation], timeout: 1.0)
        bus.removeListener(token)
    }
}
