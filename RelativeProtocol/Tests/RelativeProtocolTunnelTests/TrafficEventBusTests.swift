import XCTest
import RelativeProtocolCore

final class TrafficEventBusTests: XCTestCase {
    func testPublishesSanitizedEvent() {
        let redactor = RelativeProtocol.TrafficRedactor(
            shouldStripPayloads: true,
            shouldRedactHosts: true,
            redactionToken: "***",
            allowList: ["safe.example"]
        )
        let bus = RelativeProtocol.TrafficEventBus(redactor: redactor)

        let expectation = expectation(description: "listener received sanitized event")

        let token = bus.addListener { event in
            XCTAssertNil(event.details["payload"])
            XCTAssertEqual(event.details["host"], "***")
            expectation.fulfill()
        }

        let event = RelativeProtocol.TrafficEvent(
            category: .observation,
            confidence: .high,
            details: [
                "payload": "secret",
                "host": "tracker.example"
            ]
        )

        bus.publish(event)

        wait(for: [expectation], timeout: 1.0)
        bus.removeListener(token)
    }

    func testRemovingListenerStopsDelivery() {
        let bus = RelativeProtocol.TrafficEventBus()
        let expectation = expectation(description: "listener should not fire")
        expectation.isInverted = true

        let token = bus.addListener { _ in
            expectation.fulfill()
        }

        bus.removeListener(token)
        bus.publish(RelativeProtocol.TrafficEvent(category: .custom, details: [:]))

        wait(for: [expectation], timeout: 0.2)
    }
}
