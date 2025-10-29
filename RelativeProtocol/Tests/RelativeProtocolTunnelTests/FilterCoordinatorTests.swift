//
//  FilterCoordinatorTests.swift
//  RelativeProtocolTunnelTests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 11/07/2025.
//
//  Validates that registered filters can emit buffered events through the
//  coordinator and into the analyzer.
//
import XCTest
import RelativeProtocolCore
@testable import RelativeProtocolTunnel
import Darwin

private struct TestFilter: TrafficFilter {
    let identifier: String = "test.filter"
    func evaluate(snapshot: UnsafeBufferPointer<RelativeProtocol.PacketSample>, emit: @escaping @Sendable (RelativeProtocol.TrafficEvent) -> Void) {
        guard snapshot.count >= 2 else { return }
        let event = RelativeProtocol.TrafficEvent(
            category: .burst,
            confidence: .high,
            details: ["count": String(snapshot.count)]
        )
        emit(event)
    }
}

final class FilterCoordinatorTests: XCTestCase {
    func testFilterEmitsBufferedEvents() {
        let eventExpectation = expectation(description: "event emitted")
        let bus = RelativeProtocol.TrafficEventBus(label: "test.bus")
        _ = bus.addListener { event in
            if event.details["count"] == "2" {
                eventExpectation.fulfill()
            }
        }

        let streamConfig = RelativeProtocol.PacketStream.Configuration(bufferDuration: 120)
        let stream = RelativeProtocol.PacketStream(configuration: streamConfig)
        let analyzer = TrafficAnalyzer(stream: stream, eventBus: bus)
        let coordinator = FilterCoordinator(
            analyzer: analyzer,
            configuration: FilterConfiguration(
                evaluationInterval: 0.05,
                eventBufferConfiguration: nil
            )
        )
        coordinator.register(TestFilter())

        Thread.sleep(forTimeInterval: 0.1)

        let first = RelativeProtocol.PacketSample(
            direction: .inbound,
            payload: Data([0x01]),
            protocolNumber: Int32(AF_INET)
        )

        let second = RelativeProtocol.PacketSample(
            direction: .inbound,
            payload: Data([0x02]),
            protocolNumber: Int32(AF_INET)
        )

        analyzer.ingest(sample: first)

        DispatchQueue.global().asyncAfter(deadline: .now() + 0.06) {
            analyzer.ingest(sample: second)
        }

        wait(for: [eventExpectation], timeout: 2.0)
        coordinator.flush()
    }
}
