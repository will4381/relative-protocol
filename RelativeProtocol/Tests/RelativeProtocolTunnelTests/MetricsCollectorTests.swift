//
//  MetricsCollectorTests.swift
//  RelativeProtocolTunnelTests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Exercises the metrics collector to ensure packet counts, resets, and error
//  reporting behave as expected.
//
import Foundation
import XCTest
@testable import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class MetricsCollectorTests: XCTestCase {
    func testRecordEmitsSnapshotsForInboundAndOutbound() {
        let expectation = expectation(description: "metrics snapshots")
        expectation.expectedFulfillmentCount = 2
        let snapshots = ThreadSafeArray<RelativeProtocol.MetricsSnapshot>()
        let collector = MetricsCollector(subsystem: "test", interval: 0.0, sink: { snapshot in
            snapshots.append(snapshot)
            expectation.fulfill()
        })

        collector.reset()

        collector.record(direction: .inbound, packets: 3, bytes: 150)
        collector.record(direction: .outbound, packets: 2, bytes: 200)

        wait(for: [expectation], timeout: 1.0)

        let recorded = snapshots.values()
        XCTAssertEqual(recorded.count, 2)
        XCTAssertEqual(recorded[0].inbound.packets, 3)
        XCTAssertEqual(recorded[0].inbound.bytes, 150)
        XCTAssertEqual(recorded[0].activeTCP, 0)
        XCTAssertEqual(recorded[0].activeUDP, 0)
        XCTAssertEqual(recorded[1].outbound.packets, 2)
        XCTAssertEqual(recorded[1].outbound.bytes, 200)
        XCTAssertEqual(recorded[1].activeTCP, 0)
        XCTAssertEqual(recorded[1].activeUDP, 0)
    }

    func testResetClearsCounters() {
        let first = expectation(description: "first snapshot")
        let second = expectation(description: "second snapshot")
        let snapshots = ThreadSafeArray<RelativeProtocol.MetricsSnapshot>()
        let collector = MetricsCollector(subsystem: "test", interval: 0.0, sink: { snapshot in
            snapshots.append(snapshot)
            if snapshots.count == 1 {
                first.fulfill()
            } else if snapshots.count == 2 {
                second.fulfill()
            }
        })

        collector.reset()
        collector.record(direction: .inbound, packets: 1, bytes: 10)
        wait(for: [first], timeout: 1.0)

        collector.reset()
        collector.record(direction: .outbound, packets: 1, bytes: 20)
        wait(for: [second], timeout: 1.0)

        let recorded = snapshots.values()
        XCTAssertEqual(recorded.count, 2)
        XCTAssertEqual(recorded[0].inbound.packets, 1)
        XCTAssertEqual(recorded[0].inbound.bytes, 10)
        XCTAssertEqual(recorded[1].outbound.packets, 1)
        XCTAssertEqual(recorded[1].outbound.bytes, 20)
    }

    func testActiveConnectionAdjustmentsEmitSnapshot() {
        let expectation = expectation(description: "active connections snapshot")
        let captured = ThreadSafeBox<RelativeProtocol.MetricsSnapshot>()
        let collector = MetricsCollector(subsystem: "test", interval: 0.0, sink: { snapshot in
            captured.set(snapshot)
            expectation.fulfill()
        })

        collector.reset()
        collector.adjustActiveConnections(tcpDelta: 2, udpDelta: 1)

        wait(for: [expectation], timeout: 1.0)
        let snapshot = captured.get()
        XCTAssertEqual(snapshot?.activeTCP, 2)
        XCTAssertEqual(snapshot?.activeUDP, 1)
        XCTAssertEqual(snapshot?.inbound.packets, 0)
        XCTAssertTrue(snapshot?.errors.isEmpty ?? false)
    }

    func testRecordErrorEmitsSnapshotWithoutPackets() {
        let expectation = expectation(description: "error snapshot emitted")
        let captured = ThreadSafeBox<RelativeProtocol.MetricsSnapshot>()
        let collector = MetricsCollector(subsystem: "test", interval: 1.0, sink: { snapshot in
            captured.set(snapshot)
            expectation.fulfill()
        })

        collector.reset()
        collector.recordError("  something went wrong  ")

        wait(for: [expectation], timeout: 1.0)
        let snapshot = captured.get()
        XCTAssertEqual(snapshot?.errors.count, 1)
        XCTAssertEqual(snapshot?.errors.first?.message, "something went wrong")
        XCTAssertEqual(snapshot?.inbound.packets, 0)
        XCTAssertEqual(snapshot?.outbound.packets, 0)
    }

    func testEngineMetricsRecordingPropagatesToSnapshots() {
        let expectation = expectation(description: "engine metrics snapshot")
        let captured = ThreadSafeBox<RelativeProtocol.MetricsSnapshot>()
        let collector = MetricsCollector(subsystem: "test", interval: 0.0, sink: { snapshot in
            captured.set(snapshot)
            expectation.fulfill()
        })

        collector.reset()
        let metrics = EngineFlowMetrics(
            counters: .init(
                tcpAdmissionFail: 1,
                udpAdmissionFail: 2,
                tcpBackpressureDrops: 3,
                udpBackpressureDrops: 4
            ),
            stats: .init(
                pollIterations: 10,
                framesEmitted: 20,
                bytesEmitted: 30,
                tcpFlushEvents: 5,
                udpFlushEvents: 6
            )
        )
        collector.record(engineMetrics: metrics)

        wait(for: [expectation], timeout: 1.0)
        let snapshot = captured.get()
        XCTAssertEqual(snapshot?.flow?.counters.tcpAdmissionFail, 1)
        XCTAssertEqual(snapshot?.flow?.counters.udpBackpressureDrops, 4)
        XCTAssertEqual(snapshot?.flow?.stats.framesEmitted, 20)
    }
}

// MARK: - Helpers

private final class ThreadSafeArray<Element>: @unchecked Sendable {
    private var storage: [Element] = []
    private let lock = NSLock()

    func append(_ element: Element) {
        lock.lock()
        defer { lock.unlock() }
        storage.append(element)
    }

    func values() -> [Element] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage.count
    }
}

private final class ThreadSafeBox<Value>: @unchecked Sendable {
    private var storage: Value?
    private let lock = NSLock()

    func set(_ value: Value) {
        lock.lock()
        defer { lock.unlock() }
        storage = value
    }

    func get() -> Value? {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}
