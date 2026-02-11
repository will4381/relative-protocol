// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import XCTest
import RelativeProtocolCore

final class BurstTrackerEdgeTests: XCTestCase {
    func testZeroFlowIdReturnsNil() {
        let tracker = BurstTracker(ttl: 1.0, maxBursts: 8)
        let metrics = tracker.record(flowId: 0, burstId: 1, timestamp: 1.0, length: 100)
        XCTAssertNil(metrics)
    }

    func testNegativeLengthsAreClampedToZeroBytes() {
        let tracker = BurstTracker(ttl: 1.0, maxBursts: 8)
        let first = tracker.record(flowId: 1, burstId: 1, timestamp: 1.0, length: -42)
        let second = tracker.record(flowId: 1, burstId: 1, timestamp: 1.1, length: 50)

        XCTAssertEqual(first?.packetCount, 1)
        XCTAssertEqual(first?.byteCount, 0)
        XCTAssertEqual(second?.packetCount, 2)
        XCTAssertEqual(second?.byteCount, 50)
    }

    func testBurstDoesNotResetAtExactTTLBoundary() {
        let tracker = BurstTracker(ttl: 0.5, maxBursts: 8)
        _ = tracker.record(flowId: 10, burstId: 1, timestamp: 1.0, length: 100)
        let metrics = tracker.record(flowId: 10, burstId: 1, timestamp: 1.5, length: 20)

        XCTAssertEqual(metrics?.packetCount, 2)
        XCTAssertEqual(metrics?.byteCount, 120)
    }

    func testBurstResetsOnceTTLIsExceeded() {
        let tracker = BurstTracker(ttl: 0.5, maxBursts: 8)
        _ = tracker.record(flowId: 10, burstId: 1, timestamp: 1.0, length: 100)
        let metrics = tracker.record(flowId: 10, burstId: 1, timestamp: 1.501, length: 20)

        XCTAssertEqual(metrics?.packetCount, 1)
        XCTAssertEqual(metrics?.byteCount, 20)
    }

    func testEvictsOldestBurstWhenCapacityIsReached() {
        let tracker = BurstTracker(ttl: 120, maxBursts: 3)

        _ = tracker.record(flowId: 1, burstId: 1, timestamp: 1.0, length: 10)
        _ = tracker.record(flowId: 2, burstId: 1, timestamp: 2.0, length: 20)
        _ = tracker.record(flowId: 3, burstId: 1, timestamp: 3.0, length: 30)

        let revivedOldest = tracker.record(flowId: 1, burstId: 1, timestamp: 3.1, length: 40)
        XCTAssertEqual(revivedOldest?.packetCount, 1)
        XCTAssertEqual(revivedOldest?.byteCount, 40)
    }

    func testSameTimestampChurnDoesNotEvictHotBurst() {
        let tracker = BurstTracker(ttl: 300, maxBursts: 4)

        _ = tracker.record(flowId: 100, burstId: 1, timestamp: 1.0, length: 1)
        _ = tracker.record(flowId: 101, burstId: 1, timestamp: 2.0, length: 1)
        _ = tracker.record(flowId: 102, burstId: 1, timestamp: 3.0, length: 1)

        for _ in 0..<2_000 {
            _ = tracker.record(flowId: 102, burstId: 1, timestamp: 3.0, length: 1)
        }

        _ = tracker.record(flowId: 103, burstId: 1, timestamp: 4.0, length: 1)
        let hotAfter = tracker.record(flowId: 102, burstId: 1, timestamp: 4.1, length: 1)
        let oldAfter = tracker.record(flowId: 100, burstId: 1, timestamp: 4.2, length: 1)

        XCTAssertEqual(hotAfter?.packetCount, 2_002)
        XCTAssertEqual(oldAfter?.packetCount, 1)
    }

    func testResetClearsExistingState() {
        let tracker = BurstTracker(ttl: 10, maxBursts: 8)
        _ = tracker.record(flowId: 7, burstId: 1, timestamp: 1.0, length: 10)
        _ = tracker.record(flowId: 7, burstId: 1, timestamp: 1.1, length: 10)
        tracker.reset()
        let metrics = tracker.record(flowId: 7, burstId: 1, timestamp: 1.2, length: 10)

        XCTAssertEqual(metrics?.packetCount, 1)
        XCTAssertEqual(metrics?.byteCount, 10)
    }

    func testDurationIsNonZeroForSameTimestampUpdates() {
        let tracker = BurstTracker(ttl: 10, maxBursts: 8)
        _ = tracker.record(flowId: 9, burstId: 1, timestamp: 5.0, length: 10)
        let metrics = tracker.record(flowId: 9, burstId: 1, timestamp: 5.0, length: 20)

        XCTAssertEqual(metrics?.durationMs, 1)
        XCTAssertGreaterThan(metrics?.packetsPerSecond ?? 0, 0)
        XCTAssertGreaterThan(metrics?.bytesPerSecond ?? 0, 0)
    }

    func testHighVolumeUpdatesKeepAccurateCounts() {
        let tracker = BurstTracker(ttl: 30, maxBursts: 32)
        var metrics: BurstMetrics?
        for i in 0..<5_000 {
            metrics = tracker.record(flowId: 55, burstId: 3, timestamp: Double(i) * 0.001, length: 10)
        }

        XCTAssertEqual(metrics?.packetCount, 5_000)
        XCTAssertEqual(metrics?.byteCount, 50_000)
    }
}
