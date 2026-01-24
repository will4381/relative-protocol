// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import XCTest
import RelativeProtocolCore

final class BurstTrackerTests: XCTestCase {
    func testBurstMetricsAccumulate() {
        let tracker = BurstTracker(ttl: 1.0, maxBursts: 16)
        _ = tracker.record(flowId: 42, burstId: 1, timestamp: 0.0, length: 100)
        let metrics = tracker.record(flowId: 42, burstId: 1, timestamp: 0.5, length: 200)

        XCTAssertEqual(metrics?.packetCount, 2)
        XCTAssertEqual(metrics?.byteCount, 300)
        XCTAssertNotNil(metrics?.durationMs)
        XCTAssertGreaterThan(metrics?.packetsPerSecond ?? 0.0, 0.0)
        XCTAssertGreaterThan(metrics?.bytesPerSecond ?? 0.0, 0.0)
    }

    func testBurstResetsAfterTTL() {
        let tracker = BurstTracker(ttl: 0.5, maxBursts: 16)
        _ = tracker.record(flowId: 1, burstId: 0, timestamp: 0.0, length: 100)
        let metrics = tracker.record(flowId: 1, burstId: 0, timestamp: 1.0, length: 50)

        XCTAssertEqual(metrics?.packetCount, 1)
        XCTAssertEqual(metrics?.byteCount, 50)
    }
}