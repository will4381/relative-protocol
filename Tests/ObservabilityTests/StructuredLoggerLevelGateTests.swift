// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
@testable import Observability
import XCTest

/// Contract tests for the logger's minimum-level gate.
/// The tunnel relies on `isEnabled(_:)` to skip Task spawns and envelope construction on packet hot paths,
/// so the gate must agree exactly with what the logger actually records.
final class StructuredLoggerLevelGateTests: XCTestCase {
    func testIsEnabledMatchesSeverityOrdering() {
        let logger = StructuredLogger(sink: InMemoryLogSink(), minimumLevel: .info)

        XCTAssertFalse(logger.isEnabled(.trace))
        XCTAssertFalse(logger.isEnabled(.debug))
        XCTAssertTrue(logger.isEnabled(.info))
        XCTAssertTrue(logger.isEnabled(.notice))
        XCTAssertTrue(logger.isEnabled(.warning))
        XCTAssertTrue(logger.isEnabled(.error))
        XCTAssertTrue(logger.isEnabled(.fault))
    }

    func testDefaultMinimumLevelKeepsEverything() async {
        let sink = InMemoryLogSink()
        let logger = StructuredLogger(sink: sink)

        XCTAssertTrue(logger.isEnabled(.trace))
        await logger.log(
            level: .trace,
            phase: .relay,
            category: .control,
            component: "test",
            event: "trace-event",
            message: "trace"
        )
        let records = await sink.snapshot()
        XCTAssertEqual(records.map(\.event), ["trace-event"])
    }

    func testEventsBelowMinimumLevelAreDroppedBeforeSink() async {
        let sink = InMemoryLogSink()
        let logger = StructuredLogger(sink: sink, minimumLevel: .info)

        await logger.log(
            level: .debug,
            phase: .relay,
            category: .control,
            component: "test",
            event: "dropped",
            message: "should not appear"
        )
        await logger.log(
            level: .info,
            phase: .relay,
            category: .control,
            component: "test",
            event: "kept",
            message: "should appear"
        )

        let records = await sink.snapshot()
        XCTAssertEqual(records.map(\.event), ["kept"])
    }

    func testRateLimitedEventsBelowMinimumLevelAreDropped() async {
        let sink = InMemoryLogSink()
        let logger = StructuredLogger(sink: sink, minimumLevel: .warning)

        await logger.logRateLimited(
            key: "gate-test",
            minimumInterval: 10,
            level: .notice,
            phase: .relay,
            category: .control,
            component: "test",
            event: "dropped-notice",
            message: "below minimum"
        )
        await logger.logRateLimited(
            key: "gate-test",
            minimumInterval: 10,
            level: .warning,
            phase: .relay,
            category: .control,
            component: "test",
            event: "kept-warning",
            message: "at minimum"
        )

        let records = await sink.snapshot()
        XCTAssertEqual(records.map(\.event), ["kept-warning"])
    }

    func testLogLevelComparableOrderingIsTotal() {
        let ascending: [LogLevel] = [.trace, .debug, .info, .notice, .warning, .error, .fault]
        for (index, level) in ascending.enumerated() {
            for higher in ascending.dropFirst(index + 1) {
                XCTAssertLessThan(level, higher)
            }
            XCTAssertEqual(level, level)
        }
    }
}
