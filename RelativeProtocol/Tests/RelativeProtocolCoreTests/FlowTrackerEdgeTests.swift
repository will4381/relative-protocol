// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import XCTest
@testable import RelativeProtocolCore

final class FlowTrackerEdgeTests: XCTestCase {
    func testBurstDoesNotAdvanceAtExactThreshold() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 0.25,
            flowTTL: 60,
            maxTrackedFlows: 32
        ))
        let metadata = makeMetadata(flow: 1)

        let first = tracker.record(metadata: metadata, timestamp: 1.0)
        let second = tracker.record(metadata: metadata, timestamp: 1.25)

        XCTAssertEqual(first.burstId, 0)
        XCTAssertEqual(second.burstId, 0)
    }

    func testEvictsOldestFlowWhenCapacityExceeded() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 0.1,
            flowTTL: 60,
            maxTrackedFlows: 3
        ))

        let flowA = makeMetadata(flow: 1)
        let flowB = makeMetadata(flow: 2)
        let flowC = makeMetadata(flow: 3)

        _ = tracker.record(metadata: flowA, timestamp: 1.0)
        _ = tracker.record(metadata: flowB, timestamp: 2.0)
        let cStart = tracker.record(metadata: flowC, timestamp: 3.0) // evicts flow A when reaching capacity
        let cAdvanced = tracker.record(metadata: flowC, timestamp: 3.2)

        let aAfterEviction = tracker.record(metadata: flowA, timestamp: 3.3)

        XCTAssertEqual(cStart.burstId, 0)
        XCTAssertEqual(cAdvanced.burstId, 1)
        XCTAssertEqual(aAfterEviction.burstId, 0)
    }

    func testSameTimestampChurnStillAllowsCorrectEviction() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 0.1,
            flowTTL: 300,
            maxTrackedFlows: 4
        ))

        let oldFlow = makeMetadata(flow: 10)
        let middleFlow = makeMetadata(flow: 11)
        let hotFlow = makeMetadata(flow: 12)
        let newFlow = makeMetadata(flow: 13)

        _ = tracker.record(metadata: oldFlow, timestamp: 1.0)
        _ = tracker.record(metadata: middleFlow, timestamp: 2.0)
        _ = tracker.record(metadata: hotFlow, timestamp: 5.0)
        for _ in 0..<2_000 {
            _ = tracker.record(metadata: hotFlow, timestamp: 5.0)
        }

        _ = tracker.record(metadata: newFlow, timestamp: 6.0) // should evict oldFlow
        let middleAfter = tracker.record(metadata: middleFlow, timestamp: 6.1)
        let oldAfter = tracker.record(metadata: oldFlow, timestamp: 6.2)

        XCTAssertEqual(oldAfter.burstId, 0)
        XCTAssertEqual(middleAfter.burstId, 1)
    }

    func testExpiredFlowsArePrunedWhileCurrentFlowRemainsTracked() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 0.1,
            flowTTL: 1.0,
            maxTrackedFlows: 16
        ))

        let staleA = makeMetadata(flow: 21)
        let staleB = makeMetadata(flow: 22)
        let fresh = makeMetadata(flow: 23)

        _ = tracker.record(metadata: staleA, timestamp: 1.0)
        _ = tracker.record(metadata: staleB, timestamp: 1.0)
        let freshStart = tracker.record(metadata: fresh, timestamp: 2.0)

        let freshNext = tracker.record(metadata: fresh, timestamp: 3.0)
        let staleAfter = tracker.record(metadata: staleA, timestamp: 3.0)

        XCTAssertEqual(freshStart.flowId, freshNext.flowId)
        XCTAssertEqual(staleAfter.burstId, 0)
    }

    func testRecordWithoutPortsReturnsZeroObservation() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 0.1,
            flowTTL: 30,
            maxTrackedFlows: 8
        ))

        let src = IPAddress(bytes: Data([192, 168, 1, 1]))!
        let dst = IPAddress(bytes: Data([8, 8, 8, 8]))!
        let metadata = PacketMetadata(
            ipVersion: .v4,
            transport: .udp,
            srcAddress: src,
            dstAddress: dst,
            srcPort: nil,
            dstPort: nil,
            length: 64,
            dnsQueryName: nil,
            dnsCname: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )

        let observation = tracker.record(metadata: metadata, timestamp: 1.0)
        XCTAssertEqual(observation.flowId, 0)
        XCTAssertEqual(observation.burstId, 0)
    }

    func testResetResetsBurstProgression() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 0.1,
            flowTTL: 60,
            maxTrackedFlows: 8
        ))
        let metadata = makeMetadata(flow: 40)

        _ = tracker.record(metadata: metadata, timestamp: 1.0)
        let advanced = tracker.record(metadata: metadata, timestamp: 1.2)
        tracker.reset()
        let afterReset = tracker.record(metadata: metadata, timestamp: 1.3)

        XCTAssertEqual(advanced.burstId, 1)
        XCTAssertEqual(afterReset.burstId, 0)
    }

    func testFlowIdStableUnderHeavySameTimestampUpdates() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 10.0,
            flowTTL: 1000,
            maxTrackedFlows: 32
        ))
        let metadata = makeMetadata(flow: 50)

        let first = tracker.record(metadata: metadata, timestamp: 9.0)
        var last = first
        for _ in 0..<10_000 {
            last = tracker.record(metadata: metadata, timestamp: 9.0)
        }

        XCTAssertEqual(last.flowId, first.flowId)
        XCTAssertEqual(last.burstId, 0)
    }

    func testHighVolumeRecordsKeepReturningValidObservations() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 0.05,
            flowTTL: 120,
            maxTrackedFlows: 64
        ))

        var nonZeroObservations = 0
        for index in 0..<20_000 {
            let flow = UInt8(index % 80)
            let metadata = makeMetadata(flow: flow)
            let observation = tracker.record(metadata: metadata, timestamp: Double(index) * 0.001)
            if observation.flowId != 0 {
                nonZeroObservations += 1
            }
        }

        XCTAssertEqual(nonZeroObservations, 20_000)
    }

    func testHeapCompactionPreventsUnboundedGrowth() {
        let tracker = FlowTracker(configuration: .init(
            burstThreshold: 5.0,
            flowTTL: 300,
            maxTrackedFlows: 16
        ))
        let metadata = makeMetadata(flow: 77)
        for _ in 0..<20_000 {
            _ = tracker.record(metadata: metadata, timestamp: 1.0)
        }

        XCTAssertLessThanOrEqual(tracker._test_heapEntryCount, 1_024)
    }

    private func makeMetadata(flow: UInt8) -> PacketMetadata {
        let src = IPAddress(bytes: Data([192, 168, 10, flow]))!
        let dst = IPAddress(bytes: Data([203, 0, 113, flow]))!
        return PacketMetadata(
            ipVersion: .v4,
            transport: .udp,
            srcAddress: src,
            dstAddress: dst,
            srcPort: 20_000 + UInt16(flow),
            dstPort: 53,
            length: 96,
            dnsQueryName: nil,
            dnsCname: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
    }
}
