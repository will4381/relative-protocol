// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import XCTest
import RelativeProtocolCore

final class FlowTrackerTests: XCTestCase {
    func testBurstAdvancesAfterThreshold() {
        let tracker = FlowTracker(configuration: FlowTrackerConfiguration(
            burstThreshold: 0.1,
            flowTTL: 10,
            maxTrackedFlows: 10
        ))

        let metadata = makeMetadata()
        let first = tracker.record(metadata: metadata, timestamp: 1.0)
        let second = tracker.record(metadata: metadata, timestamp: 1.05)
        let third = tracker.record(metadata: metadata, timestamp: 1.20)

        XCTAssertEqual(first.flowId, second.flowId)
        XCTAssertEqual(first.burstId, 0)
        XCTAssertEqual(second.burstId, 0)
        XCTAssertEqual(third.burstId, 1)
    }

    func testFlowExpiresAfterTTL() {
        let tracker = FlowTracker(configuration: FlowTrackerConfiguration(
            burstThreshold: 0.1,
            flowTTL: 1,
            maxTrackedFlows: 10
        ))

        let metadata = makeMetadata()
        let first = tracker.record(metadata: metadata, timestamp: 1.0)
        let second = tracker.record(metadata: metadata, timestamp: 2.5)

        XCTAssertNotEqual(first.flowId, second.flowId)
        XCTAssertEqual(second.burstId, 0)
    }

    private func makeMetadata() -> PacketMetadata {
        let src = IPAddress(bytes: Data([192, 168, 1, 2]))!
        let dst = IPAddress(bytes: Data([8, 8, 8, 8]))!
        return PacketMetadata(
            ipVersion: .v4,
            transport: .udp,
            srcAddress: src,
            dstAddress: dst,
            srcPort: 12000,
            dstPort: 53,
            length: 60,
            dnsQueryName: nil,
            dnsCname: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
    }
}