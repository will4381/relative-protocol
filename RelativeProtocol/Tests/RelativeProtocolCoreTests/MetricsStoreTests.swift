// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import XCTest
@testable import RelativeProtocolCore

final class MetricsStoreTests: XCTestCase {
    func testNDJSONRoundTrip() {
        let store = MetricsStore(
            appGroupID: "group.test.metrics.ndjson",
            maxSnapshots: 3,
            maxBytes: 10_000,
            format: .ndjson
        )
        store.clear()

        let sample = PacketSample(
            timestamp: 1.0,
            direction: .outbound,
            ipVersion: .v4,
            transport: .tcp,
            length: 100,
            flowId: 1,
            burstId: 1,
            srcAddress: "10.0.0.2",
            dstAddress: "1.1.1.1",
            srcPort: 1234,
            dstPort: 443,
            dnsQueryName: nil,
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            burstMetrics: nil,
            trafficClassification: nil
        )
        store.append(MetricsSnapshot(capturedAt: 1.0, samples: [sample]))
        store.append(MetricsSnapshot(capturedAt: 2.0, samples: [sample]))

        let loaded = store.load()
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded.first?.samples.count, 1)
    }
}