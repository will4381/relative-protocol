// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation
import XCTest
import RelativeProtocolCore
import RelativeProtocolHost

final class HostClientTests: XCTestCase {
    func testMetricsClientLoadsSnapshotsWrittenByStore() {
        let context = makeContext(suffix: "metrics-client")
        defer { cleanup(context.url) }

        let sample = makeSample(flowID: 42, timestamp: 1.0)
        let snapshot = MetricsSnapshot(capturedAt: 1.0, samples: [sample])
        let store = MetricsStore(appGroupID: context.appGroupID, maxSnapshots: 8)
        defer { store.clear() }
        store.clear()
        store.append(snapshot)

        let client = MetricsClient(appGroupID: context.appGroupID, maxSnapshots: 8)
        let loaded = client.loadSnapshots()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.samples.first?.flowId, 42)
    }

    func testPacketStreamClientReadsNewSamplesFromOffset() {
        let context = makeContext(suffix: "packet-stream-client")
        defer { cleanup(context.url) }

        let writer = PacketSampleStreamWriter(appGroupID: context.appGroupID, maxBytes: 200_000)
        writer.append([makeSample(flowID: 1, timestamp: 1.0), makeSample(flowID: 2, timestamp: 2.0)])
        writer.close()

        let client = PacketStreamClient(appGroupID: context.appGroupID)
        let firstRead = client.readNew(sinceOffset: 0)
        XCTAssertEqual(firstRead.samples.map(\.flowId), [1, 2])

        let writer2 = PacketSampleStreamWriter(appGroupID: context.appGroupID, maxBytes: 200_000)
        writer2.append([makeSample(flowID: 3, timestamp: 3.0)])
        writer2.close()

        let secondRead = client.readNew(sinceOffset: firstRead.nextOffset)
        XCTAssertEqual(secondRead.samples.map(\.flowId), [3])
    }

    private func makeSample(flowID: UInt64, timestamp: TimeInterval) -> PacketSample {
        PacketSample(
            timestamp: timestamp,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 128,
            flowId: flowID,
            burstId: 0,
            srcAddress: "192.0.2.10",
            dstAddress: "198.51.100.20",
            srcPort: 1234,
            dstPort: 443,
            dnsQueryName: nil,
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            burstMetrics: nil,
            trafficClassification: nil
        )
    }

    private func makeContext(suffix: String) -> (appGroupID: String, url: URL) {
        let appGroupID = "group.host-client.\(UUID().uuidString)"
        _ = suffix
        let url = PacketSampleStreamLocation.makeURL(appGroupID: appGroupID)!
        return (appGroupID, url)
    }

    private func cleanup(_ streamURL: URL) {
        try? FileManager.default.removeItem(at: streamURL)
    }
}
