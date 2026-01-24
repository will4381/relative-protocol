// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
//
//  ExampleTests.swift
//  ExampleTests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/23/2025.
//
//  Core data model coverage for the Example app.
//

import XCTest
import RelativeProtocolCore

final class ExampleTests: XCTestCase {
    func testMetricsSnapshotCodableRoundTrip() throws {
        let sample = PacketSample(
            timestamp: 1.0,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 64,
            flowId: 42,
            burstId: 1,
            srcAddress: "192.0.2.10",
            dstAddress: "198.51.100.53",
            srcPort: 12000,
            dstPort: 53,
            dnsQueryName: "example.com",
            dnsCname: "example.net",
            registrableDomain: "example.com",
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
        let snapshot = MetricsSnapshot(capturedAt: 123.0, samples: [sample])

        let data = try JSONEncoder().encode(snapshot)
        let decoded = try JSONDecoder().decode(MetricsSnapshot.self, from: data)

        XCTAssertEqual(decoded.capturedAt, snapshot.capturedAt, accuracy: 0.0001)
        XCTAssertEqual(decoded.samples.count, 1)
        XCTAssertEqual(decoded.samples.first, sample)
    }
}
