// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
//
//  RelativeProtocolCoreSmokeTests.swift
//  ExampleTests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only.
//
//  Lightweight core-module smoke tests wired through the Example app test target.
//

import Darwin
import XCTest
import RelativeProtocolCore

final class RelativeProtocolCoreSmokeTests: XCTestCase {
    func testRingBufferSnapshotLimitReturnsMostRecentSamples() {
        let buffer = MetricsRingBuffer(capacity: 5)
        (1...5).forEach { buffer.append(makeSample(id: UInt64($0))) }

        let snapshot = buffer.snapshot(limit: 2)
        XCTAssertEqual(snapshot.count, 2)
        XCTAssertEqual(snapshot.first?.flowId, 4)
        XCTAssertEqual(snapshot.last?.flowId, 5)
    }

    func testFlowTrackerBurstAndTTLAdvance() {
        let tracker = FlowTracker(configuration: FlowTrackerConfiguration(
            burstThreshold: 0.1,
            flowTTL: 0.5,
            maxTrackedFlows: 8
        ))

        let metadata = makeMetadata()
        let first = tracker.record(metadata: metadata, timestamp: 1.0)
        let second = tracker.record(metadata: metadata, timestamp: 1.15)
        let third = tracker.record(metadata: metadata, timestamp: 2.0)

        XCTAssertEqual(first.flowId, second.flowId)
        XCTAssertEqual(first.burstId, 0)
        XCTAssertEqual(second.burstId, 1)
        XCTAssertNotEqual(second.flowId, third.flowId)
    }

    func testPacketParserDetectsIPv4Dns() {
        let payload = makeDNSQueryPayload(hostname: "example.com")
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 2],
            dst: [1, 1, 1, 1],
            srcPort: 5353,
            dstPort: 53,
            payload: payload
        )

        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        XCTAssertEqual(metadata?.ipVersion, .v4)
        XCTAssertEqual(metadata?.transport, .udp)
        XCTAssertEqual(metadata?.dnsQueryName, "example.com")
    }

    func testMetricsStoreCapsSnapshots() {
        let appGroupID = "test.metrics.\(UUID().uuidString)"
        let store = MetricsStore(appGroupID: appGroupID, maxSnapshots: 2, maxBytes: 10_000)
        store.clear()
        store.append(makeSnapshot(id: 1))
        store.append(makeSnapshot(id: 2))
        store.append(makeSnapshot(id: 3))

        let loaded = store.load()
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded.first?.samples.first?.flowId, 2)
        XCTAssertEqual(loaded.last?.samples.first?.flowId, 3)
    }

    func testMetricsStoreRejectsOversizedSnapshot() {
        let appGroupID = "test.metrics.large.\(UUID().uuidString)"
        let store = MetricsStore(appGroupID: appGroupID, maxSnapshots: 5, maxBytes: 256)
        store.clear()
        store.append(makeSnapshot(id: 1, dnsNameLength: 512))

        XCTAssertTrue(store.load().isEmpty)
    }

    private func makeSample(id: UInt64) -> PacketSample {
        PacketSample(
            timestamp: 1,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 64,
            flowId: id,
            burstId: 0,
            srcAddress: "192.0.2.1",
            dstAddress: "198.51.100.1",
            srcPort: 12000,
            dstPort: 53,
            dnsQueryName: nil,
            dnsCname: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
    }

    private func makeSnapshot(id: UInt64, dnsNameLength: Int = 0) -> MetricsSnapshot {
        let dnsName = dnsNameLength > 0 ? String(repeating: "a", count: dnsNameLength) : nil
        let sample = PacketSample(
            timestamp: 1,
            direction: .inbound,
            ipVersion: .v4,
            transport: .udp,
            length: 120,
            flowId: id,
            burstId: 0,
            srcAddress: "192.0.2.53",
            dstAddress: "198.51.100.2",
            srcPort: 53,
            dstPort: 53000,
            dnsQueryName: dnsName,
            dnsCname: nil,
            registrableDomain: dnsName,
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
        return MetricsSnapshot(capturedAt: 1, samples: [sample])
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

    private func makeIPv4UDPPacket(src: [UInt8], dst: [UInt8], srcPort: UInt16, dstPort: UInt16, payload: [UInt8]) -> Data {
        var packet: [UInt8] = []
        let totalLength = 20 + 8 + payload.count
        packet.append(0x45)
        packet.append(0x00)
        packet.append(UInt8((totalLength >> 8) & 0xFF))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(64)
        packet.append(17)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: src)
        packet.append(contentsOf: dst)

        packet.append(UInt8((srcPort >> 8) & 0xFF))
        packet.append(UInt8(srcPort & 0xFF))
        packet.append(UInt8((dstPort >> 8) & 0xFF))
        packet.append(UInt8(dstPort & 0xFF))
        let udpLength = 8 + payload.count
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: payload)
        return Data(packet)
    }

    private func makeDNSQueryPayload(hostname: String) -> [UInt8] {
        var payload: [UInt8] = []
        payload.append(0x12)
        payload.append(0x34)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)

        let labels = hostname.split(separator: ".")
        for label in labels {
            payload.append(UInt8(label.count))
            payload.append(contentsOf: label.utf8)
        }
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x01)
        return payload
    }
}
