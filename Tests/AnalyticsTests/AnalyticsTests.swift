// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

@testable import Analytics
import Foundation
import Observability
import TunnelRuntime
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// Analytics bounds, classification, replay, and detector contract tests.
final class AnalyticsTests: XCTestCase {
    /// Verifies the rolling packet tap keeps the newest entries that fit inside the bounded memory budget.
    func testPacketStreamRetainsNewestEntriesThatFit() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))

        let sample1 = PacketSample(timestamp: Date(timeIntervalSince1970: 1), direction: "out", flowId: "f1", bytes: 90, protocolHint: "tcp")
        let sample2 = PacketSample(timestamp: Date(timeIntervalSince1970: 2), direction: "out", flowId: "f2", bytes: 91, protocolHint: "tcp")
        let sample3 = PacketSample(timestamp: Date(timeIntervalSince1970: 3), direction: "out", flowId: "f3", bytes: 92, protocolHint: "tcp")
        let maxBytes = estimatedRecordSize(sample2) + estimatedRecordSize(sample3)

        let stream = PacketSampleStream(maxBytes: maxBytes, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink()))
        try await stream.append(contentsOf: [sample1, sample2, sample3])
        let all = await stream.readAll()
        XCTAssertEqual(all, [sample2, sample3])
    }

    /// Verifies the rolling packet tap evicts expired entries as the retention window advances.
    func testPacketStreamEvictsExpiredEntries() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))

        let sample1 = PacketSample(timestamp: Date(timeIntervalSince1970: 1), direction: "out", flowId: "f1", bytes: 90, protocolHint: "tcp")
        let sample2 = PacketSample(timestamp: Date(timeIntervalSince1970: 20), direction: "out", flowId: "f2", bytes: 91, protocolHint: "tcp")

        let stream = PacketSampleStream(
            maxBytes: 4_096,
            retentionWindowSeconds: 10,
            clock: clock,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        try await stream.append(sample1)
        await clock.advance(by: 11)
        try await stream.append(sample2)

        let all = await stream.readAll()
        XCTAssertEqual(all, [sample2])
    }

    /// Verifies rich packet metadata is preserved in the rolling in-memory tap.
    func testPacketStreamRetainsRichMetadata() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let stream = PacketSampleStream(maxBytes: 2_048, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink()))

        let sample = PacketSample(
            kind: .metadata,
            timestamp: Date(timeIntervalSince1970: 10),
            direction: "outbound",
            flowId: "flow-1",
            bytes: 128,
            packetCount: 3,
            flowPacketCount: 9,
            flowByteCount: 1_024,
            protocolHint: "udp",
            ipVersion: 4,
            transportProtocolNumber: 17,
            sourceAddress: "10.0.0.2",
            sourcePort: 53_000,
            destinationAddress: "1.1.1.1",
            destinationPort: 443,
            registrableDomain: "example.com",
            dnsQueryName: "api.example.com",
            dnsCname: "edge.example.com",
            dnsAnswerAddresses: ["1.1.1.1"],
            tlsServerName: "api.example.com",
            quicVersion: 1,
            quicPacketType: "initial",
            quicDestinationConnectionId: "abcd",
            quicSourceConnectionId: "ef01",
            classification: "video",
            burstDurationMs: 280,
            burstPacketCount: 7
        )

        try await stream.append(sample)

        let all = await stream.readAll()
        XCTAssertEqual(all, [sample])
    }

    /// Verifies compact lifecycle and burst-shape counters survive conversion into the app-facing live tap.
    func testPacketStreamConvertsCompactLifecycleAndBurstCounters() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let stream = PacketSampleStream(maxBytes: 4_096, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink()))

        try await stream.append(
            records: [
                makePacketStreamRecord(
                    kind: .flowClose,
                    timestamp: Date(timeIntervalSince1970: 42),
                    flowHash: 0xfeed_beef,
                    registrableDomain: "example.com",
                    tlsServerName: "api.example.com",
                    bytes: 1_536,
                    packetCount: 3,
                    closeReason: .tcpFin,
                    largePacketCount: 1,
                    smallPacketCount: 1,
                    udpPacketCount: 0,
                    tcpPacketCount: 3,
                    quicInitialCount: 0,
                    tcpSynCount: 1,
                    tcpFinCount: 1,
                    tcpRstCount: 0,
                    burstDurationMs: 180,
                    burstPacketCount: 3,
                    leadingBytes200ms: 1_400,
                    leadingPackets200ms: 2,
                    leadingBytes600ms: 1_536,
                    leadingPackets600ms: 3,
                    burstLargePacketCount: 1,
                    burstUdpPacketCount: 0,
                    burstTcpPacketCount: 3,
                    burstQuicInitialCount: 0
                )
            ]
        )

        let samples = await stream.readAll()
        let sample = try XCTUnwrap(samples.first)
        XCTAssertEqual(sample.kind, .flowClose)
        XCTAssertEqual(sample.closeReason, .tcpFin)
        XCTAssertEqual(sample.largePacketCount, 1)
        XCTAssertEqual(sample.smallPacketCount, 1)
        XCTAssertEqual(sample.tcpPacketCount, 3)
        XCTAssertEqual(sample.tcpSynCount, 1)
        XCTAssertEqual(sample.tcpFinCount, 1)
        XCTAssertEqual(sample.leadingBytes200ms, 1_400)
        XCTAssertEqual(sample.leadingPackets600ms, 3)
        XCTAssertEqual(sample.burstLargePacketCount, 1)
        XCTAssertEqual(sample.burstTcpPacketCount, 3)
    }

    /// Verifies compact numeric IPv4 addresses decode correctly for detector and live-tap reads.
    func testPacketStreamDecodesNumericIPv4Addresses() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let stream = PacketSampleStream(maxBytes: 4_096, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink()))

        try await stream.append(
            records: [
                PacketSampleStream.PacketStreamRecord(
                    kind: .flowOpen,
                    timestamp: Date(timeIntervalSince1970: 5),
                    direction: PacketDirection.outbound.rawValue,
                    bytes: 128,
                    packetCount: 1,
                    flowPacketCount: 1,
                    flowByteCount: 128,
                    protocolHint: "tcp",
                    ipVersion: 4,
                    transportProtocolNumber: 6,
                    sourcePort: 50_000,
                    destinationPort: 443,
                    flowHash: 0xfeed_beef,
                    textFlowId: nil,
                    sourceAddressLength: 4,
                    sourceAddressHigh: 0,
                    sourceAddressLow: 0x0000_0000_0a00_0002,
                    destinationAddressLength: 4,
                    destinationAddressHigh: 0,
                    destinationAddressLow: 0x0000_0000_0101_0101,
                    textSourceAddress: nil,
                    textDestinationAddress: nil,
                    registrableDomain: nil,
                    dnsQueryName: nil,
                    dnsCname: nil,
                    dnsAnswerAddresses: nil,
                    tlsServerName: nil,
                    quicVersion: nil,
                    quicPacketType: nil,
                    quicDestinationConnectionId: nil,
                    quicSourceConnectionId: nil,
                    classification: nil,
                    closeReason: nil,
                    largePacketCount: nil,
                    smallPacketCount: nil,
                    udpPacketCount: nil,
                    tcpPacketCount: nil,
                    quicInitialCount: nil,
                    tcpSynCount: nil,
                    tcpFinCount: nil,
                    tcpRstCount: nil,
                    burstDurationMs: nil,
                    burstPacketCount: nil,
                    leadingBytes200ms: nil,
                    leadingPackets200ms: nil,
                    leadingBytes600ms: nil,
                    leadingPackets600ms: nil,
                    burstLargePacketCount: nil,
                    burstUdpPacketCount: nil,
                    burstTcpPacketCount: nil,
                    burstQuicInitialCount: nil,
                    associatedDomain: nil,
                    associationSource: nil,
                    associationAgeMs: nil,
                    associationConfidence: nil,
                    lineageID: nil,
                    lineageGeneration: nil,
                    lineageAgeMs: nil,
                    lineageReuseGapMs: nil,
                    lineageReopenCount: nil,
                    lineageSiblingCount: nil,
                    pathEpoch: nil,
                    pathInterfaceClass: nil,
                    pathIsExpensive: nil,
                    pathIsConstrained: nil,
                    pathSupportsDNS: nil,
                    pathChangedRecently: nil,
                    serviceFamily: nil,
                    serviceFamilyConfidence: nil,
                    serviceAttributionSourceMask: nil
                )
            ]
        )

        let samples = await stream.readAll()
        let sample = try XCTUnwrap(samples.first)
        XCTAssertEqual(sample.sourceAddress, "10.0.0.2")
        XCTAssertEqual(sample.destinationAddress, "1.1.1.1")
    }

    /// Verifies the detector-first pipeline emits sparse flow and activity records without deep metadata work.
    func testPacketAnalyticsPipelineEmitsSparseFlowAndActivityRecords() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let packet1 = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x02,
                payload: [22, 3, 3, 0, 5]
            )
        )
        let packet2 = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: [0x17, 0x03, 0x03, 0x00, 0x01]
            )
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: true,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: true,
            emitBurstShapeCounters: true,
            activitySampleMinimumPackets: 2,
            activitySampleMinimumBytes: 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: true,
            emitActivitySamples: true
        )

        let records = await pipeline.ingest(
            packets: [packet1, packet2],
            families: [],
            direction: .outbound,
            policy: policy
        )

        XCTAssertEqual(records.map(\.kind), [.flowOpen, .activitySample])
        XCTAssertEqual(records.first?.packetCount, 1)
        XCTAssertEqual(records.last?.packetCount, 2)
        XCTAssertEqual(records.last?.flowPacketCount, 2)
        XCTAssertEqual(records.last?.flowByteCount, packet1.count + packet2.count)
    }

    /// Verifies detector-grade flow slices emit on cadence with typed protocol and control counters.
    func testPacketAnalyticsPipelineEmitsFlowSliceCountersOnCadence() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let syn = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x02,
                payload: []
            )
        )
        let large = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 1_400)
            )
        )
        let small = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 32)
            )
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: true,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: true,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )

        let first = await pipeline.ingest(packets: [syn], families: [], direction: .outbound, policy: policy)
        XCTAssertEqual(first.map(\.kind), [.flowOpen])

        await clock.advance(by: 0.1)
        let second = await pipeline.ingest(packets: [large], families: [], direction: .outbound, policy: policy)
        XCTAssertTrue(second.isEmpty)

        await clock.advance(by: 0.2)
        let third = await pipeline.ingest(packets: [small], families: [], direction: .outbound, policy: policy)
        XCTAssertEqual(third.map(\.kind), [.flowSlice])

        let slice = try XCTUnwrap(third.first)
        XCTAssertEqual(slice.packetCount, 3)
        XCTAssertEqual(slice.bytes, syn.count + large.count + small.count)
        XCTAssertEqual(slice.flowPacketCount, 3)
        XCTAssertEqual(slice.tcpPacketCount, 3)
        XCTAssertEqual(slice.udpPacketCount, 0)
        XCTAssertEqual(slice.largePacketCount, 1)
        XCTAssertEqual(slice.smallPacketCount, 2)
        XCTAssertEqual(slice.tcpSynCount, 1)
        XCTAssertEqual(slice.tcpFinCount, 0)
        XCTAssertEqual(slice.tcpRstCount, 0)
        XCTAssertEqual(slice.quicInitialCount, 0)
    }

    /// Verifies explicit TCP close signals produce typed `flowClose` records.
    func testPacketAnalyticsPipelineEmitsFlowCloseOnTCPFIN() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let dataPacket = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 128)
            )
        )
        let outboundFinPacket = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x11,
                payload: []
            )
        )
        let inboundFinPacket = Data(
            makeIPv4TCPPacket(
                sourceAddress: [1, 1, 1, 1],
                destinationAddress: [10, 0, 0, 2],
                sourcePort: 443,
                destinationPort: 50_000,
                tcpFlags: 0x11,
                payload: []
            )
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: true,
            emitBurstShapeCounters: true,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )

        let opened = await pipeline.ingest(packets: [dataPacket], families: [], direction: .outbound, policy: policy)
        XCTAssertEqual(opened.map(\.kind), [.flowOpen])

        await clock.advance(by: 0.05)
        let firstFin = await pipeline.ingest(packets: [outboundFinPacket], families: [], direction: .outbound, policy: policy)
        XCTAssertEqual(firstFin.map(\.kind), [])

        await clock.advance(by: 0.05)
        let closed = await pipeline.ingest(packets: [inboundFinPacket], families: [], direction: .inbound, policy: policy)
        let closeRecords = closed.filter { $0.kind == .flowClose }
        XCTAssertEqual(closeRecords.count, 2)

        let originalClose = try XCTUnwrap(closeRecords.first { $0.flowByteCount == dataPacket.count + outboundFinPacket.count })
        XCTAssertEqual(originalClose.closeReason, .tcpFin)
        XCTAssertEqual(originalClose.flowPacketCount, 2)
        XCTAssertEqual(originalClose.flowByteCount, dataPacket.count + outboundFinPacket.count)

        let inboundClose = try XCTUnwrap(closeRecords.first { $0.flowByteCount == inboundFinPacket.count })
        XCTAssertEqual(inboundClose.closeReason, .tcpFin)
        XCTAssertEqual(inboundClose.packetCount, 1)
        XCTAssertEqual(inboundClose.tcpPacketCount, 1)
        XCTAssertEqual(inboundClose.tcpFinCount, 1)
        XCTAssertEqual(inboundClose.tcpSynCount, 0)
    }

    /// Verifies idle flow eviction emits a synthetic `flowClose` record before new traffic is processed.
    func testPacketAnalyticsPipelineEmitsIdleFlowCloseOnEviction() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let firstFlowPacket = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Array(repeating: 0x42, count: 160)
            )
        )
        let secondFlowPacket = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 3],
                destinationAddress: [8, 8, 8, 8],
                sourcePort: 50_001,
                destinationPort: 443,
                payload: Array(repeating: 0x24, count: 160)
            )
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: true,
            emitBurstShapeCounters: true,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )

        let first = await pipeline.ingest(packets: [firstFlowPacket], families: [], direction: .outbound, policy: policy)
        XCTAssertEqual(first.map(\.kind), [.flowOpen])

        await clock.advance(by: 121)
        let second = await pipeline.ingest(packets: [secondFlowPacket], families: [], direction: .outbound, policy: policy)
        XCTAssertEqual(second.map(\.kind), [.flowClose, .flowOpen])

        let close = try XCTUnwrap(second.first)
        XCTAssertEqual(close.closeReason, .idleEviction)
        XCTAssertEqual(close.bytes, 0)
        XCTAssertNil(close.packetCount)
        XCTAssertEqual(close.flowPacketCount, 1)
        XCTAssertEqual(close.flowByteCount, firstFlowPacket.count)
    }

    /// Verifies completed bursts carry onset and protocol-shape counters without replaying raw packets.
    func testPacketAnalyticsPipelineEmitsBurstShapeCounters() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 50),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let small = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Array(repeating: 0x11, count: 96)
            )
        )
        let large = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Array(repeating: 0x22, count: 1_400)
            )
        )
        let nextBurst = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Array(repeating: 0x33, count: 128)
            )
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: true,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: true,
            emitActivitySamples: false
        )

        let first = await pipeline.ingest(packets: [small], families: [], direction: .inbound, policy: policy)
        XCTAssertEqual(first.map(\.kind), [.flowOpen])

        await clock.advance(by: 0.05)
        let second = await pipeline.ingest(packets: [large], families: [], direction: .inbound, policy: policy)
        XCTAssertTrue(second.isEmpty)

        await clock.advance(by: 0.15)
        let third = await pipeline.ingest(packets: [nextBurst], families: [], direction: .inbound, policy: policy)
        XCTAssertEqual(third.map(\.kind), [.burst])

        let burst = try XCTUnwrap(third.first)
        XCTAssertEqual(burst.bytes, small.count + large.count)
        XCTAssertEqual(burst.packetCount, 2)
        XCTAssertEqual(burst.burstPacketCount, 2)
        XCTAssertEqual(burst.udpPacketCount, 2)
        XCTAssertEqual(burst.tcpPacketCount, 0)
        XCTAssertEqual(burst.largePacketCount, 1)
        XCTAssertEqual(burst.smallPacketCount, 1)
        XCTAssertEqual(burst.leadingBytes200ms, small.count + large.count)
        XCTAssertEqual(burst.leadingPackets200ms, 2)
        XCTAssertEqual(burst.leadingBytes600ms, small.count + large.count)
        XCTAssertEqual(burst.leadingPackets600ms, 2)
        XCTAssertEqual(burst.burstLargePacketCount, 1)
        XCTAssertEqual(burst.burstUdpPacketCount, 2)
        XCTAssertEqual(burst.burstTcpPacketCount, 0)
        XCTAssertEqual(burst.burstQuicInitialCount, 0)
    }

    /// Verifies the telemetry worker skips pure ACK-only batches before they enter the async worker queue.
    func testPacketTelemetryWorkerSkipsAckOnlyBatch() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: PacketSampleStream(maxBytes: 2_048, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink())),
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        let ackOnly = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x10,
                payload: []
            )
        )

        let result = worker.submit(packets: [ackOnly], families: [], direction: .outbound)
        let queuedSnapshot = worker.snapshot()
        await worker.stopAndWait()
        let drainedSnapshot = worker.snapshot()

        XCTAssertTrue(result.accepted)
        XCTAssertFalse(result.skipped)
        XCTAssertEqual(queuedSnapshot.acceptedBatches, 1)
        XCTAssertEqual(drainedSnapshot.queuedBatches, 0)
        XCTAssertEqual(drainedSnapshot.skippedBatches, 1)
    }

    /// Verifies the optional rich packet JSONL stream writes packet-level facts without requiring a detector.
    func testPacketTelemetryWorkerWritesRichPacketLogRecords() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 123))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let richStore = RichPacketLogStore(
            rootURL: root,
            policy: RichPacketLogPolicy(
                isEnabled: true,
                includePacketBytePrefix: true,
                packetBytePrefixLength: 4,
                filePrefix: "debug packets"
            )
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            clock: clock,
            packetStream: nil,
            detectors: [],
            richPacketLogStore: richStore,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            writerProcess: "unit-test-worker"
        )
        await worker.updateSessionContextAndWait(
            DetectorSessionContext(
                sessionId: "session-a",
                packetStreamStartedAtMs: 123_000,
                sessionTarget: "example-service"
            )
        )

        let packet = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [93, 184, 216, 34],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: [0x17, 0x03, 0x03]
            )
        )

        let result = worker.submit(packets: [packet], families: [], direction: .outbound)
        XCTAssertTrue(result.accepted)
        await worker.flushAndWait()

        let records = try await richStore.readRecords()
        let record = try XCTUnwrap(records.first)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(record.schemaVersion, 1)
        XCTAssertEqual(record.sequenceNumber, 1)
        XCTAssertEqual(record.timestampMs, 123_000)
        XCTAssertEqual(record.direction, .outbound)
        XCTAssertEqual(record.writerProcess, "unit-test-worker")
        XCTAssertEqual(record.sessionId, "session-a")
        XCTAssertEqual(record.sessionTarget, "example-service")
        XCTAssertEqual(record.protocolHint, "tcp")
        XCTAssertEqual(record.packetLength, 43)
        XCTAssertEqual(record.transportPayloadLength, 3)
        XCTAssertEqual(record.sourceAddress, "10.0.0.2")
        XCTAssertEqual(record.sourcePort, 50_000)
        XCTAssertEqual(record.destinationAddress, "93.184.216.34")
        XCTAssertEqual(record.destinationPort, 443)
        XCTAssertEqual(record.remoteEndpoint, "tcp://93.184.216.34:443")
        XCTAssertEqual(record.flowIdentity.remoteEndpoint, "tcp://93.184.216.34:443")
        XCTAssertEqual(record.tcpFlags, 0x18)
        XCTAssertEqual(record.tcpAck, true)
        XCTAssertEqual(record.tcpPsh, true)
        XCTAssertEqual(record.tcpSyn, false)
        XCTAssertEqual(record.packetBytePrefixHex, "4500002b")
        let richSnapshot = try await richStore.snapshot()
        XCTAssertFalse(richSnapshot.files.isEmpty)

        await worker.stopAndWait()
    }

    /// Verifies stop waits for coalesced detector persistence before returning.
    func testPacketTelemetryWorkerStopFlushesPersistedDetections() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = DetectionStore(fileURL: root.appendingPathComponent("detections.json", isDirectory: false))
        let detector = TestDetector()
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: nil,
            detectors: [detector],
            detectionStore: store,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        let packet = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: [0x17, 0x03, 0x03, 0x00, 0x01]
            )
        )

        let result = worker.submit(packets: [packet], families: [], direction: .outbound)
        XCTAssertTrue(result.accepted)
        XCTAssertEqual(worker.snapshot().acceptedBatches, 1)
        await worker.stopAndWait()

        let persisted = try store.load()
        XCTAssertEqual(persisted?.totalDetectionCount, 1)
        XCTAssertEqual(persisted?.recentEvents.first?.flowId, "")
    }

    /// Verifies releasing a worker drains queued detector work even without an explicit awaited stop.
    func testPacketTelemetryWorkerDeinitDrainsQueuedDetections() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = DetectionStore(fileURL: root.appendingPathComponent("detections.json", isDirectory: false))
        let detector = TestDetector()
        var worker: PacketTelemetryWorker? = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: nil,
            detectors: [detector],
            detectionStore: store,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        let packet = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: [0x17, 0x03, 0x03, 0x00, 0x01]
            )
        )

        let result = worker?.submit(packets: [packet], families: [], direction: .outbound)
        XCTAssertEqual(result?.accepted, true)
        worker = nil

        var persisted: DetectionSnapshot?
        for _ in 0..<50 {
            persisted = try store.load()
            if persisted?.totalDetectionCount == 1 {
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }

        XCTAssertEqual(persisted?.totalDetectionCount, 1)
        XCTAssertEqual(persisted?.recentEvents.first?.flowId, "")
    }

    /// Verifies awaited clears do not race the next foreground snapshot.
    func testPacketTelemetryWorkerAwaitedClearsAreVisibleImmediately() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let packetStream = PacketSampleStream(maxBytes: 2_048, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink()))
        let event = DetectionEvent(
            id: "event-1",
            detectorIdentifier: "test-detector",
            signal: "test-signal",
            target: "test-target",
            timestamp: Date(timeIntervalSince1970: 10),
            confidence: 0.9,
            trigger: "metadata",
            flowId: "flow-1",
            host: "example.com",
            classification: nil,
            bytes: 512,
            packetCount: 1,
            durationMs: nil
        )
        let worker = PacketTelemetryWorker(
            pipeline: PacketAnalyticsPipeline(
                clock: clock,
                burstTracker: BurstTracker(thresholdMs: 350),
                signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
            ),
            packetStream: packetStream,
            initialDetectionSnapshot: DetectionSnapshot(
                updatedAt: event.timestamp,
                totalDetectionCount: 1,
                countsByDetector: ["test-detector": 1],
                countsByTarget: ["test-target": 1],
                recentEvents: [event]
            ),
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        try await packetStream.append(
            PacketSample(
                timestamp: Date(timeIntervalSince1970: 11),
                direction: "outbound",
                flowId: "flow-1",
                bytes: 256,
                protocolHint: "tcp"
            )
        )

        await worker.clearRecentEventsAndWait()
        await worker.clearDetectionsAndWait()

        let snapshot = await worker.recentSnapshot(limit: 10)
        XCTAssertTrue(snapshot.samples.isEmpty)
        XCTAssertEqual(snapshot.detections, .empty)

        await worker.stopAndWait()
    }

    /// Verifies detectors can consume richer sparse records than the foreground live tap publishes by default.
    func testPacketTelemetryWorkerDetectorsSeeFlowSlicesWhileLiveTapStaysLean() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let packetStream = PacketSampleStream(maxBytes: 4_096, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink()))
        let detector = RecordingDetector()
        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: true,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: true,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: packetStream,
            detectors: [detector],
            logger: StructuredLogger(sink: InMemoryLogSink()),
            processInfo: .processInfo,
            emissionPolicyOverride: policy
        )

        let syn = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x02,
                payload: []
            )
        )
        let payloadA = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 256)
            )
        )
        let payloadB = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 256)
            )
        )

        XCTAssertTrue(worker.submit(packets: [syn], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        await clock.advance(by: 0.1)
        XCTAssertTrue(worker.submit(packets: [payloadA], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        await clock.advance(by: 0.2)
        XCTAssertTrue(worker.submit(packets: [payloadB], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()

        await worker.stopAndWait()

        let snapshot = await worker.recentSnapshot(limit: 10)
        XCTAssertEqual(snapshot.samples.map(\.kind), [.flowOpen])
        XCTAssertEqual(detector.recordedKinds(), [.flowOpen, .flowSlice])
    }

    /// Verifies app-supplied session context is stamped by the worker onto detector records that request it.
    func testPacketTelemetryWorkerStampsSessionContextWhenRequested() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let detector = ProjectionRecordingDetector(
            identifier: "session-detector",
            requirements: DetectorRequirements(recordKinds: [.flowOpen], featureFamilies: [.sessionContext])
        )
        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: false,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            detectors: [detector],
            logger: StructuredLogger(sink: InMemoryLogSink()),
            processInfo: .processInfo,
            emissionPolicyOverride: policy
        )

        await worker.updateSessionContextAndWait(
            DetectorSessionContext(
                sessionId: "session-1",
                packetStreamStartedAtMs: 1_000,
                foregroundReadyAtMs: 1_100,
                appOpenAtMs: 900,
                sessionTarget: "example-session"
            )
        )
        let packet = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [157, 240, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Array(repeating: 0x41, count: 600)
            )
        )

        XCTAssertTrue(worker.submit(packets: [packet], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        await worker.stopAndWait()

        XCTAssertEqual(detector.recordedKinds(), [.flowOpen])
        XCTAssertEqual(detector.firstSessionID(), "session-1")
    }

    /// Verifies detector projections filter record kinds and omit unrequested enrichment families.
    func testDetectorRecordCollectionProjectsKindsAndFieldsByRequirements() {
        let records = [
            makePacketStreamRecord(
                kind: .flowOpen,
                timestamp: Date(timeIntervalSince1970: 1),
                flowHash: 0xfeed_beef,
                registrableDomain: "example.com",
                tlsServerName: "api.example.com",
                bytes: 512,
                packetCount: 2,
                associatedDomain: "example.com",
                serviceFamily: "example.com",
                serviceFamilyConfidence: 0.76,
                serviceAttributionSourceMask: 0b11
            ),
            makePacketStreamRecord(
                kind: .flowSlice,
                timestamp: Date(timeIntervalSince1970: 2),
                flowHash: 0xfeed_beef,
                registrableDomain: "example.com",
                tlsServerName: "api.example.com",
                bytes: 1_024,
                packetCount: 4,
                lineageID: 42,
                lineageGeneration: 1
            )
        ]

        let requirements = DetectorRequirements(
            recordKinds: [.flowOpen],
            featureFamilies: [.serviceAttribution]
        )
        let collection = DetectorRecordCollection(records, projection: DetectorRecordProjection(requirements: requirements))

        XCTAssertEqual(collection.count, 1)
        guard let record = collection.first else {
            XCTFail("Expected one projected record")
            return
        }
        XCTAssertEqual(record.kind, .flowOpen)
        XCTAssertNil(record.registrableDomain)
        XCTAssertNil(record.tlsServerName)
        XCTAssertNil(record.lineageID)
        XCTAssertEqual(record.serviceFamily, "example.com")
        XCTAssertEqual(record.serviceAttributionSourceMask, 0b11)
    }

    /// Verifies packet-cue records expose the exact packet-level fields required by detector implementations.
    func testDetectorRecordCollectionProjectsPacketCueFieldsByDefault() throws {
        let streamRecord = PacketSampleStream.PacketStreamRecord(
            kind: .packetCue,
            timestamp: Date(timeIntervalSince1970: 1.25),
            direction: PacketDirection.outbound.rawValue,
            bytes: 75,
            packetCount: 1,
            flowPacketCount: 3,
            flowByteCount: 512,
            protocolHint: "tcp",
            ipVersion: 4,
            transportProtocolNumber: 6,
            sourcePort: 50_000,
            destinationPort: 443,
            flowHash: 0xfeed_beef,
            textFlowId: nil,
            sourceAddressLength: 4,
            sourceAddressHigh: 0,
            sourceAddressLow: 0x0000_0000_0a00_0002,
            destinationAddressLength: 4,
            destinationAddressHigh: 0,
            destinationAddressLow: 0x0000_0000_0101_0101,
            textSourceAddress: nil,
            textDestinationAddress: nil,
            registrableDomain: "example.com",
            dnsQueryName: "api.example.com",
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            tlsServerName: "api.example.com",
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            classification: nil,
            closeReason: nil,
            largePacketCount: nil,
            smallPacketCount: nil,
            udpPacketCount: nil,
            tcpPacketCount: nil,
            quicInitialCount: nil,
            tcpSynCount: nil,
            tcpFinCount: nil,
            tcpRstCount: nil,
            burstDurationMs: nil,
            burstPacketCount: nil,
            leadingBytes200ms: nil,
            leadingPackets200ms: nil,
            leadingBytes600ms: nil,
            leadingPackets600ms: nil,
            burstLargePacketCount: nil,
            burstUdpPacketCount: nil,
            burstTcpPacketCount: nil,
            burstQuicInitialCount: nil,
            associatedDomain: "example.com",
            associationSource: nil,
            associationAgeMs: nil,
            associationConfidence: nil,
            lineageID: nil,
            lineageGeneration: nil,
            lineageAgeMs: nil,
            lineageReuseGapMs: nil,
            lineageReopenCount: nil,
            lineageSiblingCount: nil,
            pathEpoch: nil,
            pathInterfaceClass: nil,
            pathIsExpensive: nil,
            pathIsConstrained: nil,
            pathSupportsDNS: nil,
            pathChangedRecently: nil,
            serviceFamily: nil,
            serviceFamilyConfidence: nil,
            serviceAttributionSourceMask: nil,
            packetLength: 75,
            transportPayloadLength: 35,
            tcpFlags: 0x18,
            tcpAck: true,
            tcpPsh: true,
            packetCueReason: .tcpAckPshPayloadRange
        )
        let requirements = DetectorRequirements(recordKinds: [.packetCue])
        let collection = DetectorRecordCollection([streamRecord], projection: DetectorRecordProjection(requirements: requirements))

        let record = try XCTUnwrap(collection.first)
        XCTAssertEqual(record.kind, .packetCue)
        XCTAssertEqual(record.timestampMs, 1_250, accuracy: 0.001)
        XCTAssertEqual(record.direction, PacketDirection.outbound.rawValue)
        XCTAssertEqual(record.transportProtocol, .tcp)
        XCTAssertEqual(record.packetLength, 75)
        XCTAssertEqual(record.transportPayloadLength, 35)
        XCTAssertEqual(record.tcpFlags, 0x18)
        XCTAssertEqual(record.tcpAck, true)
        XCTAssertEqual(record.tcpPsh, true)
        XCTAssertEqual(record.packetCueReason, .tcpAckPshPayloadRange)
        XCTAssertEqual(record.sourceAddress, "10.0.0.2")
        XCTAssertEqual(record.sourcePort, 50_000)
        XCTAssertEqual(record.destinationAddress, "1.1.1.1")
        XCTAssertEqual(record.destinationPort, 443)
        XCTAssertEqual(record.flowId, "00000000feedbeef")
        XCTAssertEqual(record.tlsServerName, "api.example.com")
        XCTAssertEqual(record.registrableDomain, "example.com")
        XCTAssertEqual(record.associatedDomain, "example.com")
        XCTAssertEqual(record.dnsQueryName, "api.example.com")
        XCTAssertEqual(record.remoteAddress, "1.1.1.1")
        XCTAssertEqual(record.remotePort, 443)
        XCTAssertEqual(record.remoteEndpoint, "tcp://1.1.1.1:443")
        XCTAssertEqual(record.flowIdentity?.remoteEndpoint, "tcp://1.1.1.1:443")
        XCTAssertNil(record.role)
        XCTAssertEqual(record.ownerKey, "endpoint:tcp://1.1.1.1:443")
    }

    /// Verifies remote endpoint derivation follows packet direction.
    func testDetectorRecordRemoteEndpointUsesRemoteSideForInboundAndOutbound() throws {
        let outbound = makePacketStreamRecord(
            kind: .flowSlice,
            timestamp: Date(timeIntervalSince1970: 1),
            flowHash: 0xfeed_beef,
            registrableDomain: nil,
            tlsServerName: nil,
            bytes: 512,
            packetCount: 2,
            direction: .outbound,
            protocolHint: "udp",
            transportProtocolNumber: 17,
            sourceAddress: "10.0.0.2",
            sourcePort: 50_000,
            destinationAddress: "203.0.113.10",
            destinationPort: 443
        )
        let inbound = makePacketStreamRecord(
            kind: .flowSlice,
            timestamp: Date(timeIntervalSince1970: 2),
            flowHash: 0xfeed_beef,
            registrableDomain: nil,
            tlsServerName: nil,
            bytes: 256,
            packetCount: 1,
            direction: .inbound,
            protocolHint: "udp",
            transportProtocolNumber: 17,
            sourceAddress: "203.0.113.10",
            sourcePort: 443,
            destinationAddress: "10.0.0.2",
            destinationPort: 50_000
        )
        let requirements = DetectorRequirements(
            recordKinds: [.flowSlice],
            featureFamilies: [.remoteEndpoint]
        )
        let collection = DetectorRecordCollection(
            [outbound, inbound],
            projection: DetectorRecordProjection(requirements: requirements)
        )

        XCTAssertEqual(collection[0].remoteEndpoint, "udp://203.0.113.10:443")
        XCTAssertEqual(collection[1].remoteEndpoint, "udp://203.0.113.10:443")
    }

    /// Verifies topology records can expose lineage, owner, explicit role labels, and injected scope.
    func testTopologyRecordsProjectLineageOwnerRoleAndScope() throws {
        let scopeFamily = "video-cdn"
        let record = makePacketStreamRecord(
            kind: .flowSlice,
            timestamp: Date(timeIntervalSince1970: 4),
            flowHash: 0xabc,
            registrableDomain: "media.example",
            tlsServerName: nil,
            bytes: 1_200,
            packetCount: 3,
            sourceAddress: "10.0.0.2",
            destinationAddress: "203.0.113.40",
            lineageID: 99,
            lineageGeneration: 2,
            lineageAgeMs: 1_500,
            lineageReopenCount: 1,
            lineageSiblingCount: 4,
            serviceFamily: "media.example",
            role: "media-example-role",
            addressScopeFamily: scopeFamily,
            addressScopeSource: .prefix,
            addressScopeConfidence: 0.91
        )
        let requirements = DetectorRequirements(
            recordKinds: [.flowSlice],
            featureFamilies: [.lineage, .remoteEndpoint, .roleAttribution, .addressScope]
        )
        let collection = DetectorRecordCollection([record], projection: DetectorRecordProjection(requirements: requirements))
        let projected = try XCTUnwrap(collection.first)

        XCTAssertEqual(projected.lineageID, 99)
        XCTAssertEqual(projected.lineageAgeMs, 1_500)
        XCTAssertEqual(projected.lineageReopenCount, 1)
        XCTAssertEqual(projected.lineageSiblingCount, 4)
        XCTAssertEqual(projected.remoteEndpoint, "udp://203.0.113.40:443")
        XCTAssertEqual(projected.role, "media-example-role")
        XCTAssertEqual(projected.ownerKey, "endpoint:udp://203.0.113.40:443")
        XCTAssertEqual(projected.addressScopeFamily, scopeFamily)
        XCTAssertEqual(projected.addressScopeSource, .prefix)
        XCTAssertEqual(projected.addressScopeConfidence, 0.91)
    }

    /// Verifies passive content-filter attribution records expose source app identity without packet fields.
    func testSourceAppFlowRecordsProjectContentFilterAttribution() throws {
        let scopeFamily = "example-service"
        let record = makePacketStreamRecord(
            kind: .sourceAppFlow,
            timestamp: Date(timeIntervalSince1970: 5),
            flowHash: 0x1234,
            registrableDomain: nil,
            tlsServerName: nil,
            bytes: 0,
            packetCount: 0,
            sourceAddress: "10.0.0.2",
            destinationAddress: "203.0.113.55",
            addressScopeFamily: scopeFamily,
            addressScopeSource: .contentFilter,
            sourceAppIdentifier: "com.example.video",
            sourceAppUniqueIdentifierHash: "hash-1",
            sourceAppVersion: "340.0",
            attributionFlowId: "filter-flow-1",
            attributionSource: .contentFilter,
            attributionObservedAtMs: 5_000,
            localEndpoint: "10.0.0.2:50000",
            remoteEndpoint: "tcp://203.0.113.55:443",
            remoteHostname: "gateway.example.com"
        )
        let requirements = DetectorRequirements(
            recordKinds: [.sourceAppFlow],
            featureFamilies: [.sourceAppAttribution, .remoteEndpoint, .addressScope]
        )
        let collection = DetectorRecordCollection([record], projection: DetectorRecordProjection(requirements: requirements))
        let projected = try XCTUnwrap(collection.first)

        XCTAssertEqual(projected.kind, .sourceAppFlow)
        XCTAssertEqual(projected.sourceAppIdentifier, "com.example.video")
        XCTAssertEqual(projected.sourceAppUniqueIdentifierHash, "hash-1")
        XCTAssertEqual(projected.sourceAppVersion, "340.0")
        XCTAssertEqual(projected.attributionFlowId, "filter-flow-1")
        XCTAssertEqual(projected.attributionSource, .contentFilter)
        XCTAssertEqual(projected.attributionObservedAtMs, 5_000)
        XCTAssertEqual(projected.localEndpoint, "10.0.0.2:50000")
        XCTAssertEqual(projected.remoteEndpoint, "tcp://203.0.113.55:443")
        XCTAssertEqual(projected.remoteHostname, "gateway.example.com")
        XCTAssertEqual(projected.ownerKey, "app:com.example.video")
        XCTAssertEqual(projected.addressScopeFamily, scopeFamily)
        XCTAssertEqual(projected.addressScopeSource, .contentFilter)
    }

    /// Verifies legacy detector defaults do not start receiving packet-cue records implicitly.
    func testLegacyDetectorRequirementsDoNotProjectPacketCueRecords() {
        let records = [
            makePacketStreamRecord(
                kind: .flowOpen,
                timestamp: Date(timeIntervalSince1970: 1),
                flowHash: 0xfeed_beef,
                registrableDomain: nil,
                tlsServerName: nil,
                bytes: 75,
                packetCount: 1
            ),
            makePacketStreamRecord(
                kind: .packetCue,
                timestamp: Date(timeIntervalSince1970: 1),
                flowHash: 0xfeed_beef,
                registrableDomain: nil,
                tlsServerName: nil,
                bytes: 75,
                packetCount: 1
            )
        ]

        let collection = DetectorRecordCollection(records)
        XCTAssertEqual(collection.map(\.kind), [.flowOpen])
    }

    /// Verifies the analytics pipeline emits generic packet-cue records for configured TCP and UDP packet shapes.
    func testPacketAnalyticsPipelineEmitsPacketCueRecordsWhenRequested() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: false,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false,
            emitPacketCues: true,
            packetCuePolicy: PacketCueEmissionPolicy(
                tcpPayloadLengthRange: PacketLengthRange(0...800),
                udpPacketLengthRange: PacketLengthRange(500...1_300),
                directions: [.outbound],
                requireTcpAck: true,
                requireTcpPsh: true
            )
        )

        let tcpPacket = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 35)
            )
        )
        let tcpRecords = await pipeline.ingest(packets: [tcpPacket], families: [], direction: .outbound, policy: policy)
        let tcpCue = try XCTUnwrap(tcpRecords.first { $0.kind == .packetCue })
        XCTAssertEqual(tcpCue.packetLength, tcpPacket.count)
        XCTAssertEqual(tcpCue.transportPayloadLength, 35)
        XCTAssertEqual(tcpCue.tcpFlags, 0x18)
        XCTAssertEqual(tcpCue.tcpAck, true)
        XCTAssertEqual(tcpCue.tcpPsh, true)
        XCTAssertEqual(tcpCue.packetCueReason, .tcpAckPshPayloadRange)
        XCTAssertEqual(tcpCue.sourcePort, 50_000)
        XCTAssertEqual(tcpCue.destinationPort, 443)

        await clock.advance(by: 0.1)
        let udpPacket = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 2],
                sourcePort: 50_001,
                destinationPort: 443,
                payload: Array(repeating: 0x42, count: 572)
            )
        )
        let udpRecords = await pipeline.ingest(packets: [udpPacket], families: [], direction: .outbound, policy: policy)
        let udpCue = try XCTUnwrap(udpRecords.first { $0.kind == .packetCue })
        XCTAssertEqual(udpCue.packetLength, udpPacket.count)
        XCTAssertEqual(udpCue.transportPayloadLength, 572)
        XCTAssertNil(udpCue.tcpFlags)
        XCTAssertNil(udpCue.tcpAck)
        XCTAssertNil(udpCue.tcpPsh)
        XCTAssertEqual(udpCue.packetCueReason, .udpPacketLengthRange)
        XCTAssertEqual(udpCue.protocolHint, "udp")
    }

    /// Verifies no-role traffic can still carry address scope when a supplied prefix catalog knows the remote IP.
    func testPacketAnalyticsPipelineAddsAddressScopeFromConfiguredPrefixes() async throws {
        let scopeFamily = "video-cdn"
        let prefix = try XCTUnwrap(AddressScopePrefix(cidr: "203.0.113.0/24", family: scopeFamily, confidence: 0.88))
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink())),
            addressScopeClassifier: AddressScopeClassifier(prefixes: [prefix])
        )
        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: false,
            emitAddressScopeFields: true,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )
        let packet = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [203, 0, 113, 42],
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Array(repeating: 0x42, count: 64)
            )
        )

        let records = await pipeline.ingest(packets: [packet], families: [], direction: .outbound, policy: policy)
        let flowOpen = try XCTUnwrap(records.first(where: { $0.kind == .flowOpen }))

        XCTAssertEqual(flowOpen.addressScopeFamily, scopeFamily)
        XCTAssertEqual(flowOpen.addressScopeSource, .prefix)
        XCTAssertEqual(flowOpen.addressScopeConfidence, 0.88)
        XCTAssertNil(flowOpen.registrableDomain)
        XCTAssertNil(flowOpen.tlsServerName)
    }

    /// Verifies the worker only enables packet-cue emission for detectors that opt into the new record kind.
    func testPacketTelemetryWorkerEmitsPacketCueRecordsOnlyForRequestingDetectors() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let legacyDetector = RecordingDetector()
        let packetCueDetector = ProjectionRecordingDetector(
            identifier: "packet-cue",
            requirements: DetectorRequirements(recordKinds: [.packetCue])
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: nil,
            detectors: [legacyDetector, packetCueDetector],
            logger: StructuredLogger(sink: InMemoryLogSink()),
            packetCuePolicy: PacketCueEmissionPolicy(
                tcpPayloadLengthRange: PacketLengthRange(0...800),
                directions: [.outbound],
                requireTcpAck: true,
                requireTcpPsh: true
            )
        )

        let packet = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 35)
            )
        )

        XCTAssertTrue(worker.submit(packets: [packet], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        await worker.stopAndWait()

        XCTAssertEqual(legacyDetector.recordedKinds(), [.flowOpen])
        XCTAssertEqual(packetCueDetector.recordedKinds(), [.packetCue])
    }

    /// Verifies packet cues can be exported through the app-facing live tap when explicitly configured.
    func testPacketTelemetryWorkerPublishesPacketCuesHealthAndLivenessIntoLiveTap() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let packetStream = PacketSampleStream(
            maxBytes: 64 * 1_024,
            clock: clock,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: packetStream,
            detectors: [],
            logger: StructuredLogger(sink: InMemoryLogSink()),
            includePacketCuesInLiveTap: true,
            packetCuePolicy: PacketCueEmissionPolicy(
                tcpPayloadLengthRange: PacketLengthRange(0...800),
                directions: [.outbound],
                requireTcpAck: true,
                requireTcpPsh: true
            )
        )

        let packet = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 35)
            )
        )

        XCTAssertTrue(worker.submit(packets: [packet], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        let snapshot = await worker.recentSnapshot(limit: 10, includeValidationRecords: true)
        await worker.stopAndWait()

        let cue = try XCTUnwrap(snapshot.samples.first { $0.kind == .packetCue })
        XCTAssertEqual(cue.packetLength, packet.count)
        XCTAssertEqual(cue.transportPayloadLength, 35)
        XCTAssertEqual(cue.tcpAck, true)
        XCTAssertEqual(cue.tcpPsh, true)
        XCTAssertEqual(cue.packetCueReason, .tcpAckPshPayloadRange)
        XCTAssertEqual(cue.remoteEndpoint, "tcp://1.1.1.1:443")
        XCTAssertEqual(cue.flowIdentity?.remoteEndpoint, "tcp://1.1.1.1:443")
        XCTAssertTrue(snapshot.validationRecords.contains { $0.kind == .packetCue })
        XCTAssertTrue(snapshot.health?.availableFeatureFamilies.contains("packetDetails") == true)
        XCTAssertFalse(snapshot.health?.missingFeatureFamilies.contains("packetDetails") == true)
        XCTAssertEqual(snapshot.liveness?.sessionId, nil)
        XCTAssertNotNil(snapshot.liveness?.streamStartedAtMs)
        XCTAssertNotNil(snapshot.liveness?.lastRecordAtMs)
        XCTAssertGreaterThan(snapshot.liveness?.sequenceNumber ?? 0, 0)

        let responseData = try TunnelTelemetryMessageCodec.encodeResponse(.snapshot(snapshot))
        let decodedResponse = try TunnelTelemetryMessageCodec.decodeResponse(responseData)
        let decodedSnapshot = try XCTUnwrap(decodedResponse.snapshot)
        let decodedCue = try XCTUnwrap(decodedSnapshot.samples.first { $0.kind == .packetCue })
        XCTAssertEqual(decodedCue.packetLength, packet.count)
        XCTAssertEqual(decodedCue.transportPayloadLength, 35)
        XCTAssertEqual(decodedCue.timestampMs, cue.timestampMs)
        XCTAssertEqual(decodedSnapshot.liveness?.sequenceNumber, snapshot.liveness?.sequenceNumber)
        XCTAssertEqual(decodedSnapshot.liveness?.lastRecordAtMs, snapshot.liveness?.lastRecordAtMs)
        XCTAssertTrue(decodedSnapshot.validationRecords.contains { $0.kind == .packetCue && $0.timestampMs == cue.timestampMs })

        let exportedObject = try XCTUnwrap(JSONSerialization.jsonObject(with: responseData) as? [String: Any])
        let exportedSnapshot = try XCTUnwrap(exportedObject["snapshot"] as? [String: Any])
        let exportedLiveness = try XCTUnwrap(exportedSnapshot["liveness"] as? [String: Any])
        XCTAssertNotNil(exportedLiveness["sequenceNumber"])
        XCTAssertNotNil(exportedLiveness["lastRecordAtMs"])
        let exportedSamples = try XCTUnwrap(exportedSnapshot["samples"] as? [[String: Any]])
        let exportedCue = try XCTUnwrap(exportedSamples.first { $0["kind"] as? String == PacketSampleKind.packetCue.rawValue })
        XCTAssertNotNil(exportedCue["timestampMs"])
        XCTAssertEqual((exportedCue["packetLength"] as? NSNumber)?.intValue, packet.count)
        XCTAssertEqual((exportedCue["transportPayloadLength"] as? NSNumber)?.intValue, 35)
        let exportedValidationRecords = try XCTUnwrap(exportedSnapshot["validationRecords"] as? [[String: Any]])
        XCTAssertTrue(exportedValidationRecords.contains { $0["kind"] as? String == PacketSampleKind.packetCue.rawValue && $0["timestampMs"] != nil })
    }

    /// Verifies DNS answers can be reused to attribute later hostless UDP/443 traffic and derive service-family hints.
    func testPacketAnalyticsPipelineEmitsDNSAssociationAndServiceAttributionWhenRequested() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let dnsResponse = Data(
            makeIPv4UDPPacket(
                sourceAddress: [8, 8, 8, 8],
                destinationAddress: [10, 0, 0, 2],
                sourcePort: 53,
                destinationPort: 53_000,
                payload: makeDNSResponsePayload(
                    queryName: "video.example.com",
                    answerIPv4: [1, 1, 1, 1]
                )
            )
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: true,
            maxMetadataProbesPerBatch: 2,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: false,
            emitDNSAssociationFields: true,
            emitLineageFields: false,
            emitPathRegimeFields: false,
            emitServiceAttributionFields: true,
            includeHostHints: false,
            includeQUICIdentity: false,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )

        _ = await pipeline.ingest(
            packets: [dnsResponse],
            families: [],
            direction: .inbound,
            policy: policy
        )

        await clock.advance(by: 0.1)
        let mediaPacket = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 53_001,
                destinationPort: 443,
                payload: Array(repeating: 0xc0, count: 64)
            )
        )

        let records = await pipeline.ingest(
            packets: [mediaPacket],
            families: [],
            direction: .outbound,
            policy: policy
        )

        let flowOpen = try XCTUnwrap(records.first(where: { $0.kind == .flowOpen }))
        XCTAssertEqual(flowOpen.associatedDomain, "example.com")
        XCTAssertEqual(flowOpen.associationSource, .dnsAnswer)
        XCTAssertEqual(flowOpen.serviceFamily, "example.com")
        XCTAssertNotNil(flowOpen.serviceFamilyConfidence)
    }

    /// Verifies DNS answers and DNS association survive all the way into the app-facing live tap snapshot.
    func testPacketTelemetryWorkerPublishesDNSAnswersAndAssociationIntoLiveTap() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let packetStream = PacketSampleStream(maxBytes: 64 * 1_024, clock: clock, logger: StructuredLogger(sink: InMemoryLogSink()))
        let detector = ProjectionRecordingDetector(
            identifier: "dns-association-detector",
            requirements: DetectorRequirements(
                recordKinds: [.flowOpen, .metadata],
                featureFamilies: [.dnsAssociation]
            )
        )
        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: true,
            maxMetadataProbesPerBatch: 2,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: false,
            emitDNSAssociationFields: true,
            emitLineageFields: false,
            emitPathRegimeFields: false,
            emitServiceAttributionFields: false,
            includeHostHints: false,
            includeDNSAnswerAddresses: true,
            includeQUICIdentity: false,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: packetStream,
            detectors: [detector],
            logger: StructuredLogger(sink: InMemoryLogSink()),
            processInfo: .processInfo,
            emissionPolicyOverride: policy,
            pathRegimeProvider: nil,
            includeFlowSlicesInLiveTap: false
        )

        let dnsResponse = Data(
            makeIPv4UDPPacket(
                sourceAddress: [8, 8, 8, 8],
                destinationAddress: [10, 0, 0, 2],
                sourcePort: 53,
                destinationPort: 53_000,
                payload: makeDNSResponsePayload(
                    queryName: "video.example.com",
                    answerIPv4: [1, 1, 1, 1]
                )
            )
        )

        XCTAssertTrue(worker.submit(packets: [dnsResponse], families: [], direction: .inbound).accepted)
        await worker.flushAndWait()

        await clock.advance(by: 0.1)
        let mediaPacket = Data(
            makeIPv4UDPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 53_001,
                destinationPort: 443,
                payload: Array(repeating: 0xc0, count: 64)
            )
        )

        XCTAssertTrue(worker.submit(packets: [mediaPacket], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()

        let snapshot = await worker.recentSnapshot(limit: 10)
        _ = try XCTUnwrap(snapshot.samples.first(where: { sample in
            sample.kind == .metadata && sample.dnsAnswerAddresses == ["1.1.1.1"]
        }))

        let associatedFlow = try XCTUnwrap(snapshot.samples.first(where: { $0.associatedDomain == "example.com" }))
        XCTAssertEqual(associatedFlow.associationSource, .dnsAnswer)
        XCTAssertNotNil(associatedFlow.associationConfidence)

        await worker.stopAndWait()
    }

    /// Verifies the lineage tracker stitches related flows together across close/reopen boundaries.
    func testPacketAnalyticsPipelineEmitsLineageAcrossRelatedFlows() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: true,
            emitBurstShapeCounters: false,
            emitDNSAssociationFields: false,
            emitLineageFields: true,
            emitPathRegimeFields: false,
            emitServiceAttributionFields: false,
            includeHostHints: false,
            includeQUICIdentity: false,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )

        let firstOpen = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x02,
                payload: []
            )
        )
        let firstRecords = await pipeline.ingest(packets: [firstOpen], families: [], direction: .outbound, policy: policy)
        let firstFlowOpen = try XCTUnwrap(firstRecords.first(where: { $0.kind == .flowOpen }))
        let firstLineageID = try XCTUnwrap(firstFlowOpen.lineageID)
        XCTAssertEqual(firstFlowOpen.lineageGeneration, 0)

        await clock.advance(by: 0.1)
        let firstClose = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x04,
                payload: []
            )
        )
        _ = await pipeline.ingest(packets: [firstClose], families: [], direction: .outbound, policy: policy)

        await clock.advance(by: 0.5)
        let secondOpen = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_001,
                destinationPort: 443,
                tcpFlags: 0x02,
                payload: []
            )
        )
        let secondRecords = await pipeline.ingest(packets: [secondOpen], families: [], direction: .outbound, policy: policy)
        let secondFlowOpen = try XCTUnwrap(secondRecords.first(where: { $0.kind == .flowOpen }))
        XCTAssertEqual(secondFlowOpen.lineageID, firstLineageID)
        XCTAssertEqual(secondFlowOpen.lineageGeneration, 1)
        XCTAssertEqual(secondFlowOpen.lineageReopenCount, 1)
        XCTAssertNotNil(secondFlowOpen.lineageReuseGapMs)
    }

    /// Verifies path-regime snapshots are stamped onto sparse detector records when requested.
    func testPacketAnalyticsPipelineStampsPathRegimeFieldsWhenRequested() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )

        let packet = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: [0x17, 0x03, 0x03, 0x00, 0x01]
            )
        )

        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: false,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: false,
            emitDNSAssociationFields: false,
            emitLineageFields: false,
            emitPathRegimeFields: true,
            emitServiceAttributionFields: false,
            includeHostHints: false,
            includeQUICIdentity: false,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )

        let runtimeContext = PacketAnalyticsPipeline.RuntimeContext(
            pathRegime: PathRegimeSnapshot(
                epoch: 7,
                interfaceClass: .cellular,
                isExpensive: true,
                isConstrained: true,
                supportsDNS: true,
                changedAt: Date(timeIntervalSince1970: 0)
            )
        )

        let records = await pipeline.ingest(
            packets: [packet],
            families: [],
            direction: .outbound,
            policy: policy,
            runtimeContext: runtimeContext
        )

        let flowOpen = try XCTUnwrap(records.first(where: { $0.kind == .flowOpen }))
        XCTAssertEqual(flowOpen.pathEpoch, 7)
        XCTAssertEqual(flowOpen.pathInterfaceClass, .cellular)
        XCTAssertEqual(flowOpen.pathIsExpensive, true)
        XCTAssertEqual(flowOpen.pathIsConstrained, true)
        XCTAssertEqual(flowOpen.pathSupportsDNS, true)
        XCTAssertEqual(flowOpen.pathChangedRecently, true)
    }

    /// Verifies the generic arm/suppress/count helper stays lightweight and deterministic.
    func testDetectorArmingStateMachineTransitionsThroughSettleSuppressAndCooldown() {
        var machine = DetectorArmingStateMachine(
            policy: DetectorArmingPolicy(
                settlingWindow: 1,
                cooldownWindow: 0.5,
                suppressionWindow: 1
            )
        )

        let first = makeDetectorRecord(timestamp: Date(timeIntervalSince1970: 0))
        XCTAssertEqual(machine.observe(first), .settling)

        let settled = makeDetectorRecord(timestamp: Date(timeIntervalSince1970: 1.1))
        XCTAssertEqual(machine.observe(settled), .armed)

        machine.markCounted(at: settled.timestamp)
        XCTAssertEqual(machine.state, .cooldown)

        let cooled = makeDetectorRecord(timestamp: Date(timeIntervalSince1970: 1.7))
        XCTAssertEqual(machine.observe(cooled), .armed)

        let regimeChanged = makeDetectorRecord(timestamp: Date(timeIntervalSince1970: 1.8), pathChangedRecently: true)
        XCTAssertEqual(machine.observe(regimeChanged), .suppressed)

        let postSuppression = makeDetectorRecord(timestamp: Date(timeIntervalSince1970: 3.0))
        XCTAssertEqual(machine.observe(postSuppression), .settling)
        let rearmed = makeDetectorRecord(timestamp: Date(timeIntervalSince1970: 4.1))
        XCTAssertEqual(machine.observe(rearmed), .armed)
    }

    /// Verifies one worker can satisfy different detector requirements without widening every detector's input batch.
    func testPacketTelemetryWorkerProjectsDifferentViewsPerDetector() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        )
        let narrowDetector = ProjectionRecordingDetector(
            identifier: "narrow",
            requirements: DetectorRequirements(recordKinds: [.flowOpen], featureFamilies: [])
        )
        let wideDetector = ProjectionRecordingDetector(
            identifier: "wide",
            requirements: DetectorRequirements(
                recordKinds: [.flowOpen, .flowSlice],
                featureFamilies: [.lineage]
            )
        )
        let policy = PacketAnalyticsPipeline.EmissionPolicy(
            allowDeepMetadata: false,
            maxMetadataProbesPerBatch: 0,
            emitFlowSlices: true,
            flowSliceIntervalMs: 250,
            emitFlowCloseEvents: false,
            emitBurstShapeCounters: false,
            emitDNSAssociationFields: false,
            emitLineageFields: true,
            emitPathRegimeFields: false,
            emitServiceAttributionFields: false,
            includeHostHints: false,
            includeQUICIdentity: false,
            activitySampleMinimumPackets: 1_024,
            activitySampleMinimumBytes: 16 * 1_024 * 1_024,
            activitySampleMinimumInterval: 60,
            emitBurstEvents: false,
            emitActivitySamples: false
        )
        let worker = PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: nil,
            detectors: [narrowDetector, wideDetector],
            logger: StructuredLogger(sink: InMemoryLogSink()),
            processInfo: .processInfo,
            emissionPolicyOverride: policy
        )

        let syn = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x02,
                payload: []
            )
        )
        let payloadA = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 256)
            )
        )
        let payloadB = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
                tcpFlags: 0x18,
                payload: Array(repeating: 0x17, count: 256)
            )
        )

        XCTAssertTrue(worker.submit(packets: [syn], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        await clock.advance(by: 0.1)
        XCTAssertTrue(worker.submit(packets: [payloadA], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        await clock.advance(by: 0.2)
        XCTAssertTrue(worker.submit(packets: [payloadB], families: [], direction: .outbound).accepted)
        await worker.flushAndWait()
        await worker.stopAndWait()

        XCTAssertEqual(narrowDetector.recordedKinds(), [.flowOpen])
        XCTAssertEqual(wideDetector.recordedKinds(), [.flowOpen, .flowSlice])
        XCTAssertNotNil(wideDetector.firstLineageID())
    }

    /// Verifies the persisted detector store round-trips durable detector summaries.
    func testDetectionStoreRoundTrip() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let fileURL = root.appendingPathComponent("detections.json", isDirectory: false)
        let event = DetectionEvent(
            id: "event-1",
            detectorIdentifier: "example-detector",
            signal: "example-signal",
            target: "example-target",
            timestamp: Date(timeIntervalSince1970: 20),
            confidence: 0.81,
            trigger: "burst",
            flowId: "flow-1",
            host: "api.example.com",
            classification: nil,
            bytes: 96 * 1_024,
            packetCount: 7,
            durationMs: 300,
            metadata: ["source": "example"]
        )
        let snapshot = DetectionSnapshot(
            updatedAt: event.timestamp,
            totalDetectionCount: 1,
            countsByDetector: ["example-detector": 1],
            countsByTarget: ["example-target": 1],
            recentEvents: [event]
        )
        let store = DetectionStore(fileURL: fileURL)

        try store.persist(snapshot)
        XCTAssertEqual(try store.load(), snapshot.redactedForPersistence())

        try store.clear()
        XCTAssertNil(try store.load())
    }

    /// Verifies typed detector fire metadata survives Codable round trips without stringly parsing `metadata`.
    func testDetectionEventFireRecordRoundTrip() throws {
        let event = DetectionEvent(
            id: "event-1",
            detectorIdentifier: "packet-detector",
            signal: "swipe-cue",
            target: "example-target",
            timestamp: Date(timeIntervalSince1970: 20),
            confidence: 0.91,
            trigger: "packetCue",
            flowId: "flow-1",
            host: "media.example",
            classification: nil,
            bytes: 896,
            packetCount: 1,
            durationMs: nil,
            metadata: ["legacy": "kept"],
            fireRecord: DetectorFireRecord(
                detectorName: "packet-detector",
                configId: "config-v1",
                fireTime: Date(timeIntervalSince1970: 20),
                sourcePacketTime: Date(timeIntervalSince1970: 19.95),
                reason: "outbound-udp-length-rank",
                ownerKey: "endpoint:udp://203.0.113.40:443",
                role: "media-example-role",
                packetLength: 896,
                payloadLength: 868,
                flowId: "flow-1",
                lineageId: 42
            )
        )

        let data = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(DetectionEvent.self, from: data)

        XCTAssertEqual(decoded, event)
        XCTAssertEqual(decoded.fireRecord?.configId, "config-v1")
        XCTAssertEqual(decoded.fireRecord?.reason, "outbound-udp-length-rank")
        XCTAssertEqual(decoded.fireRecord?.sourcePacketTime, Date(timeIntervalSince1970: 19.95))
    }

    /// Verifies signature reload updates in-memory cache and matching behavior.
    func testSignatureClassifierReloadAndCache() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let path = root.appendingPathComponent("signatures.json", isDirectory: false)

        let payload = """
        {
          "version": 1,
          "updatedAt": "2026-03-04T00:00:00Z",
          "signatures": [
            { "label": "social", "domains": ["social.example"] }
          ]
        }
        """
        try payload.data(using: .utf8)?.write(to: path)

        let classifier = SignatureClassifier(logger: StructuredLogger(sink: InMemoryLogSink()))
        try await classifier.load(from: path)
        let classification = await classifier.classify(host: "cdn.social.example")
        XCTAssertEqual(classification, "social")
        let trailingDotClassification = await classifier.classify(host: "cdn.social.example.")
        XCTAssertEqual(trailingDotClassification, "social")
        let boundaryMiss = await classifier.classify(host: "evilsocial.example")
        XCTAssertNil(boundaryMiss)
    }

    /// Verifies burst detection emits a completed burst when a flow experiences a large timing gap.
    func testBurstTrackingAcrossPacketTimingGaps() async {
        let burst = BurstTracker(thresholdMs: 50)

        let flow = FlowKey(src: "a", dst: "b", proto: "tcp")
        let now = Date(timeIntervalSince1970: 0)
        _ = burst.recordPacket(flow: flow, now: now)
        _ = burst.recordPacket(flow: flow, now: now.addingTimeInterval(0.02))
        let ended = burst.recordPacket(flow: flow, now: now.addingTimeInterval(0.2))
        XCTAssertNotNil(ended)
    }

    /// Verifies burst tracking does not retain unbounded idle or oldest flow state.
    func testBurstTrackerEvictsExpiredAndOldFlows() async {
        let tracker = BurstTracker(thresholdMs: 50, maxTrackedFlows: 2, flowTTLSeconds: 1)
        let base = Date(timeIntervalSince1970: 0)
        let flowA = FlowKey(src: "a", dst: "b", proto: "tcp")
        let flowB = FlowKey(src: "c", dst: "d", proto: "tcp")
        let flowC = FlowKey(src: "e", dst: "f", proto: "udp")

        _ = tracker.recordPacket(flow: flowA, now: base)
        _ = tracker.recordPacket(flow: flowB, now: base.addingTimeInterval(0.1))
        let trackedAfterTwoFlows = tracker.trackedFlowCount()
        XCTAssertEqual(trackedAfterTwoFlows, 2)

        _ = tracker.recordPacket(flow: flowC, now: base.addingTimeInterval(0.2))
        let trackedAfterOverflow = tracker.trackedFlowCount()
        XCTAssertEqual(trackedAfterOverflow, 2)

        _ = tracker.recordPacket(flow: flowA, now: base.addingTimeInterval(2.0))
        let trackedAfterExpiry = tracker.trackedFlowCount()
        XCTAssertEqual(trackedAfterExpiry, 1)
    }

    private final class TestDetector: TrafficDetector {
        let identifier = "test-detector"
        private var hasEmitted = false

        func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent] {
            guard !hasEmitted, let record = records.first else {
                return []
            }
            hasEmitted = true
            return [
                DetectionEvent(
                    id: "test-event",
                    detectorIdentifier: identifier,
                    signal: "test-signal",
                    target: "test-target",
                    timestamp: record.timestamp,
                    confidence: 0.9,
                    trigger: record.kind.rawValue,
                    flowId: "flow-1",
                    host: nil,
                    classification: nil,
                    bytes: record.bytes,
                    packetCount: record.packetCount,
                    durationMs: record.burstDurationMs
                )
            ]
        }

        func reset() {
            hasEmitted = false
        }
    }

    private final class RecordingDetector: TrafficDetector {
        let identifier = "recording-detector"
        private let lock = NSLock()
        private var kinds: [PacketSampleKind] = []

        func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent] {
            lock.lock()
            kinds.append(contentsOf: records.map(\.kind))
            lock.unlock()
            return []
        }

        func reset() {
            lock.lock()
            kinds.removeAll(keepingCapacity: false)
            lock.unlock()
        }

        func recordedKinds() -> [PacketSampleKind] {
            lock.lock()
            defer { lock.unlock() }
            return kinds
        }
    }

    private final class ProjectionRecordingDetector: TrafficDetector {
        let identifier: String
        let requirements: DetectorRequirements

        private let lock = NSLock()
        private var kinds: [PacketSampleKind] = []
        private var lineageIDs: [UInt64] = []
        private var sessionIDs: [String] = []

        init(identifier: String, requirements: DetectorRequirements) {
            self.identifier = identifier
            self.requirements = requirements
        }

        func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent] {
            lock.lock()
            kinds.append(contentsOf: records.map(\.kind))
            lineageIDs.append(contentsOf: records.compactMap(\.lineageID))
            sessionIDs.append(contentsOf: records.compactMap(\.sessionId))
            lock.unlock()
            return []
        }

        func reset() {
            lock.lock()
            kinds.removeAll(keepingCapacity: false)
            lineageIDs.removeAll(keepingCapacity: false)
            sessionIDs.removeAll(keepingCapacity: false)
            lock.unlock()
        }

        func recordedKinds() -> [PacketSampleKind] {
            lock.lock()
            defer { lock.unlock() }
            return kinds
        }

        func firstLineageID() -> UInt64? {
            lock.lock()
            defer { lock.unlock() }
            return lineageIDs.first
        }

        func firstSessionID() -> String? {
            lock.lock()
            defer { lock.unlock() }
            return sessionIDs.first
        }
    }

    /// Verifies persisted provider stop records map to stable user-facing summaries.
    func testTunnelStopRecordSummaryMapping() {
        let userStop = TunnelStopRecord(timestamp: Date(timeIntervalSince1970: 0), reasonCode: 1, reasonName: "userInitiated")
        let failureStop = TunnelStopRecord(timestamp: Date(timeIntervalSince1970: 0), reasonCode: 14, reasonName: "connectionFailed")

        XCTAssertEqual(userStop.summary, "Stopped by user")
        XCTAssertEqual(failureStop.summary, "Stopped because the connection failed")
        XCTAssertTrue(userStop.isUserInitiated)
        XCTAssertFalse(failureStop.isUserInitiated)
    }

    /// Verifies the app/provider codec supports an explicit telemetry drain command.
    func testTunnelTelemetryCodecRoundTripsFlushCommand() throws {
        let requestData = try TunnelTelemetryMessageCodec.encodeRequest(.flush)
        let request = try TunnelTelemetryMessageCodec.decodeRequest(requestData)
        XCTAssertEqual(request.command, .flush)

        let responseData = try TunnelTelemetryMessageCodec.encodeResponse(.flushed)
        let response = try TunnelTelemetryMessageCodec.decodeResponse(responseData)
        XCTAssertEqual(response.kind, .flushed)
    }

    /// Verifies the app/provider codec rejects explicit schema-version mismatches cleanly.
    func testTunnelTelemetryCodecRejectsUnsupportedVersion() throws {
        let requestData = #"{"version":99,"command":"snapshot","packetLimit":null}"#.data(using: .utf8)!

        XCTAssertThrowsError(try TunnelTelemetryMessageCodec.decodeRequest(requestData)) { error in
            XCTAssertEqual(error as? TunnelTelemetryMessageCodec.Error, .unsupportedVersion(99))
        }
    }

    /// Verifies newer host code tolerates older snapshot payloads that predate validation records.
    func testTunnelTelemetrySnapshotDecodesWithoutValidationFields() throws {
        let payload = """
        {
          "version": 1,
          "kind": "snapshot",
          "snapshot": {
            "samples": [],
            "retainedSampleCount": 0,
            "retainedBytes": 0,
            "oldestSampleAt": null,
            "latestSampleAt": null,
            "acceptedBatches": 0,
            "queuedBatches": 0,
            "queuedBytes": 0,
            "droppedBatches": 0,
            "skippedBatches": 0,
            "bufferedRecords": 0,
            "thermalState": "nominal",
            "lowPowerModeEnabled": false,
            "detections": {
              "updatedAt": null,
              "totalDetectionCount": 0,
              "countsByDetector": {},
              "countsByTarget": {},
              "recentEvents": []
            }
          },
          "message": null
        }
        """.data(using: .utf8)!

        let response = try TunnelTelemetryMessageCodec.decodeResponse(payload)
        let snapshot = try XCTUnwrap(response.snapshot)

        XCTAssertNil(snapshot.health)
        XCTAssertNil(snapshot.liveness)
        XCTAssertEqual(snapshot.validationRecords, [])
    }

    private func estimatedRecordSize(_ sample: PacketSample) -> Int {
        PacketSampleStream.estimatedRecordSize(for: sample)
    }

    private func makePacketStreamRecord(
        kind: PacketSampleKind,
        timestamp: Date,
        flowHash: UInt64,
        registrableDomain: String?,
        tlsServerName: String?,
        bytes: Int,
        packetCount: Int,
        direction: PacketDirection = .outbound,
        protocolHint: String = "udp",
        transportProtocolNumber: UInt8 = 17,
        sourceAddress: String? = nil,
        sourcePort: UInt16 = 50_000,
        destinationAddress: String? = nil,
        destinationPort: UInt16 = 443,
        closeReason: FlowCloseReason? = nil,
        largePacketCount: Int? = nil,
        smallPacketCount: Int? = nil,
        udpPacketCount: Int? = nil,
        tcpPacketCount: Int? = nil,
        quicInitialCount: Int? = nil,
        tcpSynCount: Int? = nil,
        tcpFinCount: Int? = nil,
        tcpRstCount: Int? = nil,
        burstDurationMs: Int? = nil,
        burstPacketCount: Int? = nil,
        leadingBytes200ms: Int? = nil,
        leadingPackets200ms: Int? = nil,
        leadingBytes600ms: Int? = nil,
        leadingPackets600ms: Int? = nil,
        burstLargePacketCount: Int? = nil,
        burstUdpPacketCount: Int? = nil,
        burstTcpPacketCount: Int? = nil,
        burstQuicInitialCount: Int? = nil,
        associatedDomain: String? = nil,
        associationSource: DetectorAssociationSource? = nil,
        associationAgeMs: Int? = nil,
        associationConfidence: Double? = nil,
        lineageID: UInt64? = nil,
        lineageGeneration: Int? = nil,
        lineageAgeMs: Int? = nil,
        lineageReuseGapMs: Int? = nil,
        lineageReopenCount: Int? = nil,
        lineageSiblingCount: Int? = nil,
        pathEpoch: UInt32? = nil,
        pathInterfaceClass: PathInterfaceClass? = nil,
        pathIsExpensive: Bool? = nil,
        pathIsConstrained: Bool? = nil,
        pathSupportsDNS: Bool? = nil,
        pathChangedRecently: Bool? = nil,
        serviceFamily: String? = nil,
        serviceFamilyConfidence: Double? = nil,
        serviceAttributionSourceMask: UInt16? = nil,
        sessionContext: DetectorSessionContext? = nil,
        role: String? = nil,
        addressScopeFamily: String? = nil,
        addressScopeSource: AddressScopeSource? = nil,
        addressScopeConfidence: Double? = nil,
        sourceAppIdentifier: String? = nil,
        sourceAppUniqueIdentifierHash: String? = nil,
        sourceAppVersion: String? = nil,
        attributionFlowId: String? = nil,
        attributionSource: SourceAppAttributionSource? = nil,
        attributionObservedAtMs: Double? = nil,
        localEndpoint: String? = nil,
        remoteEndpoint: String? = nil,
        remoteHostname: String? = nil
    ) -> PacketSampleStream.PacketStreamRecord {
        PacketSampleStream.PacketStreamRecord(
            kind: kind,
            timestamp: timestamp,
            direction: direction.rawValue,
            bytes: bytes,
            packetCount: packetCount,
            flowPacketCount: packetCount,
            flowByteCount: bytes,
            protocolHint: protocolHint,
            ipVersion: 4,
            transportProtocolNumber: transportProtocolNumber,
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            flowHash: flowHash,
            textFlowId: nil,
            sourceAddressLength: nil,
            sourceAddressHigh: nil,
            sourceAddressLow: nil,
            destinationAddressLength: nil,
            destinationAddressHigh: nil,
            destinationAddressLow: nil,
            textSourceAddress: sourceAddress,
            textDestinationAddress: destinationAddress,
            registrableDomain: registrableDomain,
            dnsQueryName: nil,
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            tlsServerName: tlsServerName,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            classification: nil,
            closeReason: closeReason,
            largePacketCount: largePacketCount,
            smallPacketCount: smallPacketCount,
            udpPacketCount: udpPacketCount,
            tcpPacketCount: tcpPacketCount,
            quicInitialCount: quicInitialCount,
            tcpSynCount: tcpSynCount,
            tcpFinCount: tcpFinCount,
            tcpRstCount: tcpRstCount,
            burstDurationMs: burstDurationMs,
            burstPacketCount: burstPacketCount,
            leadingBytes200ms: leadingBytes200ms,
            leadingPackets200ms: leadingPackets200ms,
            leadingBytes600ms: leadingBytes600ms,
            leadingPackets600ms: leadingPackets600ms,
            burstLargePacketCount: burstLargePacketCount,
            burstUdpPacketCount: burstUdpPacketCount,
            burstTcpPacketCount: burstTcpPacketCount,
            burstQuicInitialCount: burstQuicInitialCount,
            associatedDomain: associatedDomain,
            associationSource: associationSource,
            associationAgeMs: associationAgeMs,
            associationConfidence: associationConfidence,
            lineageID: lineageID,
            lineageGeneration: lineageGeneration,
            lineageAgeMs: lineageAgeMs,
            lineageReuseGapMs: lineageReuseGapMs,
            lineageReopenCount: lineageReopenCount,
            lineageSiblingCount: lineageSiblingCount,
            pathEpoch: pathEpoch,
            pathInterfaceClass: pathInterfaceClass,
            pathIsExpensive: pathIsExpensive,
            pathIsConstrained: pathIsConstrained,
            pathSupportsDNS: pathSupportsDNS,
            pathChangedRecently: pathChangedRecently,
            serviceFamily: serviceFamily,
            serviceFamilyConfidence: serviceFamilyConfidence,
            serviceAttributionSourceMask: serviceAttributionSourceMask,
            sessionContext: sessionContext,
            remoteEndpoint: remoteEndpoint,
            role: role,
            addressScopeFamily: addressScopeFamily,
            addressScopeSource: addressScopeSource,
            addressScopeConfidence: addressScopeConfidence,
            sourceAppIdentifier: sourceAppIdentifier,
            sourceAppUniqueIdentifierHash: sourceAppUniqueIdentifierHash,
            sourceAppVersion: sourceAppVersion,
            attributionFlowId: attributionFlowId,
            attributionSource: attributionSource,
            attributionObservedAtMs: attributionObservedAtMs,
            localEndpoint: localEndpoint,
            remoteHostname: remoteHostname
        )
    }

    private func makeDetectorRecord(
        timestamp: Date,
        pathChangedRecently: Bool = false
    ) -> DetectorRecord {
        DetectorRecord(
            kind: .flowOpen,
            timestamp: timestamp,
            direction: PacketDirection.outbound.rawValue,
            bytes: 128,
            packetCount: 1,
            flowPacketCount: 1,
            flowByteCount: 128,
            protocolHint: "tcp",
            ipVersion: 4,
            transportProtocolNumber: 6,
            sourcePort: 50_000,
            destinationPort: 443,
            flowHash: 0xfeed_beef,
            textFlowId: nil,
            sourceAddress: nil,
            destinationAddress: nil,
            registrableDomain: nil,
            dnsQueryName: nil,
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            classification: nil,
            closeReason: nil,
            largePacketCount: nil,
            smallPacketCount: nil,
            udpPacketCount: nil,
            tcpPacketCount: nil,
            quicInitialCount: nil,
            tcpSynCount: nil,
            tcpFinCount: nil,
            tcpRstCount: nil,
            burstDurationMs: nil,
            burstPacketCount: nil,
            leadingBytes200ms: nil,
            leadingPackets200ms: nil,
            leadingBytes600ms: nil,
            leadingPackets600ms: nil,
            burstLargePacketCount: nil,
            burstUdpPacketCount: nil,
            burstTcpPacketCount: nil,
            burstQuicInitialCount: nil,
            pathChangedRecently: pathChangedRecently
        )
    }

    private func makeDNSResponsePayload(queryName: String, answerIPv4: [UInt8]) -> [UInt8] {
        var payload: [UInt8] = [
            0x12, 0x34,
            0x81, 0x80,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00
        ]

        for label in queryName.split(separator: ".") {
            payload.append(UInt8(label.count))
            payload.append(contentsOf: label.utf8)
        }
        payload.append(0x00)
        payload.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        payload.append(contentsOf: [
            0xc0, 0x0c,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3c,
            0x00, 0x04
        ])
        payload.append(contentsOf: answerIPv4)
        return payload
    }

    private func makeIPv4TCPPacket(
        sourceAddress: [UInt8],
        destinationAddress: [UInt8],
        sourcePort: UInt16,
        destinationPort: UInt16,
        tcpFlags: UInt8,
        payload: [UInt8]
    ) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 20 + 20 + payload.count)
        packet[0] = 0x45
        packet[2] = UInt8(packet.count >> 8)
        packet[3] = UInt8(packet.count & 0xff)
        packet[8] = 64
        packet[9] = 6
        packet[12..<16] = sourceAddress[0..<4]
        packet[16..<20] = destinationAddress[0..<4]

        let tcpOffset = 20
        packet[tcpOffset] = UInt8(sourcePort >> 8)
        packet[tcpOffset + 1] = UInt8(sourcePort & 0xff)
        packet[tcpOffset + 2] = UInt8(destinationPort >> 8)
        packet[tcpOffset + 3] = UInt8(destinationPort & 0xff)
        packet[tcpOffset + 12] = 0x50
        packet[tcpOffset + 13] = tcpFlags
        if !payload.isEmpty {
            packet[(tcpOffset + 20)...] = payload[0...]
        }
        return packet
    }

    private func makeIPv4UDPPacket(
        sourceAddress: [UInt8],
        destinationAddress: [UInt8],
        sourcePort: UInt16,
        destinationPort: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 20 + 8 + payload.count)
        packet[0] = 0x45
        packet[2] = UInt8(packet.count >> 8)
        packet[3] = UInt8(packet.count & 0xff)
        packet[8] = 64
        packet[9] = 17
        packet[12..<16] = sourceAddress[0..<4]
        packet[16..<20] = destinationAddress[0..<4]

        let udpOffset = 20
        let udpLength = 8 + payload.count
        packet[udpOffset] = UInt8(sourcePort >> 8)
        packet[udpOffset + 1] = UInt8(sourcePort & 0xff)
        packet[udpOffset + 2] = UInt8(destinationPort >> 8)
        packet[udpOffset + 3] = UInt8(destinationPort & 0xff)
        packet[udpOffset + 4] = UInt8(udpLength >> 8)
        packet[udpOffset + 5] = UInt8(udpLength & 0xff)
        if !payload.isEmpty {
            packet[(udpOffset + 8)...] = payload[0...]
        }
        return packet
    }
}
