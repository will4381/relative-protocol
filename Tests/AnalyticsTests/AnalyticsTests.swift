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
        let finPacket = Data(
            makeIPv4TCPPacket(
                sourceAddress: [10, 0, 0, 2],
                destinationAddress: [1, 1, 1, 1],
                sourcePort: 50_000,
                destinationPort: 443,
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
        let closed = await pipeline.ingest(packets: [finPacket], families: [], direction: .outbound, policy: policy)
        XCTAssertEqual(closed.map(\.kind), [.flowClose])

        let close = try XCTUnwrap(closed.first)
        XCTAssertEqual(close.closeReason, .tcpFin)
        XCTAssertEqual(close.packetCount, 1)
        XCTAssertEqual(close.tcpPacketCount, 1)
        XCTAssertEqual(close.tcpFinCount, 1)
        XCTAssertEqual(close.tcpSynCount, 0)
        XCTAssertEqual(close.flowPacketCount, 2)
        XCTAssertEqual(close.flowByteCount, dataPacket.count + finPacket.count)
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
        let snapshot = worker.snapshot()
        await worker.stopAndWait()

        XCTAssertFalse(result.accepted)
        XCTAssertTrue(result.skipped)
        XCTAssertEqual(snapshot.acceptedBatches, 0)
        XCTAssertEqual(snapshot.queuedBatches, 0)
        XCTAssertEqual(snapshot.skippedBatches, 1)
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

    /// Verifies persisted provider stop records map to stable user-facing summaries.
    func testTunnelStopRecordSummaryMapping() {
        let userStop = TunnelStopRecord(timestamp: Date(timeIntervalSince1970: 0), reasonCode: 1, reasonName: "userInitiated")
        let failureStop = TunnelStopRecord(timestamp: Date(timeIntervalSince1970: 0), reasonCode: 14, reasonName: "connectionFailed")

        XCTAssertEqual(userStop.summary, "Stopped by user")
        XCTAssertEqual(failureStop.summary, "Stopped because the connection failed")
        XCTAssertTrue(userStop.isUserInitiated)
        XCTAssertFalse(failureStop.isUserInitiated)
    }

    /// Verifies the app/provider codec rejects explicit schema-version mismatches cleanly.
    func testTunnelTelemetryCodecRejectsUnsupportedVersion() throws {
        let requestData = #"{"version":99,"command":"snapshot","packetLimit":null}"#.data(using: .utf8)!

        XCTAssertThrowsError(try TunnelTelemetryMessageCodec.decodeRequest(requestData)) { error in
            XCTAssertEqual(error as? TunnelTelemetryMessageCodec.Error, .unsupportedVersion(99))
        }
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
        burstQuicInitialCount: Int? = nil
    ) -> PacketSampleStream.PacketStreamRecord {
        PacketSampleStream.PacketStreamRecord(
            kind: kind,
            timestamp: timestamp,
            direction: PacketDirection.outbound.rawValue,
            bytes: bytes,
            packetCount: packetCount,
            flowPacketCount: packetCount,
            flowByteCount: bytes,
            protocolHint: "udp",
            ipVersion: 4,
            transportProtocolNumber: 17,
            sourcePort: 50_000,
            destinationPort: 443,
            flowHash: flowHash,
            textFlowId: nil,
            sourceAddressLength: nil,
            sourceAddressHigh: nil,
            sourceAddressLow: nil,
            destinationAddressLength: nil,
            destinationAddressHigh: nil,
            destinationAddressLow: nil,
            textSourceAddress: nil,
            textDestinationAddress: nil,
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
            burstQuicInitialCount: burstQuicInitialCount
        )
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
