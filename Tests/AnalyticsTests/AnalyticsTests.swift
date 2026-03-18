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
        burstDurationMs: Int? = nil,
        burstPacketCount: Int? = nil
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
            burstDurationMs: burstDurationMs,
            burstPacketCount: burstPacketCount
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
        packet[(tcpOffset + 20)...] = payload[0...]
        return packet
    }
}
