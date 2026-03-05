import Analytics
import Foundation
import Observability
import TunnelRuntime
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// Analytics bounds, classification, replay, and baseline contract tests.
final class AnalyticsTests: XCTestCase {
    /// Verifies ring buffer evicts oldest entry at capacity.
    func testMetricsRingBufferBounds() {
        var ring = MetricsRingBuffer<Int>(capacity: 3)
        ring.append(1)
        ring.append(2)
        ring.append(3)
        ring.append(4)
        XCTAssertEqual(ring.snapshot(), [2, 3, 4])
    }

    /// Verifies packet stream truncates to single latest entry when file size limit is exceeded.
    func testPacketStreamTruncatesWhenOverLimit() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = root.appendingPathComponent("packets.ndjson", isDirectory: false)
        let stream = PacketSampleStream(maxBytes: 120, url: url, logger: StructuredLogger(sink: InMemoryLogSink()))

        let sample = PacketSample(timestamp: Date(), direction: "out", flowId: "f1", bytes: 90, protocolHint: "tcp")
        try await stream.append(sample)
        try await stream.append(sample)

        let all = try await stream.readAll()
        XCTAssertEqual(all.count, 1)
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
        let sourcePath = await classifier.cachedSourcePath()
        XCTAssertEqual(classification, "social")
        XCTAssertEqual(sourcePath, path.path)
    }

    /// Verifies flow aggregation and burst detection across packet timing gaps.
    func testFlowAndBurstTracking() async {
        let tracker = FlowTracker(maxTrackedFlows: 2, flowTTLSeconds: 60)
        let burst = BurstTracker(thresholdMs: 50)

        let flow = FlowKey(src: "a", dst: "b", proto: "tcp")
        let now = Date(timeIntervalSince1970: 0)
        await tracker.record(flow: flow, bytes: 100, now: now)
        await tracker.record(flow: flow, bytes: 50, now: now.addingTimeInterval(1))

        let trackedBytes = await tracker.snapshot().first?.bytes
        XCTAssertEqual(trackedBytes, 150)

        _ = await burst.recordPacket(flow: flow, now: now)
        _ = await burst.recordPacket(flow: flow, now: now.addingTimeInterval(0.02))
        let ended = await burst.recordPacket(flow: flow, now: now.addingTimeInterval(0.2))
        XCTAssertNotNil(ended)
    }

    /// Verifies sampler cadence and deterministic clock integration.
    func testPathSamplerCadenceWithDeterministicClock() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let sampler = PathSampler(
            clock: clock,
            runIdGenerator: DeterministicRunIdGenerator(prefix: "sample", start: 0),
            randomSource: SeededRandomSource(seed: 1),
            cadenceSeconds: 1.0,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        try await sampler.run(iterations: 3) {
            ["status": "satisfied"]
        }
        let sampleCount = await sampler.snapshot().count
        XCTAssertEqual(sampleCount, 3)
    }

    /// Verifies runtime snapshot metrics use the injected clock instead of wall time.
    func testMetricsStorePublishUsesInjectedClock() async throws {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 1234))
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = MetricsStore(
            capacity: 8,
            maxBytes: 8_192,
            outputURL: root.appendingPathComponent("metrics.json", isDirectory: false),
            clock: clock,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        await store.publish(
            RuntimeSnapshot(
                state: .running,
                runId: "run-1",
                sessionId: "session-1",
                setupLatencyMs: 10,
                relayLatencyMs: 5,
                queueDepth: 3
            )
        )

        let records = await store.records()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].timestamp, Date(timeIntervalSince1970: 1234))
    }

    /// Verifies baseline JSON schema loading and tolerance evaluation logic.
    func testPerfBaselineSchemaAndEvaluation() throws {
        let url = Bundle.module.url(forResource: "PerfBaseline", withExtension: "json")
        XCTAssertNotNil(url)
        let baseline = try PerfBaseline.load(from: XCTUnwrap(url))

        XCTAssertEqual(baseline.baselineName, "clean-room-local-baseline-v1")
        XCTAssertFalse(baseline.metrics.isEmpty)

        let report = PerfBaselineEvaluator.evaluate(
            baseline: baseline,
            measured: [
                "setup_latency_ms": 150,
                "relay_latency_ms": 40,
                "throughput_kbps": 9000
            ],
            failMode: false
        )
        XCTAssertFalse(report.warnings.isEmpty)
        XCTAssertTrue(report.failures.isEmpty)
    }

    /// Verifies memory metric performance harness executes without failures.
    func testPerformanceMemoryMetric() {
        var ring = MetricsRingBuffer<Int>(capacity: 5000)
        // Docs: https://developer.apple.com/documentation/xctest/xctestcase/measure(metrics:options:block:)
        // Docs: https://developer.apple.com/documentation/xctest/xctmemorymetric
        measure(metrics: [XCTMemoryMetric()]) {
            for index in 0..<10_000 {
                ring.append(index)
            }
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
}
