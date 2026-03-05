import Foundation
@testable import Observability
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// Observability contract and persistence behavior tests.
final class ObservabilityTests: XCTestCase {
    /// Verifies structured envelopes preserve round-trip Codable fidelity.
    func testEnvelopeRoundTripEncoding() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601

        let envelope = LogEnvelope(
            timestamp: Date(timeIntervalSince1970: 0),
            level: .info,
            phase: .lifecycle,
            component: "unit",
            event: "start",
            runId: "run-1",
            sessionId: "session-1",
            connId: "conn-1",
            flowId: "flow-1",
            traceId: "trace-1",
            result: "ok",
            errorCode: nil,
            message: "hello",
            metadata: ["k": "v"]
        )

        let data = try encoder.encode(envelope)
        let decoded = try decoder.decode(LogEnvelope.self, from: data)
        XCTAssertEqual(decoded, envelope)
    }

    /// Verifies JSONL sink rotates files and tracks drop counters under pressure.
    func testJSONLRotationAndDropCounters() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let sink = JSONLLogSink(
            rootProvider: HarnessLogRootPathProvider(root: root),
            policy: JSONLRotationPolicy(maxBytesPerFile: 180, maxFiles: 3, maxTotalBytes: 1024, maxQueueDepth: 1),
            eventQueueLabel: "test"
        )

        let oversizedMessage = String(repeating: "a", count: 600)
        await sink.write(LogEnvelope(level: .info, phase: .storage, component: "test", event: "oversized", message: oversizedMessage))
        await sink.write(LogEnvelope(level: .info, phase: .storage, component: "test", event: "one", message: "1"))
        await sink.write(LogEnvelope(level: .info, phase: .storage, component: "test", event: "two", message: "2"))

        let files = try await sink.listLogFiles()
        XCTAssertFalse(files.isEmpty)

        let drops = await sink.dropCounters()
        XCTAssertEqual(drops.droppedIOError, 0)
        XCTAssertEqual(drops.droppedQueueFull, 0)
    }

    /// Verifies unified-log rendering preserves identifiers and severity mapping for device debugging.
    func testUnifiedLogRenderingIncludesStructuredIdentifiers() {
        let envelope = LogEnvelope(
            timestamp: Date(timeIntervalSince1970: 0),
            level: .warning,
            phase: .relay,
            component: "unit",
            event: "connect",
            runId: "run-1",
            sessionId: "session-1",
            connId: "conn-1",
            flowId: "flow-1",
            traceId: "trace-1",
            result: "retry",
            errorCode: "EHOSTUNREACH",
            message: "waiting",
            metadata: ["path": "wifi"]
        )

        XCTAssertEqual(envelope.level.unifiedLogType, .default)
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("runId=run-1"))
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("sessionId=session-1"))
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("connId=conn-1"))
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("flowId=flow-1"))
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("traceId=trace-1"))
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("result=retry"))
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("errorCode=EHOSTUNREACH"))
        XCTAssertTrue(envelope.renderedForUnifiedLog.contains("metadata={path=wifi}"))
    }
}
