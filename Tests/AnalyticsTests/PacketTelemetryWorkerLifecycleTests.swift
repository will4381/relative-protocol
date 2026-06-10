@testable import Analytics
import Foundation
import Observability
import TunnelRuntime
import XCTest

/// Lifecycle coverage for worker-owned system resources.
/// Regression target: the path-regime `NWPathMonitor` must be cancelled when the worker is stopped through
/// the command channel, not only when the worker object is eventually deallocated.
final class PacketTelemetryWorkerLifecycleTests: XCTestCase {
    private final class RecordingPathRegimeProvider: PathRegimeProvider, @unchecked Sendable {
        private let lock = NSLock()
        private var stopCallCount = 0

        var currentSnapshot: PathRegimeSnapshot {
            .unavailable
        }

        func stop() {
            lock.lock()
            stopCallCount += 1
            lock.unlock()
        }

        var stopCount: Int {
            lock.lock()
            defer { lock.unlock() }
            return stopCallCount
        }
    }

    private final class PathRegimeRequiringDetector: TrafficDetector {
        let identifier = "path-regime-lifecycle"
        let requirements = DetectorRequirements(
            recordKinds: [.flowOpen],
            featureFamilies: [.pathRegime]
        )

        func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent] {
            []
        }

        func reset() {}
    }

    private func makeWorker(pathRegimeProvider: RecordingPathRegimeProvider) -> PacketTelemetryWorker {
        let logger = StructuredLogger(sink: InMemoryLogSink())
        let pipeline = PacketAnalyticsPipeline(
            clock: SystemClock(),
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: SignatureClassifier(logger: logger)
        )
        return PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: nil,
            detectors: [PathRegimeRequiringDetector()],
            initialDetectionSnapshot: .empty,
            detectionStore: nil,
            logger: logger,
            processInfo: .processInfo,
            emissionPolicyOverride: nil,
            pathRegimeProvider: pathRegimeProvider,
            includeFlowSlicesInLiveTap: false
        )
    }

    func testStopAndWaitStopsPathRegimeProvider() async {
        let provider = RecordingPathRegimeProvider()
        let worker = makeWorker(pathRegimeProvider: provider)

        XCTAssertEqual(provider.stopCount, 0)
        await worker.stopAndWait()
        XCTAssertGreaterThanOrEqual(provider.stopCount, 1)
    }

    func testRepeatedStopAndWaitDoesNotHang() async {
        let provider = RecordingPathRegimeProvider()
        let worker = makeWorker(pathRegimeProvider: provider)

        await worker.stopAndWait()
        await worker.stopAndWait()
        XCTAssertGreaterThanOrEqual(provider.stopCount, 1)
    }

    func testSubmitAfterStopIsRejectedWithoutCrash() async {
        let provider = RecordingPathRegimeProvider()
        let worker = makeWorker(pathRegimeProvider: provider)
        await worker.stopAndWait()

        let result = worker.submit(
            packets: [Data([0x45, 0x00])],
            families: [2],
            direction: .outbound
        )
        XCTAssertFalse(result.accepted)
    }
}
