import Foundation
import Observability
import TunnelRuntime

/// Long-lived packet telemetry worker that serializes flow enrichment and optionally updates one rolling in-memory tap.
/// Decision: one worker task is cheaper than spawning a `Task` for every packet batch on the provider hot path.
public final class PacketTelemetryWorker: @unchecked Sendable {
    private enum QueuePolicy {
        static let maxQueuedBatches = 2
        static let maxQueuedBytes = 256 * 1024
    }

    private enum DetailPolicy {
        static let maxBufferedRecords = 128
        static let maxSnapshotPacketLimit = 96
    }

    private struct LiveTapPolicy: Sendable {
        let includeActivitySamples: Bool
        let includeFlowSlices: Bool
        let includeFlowCloseEvents: Bool

        /// Decision: the default app-facing live tap stays leaner than the detector-facing sparse stream.
        /// `flowSlice` remains detector-only by default because pushing every cadence record into the
        /// foreground snapshot would raise snapshot volume and debugging overhead without improving
        /// durable detector correctness.
        static let `default` = LiveTapPolicy(
            includeActivitySamples: true,
            includeFlowSlices: false,
            includeFlowCloseEvents: true
        )

        static func configured(includeFlowSlices: Bool) -> LiveTapPolicy {
            LiveTapPolicy(
                includeActivitySamples: true,
                includeFlowSlices: includeFlowSlices,
                includeFlowCloseEvents: true
            )
        }
    }

    private enum DetectionPolicy {
        static let maxRecentEvents = 96
    }

    private final class CommandSignal: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?

        init(_ continuation: CheckedContinuation<Void, Never>) {
            self.continuation = continuation
        }

        func resume() {
            lock.lock()
            let continuation = self.continuation
            self.continuation = nil
            lock.unlock()
            continuation?.resume()
        }
    }

    private enum CaptureControlError: LocalizedError, Sendable, Equatable {
        case unavailable
        case invalidSessionID
        case captureAlreadyActive(String)
        case noActiveCapture
        case sessionMismatch(expected: String, got: String)

        var errorDescription: String? {
            switch self {
            case .unavailable:
                return "Telemetry capture is unavailable for this worker."
            case .invalidSessionID:
                return "Telemetry capture requires a non-empty session id."
            case .captureAlreadyActive(let sessionID):
                return "Telemetry capture is already active for session \(sessionID)."
            case .noActiveCapture:
                return "No telemetry capture session is active."
            case .sessionMismatch(let expected, let got):
                return "Telemetry capture session mismatch. Expected \(expected), got \(got)."
            }
        }
    }

    private final class CaptureInfoSignal: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Result<TelemetryCaptureInfo, CaptureControlError>, Never>?

        init(_ continuation: CheckedContinuation<Result<TelemetryCaptureInfo, CaptureControlError>, Never>) {
            self.continuation = continuation
        }

        func resume(_ result: Result<TelemetryCaptureInfo, CaptureControlError>) {
            lock.lock()
            let continuation = self.continuation
            self.continuation = nil
            lock.unlock()
            continuation?.resume(returning: result)
        }
    }

    private actor DetectionPersistenceCoordinator {
        private static let coalescingDelay: Duration = .milliseconds(250)

        private let store: DetectionStore
        private let logger: StructuredLogger
        private var pendingSnapshot: DetectionSnapshot?
        private var persistenceTask: Task<Void, Never>?

        init(store: DetectionStore, logger: StructuredLogger) {
            self.store = store
            self.logger = logger
        }

        func schedule(_ snapshot: DetectionSnapshot) {
            pendingSnapshot = snapshot
            guard persistenceTask == nil else {
                return
            }

            persistenceTask = Task(priority: .utility) {
                await self.runLoop()
            }
        }

        func persistNow(_ snapshot: DetectionSnapshot) async {
            persistenceTask?.cancel()
            persistenceTask = nil
            pendingSnapshot = nil
            await persist(snapshot)
        }

        func flush() async {
            let snapshot = pendingSnapshot
            persistenceTask?.cancel()
            persistenceTask = nil
            pendingSnapshot = nil
            if let snapshot {
                await persist(snapshot)
            }
        }

        private func runLoop() async {
            while !Task.isCancelled {
                try? await Task.sleep(for: Self.coalescingDelay)
                guard let snapshot = pendingSnapshot else {
                    persistenceTask = nil
                    return
                }

                pendingSnapshot = nil
                await persist(snapshot)
            }
            persistenceTask = nil
        }

        private func persist(_ snapshot: DetectionSnapshot) async {
            do {
                try store.persist(snapshot)
            } catch {
                await logger.log(
                    level: .warning,
                    phase: .storage,
                    category: .control,
                    component: "PacketTelemetryWorker",
                    event: "detection-persist-failed",
                    errorCode: String(describing: error),
                    message: "Failed to persist detector outputs"
                )
            }
        }
    }

    private struct Batch: Sendable {
        let packets: [Data]
        let families: [Int32]
        let summaries: [FastPacketSummary]
        let direction: PacketDirection
        let byteCount: Int
    }

    private final class SharedState: @unchecked Sendable {
        let lock = NSLock()
        var continuation: AsyncStream<Command>.Continuation?
        var acceptedBatches = 0
        var queuedBatches = 0
        var queuedBytes = 0
        var droppedBatches = 0
        var skippedBatches = 0
        var bufferedRecords = 0
        var detectionSnapshot: DetectionSnapshot
        var hasEnteredShedMode = false
        var isStopped = false

        init(initialDetectionSnapshot: DetectionSnapshot) {
            detectionSnapshot = initialDetectionSnapshot
        }

        func withLock<T>(_ body: (SharedState) -> T) -> T {
            lock.lock()
            defer { lock.unlock() }
            return body(self)
        }
    }

    private enum Command: Sendable {
        case batch(Batch)
        case reset(CommandSignal?)
        case clearDetections(CommandSignal?)
        case barrier(CommandSignal?)
        case beginCapture(String, CaptureInfoSignal?)
        case flushCapture(String, CaptureInfoSignal?)
        case endCapture(String, CaptureInfoSignal?)
        case latestCaptureInfo(CaptureInfoSignal?)
        case stop(CommandSignal?)
    }

    public struct SubmitResult: Sendable {
        public let accepted: Bool
        public let skipped: Bool
        public let shouldLogSheddingStart: Bool
        public let queuedBatches: Int
        public let queuedBytes: Int
        public let droppedBatches: Int
    }

    public struct Snapshot: Sendable {
        public let acceptedBatches: Int
        public let queuedBatches: Int
        public let queuedBytes: Int
        public let droppedBatches: Int
        public let skippedBatches: Int
        public let bufferedRecords: Int
        public let thermalState: ProcessInfo.ThermalState
        public let lowPowerModeEnabled: Bool
    }

    private let pipeline: PacketAnalyticsPipeline
    private let packetStream: PacketSampleStream?
    private let detectors: [any TrafficDetector]
    private let detectionPersistence: DetectionPersistenceCoordinator?
    private let logger: StructuredLogger
    private let processInfo: ProcessInfo
    private let state: SharedState
    private let emissionPolicyOverride: PacketAnalyticsPipeline.EmissionPolicy?
    private let runtimePlan: DetectorRuntimePlan
    private let pathRegimeProvider: (any PathRegimeProvider)?
    private let liveTapPolicy: LiveTapPolicy
    private let captureSink: TelemetryCaptureSink?

    private var workerTask: Task<Void, Never>?

    /// Creates a telemetry worker around one analytics pipeline, an optional rolling packet tap, and zero or more detectors.
    /// Docs: https://developer.apple.com/documentation/foundation/processinfo/thermalstate
    /// Docs: https://developer.apple.com/documentation/foundation/processinfo/islowpowermodeenabled
    /// The worker evaluates thermal and power state at batch boundaries so the tunnel can reduce telemetry cost
    /// without paying for per-packet notification handling.
    public convenience init(
        pipeline: PacketAnalyticsPipeline,
        packetStream: PacketSampleStream? = nil,
        detectors: [any TrafficDetector] = [],
        initialDetectionSnapshot: DetectionSnapshot = .empty,
        detectionStore: DetectionStore? = nil,
        captureRootURL: URL? = nil,
        logger: StructuredLogger,
        processInfo: ProcessInfo = .processInfo,
        includeFlowSlicesInLiveTap: Bool = false
    ) {
        self.init(
            pipeline: pipeline,
            packetStream: packetStream,
            detectors: detectors,
            initialDetectionSnapshot: initialDetectionSnapshot,
            detectionStore: detectionStore,
            captureRootURL: captureRootURL,
            logger: logger,
            processInfo: processInfo,
            emissionPolicyOverride: nil,
            pathRegimeProvider: nil,
            includeFlowSlicesInLiveTap: includeFlowSlicesInLiveTap
        )
    }

    init(
        pipeline: PacketAnalyticsPipeline,
        packetStream: PacketSampleStream? = nil,
        detectors: [any TrafficDetector] = [],
        initialDetectionSnapshot: DetectionSnapshot = .empty,
        detectionStore: DetectionStore? = nil,
        captureRootURL: URL? = nil,
        logger: StructuredLogger,
        processInfo: ProcessInfo = .processInfo,
        emissionPolicyOverride: PacketAnalyticsPipeline.EmissionPolicy?,
        pathRegimeProvider: (any PathRegimeProvider)? = nil,
        includeFlowSlicesInLiveTap: Bool = false
    ) {
        self.pipeline = pipeline
        self.packetStream = packetStream
        self.detectors = detectors
        self.runtimePlan = DetectorRuntimePlan(detectors: detectors, liveTapEnabled: packetStream != nil)
        if let detectionStore {
            self.detectionPersistence = DetectionPersistenceCoordinator(store: detectionStore, logger: logger)
        } else {
            self.detectionPersistence = nil
        }
        self.captureSink = captureRootURL.map { TelemetryCaptureSink(analyticsRootURL: $0, logger: logger) }
        self.logger = logger
        self.processInfo = processInfo
        self.state = SharedState(initialDetectionSnapshot: initialDetectionSnapshot)
        self.emissionPolicyOverride = emissionPolicyOverride
        self.liveTapPolicy = .configured(includeFlowSlices: includeFlowSlicesInLiveTap)
        if self.runtimePlan.needsPathRegime || self.captureSink != nil {
            self.pathRegimeProvider = pathRegimeProvider ?? NWPathRegimeMonitor()
        } else {
            self.pathRegimeProvider = nil
        }

        var streamContinuation: AsyncStream<Command>.Continuation?
        let stream = AsyncStream<Command> { continuation in
            streamContinuation = continuation
        }
        state.withLock { state in
            state.continuation = streamContinuation
        }

        let pipeline = self.pipeline
        let packetStream = self.packetStream
        let detectors = self.detectors
        let detectionPersistence = self.detectionPersistence
        let logger = self.logger
        let processInfo = self.processInfo
        let state = self.state
        let emissionPolicyOverride = self.emissionPolicyOverride
        let runtimePlan = self.runtimePlan
        let pathRegimeProvider = self.pathRegimeProvider
        let liveTapPolicy = self.liveTapPolicy
        let captureSink = self.captureSink

        self.workerTask = Task { [state, pipeline, packetStream, detectors, detectionPersistence, logger, processInfo, emissionPolicyOverride, runtimePlan, pathRegimeProvider, liveTapPolicy, captureSink] in
            await Self.runLoop(
                stream: stream,
                state: state,
                pipeline: pipeline,
                packetStream: packetStream,
                detectors: detectors,
                detectionPersistence: detectionPersistence,
                captureSink: captureSink,
                logger: logger,
                processInfo: processInfo,
                emissionPolicyOverride: emissionPolicyOverride,
                runtimePlan: runtimePlan,
                pathRegimeProvider: pathRegimeProvider,
                liveTapPolicy: liveTapPolicy
            )
        }
    }

    deinit {
        pathRegimeProvider?.stop()
        let continuation: AsyncStream<Command>.Continuation? = state.withLock { state in
            state.isStopped = true
            let continuation = state.continuation
            state.continuation = nil
            return continuation
        }
        // Decision: deinit closes intake and lets already-queued work drain asynchronously, but callers that need
        // final persistence guarantees must still use `stopAndWait()`.
        continuation?.finish()
    }

    /// Enqueues one raw packet batch for telemetry processing.
    /// Decision: the worker performs one cheap, synchronous packet-summary pass here so batches that contain only
    /// uninteresting traffic (for example, pure TCP ACKs) never enter the async telemetry pipeline at all. The worker
    /// also does a cheap queue-state admission check before parsing so shed mode avoids unnecessary hot-thread work.
    /// Queue byte admission happens after prefiltering so dropped-batch accounting reflects post-filter telemetry cost.
    public func submit(packets: [Data], families: [Int32], direction: PacketDirection) -> SubmitResult {
        let initialDecision: SubmitResult? = state.withLock { state in
            guard !state.isStopped else {
                return SubmitResult(
                    accepted: false,
                    skipped: false,
                    shouldLogSheddingStart: false,
                    queuedBatches: state.queuedBatches,
                    queuedBytes: state.queuedBytes,
                    droppedBatches: state.droppedBatches
                )
            }
            if state.queuedBatches >= QueuePolicy.maxQueuedBatches {
                state.droppedBatches += 1
                let shouldLogSheddingStart = !state.hasEnteredShedMode
                state.hasEnteredShedMode = true
                return SubmitResult(
                    accepted: false,
                    skipped: false,
                    shouldLogSheddingStart: shouldLogSheddingStart,
                    queuedBatches: state.queuedBatches,
                    queuedBytes: state.queuedBytes,
                    droppedBatches: state.droppedBatches
                )
            }
            return nil
        }
        if let initialDecision {
            return initialDecision
        }

        let filtered = Self.prefilter(packets: packets, families: families)

        return state.withLock { state in
            guard !state.isStopped else {
                return SubmitResult(
                    accepted: false,
                    skipped: false,
                    shouldLogSheddingStart: false,
                    queuedBatches: state.queuedBatches,
                    queuedBytes: state.queuedBytes,
                    droppedBatches: state.droppedBatches
                )
            }

            guard !filtered.packets.isEmpty else {
                state.skippedBatches += 1
                return SubmitResult(
                    accepted: false,
                    skipped: true,
                    shouldLogSheddingStart: false,
                    queuedBatches: state.queuedBatches,
                    queuedBytes: state.queuedBytes,
                    droppedBatches: state.droppedBatches
                )
            }

            let nextQueuedBatches = state.queuedBatches + 1
            let nextQueuedBytes = state.queuedBytes + filtered.byteCount
            if nextQueuedBatches > QueuePolicy.maxQueuedBatches || nextQueuedBytes > QueuePolicy.maxQueuedBytes {
                state.droppedBatches += 1
                let shouldLogSheddingStart = !state.hasEnteredShedMode
                state.hasEnteredShedMode = true
                return SubmitResult(
                    accepted: false,
                    skipped: false,
                    shouldLogSheddingStart: shouldLogSheddingStart,
                    queuedBatches: state.queuedBatches,
                    queuedBytes: state.queuedBytes,
                    droppedBatches: state.droppedBatches
                )
            }

            state.queuedBatches = nextQueuedBatches
            state.queuedBytes = nextQueuedBytes
            state.acceptedBatches += 1
            state.continuation?.yield(
                .batch(
                    Batch(
                        packets: filtered.packets,
                        families: filtered.families,
                        summaries: filtered.summaries,
                        direction: direction,
                        byteCount: filtered.byteCount
                    )
                )
            )

            return SubmitResult(
                accepted: true,
                skipped: false,
                shouldLogSheddingStart: false,
                queuedBatches: state.queuedBatches,
                queuedBytes: state.queuedBytes,
                droppedBatches: state.droppedBatches
            )
        }
    }

    /// Returns a cheap synchronous telemetry snapshot for health sampling.
    public func snapshot() -> Snapshot {
        state.withLock { state in
            Snapshot(
                acceptedBatches: state.acceptedBatches,
                queuedBatches: state.queuedBatches,
                queuedBytes: state.queuedBytes,
                droppedBatches: state.droppedBatches,
                skippedBatches: state.skippedBatches,
                bufferedRecords: state.bufferedRecords,
                thermalState: processInfo.thermalState,
                lowPowerModeEnabled: processInfo.isLowPowerModeEnabled
            )
        }
    }

    /// Returns the latest rolling packet snapshot for the containing app.
    public func recentSnapshot(limit: Int?) async -> TunnelTelemetrySnapshot {
        let normalizedLimit = min(max(limit ?? DetailPolicy.maxSnapshotPacketLimit, 0), DetailPolicy.maxSnapshotPacketLimit)
        let streamSnapshot = if let packetStream {
            await packetStream.snapshot(limit: normalizedLimit)
        } else {
            PacketSampleStream.Snapshot(
                samples: [],
                retainedSampleCount: 0,
                retainedBytes: 0,
                oldestSampleAt: nil,
                latestSampleAt: nil
            )
        }
        let state = snapshot()
        let detections = Self.currentDetectionSnapshot(state: self.state)
        return TunnelTelemetrySnapshot(
            samples: streamSnapshot.samples,
            retainedSampleCount: streamSnapshot.retainedSampleCount,
            retainedBytes: streamSnapshot.retainedBytes,
            oldestSampleAt: streamSnapshot.oldestSampleAt,
            latestSampleAt: streamSnapshot.latestSampleAt,
            acceptedBatches: state.acceptedBatches,
            queuedBatches: state.queuedBatches,
            queuedBytes: state.queuedBytes,
            droppedBatches: state.droppedBatches,
            skippedBatches: state.skippedBatches,
            bufferedRecords: state.bufferedRecords,
            thermalState: TunnelThermalState(thermalState: state.thermalState),
            lowPowerModeEnabled: state.lowPowerModeEnabled,
            detections: detections
        )
    }

    /// Clears the in-memory rolling window used for app snapshots.
    public func clearRecentEvents() {
        enqueue(.reset(nil))
    }

    /// Clears the in-memory rolling window and waits until the worker has applied the reset.
    public func clearRecentEventsAndWait() async {
        await enqueueAndWait { .reset($0) }
    }

    /// Clears persisted detector counts and recent detector events.
    public func clearDetections() {
        enqueue(.clearDetections(nil))
    }

    /// Clears persisted detector counts and waits until the worker has applied the reset.
    public func clearDetectionsAndWait() async {
        await enqueueAndWait { .clearDetections($0) }
    }

    /// Waits until all previously enqueued telemetry work has been processed.
    func flushAndWait() async {
        await enqueueAndWait { .barrier($0) }
    }

    /// Starts a session-scoped telemetry capture ordered against the worker's packet-batch queue.
    public func beginCapture(sessionID: String) async throws -> TelemetryCaptureInfo {
        try await enqueueCaptureCommandAndWait { .beginCapture(sessionID, $0) }
    }

    /// Flushes any pending capture rows for the active session and returns the latest summary.
    public func flushCapture(sessionID: String) async throws -> TelemetryCaptureInfo {
        try await enqueueCaptureCommandAndWait { .flushCapture(sessionID, $0) }
    }

    /// Ends the active session-scoped telemetry capture and finalizes the App Group file.
    public func endCapture(sessionID: String) async throws -> TelemetryCaptureInfo {
        try await enqueueCaptureCommandAndWait { .endCapture(sessionID, $0) }
    }

    /// Returns the latest capture summary known to the worker.
    public func latestCaptureInfo() async throws -> TelemetryCaptureInfo {
        try await enqueueCaptureCommandAndWait { .latestCaptureInfo($0) }
    }

    /// Stops the worker without waiting for queued work or final persistence flushes.
    /// Use `stopAndWait()` when shutdown correctness matters.
    public func stop() {
        enqueue(.stop(nil), markStopped: true)
    }

    /// Stops the worker and waits until queued work and persistence flushes are complete.
    public func stopAndWait() async {
        let (task, continuation, shouldSignal) = state.withLock { state in
            let task = workerTask
            let continuation = state.continuation
            let shouldSignal = !state.isStopped
            if shouldSignal {
                state.isStopped = true
            }
            return (task, continuation, shouldSignal)
        }

        if shouldSignal, let continuation {
            await withCheckedContinuation { (signal: CheckedContinuation<Void, Never>) in
                let commandSignal = CommandSignal(signal)
                Self.yield(.stop(commandSignal), to: continuation, fallbackSignal: commandSignal)
            }
        }

        await task?.value
    }

    private func enqueueCaptureCommandAndWait(
        _ makeCommand: @escaping (CaptureInfoSignal) -> Command
    ) async throws -> TelemetryCaptureInfo {
        let (continuation, shouldSignal) = state.withLock { state in
            (state.continuation, !state.isStopped)
        }

        guard shouldSignal, let continuation else {
            throw CaptureControlError.unavailable
        }

        let result = await withCheckedContinuation { (signal: CheckedContinuation<Result<TelemetryCaptureInfo, CaptureControlError>, Never>) in
            let captureSignal = CaptureInfoSignal(signal)
            Self.yield(makeCommand(captureSignal), to: continuation, fallbackCaptureSignal: captureSignal)
        }

        switch result {
        case .success(let info):
            return info
        case .failure(let error):
            throw error
        }
    }

    private static func didStartBatch(state: SharedState, byteCount: Int) {
        state.withLock { state in
            state.queuedBatches = max(0, state.queuedBatches - 1)
            state.queuedBytes = max(0, state.queuedBytes - byteCount)
        }
    }

    private static func setBufferedRecordCount(state: SharedState, _ count: Int) {
        state.withLock { state in
            state.bufferedRecords = count
        }
    }

    private static func setDetectionSnapshot(state: SharedState, _ snapshot: DetectionSnapshot) {
        state.withLock { state in
            state.detectionSnapshot = snapshot
        }
    }

    private static func currentDetectionSnapshot(state: SharedState) -> DetectionSnapshot {
        state.withLock { state in
            state.detectionSnapshot
        }
    }

    private static func recordDetections(state: SharedState, events: [DetectionEvent]) -> DetectionSnapshot {
        state.withLock { state in
            var countsByDetector = state.detectionSnapshot.countsByDetector
            var countsByTarget = state.detectionSnapshot.countsByTarget
            var recentEvents = state.detectionSnapshot.recentEvents
            var totalDetectionCount = state.detectionSnapshot.totalDetectionCount
            var updatedAt = state.detectionSnapshot.updatedAt

            for event in events {
                countsByDetector[event.detectorIdentifier, default: 0] += 1
                if let target = event.target, !target.isEmpty {
                    countsByTarget[target, default: 0] += 1
                }
                recentEvents.append(event)
                totalDetectionCount += 1
                updatedAt = event.timestamp
            }

            if recentEvents.count > DetectionPolicy.maxRecentEvents {
                recentEvents.removeFirst(recentEvents.count - DetectionPolicy.maxRecentEvents)
            }

            let snapshot = DetectionSnapshot(
                updatedAt: updatedAt,
                totalDetectionCount: totalDetectionCount,
                countsByDetector: countsByDetector,
                countsByTarget: countsByTarget,
                recentEvents: recentEvents
            )
            state.detectionSnapshot = snapshot
            return snapshot
        }
    }

    private static func finishContinuation(state: SharedState) {
        state.withLock { state in
            state.continuation?.finish()
            state.continuation = nil
        }
    }

    private static func runLoop(
        stream: AsyncStream<Command>,
        state: SharedState,
        pipeline: PacketAnalyticsPipeline,
        packetStream: PacketSampleStream?,
        detectors: [any TrafficDetector],
        detectionPersistence: DetectionPersistenceCoordinator?,
        captureSink: TelemetryCaptureSink?,
        logger: StructuredLogger,
        processInfo: ProcessInfo,
        emissionPolicyOverride: PacketAnalyticsPipeline.EmissionPolicy?,
        runtimePlan: DetectorRuntimePlan,
        pathRegimeProvider: (any PathRegimeProvider)?,
        liveTapPolicy: LiveTapPolicy
    ) async {
        var detailRecords: [PacketSampleStream.PacketStreamRecord] = []
        var captureActive = false

        for await command in stream {
            switch command {
            case .batch(let batch):
                Self.didStartBatch(state: state, byteCount: batch.byteCount)
                let policy = emissionPolicyOverride ?? Self.currentEmissionPolicy(
                    processInfo: processInfo,
                    runtimePlan: runtimePlan,
                    captureActive: captureActive
                )
                let runtimeContext = PacketAnalyticsPipeline.RuntimeContext(
                    pathRegime: policy.emitPathRegimeFields ? pathRegimeProvider?.currentSnapshot : nil
                )
                let records = await pipeline.ingest(
                    packets: batch.packets,
                    families: batch.families,
                    summaries: batch.summaries,
                    direction: batch.direction,
                    policy: policy,
                    runtimeContext: runtimeContext
                )
                guard !records.isEmpty else {
                    continue
                }

                if captureActive {
                    await captureSink?.append(records: records)
                }

                if !detectors.isEmpty {
                    var emittedDetections: [DetectionEvent] = []
                    emittedDetections.reserveCapacity(4)
                    for detector in detectors {
                        let projection = runtimePlan.projection(for: detector)
                        let detectorRecords = DetectorRecordCollection(records, projection: projection)
                        emittedDetections.append(contentsOf: detector.ingest(detectorRecords))
                    }
                    if !emittedDetections.isEmpty {
                        let detectionSnapshot = Self.recordDetections(state: state, events: emittedDetections)
                        await detectionPersistence?.schedule(detectionSnapshot)
                    }
                }

                let snapshotRecords = Self.buffer(
                    packetStream: packetStream,
                    records,
                    detailRecords: &detailRecords,
                    liveTapPolicy: liveTapPolicy
                )
                Self.setBufferedRecordCount(state: state, detailRecords.count)
                if !snapshotRecords.isEmpty {
                    await Self.publish(packetStream: packetStream, logger: logger, snapshotRecords)
                }

            case .reset(let signal):
                detailRecords.removeAll(keepingCapacity: false)
                Self.setBufferedRecordCount(state: state, 0)
                if let packetStream {
                    await packetStream.reset()
                }
                signal?.resume()

            case .clearDetections(let signal):
                for detector in detectors {
                    detector.reset()
                }
                let cleared = DetectionSnapshot.empty
                Self.setDetectionSnapshot(state: state, cleared)
                await detectionPersistence?.persistNow(cleared)
                signal?.resume()

            case .barrier(let signal):
                signal?.resume()

            case .beginCapture(let sessionID, let signal):
                guard let captureSink else {
                    signal?.resume(.failure(.unavailable))
                    continue
                }
                do {
                    let info = try await captureSink.begin(sessionID: sessionID)
                    captureActive = info.state == .capturing
                    signal?.resume(.success(info))
                } catch let error as TelemetryCaptureSink.Error {
                    signal?.resume(.failure(Self.captureControlError(from: error)))
                } catch {
                    signal?.resume(.failure(.unavailable))
                }

            case .flushCapture(let sessionID, let signal):
                guard let captureSink else {
                    signal?.resume(.failure(.unavailable))
                    continue
                }
                do {
                    let info = try await captureSink.flush(sessionID: sessionID)
                    signal?.resume(.success(info))
                } catch let error as TelemetryCaptureSink.Error {
                    signal?.resume(.failure(Self.captureControlError(from: error)))
                } catch {
                    signal?.resume(.failure(.unavailable))
                }

            case .endCapture(let sessionID, let signal):
                guard let captureSink else {
                    signal?.resume(.failure(.unavailable))
                    continue
                }
                do {
                    let info = try await captureSink.end(sessionID: sessionID)
                    captureActive = false
                    signal?.resume(.success(info))
                } catch let error as TelemetryCaptureSink.Error {
                    signal?.resume(.failure(Self.captureControlError(from: error)))
                } catch {
                    signal?.resume(.failure(.unavailable))
                }

            case .latestCaptureInfo(let signal):
                if let captureSink {
                    signal?.resume(.success(await captureSink.latestCaptureInfo()))
                } else {
                    signal?.resume(.success(.inactive))
                }

            case .stop(let signal):
                detailRecords.removeAll(keepingCapacity: false)
                Self.setBufferedRecordCount(state: state, 0)
                Self.finishContinuation(state: state)
                await captureSink?.shutdown()
                await detectionPersistence?.flush()
                signal?.resume()
                return
            }
        }

        detailRecords.removeAll(keepingCapacity: false)
        Self.setBufferedRecordCount(state: state, 0)
        await captureSink?.shutdown()
        await detectionPersistence?.flush()
        pathRegimeProvider?.stop()
    }

    /// Routes sparse detector records either into the rolling app-facing tap or into the recent detail buffer.
    /// Decision: the default app-facing tap is intentionally not a mirror of the full detector stream.
    /// `flowSlice` stays detector-only by default, while `activitySample` stays memory-only until a matching
    /// `metadata`, `burst`, or `flowClose` event makes a short detector window worth exposing to the app.
    private static func buffer(
        packetStream: PacketSampleStream?,
        _ records: [PacketSampleStream.PacketStreamRecord],
        detailRecords: inout [PacketSampleStream.PacketStreamRecord],
        liveTapPolicy: LiveTapPolicy
    ) -> [PacketSampleStream.PacketStreamRecord] {
        guard packetStream != nil else {
            detailRecords.removeAll(keepingCapacity: false)
            return []
        }

        var snapshotRecords: [PacketSampleStream.PacketStreamRecord] = []
        snapshotRecords.reserveCapacity(records.count + detailRecords.count)

        for record in records {
            switch record.kind {
            case .activitySample:
                guard liveTapPolicy.includeActivitySamples else {
                    continue
                }
                detailRecords.append(record)
                if detailRecords.count > DetailPolicy.maxBufferedRecords {
                    detailRecords.removeFirst(detailRecords.count - DetailPolicy.maxBufferedRecords)
                }

            case .flowSlice:
                guard liveTapPolicy.includeFlowSlices else {
                    continue
                }
                detailRecords.append(record)
                if detailRecords.count > DetailPolicy.maxBufferedRecords {
                    detailRecords.removeFirst(detailRecords.count - DetailPolicy.maxBufferedRecords)
                }

            case .metadata, .burst:
                snapshotRecords.append(contentsOf: Self.drainDetailWindow(for: record, detailRecords: &detailRecords))
                snapshotRecords.append(record)

            case .flowClose:
                snapshotRecords.append(contentsOf: Self.drainDetailWindow(for: record, detailRecords: &detailRecords))
                if liveTapPolicy.includeFlowCloseEvents {
                    snapshotRecords.append(record)
                }

            case .flowOpen:
                snapshotRecords.append(record)
            }
        }

        return snapshotRecords
    }

    /// Pulls recent activity samples for the same flow into the app-facing snapshot right before a trigger event.
    private static func drainDetailWindow(
        for trigger: PacketSampleStream.PacketStreamRecord,
        detailRecords: inout [PacketSampleStream.PacketStreamRecord]
    ) -> [PacketSampleStream.PacketStreamRecord] {
        guard !detailRecords.isEmpty else {
            return []
        }

        var matched: [PacketSampleStream.PacketStreamRecord] = []
        var remaining: [PacketSampleStream.PacketStreamRecord] = []
        remaining.reserveCapacity(detailRecords.count)

        for record in detailRecords {
            if Self.isSameFlow(record, trigger) {
                matched.append(record)
            } else {
                remaining.append(record)
            }
        }

        detailRecords = remaining
        return matched
    }

    private static func isSameFlow(
        _ lhs: PacketSampleStream.PacketStreamRecord,
        _ rhs: PacketSampleStream.PacketStreamRecord
    ) -> Bool {
        if let lhsFlowHash = lhs.flowHash, let rhsFlowHash = rhs.flowHash {
            return lhsFlowHash == rhsFlowHash
        }
        if let lhsTextFlowId = lhs.textFlowId, let rhsTextFlowId = rhs.textFlowId {
            return lhsTextFlowId == rhsTextFlowId
        }
        return false
    }

    private static func publish(
        packetStream: PacketSampleStream?,
        logger: StructuredLogger,
        _ records: [PacketSampleStream.PacketStreamRecord]
    ) async {
        guard !records.isEmpty, let packetStream else {
            return
        }
        do {
            try await packetStream.append(records: records)
        } catch {
            await logger.log(
                level: .warning,
                phase: .storage,
                category: .liveTap,
                component: "PacketTelemetryWorker",
                event: "live-tap-update-failed",
                errorCode: String(describing: error),
                message: "Failed to update the in-memory packet tap"
            )
        }
    }

    private static func currentEmissionPolicy(
        processInfo: ProcessInfo,
        runtimePlan: DetectorRuntimePlan,
        captureActive: Bool
    ) -> PacketAnalyticsPipeline.EmissionPolicy {
        let needsFlowSlices = runtimePlan.needsFlowSlices || captureActive
        let needsBurstShapeCounters = runtimePlan.needsBurstShapeCounters ||
            runtimePlan.liveTapFeatureFamilies.contains(.burstShape) ||
            captureActive
        let needsDNSAssociation = runtimePlan.needsDNSAssociation || captureActive
        let needsLineage = runtimePlan.needsLineage || captureActive
        let needsPathRegime = runtimePlan.needsPathRegime || captureActive
        let needsServiceAttribution = runtimePlan.needsServiceAttribution || captureActive
        let needsQUICIdentity = runtimePlan.needsQUICIdentity ||
            runtimePlan.liveTapFeatureFamilies.contains(.quicIdentity) ||
            captureActive
        let needsHostHints = runtimePlan.needsHostHints ||
            runtimePlan.liveTapFeatureFamilies.contains(.hostHints) ||
            captureActive
        let needsDeepMetadata = runtimePlan.needsDeepMetadata || captureActive
        let includeDNSAnswerAddresses = runtimePlan.unionFeatureFamilies.contains(.dnsAnswerAddresses) || captureActive
        let flowSliceIntervalMs = captureActive ? min(runtimePlan.flowSliceIntervalMs, 250) : runtimePlan.flowSliceIntervalMs
        let thermalState = processInfo.thermalState
        let lowPowerModeEnabled = processInfo.isLowPowerModeEnabled

        if lowPowerModeEnabled || thermalState == .critical {
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: false,
                maxMetadataProbesPerBatch: 0,
                emitFlowSlices: false,
                flowSliceIntervalMs: flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: needsBurstShapeCounters,
                emitDNSAssociationFields: false,
                emitLineageFields: false,
                emitPathRegimeFields: needsPathRegime,
                emitServiceAttributionFields: false,
                includeHostHints: runtimePlan.liveTapFeatureFamilies.contains(.hostHints) || captureActive,
                includeDNSAnswerAddresses: includeDNSAnswerAddresses,
                includeQUICIdentity: needsQUICIdentity,
                activitySampleMinimumPackets: 2_048,
                activitySampleMinimumBytes: 4_194_304,
                activitySampleMinimumInterval: 30,
                emitBurstEvents: true,
                emitActivitySamples: false
            )
        }

        switch thermalState {
        case .nominal:
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: needsDeepMetadata ||
                    runtimePlan.liveTapFeatureFamilies.contains(.hostHints) ||
                    runtimePlan.liveTapFeatureFamilies.contains(.dnsAnswerAddresses),
                maxMetadataProbesPerBatch: needsDeepMetadata ? 2 : 1,
                emitFlowSlices: needsFlowSlices,
                flowSliceIntervalMs: flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: needsBurstShapeCounters,
                emitDNSAssociationFields: needsDNSAssociation,
                emitLineageFields: needsLineage,
                emitPathRegimeFields: needsPathRegime,
                emitServiceAttributionFields: needsServiceAttribution,
                includeHostHints: needsHostHints,
                includeDNSAnswerAddresses: includeDNSAnswerAddresses,
                includeQUICIdentity: needsQUICIdentity,
                activitySampleMinimumPackets: 256,
                activitySampleMinimumBytes: 524_288,
                activitySampleMinimumInterval: 6,
                emitBurstEvents: true,
                emitActivitySamples: true
            )
        case .fair:
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: needsDeepMetadata,
                maxMetadataProbesPerBatch: needsDeepMetadata ? 1 : 0,
                emitFlowSlices: needsFlowSlices,
                flowSliceIntervalMs: flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: needsBurstShapeCounters,
                emitDNSAssociationFields: needsDNSAssociation,
                emitLineageFields: needsLineage,
                emitPathRegimeFields: needsPathRegime,
                emitServiceAttributionFields: needsServiceAttribution,
                includeHostHints: needsHostHints,
                includeDNSAnswerAddresses: includeDNSAnswerAddresses,
                includeQUICIdentity: needsQUICIdentity,
                activitySampleMinimumPackets: 2_048,
                activitySampleMinimumBytes: 4_194_304,
                activitySampleMinimumInterval: 30,
                emitBurstEvents: true,
                emitActivitySamples: false
            )
        case .serious, .critical:
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: false,
                maxMetadataProbesPerBatch: 0,
                emitFlowSlices: false,
                flowSliceIntervalMs: flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: needsBurstShapeCounters,
                emitDNSAssociationFields: false,
                emitLineageFields: false,
                emitPathRegimeFields: needsPathRegime,
                emitServiceAttributionFields: false,
                includeHostHints: runtimePlan.liveTapFeatureFamilies.contains(.hostHints) || captureActive,
                includeDNSAnswerAddresses: includeDNSAnswerAddresses,
                includeQUICIdentity: needsQUICIdentity,
                activitySampleMinimumPackets: 2_048,
                activitySampleMinimumBytes: 4_194_304,
                activitySampleMinimumInterval: 30,
                emitBurstEvents: true,
                emitActivitySamples: false
            )
        @unknown default:
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: false,
                maxMetadataProbesPerBatch: 0,
                emitFlowSlices: false,
                flowSliceIntervalMs: flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: needsBurstShapeCounters,
                emitDNSAssociationFields: false,
                emitLineageFields: false,
                emitPathRegimeFields: needsPathRegime,
                emitServiceAttributionFields: false,
                includeHostHints: runtimePlan.liveTapFeatureFamilies.contains(.hostHints) || captureActive,
                includeDNSAnswerAddresses: includeDNSAnswerAddresses,
                includeQUICIdentity: needsQUICIdentity,
                activitySampleMinimumPackets: 2_048,
                activitySampleMinimumBytes: 4_194_304,
                activitySampleMinimumInterval: 30,
                emitBurstEvents: true,
                emitActivitySamples: false
            )
        }
    }

    private static func prefilter(
        packets: [Data],
        families: [Int32]
    ) -> (packets: [Data], families: [Int32], summaries: [FastPacketSummary], byteCount: Int) {
        guard !packets.isEmpty else {
            return ([], [], [], 0)
        }

        var filteredPackets: [Data] = []
        var filteredFamilies: [Int32] = []
        var filteredSummaries: [FastPacketSummary] = []
        filteredPackets.reserveCapacity(packets.count)
        filteredFamilies.reserveCapacity(packets.count)
        filteredSummaries.reserveCapacity(packets.count)

        var totalBytes = 0
        for (index, packet) in packets.enumerated() {
            let familyHint = families.indices.contains(index) ? families[index] : 0
            guard let summary = FastPacketSummary(data: packet, ipVersionHint: familyHint),
                  shouldTrack(summary: summary) else {
                continue
            }

            filteredPackets.append(packet)
            filteredFamilies.append(familyHint)
            filteredSummaries.append(summary)
            totalBytes += packet.count
        }

        return (filteredPackets, filteredFamilies, filteredSummaries, totalBytes)
    }

    private static func shouldTrack(summary: FastPacketSummary) -> Bool {
        switch summary.transport {
        case .tcp:
            return summary.hasTransportPayload || summary.isTCPControlSignal
        case .udp:
            return summary.hasTransportPayload
        case .icmp, .icmpv6:
            return true
        default:
            return summary.packetLength > 0
        }
    }

    private static func captureControlError(from error: TelemetryCaptureSink.Error) -> CaptureControlError {
        switch error {
        case .invalidSessionID:
            return .invalidSessionID
        case .captureAlreadyActive(let sessionID):
            return .captureAlreadyActive(sessionID)
        case .noActiveCapture:
            return .noActiveCapture
        case .sessionMismatch(let expected, let got):
            return .sessionMismatch(expected: expected, got: got)
        case .unavailable:
            return .unavailable
        }
    }

    private func enqueue(_ command: Command, markStopped: Bool = false) {
        let continuation: AsyncStream<Command>.Continuation? = state.withLock { state in
            guard !state.isStopped else {
                return nil
            }
            if markStopped {
                state.isStopped = true
            }
            return state.continuation
        }
        if let continuation {
            Self.yield(command, to: continuation)
        }
    }

    private func enqueueAndWait(_ builder: (CommandSignal?) -> Command) async {
        let continuation: AsyncStream<Command>.Continuation? = state.withLock { state in
            guard !state.isStopped else {
                return nil
            }
            return state.continuation
        }
        guard let continuation else {
            return
        }

        await withCheckedContinuation { (signal: CheckedContinuation<Void, Never>) in
            let commandSignal = CommandSignal(signal)
            Self.yield(builder(commandSignal), to: continuation, fallbackSignal: commandSignal)
        }
    }

    private static func yield(
        _ command: Command,
        to continuation: AsyncStream<Command>.Continuation,
        fallbackSignal: CommandSignal? = nil
    ) {
        let result = continuation.yield(command)
        switch result {
        case .terminated:
            fallbackSignal?.resume()
        case .dropped(_):
            fallbackSignal?.resume()
        case .enqueued(_):
            break
        @unknown default:
            fallbackSignal?.resume()
        }
    }

    private static func yield(
        _ command: Command,
        to continuation: AsyncStream<Command>.Continuation,
        fallbackCaptureSignal: CaptureInfoSignal
    ) {
        let result = continuation.yield(command)
        switch result {
        case .terminated, .dropped(_):
            fallbackCaptureSignal.resume(.failure(.unavailable))
        case .enqueued(_):
            break
        @unknown default:
            fallbackCaptureSignal.resume(.failure(.unavailable))
        }
    }
}
