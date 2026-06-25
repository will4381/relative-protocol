// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
import Observability
import TunnelRuntime

/// Long-lived packet telemetry worker that serializes flow enrichment and optionally updates one rolling in-memory tap.
/// Decision: one worker task is cheaper than spawning a `Task` for every packet batch on the provider hot path.
public final class PacketTelemetryWorker: @unchecked Sendable {
    private enum QueuePolicy {
        static let maxQueuedBatches = 512
        static let maxQueuedBytes = 4 * 1024 * 1024
        static let payloadOnlyQueuedBatches = 384
        static let payloadOnlyQueuedBytes = 3 * 1024 * 1024
    }

    private enum TrackingMode: Sendable {
        case full
        case payloadOnlyUnderPressure
    }

    private enum DetailPolicy {
        static let maxBufferedRecords = 128
        static let maxSnapshotPacketLimit = 96
    }

    private struct LiveTapPolicy: Sendable {
        let includeActivitySamples: Bool
        let includeFlowSlices: Bool
        let includeFlowCloseEvents: Bool
        let includePacketCues: Bool
        let includeValidationRecords: Bool

        /// Decision: the default app-facing live tap stays leaner than the detector-facing sparse stream.
        /// `flowSlice` remains detector-only by default because pushing every cadence record into the
        /// foreground snapshot would raise snapshot volume and debugging overhead without improving
        /// durable detector correctness.
        static let `default` = LiveTapPolicy(
            includeActivitySamples: true,
            includeFlowSlices: false,
            includeFlowCloseEvents: true,
            includePacketCues: false,
            includeValidationRecords: false
        )

        static func configured(
            includeFlowSlices: Bool,
            includePacketCues: Bool,
            includeValidationRecords: Bool
        ) -> LiveTapPolicy {
            LiveTapPolicy(
                includeActivitySamples: true,
                includeFlowSlices: includeFlowSlices,
                includeFlowCloseEvents: true,
                includePacketCues: includePacketCues,
                includeValidationRecords: includeValidationRecords
            )
        }
    }

    private enum DetectionPolicy {
        static let maxRecentEvents = 96
        static let maxCountedTargets = 256
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
        let direction: PacketDirection
        let byteCount: Int
        let trackingMode: TrackingMode
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
        var streamStartedAtMs: Double?
        var lastRecordAtMs: Double?
        var sequenceNumber: UInt64 = 0
        var droppedSequenceCount = 0
        var lastPacketTimestampMs: Double?
        var sessionId: String?
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
        case updateSessionContext(DetectorSessionContext?, CommandSignal?)
        case reset(CommandSignal?)
        case clearDetections(CommandSignal?)
        case barrier(CommandSignal?)
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
        public let thermalState: TunnelThermalState
        public let lowPowerModeEnabled: Bool
        public let health: TelemetryHealthRecord
        public let liveness: TelemetryStreamLiveness
    }

    private let pipeline: PacketAnalyticsPipeline
    private let clock: any Clock
    private let packetStream: PacketSampleStream?
    private let detectors: [any TrafficDetector]
    private let detectionPersistence: DetectionPersistenceCoordinator?
    private let richPacketLogStore: RichPacketLogStore?
    private let logger: StructuredLogger
    private let processInfo: ProcessInfo
    private let state: SharedState
    private let emissionPolicyOverride: PacketAnalyticsPipeline.EmissionPolicy?
    private let runtimePlan: DetectorRuntimePlan
    private let pathRegimeProvider: (any PathRegimeProvider)?
    private let liveTapPolicy: LiveTapPolicy
    private let packetCuePolicy: PacketCueEmissionPolicy
    private let telemetryDegradationPolicy: TelemetryDegradationPolicy
    private let writerProcess: String

    private var workerTask: Task<Void, Never>?

    /// Creates a telemetry worker around one analytics pipeline, an optional rolling packet tap, and zero or more detectors.
    /// Docs: https://developer.apple.com/documentation/foundation/processinfo/thermalstate
    /// Docs: https://developer.apple.com/documentation/foundation/processinfo/islowpowermodeenabled
    /// The worker evaluates thermal and power state at batch boundaries so the tunnel can reduce telemetry cost
    /// without paying for per-packet notification handling.
    public convenience init(
        pipeline: PacketAnalyticsPipeline,
        clock: any Clock = SystemClock(),
        packetStream: PacketSampleStream? = nil,
        detectors: [any TrafficDetector] = [],
        initialDetectionSnapshot: DetectionSnapshot = .empty,
        detectionStore: DetectionStore? = nil,
        richPacketLogStore: RichPacketLogStore? = nil,
        logger: StructuredLogger,
        processInfo: ProcessInfo = .processInfo,
        includeFlowSlicesInLiveTap: Bool = false,
        includePacketCuesInLiveTap: Bool = false,
        includeValidationRecordsInLiveTap: Bool = false,
        packetCuePolicy: PacketCueEmissionPolicy = .disabled,
        telemetryDegradationPolicy: TelemetryDegradationPolicy = .default,
        writerProcess: String = "packetTunnelProvider"
    ) {
        self.init(
            pipeline: pipeline,
            clock: clock,
            packetStream: packetStream,
            detectors: detectors,
            initialDetectionSnapshot: initialDetectionSnapshot,
            detectionStore: detectionStore,
            richPacketLogStore: richPacketLogStore,
            logger: logger,
            processInfo: processInfo,
            emissionPolicyOverride: nil,
            pathRegimeProvider: nil,
            includeFlowSlicesInLiveTap: includeFlowSlicesInLiveTap,
            includePacketCuesInLiveTap: includePacketCuesInLiveTap,
            includeValidationRecordsInLiveTap: includeValidationRecordsInLiveTap,
            packetCuePolicy: packetCuePolicy,
            telemetryDegradationPolicy: telemetryDegradationPolicy,
            writerProcess: writerProcess
        )
    }

    init(
        pipeline: PacketAnalyticsPipeline,
        clock: any Clock = SystemClock(),
        packetStream: PacketSampleStream? = nil,
        detectors: [any TrafficDetector] = [],
        initialDetectionSnapshot: DetectionSnapshot = .empty,
        detectionStore: DetectionStore? = nil,
        richPacketLogStore: RichPacketLogStore? = nil,
        logger: StructuredLogger,
        processInfo: ProcessInfo = .processInfo,
        emissionPolicyOverride: PacketAnalyticsPipeline.EmissionPolicy?,
        pathRegimeProvider: (any PathRegimeProvider)? = nil,
        includeFlowSlicesInLiveTap: Bool = false,
        includePacketCuesInLiveTap: Bool = false,
        includeValidationRecordsInLiveTap: Bool = false,
        packetCuePolicy: PacketCueEmissionPolicy = .disabled,
        telemetryDegradationPolicy: TelemetryDegradationPolicy = .default,
        writerProcess: String = "packetTunnelProvider"
    ) {
        self.pipeline = pipeline
        self.clock = clock
        self.packetStream = packetStream
        self.detectors = detectors
        self.richPacketLogStore = richPacketLogStore
        self.packetCuePolicy = packetCuePolicy
        self.telemetryDegradationPolicy = telemetryDegradationPolicy
        self.writerProcess = writerProcess
        let includePacketCueStream = includePacketCuesInLiveTap || includeValidationRecordsInLiveTap
        self.runtimePlan = DetectorRuntimePlan(
            detectors: detectors,
            liveTapEnabled: packetStream != nil,
            includePacketCuesInLiveTap: includePacketCueStream
        )
        if let detectionStore {
            self.detectionPersistence = DetectionPersistenceCoordinator(store: detectionStore, logger: logger)
        } else {
            self.detectionPersistence = nil
        }
        self.logger = logger
        self.processInfo = processInfo
        self.state = SharedState(initialDetectionSnapshot: initialDetectionSnapshot)
        self.emissionPolicyOverride = emissionPolicyOverride
        self.liveTapPolicy = .configured(
            includeFlowSlices: includeFlowSlicesInLiveTap,
            includePacketCues: includePacketCueStream,
            includeValidationRecords: includeValidationRecordsInLiveTap
        )
        if self.runtimePlan.needsPathRegime {
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
        let clock = self.clock
        let packetStream = self.packetStream
        let detectors = self.detectors
        let detectionPersistence = self.detectionPersistence
        let richPacketLogStore = self.richPacketLogStore
        let logger = self.logger
        let processInfo = self.processInfo
        let state = self.state
        let emissionPolicyOverride = self.emissionPolicyOverride
        let runtimePlan = self.runtimePlan
        let pathRegimeProvider = self.pathRegimeProvider
        let liveTapPolicy = self.liveTapPolicy
        let packetCuePolicy = self.packetCuePolicy
        let telemetryDegradationPolicy = self.telemetryDegradationPolicy
        let writerProcess = self.writerProcess

        self.workerTask = Task { [state, pipeline, clock, packetStream, detectors, detectionPersistence, richPacketLogStore, logger, processInfo, emissionPolicyOverride, runtimePlan, pathRegimeProvider, liveTapPolicy, packetCuePolicy, telemetryDegradationPolicy, writerProcess] in
            await Self.runLoop(
                stream: stream,
                state: state,
                pipeline: pipeline,
                clock: clock,
                packetStream: packetStream,
                detectors: detectors,
                detectionPersistence: detectionPersistence,
                richPacketLogStore: richPacketLogStore,
                logger: logger,
                processInfo: processInfo,
                emissionPolicyOverride: emissionPolicyOverride,
                runtimePlan: runtimePlan,
                pathRegimeProvider: pathRegimeProvider,
                liveTapPolicy: liveTapPolicy,
                packetCuePolicy: packetCuePolicy,
                telemetryDegradationPolicy: telemetryDegradationPolicy,
                writerProcess: writerProcess
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
    /// Decision: admission remains cheap on the provider queue; packet parsing and payload-only filtering happen on
    /// the worker task so telemetry cannot add per-packet parsing heat to the tunnel IO path.
    public func submit(packets: [Data], families: [Int32], direction: PacketDirection) -> SubmitResult {
        guard !packets.isEmpty else {
            return state.withLock { state in
                Self.incrementCounter(&state.skippedBatches)
                return SubmitResult(
                    accepted: false,
                    skipped: true,
                    shouldLogSheddingStart: false,
                    queuedBatches: state.queuedBatches,
                    queuedBytes: state.queuedBytes,
                    droppedBatches: state.droppedBatches
                )
            }
        }
        let rawByteCount = packets.reduce(0) { partial, packet in
            Self.saturatingAdd(partial, packet.count)
        }
        // One lock acquisition per submitted batch: admission decision, counter updates, and
        // the stream yield all happen under the same critical section.
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

            let trackingMode: TrackingMode =
                state.queuedBatches >= QueuePolicy.payloadOnlyQueuedBatches ||
                state.queuedBytes >= QueuePolicy.payloadOnlyQueuedBytes
                ? .payloadOnlyUnderPressure
                : .full

            let nextQueuedBatches = Self.saturatingAdd(state.queuedBatches, 1)
            let nextQueuedBytes = Self.saturatingAdd(state.queuedBytes, rawByteCount)
            if state.queuedBatches >= QueuePolicy.maxQueuedBatches ||
                state.queuedBytes >= QueuePolicy.maxQueuedBytes ||
                nextQueuedBatches > QueuePolicy.maxQueuedBatches ||
                nextQueuedBytes > QueuePolicy.maxQueuedBytes {
                Self.incrementCounter(&state.droppedBatches)
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
            Self.incrementCounter(&state.acceptedBatches)
            state.continuation?.yield(
                .batch(
                    Batch(
                        packets: packets,
                        families: families,
                        direction: direction,
                        byteCount: rawByteCount,
                        trackingMode: trackingMode
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
            let policy = emissionPolicyOverride ?? Self.currentEmissionPolicy(
                processInfo: processInfo,
                runtimePlan: runtimePlan,
                packetCuePolicy: packetCuePolicy,
                telemetryDegradationPolicy: telemetryDegradationPolicy
            )
            return Snapshot(
                acceptedBatches: state.acceptedBatches,
                queuedBatches: state.queuedBatches,
                queuedBytes: state.queuedBytes,
                droppedBatches: state.droppedBatches,
                skippedBatches: state.skippedBatches,
                bufferedRecords: state.bufferedRecords,
                thermalState: processInfo.tunnelThermalState,
                lowPowerModeEnabled: processInfo.tunnelLowPowerModeEnabled,
                health: Self.healthRecord(
                    state: state,
                    runtimePlan: runtimePlan,
                    policy: policy,
                    processInfo: processInfo,
                    telemetryDegradationPolicy: telemetryDegradationPolicy
                ),
                liveness: TelemetryStreamLiveness(
                    streamStartedAtMs: state.streamStartedAtMs,
                    lastRecordAtMs: state.lastRecordAtMs,
                    sequenceNumber: state.sequenceNumber,
                    droppedSequenceCount: state.droppedSequenceCount,
                    sessionId: state.sessionId,
                    writerProcess: writerProcess
                )
            )
        }
    }

    /// Returns the latest rolling packet snapshot for the containing app.
    public func recentSnapshot(limit: Int?, includeValidationRecords: Bool = false) async -> TunnelTelemetrySnapshot {
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
            thermalState: state.thermalState,
            lowPowerModeEnabled: state.lowPowerModeEnabled,
            detections: detections,
            health: state.health,
            liveness: state.liveness,
            validationRecords: liveTapPolicy.includeValidationRecords || includeValidationRecords
                ? streamSnapshot.samples.filter { $0.kind == .packetCue || $0.kind == .metadata || $0.kind == .sourceAppFlow }
                : []
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

    /// Updates app-supplied detector session context stamped onto future records.
    public func updateSessionContext(_ context: DetectorSessionContext?) {
        enqueue(.updateSessionContext(context, nil))
    }

    /// Updates app-supplied detector session context and waits until future batches will observe it.
    public func updateSessionContextAndWait(_ context: DetectorSessionContext?) async {
        await enqueueAndWait { .updateSessionContext(context, $0) }
    }

    /// Waits until all previously enqueued telemetry work has been processed.
    public func flushAndWait() async {
        await enqueueAndWait { .barrier($0) }
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

    private static func didStartBatch(state: SharedState, byteCount: Int) {
        state.withLock { state in
            state.queuedBatches = max(0, state.queuedBatches - 1)
            state.queuedBytes = max(0, state.queuedBytes - byteCount)
        }
    }

    private static func didSkipBatch(state: SharedState) {
        state.withLock { state in
            Self.incrementCounter(&state.skippedBatches)
        }
    }

    private static func setBufferedRecordCount(state: SharedState, _ count: Int) {
        state.withLock { state in
            state.bufferedRecords = count
        }
    }

    private static func notePipelineRecords(state: SharedState, records: [PacketSampleStream.PacketStreamRecord]) {
        guard let lastTimestampMs = records.last?.timestampMs else {
            return
        }
        state.withLock { state in
            state.lastPacketTimestampMs = lastTimestampMs
        }
    }

    private static func noteRichPacketLogRecords(state: SharedState, records: [RichPacketLogRecord]) {
        guard let lastTimestampMs = records.last?.timestampMs else {
            return
        }
        state.withLock { state in
            state.lastPacketTimestampMs = lastTimestampMs
        }
    }

    private static func notePublishedRecords(state: SharedState, records: [PacketSampleStream.PacketStreamRecord]) {
        guard !records.isEmpty else {
            return
        }
        let firstTimestampMs = records.first?.timestampMs
        let lastTimestampMs = records.last?.timestampMs
        state.withLock { state in
            if state.streamStartedAtMs == nil {
                state.streamStartedAtMs = firstTimestampMs
            }
            state.lastRecordAtMs = lastTimestampMs ?? state.lastRecordAtMs
            let next = state.sequenceNumber.addingReportingOverflow(UInt64(records.count))
            if next.overflow {
                state.sequenceNumber = UInt64.max
                state.droppedSequenceCount = saturatingAdd(state.droppedSequenceCount, records.count)
            } else {
                state.sequenceNumber = next.partialValue
            }
        }
    }

    private static func setSessionContext(state: SharedState, _ context: DetectorSessionContext?) {
        state.withLock { state in
            state.sessionId = context?.sessionId
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

    private static func healthRecord(
        state: SharedState,
        runtimePlan: DetectorRuntimePlan,
        policy: PacketAnalyticsPipeline.EmissionPolicy,
        processInfo: ProcessInfo,
        telemetryDegradationPolicy: TelemetryDegradationPolicy
    ) -> TelemetryHealthRecord {
        let requested = Self.featureNames(for: runtimePlan.unionFeatureFamilies)
        let available = Self.availableFeatureNames(policy: policy)
        let missing = requested.filter { !available.contains($0) }.sorted()
        let availableSorted = available.sorted()
        let degradedReason: String?
        if telemetryDegradationPolicy.reduceOnLowPowerMode, processInfo.tunnelLowPowerModeEnabled {
            degradedReason = "lowPowerMode"
        } else if telemetryDegradationPolicy.reduceOnThermalPressure {
            switch processInfo.tunnelThermalState {
            case .serious:
                degradedReason = "thermalSerious"
            case .critical:
                degradedReason = "thermalCritical"
            case .unknown where !missing.isEmpty:
                degradedReason = "thermalUnknown"
            case .nominal, .fair, .unknown:
                degradedReason = nil
            }
        } else {
            degradedReason = nil
        }
        return TelemetryHealthRecord(
            availableFeatureFamilies: availableSorted,
            missingFeatureFamilies: missing,
            degradedReason: degradedReason,
            droppedRecordCount: saturatingAdd(state.droppedBatches, state.skippedBatches),
            lastPacketTimestampMs: state.lastPacketTimestampMs
        )
    }

    private static func featureNames(for families: DetectorFeatureFamily) -> Set<String> {
        var names: Set<String> = []
        for entry in featureNameTable where families.contains(entry.family) {
            names.insert(entry.name)
        }
        return names
    }

    private static func availableFeatureNames(policy: PacketAnalyticsPipeline.EmissionPolicy) -> Set<String> {
        var available: Set<String> = [
            "packetShape",
            "controlSignals",
            "stringAddresses",
            "sessionContext",
            "remoteEndpoint",
            "roleAttribution",
            "eventAudit",
            "sourceAppAttribution"
        ]
        if policy.emitBurstShapeCounters {
            available.insert("burstShape")
        }
        if policy.includeHostHints {
            available.insert("hostHints")
        }
        if policy.includeQUICIdentity {
            available.insert("quicIdentity")
        }
        if policy.includeDNSAnswerAddresses {
            available.insert("dnsAnswerAddresses")
        }
        if policy.emitDNSAssociationFields {
            available.insert("dnsAssociation")
        }
        if policy.emitLineageFields {
            available.insert("lineage")
        }
        if policy.emitPathRegimeFields {
            available.insert("pathRegime")
        }
        if policy.emitServiceAttributionFields {
            available.insert("serviceAttribution")
        }
        if policy.emitPacketCues {
            available.insert("packetDetails")
        }
        if policy.emitAddressScopeFields {
            available.insert("addressScope")
        }
        return available
    }

    private static let featureNameTable: [(family: DetectorFeatureFamily, name: String)] = [
        (.packetShape, "packetShape"),
        (.controlSignals, "controlSignals"),
        (.burstShape, "burstShape"),
        (.hostHints, "hostHints"),
        (.quicIdentity, "quicIdentity"),
        (.stringAddresses, "stringAddresses"),
        (.dnsAnswerAddresses, "dnsAnswerAddresses"),
        (.dnsAssociation, "dnsAssociation"),
        (.lineage, "lineage"),
        (.pathRegime, "pathRegime"),
        (.serviceAttribution, "serviceAttribution"),
        (.packetDetails, "packetDetails"),
        (.sessionContext, "sessionContext"),
        (.remoteEndpoint, "remoteEndpoint"),
        (.roleAttribution, "roleAttribution"),
        (.addressScope, "addressScope"),
        (.eventAudit, "eventAudit"),
        (.sourceAppAttribution, "sourceAppAttribution")
    ]

    private static func recordDetections(state: SharedState, events: [DetectionEvent]) -> DetectionSnapshot {
        state.withLock { state in
            var countsByDetector = state.detectionSnapshot.countsByDetector
            var countsByTarget = state.detectionSnapshot.countsByTarget
            var recentEvents = state.detectionSnapshot.recentEvents
            var totalDetectionCount = state.detectionSnapshot.totalDetectionCount
            var updatedAt = state.detectionSnapshot.updatedAt

            for event in events {
                countsByDetector[event.detectorIdentifier] = Self.saturatingAdd(
                    countsByDetector[event.detectorIdentifier, default: 0],
                    1
                )
                if let target = event.target, !target.isEmpty {
                    countsByTarget[target] = Self.saturatingAdd(countsByTarget[target, default: 0], 1)
                }
                recentEvents.append(event)
                totalDetectionCount = Self.saturatingAdd(totalDetectionCount, 1)
                updatedAt = event.timestamp
            }

            if recentEvents.count > DetectionPolicy.maxRecentEvents {
                recentEvents = Array(recentEvents.suffix(DetectionPolicy.maxRecentEvents))
            }
            if countsByTarget.count > DetectionPolicy.maxCountedTargets {
                let retainedTargets = Set(
                    recentEvents
                        .compactMap(\.target)
                        .filter { !$0.isEmpty }
                        .suffix(DetectionPolicy.maxCountedTargets)
                )
                let overflow = countsByTarget
                    .filter { !retainedTargets.contains($0.key) }
                    .sorted {
                        if $0.value == $1.value {
                            return $0.key < $1.key
                        }
                        return $0.value < $1.value
                    }
                for entry in overflow.prefix(countsByTarget.count - DetectionPolicy.maxCountedTargets) {
                    countsByTarget.removeValue(forKey: entry.key)
                }
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
        clock: any Clock,
        packetStream: PacketSampleStream?,
        detectors: [any TrafficDetector],
        detectionPersistence: DetectionPersistenceCoordinator?,
        richPacketLogStore: RichPacketLogStore?,
        logger: StructuredLogger,
        processInfo: ProcessInfo,
        emissionPolicyOverride: PacketAnalyticsPipeline.EmissionPolicy?,
        runtimePlan: DetectorRuntimePlan,
        pathRegimeProvider: (any PathRegimeProvider)?,
        liveTapPolicy: LiveTapPolicy,
        packetCuePolicy: PacketCueEmissionPolicy,
        telemetryDegradationPolicy: TelemetryDegradationPolicy,
        writerProcess: String
    ) async {
        var detailRecords: [PacketSampleStream.PacketStreamRecord] = []
        var sessionContext: DetectorSessionContext?
        var richPacketLogSequenceNumber: UInt64 = 0

        for await command in stream {
            switch command {
            case .batch(let batch):
                Self.didStartBatch(state: state, byteCount: batch.byteCount)
                let filtered = Self.prefilter(
                    packets: batch.packets,
                    families: batch.families,
                    trackingMode: batch.trackingMode
                )
                guard !filtered.packets.isEmpty else {
                    Self.didSkipBatch(state: state)
                    continue
                }
                let now = await clock.now()
                if let richPacketLogStore {
                    let richRecords = Self.makeRichPacketLogRecords(
                        packets: filtered.packets,
                        families: filtered.families,
                        summaries: filtered.summaries,
                        direction: batch.direction,
                        timestamp: now,
                        sessionContext: sessionContext,
                        writerProcess: writerProcess,
                        policy: richPacketLogStore.policy,
                        sequenceNumber: &richPacketLogSequenceNumber
                    )
                    if !richRecords.isEmpty {
                        await richPacketLogStore.append(records: richRecords)
                        Self.noteRichPacketLogRecords(state: state, records: richRecords)
                    }
                }
                let policy = emissionPolicyOverride ?? Self.currentEmissionPolicy(
                    processInfo: processInfo,
                    runtimePlan: runtimePlan,
                    packetCuePolicy: packetCuePolicy,
                    telemetryDegradationPolicy: telemetryDegradationPolicy
                )
                let runtimeContext = PacketAnalyticsPipeline.RuntimeContext(
                    pathRegime: policy.emitPathRegimeFields ? pathRegimeProvider?.currentSnapshot : nil,
                    sessionContext: sessionContext
                )
                let records = await pipeline.ingest(
                    packets: filtered.packets,
                    families: filtered.families,
                    summaries: filtered.summaries,
                    direction: batch.direction,
                    policy: policy,
                    runtimeContext: runtimeContext
                )
                guard !records.isEmpty else {
                    continue
                }
                Self.notePipelineRecords(state: state, records: records)

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
                    Self.notePublishedRecords(state: state, records: snapshotRecords)
                }

            case .updateSessionContext(let context, let signal):
                sessionContext = context
                Self.setSessionContext(state: state, context)
                signal?.resume()

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

            case .stop(let signal):
                detailRecords.removeAll(keepingCapacity: false)
                Self.setBufferedRecordCount(state: state, 0)
                Self.finishContinuation(state: state)
                await detectionPersistence?.flush()
                pathRegimeProvider?.stop()
                signal?.resume()
                return
            }
        }

        detailRecords.removeAll(keepingCapacity: false)
        Self.setBufferedRecordCount(state: state, 0)
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
        let reserveLimit = records.count.addingReportingOverflow(detailRecords.count)
        if !reserveLimit.overflow {
            snapshotRecords.reserveCapacity(reserveLimit.partialValue)
        }

        for record in records {
            switch record.kind {
            case .activitySample:
                guard liveTapPolicy.includeActivitySamples else {
                    continue
                }
                detailRecords.append(record)
                trimDetailRecords(&detailRecords)

            case .flowSlice:
                guard liveTapPolicy.includeFlowSlices else {
                    continue
                }
                detailRecords.append(record)
                trimDetailRecords(&detailRecords)

            case .packetCue:
                guard liveTapPolicy.includePacketCues || liveTapPolicy.includeValidationRecords else {
                    continue
                }
                snapshotRecords.append(record)

            case .sourceAppFlow:
                snapshotRecords.append(record)

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

    private static func trimDetailRecords(_ detailRecords: inout [PacketSampleStream.PacketStreamRecord]) {
        guard detailRecords.count > DetailPolicy.maxBufferedRecords else {
            return
        }
        detailRecords = Array(detailRecords.suffix(DetailPolicy.maxBufferedRecords))
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

    private static func makeRichPacketLogRecords(
        packets: [Data],
        families: [Int32],
        summaries: [FastPacketSummary],
        direction: PacketDirection,
        timestamp: Date,
        sessionContext: DetectorSessionContext?,
        writerProcess: String,
        policy: RichPacketLogPolicy,
        sequenceNumber: inout UInt64
    ) -> [RichPacketLogRecord] {
        guard policy.isEnabled, policy.includes(direction: direction), !summaries.isEmpty else {
            return []
        }

        let timestampMs = timestamp.timeIntervalSince1970 * 1_000
        var records: [RichPacketLogRecord] = []
        records.reserveCapacity(min(summaries.count, policy.maxRecordsPerBatch))
        var metadataProbeCount = 0

        for (index, summary) in summaries.enumerated() {
            guard records.count < policy.maxRecordsPerBatch else {
                break
            }
            if let maxPacketLength = policy.maxPacketLength, summary.packetLength > maxPacketLength {
                continue
            }

            let packet = packets.indices.contains(index) ? packets[index] : Data()
            let familyHint = families.indices.contains(index) ? families[index] : 0
            let metadata: PacketMetadata?
            if policy.includeParsedMetadata, metadataProbeCount < policy.metadataProbeLimitPerBatch {
                metadataProbeCount += 1
                metadata = PacketParser.parse(packet, ipVersionHint: familyHint)
            } else {
                metadata = nil
            }

            let sourceAddress = metadata?.srcAddress.stringValue ?? PacketSampleStream.decodedAddress(
                length: summary.sourceAddressLength,
                high: summary.sourceAddressHigh,
                low: summary.sourceAddressLow,
                fallback: nil
            )
            let destinationAddress = metadata?.dstAddress.stringValue ?? PacketSampleStream.decodedAddress(
                length: summary.destinationAddressLength,
                high: summary.destinationAddressHigh,
                low: summary.destinationAddressLow,
                fallback: nil
            )
            let sourcePort = summary.hasPorts ? summary.sourcePort : metadata?.srcPort
            let destinationPort = summary.hasPorts ? summary.destinationPort : metadata?.dstPort
            let flowId = String(format: "%016llx", summary.flowHash)
            let directionRaw = direction.rawValue
            let remoteAddress = DetectorRecordDerivation.remoteAddress(
                direction: directionRaw,
                sourceAddress: sourceAddress,
                destinationAddress: destinationAddress
            )
            let remotePort = DetectorRecordDerivation.remotePort(
                direction: directionRaw,
                sourcePort: sourcePort,
                destinationPort: destinationPort
            )
            let localAddress = DetectorRecordDerivation.localAddress(
                direction: directionRaw,
                sourceAddress: sourceAddress,
                destinationAddress: destinationAddress
            )
            let localPort = DetectorRecordDerivation.localPort(
                direction: directionRaw,
                sourcePort: sourcePort,
                destinationPort: destinationPort
            )
            let remoteEndpoint = DetectorRecordDerivation.endpoint(
                protocolHint: summary.protocolHint,
                address: remoteAddress,
                port: remotePort
            )
            let flowIdentity = DetectorRecordDerivation.flowIdentity(
                protocolHint: summary.protocolHint,
                direction: directionRaw,
                sourceAddress: sourceAddress,
                sourcePort: sourcePort,
                destinationAddress: destinationAddress,
                destinationPort: destinationPort,
                flowId: flowId,
                lineageId: nil,
                generation: nil
            )
            let tcpFlags = summary.transport == .tcp ? summary.tcpFlags : nil
            let dnsAnswerAddresses = policy.includeDNSAnswerAddresses
                ? metadata?.dnsAnswerAddresses?.map(\.stringValue)
                : nil
            let packetBytePrefixHex = policy.includePacketBytePrefix
                ? Self.hexString(Data(packet.prefix(policy.packetBytePrefixLength)))
                : nil

            sequenceNumber = sequenceNumber == UInt64.max ? UInt64.max : sequenceNumber + 1
            records.append(
                RichPacketLogRecord(
                    sequenceNumber: sequenceNumber,
                    timestamp: timestamp,
                    timestampMs: timestampMs,
                    direction: direction,
                    writerProcess: writerProcess,
                    sessionContext: sessionContext,
                    packetLength: summary.packetLength,
                    transportPayloadLength: summary.transportPayloadLengthIfAvailable,
                    ipVersion: summary.ipVersion,
                    transportProtocolNumber: summary.transportProtocolNumber,
                    protocolHint: summary.protocolHint,
                    sourceAddress: sourceAddress,
                    sourcePort: sourcePort,
                    destinationAddress: destinationAddress,
                    destinationPort: destinationPort,
                    localAddress: localAddress,
                    localPort: localPort,
                    remoteAddress: remoteAddress,
                    remotePort: remotePort,
                    remoteEndpoint: remoteEndpoint,
                    flowId: flowId,
                    flowIdentity: flowIdentity,
                    tcpFlags: tcpFlags,
                    tcpAck: summary.transport == .tcp ? summary.hasTCPACK : nil,
                    tcpPsh: summary.transport == .tcp ? summary.hasTCPPSH : nil,
                    tcpSyn: summary.transport == .tcp ? summary.hasTCPSYN : nil,
                    tcpFin: summary.transport == .tcp ? summary.hasTCPFIN : nil,
                    tcpRst: summary.transport == .tcp ? summary.hasTCPRST : nil,
                    isDNSCandidate: summary.isDNSCandidate,
                    isTLSClientHelloCandidate: summary.isTLSClientHelloCandidate,
                    isQUICCandidate: summary.isQUICCandidate,
                    isQUICLongHeader: summary.isQUICLongHeader,
                    isQUICInitialCandidate: summary.isQUICInitialCandidate,
                    metadataParsed: metadata != nil,
                    dnsQueryName: metadata?.dnsQueryName,
                    dnsCname: metadata?.dnsCname,
                    dnsAnswerAddresses: dnsAnswerAddresses,
                    registrableDomain: metadata?.registrableDomain,
                    tlsServerName: metadata?.tlsServerName,
                    quicVersion: metadata?.quicVersion ?? summary.quicVersion,
                    quicPacketType: metadata?.quicPacketType?.rawValue ?? summary.quicPacketType?.rawValue,
                    quicDestinationConnectionId: policy.includeQUICConnectionIDs
                        ? metadata?.quicDestinationConnectionId ?? Self.hexString(summary.quicDestinationConnectionID)
                        : nil,
                    quicSourceConnectionId: policy.includeQUICConnectionIDs
                        ? metadata?.quicSourceConnectionId ?? Self.hexString(summary.quicSourceConnectionID)
                        : nil,
                    addressFamilyHint: familyHint == 0 ? nil : Int(familyHint),
                    packetBytePrefixHex: packetBytePrefixHex
                )
            )
        }

        return records
    }

    private static func hexString(_ data: Data?) -> String? {
        guard let data, !data.isEmpty else {
            return nil
        }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private static func currentEmissionPolicy(
        processInfo: ProcessInfo,
        runtimePlan: DetectorRuntimePlan,
        packetCuePolicy: PacketCueEmissionPolicy,
        telemetryDegradationPolicy: TelemetryDegradationPolicy
    ) -> PacketAnalyticsPipeline.EmissionPolicy {
        let reportedThermalState = processInfo.tunnelThermalState
        let thermalState = telemetryDegradationPolicy.reduceOnThermalPressure ? reportedThermalState : .nominal
        let lowPowerModeEnabled = telemetryDegradationPolicy.reduceOnLowPowerMode && processInfo.tunnelLowPowerModeEnabled

        if lowPowerModeEnabled || thermalState == .critical {
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: false,
                maxMetadataProbesPerBatch: 0,
                emitFlowSlices: false,
                flowSliceIntervalMs: runtimePlan.flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: runtimePlan.needsBurstShapeCounters || runtimePlan.liveTapFeatureFamilies.contains(.burstShape),
                emitDNSAssociationFields: false,
                emitLineageFields: false,
                emitPathRegimeFields: runtimePlan.needsPathRegime,
                emitServiceAttributionFields: false,
                emitAddressScopeFields: runtimePlan.needsAddressScope,
                includeHostHints: runtimePlan.liveTapFeatureFamilies.contains(.hostHints),
                includeDNSAnswerAddresses: runtimePlan.unionFeatureFamilies.contains(.dnsAnswerAddresses),
                includeQUICIdentity: runtimePlan.needsQUICIdentity || runtimePlan.liveTapFeatureFamilies.contains(.quicIdentity),
                activitySampleMinimumPackets: 2_048,
                activitySampleMinimumBytes: 4_194_304,
                activitySampleMinimumInterval: 30,
                emitBurstEvents: true,
                emitActivitySamples: false,
                emitPacketCues: runtimePlan.needsPacketCues,
                packetCuePolicy: packetCuePolicy
            )
        }

        switch thermalState {
        case .nominal:
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: runtimePlan.needsDeepMetadata ||
                    runtimePlan.liveTapFeatureFamilies.contains(.hostHints) ||
                    runtimePlan.liveTapFeatureFamilies.contains(.dnsAnswerAddresses),
                maxMetadataProbesPerBatch: runtimePlan.needsDeepMetadata ? 2 : 1,
                emitFlowSlices: runtimePlan.needsFlowSlices,
                flowSliceIntervalMs: runtimePlan.flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: runtimePlan.needsBurstShapeCounters || runtimePlan.liveTapFeatureFamilies.contains(.burstShape),
                emitDNSAssociationFields: runtimePlan.needsDNSAssociation,
                emitLineageFields: runtimePlan.needsLineage,
                emitPathRegimeFields: runtimePlan.needsPathRegime,
                emitServiceAttributionFields: runtimePlan.needsServiceAttribution,
                emitAddressScopeFields: runtimePlan.needsAddressScope,
                includeHostHints: runtimePlan.needsHostHints || runtimePlan.liveTapFeatureFamilies.contains(.hostHints),
                includeDNSAnswerAddresses: runtimePlan.unionFeatureFamilies.contains(.dnsAnswerAddresses),
                includeQUICIdentity: runtimePlan.needsQUICIdentity || runtimePlan.liveTapFeatureFamilies.contains(.quicIdentity),
                activitySampleMinimumPackets: 256,
                activitySampleMinimumBytes: 524_288,
                activitySampleMinimumInterval: 6,
                emitBurstEvents: true,
                emitActivitySamples: true,
                emitPacketCues: runtimePlan.needsPacketCues,
                packetCuePolicy: packetCuePolicy
            )
        case .fair:
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: runtimePlan.needsDeepMetadata,
                maxMetadataProbesPerBatch: runtimePlan.needsDeepMetadata ? 1 : 0,
                emitFlowSlices: runtimePlan.needsFlowSlices,
                flowSliceIntervalMs: runtimePlan.flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: runtimePlan.needsBurstShapeCounters || runtimePlan.liveTapFeatureFamilies.contains(.burstShape),
                emitDNSAssociationFields: runtimePlan.needsDNSAssociation,
                emitLineageFields: runtimePlan.needsLineage,
                emitPathRegimeFields: runtimePlan.needsPathRegime,
                emitServiceAttributionFields: runtimePlan.needsServiceAttribution,
                emitAddressScopeFields: runtimePlan.needsAddressScope,
                includeHostHints: runtimePlan.needsHostHints || runtimePlan.liveTapFeatureFamilies.contains(.hostHints),
                includeDNSAnswerAddresses: runtimePlan.unionFeatureFamilies.contains(.dnsAnswerAddresses),
                includeQUICIdentity: runtimePlan.needsQUICIdentity || runtimePlan.liveTapFeatureFamilies.contains(.quicIdentity),
                activitySampleMinimumPackets: 2_048,
                activitySampleMinimumBytes: 4_194_304,
                activitySampleMinimumInterval: 30,
                emitBurstEvents: true,
                emitActivitySamples: false,
                emitPacketCues: runtimePlan.needsPacketCues,
                packetCuePolicy: packetCuePolicy
            )
        case .serious, .critical, .unknown:
            return PacketAnalyticsPipeline.EmissionPolicy(
                allowDeepMetadata: false,
                maxMetadataProbesPerBatch: 0,
                emitFlowSlices: false,
                flowSliceIntervalMs: runtimePlan.flowSliceIntervalMs,
                emitFlowCloseEvents: true,
                emitBurstShapeCounters: runtimePlan.needsBurstShapeCounters || runtimePlan.liveTapFeatureFamilies.contains(.burstShape),
                emitDNSAssociationFields: false,
                emitLineageFields: false,
                emitPathRegimeFields: runtimePlan.needsPathRegime,
                emitServiceAttributionFields: false,
                emitAddressScopeFields: runtimePlan.needsAddressScope,
                includeHostHints: runtimePlan.liveTapFeatureFamilies.contains(.hostHints),
                includeDNSAnswerAddresses: runtimePlan.unionFeatureFamilies.contains(.dnsAnswerAddresses),
                includeQUICIdentity: runtimePlan.needsQUICIdentity || runtimePlan.liveTapFeatureFamilies.contains(.quicIdentity),
                activitySampleMinimumPackets: 2_048,
                activitySampleMinimumBytes: 4_194_304,
                activitySampleMinimumInterval: 30,
                emitBurstEvents: true,
                emitActivitySamples: false,
                emitPacketCues: runtimePlan.needsPacketCues,
                packetCuePolicy: packetCuePolicy
            )
        }
    }

    private static func prefilter(
        packets: [Data],
        families: [Int32],
        trackingMode: TrackingMode = .full
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
                  shouldTrack(summary: summary, trackingMode: trackingMode) else {
                continue
            }

            filteredPackets.append(packet)
            filteredFamilies.append(familyHint)
            filteredSummaries.append(summary)
            totalBytes = Self.saturatingAdd(totalBytes, packet.count)
        }

        return (filteredPackets, filteredFamilies, filteredSummaries, totalBytes)
    }

    private static func incrementCounter(_ value: inout Int) {
        value = saturatingAdd(value, 1)
    }

    private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int.max : value
    }

    private static func shouldTrack(summary: FastPacketSummary, trackingMode: TrackingMode = .full) -> Bool {
        switch summary.transport {
        case .tcp:
            if trackingMode == .payloadOnlyUnderPressure {
                return summary.hasTransportPayload
            }
            return summary.hasTransportPayload || summary.isTCPControlSignal
        case .udp:
            return summary.hasTransportPayload
        case .icmp, .icmpv6:
            return true
        default:
            return summary.packetLength > 0
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
}
