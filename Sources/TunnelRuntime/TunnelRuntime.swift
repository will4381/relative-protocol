import DataplaneFFI
import Foundation
import Observability

/// Actor-owned runtime state machine that avoids NetworkExtension dependencies.
public actor TunnelRuntime {
    private let clock: any Clock
    private let runIdGenerator: any RunIdGenerator
    private let randomSource: any RandomSource
    private let logger: StructuredLogger
    private let snapshotSink: (any RuntimeSnapshotSink)?

    private var state: RuntimeState = .idle
    private var dataplane: DataplaneHandle?
    private var runId: String?
    private var sessionId: String?
    private var setupStartedAt: Date?
    private var relayLatencyMs: Int = 0
    private var queueDepth: Int = 0

    /// Creates a runtime state machine with fully injectable deterministic dependencies.
    /// - Parameters:
    ///   - clock: Time source used for setup latency and snapshots.
    ///   - runIdGenerator: Run identifier source.
    ///   - randomSource: Random source used to generate session IDs.
    ///   - logger: Structured logger for runtime/dataplane lifecycle events.
    ///   - snapshotSink: Optional sink that receives runtime snapshots.
    public init(
        clock: any Clock,
        runIdGenerator: any RunIdGenerator,
        randomSource: any RandomSource,
        logger: StructuredLogger,
        snapshotSink: (any RuntimeSnapshotSink)? = nil
    ) {
        self.clock = clock
        self.runIdGenerator = runIdGenerator
        self.randomSource = randomSource
        self.logger = logger
        self.snapshotSink = snapshotSink
    }

    /// Starts the runtime and dataplane.
    /// Preconditions: state is `idle` or `failed`.
    /// Postconditions: state transitions to `running` on success or `failed` on error.
    /// - Parameters:
    ///   - configJSON: Dataplane configuration payload.
    ///   - tunFD: Tunnel file descriptor provided by bridge layer.
    public func start(configJSON: String, tunFD: Int32) async throws {
        guard state == .idle || state == .failed else {
            return
        }

        state = .starting
        setupStartedAt = await clock.now()
        let newRunId = await runIdGenerator.nextRunId()
        let entropy = await randomSource.nextUInt64()
        let newSessionId = "session-\(String(entropy, radix: 16))"
        runId = newRunId
        sessionId = newSessionId

        await logger.log(
            level: .notice,
            phase: .lifecycle,
            category: .control,
            component: "TunnelRuntime",
            event: "start",
            runId: newRunId,
            sessionId: newSessionId,
            message: "Starting runtime"
        )

        let callbacks = DataplaneCallbacks(
            onLog: { [logger] value in
                Task {
                    await logger.log(
                        level: .debug,
                        phase: .relay,
                        category: .dataplane,
                        component: "DataplaneCallback",
                        event: "log",
                        message: value
                    )
                }
            },
            onState: { [logger] state in
                Task {
                    await logger.log(
                        level: .debug,
                        phase: .relay,
                        category: .dataplane,
                        component: "DataplaneCallback",
                        event: "state",
                        result: "\(state.rawValue)",
                        message: "Dataplane state callback"
                    )
                }
            }
        )

        do {
            let handle = try DataplaneHandle(
                configJSON: configJSON,
                callbacks: callbacks,
                logger: logger
            )
            dataplane = handle
            try await handle.start(tunFD: tunFD)
            state = .running
            await publishSnapshot()
        } catch {
            if let dataplane {
                try? await dataplane.stop()
                await dataplane.destroy()
                self.dataplane = nil
            }
            state = .failed
            await logger.log(
                level: .error,
                phase: .lifecycle,
                category: .control,
                component: "TunnelRuntime",
                event: "start-failed",
                runId: newRunId,
                sessionId: newSessionId,
                errorCode: String(describing: error),
                message: "Runtime failed to start"
            )
            throw error
        }
    }

    /// Stops the runtime and dataplane.
    /// Preconditions: state is `running` or `starting`.
    /// Postconditions: state transitions to `idle` and dataplane handle is released.
    public func stop() async throws {
        guard state == .running || state == .starting else {
            return
        }

        state = .stopping
        if let dataplane {
            do {
                try await dataplane.stop()
            } catch {
                await dataplane.destroy()
                self.dataplane = nil
                state = .failed
                await logger.log(
                    level: .error,
                    phase: .lifecycle,
                    category: .control,
                    component: "TunnelRuntime",
                    event: "stop-failed",
                    runId: runId,
                    sessionId: sessionId,
                    errorCode: String(describing: error),
                    message: "Runtime dataplane stop failed; handle was destroyed"
                )
                throw error
            }
            await dataplane.destroy()
            self.dataplane = nil
        }
        state = .idle
        await logger.log(
            level: .notice,
            phase: .lifecycle,
            category: .control,
            component: "TunnelRuntime",
            event: "stop",
            runId: runId,
            sessionId: sessionId,
            message: "Runtime stopped"
        )
        await publishSnapshot()
    }

    /// Records current queue and relay pressure signals for diagnostics.
    /// - Parameters:
    ///   - queueDepth: Current queue depth signal.
    ///   - relayLatencyMs: Current relay latency estimate in milliseconds.
    public func updatePressure(queueDepth: Int, relayLatencyMs: Int) async {
        self.queueDepth = queueDepth
        self.relayLatencyMs = relayLatencyMs
        await publishSnapshot()
    }

    /// Returns current runtime state value.
    public func currentState() -> RuntimeState {
        state
    }

    /// Returns a runtime snapshot suitable for diagnostics and lightweight health sampling.
    public func currentSnapshot() async -> RuntimeSnapshot {
        let setupLatency = await setupLatencyMs()
        return RuntimeSnapshot(
            state: state,
            runId: runId,
            sessionId: sessionId,
            setupLatencyMs: setupLatency,
            relayLatencyMs: relayLatencyMs,
            queueDepth: queueDepth
        )
    }

    private func publishSnapshot() async {
        guard let snapshotSink else {
            return
        }
        await snapshotSink.publish(await currentSnapshot())
    }

    private func setupLatencyMs() async -> Int {
        guard let setupStartedAt else {
            return 0
        }
        let now = await clock.now()
        return Int((now.timeIntervalSince(setupStartedAt) * 1000).rounded())
    }
}
