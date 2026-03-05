import Analytics
import Foundation
import HostClient
import Observability
import PacketRelay
import TunnelRuntime

/// Summary produced by one harness scenario execution.
public struct HarnessRunResult: Sendable, Equatable {
    public let scenarioID: String
    public let runtimeState: RuntimeState
    public let metricsCount: Int
    public let packetCount: Int

    /// - Parameters:
    ///   - scenarioID: Scenario identifier used for this run.
    ///   - runtimeState: Final runtime state after scenario completion.
    ///   - metricsCount: Number of persisted metric entries.
    ///   - packetCount: Number of persisted packet samples.
    public init(scenarioID: String, runtimeState: RuntimeState, metricsCount: Int, packetCount: Int) {
        self.scenarioID = scenarioID
        self.runtimeState = runtimeState
        self.metricsCount = metricsCount
        self.packetCount = packetCount
    }
}

/// Deterministic harness runner for local flow and replay tests.
public actor HarnessRunner {
    private let logger: StructuredLogger

    /// Creates a harness runner.
    /// - Parameter logger: Structured logger for harness/runtime diagnostics.
    public init(logger: StructuredLogger) {
        self.logger = logger
    }

    /// Executes one harness scenario end-to-end.
    /// - Parameters:
    ///   - scenario: Deterministic scenario definition.
    ///   - adapter: Local packet producer adapter.
    ///   - rootPath: Output directory for metrics and packet stream artifacts.
    /// - Returns: High-level scenario result summary.
    public func run(
        scenario: HarnessScenario,
        adapter: any LocalFlowAdapter,
        rootPath: URL
    ) async throws -> HarnessRunResult {
        let formatter = ISO8601DateFormatter()
        let start = formatter.date(from: scenario.timing.startTimeISO8601) ?? Date(timeIntervalSince1970: 0)
        let clock = DeterministicClock(startTime: start)
        let runIds = DeterministicRunIdGenerator(prefix: scenario.id, start: 0)
        let random = SeededRandomSource(seed: scenario.seed)

        let metricsURL = rootPath.appendingPathComponent("metrics.json", isDirectory: false)
        let streamURL = rootPath.appendingPathComponent("packet-stream.ndjson", isDirectory: false)

        let metricsStore = MetricsStore(capacity: 128, maxBytes: 256_000, outputURL: metricsURL, logger: logger)
        let packetStream = PacketSampleStream(maxBytes: 256_000, url: streamURL, logger: logger)
        let runtime = TunnelRuntime(
            clock: clock,
            runIdGenerator: runIds,
            randomSource: random,
            logger: logger,
            snapshotSink: metricsStore
        )

        try await runtime.start(configJSON: "{\"mode\":\"deterministic-local\"}", tunFD: 0)

        try await adapter.producePackets(scenario: scenario, clock: clock, random: random) { sample in
            try await packetStream.append(sample)
            await runtime.updatePressure(queueDepth: sample.bytes, relayLatencyMs: sample.bytes / 4)
        }

        let diagnostics = DiagnosticsClient(runtime: runtime, metricsStore: metricsStore, packetStream: packetStream)
        let snapshot = try await diagnostics.snapshot()

        try await runtime.stop()

        return HarnessRunResult(
            scenarioID: scenario.id,
            runtimeState: snapshot.runtime.state,
            metricsCount: snapshot.metricsCount,
            packetCount: snapshot.packetSamplesCount
        )
    }
}
