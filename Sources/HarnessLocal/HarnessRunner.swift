import Analytics
import Foundation
import Observability
import PacketRelay
import TunnelRuntime

/// Summary produced by one harness scenario execution.
public struct HarnessRunResult: Sendable, Equatable {
    public let scenarioID: String
    public let runtimeState: RuntimeState
    public let packetCount: Int

    /// - Parameters:
    ///   - scenarioID: Scenario identifier used for this run.
    ///   - runtimeState: Final runtime state after scenario completion.
    ///   - packetCount: Number of retained packet samples in the rolling tap.
    public init(scenarioID: String, runtimeState: RuntimeState, packetCount: Int) {
        self.scenarioID = scenarioID
        self.runtimeState = runtimeState
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
    ///   - rootPath: Reserved diagnostics root for harness callers.
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

        _ = rootPath

        let packetStream = PacketSampleStream(maxBytes: 256_000, clock: clock, logger: logger)
        let runtime = TunnelRuntime(
            clock: clock,
            runIdGenerator: runIds,
            randomSource: random,
            logger: logger
        )

        try await runtime.start(configJSON: "{\"mode\":\"deterministic-local\"}", tunFD: 0)

        try await adapter.producePackets(scenario: scenario, clock: clock, random: random) { sample in
            try await packetStream.append(sample)
            await runtime.updatePressure(queueDepth: sample.bytes, relayLatencyMs: sample.bytes / 4)
        }

        let runtimeSnapshot = await runtime.currentSnapshot()
        let packetCount = await packetStream.readAll().count

        try await runtime.stop()

        return HarnessRunResult(
            scenarioID: scenario.id,
            runtimeState: runtimeSnapshot.state,
            packetCount: packetCount
        )
    }
}
