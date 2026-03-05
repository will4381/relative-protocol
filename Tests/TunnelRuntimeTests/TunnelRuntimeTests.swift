import Observability
import TunnelRuntime
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// Runtime state machine determinism and lifecycle tests.
final class TunnelRuntimeTests: XCTestCase {
    private let deterministicLocalConfig = "{\"mode\":\"deterministic-local\"}"

    /// Verifies lifecycle transitions `idle -> running -> idle`.
    func testStateTransitionsStartAndStop() async throws {
        let sink = InMemoryLogSink()
        let runtime = TunnelRuntime(
            clock: SystemClock(),
            runIdGenerator: DeterministicRunIdGenerator(),
            randomSource: SeededRandomSource(seed: 1),
            logger: StructuredLogger(sink: sink)
        )

        let initialState = await runtime.currentState()
        XCTAssertEqual(initialState, .idle)
        try await runtime.start(configJSON: deterministicLocalConfig, tunFD: 0)
        let runningState = await runtime.currentState()
        XCTAssertEqual(runningState, .running)
        try await runtime.stop()
        let finalState = await runtime.currentState()
        XCTAssertEqual(finalState, .idle)
    }

    /// Verifies replayable runtime output with deterministic seed.
    func testDeterministicRunIdAndSessionReplay() async throws {
        let first = try await executeReplay(seed: 7)
        let second = try await executeReplay(seed: 7)
        XCTAssertEqual(first, second)
    }

    /// Executes one deterministic runtime cycle and returns final snapshot.
    /// - Parameter seed: Random seed controlling session entropy.
    /// - Returns: Runtime snapshot captured before stop.
    private func executeReplay(seed: UInt64) async throws -> RuntimeSnapshot {
        let clock = DeterministicClock(startTime: Date(timeIntervalSince1970: 0))
        let sink = InMemoryLogSink()
        let runtime = TunnelRuntime(
            clock: clock,
            runIdGenerator: DeterministicRunIdGenerator(prefix: "replay", start: 0),
            randomSource: SeededRandomSource(seed: seed),
            logger: StructuredLogger(sink: sink)
        )

        try await runtime.start(configJSON: deterministicLocalConfig, tunFD: 0)
        await clock.advance(by: 1)
        await runtime.updatePressure(queueDepth: 5, relayLatencyMs: 2)
        let snapshot = await runtime.currentSnapshot()
        try await runtime.stop()
        return snapshot
    }
}
