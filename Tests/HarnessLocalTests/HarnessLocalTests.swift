import Foundation
@testable import HarnessLocal
import Observability
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// Harness replay decoding and determinism tests.
final class HarnessLocalTests: XCTestCase {
    /// Verifies scenario JSON decoding preserves replay seed and timing controls.
    func testScenarioDecodingIncludesSeedAndTiming() throws {
        let url = Bundle.module.url(forResource: "ReplayScenario", withExtension: "json")
        let scenario = try HarnessScenario.load(from: XCTUnwrap(url))

        XCTAssertEqual(scenario.id, "replay-smoke")
        XCTAssertEqual(scenario.seed, 42)
        XCTAssertEqual(scenario.timing.stepIntervalMs, 10)
    }

    /// Verifies deterministic scenarios produce stable summaries across runs.
    func testReplayDeterminismProducesStableSummary() async throws {
        let url = Bundle.module.url(forResource: "ReplayScenario", withExtension: "json")
        let scenario = try HarnessScenario.load(from: XCTUnwrap(url))

        let logger = StructuredLogger(sink: InMemoryLogSink())
        let runner = HarnessRunner(logger: logger)
        let tempRoot = FileManager.default.temporaryDirectory

        let first = try await runner.run(
            scenario: scenario,
            adapter: SyntheticFlowAdapter(),
            rootPath: tempRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        )
        let second = try await runner.run(
            scenario: scenario,
            adapter: SyntheticFlowAdapter(),
            rootPath: tempRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        )

        XCTAssertEqual(first.scenarioID, second.scenarioID)
        XCTAssertEqual(first.packetCount, second.packetCount)
        XCTAssertEqual(first.runtimeState, second.runtimeState)
    }
}
