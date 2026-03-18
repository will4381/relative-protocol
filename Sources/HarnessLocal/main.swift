import Foundation
import Observability

/// CLI entrypoint for deterministic local harness runs.
/// Usage: `HarnessLocal <scenario.json>`.
private func runHarness() async -> Int32 {
    do {
        let args = CommandLine.arguments
        guard args.count >= 2 else {
            fputs("Usage: HarnessLocal <scenario.json>\n", stderr)
            return 1
        }

        let scenarioURL = URL(fileURLWithPath: args[1])
        let scenario = try HarnessScenario.load(from: scenarioURL)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("HarnessLocal-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sink = InMemoryLogSink()
        let logger = StructuredLogger(sink: sink)
        let runner = HarnessRunner(logger: logger)
        let result = try await runner.run(scenario: scenario, adapter: SyntheticFlowAdapter(), rootPath: root)

        let output = [
            "scenario": result.scenarioID,
            "state": result.runtimeState.rawValue,
            "packets": String(result.packetCount)
        ]
        print(output)
        return 0
    } catch {
        fputs("HarnessLocal error: \(error)\n", stderr)
        return 2
    }
}

let semaphore = DispatchSemaphore(value: 0)
var exitCode: Int32 = 0
Task {
    exitCode = await runHarness()
    semaphore.signal()
}
semaphore.wait()
exit(exitCode)
