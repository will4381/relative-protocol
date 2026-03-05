import Analytics
import Foundation
import TunnelRuntime

/// Produces deterministic packet samples for a harness scenario.
public protocol LocalFlowAdapter: Sendable {
    /// Produces packet samples and streams them to `emit`.
    /// - Parameters:
    ///   - scenario: Scenario definition controlling volume and pacing.
    ///   - clock: Deterministic clock used for timestamps/advancement.
    ///   - random: Deterministic random source used for generated identifiers.
    ///   - emit: Async callback that receives generated packet samples.
    func producePackets(
        scenario: HarnessScenario,
        clock: any Clock,
        random: any RandomSource,
        emit: @escaping @Sendable (PacketSample) async throws -> Void
    ) async throws
}

/// Deterministic synthetic packet source used by local replay tests.
public struct SyntheticFlowAdapter: LocalFlowAdapter {
    /// Creates a synthetic flow adapter with no mutable state.
    public init() {}

    /// Generates one outbound sample per scenario step.
    /// - Parameters:
    ///   - scenario: Scenario containing ordered synthetic steps.
    ///   - clock: Time source for sample timestamps and cadence advancement.
    ///   - random: Random source for generated flow identifiers.
    ///   - emit: Callback that receives produced packet samples.
    public func producePackets(
        scenario: HarnessScenario,
        clock: any Clock,
        random: any RandomSource,
        emit: @escaping @Sendable (PacketSample) async throws -> Void
    ) async throws {
        for step in scenario.steps {
            let sample = PacketSample(
                timestamp: await clock.now(),
                direction: "outbound",
                flowId: "flow-\(await random.nextUInt64())",
                bytes: step.payloadBytes,
                protocolHint: step.event
            )
            try await emit(sample)
            await clock.advance(by: Double(scenario.timing.stepIntervalMs) / 1000.0)
        }
    }
}
