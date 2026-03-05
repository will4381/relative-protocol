import Foundation

/// Timing controls for deterministic replay execution.
public struct HarnessTiming: Codable, Sendable, Equatable {
    /// Scenario wall-clock start timestamp (ISO-8601).
    public let startTimeISO8601: String
    /// Millisecond delay between synthetic steps.
    public let stepIntervalMs: Int

    public enum CodingKeys: String, CodingKey {
        case startTimeISO8601 = "start_time"
        case stepIntervalMs = "step_interval_ms"
    }

    /// - Parameters:
    ///   - startTimeISO8601: ISO-8601 start timestamp.
    ///   - stepIntervalMs: Inter-step interval in milliseconds.
    public init(startTimeISO8601: String, stepIntervalMs: Int) {
        self.startTimeISO8601 = startTimeISO8601
        self.stepIntervalMs = stepIntervalMs
    }
}

/// One synthetic event in a harness scenario file.
public struct HarnessStep: Codable, Sendable, Equatable {
    /// Event kind consumed by local adapters.
    public let event: String
    /// Payload byte size used to shape generated traffic.
    public let payloadBytes: Int

    public enum CodingKeys: String, CodingKey {
        case event
        case payloadBytes = "payload_bytes"
    }

    /// - Parameters:
    ///   - event: Adapter event token.
    ///   - payloadBytes: Generated payload size.
    public init(event: String, payloadBytes: Int) {
        self.event = event
        self.payloadBytes = payloadBytes
    }
}

/// Replay scenario contract used by `HarnessRunner`.
public struct HarnessScenario: Codable, Sendable, Equatable {
    public let id: String
    public let durationSeconds: Int
    public let seed: UInt64
    public let inputProfile: String
    public let timing: HarnessTiming
    public let steps: [HarnessStep]

    public enum CodingKeys: String, CodingKey {
        case id
        case durationSeconds = "duration_seconds"
        case seed
        case inputProfile = "input_profile"
        case timing
        case steps
    }

    /// - Parameters:
    ///   - id: Stable scenario identifier.
    ///   - durationSeconds: Scenario duration budget.
    ///   - seed: Deterministic seed used by random sources.
    ///   - inputProfile: Named input shape profile.
    ///   - timing: Timing controls for replay.
    ///   - steps: Ordered synthetic events.
    public init(
        id: String,
        durationSeconds: Int,
        seed: UInt64,
        inputProfile: String,
        timing: HarnessTiming,
        steps: [HarnessStep]
    ) {
        self.id = id
        self.durationSeconds = durationSeconds
        self.seed = seed
        self.inputProfile = inputProfile
        self.timing = timing
        self.steps = steps
    }

    /// Loads and decodes a scenario from JSON.
    /// - Parameter url: Scenario JSON file URL.
    public static func load(from url: URL) throws -> HarnessScenario {
        let decoder = JSONDecoder()
        return try decoder.decode(HarnessScenario.self, from: Data(contentsOf: url))
    }
}
