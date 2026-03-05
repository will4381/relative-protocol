import Foundation

/// Stable runtime state machine values.
public enum RuntimeState: String, Sendable, Equatable {
    case idle
    case starting
    case running
    case stopping
    case failed
}

/// Memory budget profiles used for jetsam-aware mitigation strategies.
public enum RuntimeProfile: String, Codable, Sendable {
    case phoneSmall
    case phoneLarge
    case tablet
    case desktop
}

/// Tunable memory thresholds used by the runtime and analytics workers.
public struct MemoryBudget: Sendable, Equatable {
    public let softLimitBytes: Int
    public let hardLimitBytes: Int

    /// - Parameters:
    ///   - softLimitBytes: Soft memory limit where mitigation should begin.
    ///   - hardLimitBytes: Hard memory limit where aggressive shedding should occur.
    public init(softLimitBytes: Int, hardLimitBytes: Int) {
        self.softLimitBytes = softLimitBytes
        self.hardLimitBytes = hardLimitBytes
    }
}

/// Maps runtime profiles to memory budget thresholds.
public enum RuntimeBudgets {
    /// Returns the memory budget associated with a runtime profile.
    /// - Parameter profile: Device/runtime profile.
    /// - Returns: Memory budget values for the profile.
    public static func budget(for profile: RuntimeProfile) -> MemoryBudget {
        switch profile {
        case .phoneSmall:
            return MemoryBudget(softLimitBytes: 48 * 1024 * 1024, hardLimitBytes: 64 * 1024 * 1024)
        case .phoneLarge:
            return MemoryBudget(softLimitBytes: 64 * 1024 * 1024, hardLimitBytes: 96 * 1024 * 1024)
        case .tablet:
            return MemoryBudget(softLimitBytes: 96 * 1024 * 1024, hardLimitBytes: 128 * 1024 * 1024)
        case .desktop:
            return MemoryBudget(softLimitBytes: 192 * 1024 * 1024, hardLimitBytes: 256 * 1024 * 1024)
        }
    }
}

/// Runtime snapshot used by diagnostics and periodic performance logs.
public struct RuntimeSnapshot: Sendable, Equatable {
    public let state: RuntimeState
    public let runId: String?
    public let sessionId: String?
    public let setupLatencyMs: Int
    public let relayLatencyMs: Int
    public let queueDepth: Int

    /// - Parameters:
    ///   - state: Current runtime state.
    ///   - runId: Current run identifier.
    ///   - sessionId: Current session identifier.
    ///   - setupLatencyMs: Setup latency in milliseconds.
    ///   - relayLatencyMs: Relay latency in milliseconds.
    ///   - queueDepth: Current queue depth used for pressure signals.
    public init(
        state: RuntimeState,
        runId: String?,
        sessionId: String?,
        setupLatencyMs: Int,
        relayLatencyMs: Int,
        queueDepth: Int
    ) {
        self.state = state
        self.runId = runId
        self.sessionId = sessionId
        self.setupLatencyMs = setupLatencyMs
        self.relayLatencyMs = relayLatencyMs
        self.queueDepth = queueDepth
    }
}

/// Hook for analytics modules to receive runtime performance snapshots.
public protocol RuntimeSnapshotSink: Sendable {
    /// Publishes one runtime snapshot to a sink.
    /// - Parameter snapshot: Runtime snapshot payload.
    func publish(_ snapshot: RuntimeSnapshot) async
}
