import Foundation

/// Time source abstraction to make runtime and analytics deterministic in tests.
public protocol Clock: Sendable {
    /// Returns current clock time.
    func now() async -> Date
    /// Suspends until at least `seconds` have elapsed for this clock.
    /// - Parameter seconds: Duration to sleep.
    func sleep(for seconds: TimeInterval) async throws
    /// Advances clock time when supported by implementation.
    /// - Parameter seconds: Positive duration to advance.
    func advance(by seconds: TimeInterval) async
}

/// Production clock that delegates to system wall time.
public struct SystemClock: Clock {
    /// Creates a system-backed clock.
    public init() {}

    /// Returns current wall-clock time.
    public func now() async -> Date {
        Date()
    }

    /// Sleeps the current task using system monotonic clock.
    /// - Parameter seconds: Duration to sleep. Non-positive values are ignored.
    public func sleep(for seconds: TimeInterval) async throws {
        guard seconds > 0 else {
            return
        }
        try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }

    /// No-op for system clock because wall time cannot be manually advanced.
    public func advance(by _: TimeInterval) async {
        // System clock cannot be manually advanced.
    }
}

/// Manual clock with deterministic advancement for replay tests and harness scenarios.
public actor DeterministicClock: Clock {
    private struct Waiter {
        let wakeTime: Date
        let continuation: CheckedContinuation<Void, Error>
    }

    private var currentTime: Date
    private var waiters: [Waiter] = []

    /// Creates a deterministic clock with explicit start time.
    /// - Parameter startTime: Initial clock time.
    public init(startTime: Date) {
        self.currentTime = startTime
    }

    /// Returns current deterministic time.
    public func now() async -> Date {
        currentTime
    }

    /// Suspends until deterministic time is advanced by at least `seconds`.
    /// - Parameter seconds: Duration relative to current deterministic time.
    public func sleep(for seconds: TimeInterval) async throws {
        guard seconds > 0 else {
            return
        }
        let wakeTime = currentTime.addingTimeInterval(seconds)
        try await withCheckedThrowingContinuation { continuation in
            waiters.append(Waiter(wakeTime: wakeTime, continuation: continuation))
            waiters.sort { $0.wakeTime < $1.wakeTime }
        }
    }

    /// Advances deterministic time and resumes any now-ready waiters.
    /// - Parameter seconds: Non-negative time delta.
    public func advance(by seconds: TimeInterval) async {
        guard seconds >= 0 else {
            return
        }
        currentTime = currentTime.addingTimeInterval(seconds)
        var ready: [Waiter] = []
        while let first = waiters.first, first.wakeTime <= currentTime {
            ready.append(waiters.removeFirst())
        }
        for waiter in ready {
            waiter.continuation.resume()
        }
    }
}

/// Run identifier source shared by runtime, analytics, and harness.
public protocol RunIdGenerator: Sendable {
    /// Returns the next run identifier.
    func nextRunId() async -> String
}

/// Deterministic run-id generator for replay and snapshot tests.
public actor DeterministicRunIdGenerator: RunIdGenerator {
    private let prefix: String
    private var counter: UInt64

    /// Creates a deterministic run-id generator.
    /// - Parameters:
    ///   - prefix: Prefix applied to each generated identifier.
    ///   - start: Starting counter value before first generated ID.
    public init(prefix: String = "run", start: UInt64 = 0) {
        self.prefix = prefix
        self.counter = start
    }

    /// Returns the next monotonically increasing run ID.
    public func nextRunId() async -> String {
        counter += 1
        return "\(prefix)-\(counter)"
    }
}

/// Random run-id generator for production sessions.
public struct RandomRunIdGenerator: RunIdGenerator {
    /// Creates a random UUID-backed run-id generator.
    public init() {}

    /// Returns a lowercase UUID string.
    public func nextRunId() async -> String {
        UUID().uuidString.lowercased()
    }
}

/// Randomness abstraction with deterministic and nondeterministic implementations.
public protocol RandomSource: Sendable {
    /// Returns next pseudo-random 64-bit unsigned value.
    func nextUInt64() async -> UInt64
}

/// Seeded linear-congruential generator for reproducible replay sequences.
public actor SeededRandomSource: RandomSource {
    private var state: UInt64

    /// Creates a seeded deterministic random source.
    /// - Parameter seed: Initial generator state.
    public init(seed: UInt64) {
        self.state = seed
    }

    /// Returns next LCG value in deterministic sequence.
    public func nextUInt64() async -> UInt64 {
        state = 6364136223846793005 &* state &+ 1
        return state
    }
}

/// Wrapper around system random source for production behavior.
public struct SystemRandomSource: RandomSource {
    /// Creates a system-random source.
    public init() {}

    /// Returns next system-generated random `UInt64`.
    public func nextUInt64() async -> UInt64 {
        UInt64.random(in: UInt64.min ... UInt64.max)
    }
}
