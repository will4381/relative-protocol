import Foundation
import Observability
import TunnelRuntime

/// One sampled path snapshot captured by `PathSampler`.
public struct PathSample: Sendable, Equatable {
    public let timestamp: Date
    public let metadata: [String: String]

    /// - Parameters:
    ///   - timestamp: Sample capture time.
    ///   - metadata: Path metadata key/value pairs captured at sampling time.
    public init(timestamp: Date, metadata: [String: String]) {
        self.timestamp = timestamp
        self.metadata = metadata
    }
}

/// Cadence-driven path sampler that can be replayed with deterministic clocks.
public actor PathSampler {
    private let clock: any Clock
    private let runIdGenerator: any RunIdGenerator
    private let randomSource: any RandomSource
    private let cadenceSeconds: TimeInterval
    private let logger: StructuredLogger
    private var samples: [PathSample] = []

    /// Creates a cadence-driven sampler with deterministic dependencies.
    /// - Parameters:
    ///   - clock: Time source used for timestamps and replay progression.
    ///   - runIdGenerator: Run-id source used for sample log correlation.
    ///   - randomSource: Random source used for trace IDs.
    ///   - cadenceSeconds: Interval between samples when running scripted loops.
    ///   - logger: Structured logger for sample events.
    public init(
        clock: any Clock,
        runIdGenerator: any RunIdGenerator,
        randomSource: any RandomSource,
        cadenceSeconds: TimeInterval,
        logger: StructuredLogger
    ) {
        self.clock = clock
        self.runIdGenerator = runIdGenerator
        self.randomSource = randomSource
        self.cadenceSeconds = cadenceSeconds
        self.logger = logger
    }

    /// Captures one path sample and emits a structured log event.
    /// - Parameter metadata: Path metadata values to attach to sample and log record.
    public func sample(metadata: [String: String]) async {
        let runId = await runIdGenerator.nextRunId()
        let traceEntropy = await randomSource.nextUInt64()
        let sample = PathSample(timestamp: await clock.now(), metadata: metadata)
        samples.append(sample)
        await logger.log(
            level: .debug,
            phase: .path,
            category: .samplerPath,
            component: "PathSampler",
            event: "sample",
            runId: runId,
            traceId: String(traceEntropy, radix: 16),
            message: "Captured path sample",
            metadata: metadata
        )
    }

    /// Executes repeated sampling using the configured cadence.
    /// - Parameters:
    ///   - iterations: Number of samples to capture. Values `<= 0` are no-ops.
    ///   - provider: Async metadata provider called once per iteration.
    public func run(iterations: Int, provider: @escaping @Sendable () async -> [String: String]) async throws {
        guard iterations > 0 else {
            return
        }
        for index in 0..<iterations {
            await sample(metadata: await provider())
            if index < iterations - 1 {
                await clock.advance(by: cadenceSeconds)
            }
        }
    }

    /// Returns all captured samples in insertion order.
    public func snapshot() -> [PathSample] {
        samples
    }
}
