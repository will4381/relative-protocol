import Foundation
import Observability
import TunnelRuntime

/// Persistent bounded metrics store with ring semantics and configurable file budget.
public actor MetricsStore: RuntimeSnapshotSink {
    private var ring: MetricsRingBuffer<MetricRecord>
    private let capacity: Int
    private let maxBytes: Int
    private let outputURL: URL
    private let clock: any Clock
    private let logger: StructuredLogger
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    /// Creates a bounded metrics store with on-disk persistence.
    /// - Parameters:
    ///   - capacity: Max metric records retained in memory.
    ///   - maxBytes: Max serialized payload size allowed on disk.
    ///   - outputURL: File path used for persisted metrics JSON.
    ///   - clock: Time source used for deterministic metric timestamps.
    ///   - logger: Structured logger used for persistence errors.
    public init(capacity: Int, maxBytes: Int, outputURL: URL, clock: any Clock = SystemClock(), logger: StructuredLogger) {
        self.capacity = max(1, capacity)
        self.ring = MetricsRingBuffer(capacity: max(1, capacity))
        self.maxBytes = maxBytes
        self.outputURL = outputURL
        self.clock = clock
        self.logger = logger
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder.dateDecodingStrategy = .iso8601
    }

    /// Runtime snapshot sink hook. Converts runtime pressure into a metric record.
    /// - Parameter snapshot: Runtime snapshot to persist.
    public func publish(_ snapshot: RuntimeSnapshot) async {
        let timestamp = await clock.now()
        let record = MetricRecord(
            name: "runtime.queueDepth",
            value: Double(snapshot.queueDepth),
            timestamp: timestamp
        )
        await append(record)
    }

    /// Appends one metric record and persists bounded state to disk.
    /// - Parameter record: Metric entry to append.
    public func append(_ record: MetricRecord) async {
        ring.append(record)
        do {
            try persist()
        } catch {
            await logger.log(
                level: .error,
                phase: .storage,
                category: .analyticsMetrics,
                component: "MetricsStore",
                event: "persist-failed",
                errorCode: String(describing: error),
                message: "Failed to persist metrics"
            )
        }
    }

    /// Returns in-memory metric records in insertion order.
    public func records() -> [MetricRecord] {
        ring.snapshot()
    }

    private func persist() throws {
        let payload = try encoder.encode(ring.snapshot())
        var outputPayload = payload
        if outputPayload.count > maxBytes {
            var trimmed = ring.snapshot()
            while !trimmed.isEmpty {
                trimmed.removeFirst()
                let candidate = try encoder.encode(trimmed)
                if candidate.count <= maxBytes {
                    outputPayload = candidate
                    ring = MetricsRingBuffer(capacity: capacity)
                    for record in trimmed {
                        ring.append(record)
                    }
                    break
                }
            }
        }
        let directory = outputURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try outputPayload.write(to: outputURL, options: .atomic)
    }

    /// Loads persisted metric records from disk.
    /// - Returns: Decoded metric records.
    /// - Throws: File read or decode errors.
    public func loadPersisted() throws -> [MetricRecord] {
        let payload = try Data(contentsOf: outputURL)
        return try decoder.decode([MetricRecord].self, from: payload)
    }
}
