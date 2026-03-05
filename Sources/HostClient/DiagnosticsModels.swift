import Foundation
import TunnelRuntime

/// Snapshot returned to host-side diagnostics clients.
/// Captures point-in-time runtime state and lightweight counters.
public struct DiagnosticsSnapshot: Sendable, Equatable {
    public let capturedAt: Date
    public let runtime: RuntimeSnapshot
    public let metricsCount: Int
    public let packetSamplesCount: Int

    /// - Parameters:
    ///   - capturedAt: Snapshot capture time.
    ///   - runtime: Runtime state snapshot.
    ///   - metricsCount: Number of persisted metric records.
    ///   - packetSamplesCount: Number of persisted packet stream samples.
    public init(capturedAt: Date, runtime: RuntimeSnapshot, metricsCount: Int, packetSamplesCount: Int) {
        self.capturedAt = capturedAt
        self.runtime = runtime
        self.metricsCount = metricsCount
        self.packetSamplesCount = packetSamplesCount
    }
}
