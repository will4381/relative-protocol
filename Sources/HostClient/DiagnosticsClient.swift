import Analytics
import Foundation
import TunnelRuntime

/// App-facing diagnostics API for querying runtime and analytics snapshots.
public actor DiagnosticsClient {
    private let runtime: TunnelRuntime
    private let metricsStore: MetricsStore
    private let packetStream: PacketSampleStream

    /// Creates a diagnostics client backed by runtime and analytics stores.
    /// - Parameters:
    ///   - runtime: Runtime state source.
    ///   - metricsStore: Metrics persistence source.
    ///   - packetStream: Packet sample stream source.
    public init(runtime: TunnelRuntime, metricsStore: MetricsStore, packetStream: PacketSampleStream) {
        self.runtime = runtime
        self.metricsStore = metricsStore
        self.packetStream = packetStream
    }

    /// Collects a point-in-time diagnostics snapshot for host apps.
    /// - Returns: Aggregated diagnostics snapshot payload.
    /// - Throws: Errors while reading packet stream storage.
    public func snapshot() async throws -> DiagnosticsSnapshot {
        let runtimeSnapshot = await runtime.currentSnapshot()
        let metrics = await metricsStore.records()
        let packets = try await packetStream.readAll()
        return DiagnosticsSnapshot(
            capturedAt: Date(),
            runtime: runtimeSnapshot,
            metricsCount: metrics.count,
            packetSamplesCount: packets.count
        )
    }
}
