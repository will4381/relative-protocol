import Analytics
import Foundation

/// Snapshot of analytics artifacts persisted by the tunnel extension into the shared App Group container.
/// Invariant: arrays preserve on-disk order so callers can choose their own presentation order.
public struct AppGroupAnalyticsSnapshot: Sendable, Equatable {
    public let metrics: [MetricRecord]
    public let packetSamples: [PacketSample]
    public let lastStopRecord: TunnelStopRecord?

    /// - Parameters:
    ///   - metrics: Persisted metric records decoded from `metrics.json`.
    ///   - packetSamples: Persisted packet samples decoded from `packet-stream.ndjson`.
    ///   - lastStopRecord: Most recent provider stop reason decoded from `last-stop.json`.
    public init(metrics: [MetricRecord], packetSamples: [PacketSample], lastStopRecord: TunnelStopRecord?) {
        self.metrics = metrics
        self.packetSamples = packetSamples
        self.lastStopRecord = lastStopRecord
    }
}

/// Errors surfaced when shared analytics artifacts cannot be resolved from an App Group container.
public enum AppGroupAnalyticsReaderError: LocalizedError {
    case containerUnavailable(String)

    public var errorDescription: String? {
        switch self {
        case .containerUnavailable(let appGroupID):
            return "Shared container is unavailable for App Group '\(appGroupID)'."
        }
    }
}

/// Reads metrics and packet-stream artifacts written by `PacketTunnelProviderShell`.
/// Ownership: values are lightweight and safe to create on demand in host apps.
public struct AppGroupAnalyticsReader: Sendable {
    public let appGroupID: String

    /// - Parameter appGroupID: App Group identifier shared with the tunnel extension.
    public init(appGroupID: String) {
        self.appGroupID = appGroupID
    }

    /// Loads both metrics and packet samples from the shared analytics directory.
    /// - Parameter packetLimit: Optional cap applied to packet samples after decoding.
    /// - Returns: Aggregated shared analytics snapshot.
    /// - Throws: `AppGroupAnalyticsReaderError` when the App Group container is unavailable, or I/O/decode errors.
    public func snapshot(packetLimit: Int? = nil) throws -> AppGroupAnalyticsSnapshot {
        AppGroupAnalyticsSnapshot(
            metrics: try loadMetrics(),
            packetSamples: try loadPacketSamples(limit: packetLimit),
            lastStopRecord: try loadLastStopRecord()
        )
    }

    /// Loads persisted metrics from the shared container.
    /// - Returns: Metric records in insertion order.
    /// - Throws: `AppGroupAnalyticsReaderError` when the App Group container is unavailable, or I/O/decode errors.
    public func loadMetrics() throws -> [MetricRecord] {
        let url = try metricsURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            return []
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([MetricRecord].self, from: Data(contentsOf: url))
    }

    /// Loads persisted packet samples from the shared container.
    /// - Parameter limit: Optional cap applied to the newest decoded samples.
    /// - Returns: Packet samples in file order.
    /// - Throws: `AppGroupAnalyticsReaderError` when the App Group container is unavailable, or I/O/decode errors.
    public func loadPacketSamples(limit: Int? = nil) throws -> [PacketSample] {
        let url = try packetStreamURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            return []
        }

        let content = try String(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let samples = try content
            .split(separator: "\n")
            .map { try decoder.decode(PacketSample.self, from: Data($0.utf8)) }

        guard let limit else {
            return samples
        }
        return Array(samples.suffix(max(0, limit)))
    }

    /// Loads the most recent persisted provider stop reason from the shared container.
    /// - Returns: Decoded stop record, or `nil` if the tunnel has not stopped yet.
    /// - Throws: `AppGroupAnalyticsReaderError` when the App Group container is unavailable, or I/O/decode errors.
    public func loadLastStopRecord() throws -> TunnelStopRecord? {
        let url = try lastStopURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(TunnelStopRecord.self, from: Data(contentsOf: url))
    }

    /// Deletes the shared metrics, packet-stream, and last-stop files while preserving the analytics directory itself.
    /// - Throws: `AppGroupAnalyticsReaderError` when the App Group container is unavailable, or file deletion errors.
    public func clear() throws {
        let fileManager = FileManager.default
        let metricsURL = try metricsURL()
        let packetStreamURL = try packetStreamURL()
        let lastStopURL = try lastStopURL()

        if fileManager.fileExists(atPath: metricsURL.path) {
            try fileManager.removeItem(at: metricsURL)
        }
        if fileManager.fileExists(atPath: packetStreamURL.path) {
            try fileManager.removeItem(at: packetStreamURL)
        }
        if fileManager.fileExists(atPath: lastStopURL.path) {
            try fileManager.removeItem(at: lastStopURL)
        }
    }

    private func metricsURL() throws -> URL {
        try analyticsRootURL().appendingPathComponent("metrics.json", isDirectory: false)
    }

    private func packetStreamURL() throws -> URL {
        try analyticsRootURL().appendingPathComponent("packet-stream.ndjson", isDirectory: false)
    }

    private func lastStopURL() throws -> URL {
        try analyticsRootURL().appendingPathComponent("last-stop.json", isDirectory: false)
    }

    private func analyticsRootURL() throws -> URL {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            throw AppGroupAnalyticsReaderError.containerUnavailable(appGroupID)
        }
        return container.appendingPathComponent("Analytics", isDirectory: true)
    }
}
