import Foundation
import Observability

/// One persisted packet sample used by replay and diagnostics flows.
public struct PacketSample: Codable, Sendable, Equatable {
    public let timestamp: Date
    public let direction: String
    public let flowId: String
    public let bytes: Int
    public let protocolHint: String

    /// - Parameters:
    ///   - timestamp: Packet observation time.
    ///   - direction: Packet direction (`inbound` or `outbound`).
    ///   - flowId: Stable flow identifier for grouping.
    ///   - bytes: Packet size in bytes.
    ///   - protocolHint: Transport/protocol hint associated with sample.
    public init(timestamp: Date, direction: String, flowId: String, bytes: Int, protocolHint: String) {
        self.timestamp = timestamp
        self.direction = direction
        self.flowId = flowId
        self.bytes = bytes
        self.protocolHint = protocolHint
    }
}

/// Packet sample NDJSON stream with deterministic truncation behavior.
public actor PacketSampleStream {
    private let maxBytes: Int
    private let url: URL
    private let encoder = JSONEncoder()
    private let logger: StructuredLogger

    /// Creates an NDJSON packet sample sink.
    /// - Parameters:
    ///   - maxBytes: Max file size before truncation.
    ///   - url: NDJSON file destination.
    ///   - logger: Logger used for truncation and storage events.
    public init(maxBytes: Int, url: URL, logger: StructuredLogger) {
        self.maxBytes = maxBytes
        self.url = url
        self.logger = logger
        self.encoder.dateEncodingStrategy = .iso8601
        self.encoder.outputFormatting = [.sortedKeys]
    }

    /// Appends one sample, truncating file content when the size policy is exceeded.
    /// - Parameter sample: Sample to append.
    /// - Throws: I/O errors while writing the stream file.
    public func append(_ sample: PacketSample) async throws {
        let entry = try encodedLine(sample)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)

        let current = (try? Data(contentsOf: url)) ?? Data()
        if current.count + entry.count > maxBytes {
            try entry.write(to: url, options: .atomic)
            await logger.log(
                level: .warning,
                phase: .storage,
                category: .analyticsMetrics,
                component: "PacketSampleStream",
                event: "truncate",
                result: "rotated",
                message: "Packet stream exceeded max bytes and was truncated"
            )
            return
        }

        if FileManager.default.fileExists(atPath: url.path) {
            guard let handle = try? FileHandle(forWritingTo: url) else {
                throw CocoaError(.fileWriteUnknown)
            }
            try handle.seekToEnd()
            try handle.write(contentsOf: entry)
            try handle.close()
        } else {
            try entry.write(to: url, options: .atomic)
        }
    }

    /// Reads and decodes all persisted packet samples.
    /// - Returns: Packet samples in file order.
    /// - Throws: I/O or decode failures.
    public func readAll() throws -> [PacketSample] {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return []
        }
        let content = try String(contentsOf: url)
        return try content
            .split(separator: "\n")
            .map { try decoder.decode(PacketSample.self, from: Data($0.utf8)) }
    }

    private var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private func encodedLine(_ sample: PacketSample) throws -> Data {
        var data = try encoder.encode(sample)
        data.append(0x0A)
        return data
    }
}
