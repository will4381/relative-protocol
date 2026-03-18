import Foundation

/// Small persisted store for durable detector outputs.
/// Decision: durable detector state survives long background spans, while the raw packet tap remains memory-only.
public struct DetectionStore: Sendable {
    public let fileURL: URL

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    public func load() throws -> DetectionSnapshot? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(DetectionSnapshot.self, from: Data(contentsOf: fileURL))
    }

    public func persist(_ snapshot: DetectionSnapshot) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let payload = try encoder.encode(snapshot.redactedForPersistence())

        // Docs: https://developer.apple.com/documentation/foundation/data/write(to:options:)
        // Detector writes are intentionally tiny and infrequent, so an atomic protected replace is an acceptable
        // durability tradeoff without bringing packet-level disk churn back into the tunnel hot path.
        try ProtectedAnalyticsFileIO.writeProtectedData(payload, to: fileURL)
    }

    public func clear() throws {
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
    }
}
