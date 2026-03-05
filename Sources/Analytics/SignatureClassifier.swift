import Foundation
import Observability

/// One classification label with matching domain suffixes.
public struct SignatureEntry: Codable, Sendable, Equatable {
    public let label: String
    public let domains: [String]

    /// - Parameters:
    ///   - label: Classification label emitted when any domain suffix matches.
    ///   - domains: Domain suffixes associated with `label`.
    public init(label: String, domains: [String]) {
        self.label = label
        self.domains = domains
    }
}

/// Top-level signature payload loaded from disk.
public struct SignatureDocument: Codable, Sendable, Equatable {
    public let version: Int
    public let updatedAt: Date
    public let signatures: [SignatureEntry]

    /// - Parameters:
    ///   - version: Schema or payload version.
    ///   - updatedAt: Source document update timestamp.
    ///   - signatures: Signature entries used for classification.
    public init(version: Int, updatedAt: Date, signatures: [SignatureEntry]) {
        self.version = version
        self.updatedAt = updatedAt
        self.signatures = signatures
    }
}

/// Signature classifier with on-demand reload and in-memory cache.
public actor SignatureClassifier {
    private let logger: StructuredLogger
    private let decoder: JSONDecoder

    private var cache: SignatureDocument?
    private var cacheURL: URL?

    /// Creates a classifier with an empty in-memory cache.
    /// - Parameter logger: Structured logger used for reload events and errors.
    public init(logger: StructuredLogger) {
        self.logger = logger
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    /// Loads signatures from disk and replaces the in-memory cache atomically.
    /// - Parameter url: JSON file containing a `SignatureDocument`.
    /// - Throws: File read or decode errors.
    public func load(from url: URL) async throws {
        let payload = try Data(contentsOf: url)
        let document = try decoder.decode(SignatureDocument.self, from: payload)
        cache = document
        cacheURL = url
        await logger.log(
            level: .info,
            phase: .config,
            category: .analyticsClassifier,
            component: "SignatureClassifier",
            event: "reload",
            message: "Loaded signatures",
            metadata: [
                "count": String(document.signatures.count),
                "source": url.path
            ]
        )
    }

    /// Resolves a hostname to a classification label using suffix matching.
    /// - Parameter host: Hostname to classify.
    /// - Returns: Matching label, or `nil` when no signature matches.
    public func classify(host: String) -> String? {
        guard let cache else {
            return nil
        }
        let normalized = host.lowercased()
        for signature in cache.signatures {
            if signature.domains.contains(where: { normalized.hasSuffix($0.lowercased()) }) {
                return signature.label
            }
        }
        return nil
    }

    /// Returns the currently cached signature document, if loaded.
    public func cachedDocument() -> SignatureDocument? {
        cache
    }

    /// Returns the filesystem path of the currently loaded signature document.
    public func cachedSourcePath() -> String? {
        cacheURL?.path
    }
}
