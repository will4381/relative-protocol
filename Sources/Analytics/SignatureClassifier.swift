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
    private struct CompiledSignature: Sendable, Equatable {
        let label: String
        let domains: [String]
    }

    private let logger: StructuredLogger
    private let decoder: JSONDecoder
    private let maxCachedLookups = 4_096

    private var cache: SignatureDocument?
    private var cacheURL: URL?
    private var compiledSignatures: [CompiledSignature] = []
    private var classificationCache: [String: String?] = [:]

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
        compiledSignatures = document.signatures.map { signature in
            CompiledSignature(
                label: signature.label,
                domains: signature.domains.map { $0.lowercased() }
            )
        }
        classificationCache.removeAll(keepingCapacity: false)
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
        guard cache != nil else {
            return nil
        }
        let normalized = host.lowercased()
        if let cached = classificationCache[normalized] {
            return cached
        }

        let classification = compiledSignatures.first { signature in
            signature.domains.contains(where: normalized.hasSuffix)
        }?.label

        if classificationCache.count >= maxCachedLookups {
            classificationCache.removeAll(keepingCapacity: true)
        }
        classificationCache[normalized] = classification
        return classification
    }
}
