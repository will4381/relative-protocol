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
    private struct SignatureMatch: Sendable, Equatable {
        let order: Int
        let label: String
        let suffixLength: Int
    }

    private struct SuffixTrieNode: Sendable, Equatable {
        var children: [Character: Int] = [:]
        var match: SignatureMatch?
    }

    private let logger: StructuredLogger
    private let decoder: JSONDecoder
    private let maxCachedLookups = 4_096

    private var cache: SignatureDocument?
    private var cacheURL: URL?
    private var suffixTrieNodes: [SuffixTrieNode] = [SuffixTrieNode()]
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
        suffixTrieNodes = [SuffixTrieNode()]
        for (order, signature) in document.signatures.enumerated() {
            for domain in signature.domains {
                insertSignatureSuffix(domain.lowercased(), label: signature.label, order: order)
            }
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
        let normalized = host
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
        guard !normalized.isEmpty else {
            return nil
        }
        if let cached = classificationCache[normalized] {
            return cached
        }

        let classification = indexedClassification(for: normalized)

        if classificationCache.count >= maxCachedLookups {
            classificationCache.removeAll(keepingCapacity: true)
        }
        classificationCache[normalized] = classification
        return classification
    }

    private func indexedClassification(for normalizedHost: String) -> String? {
        var nodeIndex = 0
        var bestMatch = suffixTrieNodes[nodeIndex].match
        for character in normalizedHost.reversed() {
            guard let nextIndex = suffixTrieNodes[nodeIndex].children[character] else {
                break
            }
            nodeIndex = nextIndex
            guard let match = suffixTrieNodes[nodeIndex].match else {
                continue
            }
            guard Self.isDomainBoundaryMatch(host: normalizedHost, suffixLength: match.suffixLength) else {
                continue
            }
            if bestMatch == nil || match.order < bestMatch!.order {
                bestMatch = match
            }
        }
        return bestMatch?.label
    }

    private static func isDomainBoundaryMatch(host: String, suffixLength: Int) -> Bool {
        guard suffixLength > 0, suffixLength <= host.count else {
            return false
        }
        if suffixLength == host.count {
            return true
        }
        let boundaryIndex = host.index(host.endIndex, offsetBy: -suffixLength - 1)
        return host[boundaryIndex] == "."
    }

    private func insertSignatureSuffix(_ suffix: String, label: String, order: Int) {
        var nodeIndex = 0
        for character in suffix.reversed() {
            if let nextIndex = suffixTrieNodes[nodeIndex].children[character] {
                nodeIndex = nextIndex
            } else {
                let nextIndex = suffixTrieNodes.count
                suffixTrieNodes.append(SuffixTrieNode())
                suffixTrieNodes[nodeIndex].children[character] = nextIndex
                nodeIndex = nextIndex
            }
        }

        let match = SignatureMatch(order: order, label: label, suffixLength: suffix.count)
        if let existingMatch = suffixTrieNodes[nodeIndex].match,
           existingMatch.order <= order {
            return
        }
        suffixTrieNodes[nodeIndex].match = match
    }
}
