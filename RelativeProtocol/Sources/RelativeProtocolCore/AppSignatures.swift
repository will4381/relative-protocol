// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation

public struct AppSignature: Codable, Hashable, Sendable {
    public let label: String
    public let domains: [String]

    public init(label: String, domains: [String]) {
        self.label = label
        self.domains = domains
    }
}

public struct AppSignatureSet: Codable, Sendable {
    public let version: Int?
    public let updatedAt: String?
    public let signatures: [AppSignature]

    public init(version: Int? = nil, updatedAt: String? = nil, signatures: [AppSignature]) {
        self.version = version
        self.updatedAt = updatedAt
        self.signatures = signatures
    }
}

public enum AppSignatureStore {
    public static let defaultFileName = "app_signatures.json"

    public static let sampleSignatures: [AppSignature] = [
        AppSignature(label: "short_form_video", domains: [
            "example.com",
            "examplecdn.com"
        ]),
        AppSignature(label: "social", domains: [
            "social.example",
            "images.example"
        ])
    ]

    public static func defaultURL(appGroupID: String, fileName: String = defaultFileName) -> URL? {
        let fileManager = FileManager.default
        guard let container = fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            return nil
        }
        let dir = container.appendingPathComponent("AppSignatures", isDirectory: true)
        ensureDirectory(dir)
        return dir.appendingPathComponent(fileName)
    }

    public static func load(from url: URL) -> [AppSignature] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        let decoder = JSONDecoder()
        if let set = try? decoder.decode(AppSignatureSet.self, from: data) {
            return set.signatures
        }
        if let signatures = try? decoder.decode([AppSignature].self, from: data) {
            return signatures
        }
        return []
    }

    public static func loadValidated(from url: URL) -> [AppSignature] {
        let signatures = load(from: url)
        guard !signatures.isEmpty else { return [] }
        return (try? validate(signatures)) ?? []
    }

    public static func write(_ signatures: [AppSignature], to url: URL) {
        ensureDirectory(url.deletingLastPathComponent())
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let set = AppSignatureSet(version: 1, updatedAt: ISO8601DateFormatter().string(from: Date()), signatures: signatures)
        if let data = try? encoder.encode(set) {
            try? data.write(to: url, options: [.atomic])
        }
    }

    public static func writeIfMissing(_ signatures: [AppSignature], to url: URL) {
        let fileManager = FileManager.default
        guard !fileManager.fileExists(atPath: url.path) else { return }
        write(signatures, to: url)
    }

    public static func validate(_ signatures: [AppSignature]) throws -> [AppSignature] {
        guard !signatures.isEmpty else { throw AppSignatureValidationError.emptySignatures }
        var seenLabels = Set<String>()
        var normalized: [AppSignature] = []

        for signature in signatures {
            let rawLabel = signature.label.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !rawLabel.isEmpty else { throw AppSignatureValidationError.invalidLabel(signature.label) }
            let labelKey = rawLabel.lowercased()
            guard !seenLabels.contains(labelKey) else { throw AppSignatureValidationError.duplicateLabel(rawLabel) }
            seenLabels.insert(labelKey)

            let domains = signature.domains
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { !$0.isEmpty }
            guard !domains.isEmpty else { throw AppSignatureValidationError.invalidDomain("(empty)", label: rawLabel) }

            for domain in domains {
                if domain.contains("://") || domain.contains("/") || domain.contains(" ") {
                    throw AppSignatureValidationError.invalidDomain(domain, label: rawLabel)
                }
                if !domain.contains(".") {
                    throw AppSignatureValidationError.invalidDomain(domain, label: rawLabel)
                }
                if domain.hasPrefix(".") || domain.hasSuffix(".") {
                    throw AppSignatureValidationError.invalidDomain(domain, label: rawLabel)
                }
            }

            let uniqueDomains = Array(Set(domains)).sorted()
            normalized.append(AppSignature(label: rawLabel, domains: uniqueDomains))
        }

        return normalized
    }

    private static func ensureDirectory(_ url: URL) {
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: nil)
    }
}

public enum AppSignatureValidationError: LocalizedError, Sendable {
    case emptySignatures
    case invalidLabel(String)
    case invalidDomain(String, label: String)
    case duplicateLabel(String)

    public var errorDescription: String? {
        switch self {
        case .emptySignatures:
            return "Signature list is empty."
        case .invalidLabel(let label):
            return "Signature label is invalid: \(label)"
        case .invalidDomain(let domain, let label):
            return "Invalid domain '\(domain)' for label '\(label)'."
        case .duplicateLabel(let label):
            return "Duplicate signature label: \(label)"
        }
    }
}