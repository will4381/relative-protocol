// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation

/// Controls how tunnel DNS settings are installed on the virtual interface.
public enum TunnelDNSStrategy: Sendable, Equatable {
    case cleartext(
        servers: [String],
        matchDomains: [String]? = [""],
        matchDomainsNoSearch: Bool = true,
        allowFailover: Bool = false
    )
    case tls(
        servers: [String],
        serverName: String,
        matchDomains: [String]? = [""],
        matchDomainsNoSearch: Bool = true,
        allowFailover: Bool = false
    )
    case https(
        servers: [String],
        serverURL: String,
        matchDomains: [String]? = [""],
        matchDomainsNoSearch: Bool = true,
        allowFailover: Bool = false
    )
    case noOverride

    /// Dual-stack Cloudflare resolver set with IPv6 primary/secondary and IPv4 fallbacks.
    public static let defaultPublicResolvers = [
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "1.1.1.1",
        "1.0.0.1"
    ]

    /// Full-tunnel default that installs package-owned resolvers for all DNS queries.
    public static let recommendedDefault = TunnelDNSStrategy.cleartext(
        servers: defaultPublicResolvers,
        matchDomains: [""],
        matchDomainsNoSearch: true,
        allowFailover: false
    )

    /// Resolver IPs associated with the strategy. `noOverride` returns an empty list.
    public var servers: [String] {
        switch self {
        case .cleartext(let servers, _, _, _),
                .tls(let servers, _, _, _, _),
                .https(let servers, _, _, _, _):
            return servers
        case .noOverride:
            return []
        }
    }

    var providerConfiguration: [String: Any] {
        switch self {
        case .cleartext(let servers, let matchDomains, let matchDomainsNoSearch, let allowFailover):
            return compactConfiguration([
                "type": "cleartext",
                "servers": servers,
                "matchDomains": matchDomains,
                "matchDomainsNoSearch": matchDomainsNoSearch,
                "allowFailover": allowFailover
            ])
        case .tls(let servers, let serverName, let matchDomains, let matchDomainsNoSearch, let allowFailover):
            return compactConfiguration([
                "type": "tls",
                "servers": servers,
                "serverName": serverName,
                "matchDomains": matchDomains,
                "matchDomainsNoSearch": matchDomainsNoSearch,
                "allowFailover": allowFailover
            ])
        case .https(let servers, let serverURL, let matchDomains, let matchDomainsNoSearch, let allowFailover):
            return compactConfiguration([
                "type": "https",
                "servers": servers,
                "serverURL": serverURL,
                "matchDomains": matchDomains,
                "matchDomainsNoSearch": matchDomainsNoSearch,
                "allowFailover": allowFailover
            ])
        case .noOverride:
            return ["type": "none"]
        }
    }

    private func compactConfiguration(_ values: [String: Any?]) -> [String: Any] {
        values.reduce(into: [:]) { partialResult, pair in
            if let value = pair.value {
                partialResult[pair.key] = value
            }
        }
    }

    static func areValidMatchDomains(_ matchDomains: [String]?) -> Bool {
        guard let matchDomains else {
            return true
        }
        guard !matchDomains.isEmpty else {
            return false
        }
        return matchDomains.allSatisfy(isValidMatchDomain)
    }

    private static func isValidMatchDomain(_ value: String) -> Bool {
        if value.isEmpty {
            return true
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed == value,
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              value.range(of: "\0") == nil,
              value.rangeOfCharacter(from: .controlCharacters) == nil,
              !value.contains("/"),
              !value.contains("\\"),
              !value.contains("\""),
              !value.contains("'"),
              !value.contains(":"),
              !value.allSatisfy({ $0.isNumber || $0 == "." })
        else {
            return false
        }

        let normalized = value.hasSuffix(".") ? String(value.dropLast()) : value
        guard !normalized.isEmpty, normalized.utf8.count <= 253 else {
            return false
        }

        let labels = normalized.split(separator: ".", omittingEmptySubsequences: false)
        return !labels.isEmpty && labels.allSatisfy { label in
            !label.isEmpty &&
                label.utf8.count <= 63 &&
                label.first != "-" &&
                label.last != "-" &&
                label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }
}
