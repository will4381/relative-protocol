import Foundation

/// Controls how tunnel DNS settings are installed on the virtual interface.
public enum TunnelDNSStrategy: Sendable, Equatable {
    case cleartext(
        servers: [String],
        matchDomains: [String]? = nil,
        matchDomainsNoSearch: Bool = false,
        allowFailover: Bool = false
    )
    case tls(
        servers: [String],
        serverName: String,
        matchDomains: [String]? = nil,
        matchDomainsNoSearch: Bool = false,
        allowFailover: Bool = false
    )
    case https(
        servers: [String],
        serverURL: String,
        matchDomains: [String]? = nil,
        matchDomainsNoSearch: Bool = false,
        allowFailover: Bool = false
    )
    case noOverride

    /// Dual-stack Cloudflare resolver set with IPv4 primary/secondary and IPv6 counterparts.
    public static let defaultPublicResolvers = [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
    ]

    /// Compatibility-first default that preserves the system resolver path.
    public static let recommendedDefault = TunnelDNSStrategy.noOverride

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
}
