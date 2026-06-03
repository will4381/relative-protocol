import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif
import NetworkExtension

/// Converts `TunnelProfile` into NetworkExtension interface settings.
public enum TunnelNetworkSettingsFactory {
    // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelnetworksettings
    /// Builds network settings consumed by `setTunnelNetworkSettings`.
    /// - Parameter profile: Normalized runtime profile values.
    /// - Returns: Fully configured packet tunnel interface settings.
    public static func makeSettings(
        profile: TunnelProfile,
        pathSupportsIPv6: Bool? = nil
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: profile.tunnelRemoteAddress)

        // Docs: https://developer.apple.com/documentation/networkextension/neipv4settings
        let ipv4 = NEIPv4Settings(addresses: [profile.ipv4Address], subnetMasks: [profile.ipv4SubnetMask])
        ipv4.includedRoutes = profile.ipv4RouteStrategy.includedRoutes
        // Docs: https://developer.apple.com/documentation/networkextension/neipv4settings/router
        // `router` is only available on macOS, so iOS relies on the default included route alone.
        #if os(macOS)
        if #available(macOS 13.0, *) {
            ipv4.router = profile.ipv4Router
        }
        #endif
        settings.ipv4Settings = ipv4

        // Apple docs: NWPath.supportsIPv6 indicates whether the path can route IPv6 traffic, while
        // NEIPv6Settings.includedRoutes sends IPv6 traffic to the TUN interface. If startup preflight
        // proves the underlay cannot route IPv6, omit the IPv6 default route so the relay does not
        // accept IPv6 literals it cannot complete.
        // Docs: https://developer.apple.com/documentation/network/nwpath/supportsipv6
        // Docs: https://developer.apple.com/documentation/networkextension/neipv6settings/includedroutes
        let installIPv6 = profile.ipv6Enabled && (pathSupportsIPv6 ?? true)
        if installIPv6 {
            let ipv6 = NEIPv6Settings(
                addresses: [profile.ipv6Address],
                networkPrefixLengths: [NSNumber(value: profile.ipv6PrefixLength)]
            )
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }

        settings.dnsSettings = makeDNSSettings(
            strategy: profile.dnsStrategy,
            includeIPv6Servers: pathSupportsIPv6 ?? true
        )
        applyMTUStrategy(profile.mtuStrategy, to: settings)

        return settings
    }

    private static func makeDNSSettings(strategy: TunnelDNSStrategy, includeIPv6Servers: Bool) -> NEDNSSettings? {
        switch strategy {
        case .noOverride:
            return nil
        case .cleartext(let servers, let matchDomains, let matchDomainsNoSearch, let allowFailover):
            let servers = resolverServers(servers, includeIPv6Servers: includeIPv6Servers)
            guard areValidResolverServers(servers),
                  TunnelDNSStrategy.areValidMatchDomains(matchDomains) else {
                return nil
            }
            let dnsSettings = NEDNSSettings(servers: servers)
            configureCommonDNSSettings(
                dnsSettings,
                matchDomains: matchDomains,
                matchDomainsNoSearch: matchDomainsNoSearch,
                allowFailover: allowFailover
            )
            return dnsSettings
        case .tls(let servers, let serverName, let matchDomains, let matchDomainsNoSearch, let allowFailover):
            let servers = resolverServers(servers, includeIPv6Servers: includeIPv6Servers)
            guard areValidResolverServers(servers),
                  isValidHostName(serverName),
                  TunnelDNSStrategy.areValidMatchDomains(matchDomains) else {
                return nil
            }
            let dnsSettings = NEDNSOverTLSSettings(servers: servers)
            dnsSettings.serverName = serverName
            configureCommonDNSSettings(
                dnsSettings,
                matchDomains: matchDomains,
                matchDomainsNoSearch: matchDomainsNoSearch,
                allowFailover: allowFailover
            )
            return dnsSettings
        case .https(let servers, let serverURL, let matchDomains, let matchDomainsNoSearch, let allowFailover):
            let servers = resolverServers(servers, includeIPv6Servers: includeIPv6Servers)
            guard areValidResolverServers(servers),
                  TunnelDNSStrategy.areValidMatchDomains(matchDomains),
                  let url = URL(string: serverURL),
                  url.scheme?.lowercased() == "https",
                  url.host?.isEmpty == false else {
                return nil
            }
            let dnsSettings = NEDNSOverHTTPSSettings(servers: servers)
            dnsSettings.serverURL = url
            configureCommonDNSSettings(
                dnsSettings,
                matchDomains: matchDomains,
                matchDomainsNoSearch: matchDomainsNoSearch,
                allowFailover: allowFailover
            )
            return dnsSettings
        }
    }

    private static func resolverServers(_ servers: [String], includeIPv6Servers: Bool) -> [String] {
        guard !includeIPv6Servers else {
            return servers
        }
        return servers.filter { !isValidIPv6Address($0) }
    }

    private static func configureCommonDNSSettings(
        _ dnsSettings: NEDNSSettings,
        matchDomains: [String]?,
        matchDomainsNoSearch: Bool,
        allowFailover: Bool
    ) {
        // Apple NEDNSSettings.matchDomains is the resolver selection list; invalid selectors are rejected before
        // settings creation so setTunnelNetworkSettings does not fail late with an opaque DNS configuration error.
        dnsSettings.matchDomains = matchDomains
        dnsSettings.matchDomainsNoSearch = matchDomainsNoSearch
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, *) {
            dnsSettings.allowFailover = allowFailover
        }
    }

    private static func applyMTUStrategy(_ strategy: TunnelMTUStrategy, to settings: NEPacketTunnelNetworkSettings) {
        switch strategy {
        case .fixed(let mtu):
            settings.mtu = NSNumber(value: mtu)
        case .automaticTunnelOverhead(let overhead):
            settings.tunnelOverheadBytes = NSNumber(value: overhead)
        }
    }

    private static func areValidResolverServers(_ servers: [String]) -> Bool {
        !servers.isEmpty && servers.allSatisfy { isValidIPv4Address($0) || isValidIPv6Address($0) }
    }

    private static func isValidIPv4Address(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }

    private static func isValidIPv6Address(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) } == 1
    }

    private static func isValidHostName(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed == value,
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              value.range(of: "\0") == nil,
              value.rangeOfCharacter(from: .controlCharacters) == nil,
              !value.contains("/"),
              !value.contains("\\"),
              !value.contains("\""),
              !value.contains("'")
        else {
            return false
        }
        if isValidIPv4Address(value) || isValidIPv6Address(value) {
            return true
        }
        if value.contains(":") || value.allSatisfy({ $0.isNumber || $0 == "." }) {
            return false
        }
        let normalized = value.hasSuffix(".") ? String(value.dropLast()) : value
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
