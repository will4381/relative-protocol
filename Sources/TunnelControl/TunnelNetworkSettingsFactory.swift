import Foundation
import NetworkExtension

/// Converts `TunnelProfile` into NetworkExtension interface settings.
public enum TunnelNetworkSettingsFactory {
    // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelnetworksettings
    /// Builds network settings consumed by `setTunnelNetworkSettings`.
    /// - Parameter profile: Normalized runtime profile values.
    /// - Returns: Fully configured packet tunnel interface settings.
    public static func makeSettings(profile: TunnelProfile) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: profile.tunnelRemoteAddress)

        // Docs: https://developer.apple.com/documentation/networkextension/neipv4settings
        let ipv4 = NEIPv4Settings(addresses: [profile.ipv4Address], subnetMasks: [profile.ipv4SubnetMask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        // Docs: https://developer.apple.com/documentation/networkextension/neipv4settings/router
        // `router` is only available on macOS, so iOS relies on the default included route alone.
        #if os(macOS)
        if #available(macOS 13.0, *) {
            ipv4.router = profile.ipv4Router
        }
        #endif
        settings.ipv4Settings = ipv4

        // Docs: https://developer.apple.com/documentation/networkextension/neipv6settings
        if profile.ipv6Enabled {
            let ipv6 = NEIPv6Settings(
                addresses: [profile.ipv6Address],
                networkPrefixLengths: [NSNumber(value: profile.ipv6PrefixLength)]
            )
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }

        settings.dnsSettings = makeDNSSettings(strategy: profile.dnsStrategy)
        applyMTUStrategy(profile.mtuStrategy, to: settings)

        return settings
    }

    private static func makeDNSSettings(strategy: TunnelDNSStrategy) -> NEDNSSettings? {
        switch strategy {
        case .noOverride:
            return nil
        case .cleartext(let servers, let matchDomains, let matchDomainsNoSearch, let allowFailover):
            let dnsSettings = NEDNSSettings(servers: servers)
            configureCommonDNSSettings(
                dnsSettings,
                matchDomains: matchDomains,
                matchDomainsNoSearch: matchDomainsNoSearch,
                allowFailover: allowFailover
            )
            return dnsSettings
        case .tls(let servers, let serverName, let matchDomains, let matchDomainsNoSearch, let allowFailover):
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
            let dnsSettings = NEDNSOverHTTPSSettings(servers: servers)
            dnsSettings.serverURL = URL(string: serverURL)
            configureCommonDNSSettings(
                dnsSettings,
                matchDomains: matchDomains,
                matchDomainsNoSearch: matchDomainsNoSearch,
                allowFailover: allowFailover
            )
            return dnsSettings
        }
    }

    private static func configureCommonDNSSettings(
        _ dnsSettings: NEDNSSettings,
        matchDomains: [String]?,
        matchDomainsNoSearch: Bool,
        allowFailover: Bool
    ) {
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
}
