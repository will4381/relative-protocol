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

        // Docs: https://developer.apple.com/documentation/networkextension/nednssettings
        settings.dnsSettings = NEDNSSettings(servers: profile.dnsServers)
        settings.mtu = NSNumber(value: profile.mtu)
        settings.tunnelOverheadBytes = 0

        return settings
    }
}
