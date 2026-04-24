import Foundation
import NetworkExtension

/// Host-side helper for creating and updating a tunnel provider profile.
public enum TunnelProfileManager {
    public static let currentProviderConfigurationVersion = 1

    private static let managedProviderConfigurationKeys: Set<String> = [
        "vpnBridgeProfileVersion",
        "appGroupID",
        "tunnelRemoteAddress",
        "mtu",
        "mtuStrategy",
        "tunnelOverheadBytes",
        "ipv6Enabled",
        "tcpMultipathHandoverEnabled",
        "ipv4Address",
        "ipv4SubnetMask",
        "ipv4Router",
        "ipv6Address",
        "ipv6PrefixLength",
        "dnsServers",
        "dnsStrategy",
        "engineSocksPort",
        "engineLogLevel",
        "telemetryEnabled",
        "liveTapEnabled",
        "liveTapIncludeFlowSlices",
        "liveTapMaxBytes",
        "signatureFileName",
        "relayHost",
        "relayPort",
        "relayUDP",
        "dataplaneConfigJSON"
    ]

    // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovidermanager
    /// Applies `TunnelProfile` values onto a `NETunnelProviderManager`.
    /// - Parameters:
    ///   - manager: Manager instance to mutate.
    ///   - profile: Normalized profile values to apply.
    ///   - providerBundleIdentifier: Tunnel extension bundle identifier.
    ///   - localizedDescription: User-facing profile description.
    public static func configure(
        manager: NETunnelProviderManager,
        profile: TunnelProfile,
        providerBundleIdentifier: String,
        localizedDescription: String
    ) {
        let preservedConfiguration = preservedProviderConfiguration(from: manager.protocolConfiguration)
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleIdentifier
        proto.serverAddress = profile.tunnelRemoteAddress
        var configuration = preservedConfiguration
        let normalizedConfiguration: [String: Any] = [
            "vpnBridgeProfileVersion": currentProviderConfigurationVersion,
            "appGroupID": profile.appGroupID,
            "tunnelRemoteAddress": profile.tunnelRemoteAddress,
            "mtu": profile.mtu,
            "ipv6Enabled": profile.ipv6Enabled,
            "tcpMultipathHandoverEnabled": profile.tcpMultipathHandoverEnabled,
            "ipv4Address": profile.ipv4Address,
            "ipv4SubnetMask": profile.ipv4SubnetMask,
            "ipv4Router": profile.ipv4Router,
            "ipv6Address": profile.ipv6Address,
            "ipv6PrefixLength": profile.ipv6PrefixLength,
            "dnsServers": profile.dnsServers,
            "engineSocksPort": Int(profile.engineSocksPort),
            "engineLogLevel": profile.engineLogLevel,
            "telemetryEnabled": profile.telemetryEnabled,
            "liveTapEnabled": profile.liveTapEnabled,
            "liveTapIncludeFlowSlices": profile.liveTapIncludeFlowSlices,
            "liveTapMaxBytes": profile.liveTapMaxBytes,
            "signatureFileName": profile.signatureFileName,
            "relayHost": profile.relayEndpoint.host,
            "relayPort": Int(profile.relayEndpoint.port),
            "relayUDP": profile.relayEndpoint.useUDP,
            "dataplaneConfigJSON": profile.dataplaneConfigJSON
        ]
        for (key, value) in normalizedConfiguration {
            configuration[key] = value
        }
        for (key, value) in profile.mtuStrategy.providerConfiguration {
            configuration[key] = value
        }
        configuration["dnsStrategy"] = profile.dnsStrategy.providerConfiguration
        proto.providerConfiguration = configuration
        manager.protocolConfiguration = proto
        manager.localizedDescription = localizedDescription
        manager.isEnabled = true
    }

    private static func preservedProviderConfiguration(
        from configuration: NEVPNProtocol?
    ) -> [String: Any] {
        guard let proto = configuration as? NETunnelProviderProtocol,
              let providerConfiguration = proto.providerConfiguration else {
            return [:]
        }

        return providerConfiguration.reduce(into: [:]) { partialResult, pair in
            if !managedProviderConfigurationKeys.contains(pair.key) {
                partialResult[pair.key] = pair.value
            }
        }
    }
}
