import Foundation
import NetworkExtension

/// Host-side helper for creating and updating a tunnel provider profile.
public enum TunnelProfileManager {
    public static let currentProviderConfigurationVersion = 1

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
            TunnelProviderConfigurationKey.profileVersion: currentProviderConfigurationVersion,
            TunnelProviderConfigurationKey.appGroupID: profile.appGroupID,
            TunnelProviderConfigurationKey.tunnelRemoteAddress: profile.tunnelRemoteAddress,
            TunnelProviderConfigurationKey.mtu: profile.mtu,
            TunnelProviderConfigurationKey.ipv6Enabled: profile.ipv6Enabled,
            TunnelProviderConfigurationKey.tcpMultipathHandoverEnabled: profile.tcpMultipathHandoverEnabled,
            TunnelProviderConfigurationKey.ipv4Address: profile.ipv4Address,
            TunnelProviderConfigurationKey.ipv4SubnetMask: profile.ipv4SubnetMask,
            TunnelProviderConfigurationKey.ipv4Router: profile.ipv4Router,
            TunnelProviderConfigurationKey.ipv6Address: profile.ipv6Address,
            TunnelProviderConfigurationKey.ipv6PrefixLength: profile.ipv6PrefixLength,
            TunnelProviderConfigurationKey.dnsServers: profile.dnsServers,
            TunnelProviderConfigurationKey.engineSocksPort: Int(profile.engineSocksPort),
            TunnelProviderConfigurationKey.engineLogLevel: profile.engineLogLevel,
            TunnelProviderConfigurationKey.telemetryEnabled: profile.telemetryEnabled,
            TunnelProviderConfigurationKey.liveTapEnabled: profile.liveTapEnabled,
            TunnelProviderConfigurationKey.liveTapIncludeFlowSlices: profile.liveTapIncludeFlowSlices,
            TunnelProviderConfigurationKey.liveTapMaxBytes: profile.liveTapMaxBytes,
            TunnelProviderConfigurationKey.signatureFileName: profile.signatureFileName,
            TunnelProviderConfigurationKey.relayHost: profile.relayEndpoint.host,
            TunnelProviderConfigurationKey.relayPort: Int(profile.relayEndpoint.port),
            TunnelProviderConfigurationKey.relayUDP: profile.relayEndpoint.useUDP,
            TunnelProviderConfigurationKey.dataplaneConfigJSON: profile.dataplaneConfigJSON
        ]
        for (key, value) in normalizedConfiguration {
            configuration[key] = value
        }
        for (key, value) in profile.mtuStrategy.providerConfiguration {
            configuration[key] = value
        }
        configuration[TunnelProviderConfigurationKey.dnsStrategy] = profile.dnsStrategy.providerConfiguration
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
            if !TunnelProviderConfigurationKey.managedKeys.contains(pair.key) {
                partialResult[pair.key] = pair.value
            }
        }
    }
}
