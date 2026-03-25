import Foundation
import NetworkExtension

/// Host-side helper for creating and updating a tunnel provider profile.
public enum TunnelProfileManager {
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
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleIdentifier
        proto.serverAddress = profile.tunnelRemoteAddress
        proto.providerConfiguration = [
            "appGroupID": profile.appGroupID,
            "tunnelRemoteAddress": profile.tunnelRemoteAddress,
            "mtu": profile.mtu,
            "ipv6Enabled": profile.ipv6Enabled,
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
        manager.protocolConfiguration = proto
        manager.localizedDescription = localizedDescription
        manager.isEnabled = true
    }
}
