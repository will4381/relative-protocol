/// Canonical provider-configuration keys shared by the host app and packet-tunnel runtime.
enum TunnelProviderConfigurationKey {
    static let profileVersion = "vpnBridgeProfileVersion"
    static let appGroupID = "appGroupID"
    static let tunnelRemoteAddress = "tunnelRemoteAddress"
    static let mtu = "mtu"
    static let mtuStrategy = "mtuStrategy"
    static let tunnelOverheadBytes = "tunnelOverheadBytes"
    static let ipv6Enabled = "ipv6Enabled"
    static let tcpMultipathHandoverEnabled = "tcpMultipathHandoverEnabled"
    static let ipv4Address = "ipv4Address"
    static let ipv4SubnetMask = "ipv4SubnetMask"
    static let ipv4Router = "ipv4Router"
    static let ipv6Address = "ipv6Address"
    static let ipv6PrefixLength = "ipv6PrefixLength"
    static let dnsServers = "dnsServers"
    static let dnsStrategy = "dnsStrategy"
    static let engineSocksPort = "engineSocksPort"
    static let engineLogLevel = "engineLogLevel"
    static let telemetryEnabled = "telemetryEnabled"
    static let liveTapEnabled = "liveTapEnabled"
    static let liveTapIncludeFlowSlices = "liveTapIncludeFlowSlices"
    static let liveTapMaxBytes = "liveTapMaxBytes"
    static let signatureFileName = "signatureFileName"
    static let relayHost = "relayHost"
    static let relayPort = "relayPort"
    static let relayUDP = "relayUDP"
    static let dataplaneConfigJSON = "dataplaneConfigJSON"

    static let managedKeys: Set<String> = [
        profileVersion,
        appGroupID,
        tunnelRemoteAddress,
        mtu,
        mtuStrategy,
        tunnelOverheadBytes,
        ipv6Enabled,
        tcpMultipathHandoverEnabled,
        ipv4Address,
        ipv4SubnetMask,
        ipv4Router,
        ipv6Address,
        ipv6PrefixLength,
        dnsServers,
        dnsStrategy,
        engineSocksPort,
        engineLogLevel,
        telemetryEnabled,
        liveTapEnabled,
        liveTapIncludeFlowSlices,
        liveTapMaxBytes,
        signatureFileName,
        relayHost,
        relayPort,
        relayUDP,
        dataplaneConfigJSON
    ]
}
