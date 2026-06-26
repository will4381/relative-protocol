// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

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
    static let ipv4IncludedRoutes = "ipv4IncludedRoutes"
    static let ipv6Address = "ipv6Address"
    static let ipv6PrefixLength = "ipv6PrefixLength"
    static let dnsServers = "dnsServers"
    static let dnsStrategy = "dnsStrategy"
    static let engineSocksPort = "engineSocksPort"
    static let engineLogLevel = "engineLogLevel"
    static let telemetryEnabled = "telemetryEnabled"
    static let liveTapEnabled = "liveTapEnabled"
    static let liveTapIncludeFlowSlices = "liveTapIncludeFlowSlices"
    static let liveTapIncludePacketCues = "liveTapIncludePacketCues"
    static let liveTapIncludeValidationRecords = "liveTapIncludeValidationRecords"
    static let liveTapMaxBytes = "liveTapMaxBytes"
    static let packetCuePolicy = "packetCuePolicy"
    static let addressScopePrefixes = "addressScopePrefixes"
    static let telemetryReduceOnLowPowerMode = "telemetryReduceOnLowPowerMode"
    static let telemetryReduceOnThermalPressure = "telemetryReduceOnThermalPressure"
    static let richPacketLogPolicy = "richPacketLogPolicy"
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
        ipv4IncludedRoutes,
        ipv6Address,
        ipv6PrefixLength,
        dnsServers,
        dnsStrategy,
        engineSocksPort,
        engineLogLevel,
        telemetryEnabled,
        liveTapEnabled,
        liveTapIncludeFlowSlices,
        liveTapIncludePacketCues,
        liveTapIncludeValidationRecords,
        liveTapMaxBytes,
        packetCuePolicy,
        addressScopePrefixes,
        telemetryReduceOnLowPowerMode,
        telemetryReduceOnThermalPressure,
        richPacketLogPolicy,
        signatureFileName,
        relayHost,
        relayPort,
        relayUDP,
        dataplaneConfigJSON
    ]
}
