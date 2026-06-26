// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Analytics
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
            TunnelProviderConfigurationKey.liveTapIncludePacketCues: profile.liveTapIncludePacketCues,
            TunnelProviderConfigurationKey.liveTapIncludeValidationRecords: profile.liveTapIncludeValidationRecords,
            TunnelProviderConfigurationKey.liveTapMaxBytes: profile.liveTapMaxBytes,
            TunnelProviderConfigurationKey.packetCuePolicy: providerConfiguration(for: profile.packetCuePolicy),
            TunnelProviderConfigurationKey.addressScopePrefixes: providerConfiguration(for: profile.addressScopePrefixes),
            TunnelProviderConfigurationKey.telemetryReduceOnLowPowerMode: profile.telemetryDegradationPolicy.reduceOnLowPowerMode,
            TunnelProviderConfigurationKey.telemetryReduceOnThermalPressure: profile.telemetryDegradationPolicy.reduceOnThermalPressure,
            TunnelProviderConfigurationKey.richPacketLogPolicy: providerConfiguration(for: profile.richPacketLogPolicy),
            TunnelProviderConfigurationKey.signatureFileName: profile.signatureFileName,
            TunnelProviderConfigurationKey.relayUDP: profile.relayEndpoint.useUDP,
            TunnelProviderConfigurationKey.dataplaneConfigJSON: profile.dataplaneConfigJSON
        ]
        for (key, value) in normalizedConfiguration {
            configuration[key] = value
        }
        for (key, value) in profile.mtuStrategy.providerConfiguration {
            configuration[key] = value
        }
        for (key, value) in profile.ipv4RouteStrategy.providerConfiguration {
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

    private static func providerConfiguration(for policy: PacketCueEmissionPolicy) -> [String: Any] {
        var configuration: [String: Any] = [
            "directions": policy.directions.map(\.rawValue).sorted(),
            "requireTcpAck": policy.requireTcpAck,
            "requireTcpPsh": policy.requireTcpPsh,
            "includeHostAssociatedPackets": policy.includeHostAssociatedPackets,
            "emitMetadataRefreshCues": policy.emitMetadataRefreshCues
        ]
        if let tcpPayloadLengthRange = policy.tcpPayloadLengthRange {
            configuration["tcpPayloadLengthRange"] = providerConfiguration(for: tcpPayloadLengthRange)
        }
        if let udpPacketLengthRange = policy.udpPacketLengthRange {
            configuration["udpPacketLengthRange"] = providerConfiguration(for: udpPacketLengthRange)
        }
        if let maxHostAssociatedPacketLength = policy.maxHostAssociatedPacketLength {
            configuration["maxHostAssociatedPacketLength"] = maxHostAssociatedPacketLength
        }
        return configuration
    }

    private static func providerConfiguration(for range: PacketLengthRange) -> [String: Any] {
        [
            "lowerBound": range.lowerBound,
            "upperBound": range.upperBound
        ]
    }

    private static func providerConfiguration(for prefixes: [AddressScopePrefix]) -> [[String: Any]] {
        prefixes.map { prefix in
            [
                "cidr": prefix.cidr,
                "family": prefix.family,
                "confidence": prefix.confidence
            ]
        }
    }

    private static func providerConfiguration(for policy: RichPacketLogPolicy) -> [String: Any] {
        var configuration: [String: Any] = [
            "isEnabled": policy.isEnabled,
            "directions": policy.directions.map(\.rawValue).sorted(),
            "includeParsedMetadata": policy.includeParsedMetadata,
            "includeDNSAnswerAddresses": policy.includeDNSAnswerAddresses,
            "includeQUICConnectionIDs": policy.includeQUICConnectionIDs,
            "includePacketBytePrefix": policy.includePacketBytePrefix,
            "packetBytePrefixLength": policy.packetBytePrefixLength,
            "maxRecordsPerBatch": policy.maxRecordsPerBatch,
            "metadataProbeLimitPerBatch": policy.metadataProbeLimitPerBatch,
            "filePrefix": policy.filePrefix,
            "maxBytesPerFile": policy.maxBytesPerFile,
            "maxFileCount": policy.maxFileCount,
            "maxTotalBytes": policy.maxTotalBytes
        ]
        if let maxPacketLength = policy.maxPacketLength {
            configuration["maxPacketLength"] = maxPacketLength
        }
        return configuration
    }
}
