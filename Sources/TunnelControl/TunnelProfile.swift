// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Darwin
import Foundation
import PacketRelay

/// Decoded provider configuration used by extension startup.
/// Invariant: values are pre-normalized with safe defaults for missing keys.
public struct TunnelProfile: Sendable, Equatable {
    /// App Group identifier used for shared storage (logs, signatures, detections, stop records).
    public let appGroupID: String
    /// Remote address required by `NEPacketTunnelNetworkSettings`.
    public let tunnelRemoteAddress: String
    /// MTU hint used for local packet buffers and for fixed interface MTU strategies.
    public let mtu: Int
    /// Controls how packet-tunnel MTU settings are installed on the virtual interface.
    public let mtuStrategy: TunnelMTUStrategy
    /// Enables or disables IPv6 settings installation.
    public let ipv6Enabled: Bool
    /// Enables `NWParameters.MultipathServiceType.handover` for outbound TCP connects.
    public let tcpMultipathHandoverEnabled: Bool
    public let ipv4Address: String
    public let ipv4SubnetMask: String
    public let ipv4Router: String
    public let ipv4RouteStrategy: TunnelIPv4RouteStrategy
    public let ipv6Address: String
    public let ipv6PrefixLength: Int
    /// Controls which DNS settings are installed on the tunnel interface.
    public let dnsStrategy: TunnelDNSStrategy
    public let engineSocksPort: UInt16
    public let engineLogLevel: String
    public let telemetryEnabled: Bool
    public let liveTapEnabled: Bool
    public let liveTapIncludeFlowSlices: Bool
    public let liveTapMaxBytes: Int
    public let signatureFileName: String
    /// Transport selector retained for compatibility with the previous relay endpoint API.
    public let relayEndpoint: RelayEndpoint
    public let dataplaneConfigJSON: String

    /// Resolver IPs associated with the active DNS strategy.
    public var dnsServers: [String] {
        dnsStrategy.servers
    }

    /// Creates a fully-specified tunnel profile.
    /// - Parameters:
    ///   - appGroupID: App Group identifier for shared data paths.
    ///   - tunnelRemoteAddress: Tunnel remote address required by NetworkExtension.
    ///   - mtu: MTU hint used for local packet buffers and fixed interface MTU strategies.
    ///   - mtuStrategy: Controls how interface MTU settings are applied. Defaults to `.fixed(mtu)` for backward compatibility.
    ///   - ipv6Enabled: Controls whether IPv6 settings are installed.
    ///   - tcpMultipathHandoverEnabled: Enables multipath handover for outbound TCP connections.
    ///   - ipv4Address: Assigned IPv4 address.
    ///   - ipv4SubnetMask: Assigned IPv4 subnet mask.
    ///   - ipv4Router: Default IPv4 router.
    ///   - ipv4RouteStrategy: Controls which IPv4 routes are installed on the tunnel interface.
    ///   - ipv6Address: Assigned IPv6 address.
    ///   - ipv6PrefixLength: IPv6 prefix length.
    ///   - dnsServers: DNS servers used by direct callers when `dnsStrategy` is not supplied.
    ///   - dnsStrategy: Controls which DNS settings are installed. Direct callers default to cleartext DNS over
    ///     `dnsServers`; provider-configuration decoding defaults to `TunnelDNSStrategy.recommendedDefault`.
    ///   - engineSocksPort: Local SOCKS server listen port.
    ///   - engineLogLevel: Dataplane log level hint.
    ///   - telemetryEnabled: Enables sparse analytics and detector execution inside the tunnel extension.
    ///   - liveTapEnabled: Enables the live rolling packet tap used for foreground snapshots. This is a
    ///     lean app-facing debug/read surface, not a guarantee that every detector-grade sparse record kind
    ///     will be published to the containing app.
    ///   - liveTapIncludeFlowSlices: Opts the live rolling packet tap into detector-grade `flowSlice` records.
    ///     Keep this `false` for normal foreground reads and enable it only for richer inspection/debug builds.
    ///   - liveTapMaxBytes: Approximate memory budget for the live rolling packet tap.
    ///   - signatureFileName: Signature filename loaded by classifier.
    ///   - relayEndpoint: Legacy relay metadata plus the active UDP transport selector. Host and port are not egress destinations.
    ///   - dataplaneConfigJSON: Dataplane config template or raw config.
    public init(
        appGroupID: String,
        tunnelRemoteAddress: String,
        mtu: Int,
        mtuStrategy: TunnelMTUStrategy? = nil,
        ipv6Enabled: Bool,
        tcpMultipathHandoverEnabled: Bool,
        ipv4Address: String,
        ipv4SubnetMask: String,
        ipv4Router: String,
        ipv4RouteStrategy: TunnelIPv4RouteStrategy? = nil,
        ipv6Address: String,
        ipv6PrefixLength: Int,
        dnsServers: [String],
        dnsStrategy: TunnelDNSStrategy? = nil,
        engineSocksPort: UInt16,
        engineLogLevel: String,
        telemetryEnabled: Bool,
        liveTapEnabled: Bool,
        liveTapIncludeFlowSlices: Bool,
        liveTapMaxBytes: Int,
        signatureFileName: String,
        relayEndpoint: RelayEndpoint,
        dataplaneConfigJSON: String
    ) {
        let requestedMTU = TunnelMTUStrategy.clampedInterfaceMTU(mtu, minimum: TunnelMTUStrategy.minimumBufferMTUHint)
        let resolvedMTUStrategy = (mtuStrategy ?? .fixed(requestedMTU)).normalizedForProvider()

        self.appGroupID = appGroupID
        self.tunnelRemoteAddress = tunnelRemoteAddress
        self.mtuStrategy = resolvedMTUStrategy
        switch resolvedMTUStrategy {
        case .fixed(let fixedMTU):
            self.mtu = TunnelMTUStrategy.clampedInterfaceMTU(fixedMTU, minimum: TunnelMTUStrategy.minimumBufferMTUHint)
        case .automaticTunnelOverhead:
            self.mtu = max(requestedMTU, resolvedMTUStrategy.bufferMTUHint)
        }
        self.ipv6Enabled = ipv6Enabled
        self.tcpMultipathHandoverEnabled = tcpMultipathHandoverEnabled
        self.ipv4Address = ipv4Address
        self.ipv4SubnetMask = ipv4SubnetMask
        self.ipv4Router = ipv4Router
        self.ipv4RouteStrategy = (ipv4RouteStrategy ?? .defaultRoute).normalized()
        self.ipv6Address = ipv6Address
        self.ipv6PrefixLength = ipv6PrefixLength
        self.dnsStrategy = dnsStrategy ?? .cleartext(servers: dnsServers)
        self.engineSocksPort = engineSocksPort
        self.engineLogLevel = engineLogLevel
        self.telemetryEnabled = telemetryEnabled
        self.liveTapEnabled = liveTapEnabled
        self.liveTapIncludeFlowSlices = liveTapIncludeFlowSlices
        self.liveTapMaxBytes = liveTapMaxBytes
        self.signatureFileName = signatureFileName
        self.relayEndpoint = relayEndpoint
        self.dataplaneConfigJSON = dataplaneConfigJSON
    }

    /// Builds a normalized profile from `NETunnelProviderProtocol.providerConfiguration`.
    /// - Parameter providerConfiguration: Arbitrary key/value dictionary supplied by host app.
    public static func from(providerConfiguration: [String: Any]) -> TunnelProfile {
        let relayHost = providerConfiguration[TunnelProviderConfigurationKey.relayHost] as? String ?? "127.0.0.1"
        let relayPort = uint16(providerConfiguration[TunnelProviderConfigurationKey.relayPort], default: 1080)
        let useUDP = providerConfiguration[TunnelProviderConfigurationKey.relayUDP] as? Bool ?? false
        let configuredMTU = providerConfiguration[TunnelProviderConfigurationKey.mtu] == nil
            ? nil
            : int(providerConfiguration[TunnelProviderConfigurationKey.mtu], default: TunnelMTUStrategy.recommendedGeneric.bufferMTUHint)
        let mtuStrategy = mtuStrategy(
            from: providerConfiguration,
            legacyMTU: configuredMTU ?? TunnelMTUStrategy.recommendedGeneric.bufferMTUHint
        )
        let mtuValue = configuredMTU ?? mtuStrategy.bufferMTUHint
        let dnsStrategy = dnsStrategy(from: providerConfiguration)
        let ipv4RouteStrategy = ipv4RouteStrategy(from: providerConfiguration)

        return TunnelProfile(
            appGroupID: providerConfiguration[TunnelProviderConfigurationKey.appGroupID] as? String ?? "",
            tunnelRemoteAddress: providerConfiguration[TunnelProviderConfigurationKey.tunnelRemoteAddress] as? String ?? "127.0.0.1",
            mtu: mtuValue,
            mtuStrategy: mtuStrategy,
            ipv6Enabled: bool(providerConfiguration[TunnelProviderConfigurationKey.ipv6Enabled], default: true),
            tcpMultipathHandoverEnabled: bool(providerConfiguration[TunnelProviderConfigurationKey.tcpMultipathHandoverEnabled], default: false),
            ipv4Address: providerConfiguration[TunnelProviderConfigurationKey.ipv4Address] as? String ?? "10.0.0.2",
            ipv4SubnetMask: providerConfiguration[TunnelProviderConfigurationKey.ipv4SubnetMask] as? String ?? "255.255.255.0",
            ipv4Router: providerConfiguration[TunnelProviderConfigurationKey.ipv4Router] as? String ?? "10.0.0.1",
            ipv4RouteStrategy: ipv4RouteStrategy,
            ipv6Address: providerConfiguration[TunnelProviderConfigurationKey.ipv6Address] as? String ?? "fd00:1::2",
            ipv6PrefixLength: int(providerConfiguration[TunnelProviderConfigurationKey.ipv6PrefixLength], default: 64),
            dnsServers: dnsStrategy.servers,
            dnsStrategy: dnsStrategy,
            engineSocksPort: uint16AllowingZero(providerConfiguration[TunnelProviderConfigurationKey.engineSocksPort], default: 1080),
            engineLogLevel: providerConfiguration[TunnelProviderConfigurationKey.engineLogLevel] as? String ?? "warn",
            telemetryEnabled: bool(providerConfiguration[TunnelProviderConfigurationKey.telemetryEnabled], default: true),
            liveTapEnabled: bool(providerConfiguration[TunnelProviderConfigurationKey.liveTapEnabled], default: false),
            liveTapIncludeFlowSlices: bool(providerConfiguration[TunnelProviderConfigurationKey.liveTapIncludeFlowSlices], default: false),
            liveTapMaxBytes: int(providerConfiguration[TunnelProviderConfigurationKey.liveTapMaxBytes], default: 5_000_000),
            signatureFileName: providerConfiguration[TunnelProviderConfigurationKey.signatureFileName] as? String ?? "app_signatures.json",
            relayEndpoint: RelayEndpoint(host: relayHost, port: relayPort, useUDP: useUDP),
            dataplaneConfigJSON: providerConfiguration[TunnelProviderConfigurationKey.dataplaneConfigJSON] as? String ?? "{}"
        )
    }

    /// Builds a runtime profile for the packet tunnel extension and rejects sparse or hostile configuration.
    /// Decision: tests and host-side builders may still use `from(providerConfiguration:)` for compatibility/defaults,
    /// but the extension must fail closed instead of installing full-device routes from an empty dictionary.
    public static func validatedRuntimeProfile(providerConfiguration: [String: Any]) throws -> TunnelProfile {
        let profile = from(providerConfiguration: providerConfiguration)
        var missing: [String] = []

        if string(providerConfiguration[TunnelProviderConfigurationKey.appGroupID])?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            missing.append(TunnelProviderConfigurationKey.appGroupID)
        }
        if string(providerConfiguration[TunnelProviderConfigurationKey.tunnelRemoteAddress])?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            missing.append(TunnelProviderConfigurationKey.tunnelRemoteAddress)
        }
        if string(providerConfiguration[TunnelProviderConfigurationKey.ipv4Address])?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            missing.append(TunnelProviderConfigurationKey.ipv4Address)
        }
        if string(providerConfiguration[TunnelProviderConfigurationKey.ipv4SubnetMask])?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            missing.append(TunnelProviderConfigurationKey.ipv4SubnetMask)
        }
        if string(providerConfiguration[TunnelProviderConfigurationKey.ipv4Router])?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            missing.append(TunnelProviderConfigurationKey.ipv4Router)
        }
        if profile.ipv6Enabled,
           string(providerConfiguration[TunnelProviderConfigurationKey.ipv6Address])?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            missing.append(TunnelProviderConfigurationKey.ipv6Address)
        }
        if providerConfiguration[TunnelProviderConfigurationKey.engineSocksPort] == nil {
            missing.append(TunnelProviderConfigurationKey.engineSocksPort)
        }
        guard missing.isEmpty else {
            throw TunnelProfileValidationError.missingRequiredKeys(missing.sorted())
        }
        if let rawMTU = providerConfiguration[TunnelProviderConfigurationKey.mtu],
           !isExactMTU(rawMTU) {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.mtu, reason: "must be in 1280...65535")
        }
        guard profile.mtu >= TunnelMTUStrategy.minimumRuntimeMTU,
              profile.mtu <= TunnelMTUStrategy.maximumInterfaceMTU else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.mtu, reason: "must be in 1280...65535")
        }
        switch profile.mtuStrategy {
        case .fixed(let mtu):
            guard mtu >= TunnelMTUStrategy.minimumRuntimeMTU,
                  mtu <= TunnelMTUStrategy.maximumInterfaceMTU else {
                throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.mtu, reason: "must be in 1280...65535")
            }
        case .automaticTunnelOverhead(let overhead):
            if let rawOverhead = providerConfiguration[TunnelProviderConfigurationKey.tunnelOverheadBytes],
               !isExactTunnelOverhead(rawOverhead) {
                throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.tunnelOverheadBytes, reason: "must be in 0...65535")
            }
            guard overhead >= 0,
                  overhead <= TunnelMTUStrategy.maximumTunnelOverheadBytes else {
                throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.tunnelOverheadBytes, reason: "must be in 0...65535")
            }
        }
        guard isValidHostNameOrAddress(profile.tunnelRemoteAddress) else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.tunnelRemoteAddress, reason: "must be a hostname or IP literal without whitespace")
        }
        guard isValidIPv4Address(profile.ipv4Address) else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.ipv4Address, reason: "must be a valid IPv4 address")
        }
        guard isValidIPv4SubnetMask(profile.ipv4SubnetMask) else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.ipv4SubnetMask, reason: "must be a contiguous IPv4 subnet mask")
        }
        guard isValidIPv4Address(profile.ipv4Router) else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.ipv4Router, reason: "must be a valid IPv4 address")
        }
        try validateIPv4RouteStrategy(profile.ipv4RouteStrategy, rawValue: providerConfiguration[TunnelProviderConfigurationKey.ipv4IncludedRoutes])
        guard profile.ipv6PrefixLength > 0, profile.ipv6PrefixLength <= 128 else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.ipv6PrefixLength, reason: "must be in 1...128")
        }
        if profile.ipv6Enabled, !isValidIPv6Address(profile.ipv6Address) {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.ipv6Address, reason: "must be a valid IPv6 address when IPv6 is enabled")
        }
        guard exactUInt16(providerConfiguration[TunnelProviderConfigurationKey.engineSocksPort], allowingZero: true) != nil else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.engineSocksPort, reason: "must be in 0...65535")
        }
        guard isSafeFileName(profile.signatureFileName) else {
            throw TunnelProfileValidationError.invalidValue(key: TunnelProviderConfigurationKey.signatureFileName, reason: "must be a single file name without path separators")
        }
        try validateStringArrayProviderValues(providerConfiguration)
        try validateDNSStrategy(profile.dnsStrategy)
        try validateDataplaneConfig(profile.dataplaneConfigJSON)
        return profile
    }

    /// Parses an integer-like value from `Any`.
    /// - Parameters:
    ///   - value: Candidate value (`Int`, `NSNumber`, or numeric `String`).
    ///   - defaultValue: Fallback when parsing fails.
    private static func int(_ value: Any?, default defaultValue: Int) -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            guard !isBooleanNumber(value) else {
                return defaultValue
            }
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return defaultValue
    }

    private static func exactInt(_ value: Any?) -> Int? {
        if let value = value as? Int {
            return value
        }
        if let value = value as? NSNumber {
            guard !isBooleanNumber(value) else {
                return nil
            }
            let candidate = value.doubleValue
            guard candidate.isFinite,
                  candidate.rounded(.towardZero) == candidate,
                  candidate >= Double(Int.min),
                  candidate <= Double(Int.max)
            else {
                return nil
            }
            return Int(candidate)
        }
        if let value = value as? String {
            return Int(value)
        }
        return nil
    }

    private static func isBooleanNumber(_ value: NSNumber) -> Bool {
        CFGetTypeID(value) == CFBooleanGetTypeID()
    }

    private static func exactUInt16(_ value: Any?, allowingZero: Bool) -> UInt16? {
        guard let parsed = exactInt(value),
              parsed >= (allowingZero ? 0 : 1),
              parsed <= Int(UInt16.max)
        else {
            return nil
        }
        return UInt16(parsed)
    }

    private static func isExactMTU(_ value: Any?) -> Bool {
        guard let parsed = exactInt(value) else {
            return false
        }
        return parsed >= TunnelMTUStrategy.minimumRuntimeMTU && parsed <= TunnelMTUStrategy.maximumInterfaceMTU
    }

    private static func isExactTunnelOverhead(_ value: Any?) -> Bool {
        guard let parsed = exactInt(value) else {
            return false
        }
        return parsed >= 0 && parsed <= TunnelMTUStrategy.maximumTunnelOverheadBytes
    }

    /// Parses a positive `UInt16` from loosely typed input.
    /// - Parameters:
    ///   - value: Candidate port value.
    ///   - defaultValue: Fallback port when parsing fails.
    private static func uint16(_ value: Any?, default defaultValue: UInt16) -> UInt16 {
        let parsed = int(value, default: Int(defaultValue))
        if parsed <= 0 {
            return defaultValue
        }
        return UInt16(clamping: parsed)
    }

    /// Parses a `UInt16` while preserving zero for callers that explicitly want an ephemeral port.
    /// - Parameters:
    ///   - value: Candidate port value.
    ///   - defaultValue: Fallback port when parsing fails.
    private static func uint16AllowingZero(_ value: Any?, default defaultValue: UInt16) -> UInt16 {
        let parsed = int(value, default: Int(defaultValue))
        if parsed < 0 {
            return defaultValue
        }
        return UInt16(clamping: parsed)
    }

    /// Parses a boolean from loosely typed input.
    /// - Parameters:
    ///   - value: Candidate value (`Bool`, `NSNumber`, or `String`).
    ///   - defaultValue: Fallback when parsing fails.
    private static func bool(_ value: Any?, default defaultValue: Bool) -> Bool {
        if let value = value as? Bool {
            return value
        }
        if let value = value as? NSNumber {
            return value.boolValue
        }
        if let value = value as? String {
            return (value as NSString).boolValue
        }
        return defaultValue
    }

    private static func string(_ value: Any?) -> String? {
        if let value = value as? String {
            return value
        }
        return nil
    }

    private static func stringArray(_ value: Any?) -> [String]? {
        if let value = value as? [String] {
            return value
        }
        if let value = value as? [Any] {
            guard value.allSatisfy({ $0 is String }) else {
                return nil
            }
            return value as? [String]
        }
        return nil
    }

    private static func mtuStrategy(from providerConfiguration: [String: Any], legacyMTU: Int) -> TunnelMTUStrategy {
        guard let rawStrategy = string(providerConfiguration[TunnelProviderConfigurationKey.mtuStrategy]) else {
            if providerConfiguration[TunnelProviderConfigurationKey.mtu] != nil {
                return .fixed(legacyMTU)
            }
            return .recommendedGeneric
        }

        switch rawStrategy {
        case "automaticTunnelOverhead":
            return .automaticTunnelOverhead(
                max(0, int(providerConfiguration[TunnelProviderConfigurationKey.tunnelOverheadBytes], default: 80))
            )
        case "fixed":
            fallthrough
        default:
            return .fixed(legacyMTU)
        }
    }

    private static func dnsStrategy(from providerConfiguration: [String: Any]) -> TunnelDNSStrategy {
        let legacyServers = stringArray(providerConfiguration[TunnelProviderConfigurationKey.dnsServers])
        guard let rawStrategy = providerConfiguration[TunnelProviderConfigurationKey.dnsStrategy] as? [String: Any],
              let type = string(rawStrategy["type"]) else {
            if let legacyServers, !legacyServers.isEmpty {
                return .cleartext(servers: legacyServers)
            }
            return .recommendedDefault
        }

        switch type {
        case "none":
            return .noOverride
        case "tls":
            let servers = stringArray(rawStrategy["servers"]) ?? legacyServers ?? TunnelDNSStrategy.defaultPublicResolvers
            let serverName = string(rawStrategy["serverName"]) ?? ""
            return .tls(
                servers: servers,
                serverName: serverName,
                matchDomains: dnsMatchDomains(from: rawStrategy),
                matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: true),
                allowFailover: bool(rawStrategy["allowFailover"], default: false)
            )
        case "https":
            let servers = stringArray(rawStrategy["servers"]) ?? legacyServers ?? TunnelDNSStrategy.defaultPublicResolvers
            let serverURL = string(rawStrategy["serverURL"]) ?? ""
            return .https(
                servers: servers,
                serverURL: serverURL,
                matchDomains: dnsMatchDomains(from: rawStrategy),
                matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: true),
                allowFailover: bool(rawStrategy["allowFailover"], default: false)
            )
        case "cleartext":
            fallthrough
        default:
            return .cleartext(
                servers: stringArray(rawStrategy["servers"]) ?? legacyServers ?? TunnelDNSStrategy.defaultPublicResolvers,
                matchDomains: dnsMatchDomains(from: rawStrategy),
                matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: true),
                allowFailover: bool(rawStrategy["allowFailover"], default: false)
            )
        }
    }

    private static func ipv4RouteStrategy(from providerConfiguration: [String: Any]) -> TunnelIPv4RouteStrategy {
        guard let rawRoutes = providerConfiguration[TunnelProviderConfigurationKey.ipv4IncludedRoutes] else {
            return .defaultRoute
        }
        guard let routeDictionaries = ipv4RouteDictionaries(from: rawRoutes) else {
            return .defaultRoute
        }

        let routes = routeDictionaries.compactMap { route -> TunnelIPv4Route? in
            guard let destinationAddress = string(route["destinationAddress"]),
                  let subnetMask = string(route["subnetMask"]) else {
                return nil
            }
            return TunnelIPv4Route(destinationAddress: destinationAddress, subnetMask: subnetMask)
        }
        return routes.isEmpty ? .defaultRoute : .includedRoutes(routes)
    }

    private static func validateIPv4RouteStrategy(_ strategy: TunnelIPv4RouteStrategy, rawValue: Any?) throws {
        guard let rawValue else {
            return
        }
        guard let routeDictionaries = ipv4RouteDictionaries(from: rawValue), !routeDictionaries.isEmpty else {
            throw TunnelProfileValidationError.invalidValue(
                key: TunnelProviderConfigurationKey.ipv4IncludedRoutes,
                reason: "must be a non-empty array of IPv4 route dictionaries"
            )
        }

        let routes: [TunnelIPv4Route]
        switch strategy {
        case .defaultRoute:
            routes = []
        case .includedRoutes(let includedRoutes):
            routes = includedRoutes
        }

        guard routes.count == routeDictionaries.count else {
            throw TunnelProfileValidationError.invalidValue(
                key: TunnelProviderConfigurationKey.ipv4IncludedRoutes,
                reason: "each route must include destinationAddress and subnetMask strings"
            )
        }

        for route in routes {
            guard isValidIPv4Address(route.destinationAddress) else {
                throw TunnelProfileValidationError.invalidValue(
                    key: TunnelProviderConfigurationKey.ipv4IncludedRoutes,
                    reason: "destinationAddress must be a valid IPv4 address"
                )
            }
            guard isValidIPv4SubnetMask(route.subnetMask) else {
                throw TunnelProfileValidationError.invalidValue(
                    key: TunnelProviderConfigurationKey.ipv4IncludedRoutes,
                    reason: "subnetMask must be a contiguous IPv4 subnet mask"
                )
            }
        }
    }

    private static func ipv4RouteDictionaries(from value: Any?) -> [[String: Any]]? {
        if let routes = value as? [[String: Any]] {
            return routes
        }
        if let routes = value as? [[String: String]] {
            return routes.map { route in
                route.reduce(into: [String: Any]()) { partialResult, pair in
                    partialResult[pair.key] = pair.value
                }
            }
        }
        return nil
    }

    private static func dnsMatchDomains(from rawStrategy: [String: Any]) -> [String]? {
        stringArray(rawStrategy["matchDomains"]) ?? [""]
    }

    private static func validateDNSStrategy(_ strategy: TunnelDNSStrategy) throws {
        switch strategy {
        case .noOverride:
            return
        case .cleartext(let servers, let matchDomains, _, _):
            try validateDNSServers(servers, key: TunnelProviderConfigurationKey.dnsServers)
            try validateMatchDomains(matchDomains)
        case .tls(let servers, let serverName, let matchDomains, _, _):
            try validateDNSServers(servers, key: TunnelProviderConfigurationKey.dnsServers)
            guard isValidHostNameOrAddress(serverName) else {
                throw TunnelProfileValidationError.invalidValue(
                    key: "\(TunnelProviderConfigurationKey.dnsStrategy).serverName",
                    reason: "must be a DNS-over-TLS server name without whitespace"
                )
            }
            try validateMatchDomains(matchDomains)
        case .https(let servers, let serverURL, let matchDomains, _, _):
            try validateDNSServers(servers, key: TunnelProviderConfigurationKey.dnsServers)
            guard let url = URL(string: serverURL),
                  url.scheme?.lowercased() == "https",
                  url.host?.isEmpty == false else {
                throw TunnelProfileValidationError.invalidValue(
                    key: "\(TunnelProviderConfigurationKey.dnsStrategy).serverURL",
                    reason: "must be an HTTPS URL with a host"
                )
            }
            try validateMatchDomains(matchDomains)
        }
    }

    private static func validateStringArrayProviderValues(_ providerConfiguration: [String: Any]) throws {
        try validateStringArrayValue(
            providerConfiguration[TunnelProviderConfigurationKey.dnsServers],
            key: TunnelProviderConfigurationKey.dnsServers
        )
        guard let rawStrategy = providerConfiguration[TunnelProviderConfigurationKey.dnsStrategy] as? [String: Any] else {
            return
        }
        try validateStringArrayValue(
            rawStrategy["servers"],
            key: "\(TunnelProviderConfigurationKey.dnsStrategy).servers"
        )
        try validateStringArrayValue(
            rawStrategy["matchDomains"],
            key: "\(TunnelProviderConfigurationKey.dnsStrategy).matchDomains"
        )
    }

    private static func validateStringArrayValue(_ value: Any?, key: String) throws {
        guard let value else {
            return
        }
        if value is [String] {
            return
        }
        guard let array = value as? [Any], array.allSatisfy({ $0 is String }) else {
            throw TunnelProfileValidationError.invalidValue(key: key, reason: "must be an array of strings")
        }
    }

    private static func validateDNSServers(_ servers: [String], key: String) throws {
        guard !servers.isEmpty else {
            throw TunnelProfileValidationError.invalidValue(key: key, reason: "must include at least one resolver IP")
        }
        guard servers.allSatisfy({ isValidIPv4Address($0) || isValidIPv6Address($0) }) else {
            throw TunnelProfileValidationError.invalidValue(key: key, reason: "must contain only IPv4 or IPv6 resolver addresses")
        }
    }

    private static func validateMatchDomains(_ matchDomains: [String]?) throws {
        guard let matchDomains else {
            return
        }
        guard !matchDomains.isEmpty else {
            throw TunnelProfileValidationError.invalidValue(
                key: "\(TunnelProviderConfigurationKey.dnsStrategy).matchDomains",
                reason: "must include at least one domain selector; use an empty string for the default domain"
            )
        }
        // Apple NEDNSSettings.matchDomains selects which DNS queries use the tunnel resolvers.
        // Keep invalid selectors out of provider configuration so tunnel startup fails closed during validation.
        if !TunnelDNSStrategy.areValidMatchDomains(matchDomains) {
            throw TunnelProfileValidationError.invalidValue(
                key: "\(TunnelProviderConfigurationKey.dnsStrategy).matchDomains",
                reason: "must contain domain names without whitespace; use an empty string only for the default domain"
            )
        }
    }

    private static func isValidIPv4Address(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }

    private static func isValidIPv6Address(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) } == 1
    }

    private static func isValidIPv4SubnetMask(_ value: String) -> Bool {
        var address = in_addr()
        guard value.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else {
            return false
        }
        let mask = UInt32(bigEndian: address.s_addr)
        guard mask != 0 else {
            return false
        }
        let inverse = ~mask
        return inverse &+ 1 == 0 || (inverse & (inverse &+ 1)) == 0
    }

    private static func isValidHostNameOrAddress(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed == value,
              !containsWhitespace(value),
              value.range(of: "\0") == nil,
              value.rangeOfCharacter(from: CharacterSet.controlCharacters) == nil,
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
        if value.contains(":") {
            return false
        }
        if value.allSatisfy({ $0.isNumber || $0 == "." }) {
            return false
        }
        let normalized = value.hasSuffix(".") ? String(value.dropLast()) : value
        guard !normalized.isEmpty, normalized.utf8.count <= 253 else {
            return false
        }
        let labels = normalized.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else {
            return false
        }
        for label in labels {
            guard !label.isEmpty, label.utf8.count <= 63 else {
                return false
            }
            guard label.first != "-", label.last != "-" else {
                return false
            }
            guard label.allSatisfy({ character in
                character.isASCII && (character.isLetter || character.isNumber || character == "-")
            }) else {
                return false
            }
        }
        return true
    }

    private static func containsWhitespace(_ value: String) -> Bool {
        value.rangeOfCharacter(from: .whitespacesAndNewlines) != nil
    }

    private static func isSafeFileName(_ value: String) -> Bool {
        guard !value.isEmpty,
              value != ".",
              value != "..",
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              value.range(of: "\0") == nil,
              value == (value as NSString).lastPathComponent,
              !value.contains("/"),
              !value.contains("\\")
        else {
            return false
        }
        return true
    }

    private static func validateDataplaneConfig(_ config: String) throws {
        let trimmed = config.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "{}" else {
            return
        }

        let blockedKeys: Set<String> = [
            "pid-file",
            "post-up-script",
            "pre-down-script",
            "daemon"
        ]
        for line in trimmed.split(whereSeparator: \.isNewline) {
            guard let entry = dataplaneConfigEntry(from: String(line)) else {
                continue
            }
            if blockedKeys.contains(entry.key) {
                throw TunnelProfileValidationError.unsafeDataplaneConfig(entry.key)
            }
            if entry.key == "log-file", entry.value != "stderr" {
                throw TunnelProfileValidationError.unsafeDataplaneConfig("log-file")
            }
        }
    }

    private static func dataplaneConfigEntry(from line: String) -> (key: String, value: String)? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else {
            return nil
        }
        guard let colon = trimmed.firstIndex(of: ":") else {
            return nil
        }
        let rawKey = trimmed[..<colon]
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            .lowercased()
        guard !rawKey.isEmpty else {
            return nil
        }
        let rawValue = trimmed[trimmed.index(after: colon)...]
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            .lowercased()
        return (rawKey, rawValue)
    }
}

public enum TunnelProfileValidationError: LocalizedError, Equatable, Sendable {
    case missingRequiredKeys([String])
    case invalidValue(key: String, reason: String)
    case unsafeDataplaneConfig(String)

    public var errorDescription: String? {
        switch self {
        case .missingRequiredKeys(let keys):
            return "Tunnel provider configuration is missing required keys: \(keys.joined(separator: ", "))."
        case .invalidValue(let key, let reason):
            return "Tunnel provider configuration value '\(key)' is invalid: \(reason)."
        case .unsafeDataplaneConfig(let token):
            return "Tunnel dataplane configuration contains unsupported production token '\(token)'."
        }
    }
}
