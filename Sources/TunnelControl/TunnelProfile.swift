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
    ///   - ipv6Address: Assigned IPv6 address.
    ///   - ipv6PrefixLength: IPv6 prefix length.
    ///   - dnsServers: DNS servers pushed to the tunnel interface when `dnsStrategy` is not supplied.
    ///   - dnsStrategy: Controls which DNS settings are installed. Defaults to cleartext DNS over `dnsServers`.
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
    ///   - relayEndpoint: Upstream relay endpoint metadata.
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
        self.appGroupID = appGroupID
        self.tunnelRemoteAddress = tunnelRemoteAddress
        self.mtu = max(256, mtu)
        self.mtuStrategy = mtuStrategy ?? .fixed(self.mtu)
        self.ipv6Enabled = ipv6Enabled
        self.tcpMultipathHandoverEnabled = tcpMultipathHandoverEnabled
        self.ipv4Address = ipv4Address
        self.ipv4SubnetMask = ipv4SubnetMask
        self.ipv4Router = ipv4Router
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
        let relayHost = providerConfiguration["relayHost"] as? String ?? "127.0.0.1"
        let relayPort = uint16(providerConfiguration["relayPort"], default: 1080)
        let useUDP = providerConfiguration["relayUDP"] as? Bool ?? false
        let mtuValue = providerConfiguration["mtu"] == nil
            ? TunnelMTUStrategy.recommendedGeneric.bufferMTUHint
            : int(providerConfiguration["mtu"], default: TunnelMTUStrategy.recommendedGeneric.bufferMTUHint)
        let mtuStrategy = mtuStrategy(from: providerConfiguration, legacyMTU: mtuValue)
        let dnsStrategy = dnsStrategy(from: providerConfiguration)

        return TunnelProfile(
            appGroupID: providerConfiguration["appGroupID"] as? String ?? "",
            tunnelRemoteAddress: providerConfiguration["tunnelRemoteAddress"] as? String ?? "127.0.0.1",
            mtu: mtuValue,
            mtuStrategy: mtuStrategy,
            ipv6Enabled: bool(providerConfiguration["ipv6Enabled"], default: true),
            tcpMultipathHandoverEnabled: bool(providerConfiguration["tcpMultipathHandoverEnabled"], default: false),
            ipv4Address: providerConfiguration["ipv4Address"] as? String ?? "10.0.0.2",
            ipv4SubnetMask: providerConfiguration["ipv4SubnetMask"] as? String ?? "255.255.255.0",
            ipv4Router: providerConfiguration["ipv4Router"] as? String ?? "10.0.0.1",
            ipv6Address: providerConfiguration["ipv6Address"] as? String ?? "fd00:1::2",
            ipv6PrefixLength: int(providerConfiguration["ipv6PrefixLength"], default: 64),
            dnsServers: dnsStrategy.servers,
            dnsStrategy: dnsStrategy,
            engineSocksPort: uint16(providerConfiguration["engineSocksPort"], default: 1080),
            engineLogLevel: providerConfiguration["engineLogLevel"] as? String ?? "warn",
            telemetryEnabled: bool(providerConfiguration["telemetryEnabled"], default: true),
            liveTapEnabled: bool(providerConfiguration["liveTapEnabled"], default: false),
            liveTapIncludeFlowSlices: bool(providerConfiguration["liveTapIncludeFlowSlices"], default: false),
            liveTapMaxBytes: int(providerConfiguration["liveTapMaxBytes"], default: 5_000_000),
            signatureFileName: providerConfiguration["signatureFileName"] as? String ?? "app_signatures.json",
            relayEndpoint: RelayEndpoint(host: relayHost, port: relayPort, useUDP: useUDP),
            dataplaneConfigJSON: providerConfiguration["dataplaneConfigJSON"] as? String ?? "{}"
        )
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
            return value.intValue
        }
        if let value = value as? String, let parsed = Int(value) {
            return parsed
        }
        return defaultValue
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
            let strings = value.compactMap { $0 as? String }
            return strings.isEmpty ? nil : strings
        }
        return nil
    }

    private static func mtuStrategy(from providerConfiguration: [String: Any], legacyMTU: Int) -> TunnelMTUStrategy {
        guard let rawStrategy = string(providerConfiguration["mtuStrategy"]) else {
            if providerConfiguration["mtu"] != nil {
                return .fixed(legacyMTU)
            }
            return .recommendedGeneric
        }

        switch rawStrategy {
        case "automaticTunnelOverhead":
            return .automaticTunnelOverhead(
                max(0, int(providerConfiguration["tunnelOverheadBytes"], default: 80))
            )
        case "fixed":
            fallthrough
        default:
            return .fixed(legacyMTU)
        }
    }

    private static func dnsStrategy(from providerConfiguration: [String: Any]) -> TunnelDNSStrategy {
        let legacyServers = stringArray(providerConfiguration["dnsServers"])
        guard let rawStrategy = providerConfiguration["dnsStrategy"] as? [String: Any],
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
            if serverName.isEmpty {
                return .cleartext(
                    servers: servers,
                    matchDomains: stringArray(rawStrategy["matchDomains"]),
                    matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: false),
                    allowFailover: bool(rawStrategy["allowFailover"], default: false)
                )
            }
            return .tls(
                servers: servers,
                serverName: serverName,
                matchDomains: stringArray(rawStrategy["matchDomains"]),
                matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: false),
                allowFailover: bool(rawStrategy["allowFailover"], default: false)
            )
        case "https":
            let servers = stringArray(rawStrategy["servers"]) ?? legacyServers ?? TunnelDNSStrategy.defaultPublicResolvers
            let serverURL = string(rawStrategy["serverURL"]) ?? ""
            if serverURL.isEmpty {
                return .cleartext(
                    servers: servers,
                    matchDomains: stringArray(rawStrategy["matchDomains"]),
                    matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: false),
                    allowFailover: bool(rawStrategy["allowFailover"], default: false)
                )
            }
            return .https(
                servers: servers,
                serverURL: serverURL,
                matchDomains: stringArray(rawStrategy["matchDomains"]),
                matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: false),
                allowFailover: bool(rawStrategy["allowFailover"], default: false)
            )
        case "cleartext":
            fallthrough
        default:
            return .cleartext(
                servers: stringArray(rawStrategy["servers"]) ?? legacyServers ?? TunnelDNSStrategy.defaultPublicResolvers,
                matchDomains: stringArray(rawStrategy["matchDomains"]),
                matchDomainsNoSearch: bool(rawStrategy["matchDomainsNoSearch"], default: false),
                allowFailover: bool(rawStrategy["allowFailover"], default: false)
            )
        }
    }
}
