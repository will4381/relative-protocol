import Foundation
import PacketRelay

/// Decoded provider configuration used by extension startup.
/// Invariant: values are pre-normalized with safe defaults for missing keys.
public struct TunnelProfile: Sendable, Equatable {
    /// App Group identifier used for shared storage (logs, metrics, signatures).
    public let appGroupID: String
    /// Remote address required by `NEPacketTunnelNetworkSettings`.
    public let tunnelRemoteAddress: String
    /// Virtual tunnel interface MTU.
    public let mtu: Int
    /// Enables or disables IPv6 settings installation.
    public let ipv6Enabled: Bool
    public let ipv4Address: String
    public let ipv4SubnetMask: String
    public let ipv4Router: String
    public let ipv6Address: String
    public let ipv6PrefixLength: Int
    public let dnsServers: [String]
    public let engineSocksPort: UInt16
    public let engineLogLevel: String
    public let packetStreamEnabled: Bool
    public let packetStreamMaxBytes: Int
    public let signatureFileName: String
    public let relayEndpoint: RelayEndpoint
    public let dataplaneConfigJSON: String

    /// Creates a fully-specified tunnel profile.
    /// - Parameters:
    ///   - appGroupID: App Group identifier for shared data paths.
    ///   - tunnelRemoteAddress: Tunnel remote address required by NetworkExtension.
    ///   - mtu: Virtual interface MTU.
    ///   - ipv6Enabled: Controls whether IPv6 settings are installed.
    ///   - ipv4Address: Assigned IPv4 address.
    ///   - ipv4SubnetMask: Assigned IPv4 subnet mask.
    ///   - ipv4Router: Default IPv4 router.
    ///   - ipv6Address: Assigned IPv6 address.
    ///   - ipv6PrefixLength: IPv6 prefix length.
    ///   - dnsServers: DNS servers pushed to the tunnel interface.
    ///   - engineSocksPort: Local SOCKS server listen port.
    ///   - engineLogLevel: Dataplane log level hint.
    ///   - packetStreamEnabled: Enables packet sample stream persistence.
    ///   - packetStreamMaxBytes: Max packet stream size before truncation.
    ///   - signatureFileName: Signature filename loaded by classifier.
    ///   - relayEndpoint: Upstream relay endpoint metadata.
    ///   - dataplaneConfigJSON: Dataplane config template or raw config.
    public init(
        appGroupID: String,
        tunnelRemoteAddress: String,
        mtu: Int,
        ipv6Enabled: Bool,
        ipv4Address: String,
        ipv4SubnetMask: String,
        ipv4Router: String,
        ipv6Address: String,
        ipv6PrefixLength: Int,
        dnsServers: [String],
        engineSocksPort: UInt16,
        engineLogLevel: String,
        packetStreamEnabled: Bool,
        packetStreamMaxBytes: Int,
        signatureFileName: String,
        relayEndpoint: RelayEndpoint,
        dataplaneConfigJSON: String
    ) {
        self.appGroupID = appGroupID
        self.tunnelRemoteAddress = tunnelRemoteAddress
        self.mtu = mtu
        self.ipv6Enabled = ipv6Enabled
        self.ipv4Address = ipv4Address
        self.ipv4SubnetMask = ipv4SubnetMask
        self.ipv4Router = ipv4Router
        self.ipv6Address = ipv6Address
        self.ipv6PrefixLength = ipv6PrefixLength
        self.dnsServers = dnsServers
        self.engineSocksPort = engineSocksPort
        self.engineLogLevel = engineLogLevel
        self.packetStreamEnabled = packetStreamEnabled
        self.packetStreamMaxBytes = packetStreamMaxBytes
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

        return TunnelProfile(
            appGroupID: providerConfiguration["appGroupID"] as? String ?? "",
            tunnelRemoteAddress: providerConfiguration["tunnelRemoteAddress"] as? String ?? "127.0.0.1",
            mtu: int(providerConfiguration["mtu"], default: 1500),
            ipv6Enabled: bool(providerConfiguration["ipv6Enabled"], default: true),
            ipv4Address: providerConfiguration["ipv4Address"] as? String ?? "10.0.0.2",
            ipv4SubnetMask: providerConfiguration["ipv4SubnetMask"] as? String ?? "255.255.255.0",
            ipv4Router: providerConfiguration["ipv4Router"] as? String ?? "10.0.0.1",
            ipv6Address: providerConfiguration["ipv6Address"] as? String ?? "fd00:1::2",
            ipv6PrefixLength: int(providerConfiguration["ipv6PrefixLength"], default: 64),
            dnsServers: providerConfiguration["dnsServers"] as? [String] ?? ["1.1.1.1"],
            engineSocksPort: uint16(providerConfiguration["engineSocksPort"], default: 1080),
            engineLogLevel: providerConfiguration["engineLogLevel"] as? String ?? "warn",
            packetStreamEnabled: bool(providerConfiguration["packetStreamEnabled"], default: false),
            packetStreamMaxBytes: int(providerConfiguration["packetStreamMaxBytes"], default: 5_000_000),
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
}
