// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Foundation

public struct TunnelConfiguration: Sendable {
    public let appGroupID: String
    public let relayMode: String
    public let mtu: Int
    public let ipv6Enabled: Bool
    public let dnsServers: [String]
    public let enginePacketPoolBytes: Int
    public let enginePerFlowBufferBytes: Int
    public let engineMaxFlows: Int
    public let engineSocksPort: Int
    public let engineLogLevel: String
    public let metricsEnabled: Bool
    public let metricsRingBufferSize: Int
    public let metricsSnapshotInterval: TimeInterval
    public let metricsStoreFormat: MetricsStoreFormat
    public let burstThresholdMs: Int
    public let flowTTLSeconds: Int
    public let maxTrackedFlows: Int
    public let maxPendingAnalytics: Int
    public let packetStreamEnabled: Bool
    public let packetStreamMaxBytes: Int
    public let signatureFileName: String

    public let ipv4Address: String
    public let ipv4SubnetMask: String
    public let ipv4Router: String
    public let ipv6Address: String
    public let ipv6PrefixLength: Int
    public let tunnelRemoteAddress: String

    public init(providerConfiguration: [String: Any]) {
        appGroupID = Self.string(providerConfiguration["appGroupID"], default: "")
        relayMode = Self.string(providerConfiguration["relayMode"], default: "tun2socks")
        mtu = Self.int(providerConfiguration["mtu"], default: 1500)
        ipv6Enabled = Self.bool(providerConfiguration["ipv6Enabled"], default: true)
        dnsServers = Self.stringArray(providerConfiguration["dnsServers"], default: [])
        enginePacketPoolBytes = Self.int(providerConfiguration["enginePacketPoolBytes"], default: 2_097_152)
        enginePerFlowBufferBytes = Self.int(providerConfiguration["enginePerFlowBufferBytes"], default: 16_384)
        engineMaxFlows = Self.int(providerConfiguration["engineMaxFlows"], default: 512)
        engineSocksPort = Self.int(providerConfiguration["engineSocksPort"], default: 1080)
        engineLogLevel = Self.string(providerConfiguration["engineLogLevel"], default: "")
        metricsEnabled = Self.bool(providerConfiguration["metricsEnabled"], default: true)
        metricsRingBufferSize = Self.int(providerConfiguration["metricsRingBufferSize"], default: 2048)
        metricsSnapshotInterval = Self.double(providerConfiguration["metricsSnapshotInterval"], default: 1.0)
        metricsStoreFormat = Self.metricsFormat(providerConfiguration["metricsStoreFormat"])
        burstThresholdMs = Self.int(providerConfiguration["burstThresholdMs"], default: 350)
        flowTTLSeconds = Self.int(providerConfiguration["flowTTLSeconds"], default: 300)
        maxTrackedFlows = Self.int(providerConfiguration["maxTrackedFlows"], default: 2048)
        maxPendingAnalytics = Self.int(providerConfiguration["maxPendingAnalytics"], default: 512)
        packetStreamEnabled = Self.bool(providerConfiguration["packetStreamEnabled"], default: false)
        packetStreamMaxBytes = Self.int(providerConfiguration["packetStreamMaxBytes"], default: 5_000_000)
        signatureFileName = Self.string(providerConfiguration["signatureFileName"], default: AppSignatureStore.defaultFileName)

        ipv4Address = Self.string(providerConfiguration["ipv4Address"], default: "10.0.0.2")
        ipv4SubnetMask = Self.string(providerConfiguration["ipv4SubnetMask"], default: "255.255.255.0")
        ipv4Router = Self.string(providerConfiguration["ipv4Router"], default: "10.0.0.1")
        ipv6Address = Self.string(providerConfiguration["ipv6Address"], default: "fd00:1:1:1::2")
        ipv6PrefixLength = Self.int(providerConfiguration["ipv6PrefixLength"], default: 64)
        tunnelRemoteAddress = Self.string(providerConfiguration["tunnelRemoteAddress"], default: "127.0.0.1")
    }

    private static func string(_ value: Any?, default defaultValue: String) -> String {
        if let value = value as? String, !value.isEmpty {
            return value
        }
        return defaultValue
    }

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

    private static func double(_ value: Any?, default defaultValue: TimeInterval) -> TimeInterval {
        if let value = value as? TimeInterval {
            return value
        }
        if let value = value as? NSNumber {
            return value.doubleValue
        }
        if let value = value as? String, let parsed = Double(value) {
            return parsed
        }
        return defaultValue
    }

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

    private static func stringArray(_ value: Any?, default defaultValue: [String]) -> [String] {
        if let value = value as? [String] {
            return value
        }
        if let value = value as? [Any] {
            return value.compactMap { $0 as? String }
        }
        return defaultValue
    }

    private static func metricsFormat(_ value: Any?) -> MetricsStoreFormat {
        if let value = value as? MetricsStoreFormat {
            return value
        }
        if let value = value as? String, let format = MetricsStoreFormat(rawValue: value.lowercased()) {
            return format
        }
        return .json
    }
}
