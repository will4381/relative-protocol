// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Darwin
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
    public let keepaliveIntervalSeconds: TimeInterval
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
    public let tunnelOverheadBytes: Int

    public init(providerConfiguration: [String: Any]) {
        appGroupID = Self.string(providerConfiguration["appGroupID"], default: "")
        relayMode = Self.string(providerConfiguration["relayMode"], default: "tun2socks")
        mtu = Self.clamp(Self.int(providerConfiguration["mtu"], default: 1400), min: 576, max: 9000)
        ipv6Enabled = Self.bool(providerConfiguration["ipv6Enabled"], default: true)
        dnsServers = Self.stringArray(providerConfiguration["dnsServers"], default: [])
        enginePacketPoolBytes = Self.int(providerConfiguration["enginePacketPoolBytes"], default: 2_097_152)
        enginePerFlowBufferBytes = Self.int(providerConfiguration["enginePerFlowBufferBytes"], default: 16_384)
        engineMaxFlows = Self.int(providerConfiguration["engineMaxFlows"], default: 512)
        engineSocksPort = Self.port(providerConfiguration["engineSocksPort"], default: 1080)
        engineLogLevel = Self.string(providerConfiguration["engineLogLevel"], default: "")
        metricsEnabled = Self.bool(providerConfiguration["metricsEnabled"], default: true)
        metricsRingBufferSize = Self.clamp(Self.int(providerConfiguration["metricsRingBufferSize"], default: 2048), min: 1, max: 100_000)
        metricsSnapshotInterval = Self.clamp(Self.double(providerConfiguration["metricsSnapshotInterval"], default: 5.0), min: 1.0, max: 3600.0)
        keepaliveIntervalSeconds = Self.clamp(Self.double(providerConfiguration["keepaliveIntervalSeconds"], default: 25.0), min: 0.0, max: 3600.0)
        metricsStoreFormat = Self.metricsFormat(providerConfiguration["metricsStoreFormat"])
        burstThresholdMs = Self.clamp(Self.int(providerConfiguration["burstThresholdMs"], default: 350), min: 1, max: 60_000)
        flowTTLSeconds = Self.clamp(Self.int(providerConfiguration["flowTTLSeconds"], default: 300), min: 1, max: 86_400)
        maxTrackedFlows = Self.clamp(Self.int(providerConfiguration["maxTrackedFlows"], default: 2048), min: 1, max: 100_000)
        maxPendingAnalytics = Self.clamp(Self.int(providerConfiguration["maxPendingAnalytics"], default: 512), min: 1, max: 10_000)
        packetStreamEnabled = Self.bool(providerConfiguration["packetStreamEnabled"], default: false)
        packetStreamMaxBytes = Self.clamp(Self.int(providerConfiguration["packetStreamMaxBytes"], default: 5_000_000), min: 65_536, max: 100_000_000)
        signatureFileName = Self.string(providerConfiguration["signatureFileName"], default: AppSignatureStore.defaultFileName)

        ipv4Address = Self.ipv4Address(providerConfiguration["ipv4Address"], default: "10.0.0.2")
        ipv4SubnetMask = Self.ipv4Address(providerConfiguration["ipv4SubnetMask"], default: "255.255.255.0")
        ipv4Router = Self.ipv4Address(providerConfiguration["ipv4Router"], default: "10.0.0.1")
        ipv6Address = Self.ipv6Address(providerConfiguration["ipv6Address"], default: "fd00:1:1:1::2")
        ipv6PrefixLength = Self.clamp(Self.int(providerConfiguration["ipv6PrefixLength"], default: 64), min: 8, max: 128)
        tunnelRemoteAddress = Self.ipAddress(providerConfiguration["tunnelRemoteAddress"], default: "127.0.0.1")
        tunnelOverheadBytes = Self.clamp(Self.int(providerConfiguration["tunnelOverheadBytes"], default: 80), min: 0, max: 1024)
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

    private static func clamp(_ value: Int, min minValue: Int, max maxValue: Int) -> Int {
        Swift.max(minValue, Swift.min(maxValue, value))
    }

    private static func clamp(_ value: TimeInterval, min minValue: TimeInterval, max maxValue: TimeInterval) -> TimeInterval {
        Swift.max(minValue, Swift.min(maxValue, value))
    }

    private static func port(_ value: Any?, default defaultValue: Int) -> Int {
        let parsed = int(value, default: defaultValue)
        guard (1...65_535).contains(parsed) else {
            return defaultValue
        }
        return parsed
    }

    private static func ipv4Address(_ value: Any?, default defaultValue: String) -> String {
        let candidate = string(value, default: defaultValue)
        return isValidIPv4Address(candidate) ? candidate : defaultValue
    }

    private static func ipv6Address(_ value: Any?, default defaultValue: String) -> String {
        let candidate = string(value, default: defaultValue)
        return isValidIPv6Address(candidate) ? candidate : defaultValue
    }

    private static func ipAddress(_ value: Any?, default defaultValue: String) -> String {
        let candidate = string(value, default: defaultValue)
        return isValidIPAddress(candidate) ? candidate : defaultValue
    }

    private static func isValidIPv4Address(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isValidIPv6Address(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private static func isValidIPAddress(_ value: String) -> Bool {
        isValidIPv4Address(value) || isValidIPv6Address(value)
    }
}
