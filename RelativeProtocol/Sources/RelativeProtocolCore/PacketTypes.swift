// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Darwin
import Foundation

public enum IPVersion: UInt8, Codable, Sendable {
    case v4 = 4
    case v6 = 6
}

public struct TransportProtocol: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let tcp = TransportProtocol(rawValue: 6)
    public static let udp = TransportProtocol(rawValue: 17)
    public static let icmp = TransportProtocol(rawValue: 1)
    public static let icmpv6 = TransportProtocol(rawValue: 58)
}

public enum PacketDirection: String, Codable, Sendable {
    case outbound
    case inbound
}

public enum QuicPacketType: String, Codable, Sendable {
    case initial
    case zeroRTT
    case handshake
    case retry
}

public struct IPAddress: Hashable, Codable, Sendable {
    public let bytes: Data

    private static let stringCache: NSCache<NSData, NSString> = {
        let cache = NSCache<NSData, NSString>()
        cache.countLimit = 4096
        return cache
    }()

    public init?(bytes: Data) {
        guard bytes.count == 4 || bytes.count == 16 else { return nil }
        self.bytes = bytes
    }

    public var version: IPVersion {
        bytes.count == 4 ? .v4 : .v6
    }

    public var stringValue: String {
        let key = bytes as NSData
        if let cached = Self.stringCache.object(forKey: key) {
            return cached as String
        }
        let value = bytes.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else {
                return ""
            }

            if bytes.count == 4 {
                var addr = in_addr()
                memcpy(&addr, baseAddress, 4)
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                let result = inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN))
                return result == nil ? "" : String(cString: buffer)
            } else {
                var addr = in6_addr()
                memcpy(&addr, baseAddress, 16)
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let result = inet_ntop(AF_INET6, &addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
                return result == nil ? "" : String(cString: buffer)
            }
        }
        if !value.isEmpty {
            Self.stringCache.setObject(value as NSString, forKey: key)
        }
        return value
    }
}

public struct FlowKey: Hashable, Sendable {
    public let ipVersion: IPVersion
    public let transport: TransportProtocol
    public let srcAddress: IPAddress
    public let dstAddress: IPAddress
    public let srcPort: UInt16
    public let dstPort: UInt16
}

public struct PacketMetadata: Sendable {
    public let ipVersion: IPVersion
    public let transport: TransportProtocol
    public let srcAddress: IPAddress
    public let dstAddress: IPAddress
    public let srcPort: UInt16?
    public let dstPort: UInt16?
    public let length: Int
    public let dnsQueryName: String?
    public let dnsCname: String?
    public let dnsAnswerAddresses: [IPAddress]?
    public let registrableDomain: String?
    public let tlsServerName: String?
    public let quicVersion: UInt32?
    public let quicPacketType: QuicPacketType?
    public let quicDestinationConnectionId: String?
    public let quicSourceConnectionId: String?

    public init(
        ipVersion: IPVersion,
        transport: TransportProtocol,
        srcAddress: IPAddress,
        dstAddress: IPAddress,
        srcPort: UInt16?,
        dstPort: UInt16?,
        length: Int,
        dnsQueryName: String?,
        dnsCname: String?,
        dnsAnswerAddresses: [IPAddress]? = nil,
        registrableDomain: String?,
        tlsServerName: String?,
        quicVersion: UInt32?,
        quicPacketType: QuicPacketType?,
        quicDestinationConnectionId: String?,
        quicSourceConnectionId: String?
    ) {
        self.ipVersion = ipVersion
        self.transport = transport
        self.srcAddress = srcAddress
        self.dstAddress = dstAddress
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.length = length
        self.dnsQueryName = dnsQueryName
        self.dnsCname = dnsCname
        self.dnsAnswerAddresses = dnsAnswerAddresses
        self.registrableDomain = registrableDomain
        self.tlsServerName = tlsServerName
        self.quicVersion = quicVersion
        self.quicPacketType = quicPacketType
        self.quicDestinationConnectionId = quicDestinationConnectionId
        self.quicSourceConnectionId = quicSourceConnectionId
    }
}

public struct PacketSample: Codable, Hashable, Sendable {
    public let timestamp: TimeInterval
    public let direction: PacketDirection
    public let ipVersion: IPVersion
    public let transport: TransportProtocol
    public let length: Int
    public let flowId: UInt64
    public let burstId: UInt32
    public let srcAddress: String?
    public let dstAddress: String?
    public let srcPort: UInt16?
    public let dstPort: UInt16?
    public let dnsQueryName: String?
    public let dnsCname: String?
    public let dnsAnswerAddresses: [String]?
    public let registrableDomain: String?
    public let tlsServerName: String?
    public let quicVersion: UInt32?
    public let quicPacketType: QuicPacketType?
    public let quicDestinationConnectionId: String?
    public let quicSourceConnectionId: String?
    public let burstMetrics: BurstMetrics?
    public let trafficClassification: TrafficClassification?

    public init(
        timestamp: TimeInterval,
        direction: PacketDirection,
        ipVersion: IPVersion,
        transport: TransportProtocol,
        length: Int,
        flowId: UInt64,
        burstId: UInt32,
        srcAddress: String?,
        dstAddress: String?,
        srcPort: UInt16?,
        dstPort: UInt16?,
        dnsQueryName: String?,
        dnsCname: String?,
        dnsAnswerAddresses: [String]? = nil,
        registrableDomain: String?,
        tlsServerName: String?,
        quicVersion: UInt32?,
        quicPacketType: QuicPacketType?,
        quicDestinationConnectionId: String?,
        quicSourceConnectionId: String?,
        burstMetrics: BurstMetrics? = nil,
        trafficClassification: TrafficClassification? = nil
    ) {
        self.timestamp = timestamp
        self.direction = direction
        self.ipVersion = ipVersion
        self.transport = transport
        self.length = length
        self.flowId = flowId
        self.burstId = burstId
        self.srcAddress = srcAddress
        self.dstAddress = dstAddress
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.dnsQueryName = dnsQueryName
        self.dnsCname = dnsCname
        self.dnsAnswerAddresses = dnsAnswerAddresses
        self.registrableDomain = registrableDomain
        self.tlsServerName = tlsServerName
        self.quicVersion = quicVersion
        self.quicPacketType = quicPacketType
        self.quicDestinationConnectionId = quicDestinationConnectionId
        self.quicSourceConnectionId = quicSourceConnectionId
        self.burstMetrics = burstMetrics
        self.trafficClassification = trafficClassification
    }
}

public struct MetricsSnapshot: Codable, Sendable {
    public let capturedAt: TimeInterval
    public let samples: [PacketSample]

    public init(capturedAt: TimeInterval, samples: [PacketSample]) {
        self.capturedAt = capturedAt
        self.samples = samples
    }
}
