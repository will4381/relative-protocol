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

    public init?(string: String) {
        var v4 = in_addr()
        if string.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            var bytes = Data(repeating: 0, count: 4)
            bytes.withUnsafeMutableBytes { rawBuffer in
                guard let baseAddress = rawBuffer.baseAddress else { return }
                memcpy(baseAddress, &v4, 4)
            }
            self.bytes = bytes
            return
        }

        var v6 = in6_addr()
        if string.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            var bytes = Data(repeating: 0, count: 16)
            bytes.withUnsafeMutableBytes { rawBuffer in
                guard let baseAddress = rawBuffer.baseAddress else { return }
                memcpy(baseAddress, &v6, 16)
            }
            self.bytes = bytes
            return
        }

        return nil
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

private enum PacketSampleAddressValue: Hashable, Sendable {
    case ip(IPAddress)
    case literal(String)

    init(string: String) {
        if let address = IPAddress(string: string) {
            self = .ip(address)
        } else {
            self = .literal(string)
        }
    }

    var stringValue: String {
        switch self {
        case .ip(let address):
            return address.stringValue
        case .literal(let value):
            return value
        }
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
    private let srcAddressValue: PacketSampleAddressValue?
    private let dstAddressValue: PacketSampleAddressValue?
    public let srcPort: UInt16?
    public let dstPort: UInt16?
    public let dnsQueryName: String?
    public let dnsCname: String?
    private let dnsAnswerAddressValues: [PacketSampleAddressValue]?
    public let registrableDomain: String?
    public let tlsServerName: String?
    public let quicVersion: UInt32?
    public let quicPacketType: QuicPacketType?
    public let quicDestinationConnectionId: String?
    public let quicSourceConnectionId: String?
    public let burstMetrics: BurstMetrics?
    public let trafficClassification: TrafficClassification?

    public var srcAddress: String? {
        srcAddressValue?.stringValue
    }

    public var dstAddress: String? {
        dstAddressValue?.stringValue
    }

    public var dnsAnswerAddresses: [String]? {
        dnsAnswerAddressValues?.map(\.stringValue)
    }

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
        self.init(
            timestamp: timestamp,
            direction: direction,
            ipVersion: ipVersion,
            transport: transport,
            length: length,
            flowId: flowId,
            burstId: burstId,
            srcAddressValue: srcAddress.map(PacketSampleAddressValue.init(string:)),
            dstAddressValue: dstAddress.map(PacketSampleAddressValue.init(string:)),
            srcPort: srcPort,
            dstPort: dstPort,
            dnsQueryName: dnsQueryName,
            dnsCname: dnsCname,
            dnsAnswerAddressValues: dnsAnswerAddresses?.map(PacketSampleAddressValue.init(string:)),
            registrableDomain: registrableDomain,
            tlsServerName: tlsServerName,
            quicVersion: quicVersion,
            quicPacketType: quicPacketType,
            quicDestinationConnectionId: quicDestinationConnectionId,
            quicSourceConnectionId: quicSourceConnectionId,
            burstMetrics: burstMetrics,
            trafficClassification: trafficClassification
        )
    }

    public init(
        timestamp: TimeInterval,
        direction: PacketDirection,
        ipVersion: IPVersion,
        transport: TransportProtocol,
        length: Int,
        flowId: UInt64,
        burstId: UInt32,
        srcIPAddress: IPAddress?,
        dstIPAddress: IPAddress?,
        srcPort: UInt16?,
        dstPort: UInt16?,
        dnsQueryName: String?,
        dnsCname: String?,
        dnsAnswerIPAddresses: [IPAddress]? = nil,
        registrableDomain: String?,
        tlsServerName: String?,
        quicVersion: UInt32?,
        quicPacketType: QuicPacketType?,
        quicDestinationConnectionId: String?,
        quicSourceConnectionId: String?,
        burstMetrics: BurstMetrics? = nil,
        trafficClassification: TrafficClassification? = nil
    ) {
        self.init(
            timestamp: timestamp,
            direction: direction,
            ipVersion: ipVersion,
            transport: transport,
            length: length,
            flowId: flowId,
            burstId: burstId,
            srcAddressValue: srcIPAddress.map { .ip($0) },
            dstAddressValue: dstIPAddress.map { .ip($0) },
            srcPort: srcPort,
            dstPort: dstPort,
            dnsQueryName: dnsQueryName,
            dnsCname: dnsCname,
            dnsAnswerAddressValues: dnsAnswerIPAddresses?.map { .ip($0) },
            registrableDomain: registrableDomain,
            tlsServerName: tlsServerName,
            quicVersion: quicVersion,
            quicPacketType: quicPacketType,
            quicDestinationConnectionId: quicDestinationConnectionId,
            quicSourceConnectionId: quicSourceConnectionId,
            burstMetrics: burstMetrics,
            trafficClassification: trafficClassification
        )
    }

    private init(
        timestamp: TimeInterval,
        direction: PacketDirection,
        ipVersion: IPVersion,
        transport: TransportProtocol,
        length: Int,
        flowId: UInt64,
        burstId: UInt32,
        srcAddressValue: PacketSampleAddressValue?,
        dstAddressValue: PacketSampleAddressValue?,
        srcPort: UInt16?,
        dstPort: UInt16?,
        dnsQueryName: String?,
        dnsCname: String?,
        dnsAnswerAddressValues: [PacketSampleAddressValue]? = nil,
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
        self.srcAddressValue = srcAddressValue
        self.dstAddressValue = dstAddressValue
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.dnsQueryName = dnsQueryName
        self.dnsCname = dnsCname
        self.dnsAnswerAddressValues = dnsAnswerAddressValues
        self.registrableDomain = registrableDomain
        self.tlsServerName = tlsServerName
        self.quicVersion = quicVersion
        self.quicPacketType = quicPacketType
        self.quicDestinationConnectionId = quicDestinationConnectionId
        self.quicSourceConnectionId = quicSourceConnectionId
        self.burstMetrics = burstMetrics
        self.trafficClassification = trafficClassification
    }

    private enum CodingKeys: String, CodingKey {
        case timestamp
        case direction
        case ipVersion
        case transport
        case length
        case flowId
        case burstId
        case srcAddress
        case dstAddress
        case srcPort
        case dstPort
        case dnsQueryName
        case dnsCname
        case dnsAnswerAddresses
        case registrableDomain
        case tlsServerName
        case quicVersion
        case quicPacketType
        case quicDestinationConnectionId
        case quicSourceConnectionId
        case burstMetrics
        case trafficClassification
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let srcAddress = try container.decodeIfPresent(String.self, forKey: .srcAddress)
        let dstAddress = try container.decodeIfPresent(String.self, forKey: .dstAddress)
        let dnsAnswers = try container.decodeIfPresent([String].self, forKey: .dnsAnswerAddresses)

        self.init(
            timestamp: try container.decode(TimeInterval.self, forKey: .timestamp),
            direction: try container.decode(PacketDirection.self, forKey: .direction),
            ipVersion: try container.decode(IPVersion.self, forKey: .ipVersion),
            transport: try container.decode(TransportProtocol.self, forKey: .transport),
            length: try container.decode(Int.self, forKey: .length),
            flowId: try container.decode(UInt64.self, forKey: .flowId),
            burstId: try container.decode(UInt32.self, forKey: .burstId),
            srcAddressValue: srcAddress.map(PacketSampleAddressValue.init(string:)),
            dstAddressValue: dstAddress.map(PacketSampleAddressValue.init(string:)),
            srcPort: try container.decodeIfPresent(UInt16.self, forKey: .srcPort),
            dstPort: try container.decodeIfPresent(UInt16.self, forKey: .dstPort),
            dnsQueryName: try container.decodeIfPresent(String.self, forKey: .dnsQueryName),
            dnsCname: try container.decodeIfPresent(String.self, forKey: .dnsCname),
            dnsAnswerAddressValues: dnsAnswers?.map(PacketSampleAddressValue.init(string:)),
            registrableDomain: try container.decodeIfPresent(String.self, forKey: .registrableDomain),
            tlsServerName: try container.decodeIfPresent(String.self, forKey: .tlsServerName),
            quicVersion: try container.decodeIfPresent(UInt32.self, forKey: .quicVersion),
            quicPacketType: try container.decodeIfPresent(QuicPacketType.self, forKey: .quicPacketType),
            quicDestinationConnectionId: try container.decodeIfPresent(String.self, forKey: .quicDestinationConnectionId),
            quicSourceConnectionId: try container.decodeIfPresent(String.self, forKey: .quicSourceConnectionId),
            burstMetrics: try container.decodeIfPresent(BurstMetrics.self, forKey: .burstMetrics),
            trafficClassification: try container.decodeIfPresent(TrafficClassification.self, forKey: .trafficClassification)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(direction, forKey: .direction)
        try container.encode(ipVersion, forKey: .ipVersion)
        try container.encode(transport, forKey: .transport)
        try container.encode(length, forKey: .length)
        try container.encode(flowId, forKey: .flowId)
        try container.encode(burstId, forKey: .burstId)
        try container.encodeIfPresent(srcAddress, forKey: .srcAddress)
        try container.encodeIfPresent(dstAddress, forKey: .dstAddress)
        try container.encodeIfPresent(srcPort, forKey: .srcPort)
        try container.encodeIfPresent(dstPort, forKey: .dstPort)
        try container.encodeIfPresent(dnsQueryName, forKey: .dnsQueryName)
        try container.encodeIfPresent(dnsCname, forKey: .dnsCname)
        try container.encodeIfPresent(dnsAnswerAddresses, forKey: .dnsAnswerAddresses)
        try container.encodeIfPresent(registrableDomain, forKey: .registrableDomain)
        try container.encodeIfPresent(tlsServerName, forKey: .tlsServerName)
        try container.encodeIfPresent(quicVersion, forKey: .quicVersion)
        try container.encodeIfPresent(quicPacketType, forKey: .quicPacketType)
        try container.encodeIfPresent(quicDestinationConnectionId, forKey: .quicDestinationConnectionId)
        try container.encodeIfPresent(quicSourceConnectionId, forKey: .quicSourceConnectionId)
        try container.encodeIfPresent(burstMetrics, forKey: .burstMetrics)
        try container.encodeIfPresent(trafficClassification, forKey: .trafficClassification)
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
