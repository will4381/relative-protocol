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

public struct IPAddress: Hashable, Codable, Sendable {
    public let bytes: Data

    public init?(bytes: Data) {
        guard bytes.count == 4 || bytes.count == 16 else { return nil }
        self.bytes = bytes
    }

    public var version: IPVersion {
        bytes.count == 4 ? .v4 : .v6
    }

    public var stringValue: String {
        bytes.withUnsafeBytes { rawBuffer in
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

    public init(
        ipVersion: IPVersion,
        transport: TransportProtocol,
        srcAddress: IPAddress,
        dstAddress: IPAddress,
        srcPort: UInt16?,
        dstPort: UInt16?,
        length: Int,
        dnsQueryName: String?
    ) {
        self.ipVersion = ipVersion
        self.transport = transport
        self.srcAddress = srcAddress
        self.dstAddress = dstAddress
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.length = length
        self.dnsQueryName = dnsQueryName
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
    public let srcPort: UInt16?
    public let dstPort: UInt16?
    public let dnsQueryName: String?

    public init(
        timestamp: TimeInterval,
        direction: PacketDirection,
        ipVersion: IPVersion,
        transport: TransportProtocol,
        length: Int,
        flowId: UInt64,
        burstId: UInt32,
        srcPort: UInt16?,
        dstPort: UInt16?,
        dnsQueryName: String?
    ) {
        self.timestamp = timestamp
        self.direction = direction
        self.ipVersion = ipVersion
        self.transport = transport
        self.length = length
        self.flowId = flowId
        self.burstId = burstId
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.dnsQueryName = dnsQueryName
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
