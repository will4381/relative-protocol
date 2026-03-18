import Darwin
import Foundation

/// IP protocol version discriminator.
public enum IPVersion: UInt8, Codable, Sendable {
    case v4 = 4
    case v6 = 6
}

/// Lightweight transport protocol wrapper that preserves unknown values.
public struct TransportProtocol: RawRepresentable, Codable, Hashable, Sendable, Equatable {
    public let rawValue: UInt8

    /// - Parameter rawValue: IANA protocol number.
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let tcp = TransportProtocol(rawValue: 6)
    public static let udp = TransportProtocol(rawValue: 17)
    public static let icmp = TransportProtocol(rawValue: 1)
    public static let icmpv6 = TransportProtocol(rawValue: 58)
}

/// Packet direction relative to the device tunnel interface.
public enum PacketDirection: String, Codable, Sendable {
    case outbound
    case inbound
}

/// QUIC packet type extracted from long-header packets.
public enum QuicPacketType: String, Codable, Sendable {
    case initial
    case zeroRTT
    case handshake
    case retry
}

/// Normalized IPv4/IPv6 address storage.
public struct IPAddress: Hashable, Codable, Sendable {
    /// Network-order bytes (`4` for IPv4, `16` for IPv6).
    public let bytes: Data

    private static let stringCache = BoundedCache<Data, String>(countLimit: 4_096)

    /// - Parameter bytes: Raw address bytes.
    public init?(bytes: Data) {
        guard bytes.count == 4 || bytes.count == 16 else { return nil }
        self.bytes = bytes
    }

    /// Inferred address family from byte length.
    public var version: IPVersion {
        bytes.count == 4 ? .v4 : .v6
    }

    /// Cached text form for logging and analytics keys.
    public var stringValue: String {
        if let cached = Self.stringCache.value(for: bytes) {
            return cached
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
            }

            var addr = in6_addr()
            memcpy(&addr, baseAddress, 16)
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let result = inet_ntop(AF_INET6, &addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
            return result == nil ? "" : String(cString: buffer)
        }

        if !value.isEmpty {
            Self.stringCache.insert(value, for: bytes)
        }
        return value
    }
}

/// Parsed packet metadata used by analytics and classification.
/// Invariant: `srcPort` and `dstPort` are non-`nil` only for TCP/UDP.
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

    /// - Parameters:
    ///   - ipVersion: IP version extracted from packet header.
    ///   - transport: Transport protocol number.
    ///   - srcAddress: Source IP address.
    ///   - dstAddress: Destination IP address.
    ///   - srcPort: Source transport port, when available.
    ///   - dstPort: Destination transport port, when available.
    ///   - length: Packet byte length.
    ///   - dnsQueryName: DNS query name when packet carries DNS.
    ///   - dnsCname: DNS CNAME answer, when present.
    ///   - dnsAnswerAddresses: DNS A/AAAA answer addresses.
    ///   - registrableDomain: Normalized registrable domain.
    ///   - tlsServerName: TLS SNI hostname.
    ///   - quicVersion: QUIC version (long header only).
    ///   - quicPacketType: Parsed QUIC packet type.
    ///   - quicDestinationConnectionId: QUIC destination connection ID (hex).
    ///   - quicSourceConnectionId: QUIC source connection ID (hex).
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
