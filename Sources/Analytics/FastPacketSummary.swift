import Foundation
import PacketIntelligenceCore

/// Zero-copy packet header summary produced by the C fast path.
/// Decision: the fast path owns cheap packet/header extraction, while Swift layers cache any expensive enrichment.
struct FastPacketSummary: Sendable {
    let ipVersion: UInt8
    let transportProtocolNumber: UInt8
    let flags: UInt8
    let sourceAddressLength: UInt8
    let destinationAddressLength: UInt8
    let tcpFlags: UInt8
    let quicPacketTypeRaw: UInt8
    let sourcePort: UInt16
    let destinationPort: UInt16
    let transportPayloadOffset: UInt16
    let packetLength: Int
    let quicVersion: UInt32?
    let flowHash: UInt64
    let reverseFlowHash: UInt64
    let sourceAddressHigh: UInt64
    let sourceAddressLow: UInt64
    let destinationAddressHigh: UInt64
    let destinationAddressLow: UInt64
    let quicDestinationConnectionID: Data?
    let quicSourceConnectionID: Data?

    /// Docs: https://developer.apple.com/documentation/foundation/data/withunsafebytes(_:)
    /// `Data.withUnsafeBytes` exposes the packet buffer to the C parser without copying.
    /// - Parameters:
    ///   - data: Raw packet bytes emitted by the tunnel interface or dataplane bridge.
    ///   - ipVersionHint: Optional address-family hint supplied by `NEPacketTunnelFlow`.
    init?(data: Data, ipVersionHint: Int32?) {
        guard !data.isEmpty else {
            return nil
        }

        var raw = rbpi_fast_packet_t()
        let parsed = data.withUnsafeBytes { rawBuffer -> Bool in
            guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return false
            }
            return rbpi_parse_packet(baseAddress, rawBuffer.count, ipVersionHint ?? 0, &raw)
        }
        guard parsed else {
            return nil
        }

        self.ipVersion = raw.ip_version
        self.transportProtocolNumber = raw.transport_protocol
        self.flags = raw.flags
        self.sourceAddressLength = raw.source_address_length
        self.destinationAddressLength = raw.destination_address_length
        self.tcpFlags = raw.tcp_flags
        self.quicPacketTypeRaw = raw.quic_packet_type
        self.sourcePort = raw.source_port
        self.destinationPort = raw.destination_port
        self.transportPayloadOffset = raw.transport_payload_offset
        self.packetLength = Int(raw.packet_length)
        self.quicVersion = raw.quic_version == 0 ? nil : raw.quic_version
        self.flowHash = raw.flow_hash
        self.reverseFlowHash = raw.reverse_flow_hash
        self.sourceAddressHigh = raw.source_address_high
        self.sourceAddressLow = raw.source_address_low
        self.destinationAddressHigh = raw.destination_address_high
        self.destinationAddressLow = raw.destination_address_low
        self.quicDestinationConnectionID = Self.connectionID(from: raw.quic_dcid, length: Int(raw.quic_dcid_length))
        self.quicSourceConnectionID = Self.connectionID(from: raw.quic_scid, length: Int(raw.quic_scid_length))
    }

    var transport: TransportProtocol {
        TransportProtocol(rawValue: transportProtocolNumber)
    }

    /// Returns the parsed transport payload length when the summary includes a valid transport offset.
    /// The fast-path detector uses this to ignore pure TCP ACK traffic that otherwise creates a lot of heat
    /// without adding useful transition or burst signal.
    var transportPayloadLength: Int {
        let offset = Int(transportPayloadOffset)
        guard offset > 0, packetLength >= offset else {
            return 0
        }
        return packetLength - offset
    }

    var hasPorts: Bool {
        (flags & UInt8(RBPI_FLAG_HAS_PORTS)) != 0
    }

    var isDNSCandidate: Bool {
        (flags & UInt8(RBPI_FLAG_MAYBE_DNS)) != 0
    }

    var isTLSClientHelloCandidate: Bool {
        (flags & UInt8(RBPI_FLAG_MAYBE_TLS_CLIENT_HELLO)) != 0
    }

    var isQUICCandidate: Bool {
        (flags & UInt8(RBPI_FLAG_MAYBE_QUIC)) != 0
    }

    var isQUICLongHeader: Bool {
        (flags & UInt8(RBPI_FLAG_MAYBE_QUIC_LONG)) != 0
    }

    var isQUICInitialCandidate: Bool {
        (flags & UInt8(RBPI_FLAG_MAYBE_QUIC_INITIAL)) != 0
    }

    /// Returns `true` when the packet carries application payload bytes.
    var hasTransportPayload: Bool {
        transportPayloadLength > 0
    }

    /// Returns `true` when the TCP packet carries control flags that are useful for flow lifecycle detection.
    var isTCPControlSignal: Bool {
        transport == .tcp && (tcpFlags & 0x07) != 0
    }

    var flowKey: FlowKey {
        FlowKey(
            flowHash: flowHash,
            reverseFlowHash: reverseFlowHash,
            ipVersion: ipVersion,
            transportProtocolNumber: transportProtocolNumber,
            sourceAddressLength: sourceAddressLength,
            destinationAddressLength: destinationAddressLength,
            sourceAddressHigh: sourceAddressHigh,
            sourceAddressLow: sourceAddressLow,
            destinationAddressHigh: destinationAddressHigh,
            destinationAddressLow: destinationAddressLow,
            sourcePort: hasPorts ? sourcePort : 0,
            destinationPort: hasPorts ? destinationPort : 0
        )
    }

    var protocolHint: String {
        switch transport {
        case .tcp:
            return "tcp"
        case .udp:
            return "udp"
        case .icmp:
            return "icmp"
        case .icmpv6:
            return "icmpv6"
        default:
            return "ip"
        }
    }

    var quicPacketType: QuicPacketType? {
        guard let quicVersion else {
            return nil
        }
        return Self.mapQuicPacketType(version: quicVersion, rawType: quicPacketTypeRaw)
    }

    private static func mapQuicPacketType(version: UInt32, rawType: UInt8) -> QuicPacketType? {
        switch version {
        case 0x0000_0001:
            switch rawType {
            case 0: return .initial
            case 1: return .zeroRTT
            case 2: return .handshake
            case 3: return .retry
            default: return nil
            }
        case 0x6b33_43cf:
            switch rawType {
            case 0: return .retry
            case 1: return .initial
            case 2: return .zeroRTT
            case 3: return .handshake
            default: return nil
            }
        default:
            return nil
        }
    }

    private static func connectionID<T>(from tuple: T, length: Int) -> Data? {
        guard length > 0 else {
            return nil
        }

        return withUnsafeBytes(of: tuple) { rawBuffer in
            let count = min(length, rawBuffer.count)
            return Data(rawBuffer.prefix(count))
        }
    }
}
