// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation

/// Closed integer range used in Codable detector-stream configuration.
public struct PacketLengthRange: Codable, Sendable, Equatable, Hashable {
    public let lowerBound: Int
    public let upperBound: Int

    public init(lowerBound: Int, upperBound: Int) {
        self.lowerBound = min(lowerBound, upperBound)
        self.upperBound = max(lowerBound, upperBound)
    }

    public init(_ range: ClosedRange<Int>) {
        self.init(lowerBound: range.lowerBound, upperBound: range.upperBound)
    }

    public func contains(_ value: Int) -> Bool {
        value >= lowerBound && value <= upperBound
    }
}

/// Generic reason a packet-level cue was emitted.
public enum PacketCueReason: String, Codable, Sendable, Equatable, Hashable {
    case tcpAckPshPayloadRange
    case udpPacketLengthRange
    case hostAssociatedPacket
    case metadataRefresh
    case explicitPolicyMatch
}

/// Generic packet-cue emission knobs. Product-specific length windows and role decisions belong in the app.
public struct PacketCueEmissionPolicy: Codable, Sendable, Equatable {
    public let tcpPayloadLengthRange: PacketLengthRange?
    public let udpPacketLengthRange: PacketLengthRange?
    public let directions: Set<PacketDirection>
    public let requireTcpAck: Bool
    public let requireTcpPsh: Bool
    public let includeHostAssociatedPackets: Bool
    public let maxHostAssociatedPacketLength: Int?
    public let emitMetadataRefreshCues: Bool

    public init(
        tcpPayloadLengthRange: PacketLengthRange? = nil,
        udpPacketLengthRange: PacketLengthRange? = nil,
        directions: Set<PacketDirection> = [],
        requireTcpAck: Bool = false,
        requireTcpPsh: Bool = false,
        includeHostAssociatedPackets: Bool = false,
        maxHostAssociatedPacketLength: Int? = nil,
        emitMetadataRefreshCues: Bool = false
    ) {
        self.tcpPayloadLengthRange = tcpPayloadLengthRange
        self.udpPacketLengthRange = udpPacketLengthRange
        self.directions = directions
        self.requireTcpAck = requireTcpAck
        self.requireTcpPsh = requireTcpPsh
        self.includeHostAssociatedPackets = includeHostAssociatedPackets
        self.maxHostAssociatedPacketLength = maxHostAssociatedPacketLength.map { max(0, $0) }
        self.emitMetadataRefreshCues = emitMetadataRefreshCues
    }

    public static let disabled = PacketCueEmissionPolicy()

    public var isEnabled: Bool {
        emitMetadataRefreshCues ||
            tcpPayloadLengthRange != nil ||
            udpPacketLengthRange != nil ||
            includeHostAssociatedPackets
    }
}

/// Opt-in, high-volume packet metadata logging policy for debug builds and external analysis tools.
/// Decision: raw packet bytes stay off by default; callers must explicitly enable a short byte-prefix capture.
public struct RichPacketLogPolicy: Codable, Sendable, Equatable {
    public static let defaultFilePrefix = "rich-packets"

    public let isEnabled: Bool
    public let directions: Set<PacketDirection>
    public let includeParsedMetadata: Bool
    public let includeDNSAnswerAddresses: Bool
    public let includeQUICConnectionIDs: Bool
    public let includePacketBytePrefix: Bool
    public let packetBytePrefixLength: Int
    public let maxPacketLength: Int?
    public let maxRecordsPerBatch: Int
    public let metadataProbeLimitPerBatch: Int
    public let filePrefix: String
    public let maxBytesPerFile: Int
    public let maxFileCount: Int
    public let maxTotalBytes: Int

    public init(
        isEnabled: Bool = false,
        directions: Set<PacketDirection> = [],
        includeParsedMetadata: Bool = true,
        includeDNSAnswerAddresses: Bool = true,
        includeQUICConnectionIDs: Bool = true,
        includePacketBytePrefix: Bool = false,
        packetBytePrefixLength: Int = 0,
        maxPacketLength: Int? = nil,
        maxRecordsPerBatch: Int = 256,
        metadataProbeLimitPerBatch: Int = 16,
        filePrefix: String = RichPacketLogPolicy.defaultFilePrefix,
        maxBytesPerFile: Int = 4_194_304,
        maxFileCount: Int = 8,
        maxTotalBytes: Int = 33_554_432
    ) {
        self.isEnabled = isEnabled
        self.directions = directions
        self.includeParsedMetadata = includeParsedMetadata
        self.includeDNSAnswerAddresses = includeDNSAnswerAddresses
        self.includeQUICConnectionIDs = includeQUICConnectionIDs
        self.includePacketBytePrefix = includePacketBytePrefix
        self.packetBytePrefixLength = includePacketBytePrefix ? min(max(0, packetBytePrefixLength), 512) : 0
        self.maxPacketLength = maxPacketLength.map { max(0, $0) }
        self.maxRecordsPerBatch = min(max(1, maxRecordsPerBatch), 4_096)
        self.metadataProbeLimitPerBatch = min(max(0, metadataProbeLimitPerBatch), 1_024)
        self.filePrefix = filePrefix
        self.maxBytesPerFile = max(16_384, maxBytesPerFile)
        self.maxFileCount = max(1, maxFileCount)
        self.maxTotalBytes = max(self.maxBytesPerFile, maxTotalBytes)
    }

    public static let disabled = RichPacketLogPolicy()

    public var shouldLogAnyDirection: Bool {
        directions.isEmpty
    }

    public func includes(direction: PacketDirection) -> Bool {
        directions.isEmpty || directions.contains(direction)
    }
}

/// One durable rich packet metadata record written to the optional JSONL debug stream.
public struct RichPacketLogRecord: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let sequenceNumber: UInt64
    public let timestamp: Date
    public let timestampMs: Double
    public let direction: PacketDirection
    public let writerProcess: String
    public let sessionId: String?
    public let packetStreamStartedAtMs: Double?
    public let foregroundReadyAtMs: Double?
    public let appOpenAtMs: Double?
    public let sessionTarget: String?
    public let packetLength: Int
    public let transportPayloadLength: Int?
    public let ipVersion: UInt8
    public let transportProtocolNumber: UInt8
    public let protocolHint: String
    public let sourceAddress: String?
    public let sourcePort: UInt16?
    public let destinationAddress: String?
    public let destinationPort: UInt16?
    public let localAddress: String?
    public let localPort: UInt16?
    public let remoteAddress: String?
    public let remotePort: UInt16?
    public let remoteEndpoint: String?
    public let flowId: String
    public let flowIdentity: FlowIdentity
    public let tcpFlags: UInt8?
    public let tcpAck: Bool?
    public let tcpPsh: Bool?
    public let tcpSyn: Bool?
    public let tcpFin: Bool?
    public let tcpRst: Bool?
    public let isDNSCandidate: Bool
    public let isTLSClientHelloCandidate: Bool
    public let isQUICCandidate: Bool
    public let isQUICLongHeader: Bool
    public let isQUICInitialCandidate: Bool
    public let metadataParsed: Bool
    public let dnsQueryName: String?
    public let dnsCname: String?
    public let dnsAnswerAddresses: [String]?
    public let registrableDomain: String?
    public let tlsServerName: String?
    public let quicVersion: UInt32?
    public let quicPacketType: String?
    public let quicDestinationConnectionId: String?
    public let quicSourceConnectionId: String?
    public let addressFamilyHint: Int?
    public let packetBytePrefixHex: String?

    public init(
        schemaVersion: Int = 1,
        sequenceNumber: UInt64,
        timestamp: Date,
        timestampMs: Double,
        direction: PacketDirection,
        writerProcess: String,
        sessionContext: DetectorSessionContext? = nil,
        packetLength: Int,
        transportPayloadLength: Int?,
        ipVersion: UInt8,
        transportProtocolNumber: UInt8,
        protocolHint: String,
        sourceAddress: String?,
        sourcePort: UInt16?,
        destinationAddress: String?,
        destinationPort: UInt16?,
        localAddress: String?,
        localPort: UInt16?,
        remoteAddress: String?,
        remotePort: UInt16?,
        remoteEndpoint: String?,
        flowId: String,
        flowIdentity: FlowIdentity,
        tcpFlags: UInt8?,
        tcpAck: Bool?,
        tcpPsh: Bool?,
        tcpSyn: Bool?,
        tcpFin: Bool?,
        tcpRst: Bool?,
        isDNSCandidate: Bool,
        isTLSClientHelloCandidate: Bool,
        isQUICCandidate: Bool,
        isQUICLongHeader: Bool,
        isQUICInitialCandidate: Bool,
        metadataParsed: Bool,
        dnsQueryName: String? = nil,
        dnsCname: String? = nil,
        dnsAnswerAddresses: [String]? = nil,
        registrableDomain: String? = nil,
        tlsServerName: String? = nil,
        quicVersion: UInt32? = nil,
        quicPacketType: String? = nil,
        quicDestinationConnectionId: String? = nil,
        quicSourceConnectionId: String? = nil,
        addressFamilyHint: Int? = nil,
        packetBytePrefixHex: String? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.sequenceNumber = sequenceNumber
        self.timestamp = timestamp
        self.timestampMs = timestampMs
        self.direction = direction
        self.writerProcess = writerProcess
        self.sessionId = sessionContext?.sessionId
        self.packetStreamStartedAtMs = sessionContext?.packetStreamStartedAtMs
        self.foregroundReadyAtMs = sessionContext?.foregroundReadyAtMs
        self.appOpenAtMs = sessionContext?.appOpenAtMs
        self.sessionTarget = sessionContext?.sessionTarget
        self.packetLength = packetLength
        self.transportPayloadLength = transportPayloadLength
        self.ipVersion = ipVersion
        self.transportProtocolNumber = transportProtocolNumber
        self.protocolHint = protocolHint
        self.sourceAddress = sourceAddress
        self.sourcePort = sourcePort
        self.destinationAddress = destinationAddress
        self.destinationPort = destinationPort
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.remoteEndpoint = remoteEndpoint
        self.flowId = flowId
        self.flowIdentity = flowIdentity
        self.tcpFlags = tcpFlags
        self.tcpAck = tcpAck
        self.tcpPsh = tcpPsh
        self.tcpSyn = tcpSyn
        self.tcpFin = tcpFin
        self.tcpRst = tcpRst
        self.isDNSCandidate = isDNSCandidate
        self.isTLSClientHelloCandidate = isTLSClientHelloCandidate
        self.isQUICCandidate = isQUICCandidate
        self.isQUICLongHeader = isQUICLongHeader
        self.isQUICInitialCandidate = isQUICInitialCandidate
        self.metadataParsed = metadataParsed
        self.dnsQueryName = dnsQueryName
        self.dnsCname = dnsCname
        self.dnsAnswerAddresses = dnsAnswerAddresses
        self.registrableDomain = registrableDomain
        self.tlsServerName = tlsServerName
        self.quicVersion = quicVersion
        self.quicPacketType = quicPacketType
        self.quicDestinationConnectionId = quicDestinationConnectionId
        self.quicSourceConnectionId = quicSourceConnectionId
        self.addressFamilyHint = addressFamilyHint
        self.packetBytePrefixHex = packetBytePrefixHex
    }
}

/// Canonical flow tuple shared by packet tunnel records and optional attribution sidecars.
public struct FlowIdentity: Codable, Sendable, Equatable, Hashable {
    public let protocolName: String
    public let localAddress: String?
    public let localPort: UInt16?
    public let remoteAddress: String?
    public let remotePort: UInt16?
    public let direction: String
    public let flowId: String
    public let lineageId: UInt64?
    public let generation: Int?

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case localAddress
        case localPort
        case remoteAddress
        case remotePort
        case direction
        case flowId
        case lineageId
        case generation
    }

    public init(
        protocolName: String,
        localAddress: String?,
        localPort: UInt16?,
        remoteAddress: String?,
        remotePort: UInt16?,
        direction: String,
        flowId: String,
        lineageId: UInt64? = nil,
        generation: Int? = nil
    ) {
        self.protocolName = protocolName
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.direction = direction
        self.flowId = flowId
        self.lineageId = lineageId
        self.generation = generation
    }

    public var remoteEndpoint: String? {
        guard let remoteAddress, !remoteAddress.isEmpty, let remotePort else {
            return nil
        }
        let host = remoteAddress.contains(":") ? "[\(remoteAddress)]" : remoteAddress
        return "\(protocolName.lowercased())://\(host):\(remotePort)"
    }
}

/// Package-visible stream health record. Missing feature families are explicit instead of silently disappearing.
public struct TelemetryHealthRecord: Codable, Sendable, Equatable {
    public let availableFeatureFamilies: [String]
    public let missingFeatureFamilies: [String]
    public let degradedReason: String?
    public let droppedRecordCount: Int
    public let lastPacketTimestampMs: Double?

    public init(
        availableFeatureFamilies: [String],
        missingFeatureFamilies: [String],
        degradedReason: String? = nil,
        droppedRecordCount: Int = 0,
        lastPacketTimestampMs: Double? = nil
    ) {
        self.availableFeatureFamilies = availableFeatureFamilies
        self.missingFeatureFamilies = missingFeatureFamilies
        self.degradedReason = degradedReason
        self.droppedRecordCount = max(0, droppedRecordCount)
        self.lastPacketTimestampMs = lastPacketTimestampMs
    }
}

/// Controls whether environment pressure reduces detector-stream detail.
public struct TelemetryDegradationPolicy: Codable, Sendable, Equatable {
    public let reduceOnLowPowerMode: Bool
    public let reduceOnThermalPressure: Bool

    public init(
        reduceOnLowPowerMode: Bool = true,
        reduceOnThermalPressure: Bool = true
    ) {
        self.reduceOnLowPowerMode = reduceOnLowPowerMode
        self.reduceOnThermalPressure = reduceOnThermalPressure
    }

    public static let `default` = TelemetryDegradationPolicy()
    public static let disabled = TelemetryDegradationPolicy(
        reduceOnLowPowerMode: false,
        reduceOnThermalPressure: false
    )
    public static let lowPowerOnly = TelemetryDegradationPolicy(
        reduceOnLowPowerMode: true,
        reduceOnThermalPressure: false
    )
    public static let thermalOnly = TelemetryDegradationPolicy(
        reduceOnLowPowerMode: false,
        reduceOnThermalPressure: true
    )
}

/// Liveness metadata returned with app-visible snapshots.
public struct TelemetryStreamLiveness: Codable, Sendable, Equatable {
    public let streamStartedAtMs: Double?
    public let lastRecordAtMs: Double?
    public let sequenceNumber: UInt64
    public let droppedSequenceCount: Int
    public let sessionId: String?
    public let writerProcess: String

    public init(
        streamStartedAtMs: Double?,
        lastRecordAtMs: Double?,
        sequenceNumber: UInt64,
        droppedSequenceCount: Int,
        sessionId: String?,
        writerProcess: String
    ) {
        self.streamStartedAtMs = streamStartedAtMs
        self.lastRecordAtMs = lastRecordAtMs
        self.sequenceNumber = sequenceNumber
        self.droppedSequenceCount = max(0, droppedSequenceCount)
        self.sessionId = sessionId
        self.writerProcess = writerProcess
    }
}
