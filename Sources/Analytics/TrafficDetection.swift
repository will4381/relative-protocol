import Foundation

/// Stable input record exposed to custom detector implementations.
/// Decision: detectors consume a narrow, package-owned view of telemetry data so package clients can add detectors
/// without depending on internal rolling-tap storage types.
public struct DetectorRecord: Sendable, Equatable {
    public let kind: PacketSampleKind
    public let timestamp: Date
    public let direction: String
    public let bytes: Int
    public let packetCount: Int?
    public let flowPacketCount: Int?
    public let flowByteCount: Int?
    public let protocolHint: String
    public let ipVersion: UInt8?
    public let transportProtocolNumber: UInt8?
    public let sourcePort: UInt16?
    public let destinationPort: UInt16?
    public let flowHash: UInt64?
    public let textFlowId: String?
    private let sourceAddressStorage: String?
    private let destinationAddressStorage: String?
    private let sourceAddressLength: UInt8?
    private let sourceAddressHigh: UInt64?
    private let sourceAddressLow: UInt64?
    private let destinationAddressLength: UInt8?
    private let destinationAddressHigh: UInt64?
    private let destinationAddressLow: UInt64?
    public let registrableDomain: String?
    public let dnsQueryName: String?
    public let dnsCname: String?
    public let dnsAnswerAddresses: [String]?
    public let tlsServerName: String?
    public let quicVersion: UInt32?
    public let quicPacketType: String?
    public let quicDestinationConnectionId: String?
    public let quicSourceConnectionId: String?
    public let classification: String?
    public let closeReason: FlowCloseReason?
    public let largePacketCount: Int?
    public let smallPacketCount: Int?
    public let udpPacketCount: Int?
    public let tcpPacketCount: Int?
    public let quicInitialCount: Int?
    public let tcpSynCount: Int?
    public let tcpFinCount: Int?
    public let tcpRstCount: Int?
    public let burstDurationMs: Int?
    public let burstPacketCount: Int?
    public let leadingBytes200ms: Int?
    public let leadingPackets200ms: Int?
    public let leadingBytes600ms: Int?
    public let leadingPackets600ms: Int?
    public let burstLargePacketCount: Int?
    public let burstUdpPacketCount: Int?
    public let burstTcpPacketCount: Int?
    public let burstQuicInitialCount: Int?
    public let associatedDomain: String?
    public let associationSource: DetectorAssociationSource?
    public let associationAgeMs: Int?
    public let associationConfidence: Double?
    public let lineageID: UInt64?
    public let lineageGeneration: Int?
    public let lineageAgeMs: Int?
    public let lineageReuseGapMs: Int?
    public let lineageReopenCount: Int?
    public let lineageSiblingCount: Int?
    public let pathEpoch: UInt32?
    public let pathInterfaceClass: PathInterfaceClass?
    public let pathIsExpensive: Bool?
    public let pathIsConstrained: Bool?
    public let pathSupportsDNS: Bool?
    public let pathChangedRecently: Bool?
    public let serviceFamily: String?
    public let serviceFamilyConfidence: Double?
    public let serviceAttributionSourceMask: UInt16?

    public var sourceAddress: String? {
        if let sourceAddressStorage {
            return sourceAddressStorage
        }
        return PacketSampleStream.decodedAddress(
            length: sourceAddressLength,
            high: sourceAddressHigh,
            low: sourceAddressLow,
            fallback: nil
        )
    }

    public var destinationAddress: String? {
        if let destinationAddressStorage {
            return destinationAddressStorage
        }
        return PacketSampleStream.decodedAddress(
            length: destinationAddressLength,
            high: destinationAddressHigh,
            low: destinationAddressLow,
            fallback: nil
        )
    }

    public init(
        kind: PacketSampleKind,
        timestamp: Date,
        direction: String,
        bytes: Int,
        packetCount: Int?,
        flowPacketCount: Int?,
        flowByteCount: Int?,
        protocolHint: String,
        ipVersion: UInt8?,
        transportProtocolNumber: UInt8?,
        sourcePort: UInt16?,
        destinationPort: UInt16?,
        flowHash: UInt64?,
        textFlowId: String?,
        sourceAddress: String?,
        destinationAddress: String?,
        registrableDomain: String?,
        dnsQueryName: String?,
        dnsCname: String?,
        dnsAnswerAddresses: [String]?,
        tlsServerName: String?,
        quicVersion: UInt32?,
        quicPacketType: String?,
        quicDestinationConnectionId: String?,
        quicSourceConnectionId: String?,
        classification: String?,
        closeReason: FlowCloseReason?,
        largePacketCount: Int?,
        smallPacketCount: Int?,
        udpPacketCount: Int?,
        tcpPacketCount: Int?,
        quicInitialCount: Int?,
        tcpSynCount: Int?,
        tcpFinCount: Int?,
        tcpRstCount: Int?,
        burstDurationMs: Int?,
        burstPacketCount: Int?,
        leadingBytes200ms: Int?,
        leadingPackets200ms: Int?,
        leadingBytes600ms: Int?,
        leadingPackets600ms: Int?,
        burstLargePacketCount: Int?,
        burstUdpPacketCount: Int?,
        burstTcpPacketCount: Int?,
        burstQuicInitialCount: Int?,
        associatedDomain: String? = nil,
        associationSource: DetectorAssociationSource? = nil,
        associationAgeMs: Int? = nil,
        associationConfidence: Double? = nil,
        lineageID: UInt64? = nil,
        lineageGeneration: Int? = nil,
        lineageAgeMs: Int? = nil,
        lineageReuseGapMs: Int? = nil,
        lineageReopenCount: Int? = nil,
        lineageSiblingCount: Int? = nil,
        pathEpoch: UInt32? = nil,
        pathInterfaceClass: PathInterfaceClass? = nil,
        pathIsExpensive: Bool? = nil,
        pathIsConstrained: Bool? = nil,
        pathSupportsDNS: Bool? = nil,
        pathChangedRecently: Bool? = nil,
        serviceFamily: String? = nil,
        serviceFamilyConfidence: Double? = nil,
        serviceAttributionSourceMask: UInt16? = nil
    ) {
        self.kind = kind
        self.timestamp = timestamp
        self.direction = direction
        self.bytes = bytes
        self.packetCount = packetCount
        self.flowPacketCount = flowPacketCount
        self.flowByteCount = flowByteCount
        self.protocolHint = protocolHint
        self.ipVersion = ipVersion
        self.transportProtocolNumber = transportProtocolNumber
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.flowHash = flowHash
        self.textFlowId = textFlowId
        self.sourceAddressStorage = sourceAddress
        self.destinationAddressStorage = destinationAddress
        self.sourceAddressLength = nil
        self.sourceAddressHigh = nil
        self.sourceAddressLow = nil
        self.destinationAddressLength = nil
        self.destinationAddressHigh = nil
        self.destinationAddressLow = nil
        self.registrableDomain = registrableDomain
        self.dnsQueryName = dnsQueryName
        self.dnsCname = dnsCname
        self.dnsAnswerAddresses = dnsAnswerAddresses
        self.tlsServerName = tlsServerName
        self.quicVersion = quicVersion
        self.quicPacketType = quicPacketType
        self.quicDestinationConnectionId = quicDestinationConnectionId
        self.quicSourceConnectionId = quicSourceConnectionId
        self.classification = classification
        self.closeReason = closeReason
        self.largePacketCount = largePacketCount
        self.smallPacketCount = smallPacketCount
        self.udpPacketCount = udpPacketCount
        self.tcpPacketCount = tcpPacketCount
        self.quicInitialCount = quicInitialCount
        self.tcpSynCount = tcpSynCount
        self.tcpFinCount = tcpFinCount
        self.tcpRstCount = tcpRstCount
        self.burstDurationMs = burstDurationMs
        self.burstPacketCount = burstPacketCount
        self.leadingBytes200ms = leadingBytes200ms
        self.leadingPackets200ms = leadingPackets200ms
        self.leadingBytes600ms = leadingBytes600ms
        self.leadingPackets600ms = leadingPackets600ms
        self.burstLargePacketCount = burstLargePacketCount
        self.burstUdpPacketCount = burstUdpPacketCount
        self.burstTcpPacketCount = burstTcpPacketCount
        self.burstQuicInitialCount = burstQuicInitialCount
        self.associatedDomain = associatedDomain
        self.associationSource = associationSource
        self.associationAgeMs = associationAgeMs
        self.associationConfidence = associationConfidence
        self.lineageID = lineageID
        self.lineageGeneration = lineageGeneration
        self.lineageAgeMs = lineageAgeMs
        self.lineageReuseGapMs = lineageReuseGapMs
        self.lineageReopenCount = lineageReopenCount
        self.lineageSiblingCount = lineageSiblingCount
        self.pathEpoch = pathEpoch
        self.pathInterfaceClass = pathInterfaceClass
        self.pathIsExpensive = pathIsExpensive
        self.pathIsConstrained = pathIsConstrained
        self.pathSupportsDNS = pathSupportsDNS
        self.pathChangedRecently = pathChangedRecently
        self.serviceFamily = serviceFamily
        self.serviceFamilyConfidence = serviceFamilyConfidence
        self.serviceAttributionSourceMask = serviceAttributionSourceMask
    }

    init(compactRecord record: PacketSampleStream.PacketStreamRecord, projection: DetectorRecordProjection) {
        let includePacketShape = projection.includes(.packetShape)
        let includeControlSignals = projection.includes(.controlSignals)
        let includeBurstShape = projection.includes(.burstShape)
        let includeHostHints = projection.includes(.hostHints)
        let includeQUICIdentity = projection.includes(.quicIdentity)
        let includeStringAddresses = projection.includes(.stringAddresses)
        let includeDNSAnswerAddresses = projection.includes(.dnsAnswerAddresses)
        let includeDNSAssociation = projection.includes(.dnsAssociation)
        let includeLineage = projection.includes(.lineage)
        let includePathRegime = projection.includes(.pathRegime)
        let includeServiceAttribution = projection.includes(.serviceAttribution)

        self.kind = record.kind
        self.timestamp = record.timestamp
        self.direction = record.direction
        self.bytes = record.bytes
        self.packetCount = record.packetCount
        self.flowPacketCount = record.flowPacketCount
        self.flowByteCount = record.flowByteCount
        self.protocolHint = record.protocolHint
        self.ipVersion = record.ipVersion
        self.transportProtocolNumber = record.transportProtocolNumber
        self.sourcePort = record.sourcePort
        self.destinationPort = record.destinationPort
        self.flowHash = record.flowHash
        self.textFlowId = record.textFlowId
        self.sourceAddressStorage = includeStringAddresses ? record.textSourceAddress : nil
        self.destinationAddressStorage = includeStringAddresses ? record.textDestinationAddress : nil
        self.sourceAddressLength = includeStringAddresses ? record.sourceAddressLength : nil
        self.sourceAddressHigh = includeStringAddresses ? record.sourceAddressHigh : nil
        self.sourceAddressLow = includeStringAddresses ? record.sourceAddressLow : nil
        self.destinationAddressLength = includeStringAddresses ? record.destinationAddressLength : nil
        self.destinationAddressHigh = includeStringAddresses ? record.destinationAddressHigh : nil
        self.destinationAddressLow = includeStringAddresses ? record.destinationAddressLow : nil
        self.registrableDomain = includeHostHints ? record.registrableDomain : nil
        self.dnsQueryName = includeHostHints ? record.dnsQueryName : nil
        self.dnsCname = includeHostHints ? record.dnsCname : nil
        self.dnsAnswerAddresses = includeDNSAnswerAddresses ? record.dnsAnswerAddresses : nil
        self.tlsServerName = includeHostHints ? record.tlsServerName : nil
        self.quicVersion = includeQUICIdentity ? record.quicVersion : nil
        self.quicPacketType = includeQUICIdentity ? record.quicPacketType : nil
        self.quicDestinationConnectionId = includeQUICIdentity ? record.quicDestinationConnectionId : nil
        self.quicSourceConnectionId = includeQUICIdentity ? record.quicSourceConnectionId : nil
        self.classification = includeHostHints ? record.classification : nil
        self.closeReason = record.closeReason
        self.largePacketCount = includePacketShape || includeBurstShape ? record.largePacketCount : nil
        self.smallPacketCount = includePacketShape || includeBurstShape ? record.smallPacketCount : nil
        self.udpPacketCount = includePacketShape || includeBurstShape ? record.udpPacketCount : nil
        self.tcpPacketCount = includePacketShape || includeBurstShape ? record.tcpPacketCount : nil
        self.quicInitialCount = includeControlSignals ? record.quicInitialCount : nil
        self.tcpSynCount = includeControlSignals ? record.tcpSynCount : nil
        self.tcpFinCount = includeControlSignals ? record.tcpFinCount : nil
        self.tcpRstCount = includeControlSignals ? record.tcpRstCount : nil
        self.burstDurationMs = record.burstDurationMs
        self.burstPacketCount = record.burstPacketCount
        self.leadingBytes200ms = includeBurstShape ? record.leadingBytes200ms : nil
        self.leadingPackets200ms = includeBurstShape ? record.leadingPackets200ms : nil
        self.leadingBytes600ms = includeBurstShape ? record.leadingBytes600ms : nil
        self.leadingPackets600ms = includeBurstShape ? record.leadingPackets600ms : nil
        self.burstLargePacketCount = includeBurstShape ? record.burstLargePacketCount : nil
        self.burstUdpPacketCount = includeBurstShape ? record.burstUdpPacketCount : nil
        self.burstTcpPacketCount = includeBurstShape ? record.burstTcpPacketCount : nil
        self.burstQuicInitialCount = includeBurstShape ? record.burstQuicInitialCount : nil
        self.associatedDomain = includeDNSAssociation ? record.associatedDomain : nil
        self.associationSource = includeDNSAssociation ? record.associationSource : nil
        self.associationAgeMs = includeDNSAssociation ? record.associationAgeMs : nil
        self.associationConfidence = includeDNSAssociation ? record.associationConfidence : nil
        self.lineageID = includeLineage ? record.lineageID : nil
        self.lineageGeneration = includeLineage ? record.lineageGeneration : nil
        self.lineageAgeMs = includeLineage ? record.lineageAgeMs : nil
        self.lineageReuseGapMs = includeLineage ? record.lineageReuseGapMs : nil
        self.lineageReopenCount = includeLineage ? record.lineageReopenCount : nil
        self.lineageSiblingCount = includeLineage ? record.lineageSiblingCount : nil
        self.pathEpoch = includePathRegime ? record.pathEpoch : nil
        self.pathInterfaceClass = includePathRegime ? record.pathInterfaceClass : nil
        self.pathIsExpensive = includePathRegime ? record.pathIsExpensive : nil
        self.pathIsConstrained = includePathRegime ? record.pathIsConstrained : nil
        self.pathSupportsDNS = includePathRegime ? record.pathSupportsDNS : nil
        self.pathChangedRecently = includePathRegime ? record.pathChangedRecently : nil
        self.serviceFamily = includeServiceAttribution ? record.serviceFamily : nil
        self.serviceFamilyConfidence = includeServiceAttribution ? record.serviceFamilyConfidence : nil
        self.serviceAttributionSourceMask = includeServiceAttribution ? record.serviceAttributionSourceMask : nil
    }
}

/// One durable detector output emitted by the tunnel extension.
/// Decision: the tunnel persists small detector outputs instead of raw packet history so detector state survives while
/// the containing app is suspended or terminated.
public struct DetectionEvent: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let detectorIdentifier: String
    /// Stable detector-defined signal name.
    /// Contract: treat this as an opaque identifier scoped by `detectorIdentifier`, not as a package-wide enum.
    public let signal: String
    /// Optional stable detector-defined bucket or subject.
    /// Contract: detectors own this namespace; downstream consumers should scope parsing by `detectorIdentifier`.
    public let target: String?
    public let timestamp: Date
    public let confidence: Double
    /// Stable detector-defined trigger label describing which sparse tunnel event caused the detection.
    /// Contract: treat this as an opaque identifier scoped by `detectorIdentifier`.
    public let trigger: String
    public let flowId: String
    public let host: String?
    public let classification: String?
    public let bytes: Int
    public let packetCount: Int?
    public let durationMs: Int?
    public let metadata: [String: String]

    public init(
        id: String,
        detectorIdentifier: String,
        signal: String,
        target: String?,
        timestamp: Date,
        confidence: Double,
        trigger: String,
        flowId: String,
        host: String?,
        classification: String?,
        bytes: Int,
        packetCount: Int?,
        durationMs: Int?,
        metadata: [String: String] = [:]
    ) {
        self.id = id
        self.detectorIdentifier = detectorIdentifier
        self.signal = signal
        self.target = target
        self.timestamp = timestamp
        self.confidence = confidence
        self.trigger = trigger
        self.flowId = flowId
        self.host = host
        self.classification = classification
        self.bytes = bytes
        self.packetCount = packetCount
        self.durationMs = durationMs
        self.metadata = metadata
    }

    /// Returns a privacy-preserving representation safe to persist in shared storage.
    /// Decision: the tunnel keeps rich detector context in memory for foreground reads, but only writes a minimized
    /// event summary to the App Group container.
    public func redactedForPersistence() -> DetectionEvent {
        DetectionEvent(
            id: id,
            detectorIdentifier: detectorIdentifier,
            signal: signal,
            target: target,
            timestamp: timestamp,
            confidence: confidence,
            trigger: trigger,
            flowId: "",
            host: nil,
            classification: nil,
            bytes: bytes,
            packetCount: packetCount,
            durationMs: durationMs,
            metadata: [:]
        )
    }
}

/// Compact persisted detector state shared between the extension and the containing app.
public struct DetectionSnapshot: Codable, Sendable, Equatable {
    public let updatedAt: Date?
    public let totalDetectionCount: Int
    public let countsByDetector: [String: Int]
    public let countsByTarget: [String: Int]
    public let recentEvents: [DetectionEvent]

    public init(
        updatedAt: Date?,
        totalDetectionCount: Int,
        countsByDetector: [String: Int],
        countsByTarget: [String: Int],
        recentEvents: [DetectionEvent]
    ) {
        self.updatedAt = updatedAt
        self.totalDetectionCount = totalDetectionCount
        self.countsByDetector = countsByDetector
        self.countsByTarget = countsByTarget
        self.recentEvents = recentEvents
    }

    public func count(forDetector identifier: String) -> Int {
        countsByDetector[identifier] ?? 0
    }

    public func count(forTarget target: String) -> Int {
        countsByTarget[target] ?? 0
    }

    public static let empty = DetectionSnapshot(
        updatedAt: nil,
        totalDetectionCount: 0,
        countsByDetector: [:],
        countsByTarget: [:],
        recentEvents: []
    )

    /// Returns the privacy-preserving representation written to shared storage.
    public func redactedForPersistence() -> DetectionSnapshot {
        DetectionSnapshot(
            updatedAt: updatedAt,
            totalDetectionCount: totalDetectionCount,
            countsByDetector: countsByDetector,
            countsByTarget: countsByTarget,
            recentEvents: recentEvents.map { $0.redactedForPersistence() }
        )
    }
}

/// Protocol implemented by package clients.
/// Ownership: detectors are worker-owned and invoked inline on one long-lived telemetry task, so implementations can
/// keep mutable state without adding their own synchronization.
/// Contract: `ingest(_:)` runs on the tunnel's hot telemetry path. Detector implementations must avoid blocking I/O,
/// sleeps, long CPU work, cross-process calls, or unbounded allocations.
public protocol TrafficDetector: AnyObject {
    var identifier: String { get }
    var requirements: DetectorRequirements { get }
    func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent]
    func reset()
}

public extension TrafficDetector {
    var requirements: DetectorRequirements {
        .legacyDefault
    }
}

/// Stable semantics for detector-owned string fields.
/// Contract: `signal`, `target`, and `trigger` are not package-wide enums. Downstream consumers must scope any
/// interpretation by `detectorIdentifier` and treat unknown values as forward-compatible.
public enum DetectionFieldSemantics {
    /// Stable detector-defined event identifier such as `ad-burst` or `custom-signal`.
    public static let signal = "signal"
    /// Stable detector-defined subject bucket such as a product surface, cohort, or domain family.
    public static let target = "target"
    /// Stable detector-defined cause label describing which sparse telemetry record triggered the event.
    public static let trigger = "trigger"
}

extension DetectorRecord {
    init(_ record: PacketSampleStream.PacketStreamRecord) {
        self.init(compactRecord: record, projection: .legacyDefault)
    }
}

/// Lazy detector-facing view over one compact telemetry batch.
/// Decision: detector input stays lazy so the telemetry worker does not allocate a second `[DetectorRecord]` array
/// for every emitted batch when detectors are installed.
public struct DetectorRecordCollection: RandomAccessCollection, Sendable {
    public typealias Element = DetectorRecord
    public typealias Index = Int

    private let records: [PacketSampleStream.PacketStreamRecord]
    private let projection: DetectorRecordProjection
    private let includedIndices: [Int]?

    init(_ records: [PacketSampleStream.PacketStreamRecord], projection: DetectorRecordProjection = .legacyDefault) {
        self.records = records
        self.projection = projection
        if projection.recordKinds == Set(PacketSampleKind.allCases) {
            self.includedIndices = nil
        } else {
            var includedIndices: [Int] = []
            includedIndices.reserveCapacity(records.count)
            for (index, record) in records.enumerated() where projection.includes(record.kind) {
                includedIndices.append(index)
            }
            self.includedIndices = includedIndices
        }
    }

    public var startIndex: Int { 0 }
    public var endIndex: Int { includedIndices?.count ?? records.count }
    public var count: Int { endIndex }
    public var isEmpty: Bool { count == 0 }

    public subscript(position: Int) -> DetectorRecord {
        let recordIndex = includedIndices?[position] ?? position
        return DetectorRecord(compactRecord: records[recordIndex], projection: projection)
    }
}
