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
    public let burstDurationMs: Int?
    public let burstPacketCount: Int?

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
        burstDurationMs: Int?,
        burstPacketCount: Int?
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
        self.burstDurationMs = burstDurationMs
        self.burstPacketCount = burstPacketCount
    }

    init(compactRecord record: PacketSampleStream.PacketStreamRecord) {
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
        self.sourceAddressStorage = record.textSourceAddress
        self.destinationAddressStorage = record.textDestinationAddress
        self.sourceAddressLength = record.sourceAddressLength
        self.sourceAddressHigh = record.sourceAddressHigh
        self.sourceAddressLow = record.sourceAddressLow
        self.destinationAddressLength = record.destinationAddressLength
        self.destinationAddressHigh = record.destinationAddressHigh
        self.destinationAddressLow = record.destinationAddressLow
        self.registrableDomain = record.registrableDomain
        self.dnsQueryName = record.dnsQueryName
        self.dnsCname = record.dnsCname
        self.dnsAnswerAddresses = record.dnsAnswerAddresses
        self.tlsServerName = record.tlsServerName
        self.quicVersion = record.quicVersion
        self.quicPacketType = record.quicPacketType
        self.quicDestinationConnectionId = record.quicDestinationConnectionId
        self.quicSourceConnectionId = record.quicSourceConnectionId
        self.classification = record.classification
        self.burstDurationMs = record.burstDurationMs
        self.burstPacketCount = record.burstPacketCount
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
    func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent]
    func reset()
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
        self.init(compactRecord: record)
    }
}

/// Lazy detector-facing view over one compact telemetry batch.
/// Decision: detector input stays lazy so the telemetry worker does not allocate a second `[DetectorRecord]` array
/// for every emitted batch when detectors are installed.
public struct DetectorRecordCollection: RandomAccessCollection, Sendable {
    public typealias Element = DetectorRecord
    public typealias Index = Int

    private let records: [PacketSampleStream.PacketStreamRecord]

    init(_ records: [PacketSampleStream.PacketStreamRecord]) {
        self.records = records
    }

    public var startIndex: Int { records.startIndex }
    public var endIndex: Int { records.endIndex }
    public var count: Int { records.count }
    public var isEmpty: Bool { records.isEmpty }

    public subscript(position: Int) -> DetectorRecord {
        DetectorRecord(compactRecord: records[position])
    }
}
