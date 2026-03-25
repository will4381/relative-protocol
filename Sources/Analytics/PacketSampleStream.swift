import Darwin
import Foundation
import Observability
import TunnelRuntime

/// Event kind used by the app-facing rolling packet tap.
/// Decision: the tunnel writes fewer, more meaningful events (`flowOpen`, `flowSlice`, `flowClose`, `metadata`,
/// `burst`, `activitySample`)
/// instead of one rich sample for every admitted packet.
public enum PacketSampleKind: String, Codable, Sendable, Equatable, CaseIterable {
    case flowOpen
    case flowSlice
    case flowClose
    case metadata
    case burst
    case activitySample
}

/// Lifecycle reason attached to `flowClose` records.
public enum FlowCloseReason: String, Codable, Sendable, Equatable {
    case tcpFin
    case tcpRst
    case idleEviction
    case overflowEviction
}

/// One app-facing packet intelligence event.
public struct PacketSample: Codable, Sendable, Equatable {
    public let kind: PacketSampleKind
    public let timestamp: Date
    public let direction: String
    public let flowId: String
    public let bytes: Int
    public let packetCount: Int?
    public let flowPacketCount: Int?
    public let flowByteCount: Int?
    public let protocolHint: String
    public let ipVersion: UInt8?
    public let transportProtocolNumber: UInt8?
    public let sourceAddress: String?
    public let sourcePort: UInt16?
    public let destinationAddress: String?
    public let destinationPort: UInt16?
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

    public init(
        kind: PacketSampleKind = .activitySample,
        timestamp: Date,
        direction: String,
        flowId: String,
        bytes: Int,
        packetCount: Int? = nil,
        flowPacketCount: Int? = nil,
        flowByteCount: Int? = nil,
        protocolHint: String,
        ipVersion: UInt8? = nil,
        transportProtocolNumber: UInt8? = nil,
        sourceAddress: String? = nil,
        sourcePort: UInt16? = nil,
        destinationAddress: String? = nil,
        destinationPort: UInt16? = nil,
        registrableDomain: String? = nil,
        dnsQueryName: String? = nil,
        dnsCname: String? = nil,
        dnsAnswerAddresses: [String]? = nil,
        tlsServerName: String? = nil,
        quicVersion: UInt32? = nil,
        quicPacketType: String? = nil,
        quicDestinationConnectionId: String? = nil,
        quicSourceConnectionId: String? = nil,
        classification: String? = nil,
        closeReason: FlowCloseReason? = nil,
        largePacketCount: Int? = nil,
        smallPacketCount: Int? = nil,
        udpPacketCount: Int? = nil,
        tcpPacketCount: Int? = nil,
        quicInitialCount: Int? = nil,
        tcpSynCount: Int? = nil,
        tcpFinCount: Int? = nil,
        tcpRstCount: Int? = nil,
        burstDurationMs: Int? = nil,
        burstPacketCount: Int? = nil,
        leadingBytes200ms: Int? = nil,
        leadingPackets200ms: Int? = nil,
        leadingBytes600ms: Int? = nil,
        leadingPackets600ms: Int? = nil,
        burstLargePacketCount: Int? = nil,
        burstUdpPacketCount: Int? = nil,
        burstTcpPacketCount: Int? = nil,
        burstQuicInitialCount: Int? = nil,
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
        self.flowId = flowId
        self.bytes = bytes
        self.packetCount = packetCount
        self.flowPacketCount = flowPacketCount
        self.flowByteCount = flowByteCount
        self.protocolHint = protocolHint
        self.ipVersion = ipVersion
        self.transportProtocolNumber = transportProtocolNumber
        self.sourceAddress = sourceAddress
        self.sourcePort = sourcePort
        self.destinationAddress = destinationAddress
        self.destinationPort = destinationPort
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
}

/// Bounded in-memory rolling packet tap retained inside the tunnel provider.
/// Decision: keep the last few seconds of detector events in memory and expose snapshots on demand through
/// `NETunnelProviderSession.sendProviderMessage`, instead of rewriting any persisted packet artifact in the tunnel
/// hot path.
public actor PacketSampleStream {
    public struct Snapshot: Sendable, Equatable {
        public let samples: [PacketSample]
        public let retainedSampleCount: Int
        public let retainedBytes: Int
        public let oldestSampleAt: Date?
        public let latestSampleAt: Date?

        public init(
            samples: [PacketSample],
            retainedSampleCount: Int,
            retainedBytes: Int,
            oldestSampleAt: Date?,
            latestSampleAt: Date?
        ) {
            self.samples = samples
            self.retainedSampleCount = retainedSampleCount
            self.retainedBytes = retainedBytes
            self.oldestSampleAt = oldestSampleAt
            self.latestSampleAt = latestSampleAt
        }
    }

    struct PacketStreamRecord: Sendable {
        let kind: PacketSampleKind
        let timestamp: Date
        let direction: String
        let bytes: Int
        let packetCount: Int?
        let flowPacketCount: Int?
        let flowByteCount: Int?
        let protocolHint: String
        let ipVersion: UInt8?
        let transportProtocolNumber: UInt8?
        let sourcePort: UInt16?
        let destinationPort: UInt16?
        let flowHash: UInt64?
        let textFlowId: String?
        let sourceAddressLength: UInt8?
        let sourceAddressHigh: UInt64?
        let sourceAddressLow: UInt64?
        let destinationAddressLength: UInt8?
        let destinationAddressHigh: UInt64?
        let destinationAddressLow: UInt64?
        let textSourceAddress: String?
        let textDestinationAddress: String?
        let registrableDomain: String?
        let dnsQueryName: String?
        let dnsCname: String?
        let dnsAnswerAddresses: [String]?
        let tlsServerName: String?
        let quicVersion: UInt32?
        let quicPacketType: String?
        let quicDestinationConnectionId: String?
        let quicSourceConnectionId: String?
        let classification: String?
        let closeReason: FlowCloseReason?
        let largePacketCount: Int?
        let smallPacketCount: Int?
        let udpPacketCount: Int?
        let tcpPacketCount: Int?
        let quicInitialCount: Int?
        let tcpSynCount: Int?
        let tcpFinCount: Int?
        let tcpRstCount: Int?
        let burstDurationMs: Int?
        let burstPacketCount: Int?
        let leadingBytes200ms: Int?
        let leadingPackets200ms: Int?
        let leadingBytes600ms: Int?
        let leadingPackets600ms: Int?
        let burstLargePacketCount: Int?
        let burstUdpPacketCount: Int?
        let burstTcpPacketCount: Int?
        let burstQuicInitialCount: Int?
        let associatedDomain: String?
        let associationSource: DetectorAssociationSource?
        let associationAgeMs: Int?
        let associationConfidence: Double?
        let lineageID: UInt64?
        let lineageGeneration: Int?
        let lineageAgeMs: Int?
        let lineageReuseGapMs: Int?
        let lineageReopenCount: Int?
        let lineageSiblingCount: Int?
        let pathEpoch: UInt32?
        let pathInterfaceClass: PathInterfaceClass?
        let pathIsExpensive: Bool?
        let pathIsConstrained: Bool?
        let pathSupportsDNS: Bool?
        let pathChangedRecently: Bool?
        let serviceFamily: String?
        let serviceFamilyConfidence: Double?
        let serviceAttributionSourceMask: UInt16?
    }

    private enum StoredPayload: Sendable {
        case sample(PacketSample)
        case record(PacketStreamRecord)
    }

    private struct StoredRecord: Sendable {
        let payload: StoredPayload
        let timestamp: Date
        let retainedAt: Date
        let estimatedBytes: Int

        var sample: PacketSample {
            switch payload {
            case .sample(let sample):
                return sample
            case .record(let record):
                return PacketSampleStream.makeSample(from: record)
            }
        }
    }

    private let maxBytes: Int
    private let retentionWindowSeconds: TimeInterval
    private let clock: any Clock
    private let logger: StructuredLogger

    private var records: [StoredRecord] = []
    private var startIndex = 0
    private var retainedBytes = 0

    /// Creates a bounded rolling packet tap.
    /// - Parameters:
    ///   - maxBytes: Approximate memory budget for retained samples.
    ///   - retentionWindowSeconds: Maximum age of retained samples.
    ///   - clock: Time source shared with the telemetry pipeline.
    ///   - logger: Logger used when a single record exceeds the memory budget.
    public init(
        maxBytes: Int,
        retentionWindowSeconds: TimeInterval = 10,
        clock: any Clock = SystemClock(),
        logger: StructuredLogger
    ) {
        self.maxBytes = max(1, maxBytes)
        self.retentionWindowSeconds = max(1, retentionWindowSeconds)
        self.clock = clock
        self.logger = logger
    }

    /// Appends one sample into the rolling tap.
    public func append(_ sample: PacketSample) async throws {
        try await append(contentsOf: [sample])
    }

    /// Appends a batch of already-decoded samples into the rolling tap.
    public func append(contentsOf samples: [PacketSample]) async throws {
        guard !samples.isEmpty else {
            return
        }

        let now = await clock.now()
        evictExpired(now: now)
        for sample in samples {
            try await store(sample, retainedAt: now)
        }
        compactStorageIfNeeded()
    }

    /// Appends compact detector records into the rolling tap.
    /// Decision: the worker still emits compact records to avoid rebuilding expensive flow metadata on every branch,
    /// and the app-facing snapshot reconstructs `PacketSample` values lazily only when a foreground reader asks.
    func append(records: [PacketStreamRecord]) async throws {
        guard !records.isEmpty else {
            return
        }

        let now = await clock.now()
        evictExpired(now: now)
        for record in records {
            try await store(record: record, retainedAt: now)
        }
        compactStorageIfNeeded()
    }

    /// Returns the current rolling window in oldest-to-newest order.
    /// - Parameter limit: Optional cap applied to the newest retained samples.
    public func snapshot(limit: Int? = nil) async -> Snapshot {
        let now = await clock.now()
        evictExpired(now: now)

        let liveRecords = liveRecordsSlice()
        let limitedRecords: ArraySlice<StoredRecord>
        if let limit {
            limitedRecords = liveRecords.suffix(max(0, limit))
        } else {
            limitedRecords = liveRecords
        }
        let limitedSamples = limitedRecords.map(\.sample)

        return Snapshot(
            samples: limitedSamples,
            retainedSampleCount: liveRecords.count,
            retainedBytes: retainedBytes,
            oldestSampleAt: liveRecords.first?.timestamp,
            latestSampleAt: liveRecords.last?.timestamp
        )
    }

    /// Returns all currently retained samples.
    public func readAll() async -> [PacketSample] {
        await snapshot().samples
    }

    /// Clears the rolling window immediately.
    public func reset() {
        records.removeAll(keepingCapacity: false)
        startIndex = 0
        retainedBytes = 0
    }

    /// Approximate memory cost used for eviction policy tests and capacity sizing.
    public static func estimatedRecordSize(for sample: PacketSample) -> Int {
        var size = 224

        func add(_ value: String?) {
            guard let value else { return }
            size += value.utf8.count
        }

        func add(_ values: [String]?) {
            guard let values else { return }
            size += 16
            for value in values {
                size += value.utf8.count
            }
        }

        add(sample.direction)
        add(sample.flowId)
        add(sample.protocolHint)
        add(sample.sourceAddress)
        add(sample.destinationAddress)
        add(sample.registrableDomain)
        add(sample.dnsQueryName)
        add(sample.dnsCname)
        add(sample.dnsAnswerAddresses)
        add(sample.tlsServerName)
        add(sample.quicPacketType)
        add(sample.quicDestinationConnectionId)
        add(sample.quicSourceConnectionId)
        add(sample.classification)
        add(sample.associatedDomain)
        add(sample.serviceFamily)
        return size
    }

    static func estimatedRecordSize(for record: PacketStreamRecord) -> Int {
        var size = 224

        func add(_ value: String?) {
            guard let value else { return }
            size += value.utf8.count
        }

        func add(_ values: [String]?) {
            guard let values else { return }
            size += 16
            for value in values {
                size += value.utf8.count
            }
        }

        add(record.direction)
        if let textFlowId = record.textFlowId, !textFlowId.isEmpty {
            add(textFlowId)
        } else if record.flowHash != nil {
            size += 16
        }
        add(record.protocolHint)
        add(record.textSourceAddress)
        add(record.textDestinationAddress)
        add(record.registrableDomain)
        add(record.dnsQueryName)
        add(record.dnsCname)
        add(record.dnsAnswerAddresses)
        add(record.tlsServerName)
        add(record.quicPacketType)
        add(record.quicDestinationConnectionId)
        add(record.quicSourceConnectionId)
        add(record.classification)
        add(record.associatedDomain)
        add(record.serviceFamily)
        return size
    }

    private func store(_ sample: PacketSample, retainedAt: Date) async throws {
        let estimatedBytes = Self.estimatedRecordSize(for: sample)
        guard estimatedBytes <= maxBytes else {
            await logger.log(
                level: .warning,
                phase: .storage,
                category: .liveTap,
                component: "PacketSampleStream",
                event: "packet-sample-dropped",
                result: "oversized-record",
                message: "Dropped packet sample because it exceeds the in-memory rolling window budget",
                metadata: [
                    "record_bytes": String(estimatedBytes),
                    "window_bytes": String(maxBytes)
                ]
            )
            return
        }

        records.append(
            StoredRecord(
                payload: .sample(sample),
                timestamp: sample.timestamp,
                retainedAt: retainedAt,
                estimatedBytes: estimatedBytes
            )
        )
        retainedBytes += estimatedBytes
        evictToFitBudget()
    }

    private func store(record: PacketStreamRecord, retainedAt: Date) async throws {
        let estimatedBytes = Self.estimatedRecordSize(for: record)
        guard estimatedBytes <= maxBytes else {
            await logger.log(
                level: .warning,
                phase: .storage,
                category: .liveTap,
                component: "PacketSampleStream",
                event: "packet-sample-dropped",
                result: "oversized-record",
                message: "Dropped packet sample because it exceeds the in-memory rolling window budget",
                metadata: [
                    "record_bytes": String(estimatedBytes),
                    "window_bytes": String(maxBytes)
                ]
            )
            return
        }

        records.append(
            StoredRecord(
                payload: .record(record),
                timestamp: record.timestamp,
                retainedAt: retainedAt,
                estimatedBytes: estimatedBytes
            )
        )
        retainedBytes += estimatedBytes
        evictToFitBudget()
    }

    private func evictExpired(now: Date) {
        while startIndex < records.count,
              now.timeIntervalSince(records[startIndex].retainedAt) > retentionWindowSeconds {
            retainedBytes -= records[startIndex].estimatedBytes
            startIndex += 1
        }
        compactStorageIfNeeded()
    }

    private func evictToFitBudget() {
        while retainedBytes > maxBytes, startIndex < records.count {
            retainedBytes -= records[startIndex].estimatedBytes
            startIndex += 1
        }
        compactStorageIfNeeded()
    }

    private func compactStorageIfNeeded() {
        guard startIndex > 0 else {
            return
        }
        if startIndex >= 128 || startIndex * 2 >= records.count {
            records.removeFirst(startIndex)
            startIndex = 0
        }
        if startIndex >= records.count {
            records.removeAll(keepingCapacity: false)
            startIndex = 0
        }
        retainedBytes = max(0, retainedBytes)
    }

    private func liveRecordsSlice() -> ArraySlice<StoredRecord> {
        guard startIndex < records.count else {
            return []
        }
        return records[startIndex...]
    }

    private static func makeSample(from record: PacketStreamRecord) -> PacketSample {
        PacketSample(
            kind: record.kind,
            timestamp: record.timestamp,
            direction: record.direction,
            flowId: flowIdentifier(for: record),
            bytes: record.bytes,
            packetCount: record.packetCount,
            flowPacketCount: record.flowPacketCount,
            flowByteCount: record.flowByteCount,
            protocolHint: record.protocolHint,
            ipVersion: record.ipVersion,
            transportProtocolNumber: record.transportProtocolNumber,
            sourceAddress: decodedAddress(
                length: record.sourceAddressLength,
                high: record.sourceAddressHigh,
                low: record.sourceAddressLow,
                fallback: record.textSourceAddress
            ),
            sourcePort: record.sourcePort,
            destinationAddress: decodedAddress(
                length: record.destinationAddressLength,
                high: record.destinationAddressHigh,
                low: record.destinationAddressLow,
                fallback: record.textDestinationAddress
            ),
            destinationPort: record.destinationPort,
            registrableDomain: record.registrableDomain,
            dnsQueryName: record.dnsQueryName,
            dnsCname: record.dnsCname,
            dnsAnswerAddresses: record.dnsAnswerAddresses,
            tlsServerName: record.tlsServerName,
            quicVersion: record.quicVersion,
            quicPacketType: record.quicPacketType,
            quicDestinationConnectionId: record.quicDestinationConnectionId,
            quicSourceConnectionId: record.quicSourceConnectionId,
            classification: record.classification,
            closeReason: record.closeReason,
            largePacketCount: record.largePacketCount,
            smallPacketCount: record.smallPacketCount,
            udpPacketCount: record.udpPacketCount,
            tcpPacketCount: record.tcpPacketCount,
            quicInitialCount: record.quicInitialCount,
            tcpSynCount: record.tcpSynCount,
            tcpFinCount: record.tcpFinCount,
            tcpRstCount: record.tcpRstCount,
            burstDurationMs: record.burstDurationMs,
            burstPacketCount: record.burstPacketCount,
            leadingBytes200ms: record.leadingBytes200ms,
            leadingPackets200ms: record.leadingPackets200ms,
            leadingBytes600ms: record.leadingBytes600ms,
            leadingPackets600ms: record.leadingPackets600ms,
            burstLargePacketCount: record.burstLargePacketCount,
            burstUdpPacketCount: record.burstUdpPacketCount,
            burstTcpPacketCount: record.burstTcpPacketCount,
            burstQuicInitialCount: record.burstQuicInitialCount,
            associatedDomain: record.associatedDomain,
            associationSource: record.associationSource,
            associationAgeMs: record.associationAgeMs,
            associationConfidence: record.associationConfidence,
            lineageID: record.lineageID,
            lineageGeneration: record.lineageGeneration,
            lineageAgeMs: record.lineageAgeMs,
            lineageReuseGapMs: record.lineageReuseGapMs,
            lineageReopenCount: record.lineageReopenCount,
            lineageSiblingCount: record.lineageSiblingCount,
            pathEpoch: record.pathEpoch,
            pathInterfaceClass: record.pathInterfaceClass,
            pathIsExpensive: record.pathIsExpensive,
            pathIsConstrained: record.pathIsConstrained,
            pathSupportsDNS: record.pathSupportsDNS,
            pathChangedRecently: record.pathChangedRecently,
            serviceFamily: record.serviceFamily,
            serviceFamilyConfidence: record.serviceFamilyConfidence,
            serviceAttributionSourceMask: record.serviceAttributionSourceMask
        )
    }

    private static func flowIdentifier(for record: PacketStreamRecord) -> String {
        if let textFlowId = record.textFlowId, !textFlowId.isEmpty {
            return textFlowId
        }
        if let flowHash = record.flowHash {
            return String(format: "%016llx", flowHash)
        }
        return "unknown-flow"
    }

    static func decodedAddress(
        length: UInt8?,
        high: UInt64?,
        low: UInt64?,
        fallback: String?
    ) -> String? {
        guard let length, let high, let low else {
            return fallback
        }

        var bytes = [UInt8](repeating: 0, count: 16)
        var highBE = high.bigEndian
        var lowBE = low.bigEndian
        let highBytes = withUnsafeBytes(of: &highBE) { Array($0) }
        let lowBytes = withUnsafeBytes(of: &lowBE) { Array($0) }
        bytes.replaceSubrange(0..<8, with: highBytes)
        bytes.replaceSubrange(8..<16, with: lowBytes)

        switch length {
        case 4:
            var address = in_addr()
            _ = bytes.withUnsafeBytes { rawBuffer in
                memcpy(&address, rawBuffer.baseAddress!.advanced(by: 12), 4)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
                return fallback
            }
            return String(cString: buffer)
        case 16:
            var address = in6_addr()
            _ = bytes.withUnsafeBytes { rawBuffer in
                memcpy(&address, rawBuffer.baseAddress, 16)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return fallback
            }
            return String(cString: buffer)
        default:
            return fallback
        }
    }
}
