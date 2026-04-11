import Foundation
import Observability

/// Session-scoped summary for one telemetry capture export run.
/// Decision: keep the control response tiny and let the host app read the actual NDJSON file from shared storage.
public struct TelemetryCaptureInfo: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable, Equatable {
        case inactive
        case capturing
        case finalized
    }

    public let sessionID: String?
    public let state: State
    public let recordsRelativePath: String?
    public let startedAt: Date?
    public let latestRecordAt: Date?
    public let finalizedAt: Date?
    public let recordCount: Int

    public init(
        sessionID: String?,
        state: State,
        recordsRelativePath: String?,
        startedAt: Date?,
        latestRecordAt: Date?,
        finalizedAt: Date?,
        recordCount: Int
    ) {
        self.sessionID = sessionID
        self.state = state
        self.recordsRelativePath = recordsRelativePath
        self.startedAt = startedAt
        self.latestRecordAt = latestRecordAt
        self.finalizedAt = finalizedAt
        self.recordCount = recordCount
    }

    public static let inactive = TelemetryCaptureInfo(
        sessionID: nil,
        state: .inactive,
        recordsRelativePath: nil,
        startedAt: nil,
        latestRecordAt: nil,
        finalizedAt: nil,
        recordCount: 0
    )
}

/// NDJSON export row for one compact runtime telemetry record.
/// Contract: this mirrors the package-owned runtime record surface so offline modeling can use the same typed fields
/// detectors see in-process, without re-parsing packet captures later.
public struct TelemetryCaptureRecord: Codable, Sendable, Equatable {
    public let captureSessionId: String
    public let exportedAtMs: Int?
    public let recordKind: PacketSampleKind
    public let timestamp: Date
    public let direction: String
    public let flowId: String
    public let flowHash: UInt64?
    public let textFlowId: String?
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

    init(
        captureSessionId: String,
        exportedAtMs: Int? = nil,
        compactRecord record: PacketSampleStream.PacketStreamRecord
    ) {
        self.captureSessionId = captureSessionId
        self.exportedAtMs = exportedAtMs
        self.recordKind = record.kind
        self.timestamp = record.timestamp
        self.direction = record.direction
        if let textFlowId = record.textFlowId, !textFlowId.isEmpty {
            self.flowId = textFlowId
        } else if let flowHash = record.flowHash {
            self.flowId = String(format: "%016llx", flowHash)
        } else {
            self.flowId = "unknown-flow"
        }
        self.flowHash = record.flowHash
        self.textFlowId = record.textFlowId
        self.bytes = record.bytes
        self.packetCount = record.packetCount
        self.flowPacketCount = record.flowPacketCount
        self.flowByteCount = record.flowByteCount
        self.protocolHint = record.protocolHint
        self.ipVersion = record.ipVersion
        self.transportProtocolNumber = record.transportProtocolNumber
        self.sourceAddress = PacketSampleStream.decodedAddress(
            length: record.sourceAddressLength,
            high: record.sourceAddressHigh,
            low: record.sourceAddressLow,
            fallback: record.textSourceAddress
        )
        self.sourcePort = record.sourcePort
        self.destinationAddress = PacketSampleStream.decodedAddress(
            length: record.destinationAddressLength,
            high: record.destinationAddressHigh,
            low: record.destinationAddressLow,
            fallback: record.textDestinationAddress
        )
        self.destinationPort = record.destinationPort
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
        self.closeReason = record.closeReason
        self.largePacketCount = record.largePacketCount
        self.smallPacketCount = record.smallPacketCount
        self.udpPacketCount = record.udpPacketCount
        self.tcpPacketCount = record.tcpPacketCount
        self.quicInitialCount = record.quicInitialCount
        self.tcpSynCount = record.tcpSynCount
        self.tcpFinCount = record.tcpFinCount
        self.tcpRstCount = record.tcpRstCount
        self.burstDurationMs = record.burstDurationMs
        self.burstPacketCount = record.burstPacketCount
        self.leadingBytes200ms = record.leadingBytes200ms
        self.leadingPackets200ms = record.leadingPackets200ms
        self.leadingBytes600ms = record.leadingBytes600ms
        self.leadingPackets600ms = record.leadingPackets600ms
        self.burstLargePacketCount = record.burstLargePacketCount
        self.burstUdpPacketCount = record.burstUdpPacketCount
        self.burstTcpPacketCount = record.burstTcpPacketCount
        self.burstQuicInitialCount = record.burstQuicInitialCount
        self.associatedDomain = record.associatedDomain
        self.associationSource = record.associationSource
        self.associationAgeMs = record.associationAgeMs
        self.associationConfidence = record.associationConfidence
        self.lineageID = record.lineageID
        self.lineageGeneration = record.lineageGeneration
        self.lineageAgeMs = record.lineageAgeMs
        self.lineageReuseGapMs = record.lineageReuseGapMs
        self.lineageReopenCount = record.lineageReopenCount
        self.lineageSiblingCount = record.lineageSiblingCount
        self.pathEpoch = record.pathEpoch
        self.pathInterfaceClass = record.pathInterfaceClass
        self.pathIsExpensive = record.pathIsExpensive
        self.pathIsConstrained = record.pathIsConstrained
        self.pathSupportsDNS = record.pathSupportsDNS
        self.pathChangedRecently = record.pathChangedRecently
        self.serviceFamily = record.serviceFamily
        self.serviceFamilyConfidence = record.serviceFamilyConfidence
        self.serviceAttributionSourceMask = record.serviceAttributionSourceMask
    }

    public func withExportedAtMs(_ exportedAtMs: Int) -> TelemetryCaptureRecord {
        TelemetryCaptureRecord(
            captureSessionId: captureSessionId,
            exportedAtMs: exportedAtMs,
            recordKind: recordKind,
            timestamp: timestamp,
            direction: direction,
            flowId: flowId,
            flowHash: flowHash,
            textFlowId: textFlowId,
            bytes: bytes,
            packetCount: packetCount,
            flowPacketCount: flowPacketCount,
            flowByteCount: flowByteCount,
            protocolHint: protocolHint,
            ipVersion: ipVersion,
            transportProtocolNumber: transportProtocolNumber,
            sourceAddress: sourceAddress,
            sourcePort: sourcePort,
            destinationAddress: destinationAddress,
            destinationPort: destinationPort,
            registrableDomain: registrableDomain,
            dnsQueryName: dnsQueryName,
            dnsCname: dnsCname,
            dnsAnswerAddresses: dnsAnswerAddresses,
            tlsServerName: tlsServerName,
            quicVersion: quicVersion,
            quicPacketType: quicPacketType,
            quicDestinationConnectionId: quicDestinationConnectionId,
            quicSourceConnectionId: quicSourceConnectionId,
            classification: classification,
            closeReason: closeReason,
            largePacketCount: largePacketCount,
            smallPacketCount: smallPacketCount,
            udpPacketCount: udpPacketCount,
            tcpPacketCount: tcpPacketCount,
            quicInitialCount: quicInitialCount,
            tcpSynCount: tcpSynCount,
            tcpFinCount: tcpFinCount,
            tcpRstCount: tcpRstCount,
            burstDurationMs: burstDurationMs,
            burstPacketCount: burstPacketCount,
            leadingBytes200ms: leadingBytes200ms,
            leadingPackets200ms: leadingPackets200ms,
            leadingBytes600ms: leadingBytes600ms,
            leadingPackets600ms: leadingPackets600ms,
            burstLargePacketCount: burstLargePacketCount,
            burstUdpPacketCount: burstUdpPacketCount,
            burstTcpPacketCount: burstTcpPacketCount,
            burstQuicInitialCount: burstQuicInitialCount,
            associatedDomain: associatedDomain,
            associationSource: associationSource,
            associationAgeMs: associationAgeMs,
            associationConfidence: associationConfidence,
            lineageID: lineageID,
            lineageGeneration: lineageGeneration,
            lineageAgeMs: lineageAgeMs,
            lineageReuseGapMs: lineageReuseGapMs,
            lineageReopenCount: lineageReopenCount,
            lineageSiblingCount: lineageSiblingCount,
            pathEpoch: pathEpoch,
            pathInterfaceClass: pathInterfaceClass,
            pathIsExpensive: pathIsExpensive,
            pathIsConstrained: pathIsConstrained,
            pathSupportsDNS: pathSupportsDNS,
            pathChangedRecently: pathChangedRecently,
            serviceFamily: serviceFamily,
            serviceFamilyConfidence: serviceFamilyConfidence,
            serviceAttributionSourceMask: serviceAttributionSourceMask
        )
    }

    public init(
        captureSessionId: String,
        exportedAtMs: Int? = nil,
        recordKind: PacketSampleKind,
        timestamp: Date,
        direction: String,
        flowId: String,
        flowHash: UInt64?,
        textFlowId: String?,
        bytes: Int,
        packetCount: Int?,
        flowPacketCount: Int?,
        flowByteCount: Int?,
        protocolHint: String,
        ipVersion: UInt8?,
        transportProtocolNumber: UInt8?,
        sourceAddress: String?,
        sourcePort: UInt16?,
        destinationAddress: String?,
        destinationPort: UInt16?,
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
        associatedDomain: String?,
        associationSource: DetectorAssociationSource?,
        associationAgeMs: Int?,
        associationConfidence: Double?,
        lineageID: UInt64?,
        lineageGeneration: Int?,
        lineageAgeMs: Int?,
        lineageReuseGapMs: Int?,
        lineageReopenCount: Int?,
        lineageSiblingCount: Int?,
        pathEpoch: UInt32?,
        pathInterfaceClass: PathInterfaceClass?,
        pathIsExpensive: Bool?,
        pathIsConstrained: Bool?,
        pathSupportsDNS: Bool?,
        pathChangedRecently: Bool?,
        serviceFamily: String?,
        serviceFamilyConfidence: Double?,
        serviceAttributionSourceMask: UInt16?
    ) {
        self.captureSessionId = captureSessionId
        self.exportedAtMs = exportedAtMs
        self.recordKind = recordKind
        self.timestamp = timestamp
        self.direction = direction
        self.flowId = flowId
        self.flowHash = flowHash
        self.textFlowId = textFlowId
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

/// Streams raw capture NDJSON into an exported file with one uniform `exportedAtMs` stamp.
/// Decision: export-time rewriting keeps hot-path capture appends cheap while still producing one file tailored for
/// offline dataset ingestion.
public enum TelemetryCaptureExporter {
    @discardableResult
    public static func exportRecords(from sourceURL: URL, to destinationURL: URL) throws -> URL {
        let destinationRoot = destinationURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: destinationRoot, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: destinationURL.path) {
            try FileManager.default.removeItem(at: destinationURL)
        }
        FileManager.default.createFile(atPath: destinationURL.path, contents: Data())

        let exportedAtMs = Int(Date().timeIntervalSince1970 * 1000)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]

        let sourceHandle = try FileHandle(forReadingFrom: sourceURL)
        let destinationHandle = try FileHandle(forWritingTo: destinationURL)
        defer {
            try? sourceHandle.close()
            try? destinationHandle.close()
        }

        var buffer = Data()
        while let chunk = try sourceHandle.read(upToCount: 64 * 1024), !chunk.isEmpty {
            buffer.append(chunk)
            try drainCompleteLines(
                buffer: &buffer,
                decoder: decoder,
                encoder: encoder,
                destinationHandle: destinationHandle,
                exportedAtMs: exportedAtMs
            )
        }

        if !buffer.isEmpty {
            try writeLine(
                buffer,
                decoder: decoder,
                encoder: encoder,
                destinationHandle: destinationHandle,
                exportedAtMs: exportedAtMs
            )
        }

        try destinationHandle.synchronize()
        return destinationURL
    }

    private static func drainCompleteLines(
        buffer: inout Data,
        decoder: JSONDecoder,
        encoder: JSONEncoder,
        destinationHandle: FileHandle,
        exportedAtMs: Int
    ) throws {
        while let newlineIndex = buffer.firstIndex(of: 0x0A) {
            let line = Data(buffer[..<newlineIndex])
            buffer.removeSubrange(...newlineIndex)
            guard !line.isEmpty else {
                continue
            }
            try writeLine(
                line,
                decoder: decoder,
                encoder: encoder,
                destinationHandle: destinationHandle,
                exportedAtMs: exportedAtMs
            )
        }
    }

    private static func writeLine(
        _ line: Data,
        decoder: JSONDecoder,
        encoder: JSONEncoder,
        destinationHandle: FileHandle,
        exportedAtMs: Int
    ) throws {
        let record = try decoder.decode(TelemetryCaptureRecord.self, from: line)
        try destinationHandle.write(contentsOf: encoder.encode(record.withExportedAtMs(exportedAtMs)))
        try destinationHandle.write(contentsOf: Data([0x0A]))
    }
}

internal actor TelemetryCaptureSink {
    enum Error: LocalizedError, Sendable, Equatable {
        case invalidSessionID
        case captureAlreadyActive(String)
        case noActiveCapture
        case sessionMismatch(expected: String, got: String)
        case unavailable

        var errorDescription: String? {
            switch self {
            case .invalidSessionID:
                return "Telemetry capture requires a non-empty session id."
            case .captureAlreadyActive(let sessionID):
                return "A telemetry capture session is already active: \(sessionID)."
            case .noActiveCapture:
                return "No telemetry capture session is active."
            case .sessionMismatch(let expected, let got):
                return "Telemetry capture session mismatch. Expected \(expected), got \(got)."
            case .unavailable:
                return "Telemetry capture storage is unavailable."
            }
        }
    }

    private enum Policy {
        static let flushThresholdBytes = 64 * 1024
        static let coalescingDelay: Duration = .milliseconds(250)
    }

    private struct ActiveCapture {
        var info: TelemetryCaptureInfo
        let sessionRootURL: URL
        let recordsURL: URL
        let infoURL: URL
        let handle: FileHandle
        var pendingData = Data()
    }

    private let analyticsRootURL: URL
    private let logger: StructuredLogger
    private let encoder: JSONEncoder

    private var activeCapture: ActiveCapture?
    private var latestInfo = TelemetryCaptureInfo.inactive
    private var flushTask: Task<Void, Never>?

    init(analyticsRootURL: URL, logger: StructuredLogger) {
        self.analyticsRootURL = analyticsRootURL
        self.logger = logger
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        self.encoder = encoder
    }

    func begin(sessionID rawSessionID: String) async throws -> TelemetryCaptureInfo {
        let sessionID = rawSessionID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sessionID.isEmpty else {
            throw Error.invalidSessionID
        }

        if let activeCapture {
            if activeCapture.info.sessionID == sessionID {
                return activeCapture.info
            }
            throw Error.captureAlreadyActive(activeCapture.info.sessionID ?? "unknown")
        }

        let recordsURL = analyticsRootURL
            .appendingPathComponent(AnalyticsStoragePaths.telemetryCaptureRelativeRecordsPath(sessionID: sessionID), isDirectory: false)
        let sessionRootURL = recordsURL.deletingLastPathComponent()
        let infoURL = sessionRootURL.appendingPathComponent("capture-info.json", isDirectory: false)
        let currentInfoURL = analyticsRootURL
            .appendingPathComponent("TelemetryCaptures", isDirectory: true)
            .appendingPathComponent("current-session.json", isDirectory: false)

        if FileManager.default.fileExists(atPath: sessionRootURL.path) {
            try FileManager.default.removeItem(at: sessionRootURL)
        }
        try ProtectedAnalyticsFileIO.createProtectedDirectory(at: sessionRootURL)
        try ProtectedAnalyticsFileIO.prepareProtectedFile(at: recordsURL)

        let handle = try FileHandle(forWritingTo: recordsURL)
        try handle.seekToEnd()

        let startedAt = Date()
        let info = TelemetryCaptureInfo(
            sessionID: sessionID,
            state: .capturing,
            recordsRelativePath: AnalyticsStoragePaths.telemetryCaptureRelativeRecordsPath(sessionID: sessionID),
            startedAt: startedAt,
            latestRecordAt: nil,
            finalizedAt: nil,
            recordCount: 0
        )
        let capture = ActiveCapture(
            info: info,
            sessionRootURL: sessionRootURL,
            recordsURL: recordsURL,
            infoURL: infoURL,
            handle: handle,
            pendingData: Data()
        )
        activeCapture = capture
        latestInfo = info
        try persist(info: info, currentInfoURL: currentInfoURL, infoURL: infoURL)
        return info
    }

    func append(records: [PacketSampleStream.PacketStreamRecord]) async {
        guard !records.isEmpty, var activeCapture else {
            return
        }

        for record in records {
            let payload = TelemetryCaptureRecord(
                captureSessionId: activeCapture.info.sessionID ?? "unknown-session",
                compactRecord: record
            )
            do {
                activeCapture.pendingData.append(try encoder.encode(payload))
                activeCapture.pendingData.append(0x0A)
                activeCapture.info = TelemetryCaptureInfo(
                    sessionID: activeCapture.info.sessionID,
                    state: .capturing,
                    recordsRelativePath: activeCapture.info.recordsRelativePath,
                    startedAt: activeCapture.info.startedAt,
                    latestRecordAt: record.timestamp,
                    finalizedAt: nil,
                    recordCount: activeCapture.info.recordCount + 1
                )
            } catch {
                await logWriteFailure(event: "capture-record-encode-failed", error: error)
            }
        }

        self.activeCapture = activeCapture
        latestInfo = activeCapture.info
        if activeCapture.pendingData.count >= Policy.flushThresholdBytes {
            await flushPending(reason: "threshold")
        } else {
            scheduleFlushIfNeeded()
        }
    }

    func flush(sessionID: String) async throws -> TelemetryCaptureInfo {
        let normalizedSessionID = sessionID.trimmingCharacters(in: .whitespacesAndNewlines)
        if var activeCapture {
            guard activeCapture.info.sessionID == normalizedSessionID else {
                throw Error.sessionMismatch(expected: activeCapture.info.sessionID ?? "unknown", got: normalizedSessionID)
            }
            await flushPending(reason: "explicit")
            activeCapture = self.activeCapture ?? activeCapture
            return activeCapture.info
        }

        guard latestInfo.sessionID == normalizedSessionID else {
            throw Error.noActiveCapture
        }
        return latestInfo
    }

    func end(sessionID: String) async throws -> TelemetryCaptureInfo {
        let normalizedSessionID = sessionID.trimmingCharacters(in: .whitespacesAndNewlines)
        if let activeCapture {
            guard activeCapture.info.sessionID == normalizedSessionID else {
                throw Error.sessionMismatch(expected: activeCapture.info.sessionID ?? "unknown", got: normalizedSessionID)
            }
        } else {
            guard latestInfo.sessionID == normalizedSessionID else {
                throw Error.noActiveCapture
            }
            return latestInfo
        }

        await flushPending(reason: "end")
        flushTask?.cancel()
        flushTask = nil

        guard let activeCapture = self.activeCapture else {
            return latestInfo
        }

        do {
            try activeCapture.handle.synchronize()
        } catch {
            await logWriteFailure(event: "capture-file-synchronize-failed", error: error)
        }
        try? activeCapture.handle.close()

        let finalizedAt = Date()
        let finalized = TelemetryCaptureInfo(
            sessionID: activeCapture.info.sessionID,
            state: .finalized,
            recordsRelativePath: activeCapture.info.recordsRelativePath,
            startedAt: activeCapture.info.startedAt,
            latestRecordAt: activeCapture.info.latestRecordAt,
            finalizedAt: finalizedAt,
            recordCount: activeCapture.info.recordCount
        )
        let currentInfoURL = analyticsRootURL
            .appendingPathComponent("TelemetryCaptures", isDirectory: true)
            .appendingPathComponent("current-session.json", isDirectory: false)
        do {
            try persist(info: finalized, currentInfoURL: currentInfoURL, infoURL: activeCapture.infoURL)
        } catch {
            await logWriteFailure(event: "capture-info-persist-failed", error: error)
        }

        latestInfo = finalized
        self.activeCapture = nil
        return finalized
    }

    func latestCaptureInfo() -> TelemetryCaptureInfo {
        activeCapture?.info ?? latestInfo
    }

    func shutdown() async {
        await flushPending(reason: "shutdown")
        flushTask?.cancel()
        flushTask = nil

        guard let activeCapture else {
            return
        }

        do {
            try activeCapture.handle.synchronize()
        } catch {
            await logWriteFailure(event: "capture-file-synchronize-failed", error: error)
        }
        try? activeCapture.handle.close()

        let finalized = TelemetryCaptureInfo(
            sessionID: activeCapture.info.sessionID,
            state: .finalized,
            recordsRelativePath: activeCapture.info.recordsRelativePath,
            startedAt: activeCapture.info.startedAt,
            latestRecordAt: activeCapture.info.latestRecordAt,
            finalizedAt: Date(),
            recordCount: activeCapture.info.recordCount
        )
        let currentInfoURL = analyticsRootURL
            .appendingPathComponent("TelemetryCaptures", isDirectory: true)
            .appendingPathComponent("current-session.json", isDirectory: false)
        do {
            try persist(info: finalized, currentInfoURL: currentInfoURL, infoURL: activeCapture.infoURL)
        } catch {
            await logWriteFailure(event: "capture-info-persist-failed", error: error)
        }

        latestInfo = finalized
        self.activeCapture = nil
    }

    private func scheduleFlushIfNeeded() {
        guard flushTask == nil else {
            return
        }

        flushTask = Task(priority: .utility) { [weak self] in
            try? await Task.sleep(for: Policy.coalescingDelay)
            await self?.flushPending(reason: "coalesced")
        }
    }

    private func flushPending(reason: String) async {
        flushTask?.cancel()
        flushTask = nil

        guard var activeCapture, !activeCapture.pendingData.isEmpty else {
            return
        }

        let payload = activeCapture.pendingData
        activeCapture.pendingData.removeAll(keepingCapacity: true)
        self.activeCapture = activeCapture

        do {
            try activeCapture.handle.write(contentsOf: payload)
            try activeCapture.handle.synchronize()
        } catch {
            await logWriteFailure(event: "capture-file-write-failed", error: error, metadata: ["reason": reason])
            return
        }

        let currentInfoURL = analyticsRootURL
            .appendingPathComponent("TelemetryCaptures", isDirectory: true)
            .appendingPathComponent("current-session.json", isDirectory: false)
        do {
            try persist(info: activeCapture.info, currentInfoURL: currentInfoURL, infoURL: activeCapture.infoURL)
        } catch {
            await logWriteFailure(event: "capture-info-persist-failed", error: error, metadata: ["reason": reason])
        }

        latestInfo = activeCapture.info
    }

    private func persist(info: TelemetryCaptureInfo, currentInfoURL: URL, infoURL: URL) throws {
        let payload = try encoder.encode(info)
        try ProtectedAnalyticsFileIO.writeProtectedData(payload, to: currentInfoURL)
        try ProtectedAnalyticsFileIO.writeProtectedData(payload, to: infoURL)
    }

    private func logWriteFailure(event: String, error: any Swift.Error, metadata: [String: String] = [:]) async {
        await logger.log(
            level: .warning,
            phase: .storage,
            category: .control,
            component: "TelemetryCaptureSink",
            event: event,
            errorCode: String(describing: error),
            message: "Failed to persist telemetry capture artifacts",
            metadata: metadata
        )
    }
}
