import Foundation
import TunnelRuntime

/// Runtime packet pipeline that favors detector-friendly flow and burst events over rich per-packet logging.
/// Actor ownership: packet parsing, flow state, burst tracking, and metadata caches are serialized here.
public actor PacketAnalyticsPipeline {
    private enum FlowCachePolicy {
        static let maxTrackedFlows = 2_048
        static let flowTTLSeconds: TimeInterval = 120
        static let evictionSweepIntervalSeconds: TimeInterval = 15
        static let arrivalQueueCompactionThreshold = 128
    }

    /// Emission policy applied by the long-lived telemetry worker.
    /// Decision: always-on capture stays cheap, while richer metadata and activity samples are reduced as thermal pressure rises.
    public struct EmissionPolicy: Sendable {
        public let allowDeepMetadata: Bool
        public let maxMetadataProbesPerBatch: Int
        public let activitySampleMinimumPackets: Int
        public let activitySampleMinimumBytes: Int
        public let activitySampleMinimumInterval: TimeInterval
        public let emitBurstEvents: Bool
        public let emitActivitySamples: Bool

        public init(
            allowDeepMetadata: Bool,
            maxMetadataProbesPerBatch: Int,
            activitySampleMinimumPackets: Int,
            activitySampleMinimumBytes: Int,
            activitySampleMinimumInterval: TimeInterval,
            emitBurstEvents: Bool,
            emitActivitySamples: Bool
        ) {
            self.allowDeepMetadata = allowDeepMetadata
            self.maxMetadataProbesPerBatch = max(0, maxMetadataProbesPerBatch)
            self.activitySampleMinimumPackets = max(1, activitySampleMinimumPackets)
            self.activitySampleMinimumBytes = max(1, activitySampleMinimumBytes)
            self.activitySampleMinimumInterval = max(0, activitySampleMinimumInterval)
            self.emitBurstEvents = emitBurstEvents
            self.emitActivitySamples = emitActivitySamples
        }
    }

    private struct FlowContext: Sendable {
        var registrableDomain: String?
        var dnsQueryName: String?
        var dnsCname: String?
        var dnsAnswerAddresses: [String]?
        var tlsServerName: String?
        var quicVersion: UInt32?
        var quicPacketType: String?
        var quicDestinationConnectionId: String?
        var quicSourceConnectionId: String?
        var classification: String?
        var lastSeen: Date
        var hasEmittedFlowOpen = false
        var lastMetadataFingerprint: UInt64?
        var lastActivityEmissionAt: Date?
        var totalPacketCount = 0
        var totalByteCount = 0
        var windowPacketCount = 0
        var windowByteCount = 0
        var currentBurstPacketCount = 0
        var currentBurstByteCount = 0
    }

    private let clock: any Clock
    private let burstTracker: BurstTracker
    private let signatureClassifier: SignatureClassifier

    private var flowContexts: [FlowKey: FlowContext] = [:]
    private var flowContextArrivalQueue: ArraySlice<FlowKey> = []
    private var lastFlowContextSweepAt: Date?

    /// - Parameters:
    ///   - clock: Time source used for deterministic timestamps.
    ///   - burstTracker: Burst detector keyed by stable flow identity.
    ///   - signatureClassifier: Domain classifier for packet-level labeling.
    public init(
        clock: any Clock,
        burstTracker: BurstTracker,
        signatureClassifier: SignatureClassifier
    ) {
        self.clock = clock
        self.burstTracker = burstTracker
        self.signatureClassifier = signatureClassifier
    }

    /// Ingests a packet batch and returns compact detector-facing records.
    /// Decision: the tunnel emits a sparse event stream (`flowOpen`, `metadata`, `burst`, `activitySample`)
    /// instead of serializing a rich `PacketSample` for every admitted packet.
    /// - Parameters:
    ///   - packets: Raw packet payloads.
    ///   - families: Optional family hints aligned by packet index.
    ///   - summaries: Optional precomputed fast-path summaries aligned by packet index.
    ///   - direction: Packet direction relative to the tunnel interface.
    ///   - policy: Thermal-aware emission policy chosen by the worker.
    /// - Returns: Compact live-tap records ready for the rolling in-memory tap.
    func ingest(
        packets: [Data],
        families: [Int32],
        summaries: [FastPacketSummary]? = nil,
        direction: PacketDirection,
        policy: EmissionPolicy
    ) async -> [PacketSampleStream.PacketStreamRecord] {
        guard !packets.isEmpty else {
            return []
        }

        let now = await clock.now()
        maybeEvictExpiredFlowContexts(now: now)

        var records: [PacketSampleStream.PacketStreamRecord] = []
        records.reserveCapacity(min(packets.count, 64))

        var metadataProbesRemaining = policy.maxMetadataProbesPerBatch

        for (index, packet) in packets.enumerated() {
            let familyHint: Int32? = families.indices.contains(index) ? families[index] : nil
            let summary: FastPacketSummary
            if let summaries, summaries.indices.contains(index) {
                summary = summaries[index]
            } else {
                guard let parsed = FastPacketSummary(data: packet, ipVersionHint: familyHint) else {
                    continue
                }
                summary = parsed
            }

            let shouldTrackForTelemetry = shouldTrackForTelemetry(summary: summary)
            guard shouldTrackForTelemetry else {
                continue
            }

            let allowMetadataProbe = policy.allowDeepMetadata &&
                metadataProbesRemaining > 0

            let flow = summary.flowKey
            let isNewFlow = flowContexts[flow] == nil
            var context = flowContexts[flow] ?? makeFlowContext(for: summary, now: now)
            context.lastSeen = now

            if let burst = burstTracker.recordPacket(flow: flow, now: now) {
                if policy.emitBurstEvents, context.currentBurstPacketCount > 0 {
                    records.append(
                        makeRecord(
                            kind: .burst,
                            timestamp: now,
                            direction: direction,
                            summary: summary,
                            flowContext: context,
                            bytes: context.currentBurstByteCount,
                            packetCount: burst.packetCount,
                            burstDurationMs: burst.burstDurationMs,
                            burstPacketCount: burst.packetCount
                        )
                    )
                }
                context.currentBurstPacketCount = 0
                context.currentBurstByteCount = 0
            }

            context.totalPacketCount += 1
            context.totalByteCount += summary.packetLength
            context.windowPacketCount += 1
            context.windowByteCount += summary.packetLength
            context.currentBurstPacketCount += 1
            context.currentBurstByteCount += summary.packetLength

            mergeCheapMetadata(into: &context, summary: summary)

            if !context.hasEmittedFlowOpen {
                records.append(
                    makeRecord(
                        kind: .flowOpen,
                        timestamp: now,
                        direction: direction,
                        summary: summary,
                        flowContext: context,
                        bytes: summary.packetLength,
                        packetCount: 1
                    )
                )
                context.hasEmittedFlowOpen = true
            }

            if allowMetadataProbe,
               shouldProbeDeepMetadata(summary: summary, flowContext: context) {
                if let deepMetadata = PacketParser.parse(packet, ipVersionHint: familyHint) {
                    metadataProbesRemaining -= 1
                    let previousFingerprint = context.lastMetadataFingerprint
                    await mergeDeepMetadata(into: &context, metadata: deepMetadata)
                    let nextFingerprint = metadataFingerprint(for: context)
                    if nextFingerprint != previousFingerprint {
                        context.lastMetadataFingerprint = nextFingerprint
                        records.append(
                            makeRecord(
                                kind: .metadata,
                                timestamp: now,
                                direction: direction,
                                summary: summary,
                                flowContext: context,
                                bytes: summary.packetLength,
                                packetCount: 1
                            )
                        )
                    }
                }
            }

            if shouldEmitActivitySample(context: context, now: now, policy: policy) {
                records.append(
                    makeRecord(
                        kind: .activitySample,
                        timestamp: now,
                        direction: direction,
                        summary: summary,
                        flowContext: context,
                        bytes: context.windowByteCount,
                        packetCount: context.windowPacketCount
                    )
                )
                context.windowPacketCount = 0
                context.windowByteCount = 0
                context.lastActivityEmissionAt = now
            }

            flowContexts[flow] = context
            if isNewFlow {
                flowContextArrivalQueue.append(flow)
            }
        }

        trimOverflowFlowContextsIfNeeded()
        return records
    }

    /// Returns `true` when a packet is worth tracking for burst/activity detection.
    /// Decision: pure TCP ACK traffic is ignored because it adds a lot of heat without improving detector signal.
    private func shouldTrackForTelemetry(summary: FastPacketSummary) -> Bool {
        switch summary.transport {
        case .tcp:
            return summary.hasTransportPayload || summary.isTCPControlSignal
        case .udp:
            return summary.hasTransportPayload
        case .icmp, .icmpv6:
            return true
        default:
            return summary.packetLength > 0
        }
    }

    private func makeFlowContext(for summary: FastPacketSummary, now: Date) -> FlowContext {
        FlowContext(
            registrableDomain: nil,
            dnsQueryName: nil,
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            tlsServerName: nil,
            quicVersion: summary.quicVersion,
            quicPacketType: summary.quicPacketType?.rawValue,
            quicDestinationConnectionId: Self.hexString(summary.quicDestinationConnectionID),
            quicSourceConnectionId: Self.hexString(summary.quicSourceConnectionID),
            classification: nil,
            lastSeen: now
        )
    }

    private func mergeCheapMetadata(into flowContext: inout FlowContext, summary: FastPacketSummary) {
        if flowContext.quicVersion == nil {
            flowContext.quicVersion = summary.quicVersion
        }
        if flowContext.quicPacketType == nil {
            flowContext.quicPacketType = summary.quicPacketType?.rawValue
        }
        if flowContext.quicDestinationConnectionId == nil {
            flowContext.quicDestinationConnectionId = Self.hexString(summary.quicDestinationConnectionID)
        }
        if flowContext.quicSourceConnectionId == nil {
            flowContext.quicSourceConnectionId = Self.hexString(summary.quicSourceConnectionID)
        }
    }

    private func shouldProbeDeepMetadata(summary: FastPacketSummary, flowContext: FlowContext) -> Bool {
        if summary.isDNSCandidate {
            return true
        }
        if summary.isTLSClientHelloCandidate && flowContext.tlsServerName == nil {
            return true
        }
        if summary.isQUICInitialCandidate && flowContext.tlsServerName == nil {
            return true
        }
        return false
    }

    private func mergeDeepMetadata(into flowContext: inout FlowContext, metadata: PacketMetadata) async {
        if let registrableDomain = metadata.registrableDomain, !registrableDomain.isEmpty {
            flowContext.registrableDomain = registrableDomain
        }
        if let dnsQueryName = metadata.dnsQueryName, !dnsQueryName.isEmpty {
            flowContext.dnsQueryName = dnsQueryName
        }
        if let dnsCname = metadata.dnsCname, !dnsCname.isEmpty {
            flowContext.dnsCname = dnsCname
        }
        if let dnsAnswerAddresses = metadata.dnsAnswerAddresses, !dnsAnswerAddresses.isEmpty {
            flowContext.dnsAnswerAddresses = dnsAnswerAddresses.map(\.stringValue)
        }
        if let tlsServerName = metadata.tlsServerName, !tlsServerName.isEmpty {
            flowContext.tlsServerName = tlsServerName
        }
        if let quicVersion = metadata.quicVersion {
            flowContext.quicVersion = quicVersion
        }
        if let quicPacketType = metadata.quicPacketType?.rawValue {
            flowContext.quicPacketType = quicPacketType
        }
        if let quicDestinationConnectionId = metadata.quicDestinationConnectionId, !quicDestinationConnectionId.isEmpty {
            flowContext.quicDestinationConnectionId = quicDestinationConnectionId
        }
        if let quicSourceConnectionId = metadata.quicSourceConnectionId, !quicSourceConnectionId.isEmpty {
            flowContext.quicSourceConnectionId = quicSourceConnectionId
        }

        let hostCandidate = metadata.tlsServerName
            ?? metadata.dnsCname
            ?? metadata.dnsQueryName
            ?? metadata.registrableDomain
        if let hostCandidate, !hostCandidate.isEmpty {
            flowContext.classification = await signatureClassifier.classify(host: hostCandidate)
        }
    }

    private func shouldEmitActivitySample(context: FlowContext, now: Date, policy: EmissionPolicy) -> Bool {
        guard policy.emitActivitySamples else {
            return false
        }

        if context.windowPacketCount >= policy.activitySampleMinimumPackets {
            return true
        }
        if context.windowByteCount >= policy.activitySampleMinimumBytes {
            return true
        }
        if let lastActivityEmissionAt = context.lastActivityEmissionAt {
            return now.timeIntervalSince(lastActivityEmissionAt) >= policy.activitySampleMinimumInterval
        }
        return context.windowPacketCount > 0 && policy.activitySampleMinimumInterval == 0
    }

    private func metadataFingerprint(for flowContext: FlowContext) -> UInt64 {
        var hash: UInt64 = 14_695_981_039_346_656_037
        func mix(_ value: String?) {
            guard let value else { return }
            for byte in value.utf8 {
                hash ^= UInt64(byte)
                hash &*= 1_099_511_628_211
            }
        }
        func mix(_ values: [String]?) {
            guard let values else { return }
            for value in values {
                mix(value)
            }
        }

        mix(flowContext.registrableDomain)
        mix(flowContext.dnsQueryName)
        mix(flowContext.dnsCname)
        mix(flowContext.dnsAnswerAddresses)
        mix(flowContext.tlsServerName)
        mix(flowContext.quicPacketType)
        mix(flowContext.quicDestinationConnectionId)
        mix(flowContext.quicSourceConnectionId)
        mix(flowContext.classification)
        if let quicVersion = flowContext.quicVersion {
            hash ^= UInt64(quicVersion)
            hash &*= 1_099_511_628_211
        }
        return hash
    }

    private func makeRecord(
        kind: PacketSampleKind,
        timestamp: Date,
        direction: PacketDirection,
        summary: FastPacketSummary,
        flowContext: FlowContext,
        bytes: Int,
        packetCount: Int,
        burstDurationMs: Int? = nil,
        burstPacketCount: Int? = nil
    ) -> PacketSampleStream.PacketStreamRecord {
        PacketSampleStream.PacketStreamRecord(
            kind: kind,
            timestamp: timestamp,
            direction: direction.rawValue,
            bytes: bytes,
            packetCount: packetCount,
            flowPacketCount: flowContext.totalPacketCount,
            flowByteCount: flowContext.totalByteCount,
            protocolHint: summary.protocolHint,
            ipVersion: summary.ipVersion,
            transportProtocolNumber: summary.transportProtocolNumber,
            sourcePort: summary.hasPorts ? summary.sourcePort : nil,
            destinationPort: summary.hasPorts ? summary.destinationPort : nil,
            flowHash: summary.flowHash,
            textFlowId: nil,
            sourceAddressLength: summary.sourceAddressLength,
            sourceAddressHigh: summary.sourceAddressHigh,
            sourceAddressLow: summary.sourceAddressLow,
            destinationAddressLength: summary.destinationAddressLength,
            destinationAddressHigh: summary.destinationAddressHigh,
            destinationAddressLow: summary.destinationAddressLow,
            textSourceAddress: nil,
            textDestinationAddress: nil,
            registrableDomain: flowContext.registrableDomain,
            dnsQueryName: flowContext.dnsQueryName,
            dnsCname: flowContext.dnsCname,
            dnsAnswerAddresses: flowContext.dnsAnswerAddresses,
            tlsServerName: flowContext.tlsServerName,
            quicVersion: flowContext.quicVersion,
            quicPacketType: flowContext.quicPacketType,
            quicDestinationConnectionId: flowContext.quicDestinationConnectionId,
            quicSourceConnectionId: flowContext.quicSourceConnectionId,
            classification: flowContext.classification,
            burstDurationMs: burstDurationMs,
            burstPacketCount: burstPacketCount
        )
    }

    /// Decision: flow-context cleanup is amortized because sweeping a large dictionary on every batch adds heat
    /// without improving detector quality.
    private func maybeEvictExpiredFlowContexts(now: Date) {
        if let lastFlowContextSweepAt,
           now.timeIntervalSince(lastFlowContextSweepAt) < FlowCachePolicy.evictionSweepIntervalSeconds,
           flowContexts.count < FlowCachePolicy.maxTrackedFlows {
            return
        }

        lastFlowContextSweepAt = now
        let expiredFlows = flowContexts.compactMap { flow, context in
            now.timeIntervalSince(context.lastSeen) > FlowCachePolicy.flowTTLSeconds ? flow : nil
        }
        for flow in expiredFlows {
            flowContexts.removeValue(forKey: flow)
        }
        pruneFlowContextArrivalQueueIfNeeded(force: !expiredFlows.isEmpty)
    }

    private func trimOverflowFlowContextsIfNeeded() {
        guard flowContexts.count > FlowCachePolicy.maxTrackedFlows else {
            return
        }

        pruneFlowContextArrivalQueueIfNeeded(force: true)

        while flowContexts.count > FlowCachePolicy.maxTrackedFlows {
            if let candidate = flowContextArrivalQueue.popFirst() {
                guard flowContexts.removeValue(forKey: candidate) != nil else {
                    continue
                }
            } else if let fallback = flowContexts.keys.first {
                // Decision: this should stay cold because the arrival queue is the primary eviction path.
                // If the queue is unexpectedly empty, removing any active flow is cheaper than re-sorting the actor state.
                flowContexts.removeValue(forKey: fallback)
            } else {
                break
            }
        }

        pruneFlowContextArrivalQueueIfNeeded()
    }

    private func pruneFlowContextArrivalQueueIfNeeded(force: Bool = false) {
        let queueLimit = max(FlowCachePolicy.maxTrackedFlows * 4, 256)
        guard force ||
                flowContextArrivalQueue.startIndex > FlowCachePolicy.arrivalQueueCompactionThreshold ||
                flowContextArrivalQueue.count > queueLimit else {
            return
        }

        var seen: Set<FlowKey> = []
        var activeQueue: [FlowKey] = []
        activeQueue.reserveCapacity(min(flowContexts.count, FlowCachePolicy.maxTrackedFlows))

        for flow in flowContextArrivalQueue {
            guard flowContexts[flow] != nil, seen.insert(flow).inserted else {
                continue
            }
            activeQueue.append(flow)
        }

        flowContextArrivalQueue = ArraySlice(activeQueue)
    }

    private static func hexString(_ data: Data?) -> String? {
        guard let data, !data.isEmpty else {
            return nil
        }
        return data.map { String(format: "%02x", $0) }.joined()
    }
}
