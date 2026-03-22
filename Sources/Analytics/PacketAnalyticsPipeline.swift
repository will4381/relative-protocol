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
        public let emitFlowSlices: Bool
        public let flowSliceIntervalMs: Int
        public let emitFlowCloseEvents: Bool
        public let emitBurstShapeCounters: Bool
        public let activitySampleMinimumPackets: Int
        public let activitySampleMinimumBytes: Int
        public let activitySampleMinimumInterval: TimeInterval
        public let emitBurstEvents: Bool
        public let emitActivitySamples: Bool

        public init(
            allowDeepMetadata: Bool,
            maxMetadataProbesPerBatch: Int,
            emitFlowSlices: Bool,
            flowSliceIntervalMs: Int,
            emitFlowCloseEvents: Bool,
            emitBurstShapeCounters: Bool,
            activitySampleMinimumPackets: Int,
            activitySampleMinimumBytes: Int,
            activitySampleMinimumInterval: TimeInterval,
            emitBurstEvents: Bool,
            emitActivitySamples: Bool
        ) {
            self.allowDeepMetadata = allowDeepMetadata
            self.maxMetadataProbesPerBatch = max(0, maxMetadataProbesPerBatch)
            self.emitFlowSlices = emitFlowSlices
            self.flowSliceIntervalMs = max(50, flowSliceIntervalMs)
            self.emitFlowCloseEvents = emitFlowCloseEvents
            self.emitBurstShapeCounters = emitBurstShapeCounters
            self.activitySampleMinimumPackets = max(1, activitySampleMinimumPackets)
            self.activitySampleMinimumBytes = max(1, activitySampleMinimumBytes)
            self.activitySampleMinimumInterval = max(0, activitySampleMinimumInterval)
            self.emitBurstEvents = emitBurstEvents
            self.emitActivitySamples = emitActivitySamples
        }
    }

    private struct FlowRecordTemplate: Sendable {
        let protocolHint: String
        let ipVersion: UInt8
        let transportProtocolNumber: UInt8
        let sourcePort: UInt16?
        let destinationPort: UInt16?
        let flowHash: UInt64
        let sourceAddressLength: UInt8
        let sourceAddressHigh: UInt64
        let sourceAddressLow: UInt64
        let destinationAddressLength: UInt8
        let destinationAddressHigh: UInt64
        let destinationAddressLow: UInt64
    }

    private struct CounterSet: Sendable {
        var bytes = 0
        var packetCount = 0
        var largePacketCount = 0
        var smallPacketCount = 0
        var udpPacketCount = 0
        var tcpPacketCount = 0
        var quicInitialCount = 0
        var tcpSynCount = 0
        var tcpFinCount = 0
        var tcpRstCount = 0

        var isEmpty: Bool {
            packetCount == 0
        }

        mutating func record(summary: FastPacketSummary) {
            bytes += summary.packetLength
            packetCount += 1
            if summary.isLargePacketForDetectorStats {
                largePacketCount += 1
            }
            if summary.isSmallPacketForDetectorStats {
                smallPacketCount += 1
            }
            switch summary.transport {
            case .udp:
                udpPacketCount += 1
            case .tcp:
                tcpPacketCount += 1
            default:
                break
            }
            if summary.isQUICInitialCandidate {
                quicInitialCount += 1
            }
            if summary.hasTCPSYN {
                tcpSynCount += 1
            }
            if summary.hasTCPFIN {
                tcpFinCount += 1
            }
            if summary.hasTCPRST {
                tcpRstCount += 1
            }
        }

        mutating func reset() {
            self = CounterSet()
        }

        init() {}

        init(summary: FastPacketSummary) {
            self.init()
            record(summary: summary)
        }
    }

    private struct FlowSliceAccumulator: Sendable {
        var startedAt: Date?
        var counters = CounterSet()

        var isEmpty: Bool {
            counters.isEmpty
        }

        mutating func record(summary: FastPacketSummary, now: Date) {
            if startedAt == nil {
                startedAt = now
            }
            counters.record(summary: summary)
        }

        mutating func reset() {
            startedAt = nil
            counters.reset()
        }
    }

    private struct BurstAccumulator: Sendable {
        var startedAt: Date?
        var counters = CounterSet()
        var leadingBytes200ms = 0
        var leadingPackets200ms = 0
        var leadingBytes600ms = 0
        var leadingPackets600ms = 0

        var isEmpty: Bool {
            counters.isEmpty
        }

        mutating func record(summary: FastPacketSummary, now: Date) {
            if startedAt == nil {
                startedAt = now
            }
            counters.record(summary: summary)

            guard let startedAt else {
                return
            }

            let elapsed = now.timeIntervalSince(startedAt)
            if elapsed <= 0.2 {
                leadingBytes200ms += summary.packetLength
                leadingPackets200ms += 1
            }
            if elapsed <= 0.6 {
                leadingBytes600ms += summary.packetLength
                leadingPackets600ms += 1
            }
        }

        mutating func reset() {
            startedAt = nil
            counters.reset()
            leadingBytes200ms = 0
            leadingPackets200ms = 0
            leadingBytes600ms = 0
            leadingPackets600ms = 0
        }
    }

    private struct FlowContext: Sendable {
        let recordTemplate: FlowRecordTemplate
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
        var lastDirection: PacketDirection
        var hasEmittedFlowOpen = false
        var lastMetadataFingerprint: UInt64?
        var lastActivityEmissionAt: Date?
        var totalPacketCount = 0
        var totalByteCount = 0
        var activityCounters = CounterSet()
        var slice = FlowSliceAccumulator()
        var currentBurst = BurstAccumulator()
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
    /// Decision: the tunnel emits a sparse event stream (`flowOpen`, `flowSlice`, `flowClose`, `metadata`,
    /// `burst`, `activitySample`)
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
        var records: [PacketSampleStream.PacketStreamRecord] = []
        records.reserveCapacity(min(packets.count * 2, 128))
        records.append(contentsOf: maybeEvictExpiredFlowContexts(now: now, policy: policy))

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
            var context = flowContexts[flow] ?? makeFlowContext(for: summary, now: now, direction: direction)
            context.lastSeen = now
            context.lastDirection = direction

            if let burst = burstTracker.recordPacket(flow: flow, now: now) {
                if policy.emitBurstEvents, !context.currentBurst.isEmpty {
                    records.append(makeBurstRecord(timestamp: now, direction: direction, flowContext: context, burst: burst, policy: policy))
                }
                context.currentBurst.reset()
            }

            context.totalPacketCount += 1
            context.totalByteCount += summary.packetLength
            context.activityCounters.record(summary: summary)
            context.slice.record(summary: summary, now: now)
            context.currentBurst.record(summary: summary, now: now)

            mergeCheapMetadata(into: &context, summary: summary)

            if !context.hasEmittedFlowOpen {
                records.append(
                    makeRecord(
                        kind: .flowOpen,
                        timestamp: now,
                        direction: direction,
                        flowContext: context,
                        counters: CounterSet(summary: summary)
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
                                flowContext: context,
                                counters: CounterSet(summary: summary)
                            )
                        )
                    }
                }
            }

            if shouldEmitFlowSlice(context: context, now: now, policy: policy) {
                records.append(
                    makeRecord(
                        kind: .flowSlice,
                        timestamp: now,
                        direction: direction,
                        flowContext: context,
                        counters: context.slice.counters
                    )
                )
                context.slice.reset()
            }

            if shouldEmitActivitySample(context: context, now: now, policy: policy) {
                records.append(
                    makeRecord(
                        kind: .activitySample,
                        timestamp: now,
                        direction: direction,
                        flowContext: context,
                        counters: context.activityCounters
                    )
                )
                context.activityCounters.reset()
                context.lastActivityEmissionAt = now
            }

            if let closeReason = closeReason(for: summary) {
                records.append(
                    contentsOf: closeFlow(
                        flow: flow,
                        context: context,
                        timestamp: now,
                        direction: direction,
                        reason: closeReason,
                        policy: policy,
                        closingSummary: summary
                    )
                )
                continue
            }

            flowContexts[flow] = context
            if isNewFlow {
                flowContextArrivalQueue.append(flow)
            }
        }

        records.append(contentsOf: trimOverflowFlowContextsIfNeeded(policy: policy, now: now))
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

    private func makeFlowContext(for summary: FastPacketSummary, now: Date, direction: PacketDirection) -> FlowContext {
        FlowContext(
            recordTemplate: FlowRecordTemplate(
                protocolHint: summary.protocolHint,
                ipVersion: summary.ipVersion,
                transportProtocolNumber: summary.transportProtocolNumber,
                sourcePort: summary.hasPorts ? summary.sourcePort : nil,
                destinationPort: summary.hasPorts ? summary.destinationPort : nil,
                flowHash: summary.flowHash,
                sourceAddressLength: summary.sourceAddressLength,
                sourceAddressHigh: summary.sourceAddressHigh,
                sourceAddressLow: summary.sourceAddressLow,
                destinationAddressLength: summary.destinationAddressLength,
                destinationAddressHigh: summary.destinationAddressHigh,
                destinationAddressLow: summary.destinationAddressLow
            ),
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
            lastSeen: now,
            lastDirection: direction
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

        if context.activityCounters.packetCount >= policy.activitySampleMinimumPackets {
            return true
        }
        if context.activityCounters.bytes >= policy.activitySampleMinimumBytes {
            return true
        }
        if let lastActivityEmissionAt = context.lastActivityEmissionAt {
            return now.timeIntervalSince(lastActivityEmissionAt) >= policy.activitySampleMinimumInterval
        }
        return context.activityCounters.packetCount > 0 && policy.activitySampleMinimumInterval == 0
    }

    private func shouldEmitFlowSlice(context: FlowContext, now: Date, policy: EmissionPolicy) -> Bool {
        guard policy.emitFlowSlices, let startedAt = context.slice.startedAt else {
            return false
        }
        return now.timeIntervalSince(startedAt) * 1000 >= Double(policy.flowSliceIntervalMs)
    }

    private func closeReason(for summary: FastPacketSummary) -> FlowCloseReason? {
        if summary.hasTCPRST {
            return .tcpRst
        }
        if summary.hasTCPFIN {
            return .tcpFin
        }
        return nil
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

    private func makeBurstRecord(
        timestamp: Date,
        direction: PacketDirection,
        flowContext: FlowContext,
        burst: BurstSample,
        policy: EmissionPolicy
    ) -> PacketSampleStream.PacketStreamRecord {
        makeRecord(
            kind: .burst,
            timestamp: timestamp,
            direction: direction,
            flowContext: flowContext,
            counters: flowContext.currentBurst.counters,
            burstDurationMs: burst.burstDurationMs,
            burstPacketCount: burst.packetCount,
            leadingBytes200ms: policy.emitBurstShapeCounters ? flowContext.currentBurst.leadingBytes200ms : nil,
            leadingPackets200ms: policy.emitBurstShapeCounters ? flowContext.currentBurst.leadingPackets200ms : nil,
            leadingBytes600ms: policy.emitBurstShapeCounters ? flowContext.currentBurst.leadingBytes600ms : nil,
            leadingPackets600ms: policy.emitBurstShapeCounters ? flowContext.currentBurst.leadingPackets600ms : nil,
            burstLargePacketCount: policy.emitBurstShapeCounters ? flowContext.currentBurst.counters.largePacketCount : nil,
            burstUdpPacketCount: policy.emitBurstShapeCounters ? flowContext.currentBurst.counters.udpPacketCount : nil,
            burstTcpPacketCount: policy.emitBurstShapeCounters ? flowContext.currentBurst.counters.tcpPacketCount : nil,
            burstQuicInitialCount: policy.emitBurstShapeCounters ? flowContext.currentBurst.counters.quicInitialCount : nil
        )
    }

    private func makeRecord(
        kind: PacketSampleKind,
        timestamp: Date,
        direction: PacketDirection,
        flowContext: FlowContext,
        counters: CounterSet? = nil,
        closeReason: FlowCloseReason? = nil,
        burstDurationMs: Int? = nil,
        burstPacketCount: Int? = nil,
        leadingBytes200ms: Int? = nil,
        leadingPackets200ms: Int? = nil,
        leadingBytes600ms: Int? = nil,
        leadingPackets600ms: Int? = nil,
        burstLargePacketCount: Int? = nil,
        burstUdpPacketCount: Int? = nil,
        burstTcpPacketCount: Int? = nil,
        burstQuicInitialCount: Int? = nil
    ) -> PacketSampleStream.PacketStreamRecord {
        let counters = counters ?? CounterSet()
        let template = flowContext.recordTemplate
        return PacketSampleStream.PacketStreamRecord(
            kind: kind,
            timestamp: timestamp,
            direction: direction.rawValue,
            bytes: counters.bytes,
            packetCount: counters.isEmpty ? nil : counters.packetCount,
            flowPacketCount: flowContext.totalPacketCount,
            flowByteCount: flowContext.totalByteCount,
            protocolHint: template.protocolHint,
            ipVersion: template.ipVersion,
            transportProtocolNumber: template.transportProtocolNumber,
            sourcePort: template.sourcePort,
            destinationPort: template.destinationPort,
            flowHash: template.flowHash,
            textFlowId: nil,
            sourceAddressLength: template.sourceAddressLength,
            sourceAddressHigh: template.sourceAddressHigh,
            sourceAddressLow: template.sourceAddressLow,
            destinationAddressLength: template.destinationAddressLength,
            destinationAddressHigh: template.destinationAddressHigh,
            destinationAddressLow: template.destinationAddressLow,
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
            closeReason: closeReason,
            largePacketCount: counters.isEmpty ? nil : counters.largePacketCount,
            smallPacketCount: counters.isEmpty ? nil : counters.smallPacketCount,
            udpPacketCount: counters.isEmpty ? nil : counters.udpPacketCount,
            tcpPacketCount: counters.isEmpty ? nil : counters.tcpPacketCount,
            quicInitialCount: counters.isEmpty ? nil : counters.quicInitialCount,
            tcpSynCount: counters.isEmpty ? nil : counters.tcpSynCount,
            tcpFinCount: counters.isEmpty ? nil : counters.tcpFinCount,
            tcpRstCount: counters.isEmpty ? nil : counters.tcpRstCount,
            burstDurationMs: burstDurationMs,
            burstPacketCount: burstPacketCount,
            leadingBytes200ms: leadingBytes200ms,
            leadingPackets200ms: leadingPackets200ms,
            leadingBytes600ms: leadingBytes600ms,
            leadingPackets600ms: leadingPackets600ms,
            burstLargePacketCount: burstLargePacketCount,
            burstUdpPacketCount: burstUdpPacketCount,
            burstTcpPacketCount: burstTcpPacketCount,
            burstQuicInitialCount: burstQuicInitialCount
        )
    }

    /// Decision: flow-context cleanup is amortized because sweeping a large dictionary on every batch adds heat
    /// without improving detector quality.
    private func maybeEvictExpiredFlowContexts(now: Date, policy: EmissionPolicy) -> [PacketSampleStream.PacketStreamRecord] {
        if let lastFlowContextSweepAt,
           now.timeIntervalSince(lastFlowContextSweepAt) < FlowCachePolicy.evictionSweepIntervalSeconds,
           flowContexts.count < FlowCachePolicy.maxTrackedFlows {
            return []
        }

        lastFlowContextSweepAt = now
        let expiredFlows = flowContexts.compactMap { flow, context in
            now.timeIntervalSince(context.lastSeen) > FlowCachePolicy.flowTTLSeconds ? flow : nil
        }
        var records: [PacketSampleStream.PacketStreamRecord] = []
        for flow in expiredFlows {
            guard let context = flowContexts[flow] else {
                continue
            }
            records.append(contentsOf: closeFlow(flow: flow, context: context, timestamp: now, direction: context.lastDirection, reason: .idleEviction, policy: policy))
        }
        pruneFlowContextArrivalQueueIfNeeded(force: !expiredFlows.isEmpty)
        return records
    }

    private func trimOverflowFlowContextsIfNeeded(policy: EmissionPolicy, now: Date) -> [PacketSampleStream.PacketStreamRecord] {
        guard flowContexts.count > FlowCachePolicy.maxTrackedFlows else {
            return []
        }

        pruneFlowContextArrivalQueueIfNeeded(force: true)
        var records: [PacketSampleStream.PacketStreamRecord] = []

        while flowContexts.count > FlowCachePolicy.maxTrackedFlows {
            if let candidate = flowContextArrivalQueue.popFirst() {
                guard let context = flowContexts[candidate] else {
                    continue
                }
                records.append(contentsOf: closeFlow(flow: candidate, context: context, timestamp: now, direction: context.lastDirection, reason: .overflowEviction, policy: policy))
            } else if let fallback = flowContexts.keys.first {
                // Decision: this should stay cold because the arrival queue is the primary eviction path.
                // If the queue is unexpectedly empty, removing any active flow is cheaper than re-sorting the actor state.
                guard let context = flowContexts[fallback] else {
                    continue
                }
                records.append(contentsOf: closeFlow(flow: fallback, context: context, timestamp: now, direction: context.lastDirection, reason: .overflowEviction, policy: policy))
            } else {
                break
            }
        }

        pruneFlowContextArrivalQueueIfNeeded()
        return records
    }

    private func closeFlow(
        flow: FlowKey,
        context: FlowContext,
        timestamp: Date,
        direction: PacketDirection,
        reason: FlowCloseReason,
        policy: EmissionPolicy,
        closingSummary: FastPacketSummary? = nil
    ) -> [PacketSampleStream.PacketStreamRecord] {
        var records: [PacketSampleStream.PacketStreamRecord] = []
        if policy.emitFlowSlices, !context.slice.isEmpty {
            records.append(
                makeRecord(
                    kind: .flowSlice,
                    timestamp: timestamp,
                    direction: direction,
                    flowContext: context,
                    counters: context.slice.counters
                )
            )
        }
        if policy.emitFlowCloseEvents {
            let closingCounters = closingSummary.map(CounterSet.init(summary:)) ?? CounterSet()
            records.append(
                makeRecord(
                    kind: .flowClose,
                    timestamp: timestamp,
                    direction: direction,
                    flowContext: context,
                    counters: closingSummary == nil ? nil : closingCounters,
                    closeReason: reason
                )
            )
        }
        flowContexts.removeValue(forKey: flow)
        burstTracker.removeFlow(flow: flow)
        return records
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
