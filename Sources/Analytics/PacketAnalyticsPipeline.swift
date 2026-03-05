import Foundation
import Observability
import TunnelRuntime

/// Runtime analytics pipeline that parses packets, tracks flows/bursts, and emits bounded packet samples.
/// Actor ownership: all parsing side effects and rolling insight buffers are serialized here.
public actor PacketAnalyticsPipeline {
    private let clock: any Clock
    private let flowTracker: FlowTracker
    private let burstTracker: BurstTracker
    private let signatureClassifier: SignatureClassifier
    private let packetStream: PacketSampleStream?
    private let metricsStore: MetricsStore?
    private let logger: StructuredLogger

    private var recentInsights: MetricsRingBuffer<PacketInsight>

    /// - Parameters:
    ///   - clock: Time source used for deterministic timestamps.
    ///   - flowTracker: Bounded flow tracker for per-flow aggregation.
    ///   - burstTracker: Burst detector keyed by flow.
    ///   - signatureClassifier: Domain classifier for packet-level labeling.
    ///   - packetStream: Optional NDJSON packet sample stream sink.
    ///   - metricsStore: Optional metrics sink for aggregated counters.
    ///   - logger: Structured logger for analytics and storage errors.
    ///   - insightCapacity: Max in-memory retained packet insights.
    public init(
        clock: any Clock,
        flowTracker: FlowTracker,
        burstTracker: BurstTracker,
        signatureClassifier: SignatureClassifier,
        packetStream: PacketSampleStream?,
        metricsStore: MetricsStore?,
        logger: StructuredLogger,
        insightCapacity: Int = 1024
    ) {
        self.clock = clock
        self.flowTracker = flowTracker
        self.burstTracker = burstTracker
        self.signatureClassifier = signatureClassifier
        self.packetStream = packetStream
        self.metricsStore = metricsStore
        self.logger = logger
        self.recentInsights = MetricsRingBuffer(capacity: insightCapacity)
    }

    /// Ingests a packet batch and updates flow/burst/classification artifacts.
    /// - Parameters:
    ///   - packets: Raw packet payloads.
    ///   - families: Optional family hints aligned by packet index.
    ///   - direction: Packet direction relative to tunnel interface.
    public func ingest(packets: [Data], families: [Int32], direction: PacketDirection) async {
        guard !packets.isEmpty else {
            return
        }

        let now = await clock.now()
        var batchBytes = 0
        var parsedCount = 0

        for (index, packet) in packets.enumerated() {
            let familyHint: Int32? = families.indices.contains(index) ? families[index] : nil
            guard let metadata = PacketParser.parse(packet, ipVersionHint: familyHint) else {
                continue
            }

            parsedCount += 1
            batchBytes += metadata.length

            let flow = FlowKey(
                src: flowAddress(address: metadata.srcAddress, port: metadata.srcPort),
                dst: flowAddress(address: metadata.dstAddress, port: metadata.dstPort),
                proto: String(metadata.transport.rawValue)
            )
            await flowTracker.record(flow: flow, bytes: metadata.length, now: now)
            let burst = await burstTracker.recordPacket(flow: flow, now: now)

            let hostCandidate = metadata.tlsServerName
                ?? metadata.dnsCname
                ?? metadata.dnsQueryName
                ?? metadata.registrableDomain
            let classification = await signatureClassifier.classify(host: hostCandidate ?? "")

            let insight = PacketInsight(
                timestamp: now,
                direction: direction,
                metadata: metadata,
                classification: classification,
                burst: burst
            )
            recentInsights.append(insight)

            if let packetStream {
                do {
                    try await packetStream.append(
                        PacketSample(
                            timestamp: now,
                            direction: direction.rawValue,
                            flowId: flowId(flow),
                            bytes: metadata.length,
                            protocolHint: protocolHint(metadata)
                        )
                    )
                } catch {
                    await logger.log(
                        level: .warning,
                        phase: .storage,
                        category: .analyticsMetrics,
                        component: "PacketAnalyticsPipeline",
                        event: "packet-stream-write-failed",
                        errorCode: String(describing: error),
                        message: "Failed to append packet sample"
                    )
                }
            }

            if metadata.dnsQueryName != nil || metadata.dnsCname != nil || metadata.tlsServerName != nil {
                await logger.log(
                    level: .debug,
                    phase: metadata.dnsQueryName == nil && metadata.dnsCname == nil ? .analytics : .dns,
                    category: .analyticsClassifier,
                    component: "PacketAnalyticsPipeline",
                    event: "packet-insight",
                    flowId: flowId(flow),
                    message: "Parsed packet metadata",
                    metadata: insightMetadata(insight)
                )
            }
        }

        if let metricsStore {
            await metricsStore.append(
                MetricRecord(
                    name: direction == .outbound ? "packet.outbound.count" : "packet.inbound.count",
                    value: Double(parsedCount),
                    timestamp: now
                )
            )
            await metricsStore.append(
                MetricRecord(
                    name: direction == .outbound ? "packet.outbound.bytes" : "packet.inbound.bytes",
                    value: Double(batchBytes),
                    timestamp: now
                )
            )
        }
    }

    /// Returns current in-memory packet insight snapshot.
    public func latestInsights() -> [PacketInsight] {
        recentInsights.snapshot()
    }

    private func flowAddress(address: IPAddress, port: UInt16?) -> String {
        if let port {
            return "\(address.stringValue):\(port)"
        }
        return address.stringValue
    }

    private func flowId(_ flow: FlowKey) -> String {
        let input = "\(flow.src)|\(flow.dst)|\(flow.proto)"
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in input.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }

        let hex = String(hash, radix: 16, uppercase: false)
        if hex.count >= 16 {
            return hex
        }
        return String(repeating: "0", count: 16 - hex.count) + hex
    }

    private func protocolHint(_ metadata: PacketMetadata) -> String {
        switch metadata.transport {
        case .tcp:
            return "tcp"
        case .udp:
            return "udp"
        default:
            return "ip"
        }
    }

    private func insightMetadata(_ insight: PacketInsight) -> [String: String] {
        var metadata: [String: String] = [
            "ip_version": String(insight.metadata.ipVersion.rawValue),
            "transport": String(insight.metadata.transport.rawValue),
            "length": String(insight.metadata.length)
        ]
        if let dns = insight.metadata.dnsQueryName {
            metadata["dns_query"] = dns
        }
        if let cname = insight.metadata.dnsCname {
            metadata["dns_cname"] = cname
        }
        if let sni = insight.metadata.tlsServerName {
            metadata["tls_sni"] = sni
        }
        if let quicVersion = insight.metadata.quicVersion {
            metadata["quic_version"] = String(quicVersion)
        }
        if let quicType = insight.metadata.quicPacketType {
            metadata["quic_packet_type"] = quicType.rawValue
        }
        if let classification = insight.classification {
            metadata["classification"] = classification
        }
        if let burst = insight.burst {
            metadata["burst_duration_ms"] = String(burst.burstDurationMs)
            metadata["burst_packet_count"] = String(burst.packetCount)
        }
        return metadata
    }
}
