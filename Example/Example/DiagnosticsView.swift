// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Combine
import Darwin
import RelativeProtocolCore
import RelativeProtocolHost
import SwiftUI

enum DiagnosticStatus: Equatable {
    case pending
    case passed
    case failed(String)
}

struct DiagnosticItem: Identifiable, Equatable {
    let id = UUID()
    let name: String
    let detail: String
    var status: DiagnosticStatus
}

struct DiagnosticCheck {
    let name: String
    let detail: String
    let run: () -> DiagnosticStatus
}

struct PacketStreamDiagnostics: Equatable {
    let appGroupID: String
    let containerURL: URL?
    let streamURL: URL?
    let fileExists: Bool
    let fileSizeBytes: Int?
    let usesAppGroupContainer: Bool
}

@MainActor
final class DiagnosticsViewModel: ObservableObject {
    @Published var items: [DiagnosticItem]
    @Published var isRunning = false
    @Published var lastRun: Date?
    @Published var recentSamples: [PacketSample] = []
    @Published var lastStreamUpdate: Date?
    @Published var streamDiagnostics: PacketStreamDiagnostics
    @Published var streamSampleCount: Int = 0

    private let checks: [DiagnosticCheck]
    private let packetStreamClient: PacketStreamClient

    private static let appGroupID = "group.relative-companies.Example"

    init() {
        self.packetStreamClient = PacketStreamClient(appGroupID: Self.appGroupID)
        self.checks = DiagnosticsViewModel.makeChecks()
        self.items = checks.map {
            DiagnosticItem(name: $0.name, detail: $0.detail, status: .pending)
        }
        self.streamDiagnostics = DiagnosticsViewModel.makeStreamDiagnostics()
    }

    func runAll() {
        guard !isRunning else { return }
        isRunning = true
        lastRun = nil
        items = items.map { DiagnosticItem(name: $0.name, detail: $0.detail, status: .pending) }

        Task {
            for index in checks.indices {
                let result = checks[index].run()
                await MainActor.run {
                    items[index].status = result
                }
            }
            await MainActor.run {
                isRunning = false
                lastRun = Date()
            }
        }
    }

    func refreshPacketStream() {
        let samples = packetStreamClient.readAll()
        streamSampleCount = samples.count
        recentSamples = Array(samples.suffix(10)).reversed()
        lastStreamUpdate = Date()
        streamDiagnostics = DiagnosticsViewModel.makeStreamDiagnostics()
    }

    static func makeStreamDiagnostics() -> PacketStreamDiagnostics {
        let fileManager = FileManager.default
        let containerURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
        let streamURL = PacketSampleStreamLocation.makeURL(appGroupID: appGroupID)
        let fileExists = streamURL.map { fileManager.fileExists(atPath: $0.path) } ?? false
        let fileSize: Int?
        if let streamURL, fileExists,
           let size = try? fileManager.attributesOfItem(atPath: streamURL.path)[.size] as? NSNumber {
            fileSize = size.intValue
        } else {
            fileSize = nil
        }
        let usesAppGroupContainer = containerURL != nil
        return PacketStreamDiagnostics(
            appGroupID: appGroupID,
            containerURL: containerURL,
            streamURL: streamURL,
            fileExists: fileExists,
            fileSizeBytes: fileSize,
            usesAppGroupContainer: usesAppGroupContainer
        )
    }

    private static func makeChecks() -> [DiagnosticCheck] {
        [
            DiagnosticCheck(
                name: "Ring buffer snapshot limit",
                detail: "Ensures the ring buffer returns the most recent samples.",
                run: DiagnosticsViewModel.checkRingBufferLimit
            ),
            DiagnosticCheck(
                name: "Flow tracker burst/TTL",
                detail: "Verifies burst advancement and flow expiration.",
                run: DiagnosticsViewModel.checkFlowTracker
            ),
            DiagnosticCheck(
                name: "Packet parser DNS",
                detail: "Parses an IPv4 UDP DNS query payload.",
                run: DiagnosticsViewModel.checkPacketParser
            ),
            DiagnosticCheck(
                name: "Metrics store cap",
                detail: "Evicts snapshots beyond maxSnapshots/maxBytes.",
                run: DiagnosticsViewModel.checkMetricsStoreCap
            ),
            DiagnosticCheck(
                name: "Metrics store oversized snapshot",
                detail: "Rejects snapshots exceeding maxBytes.",
                run: DiagnosticsViewModel.checkMetricsStoreOversized
            )
        ]
    }

    private static func checkRingBufferLimit() -> DiagnosticStatus {
        let buffer = MetricsRingBuffer(capacity: 5)
        (1...5).forEach { buffer.append(makeSample(id: UInt64($0))) }
        let snapshot = buffer.snapshot(limit: 2)
        guard snapshot.count == 2 else {
            return .failed("Expected 2 samples, got \(snapshot.count).")
        }
        guard snapshot.first?.flowId == 4, snapshot.last?.flowId == 5 else {
            return .failed("Expected flowIds 4 and 5.")
        }
        return .passed
    }

    private static func checkFlowTracker() -> DiagnosticStatus {
        let tracker = FlowTracker(configuration: FlowTrackerConfiguration(
            burstThreshold: 0.1,
            flowTTL: 0.5,
            maxTrackedFlows: 8
        ))
        let metadata = makeMetadata()
        let first = tracker.record(metadata: metadata, timestamp: 1.0)
        let second = tracker.record(metadata: metadata, timestamp: 1.15)
        let third = tracker.record(metadata: metadata, timestamp: 2.0)

        guard first.flowId == second.flowId else {
            return .failed("Flow id changed too early.")
        }
        guard first.burstId == 0, second.burstId == 1 else {
            return .failed("Burst did not advance.")
        }
        guard third.flowId != second.flowId else {
            return .failed("Flow did not expire after TTL.")
        }
        return .passed
    }

    private static func checkPacketParser() -> DiagnosticStatus {
        let payload = makeDNSQueryPayload(hostname: "example.com")
        let packet = makeIPv4UDPPacket(
            src: [10, 0, 0, 2],
            dst: [1, 1, 1, 1],
            srcPort: 5353,
            dstPort: 53,
            payload: payload
        )
        let metadata = PacketParser.parse(packet, ipVersionHint: AF_INET)
        guard metadata?.ipVersion == .v4, metadata?.transport == .udp else {
            return .failed("Expected IPv4 UDP metadata.")
        }
        guard metadata?.dnsQueryName == "example.com" else {
            return .failed("DNS query name mismatch.")
        }
        return .passed
    }

    private static func checkMetricsStoreCap() -> DiagnosticStatus {
        let appGroupID = "diagnostics.metrics.\(UUID().uuidString)"
        let store = MetricsStore(appGroupID: appGroupID, maxSnapshots: 2, maxBytes: 10_000)
        store.clear()
        store.append(makeSnapshot(id: 1))
        store.append(makeSnapshot(id: 2))
        store.append(makeSnapshot(id: 3))

        let loaded = store.load()
        guard loaded.count == 2 else {
            return .failed("Expected 2 snapshots, got \(loaded.count).")
        }
        guard loaded.first?.samples.first?.flowId == 2,
              loaded.last?.samples.first?.flowId == 3 else {
            return .failed("Expected snapshots 2 and 3.")
        }
        return .passed
    }

    private static func checkMetricsStoreOversized() -> DiagnosticStatus {
        let appGroupID = "diagnostics.metrics.large.\(UUID().uuidString)"
        let store = MetricsStore(appGroupID: appGroupID, maxSnapshots: 5, maxBytes: 256)
        store.clear()
        store.append(makeSnapshot(id: 1, dnsNameLength: 512))

        guard store.load().isEmpty else {
            return .failed("Oversized snapshot should be rejected.")
        }
        return .passed
    }

    private static func makeSample(id: UInt64) -> PacketSample {
        PacketSample(
            timestamp: 1,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 64,
            flowId: id,
            burstId: 0,
            srcAddress: "192.0.2.1",
            dstAddress: "198.51.100.1",
            srcPort: 12000,
            dstPort: 53,
            dnsQueryName: nil,
            dnsCname: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
    }

    private static func makeSnapshot(id: UInt64, dnsNameLength: Int = 0) -> MetricsSnapshot {
        let dnsName = dnsNameLength > 0 ? String(repeating: "a", count: dnsNameLength) : nil
        let sample = PacketSample(
            timestamp: 1,
            direction: .inbound,
            ipVersion: .v4,
            transport: .udp,
            length: 120,
            flowId: id,
            burstId: 0,
            srcAddress: "192.0.2.53",
            dstAddress: "198.51.100.2",
            srcPort: 53,
            dstPort: 53000,
            dnsQueryName: dnsName,
            dnsCname: nil,
            registrableDomain: dnsName,
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
        return MetricsSnapshot(capturedAt: 1, samples: [sample])
    }

    private static func makeMetadata() -> PacketMetadata {
        let src = IPAddress(bytes: Data([192, 168, 1, 2]))!
        let dst = IPAddress(bytes: Data([8, 8, 8, 8]))!
        return PacketMetadata(
            ipVersion: .v4,
            transport: .udp,
            srcAddress: src,
            dstAddress: dst,
            srcPort: 12000,
            dstPort: 53,
            length: 60,
            dnsQueryName: nil,
            dnsCname: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
    }

    private static func makeIPv4UDPPacket(src: [UInt8], dst: [UInt8], srcPort: UInt16, dstPort: UInt16, payload: [UInt8]) -> Data {
        var packet: [UInt8] = []
        let totalLength = 20 + 8 + payload.count
        packet.append(0x45)
        packet.append(0x00)
        packet.append(UInt8((totalLength >> 8) & 0xFF))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(64)
        packet.append(17)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: src)
        packet.append(contentsOf: dst)

        packet.append(UInt8((srcPort >> 8) & 0xFF))
        packet.append(UInt8(srcPort & 0xFF))
        packet.append(UInt8((dstPort >> 8) & 0xFF))
        packet.append(UInt8(dstPort & 0xFF))
        let udpLength = 8 + payload.count
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(0x00)
        packet.append(0x00)
        packet.append(contentsOf: payload)
        return Data(packet)
    }

    private static func makeDNSQueryPayload(hostname: String) -> [UInt8] {
        var payload: [UInt8] = []
        payload.append(0x12)
        payload.append(0x34)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)

        let labels = hostname.split(separator: ".")
        for label in labels {
            payload.append(UInt8(label.count))
            payload.append(contentsOf: label.utf8)
        }
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x01)
        payload.append(0x00)
        payload.append(0x01)
        return payload
    }
}

struct DiagnosticsView: View {
    @StateObject private var model = DiagnosticsViewModel()

    var body: some View {
        List {
            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Diagnostics")
                            .font(.headline)
                        Text("Run non-invasive checks for core packet processing logic.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                if let lastRun = model.lastRun {
                    Text("Last run: \(lastRun.formatted(.dateTime.hour().minute().second()))")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Button(model.isRunning ? "Running..." : "Run diagnostics") {
                    model.runAll()
                }
                .disabled(model.isRunning)
            }

            Section("Checks") {
                ForEach(model.items) { item in
                    HStack(alignment: .top, spacing: 12) {
                        Circle()
                            .fill(statusColor(for: item.status))
                            .frame(width: 10, height: 10)
                            .padding(.top, 6)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.name)
                                .font(.body)
                            Text(item.detail)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            if case .failed(let message) = item.status {
                                Text(message)
                                    .font(.footnote)
                                    .foregroundStyle(.red)
                            }
                        }
                        Spacer()
                        Text(statusLabel(for: item.status))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }

            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Packet Stream")
                            .font(.headline)
                        Text("Most recent packet samples from the tunnel stream.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        if let lastUpdate = model.lastStreamUpdate {
                            Text("Last refresh: \(lastUpdate.formatted(.dateTime.hour().minute().second()))")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Button("Refresh") {
                        model.refreshPacketStream()
                    }
                    .buttonStyle(.borderless)
                }

                packetStreamDiagnosticsView(model.streamDiagnostics)

                if model.recentSamples.isEmpty {
                    Text("No packet samples available yet.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(model.recentSamples.enumerated()), id: \.offset) { _, sample in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(packetHeadline(sample))
                                .font(.subheadline)
                                .monospaced()
                            Text(packetDetail(sample))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if let dnsLine = packetDNSLine(sample) {
                                Text(dnsLine)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            if let classificationLine = packetClassificationLine(sample) {
                                Text(classificationLine)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            if let burstLine = packetBurstLine(sample) {
                                Text(burstLine)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            if let tlsLine = packetTLSLine(sample) {
                                Text(tlsLine)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            if let quicLine = packetQuicLine(sample) {
                                Text(quicLine)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
        }
        .navigationTitle("Diagnostics")
        .onAppear {
            if model.lastRun == nil && model.items.allSatisfy({ $0.status == .pending }) {
                model.runAll()
            }
            model.refreshPacketStream()
        }
    }

    private func statusColor(for status: DiagnosticStatus) -> Color {
        switch status {
        case .pending:
            return .gray.opacity(0.4)
        case .passed:
            return .green
        case .failed:
            return .red
        }
    }

    private func statusLabel(for status: DiagnosticStatus) -> String {
        switch status {
        case .pending:
            return "Pending"
        case .passed:
            return "Passed"
        case .failed:
            return "Failed"
        }
    }

    private func packetHeadline(_ sample: PacketSample) -> String {
        let timestamp = Date(timeIntervalSince1970: sample.timestamp)
            .formatted(.dateTime.hour().minute().second())
        return "\(timestamp)  \(directionLabel(sample.direction)) \(ipVersionLabel(sample.ipVersion))/\(transportLabel(sample.transport))  \(sample.length)B"
    }

    private func packetDetail(_ sample: PacketSample) -> String {
        let srcPort = sample.srcPort.map(String.init) ?? "-"
        let dstPort = sample.dstPort.map(String.init) ?? "-"
        let srcAddress = sample.srcAddress ?? "-"
        let dstAddress = sample.dstAddress ?? "-"
        return "Flow \(sample.flowId)  Burst \(sample.burstId)  \(srcAddress):\(srcPort) → \(dstAddress):\(dstPort)"
    }

    private func packetDNSLine(_ sample: PacketSample) -> String? {
        let parts = [
            sample.dnsQueryName.map { "Query: \($0)" },
            sample.dnsCname.map { "CNAME: \($0)" },
            sample.dnsAnswerAddresses
                .flatMap { $0.isEmpty ? nil : $0 }
                .map { "Answers: \($0.joined(separator: ", "))" },
            sample.registrableDomain.map { "Domain: \($0)" }
        ].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: "  ")
    }

    private func packetClassificationLine(_ sample: PacketSample) -> String? {
        guard let classification = sample.trafficClassification else { return nil }
        let label = classification.label ?? "unknown"
        let domain = classification.domain ?? "-"
        let cdn = classification.cdn ?? "-"
        let asn = classification.asn ?? "-"
        let confidence = String(format: "%.2f", classification.confidence)
        let reasons = classification.reasons.isEmpty ? "-" : classification.reasons.joined(separator: ",")
        return "Guess: \(label) domain=\(domain) cdn=\(cdn) asn=\(asn) conf=\(confidence) reasons=\(reasons)"
    }

    private func packetBurstLine(_ sample: PacketSample) -> String? {
        guard let burst = sample.burstMetrics else { return nil }
        let pps = String(format: "%.1f", burst.packetsPerSecond)
        let bps = String(format: "%.0f", burst.bytesPerSecond)
        return "Burst: \(burst.packetCount)pkt \(burst.byteCount)B \(burst.durationMs)ms \(pps)p/s \(bps)B/s"
    }

    private func packetTLSLine(_ sample: PacketSample) -> String? {
        guard let serverName = sample.tlsServerName else { return nil }
        return "TLS SNI: \(serverName)"
    }

    private func packetQuicLine(_ sample: PacketSample) -> String? {
        let hasQuic = sample.quicVersion != nil ||
            sample.quicDestinationConnectionId != nil ||
            sample.quicSourceConnectionId != nil
        guard hasQuic else { return nil }
        let version = sample.quicVersion.map { String(format: "0x%08X", $0) }
        let dcid = sample.quicDestinationConnectionId
        let scid = sample.quicSourceConnectionId
        let parts = [
            version.map { "QUIC v\($0)" },
            dcid.map { "DCID: \($0)" },
            scid.map { "SCID: \($0)" }
        ].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: "  ")
    }

    private func directionLabel(_ direction: PacketDirection) -> String {
        switch direction {
        case .inbound:
            return "IN"
        case .outbound:
            return "OUT"
        }
    }

    private func ipVersionLabel(_ version: IPVersion) -> String {
        switch version {
        case .v4:
            return "IPv4"
        case .v6:
            return "IPv6"
        }
    }

    private func transportLabel(_ transport: TransportProtocol) -> String {
        if transport == .tcp {
            return "TCP"
        }
        if transport == .udp {
            return "UDP"
        }
        if transport == .icmp {
            return "ICMP"
        }
        if transport == .icmpv6 {
            return "ICMPv6"
        }
        return "P\(transport.rawValue)"
    }

    @ViewBuilder
    private func packetStreamDiagnosticsView(_ info: PacketStreamDiagnostics) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("App Group: \(info.appGroupID)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Decoded samples: \(model.streamSampleCount)")
                .font(.caption)
                .foregroundStyle(.secondary)
            if info.usesAppGroupContainer {
                Text("App group container: available")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("App group container: unavailable (entitlement missing at runtime)")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if let streamURL = info.streamURL {
                Text("Stream path: \(streamURL.path)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                Text("Stream path: unavailable")
                    .font(.caption2)
                    .foregroundStyle(.red)
            }
            if info.fileExists {
                if let size = info.fileSizeBytes {
                    Text("Stream size: \(size) bytes")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                } else {
                    Text("Stream size: unknown")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("Stream file: not found")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
