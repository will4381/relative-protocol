import Combine
import Darwin
import RelativeProtocolCore
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

@MainActor
final class DiagnosticsViewModel: ObservableObject {
    @Published var items: [DiagnosticItem]
    @Published var isRunning = false
    @Published var lastRun: Date?

    private let checks: [DiagnosticCheck]

    init() {
        self.checks = DiagnosticsViewModel.makeChecks()
        self.items = checks.map {
            DiagnosticItem(name: $0.name, detail: $0.detail, status: .pending)
        }
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
        let suiteName = "diagnostics.metrics.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            return .failed("UserDefaults suite unavailable.")
        }
        defaults.removePersistentDomain(forName: suiteName)

        let store = MetricsStore(appGroupID: suiteName, maxSnapshots: 2, maxBytes: 10_000)
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
        let suiteName = "diagnostics.metrics.large.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            return .failed("UserDefaults suite unavailable.")
        }
        defaults.removePersistentDomain(forName: suiteName)

        let store = MetricsStore(appGroupID: suiteName, maxSnapshots: 5, maxBytes: 256)
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
            srcPort: 12000,
            dstPort: 53,
            dnsQueryName: nil
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
            srcPort: 53,
            dstPort: 53000,
            dnsQueryName: dnsName
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
            dnsQueryName: nil
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
        }
        .navigationTitle("Diagnostics")
        .onAppear {
            if model.lastRun == nil && model.items.allSatisfy({ $0.status == .pending }) {
                model.runAll()
            }
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
}
