import SwiftUI
import NetworkExtension
import RelativeProtocolCore

@MainActor
struct ContentView: View {
    @StateObject private var vpn = VPNManager.shared
    @State private var rulePattern = "example.com"
    @State private var actionSelection: RuleActionSelection = .block
    @State private var latencyMs: Double = 300
    @State private var jitterMs: Double = 50

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                headerSection
                hostRuleSection
                dnsSection
                telemetrySection
            }
            .padding()
            .frame(maxWidth: .infinity)
        }
        .task { await vpn.prepare() }
    }

    private var headerSection: some View {
        VStack(spacing: 16) {
            Text("Relative Protocol – Example")
                .font(.title2)
                .bold()

            Text(vpn.status.displayTitle)
                .font(.headline)
                .foregroundStyle(.secondary)

            if let message = vpn.lastErrorMessage {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            Button(action: toggle) {
                HStack {
                    if vpn.isBusy { ProgressView().tint(.white) }
                    Text(vpn.status.isActive ? "Disconnect" : "Connect")
                        .bold()
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .disabled(vpn.isBusy || (!vpn.configurationReady && !vpn.status.isActive))
        }
        .frame(maxWidth: .infinity)
    }

    private var hostRuleSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Host Rules")
                .font(.headline)
            VStack(spacing: 12) {
                TextField("Pattern (e.g. *.example.com or 23.215.0.138)", text: $rulePattern)
                    .textFieldStyle(.roundedBorder)
                Picker("Action", selection: $actionSelection) {
                    Text("Block").tag(RuleActionSelection.block)
                    Text("Shape").tag(RuleActionSelection.shape)
                }
                .pickerStyle(.segmented)
                if actionSelection == .shape {
                    VStack {
                        HStack {
                            Text("Latency: \(Int(latencyMs)) ms")
                            Spacer()
                        }
                        Slider(value: $latencyMs, in: 50...1000, step: 50)
                    }
                    VStack {
                        HStack {
                            Text("Jitter: \(Int(jitterMs)) ms")
                            Spacer()
                        }
                        Slider(value: $jitterMs, in: 0...500, step: 25)
                    }
                }
                Button("Install Rule") {
                    Task {
                        let action = actionSelection.action(latency: UInt32(latencyMs), jitter: UInt32(jitterMs))
                        await vpn.installHostRule(pattern: rulePattern, action: action)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(vpn.isBusy || !vpn.status.isActive)
            }
            .padding()
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))

            if vpn.hostRules.isEmpty {
                Text("No host rules installed.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(vpn.hostRules) { rule in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(rule.pattern)
                                .font(.subheadline)
                                .bold()
                            Text(rule.action.description)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(role: .destructive) {
                            Task { await vpn.removeHostRule(rule) }
                        } label: {
                            Image(systemName: "trash")
                        }
                        .disabled(vpn.isBusy)
                    }
                    .padding(.vertical, 4)
                    Divider()
                }
                .padding(.vertical, -4)
            }
        }
        .padding()
        .background(Color(uiColor: .secondarySystemBackground), in: RoundedRectangle(cornerRadius: 16))
    }

    private var dnsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("DNS Activity")
                    .font(.headline)
                Spacer()
                Button("Refresh") {
                    Task { await vpn.refreshDnsHistory() }
                }
                .disabled(!vpn.status.isActive || vpn.isBusy)
            }

            if vpn.dnsHistory.isEmpty {
                Text(vpn.status.isActive ? "Waiting for DNS requests…" : "Connect to start capturing DNS activity.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(vpn.dnsHistory.reversed()) { record in
                    DNSRow(observation: record)
                        .padding(.vertical, 6)
                    Divider()
                }
                .padding(.vertical, -6)
            }
        }
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14))
    }

    private var telemetrySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Telemetry")
                    .font(.headline)
                Spacer()
                Button("Pull Packets") {
                    Task { await vpn.drainTelemetry() }
                }
                .disabled(!vpn.status.isActive || vpn.isBusy)
            }

            if vpn.telemetryEvents.isEmpty {
                Text("Drain telemetry to view packet records.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(vpn.telemetryEvents.reversed()) { event in
                    TelemetryRow(event: event)
                        .padding(.vertical, 6)
                    Divider()
                }
                .padding(.vertical, -6)
            }
        }
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14))
    }

    private func toggle() {
        Task { @MainActor in
            if vpn.status.isActive {
                await vpn.disconnect()
            } else {
                await vpn.connect()
            }
        }
    }
}

private struct DNSRow: View {
    let observation: DNSObservation
    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.timeStyle = .medium
        formatter.dateStyle = .none
        return formatter
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(observation.host)
                .font(.subheadline)
                .bold()
            Text(observation.addresses.joined(separator: ", "))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
            HStack(spacing: 12) {
                Label("TTL \(observation.ttlSeconds)s", systemImage: "clock")
                    .font(.caption2)
                Label(Self.formatter.string(from: observation.observedAt), systemImage: "calendar")
                    .font(.caption2)
            }
            .foregroundStyle(.secondary)
        }
    }
}

#Preview { ContentView() }

private enum RuleActionSelection {
    case block
    case shape

    func action(latency: UInt32, jitter: UInt32) -> HostRuleConfiguration.Action {
        switch self {
        case .block:
            return .block
        case .shape:
            return .shape(latencyMs: latency, jitterMs: jitter)
        }
    }
}

private extension HostRuleConfiguration.Action {
    var description: String {
        switch self {
        case .block:
            return "Block"
        case .shape(let latencyMs, let jitterMs):
            return "Shape (\(latencyMs)ms ±\(jitterMs)ms)"
        }
    }
}

private struct TelemetryRow: View {
    let event: TelemetryEvent
    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.timeStyle = .medium
        formatter.dateStyle = .none
        return formatter
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(Self.formatter.string(from: event.timestamp))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(event.direction == .clientToNetwork ? "↗︎" : "↘︎")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text("\(event.source) → \(event.destination)")
                .font(.caption)
            if let dns = event.dnsQuery {
                Text("DNS: \(dns)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 8) {
                Label("Proto \(event.protocolNumber)", systemImage: "point.topleft.down.curvedto.point.bottomright.up")
                Label("\(event.payloadLength) bytes", systemImage: "arrow.up.arrow.down")
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
            HStack(spacing: 8) {
                if event.flags.contains(.policyBlock) {
                    label(text: "Blocked", color: .red)
                }
                if event.flags.contains(.policyShape) {
                    label(text: "Shaped", color: .orange)
                }
                if event.flags.contains(.dns) {
                    label(text: "DNS", color: .blue)
                }
            }
        }
    }

    private func label(text: String, color: Color) -> some View {
        Text(text.uppercased())
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}
