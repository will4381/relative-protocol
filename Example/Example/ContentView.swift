// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import SwiftUI
@preconcurrency import NetworkExtension

struct ContentView: View {
    @EnvironmentObject private var vpnManager: VPNManager
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                headerSection
                actionSection
                dnsSection
                stressSection
                summarySection
                detectionsSection
                packetStreamSection
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
        .background(Color(.systemBackground))
        .task {
            await vpnManager.refreshStatus()
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            Task { await vpnManager.refreshStatus() }
        }
    }

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("VPN Bridge")
                .font(.largeTitle.weight(.semibold))

            Text("Simple on-device tunnel tester.")
                .font(.body)
                .foregroundStyle(.secondary)

            Text(statusTitle)
                .font(.title3.weight(.medium))
                .foregroundStyle(statusColor)

            if vpnManager.isBusy {
                Text("Updating VPN configuration...")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            if vpnManager.hasProfile && !vpnManager.isEnabled {
                Text("The VPN profile is installed but disabled in Settings.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            if vpnManager.profileDiagnostics.requiresAttention {
                Text("Installed VPN manager does not cleanly match the desired profile.")
                    .font(.subheadline)
                    .foregroundStyle(.orange)
            }

            if let lastError = vpnManager.lastError, !lastError.isEmpty {
                Text(lastError)
                    .font(.subheadline)
                    .foregroundStyle(.red)
            }
        }
    }

    private var actionSection: some View {
        VStack(spacing: 12) {
            Button(primaryActionTitle) {
                if vpnManager.isConnected {
                    vpnManager.disconnect()
                } else {
                    Task { await vpnManager.connect() }
                }
            }
            .buttonStyle(FlatFillButtonStyle(fill: primaryButtonColor, foreground: .white))
            .disabled(vpnManager.isBusy)

            Button("Refresh") {
                Task { await vpnManager.refreshStatus() }
            }
            .buttonStyle(FlatFillButtonStyle(fill: Color(.secondarySystemBackground), foreground: .primary))
            .disabled(vpnManager.isBusy)

            Button("Clear Local Data") {
                Task { await vpnManager.clearLocalData() }
            }
            .buttonStyle(FlatFillButtonStyle(fill: Color(.secondarySystemBackground), foreground: .primary))
            .disabled(vpnManager.isBusy)
        }
    }

    private var dnsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("DNS Policy")
                .font(.headline)

            Picker("DNS mode", selection: $vpnManager.dnsMode) {
                ForEach(ExampleDNSMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.menu)
            .disabled(!vpnManager.canEditDNSMode)

            SummaryRow(label: "Mode", value: vpnManager.dnsModeDisplayText)
            SummaryRow(label: "Effective DNS", value: vpnManager.effectiveDNSDisplayText)
            SummaryRow(label: "System DNS visible", value: vpnManager.currentPathSupportsDNSText)
            SummaryRow(label: "Current path", value: vpnManager.currentPathSummary)
        }
    }

    private var stressSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Stress Matrix")
                .font(.headline)

            Button(vpnManager.stressReport.isRunning ? "Running Stress Matrix" : "Run Stress Matrix") {
                vpnManager.startStressMatrix()
            }
            .buttonStyle(FlatFillButtonStyle(fill: .purple, foreground: .white))
            .disabled(vpnManager.isBusy || vpnManager.stressReport.isRunning)

            if vpnManager.stressReport.isRunning {
                Button("Cancel Stress Matrix") {
                    vpnManager.cancelStressMatrix()
                }
                .buttonStyle(FlatFillButtonStyle(fill: Color(.secondarySystemBackground), foreground: .primary))
            }

            SummaryRow(label: "Stress", value: vpnManager.stressReport.summaryText)
            SummaryRow(label: "DNS mode", value: vpnManager.stressReport.dnsMode)
            SummaryRow(label: "Effective DNS", value: vpnManager.stressReport.effectiveDNS)
            SummaryRow(label: "Start path", value: vpnManager.stressReport.pathSummary)
            if let activeScenario = vpnManager.stressReport.activeScenario {
                SummaryRow(label: "Active", value: activeScenario)
            }
            SummaryRow(label: "Probes", value: "\(vpnManager.stressReport.totalProbes)")
            SummaryRow(label: "Failures", value: "\(vpnManager.stressReport.failedProbes)")
            if vpnManager.stressReport.blockedProbes > 0 {
                SummaryRow(label: "Blocked", value: "\(vpnManager.stressReport.blockedProbes)")
            }
            if let savedReportPath = vpnManager.stressReport.savedReportPath {
                SummaryRow(label: "Report", value: savedReportPath)
            }

            ForEach(vpnManager.stressReport.rows) { row in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(row.name)
                            .font(.body.weight(.medium))
                        Spacer(minLength: 8)
                        Text(row.statusText)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(row.blocked ? .orange : (row.passed ? .green : .red))
                    }

                    Text("\(row.condition) · \(row.probeCount) probes · \(row.durationMs)ms")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)

                    if !row.detail.isEmpty {
                        Text(row.detail)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                Divider()
            }
        }
    }

    private var summarySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Overview")
                .font(.headline)

            SummaryRow(label: "Profile", value: vpnManager.hasProfile ? "Installed" : "Not installed")
            SummaryRow(label: "Config match", value: vpnManager.profileDiagnostics.statusText)
            SummaryRow(label: "Managers", value: vpnManager.profileDiagnostics.managerCountText)
            SummaryRow(label: "Desired config", value: vpnManager.profileDiagnostics.desiredSummary)
            SummaryRow(label: "Installed config", value: vpnManager.profileDiagnostics.installedSummary)
            if let note = vpnManager.profileDiagnostics.note {
                SummaryRow(label: "Profile note", value: note)
            }
            SummaryRow(label: "Last stop", value: vpnManager.lastStopDisplayText)
            SummaryRow(label: "Recent events", value: "\(vpnManager.trafficSummary.recentEventCount)")
            SummaryRow(label: "Inspected events", value: "\(vpnManager.trafficSummary.inspectedEventCount)")
            SummaryRow(label: "Events shown", value: "\(vpnManager.packetRows.count)")
            if let thermalState = vpnManager.trafficSummary.thermalState {
                SummaryRow(label: "Thermal", value: thermalState.capitalized)
            }
            SummaryRow(label: "Total detections", value: "\(vpnManager.trafficSummary.totalDetectionCount)")
            SummaryRow(label: "TikTok CDN", value: "\(vpnManager.trafficSummary.tikTokCDNCount)")
            SummaryRow(label: "Instagram CDN", value: "\(vpnManager.trafficSummary.instagramCDNCount)")
            SummaryRow(label: "Flow opens", value: "\(vpnManager.trafficSummary.flowOpenCount)")
            SummaryRow(label: "Flow slices", value: "\(vpnManager.trafficSummary.flowSliceCount)")
            SummaryRow(label: "Flow closes", value: "\(vpnManager.trafficSummary.flowCloseCount)")
            SummaryRow(label: "Metadata", value: "\(vpnManager.trafficSummary.metadataCount)")
            SummaryRow(label: "Bursts", value: "\(vpnManager.trafficSummary.burstCount)")
            SummaryRow(label: "Activity samples", value: "\(vpnManager.trafficSummary.activitySampleCount)")
            SummaryRow(label: "Host hints", value: "\(vpnManager.trafficSummary.hostHintCount)")
            SummaryRow(label: "DNS answers", value: "\(vpnManager.trafficSummary.dnsAnswerCount)")
            SummaryRow(label: "DNS associated", value: "\(vpnManager.trafficSummary.dnsAssociationCount)")
            SummaryRow(label: "Lineage stamped", value: "\(vpnManager.trafficSummary.lineageCount)")
            SummaryRow(label: "Path stamped", value: "\(vpnManager.trafficSummary.pathRegimeCount)")
            SummaryRow(label: "Service attributed", value: "\(vpnManager.trafficSummary.serviceAttributionCount)")
            SummaryRow(label: "QUIC identity", value: "\(vpnManager.trafficSummary.quicIdentityCount)")
            if let lastFlowCloseReason = vpnManager.trafficSummary.lastFlowCloseReason {
                SummaryRow(label: "Last close", value: lastFlowCloseReason)
            }
            if let lastAssociatedDomain = vpnManager.trafficSummary.lastAssociatedDomain {
                SummaryRow(label: "Last association", value: lastAssociatedDomain)
            }
            if let lastServiceFamily = vpnManager.trafficSummary.lastServiceFamily {
                SummaryRow(label: "Last service", value: lastServiceFamily)
            }
            if let lastPathRegime = vpnManager.trafficSummary.lastPathRegime {
                SummaryRow(label: "Last path", value: lastPathRegime)
            }
            SummaryRow(label: "Telemetry batches accepted", value: "\(vpnManager.trafficSummary.acceptedTelemetryBatches)")
            SummaryRow(label: "Telemetry batches shed", value: "\(vpnManager.trafficSummary.droppedBatches)")
            SummaryRow(label: "Telemetry batches skipped", value: "\(vpnManager.trafficSummary.skippedBatches)")
            SummaryRow(label: "Telemetry shed rate", value: vpnManager.trafficSummary.shedRateText)

            if let updatedAt = vpnManager.trafficSummary.updatedAt {
                SummaryRow(
                    label: "Updated",
                    value: updatedAt.formatted(.dateTime.hour().minute().second())
                )
            }
        }
    }

    private var detectionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Detected Events")
                .font(.headline)

            if vpnManager.detectionRows.isEmpty {
                Text("No persisted detections yet.")
                    .font(.body)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(vpnManager.detectionRows.enumerated()), id: \.element.id) { index, row in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(row.title)
                            .font(.body.weight(.medium))

                        Text(row.subtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)

                        if let detail = row.detail {
                            Text(detail)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }

                    if index < vpnManager.detectionRows.count - 1 {
                        Divider()
                    }
                }
            }
        }
    }

    private var packetStreamSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Live Tap")
                .font(.headline)

            if vpnManager.packetRows.isEmpty {
                Text(vpnManager.isConnected ? "Waiting for live tunnel events..." : "No live tunnel events available.")
                    .font(.body)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(vpnManager.packetRows.enumerated()), id: \.element.id) { index, row in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(row.title)
                            .font(.body.weight(.medium))

                        Text(row.subtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)

                        if let detail = row.detail {
                            Text(detail)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }

                    if index < vpnManager.packetRows.count - 1 {
                        Divider()
                    }
                }
            }
        }
    }

    private var statusTitle: String {
        switch vpnManager.status {
        case .connected:
            return "Connected"
        case .connecting:
            return "Connecting"
        case .disconnected:
            return "Disconnected"
        case .disconnecting:
            return "Disconnecting"
        case .reasserting:
            return "Reasserting"
        case .invalid:
            return "Not Configured"
        @unknown default:
            return "Unknown"
        }
    }

    private var statusColor: Color {
        switch vpnManager.status {
        case .connected:
            return .green
        case .connecting, .reasserting:
            return .orange
        case .invalid:
            return .red
        default:
            return .secondary
        }
    }

    private var primaryActionTitle: String {
        vpnManager.isConnected ? "Disconnect" : "Connect"
    }

    private var primaryButtonColor: Color {
        vpnManager.isConnected ? .red : .blue
    }

}

private struct SummaryRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Spacer(minLength: 8)

            Text(value)
                .font(.subheadline)
                .multilineTextAlignment(.trailing)
        }
    }
}

private struct FlatFillButtonStyle: ButtonStyle {
    let fill: Color
    let foreground: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.medium))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .foregroundStyle(foreground)
            .background(configuration.isPressed ? fill.opacity(0.85) : fill)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}
