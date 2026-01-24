// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import SwiftUI
@preconcurrency import NetworkExtension

struct ContentView: View {
    @EnvironmentObject private var vpnManager: VPNManager
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("pre_use_disclosure_accepted") private var hasAcceptedDisclosure = false
    @State private var showDisclosure = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                if vpnManager.hasProfile && !vpnManager.isEnabled {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("VPN profile is disabled in Settings.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Button("Re-enable VPN") {
                            Task { await vpnManager.enable() }
                        }
                        .buttonStyle(.bordered)
                    }
                }

                HStack(spacing: 12) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 12, height: 12)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("VPN Status")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(statusText)
                            .font(.headline)
                    }
                }

                if vpnManager.isBusy {
                    ProgressView("Updating VPN profile...")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                if let lastError = vpnManager.lastError, !lastError.isEmpty {
                    Text("Last error: \(lastError)")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }

                HStack(spacing: 12) {
                    Button(action: handlePrimaryAction) {
                        Text(primaryActionTitle)
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(vpnManager.isBusy)

                    Button(action: vpnManager.disconnect) {
                        Text("Disconnect")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .disabled(vpnManager.isBusy || !vpnManager.isConnected)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("Metrics")
                        .font(.headline)
                    Text("Metrics are stored on device only. You can delete them at any time.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if let summary = vpnManager.metricsSummary {
                        Text("Latest snapshot: \(summary.capturedAt.formatted(.dateTime.hour().minute().second()))")
                            .font(.footnote)
                        Text("Samples: \(summary.totalSamples) (in \(summary.inboundSamples), out \(summary.outboundSamples))")
                            .font(.footnote)
                        Text("DNS samples: \(summary.dnsSamples)")
                            .font(.footnote)
                        Text("Snapshots stored: \(vpnManager.metricsSnapshotCount)")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("No metrics captured yet.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Button("Refresh metrics") {
                        vpnManager.refreshMetrics()
                    }
                    .buttonStyle(.bordered)
                    Button("Clear local metrics") {
                        vpnManager.clearMetrics()
                    }
                    .buttonStyle(.bordered)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("VPN Bridge")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink("Diagnostics") {
                        DiagnosticsView()
                    }
                }
            }
        }
        .sheet(isPresented: $showDisclosure) {
            PreUseDisclosureView(
                onContinue: {
                    hasAcceptedDisclosure = true
                    showDisclosure = false
                    Task {
                        await vpnManager.bootstrapProfile()
                        await vpnManager.connect()
                    }
                },
                onCancel: {
                    showDisclosure = false
                }
            )
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            Task { await vpnManager.refreshStatus() }
        }
        .task {
            guard hasAcceptedDisclosure else { return }
            await vpnManager.bootstrapProfile()
        }
    }

    private var statusText: String {
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
            return "Not configured"
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
        case .disconnected, .disconnecting:
            return .gray
        case .invalid:
            return .red
        @unknown default:
            return .gray
        }
    }

    private var primaryActionTitle: String {
        vpnManager.isConnected ? "Reconnect" : "Connect"
    }

    private func handlePrimaryAction() {
        if hasAcceptedDisclosure {
            Task {
                if !vpnManager.isEnabled {
                    await vpnManager.enable()
                }
                await vpnManager.connect()
            }
        } else {
            showDisclosure = true
        }
    }
}

private struct PreUseDisclosureView: View {
    let onContinue: () -> Void
    let onCancel: () -> Void

    @State private var showPrivacyPolicy = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Before you connect")
                        .font(.title2)
                        .fontWeight(.semibold)

                    Text(disclosureBody)
                        .font(.body)

                    Button("Privacy Policy") {
                        showPrivacyPolicy = true
                    }
                    .font(.body)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            .navigationTitle("Disclosure")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Not now", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue", action: onContinue)
                }
            }
        }
        .sheet(isPresented: $showPrivacyPolicy) {
            PrivacyPolicyView()
        }
    }

    private var disclosureBody: String {
        "To provide swipe metrics, the VPN processes traffic metadata on this device only. We do not inspect content, store payloads, or sell or share VPN-derived data. You can turn off the VPN and delete local metrics at any time."
    }
}

private struct PrivacyPolicyView: View {
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Privacy Policy")
                        .font(.title2)
                        .fontWeight(.semibold)

                    Text(policySummary)
                        .font(.body)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            .navigationTitle("Privacy Policy")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var policySummary: String {
        """
        We process VPN traffic metadata on device only to compute swipe metrics. We do not inspect content, store payloads, or sell or share VPN-derived data. We do not operate servers for VPN traffic or analytics.

        We store packet counts, sizes, timestamps, direction, flow id, and burst boundaries locally in a bounded ring buffer. You can delete local metrics at any time. Logs are off by default and user controlled.
        """
    }
}
