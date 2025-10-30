//
//  ContentView.swift
//  Example
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/23/2025.
//
//  Displays tunnel status, metrics, and controls in the sample host app UI.
//

import SwiftUI
import OSLog
import NetworkExtension
import RelativeProtocolCore

private let trafficDateFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .none
    formatter.timeStyle = .medium
    return formatter
}()

private let byteFormatter: ByteCountFormatter = {
    let formatter = ByteCountFormatter()
    formatter.allowedUnits = [.useKB, .useMB, .useGB]
    formatter.countStyle = .decimal
    formatter.includesUnit = true
    return formatter
}()

@MainActor
struct ContentView: View {
    @StateObject private var vpn = VPNManager.shared
    @State private var newRulePattern = ""

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Text("Relative Protocol – Example")
                    .font(.title3)
                    .bold()

                Text(vpn.status.displayTitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                if let error = vpn.lastErrorMessage {
                    Text(error)
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
                .disabled(vpn.isBusy || !vpn.configurationReady)
                .padding(.horizontal)

                Button("Probe Network") {
                    Task { await vpn.probe() }
                }
                .disabled(vpn.isBusy)

                Button("Probe HTTPS") {
                    Task { await vpn.probeHTTP() }
                }
                .disabled(vpn.isBusy)

                VStack(alignment: .leading, spacing: 16) {
                    Text("Global Traffic Shaping")
                        .font(.headline)

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Added latency")
                            .font(.subheadline)
                        Slider(
                            value: Binding(
                                get: { vpn.shapingConfiguration.defaultLatencyMs },
                                set: { vpn.setDefaultLatency($0) }
                            ),
                            in: 0...500,
                            step: 10
                        )
                        HStack {
                            Text("0 ms")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("500 ms")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text("\(Int(vpn.shapingConfiguration.defaultLatencyMs)) ms added to all traffic")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Bandwidth ceiling")
                            .font(.subheadline)
                        Slider(
                            value: Binding(
                                get: { vpn.shapingConfiguration.defaultBandwidthKbps },
                                set: { vpn.setDefaultBandwidth($0) }
                            ),
                            in: 0...4096,
                            step: 64
                        )
                        HStack {
                            Text("Unlimited")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("4 Mbps")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text(defaultBandwidthDescription)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal)

                VStack(alignment: .leading, spacing: 12) {
                    Text("Per-Domain Overrides")
                        .font(.headline)

                    HStack(spacing: 12) {
                        TextField("Domain or wildcard (e.g. *.example.com)", text: $newRulePattern)
                            .textFieldStyle(.roundedBorder)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)
                        Button("Add") {
                            vpn.addRule(pattern: newRulePattern)
                            newRulePattern = ""
                        }
                        .disabled(newRulePattern.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }

                    if vpn.shapingConfiguration.rules.isEmpty {
                        Text("Add wildcard or host-specific rules to override the global profile.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(vpn.shapingConfiguration.rules) { rule in
                                VStack(alignment: .leading, spacing: 8) {
                                    TextField(
                                        "Pattern",
                                        text: Binding(
                                            get: { rule.pattern },
                                            set: { vpn.setRulePattern($0, for: rule.id) }
                                        )
                                    )
                                    .textFieldStyle(.roundedBorder)
                                    .textInputAutocapitalization(.never)
                                    .disableAutocorrection(true)

                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("Latency")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                        Slider(
                                            value: Binding(
                                                get: { rule.latencyMs },
                                                set: { vpn.setRuleLatency($0, for: rule.id) }
                                            ),
                                            in: 0...500,
                                            step: 10
                                        )
                                        Text("\(Int(rule.latencyMs)) ms added")
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }

                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("Bandwidth")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                        Slider(
                                            value: Binding(
                                                get: { rule.bandwidthKbps },
                                                set: { vpn.setRuleBandwidth($0, for: rule.id) }
                                            ),
                                            in: 0...4096,
                                            step: 64
                                        )
                                        Text(perRuleBandwidthDescription(rule.bandwidthKbps))
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }

                                    Button(role: .destructive) {
                                        vpn.removeRule(id: rule.id)
                                    } label: {
                                        Label("Remove Rule", systemImage: "trash")
                                            .font(.caption)
                                    }
                                    .buttonStyle(.borderless)
                                }
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.gray.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                            }
                        }
                    }
                }
                .padding(.horizontal)

                if let probe = vpn.lastProbeResult {
                    Text("Probe: \(probe)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal)
                }

                if let http = vpn.lastHTTPProbeResult {
                    Text("HTTPS Probe: \(http)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("How it works")
                        .font(.headline)
                    Text("This app installs a personal VPN configuration using Apple’s Network Extension (Packet Tunnel). Traffic is routed into a virtual interface and bridged by Relative Protocol. You will be prompted once to allow VPN control.")
                    Text("Sources are local to this repo; no external servers are required for this demo.")
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding()

                Divider()

                VStack(alignment: .leading, spacing: 16) {
                    Text("Observed Sites")
                        .font(.headline)

                    HStack(spacing: 12) {
                        Button {
                            Task { await vpn.fetchSites() }
                        } label: {
                            HStack {
                                if vpn.isFetchingSites {
                                    ProgressView()
                                        .progressViewStyle(.circular)
                                        .tint(.accentColor)
                                } else {
                                    Image(systemName: "arrow.clockwise")
                                }
                                Text("Fetch Sites")
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(vpn.isFetchingSites || !vpn.status.isActive)

                        Button("Clear Sites") {
                            Task { await vpn.clearSites() }
                        }
                        .buttonStyle(.bordered)
                        .disabled(!vpn.status.isActive)
                    }

                    if let controlError = vpn.lastControlError {
                        Text(controlError)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }

                    if vpn.siteSummaries.isEmpty {
                        Text("No sites observed yet. Connect the tunnel and fetch to view recent activity.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    } else {
                        Text("Unique sites tracked: \(vpn.totalObservedSites)")
                            .font(.footnote)
                            .foregroundStyle(.secondary)

                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(vpn.siteSummaries) { summary in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(summary.displayName)
                                        .font(.subheadline)
                                        .bold()
                                    Text("Last seen: \(trafficDateFormatter.string(from: summary.lastSeen))")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    if let host = summary.host, host != summary.displayName {
                                        Text("Host: \(host)")
                                            .font(.caption)
                                            .foregroundStyle(.primary)
                                    }
                                    Text("Remote IP: \(summary.remoteIP)")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    let inbound = byteFormatter.string(fromByteCount: Int64(summary.inboundBytes))
                                    let outbound = byteFormatter.string(fromByteCount: Int64(summary.outboundBytes))
                                    Text("Inbound \(inbound) · Outbound \(outbound)")
                                        .font(.caption)
                                        .foregroundStyle(.primary)
                                    Text("Packets in/out: \(summary.inboundPackets)/\(summary.outboundPackets)")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    if summary.firstSeen < summary.lastSeen {
                                        Text("First seen: \(trafficDateFormatter.string(from: summary.firstSeen))")
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.gray.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                            }
                        }
                    }
                }
                .padding()

                Spacer()
            }
            .padding(.top, 24)
        }
        .task { await vpn.prepare() }
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

    private var defaultBandwidthDescription: String {
        let kbps = vpn.shapingConfiguration.defaultBandwidthKbps
        if kbps <= 0 {
            return "Unlimited throughput"
        }
        if kbps >= 1000 {
            return String(format: "%.1f Mbps ceiling", kbps / 1000.0)
        }
        return "\(Int(kbps)) Kbps ceiling"
    }

    private func perRuleBandwidthDescription(_ kbps: Double) -> String {
        if kbps <= 0 {
            return "Unlimited throughput"
        }
        if kbps >= 1000 {
            return String(format: "%.1f Mbps ceiling", kbps / 1000.0)
        }
        return "\(Int(kbps)) Kbps ceiling"
    }
}

#Preview { ContentView() }
