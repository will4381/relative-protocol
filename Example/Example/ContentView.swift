//
//  ContentView.swift
//  Example
//
//  Created by Will Kusch on 10/23/25.
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
}

#Preview { ContentView() }
