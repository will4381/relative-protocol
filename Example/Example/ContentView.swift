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

@MainActor
struct ContentView: View {
    @StateObject private var vpn = VPNManager.shared

    var body: some View {
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

            Spacer()
        }
        .padding(.top, 24)
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
