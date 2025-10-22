//
//  ContentView.swift
//  VPN Bridge
//
//  Created by Will Kusch on 10/21/25.
//

import SwiftUI
@preconcurrency import NetworkExtension

struct ContentView: View {
    @StateObject private var viewModel = TunnelViewModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 28) {
                VStack(spacing: 8) {
                    Image(systemName: viewModel.status == .connected ? "lock.shield" : "lock.slash" )
                        .font(.system(size: 52, weight: .semibold))
                        .foregroundStyle(viewModel.status == .connected ? .green : .secondary)
                    Text(viewModel.statusDescription)
                        .font(.title2.weight(.semibold))
                        .multilineTextAlignment(.center)
                }

                if let message = viewModel.errorMessage {
                    Text(message)
                        .font(.subheadline)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Button {
                    Task { await viewModel.toggleTunnel() }
                } label: {
                    Text(viewModel.primaryButtonTitle)
                        .frame(maxWidth: .infinity)
                        .padding()
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isActionDisabled)

                if viewModel.isBusy {
                    ProgressView()
                        .progressViewStyle(.circular)
                }

                Spacer()

                VStack(spacing: 6) {
                    Text("This bridge runs entirely on-device. Keep the app installed so the tunnel can reconnect in the background.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Button("Reinstall Configuration") {
                        Task { await viewModel.reinstallConfiguration() }
                    }
                    .font(.footnote.weight(.semibold))
                    .disabled(viewModel.isActionDisabled)
                }
            }
            .padding()
            .navigationTitle("VPN Bridge")
        }
    }
}

#Preview {
    ContentView()
}
