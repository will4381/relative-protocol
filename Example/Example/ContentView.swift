import SwiftUI
import NetworkExtension
import RelativeProtocolCore

@MainActor
struct ContentView: View {
    @StateObject private var vpn = VPNManager.shared

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                headerSection
            }
            .padding()
            .frame(maxWidth: .infinity)
        }
        .task { await vpn.prepare() }
    }

    private var headerSection: some View {
        VStack(spacing: 16) {
            Text("Relative Protocol")
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
