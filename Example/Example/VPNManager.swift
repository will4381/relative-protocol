import Combine
import Foundation
import NetworkExtension
import RelativeProtocolCore
import RelativeProtocolHost

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published private(set) var status: VPNDisplayStatus = .disconnected
    @Published private(set) var isBusy = false
    @Published private(set) var configurationReady = false
    @Published private(set) var lastErrorMessage: String?

    private let controller = RelativeVPNController.shared
    private var statusObserver: NSObjectProtocol?

    private init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.updateStatusFromController()
            }
        }

        updateStatusFromController()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func prepare() async {
        guard !configurationReady else {
            print("[VPNManager] prepare() called but already configured")
            return
        }
        print("[VPNManager] prepare() starting...")
        isBusy = true
        lastErrorMessage = nil
        do {
            try await controller.loadConfiguration()
            print("[VPNManager] loadConfiguration completed, isConfigured=\(controller.isConfigured)")

            // If no configuration exists, create one
            if !controller.isConfigured {
                print("[VPNManager] No configuration found, creating new one...")
                // IMPORTANT: This bundle ID must match your tunnel extension's PRODUCT_BUNDLE_IDENTIFIER
                // Found in Example.xcodeproj: relative-companies.Example.Example-Tunnel
                let settings = TunnelNetworkSettings(
                    tunnelAddress: "10.0.0.2",
                    subnetMask: "255.255.255.0",
                    tunnelRemoteAddress: "10.0.0.1",
                    mtu: 1280,
                    dns: DNSConfiguration(servers: ["1.1.1.1", "8.8.8.8"]),
                    includeAllNetworks: true,
                    providerBundleIdentifier: "relative-companies.Example.Example-Tunnel"
                )
                try await controller.saveConfiguration(settings: settings)
                print("[VPNManager] saveConfiguration completed")
            }

            configurationReady = true
            print("[VPNManager] prepare() completed successfully, configurationReady=true")
        } catch {
            lastErrorMessage = "Prepare failed: \(error.localizedDescription)"
        }
        isBusy = false
        updateStatusFromController()
    }

    func connect() async {
        guard configurationReady else {
            lastErrorMessage = "Call prepare() before connecting"
            return
        }
        isBusy = true
        lastErrorMessage = nil
        do {
            print("[VPNManager] Calling controller.connect()...")
            try await controller.connect()
            print("[VPNManager] connect() returned successfully, waiting for status change...")
            // Don't set isBusy = false immediately - wait for status to change to connecting/connected
            // The NEVPNStatusDidChange notification will update the status
        } catch {
            print("[VPNManager] connect() threw error: \(error)")
            lastErrorMessage = error.localizedDescription
            isBusy = false
        }
        updateStatusFromController()
    }

    func disconnect() async {
        controller.disconnect()
        updateStatusFromController()
    }

    private func updateStatusFromController() {
        let newStatus = VPNDisplayStatus(controller.status)
        print("[VPNManager] Status update: \(status) -> \(newStatus)")
        status = newStatus

        // Clear busy state when we reach a stable state
        if newStatus == .connected || newStatus == .disconnected || newStatus == .invalid {
            isBusy = false
        }
    }
}

enum VPNDisplayStatus {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case invalid

    init(_ status: VPNStatus) {
        switch status {
        case .connected: self = .connected
        case .connecting: self = .connecting
        case .disconnecting: self = .disconnecting
        case .disconnected: self = .disconnected
        case .invalid: self = .invalid
        }
    }

    var isActive: Bool {
        if case .connected = self { return true }
        return false
    }

    var displayTitle: String {
        switch self {
        case .connected: return "Connected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .disconnected: return "Disconnected"
        case .invalid: return "Unavailable"
        }
    }
}
