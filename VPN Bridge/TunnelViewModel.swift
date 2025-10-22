//
//  TunnelViewModel.swift
//  VPN Bridge
//
//  Hosts the NETunnelProviderManager wiring so the SwiftUI shell
//  can install, connect, and disconnect the PacketTunnel extension.
//

import Foundation
@preconcurrency import NetworkExtension
import Combine
import os.log

@MainActor
final class TunnelViewModel: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var isBusy = false
    @Published var isReady = false
    @Published var errorMessage: String?

    private let logger = Logger(subsystem: "VPN Bridge", category: "TunnelViewModel")
    private let providerBundleIdentifier = "relative-companies.VPN-Bridge.PacketTunnel"
    private var manager: NETunnelProviderManager?
    private var statusObservation: NSObjectProtocol?

    init() {
        Task { await bootstrapManager() }
    }

    deinit {
        if let statusObservation {
            NotificationCenter.default.removeObserver(statusObservation)
        }
    }

    var statusDescription: String {
        switch status {
        case .invalid:
            return "Not Configured"
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting…"
        case .connected:
            return "Connected"
        case .reasserting:
            return "Reconnecting…"
        case .disconnecting:
            return "Disconnecting…"
        @unknown default:
            return "Unknown"
        }
    }

    var primaryButtonTitle: String {
        switch status {
        case .connected, .connecting, .reasserting:
            return "Disconnect"
        default:
            return "Connect"
        }
    }

    var isActionDisabled: Bool {
        !isReady || isBusy
    }

    func toggleTunnel() async {
        guard let manager else {
            logger.error("toggleTunnel called before manager was ready")
            return
        }
        isBusy = true
        errorMessage = nil
        do {
            try await manager.loadFromPreferencesAsync()
            switch manager.connection.status {
            case .connected, .connecting, .reasserting:
                logger.notice("Stopping tunnel on user request")
                manager.connection.stopVPNTunnel()
            default:
                logger.notice("Starting tunnel on user request")
                try manager.connection.startVPNTunnel()
            }
        } catch {
            logger.error("Failed to toggle tunnel: \(error, privacy: .public)")
            errorMessage = prettyError(error)
        }
        status = manager.connection.status
        isBusy = false
    }

    func reinstallConfiguration() async {
        guard let manager else { return }
        isBusy = true
        errorMessage = nil
        do {
            logger.notice("Re-saving tunnel configuration")
            manager.isEnabled = true
            try await manager.saveToPreferencesAsync()
            try await manager.loadFromPreferencesAsync()
            status = manager.connection.status
        } catch {
            logger.error("Failed to save tunnel preferences: \(error, privacy: .public)")
            errorMessage = prettyError(error)
        }
        isBusy = false
    }

    private func bootstrapManager() async {
        isBusy = true
        errorMessage = nil
        do {
            let manager = try await loadOrCreateManager()
            observeStatus(for: manager)
            self.manager = manager
            status = manager.connection.status
            isReady = true
        } catch {
            logger.error("Failed to prepare tunnel manager: \(error, privacy: .public)")
            errorMessage = prettyError(error)
        }
        isBusy = false
    }

    private func loadOrCreateManager() async throws -> NETunnelProviderManager {
        let managers = try await Self.loadManagers()
        if let existing = managers.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleIdentifier }) {
            logger.debug("Loaded existing tunnel manager")
            try await existing.loadFromPreferencesAsync()
            existing.localizedDescription = "VPN Bridge"
            if !existing.isEnabled {
                existing.isEnabled = true
                try await existing.saveToPreferencesAsync()
                try await existing.loadFromPreferencesAsync()
            }
            return existing
        }

        logger.notice("Creating a fresh tunnel manager configuration")
        let manager = NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerBundleIdentifier
        configuration.serverAddress = "127.0.0.1"
        configuration.providerConfiguration = [:]
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "VPN Bridge"
        manager.isEnabled = true

        try await manager.saveToPreferencesAsync()
        try await manager.loadFromPreferencesAsync()
        return manager
    }

    private func observeStatus(for manager: NETunnelProviderManager) {
        if let statusObservation {
            NotificationCenter.default.removeObserver(statusObservation)
        }
        statusObservation = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            Task { [weak self] in
                await self?.handleStatusDidChange()
            }
        }
    }

    @MainActor
    private func handleStatusDidChange() {
        let newStatus = manager?.connection.status ?? status
        status = newStatus
        logger.debug("Tunnel status changed: \(newStatus.rawValue, privacy: .public)")
    }

    private func prettyError(_ error: Error) -> String {
        if let vpnError = error as? NEVPNError {
            return describe(vpnError.code)
        }
        let nsError = error as NSError
        if nsError.domain == NEVPNErrorDomain,
           let code = NEVPNError.Code(rawValue: nsError.code) {
            return describe(code)
        }
        return error.localizedDescription
    }

    private func describe(_ code: NEVPNError.Code) -> String {
        switch code {
        case .configurationInvalid:
            return "The tunnel configuration is invalid."
        case .configurationDisabled:
            return "The tunnel configuration is disabled."
        case .connectionFailed:
            return "The system refused to start the tunnel."
        case .configurationStale:
            return "The tunnel configuration is out of date. Try reinstalling."
        case .configurationReadWriteFailed:
            return "Could not save the VPN configuration. Check your provisioning profile."
        case .configurationUnknown:
            fallthrough
        @unknown default:
            return "An unknown Network Extension error occurred."
        }
    }

    private static func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }
}

private extension NETunnelProviderManager {
    func saveToPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    func loadFromPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}
