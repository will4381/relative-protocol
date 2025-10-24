//
//  VPNManager.swift
//  Example
//
//  Created by Codex on 10/23/25.
//

import Foundation
import Combine
import OSLog
@preconcurrency import NetworkExtension
import RelativeProtocolCore

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var isBusy = false
    @Published private(set) var configurationReady = false
    @Published private(set) var lastErrorMessage: String?
    @Published private(set) var lastProbeResult: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private let logger = Logger(subsystem: "relative.example", category: "VPNManager")

    private init() { }

    deinit {
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
    }

    func prepare() async {
        guard !configurationReady else { return }
        await loadManagerIfNeeded()
    }

    func connect() async {
        guard await ensureManager(), let manager else { return }

        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            logger.debug("Connect ignored; status=\(manager.connection.status.displayTitle)")
            return
        default: break
        }

        isBusy = true
        defer { isBusy = false }

        do {
            try await Self.loadPreferences(for: manager)
            guard let session = manager.connection as? NETunnelProviderSession else {
                throw VPNManagerError.unexpectedConnection
            }
            try session.startVPNTunnel()
            lastErrorMessage = nil
        } catch {
            logger.error("startVPNTunnel failed: \(error.localizedDescription, privacy: .public)")
            lastErrorMessage = error.localizedDescription
            refreshStatus()
        }
    }

    func disconnect() async {
        guard await ensureManager(), let manager else { return }
        switch manager.connection.status {
        case .disconnected, .disconnecting, .invalid:
            logger.debug("Disconnect ignored; status=\(manager.connection.status.displayTitle)")
            return
        default: break
        }
        isBusy = true
        defer { isBusy = false }
        manager.connection.stopVPNTunnel()
        refreshStatus()
    }

    func probe() async {
        guard await ensureManager(), let manager else { return }
        lastProbeResult = "Running…"
        do {
            try await Self.loadPreferences(for: manager)
            guard let session = manager.connection as? NETunnelProviderSession else {
                lastProbeResult = "error: no session"
                return
            }
            try session.sendProviderMessage(Data("probe".utf8)) { [weak self] response in
                Task { @MainActor in
                    if let response, let text = String(data: response, encoding: .utf8) {
                        self?.lastProbeResult = text
                    } else {
                        self?.lastProbeResult = "no response"
                    }
                }
            }
        } catch {
            lastProbeResult = "error: \(error.localizedDescription)"
        }
    }

    // MARK: - Private

    private func ensureManager() async -> Bool {
        if manager != nil { return true }
        await loadManagerIfNeeded()
        return manager != nil
    }

    private func loadManagerIfNeeded() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let managers = try await Self.loadManagers()
            let activeManager: NETunnelProviderManager
            if let existing = managers.first {
                activeManager = existing
                try await Self.loadPreferences(for: activeManager)
            } else {
                activeManager = NETunnelProviderManager()
            }

            if activeManager.protocolConfiguration == nil {
                let proto = NETunnelProviderProtocol()
                // Must match Example Tunnel’s bundle id from project.pbxproj
                proto.providerBundleIdentifier = "relative-companies.Example.Example-Tunnel"
                proto.serverAddress = "RelativeProtocol"

                // Provide Relative Protocol configuration for the extension
                let configuration = makeRelativeProtocolConfiguration()
                _ = try? configuration.validateOrThrow()
                proto.providerConfiguration = configuration.providerConfigurationDictionary()

                proto.includeAllNetworks = true
                proto.excludeLocalNetworks = false
                proto.disconnectOnSleep = false

                activeManager.protocolConfiguration = proto
                activeManager.localizedDescription = "Relative Protocol Example"
                activeManager.isEnabled = true

                try await Self.save(activeManager)
                try await Self.loadPreferences(for: activeManager)
            } else if activeManager.isEnabled == false {
                activeManager.isEnabled = true
                try await Self.save(activeManager)
                try await Self.loadPreferences(for: activeManager)
            }

            manager = activeManager
            configurationReady = true
            lastErrorMessage = nil

            observeStatus(for: activeManager)
            refreshStatus()
        } catch {
            logger.error("Failed to load NETunnelProviderManager: \(error.localizedDescription, privacy: .public)")
            lastErrorMessage = error.localizedDescription
        }
    }

    private func observeStatus(for manager: NETunnelProviderManager) {
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in self?.refreshStatus() }
        }
        status = manager.connection.status
    }

    private func refreshStatus() {
        guard let manager else { status = .invalid; return }
        status = manager.connection.status
    }

    private func makeRelativeProtocolConfiguration() -> RelativeProtocol.Configuration {
        RelativeProtocol.Configuration(
            provider: .init(
                mtu: 1500,
                ipv4: .init(
                    address: "10.0.0.2",
                    subnetMask: "255.255.255.0",
                    remoteAddress: "10.0.0.1"
                ),
                dns: .init(servers: ["1.1.1.1", "8.8.8.8"]),
                metrics: .init(isEnabled: true, reportingInterval: 1.0),
                policies: .init(blockedHosts: [])
            ),
            hooks: .init(),
            logging: .init(enableDebug: true)
        )
    }
}

// MARK: - Helpers

private extension VPNManager {
    enum VPNManagerError: Error { case unexpectedConnection }

    static func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error { c.resume(throwing: error) }
                else { c.resume(returning: managers ?? []) }
            }
        }
    }

    static func loadPreferences(for manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { c.resume(throwing: error) } else { c.resume(returning: ()) }
            }
        }
    }

    static func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { c.resume(throwing: error) } else { c.resume(returning: ()) }
            }
        }
    }
}

extension NEVPNStatus {
    var isActive: Bool {
        switch self { case .connected, .connecting, .reasserting: return true; default: return false }
    }
    var displayTitle: String {
        switch self {
        case .invalid: return "Not Configured"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        @unknown default: return "Unknown"
        }
    }
}
