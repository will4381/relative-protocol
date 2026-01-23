import Combine
import Foundation
import RelativeProtocolHost
import RelativeProtocolCore
@preconcurrency import NetworkExtension

@MainActor
final class VPNManager: ObservableObject {
    struct MetricsSummary: Equatable {
        let capturedAt: Date
        let totalSamples: Int
        let inboundSamples: Int
        let outboundSamples: Int
        let dnsSamples: Int
    }

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastError: String?
    @Published private(set) var isBusy = false
    @Published private(set) var hasProfile = false
    @Published private(set) var metricsSummary: MetricsSummary?
    @Published private(set) var metricsSnapshotCount = 0

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    private let providerBundleIdentifier = "relative-companies.Example.Example-Tunnel"
    private let localizedDescription = "Example VPN"
    private let providerConfiguration: [String: Any] = [
        "appGroupID": "group.relative-companies.Example",
        "relayMode": "tun2socks",
        "mtu": 1500,
        "ipv4Address": "10.0.0.2",
        "ipv4SubnetMask": "255.255.255.0",
        "ipv4Router": "10.0.0.1",
        "ipv6Address": "fd00:1:1:1::2",
        "ipv6PrefixLength": 64,
        "tunnelRemoteAddress": "127.0.0.1",
        "enginePacketPoolBytes": 2_097_152,
        "enginePerFlowBufferBytes": 16_384,
        "engineMaxFlows": 512,
        "engineSocksPort": 1080,
        "engineLogLevel": "engine_bridge=debug",
        "ipv6Enabled": true,
        "dnsServers": ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"],
        "metricsEnabled": true,
        "metricsRingBufferSize": 2048,
        "metricsSnapshotInterval": 1.0,
        "burstThresholdMs": 350,
        "flowTTLSeconds": 300,
        "maxTrackedFlows": 2048,
        "maxPendingAnalytics": 512
    ]
    private let appGroupID = "group.relative-companies.Example"
    private lazy var metricsClient = MetricsClient(appGroupID: appGroupID)

    init() {
        Task { await refreshStatus() }
    }

    var isConnected: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    var isEnabled: Bool {
        manager?.isEnabled ?? false
    }

    func refreshStatus() async {
        do {
            let managers = try await loadAllManagers()
            guard let existing = managers.first else {
                manager = nil
                status = .invalid
                hasProfile = false
                refreshMetrics()
                return
            }
            applyManager(existing)
            refreshMetrics()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func bootstrapProfile() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let manager = try await loadOrCreateManager()
            configureManager(manager)
            try await saveManager(manager)
            try await loadManager(manager)
            hasProfile = true
            status = manager.connection.status
            refreshMetrics()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func connect() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let manager = try await loadOrCreateManager()
            configureManager(manager)
            try await saveManager(manager)
            try await loadManager(manager)
            try manager.connection.startVPNTunnel()
            status = manager.connection.status
            hasProfile = true
            refreshMetrics()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    func clearMetrics() {
        metricsClient.clear()
        refreshMetrics()
    }

    func refreshMetrics() {
        let snapshots = metricsClient.loadSnapshots()
        metricsSnapshotCount = snapshots.count
        guard let latest = snapshots.last else {
            metricsSummary = nil
            return
        }
        let inboundSamples = latest.samples.filter { $0.direction == .inbound }.count
        let outboundSamples = latest.samples.filter { $0.direction == .outbound }.count
        let dnsSamples = latest.samples.filter { $0.dnsQueryName != nil }.count
        metricsSummary = MetricsSummary(
            capturedAt: Date(timeIntervalSince1970: latest.capturedAt),
            totalSamples: latest.samples.count,
            inboundSamples: inboundSamples,
            outboundSamples: outboundSamples,
            dnsSamples: dnsSamples
        )
    }

    func enable() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let manager = try await loadOrCreateManager()
            configureManager(manager)
            manager.isEnabled = true
            try await saveManager(manager)
            try await loadManager(manager)
            hasProfile = true
            status = manager.connection.status
            refreshMetrics()
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func loadOrCreateManager() async throws -> NETunnelProviderManager {
        if let manager {
            return manager
        }

        let managers = try await loadAllManagers()
        if let existing = managers.first {
            applyManager(existing)
            return existing
        }

        let manager = NETunnelProviderManager()
        configureManager(manager)
        applyManager(manager)
        return manager
    }

    private func applyManager(_ manager: NETunnelProviderManager) {
        self.manager = manager
        status = manager.connection.status
        hasProfile = true
        observeStatus(for: manager)
    }

    private func configureManager(_ manager: NETunnelProviderManager) {
        let protocolConfiguration = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        protocolConfiguration.providerBundleIdentifier = providerBundleIdentifier
        protocolConfiguration.serverAddress = localizedDescription
        protocolConfiguration.providerConfiguration = providerConfiguration
        protocolConfiguration.disconnectOnSleep = false
        protocolConfiguration.includeAllNetworks = true
        protocolConfiguration.excludeLocalNetworks = true
        protocolConfiguration.excludeCellularServices = false
        protocolConfiguration.excludeAPNs = true

        manager.protocolConfiguration = protocolConfiguration
        manager.localizedDescription = localizedDescription
        manager.isEnabled = true
        manager.onDemandRules = onDemandRules()
        manager.isOnDemandEnabled = true
    }

    private func onDemandRules() -> [NEOnDemandRule] {
        let wifiRule = NEOnDemandRuleConnect()
        wifiRule.interfaceTypeMatch = .wiFi

        let cellularRule = NEOnDemandRuleConnect()
        cellularRule.interfaceTypeMatch = .cellular

        let anyRule = NEOnDemandRuleConnect()
        anyRule.interfaceTypeMatch = .any

        return [wifiRule, cellularRule, anyRule]
    }

    private func observeStatus(for manager: NETunnelProviderManager) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }

        let connection = manager.connection
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self] _ in
            let newStatus = connection.status
            MainActor.assumeIsolated {
                self?.status = newStatus
            }
        }
    }

    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        let bundleIdentifier = providerBundleIdentifier
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    let matching = managers?
                        .compactMap { manager -> NETunnelProviderManager? in
                            guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                                return nil
                            }
                            return configuration.providerBundleIdentifier == bundleIdentifier ? manager : nil
                        } ?? []
                    continuation.resume(returning: matching)
                }
            }
        }
    }

    private func saveManager(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func loadManager(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}
