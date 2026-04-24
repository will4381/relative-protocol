// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Combine
import Foundation
import Analytics
import HostClient
import Network
import Observability
import PacketRelay
import TunnelControl
@preconcurrency import NetworkExtension

enum ExampleDNSMode: String, CaseIterable, Identifiable, Sendable {
    case adaptive
    case system
    case cloudflare
    case google

    var id: String { rawValue }

    var title: String {
        switch self {
        case .adaptive:
            return "Adaptive"
        case .system:
            return "System"
        case .cloudflare:
            return "Cloudflare"
        case .google:
            return "Google"
        }
    }
}

private struct ExampleDNSConfiguration: Equatable, Sendable {
    let strategy: TunnelDNSStrategy
    let summary: String
}

private final class OneShot<T>: @unchecked Sendable {
    private let lock = NSLock()
    nonisolated(unsafe) private var continuation: CheckedContinuation<T, Never>?

    nonisolated init(_ continuation: CheckedContinuation<T, Never>) {
        self.continuation = continuation
    }

    nonisolated func resume(_ value: T) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: value)
    }
}

/// One row in the on-device stress matrix output.
struct VPNStressScenarioRow: Identifiable, Equatable, Sendable {
    let id: String
    let name: String
    let condition: String
    let passed: Bool
    let blocked: Bool
    let probeCount: Int
    let failureCount: Int
    let durationMs: Int
    let detail: String

    var statusText: String {
        if blocked {
            return "BLOCKED"
        }
        return passed ? "PASS" : "FAIL"
    }
}

/// Current stress matrix state shown by the Example app and exported for device-side triage.
struct VPNStressReport: Equatable, Sendable {
    var isRunning: Bool
    var startedAt: Date?
    var completedAt: Date?
    var activeScenario: String?
    var progressText: String
    var dnsMode: String
    var effectiveDNS: String
    var pathSummary: String
    var rows: [VPNStressScenarioRow]
    var totalProbes: Int
    var failedProbes: Int
    var blockedProbes: Int
    var savedReportPath: String?

    static let idle = VPNStressReport(
        isRunning: false,
        startedAt: nil,
        completedAt: nil,
        activeScenario: nil,
        progressText: "Not run",
        dnsMode: "Unknown",
        effectiveDNS: "Unknown",
        pathSummary: "Unknown",
        rows: [],
        totalProbes: 0,
        failedProbes: 0,
        blockedProbes: 0,
        savedReportPath: nil
    )

    var passed: Bool {
        let coveredRows = rows.filter { !$0.blocked }
        return !isRunning && !coveredRows.isEmpty && failedProbes == 0 && coveredRows.allSatisfy(\.passed)
    }

    var summaryText: String {
        if isRunning {
            return progressText
        }
        guard !rows.isEmpty else {
            return progressText
        }
        let blockedSuffix = blockedProbes == 0 ? "" : " · \(blockedProbes) blocked"
        return passed ? "PASS · \(totalProbes) probes\(blockedSuffix)" : "FAIL · \(failedProbes)/\(totalProbes) probes\(blockedSuffix)"
    }
}

/// Main app controller for installing, connecting, and inspecting the example packet tunnel.
/// Ownership: all published state is mutated on the main actor.
@MainActor
final class VPNManager: ObservableObject {
    /// Lightweight packet row shown on the main test screen.
    struct PacketRow: Identifiable, Equatable {
        let id: String
        let title: String
        let subtitle: String
        let detail: String?
    }

    /// Lightweight detector row shown below the summary counters.
    struct DetectionRow: Identifiable, Equatable {
        let id: String
        let title: String
        let subtitle: String
        let detail: String?
    }

    /// Summary of the live rolling tunnel tap shown above the event list.
    struct TrafficSummary: Equatable {
        var recentEventCount: Int
        var inspectedEventCount: Int
        var updatedAt: Date?
        var lastStopSummary: String?
        var lastStopTimestamp: Date?
        var thermalState: String?
        var acceptedTelemetryBatches: Int
        var droppedBatches: Int
        var skippedBatches: Int
        var totalDetectionCount: Int
        var tikTokCDNCount: Int
        var instagramCDNCount: Int
        var flowOpenCount: Int
        var flowSliceCount: Int
        var flowCloseCount: Int
        var metadataCount: Int
        var burstCount: Int
        var activitySampleCount: Int
        var hostHintCount: Int
        var dnsAnswerCount: Int
        var dnsAssociationCount: Int
        var lineageCount: Int
        var pathRegimeCount: Int
        var serviceAttributionCount: Int
        var quicIdentityCount: Int
        var lastFlowCloseReason: String?
        var lastAssociatedDomain: String?
        var lastServiceFamily: String?
        var lastPathRegime: String?

        var evaluatedTelemetryBatches: Int {
            acceptedTelemetryBatches + droppedBatches + skippedBatches
        }

        var shedRateText: String {
            let total = evaluatedTelemetryBatches
            guard total > 0 else {
                return "0%"
            }
            let rate = (Double(droppedBatches) / Double(total)) * 100
            return String(format: "%.1f%%", rate)
        }
    }

    /// Compares the desired host profile with the currently installed manager profile.
    struct ProfileDiagnostics: Equatable {
        enum MatchState: Equatable {
            case missing
            case exactMatch
            case mismatch
            case duplicateExactMatch
        }

        var matchState: MatchState
        var totalManagerCount: Int
        var exactMatchCount: Int
        var desiredSummary: String
        var installedSummary: String
        var note: String?

        static let unconfigured = ProfileDiagnostics(
            matchState: .missing,
            totalManagerCount: 0,
            exactMatchCount: 0,
            desiredSummary: "Loading…",
            installedSummary: "No installed manager",
            note: nil
        )

        var statusText: String {
            switch matchState {
            case .missing:
                return "No installed manager"
            case .exactMatch:
                return "Exact match"
            case .mismatch:
                return "Mismatch"
            case .duplicateExactMatch:
                return "Multiple exact matches"
            }
        }

        var managerCountText: String {
            "\(totalManagerCount) total · \(exactMatchCount) exact"
        }

        var requiresAttention: Bool {
            matchState == .mismatch || matchState == .duplicateExactMatch
        }
    }

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var isBusy = false
    @Published private(set) var hasProfile = false
    @Published private(set) var lastError: String?
    @Published private(set) var trafficSummary = TrafficSummary(
        recentEventCount: 0,
        inspectedEventCount: 0,
        updatedAt: nil,
        lastStopSummary: nil,
        lastStopTimestamp: nil,
        thermalState: nil,
        acceptedTelemetryBatches: 0,
        droppedBatches: 0,
        skippedBatches: 0,
        totalDetectionCount: 0,
        tikTokCDNCount: 0,
        instagramCDNCount: 0,
        flowOpenCount: 0,
        flowSliceCount: 0,
        flowCloseCount: 0,
        metadataCount: 0,
        burstCount: 0,
        activitySampleCount: 0,
        hostHintCount: 0,
        dnsAnswerCount: 0,
        dnsAssociationCount: 0,
        lineageCount: 0,
        pathRegimeCount: 0,
        serviceAttributionCount: 0,
        quicIdentityCount: 0,
        lastFlowCloseReason: nil,
        lastAssociatedDomain: nil,
        lastServiceFamily: nil,
        lastPathRegime: nil
    )
    @Published private(set) var profileDiagnostics = ProfileDiagnostics.unconfigured
    @Published private(set) var packetRows: [PacketRow] = []
    @Published private(set) var detectionRows: [DetectionRow] = []
    @Published private(set) var stressReport = VPNStressReport.idle
    @Published var dnsMode: ExampleDNSMode = .adaptive {
        didSet {
            guard oldValue != dnsMode else { return }
            adaptiveDNSFallbackForced = false
            refreshProfileDiagnosticsForCurrentManager()
            resetStressDNSContext()
        }
    }
    @Published private(set) var currentPathSummary = "Unknown"
    @Published private(set) var currentPathSupportsDNSText = "Unknown"

    private let providerBundleIdentifier = "relative-companies.Example.Example-Tunnel"
    private let localizedDescription = "VPN Bridge Example"
    private let appGroupID = "group.relative-companies.Example"
    private let packetInspectionLimit = 96
    private let packetRowLimit = 40
    private let telemetryClient: TunnelTelemetryClient
    private let stopStore: TunnelStopStore
    private let detectionStore: TunnelDetectionStore
    private let pathMonitor = Network.NWPathMonitor()
    private let pathMonitorQueue = DispatchQueue(label: "relative.example.default-path", qos: .utility)

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pendingUserDisconnectRequest = false
    private var stressTask: Task<Void, Never>?
    private var currentPathSupportsDNS: Bool?
    private var adaptiveDNSFallbackForced = false

    init() {
        self.telemetryClient = TunnelTelemetryClient()
        self.stopStore = TunnelStopStore(appGroupID: appGroupID)
        self.detectionStore = TunnelDetectionStore(appGroupID: appGroupID)
        updateProfileDiagnostics(managers: [], selectedManager: nil)
        startPathMonitor()
        Task { await refreshStatus() }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        pathMonitor.cancel()
    }

    var isConnected: Bool {
        switch status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    var isEnabled: Bool {
        manager?.isEnabled ?? false
    }

    var lastStopDisplayText: String {
        let summary = trafficSummary.lastStopSummary ?? "Not recorded yet"
        guard let timestamp = trafficSummary.lastStopTimestamp else {
            return summary
        }
        return "\(summary) · \(timestamp.formatted(.dateTime.hour().minute().second()))"
    }

    var dnsModeDisplayText: String {
        dnsMode.title
    }

    var effectiveDNSDisplayText: String {
        effectiveDNSConfiguration.summary
    }

    var canEditDNSMode: Bool {
        !isBusy && !isConnected && !stressReport.isRunning
    }

    /// Loads the current tunnel profile from system preferences and refreshes live tunnel diagnostics.
    func refreshStatus() async {
        do {
            await refreshCurrentPath()
            let managers = try await loadAllManagers()
            if let existing = managers.first {
                applyManager(existing)
                updateProfileDiagnostics(managers: managers, selectedManager: existing)
            } else {
                clearLoadedManager()
            }
            await refreshTraffic()
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Installs or updates the packet-tunnel profile, then starts the tunnel connection.
    func connect() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let preparedManager = try await prepareManager()
            let managers = try await loadAllManagers()
            updateProfileDiagnostics(managers: managers, selectedManager: preparedManager)
            // Docs: https://developer.apple.com/documentation/networkextension/nevpnconnection/startvpntunnel()
            try preparedManager.connection.startVPNTunnel()
            pendingUserDisconnectRequest = false
            status = preparedManager.connection.status
            hasProfile = true
            await refreshTraffic()
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Stops the active tunnel connection if one is installed.
    func disconnect() {
        // Docs: https://developer.apple.com/documentation/networkextension/nevpnconnection/stopvpntunnel()
        pendingUserDisconnectRequest = true
        manager?.connection.stopVPNTunnel()
    }

    /// Starts the real-device network stress matrix against the active Example tunnel.
    func startStressMatrix() {
        guard stressTask == nil else { return }
        stressTask = Task { [weak self] in
            await self?.runStressMatrix()
        }
    }

    /// Cancels the currently running stress matrix.
    func cancelStressMatrix() {
        stressTask?.cancel()
    }

    private func runStressMatrix() async {
        stressReport = VPNStressReport(
            isRunning: true,
            startedAt: Date(),
            completedAt: nil,
            activeScenario: "Preparing",
            progressText: "Preparing tunnel",
            dnsMode: dnsModeDisplayText,
            effectiveDNS: effectiveDNSDisplayText,
            pathSummary: currentPathSummary,
            rows: [],
            totalProbes: 0,
            failedProbes: 0,
            blockedProbes: 0,
            savedReportPath: nil
        )
        defer {
            stressTask = nil
        }

        do {
            if !isConnected {
                await connect()
                try await waitForConnectedTunnel(timeoutSeconds: 25)
            }
            try await ensureAdaptiveDNSReadyForStress()
            guard let connection = manager?.connection else {
                throw VPNStressError.missingTunnelConnection
            }
            let activeProfile = manager.flatMap(Self.decodedProfile(from:))
            let activeDNSDescription = activeProfile.map { Self.dnsStrategySummary($0.dnsStrategy) } ?? effectiveDNSDisplayText
            let dnsPolicyProvidesResolver = activeProfile.map { !$0.dnsStrategy.servers.isEmpty } ?? false

            let runner = VPNStressRunner(
                telemetryClient: telemetryClient,
                appGroupID: appGroupID
            )
            let report = try await runner.run(
                connection: connection,
                dnsMode: dnsModeDisplayText,
                effectiveDNS: activeDNSDescription,
                pathSummary: currentPathSummary,
                dnsPolicyProvidesResolver: dnsPolicyProvidesResolver
            ) { [weak self] update in
                await self?.applyStressUpdate(update)
            }
            stressReport = report
            await refreshTraffic()
        } catch is CancellationError {
            var cancelled = stressReport
            cancelled.isRunning = false
            cancelled.completedAt = Date()
            cancelled.activeScenario = nil
            cancelled.progressText = "Cancelled"
            stressReport = cancelled
        } catch {
            var failed = stressReport
            failed.isRunning = false
            failed.completedAt = Date()
            failed.activeScenario = nil
            failed.progressText = "Failed · \(error.localizedDescription)"
            failed.failedProbes = max(1, failed.failedProbes)
            stressReport = failed
            lastError = error.localizedDescription
        }
    }

    private func waitForConnectedTunnel(timeoutSeconds: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            if status == .connected {
                return
            }
            try Task.checkCancellation()
            try await Task.sleep(for: .milliseconds(300))
            await refreshStatus()
        }
        throw VPNStressError.tunnelDidNotConnect
    }

    private func waitForDisconnectedTunnel(timeoutSeconds: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            if status == .disconnected || status == .invalid {
                return
            }
            try Task.checkCancellation()
            try await Task.sleep(for: .milliseconds(300))
            await refreshStatus()
        }
        throw VPNStressError.tunnelDidNotDisconnect
    }

    private func ensureAdaptiveDNSReadyForStress() async throws {
        guard dnsMode == .adaptive else { return }
        await refreshCurrentPath()
        guard currentPathSupportsDNS == false else { return }
        guard manager.flatMap(Self.decodedProfile(from:))?.dnsStrategy == .noOverride else { return }

        var update = stressReport
        update.activeScenario = "Reconfiguring DNS"
        update.progressText = "Adaptive DNS fallback"
        stressReport = update

        adaptiveDNSFallbackForced = true
        disconnect()
        try await waitForDisconnectedTunnel(timeoutSeconds: 12)
        await connect()
        try await waitForConnectedTunnel(timeoutSeconds: 25)
        await refreshCurrentPath()
    }

    private func applyStressUpdate(_ update: VPNStressReport) {
        stressReport = update
    }

    /// Clears the live rolling tap and the persisted last-stop breadcrumb, then reloads the main screen.
    func clearLocalData() async {
        do {
            if isConnected, let connection = manager?.connection {
                try await telemetryClient.clearRecentEvents(from: connection)
                try await telemetryClient.clearDetections(from: connection)
            }
            let stopStore = self.stopStore
            let detectionStore = self.detectionStore
            try await Task.detached(priority: .utility) {
                try stopStore.clear()
                try detectionStore.clear()
            }.value
            await refreshTraffic()
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Reloads the live rolling tunnel snapshot without touching the installed VPN profile.
    func refreshTraffic() async {
        let connection = manager?.connection
        let shouldLoadLiveSnapshot = isConnected && connection != nil
        let packetLimit = packetInspectionLimit

        async let liveSnapshotTask: TunnelTelemetrySnapshot? = {
            guard shouldLoadLiveSnapshot, let connection else {
                return nil
            }
            return try? await telemetryClient.snapshot(from: connection, packetLimit: packetLimit)
        }()

        let stopStore = self.stopStore
        let detectionStore = self.detectionStore
        let lastStopRecord = try? await Task.detached(priority: .utility) {
            try stopStore.load()
        }.value
        let persistedDetections = try? await Task.detached(priority: .utility) {
            try detectionStore.load()
        }.value
        let liveSnapshot = await liveSnapshotTask
        let detections = liveSnapshot?.detections ?? persistedDetections ?? .empty
        let inspectedSamples = liveSnapshot?.samples ?? []
        let visibleSamples = Array(inspectedSamples.suffix(packetRowLimit))

        let latestPacketTime = liveSnapshot?.latestSampleAt
        let updatedAt = latestPacketTime ?? .distantPast
        let flowOpenCount = inspectedSamples.filter { $0.kind == .flowOpen }.count
        let flowSliceCount = inspectedSamples.filter { $0.kind == .flowSlice }.count
        let flowCloseCount = inspectedSamples.filter { $0.kind == .flowClose }.count
        let metadataCount = inspectedSamples.filter { $0.kind == .metadata }.count
        let burstCount = inspectedSamples.filter { $0.kind == .burst }.count
        let activitySampleCount = inspectedSamples.filter { $0.kind == .activitySample }.count
        let hostHintCount = inspectedSamples.filter(Self.hasHostHints).count
        let dnsAnswerCount = inspectedSamples.filter(Self.hasDNSAnswers).count
        let dnsAssociationCount = inspectedSamples.filter(Self.hasDNSAssociation).count
        let lineageCount = inspectedSamples.filter(Self.hasLineage).count
        let pathRegimeCount = inspectedSamples.filter(Self.hasPathRegime).count
        let serviceAttributionCount = inspectedSamples.filter(Self.hasServiceAttribution).count
        let quicIdentityCount = inspectedSamples.filter(Self.hasQUICIdentity).count
        let lastFlowCloseReason = inspectedSamples.reversed().first(where: { $0.kind == .flowClose })?.closeReason?.rawValue
        let lastAssociatedDomain = inspectedSamples.reversed().compactMap(\.associatedDomain).first
        let lastServiceFamily = inspectedSamples.reversed().compactMap(\.serviceFamily).first
        let lastPathRegime = inspectedSamples.reversed().compactMap(Self.pathRegimeSummary).first

        trafficSummary = TrafficSummary(
            recentEventCount: liveSnapshot?.retainedSampleCount ?? 0,
            inspectedEventCount: inspectedSamples.count,
            updatedAt: updatedAt == .distantPast ? nil : updatedAt,
            lastStopSummary: lastStopRecord?.summary,
            lastStopTimestamp: lastStopRecord?.timestamp,
            thermalState: liveSnapshot?.thermalState.rawValue,
            acceptedTelemetryBatches: liveSnapshot?.acceptedBatches ?? 0,
            droppedBatches: liveSnapshot?.droppedBatches ?? 0,
            skippedBatches: liveSnapshot?.skippedBatches ?? 0,
            totalDetectionCount: detections.totalDetectionCount,
            tikTokCDNCount: detections.count(forTarget: "tiktok-cdn"),
            instagramCDNCount: detections.count(forTarget: "instagram-cdn"),
            flowOpenCount: flowOpenCount,
            flowSliceCount: flowSliceCount,
            flowCloseCount: flowCloseCount,
            metadataCount: metadataCount,
            burstCount: burstCount,
            activitySampleCount: activitySampleCount,
            hostHintCount: hostHintCount,
            dnsAnswerCount: dnsAnswerCount,
            dnsAssociationCount: dnsAssociationCount,
            lineageCount: lineageCount,
            pathRegimeCount: pathRegimeCount,
            serviceAttributionCount: serviceAttributionCount,
            quicIdentityCount: quicIdentityCount,
            lastFlowCloseReason: lastFlowCloseReason,
            lastAssociatedDomain: lastAssociatedDomain,
            lastServiceFamily: lastServiceFamily,
            lastPathRegime: lastPathRegime
        )

        let visibleSampleRows = Array(visibleSamples.enumerated().reversed())
        packetRows = visibleSampleRows.map { sourceIndex, sample in
            Self.makePacketRow(from: sample, sourceIndex: sourceIndex)
        }
        detectionRows = Array(detections.recentEvents.reversed()).map(Self.makeDetectionRow)
        await refreshLastStopDetails(connection: connection, baseRecord: lastStopRecord)
        lastError = nil
    }

    private var profile: TunnelProfile {
        let dnsConfiguration = effectiveDNSConfiguration
        return TunnelProfile(
            appGroupID: appGroupID,
            tunnelRemoteAddress: "127.0.0.1",
            mtu: 1_280,
            mtuStrategy: .fixed(1_280),
            ipv6Enabled: true,
            tcpMultipathHandoverEnabled: true,
            ipv4Address: "10.0.0.2",
            ipv4SubnetMask: "255.255.255.0",
            ipv4Router: "10.0.0.1",
            ipv6Address: "fd00:1:1:1::2",
            ipv6PrefixLength: 64,
            dnsServers: dnsConfiguration.strategy.servers,
            dnsStrategy: dnsConfiguration.strategy,
            engineSocksPort: 0,
            engineLogLevel: "info",
            telemetryEnabled: true,
            liveTapEnabled: true,
            liveTapIncludeFlowSlices: true,
            liveTapMaxBytes: 1_048_576,
            signatureFileName: "app_signatures.json",
            relayEndpoint: RelayEndpoint(host: "127.0.0.1", port: 1080, useUDP: false),
            dataplaneConfigJSON: "{}"
        )
    }

    private var effectiveDNSConfiguration: ExampleDNSConfiguration {
        Self.dnsConfiguration(
            for: dnsMode,
            pathSupportsDNS: currentPathSupportsDNS,
            forceAdaptiveFallback: adaptiveDNSFallbackForced,
            allowPreconnectFallback: !isConnected
        )
    }

    private static func dnsConfiguration(
        for mode: ExampleDNSMode,
        pathSupportsDNS: Bool?,
        forceAdaptiveFallback: Bool,
        allowPreconnectFallback: Bool
    ) -> ExampleDNSConfiguration {
        switch mode {
        case .adaptive:
            if forceAdaptiveFallback || (allowPreconnectFallback && pathSupportsDNS == false) {
                return publicDNSConfiguration(
                    name: "Adaptive -> Cloudflare",
                    servers: TunnelDNSStrategy.defaultPublicResolvers
                )
            }
            return ExampleDNSConfiguration(
                strategy: .noOverride,
                summary: pathSupportsDNS == nil ? "Adaptive -> System DNS (path unknown)" : "Adaptive -> System DNS"
            )
        case .system:
            return ExampleDNSConfiguration(strategy: .noOverride, summary: "System DNS")
        case .cloudflare:
            return publicDNSConfiguration(name: "Cloudflare", servers: TunnelDNSStrategy.defaultPublicResolvers)
        case .google:
            return publicDNSConfiguration(name: "Google", servers: googlePublicResolvers)
        }
    }

    private static func publicDNSConfiguration(name: String, servers: [String]) -> ExampleDNSConfiguration {
        ExampleDNSConfiguration(
            strategy: .cleartext(servers: servers, allowFailover: true),
            summary: "\(name) cleartext (\(servers.count), failover on)"
        )
    }

    private func prepareManager() async throws -> NETunnelProviderManager {
        await refreshCurrentPath()
        let manager = try await loadOrCreateManager()
        configureManager(manager)
        try await saveManager(manager)
        try await loadManager(manager)
        applyManager(manager)
        updateProfileDiagnostics(managers: [manager], selectedManager: manager)
        return manager
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
        applyManager(manager)
        return manager
    }

    private func configureManager(_ manager: NETunnelProviderManager) {
        // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovidermanager
        // Docs: https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol
        TunnelProfileManager.configure(
            manager: manager,
            profile: profile,
            providerBundleIdentifier: providerBundleIdentifier,
            localizedDescription: localizedDescription
        )
    }

    private func applyManager(_ manager: NETunnelProviderManager) {
        self.manager = manager
        self.status = manager.connection.status
        self.hasProfile = true
        observeStatus(for: manager)
    }

    private func clearLoadedManager() {
        manager = nil
        status = .invalid
        hasProfile = false
        pendingUserDisconnectRequest = false

        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
            self.statusObserver = nil
        }

        updateProfileDiagnostics(managers: [], selectedManager: nil)
    }

    private func observeStatus(for manager: NETunnelProviderManager) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }

        let connection = manager.connection
        // Docs: https://developer.apple.com/documentation/networkextension/nevpnstatusdidchangenotification
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.status = connection.status
                if connection.status == .connected {
                    self.pendingUserDisconnectRequest = false
                }
                Task { await self.refreshTraffic() }
            }
        }
    }

    private func startPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor [weak self] in
                self?.applyCurrentPath(path)
            }
        }
        pathMonitor.start(queue: pathMonitorQueue)
    }

    private func refreshCurrentPath() async {
        let path = await Self.sampleCurrentPath(timeoutSeconds: 1.0)
        applyCurrentPath(path)
    }

    private func applyCurrentPath(_ path: Network.NWPath) {
        currentPathSupportsDNS = path.supportsDNS
        currentPathSupportsDNSText = path.supportsDNS ? "Yes" : "No"
        currentPathSummary = Self.pathSummary(path)
        refreshProfileDiagnosticsForCurrentManager()
        resetStressDNSContext()
    }

    private func refreshProfileDiagnosticsForCurrentManager() {
        if let manager {
            updateProfileDiagnostics(managers: [manager], selectedManager: manager)
        } else {
            updateProfileDiagnostics(managers: [], selectedManager: nil)
        }
    }

    private func resetStressDNSContext() {
        guard !stressReport.isRunning, stressReport.rows.isEmpty else { return }
        var report = stressReport
        report.dnsMode = dnsModeDisplayText
        report.effectiveDNS = effectiveDNSDisplayText
        report.pathSummary = currentPathSummary
        stressReport = report
    }

    nonisolated private static func sampleCurrentPath(timeoutSeconds: TimeInterval) async -> Network.NWPath {
        await withCheckedContinuation { continuation in
            let monitor = Network.NWPathMonitor()
            let queue = DispatchQueue(label: "relative.example.path-sample", qos: .utility)
            let gate = OneShot<Network.NWPath>(continuation)
            monitor.pathUpdateHandler = { path in
                if path.status == .satisfied {
                    monitor.cancel()
                    gate.resume(path)
                }
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeoutSeconds) {
                let path = monitor.currentPath
                monitor.cancel()
                gate.resume(path)
            }
        }
    }

    nonisolated private static func pathSummary(_ path: Network.NWPath) -> String {
        var interfaces: [String] = []
        if path.usesInterfaceType(.wifi) { interfaces.append("wifi") }
        if path.usesInterfaceType(.cellular) { interfaces.append("cellular") }
        if path.usesInterfaceType(.wiredEthernet) { interfaces.append("wired") }
        if path.usesInterfaceType(.loopback) { interfaces.append("loopback") }
        if interfaces.isEmpty { interfaces.append("other") }

        let status: String
        switch path.status {
        case .satisfied:
            status = "satisfied"
        case .unsatisfied:
            status = "unsatisfied"
        case .requiresConnection:
            status = "requires-connection"
        @unknown default:
            status = "unknown"
        }

        return "path \(status), interfaces \(interfaces.joined(separator: "/")), expensive \(path.isExpensive), constrained \(path.isConstrained), dns \(path.supportsDNS)"
    }

    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        let bundleIdentifier = providerBundleIdentifier
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovidermanager/loadallfrompreferences(completionhandler:)
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                let matchingManagers = managers?
                    .compactMap { manager -> NETunnelProviderManager? in
                        guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                            return nil
                        }
                        return configuration.providerBundleIdentifier == bundleIdentifier ? manager : nil
                    } ?? []
                continuation.resume(returning: matchingManagers)
            }
        }
    }

    private func saveManager(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovidermanager/savetopreferences(completionhandler:)
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
            // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovidermanager/loadfrompreferences(completionhandler:)
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func updateProfileDiagnostics(
        managers: [NETunnelProviderManager],
        selectedManager: NETunnelProviderManager?
    ) {
        let desiredProfile = profile
        let desiredSummary = Self.profileSummary(for: desiredProfile)
        let decodedProfiles = managers.compactMap(Self.decodedProfile(from:))
        let exactMatchCount = decodedProfiles.filter { $0 == desiredProfile }.count
        let installedProfile = selectedManager.flatMap(Self.decodedProfile(from:))

        let matchState: ProfileDiagnostics.MatchState
        if installedProfile == nil {
            matchState = .missing
        } else if installedProfile == desiredProfile {
            matchState = exactMatchCount > 1 ? .duplicateExactMatch : .exactMatch
        } else {
            matchState = .mismatch
        }

        let note: String?
        if exactMatchCount > 0,
           installedProfile != desiredProfile,
           managers.count > 1 {
            note = "A saved manager matches the desired profile, but the selected manager does not."
        } else if exactMatchCount == 0,
                  managers.count > 1 {
            note = "Multiple saved managers exist and none decode to the desired profile."
        } else if exactMatchCount > 1 {
            note = "Multiple saved managers decode to the desired profile."
        } else {
            note = nil
        }

        profileDiagnostics = ProfileDiagnostics(
            matchState: matchState,
            totalManagerCount: managers.count,
            exactMatchCount: exactMatchCount,
            desiredSummary: desiredSummary,
            installedSummary: installedProfile.map(Self.profileSummary(for:)) ?? "No installed manager",
            note: note
        )
    }

    private static func decodedProfile(from manager: NETunnelProviderManager) -> TunnelProfile? {
        guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = configuration.providerConfiguration else {
            return nil
        }
        return TunnelProfile.from(providerConfiguration: providerConfiguration)
    }

    private static func profileSummary(for profile: TunnelProfile) -> String {
        let mtuSummary: String
        switch profile.mtuStrategy {
        case .fixed(let mtu):
            mtuSummary = "MTU \(mtu)"
        case .automaticTunnelOverhead(let overhead):
            mtuSummary = "MTU auto-\(overhead)"
        }

        let socksSummary = profile.engineSocksPort == 0 ? "SOCKS auto" : "SOCKS \(profile.engineSocksPort)"
        let dnsSummary = dnsStrategySummary(profile.dnsStrategy)
        let handoverSummary = profile.tcpMultipathHandoverEnabled ? "handover on" : "handover off"
        return "\(mtuSummary) · \(socksSummary) · \(dnsSummary) · \(handoverSummary)"
    }

    private static func dnsStrategySummary(_ strategy: TunnelDNSStrategy) -> String {
        switch strategy {
        case .cleartext(let servers, _, _, _):
            return "DNS cleartext (\(servers.count))"
        case .tls(let servers, _, _, _, _):
            return "DNS TLS (\(servers.count))"
        case .https(let servers, _, _, _, _):
            return "DNS HTTPS (\(servers.count))"
        case .noOverride:
            return "DNS system"
        }
    }

    /// Creates a display row with identity anchored to the current live snapshot order.
    /// - Parameters:
    ///   - sample: Packet sample decoded from the live rolling tunnel tap.
    ///   - sourceIndex: Zero-based line position in the current live snapshot.
    /// - Returns: Display-ready row whose identifier stays unique even when packet metadata repeats.
    private static func makePacketRow(from sample: PacketSample, sourceIndex: Int) -> PacketRow {
        let kindText = kindDisplayName(sample.kind)
        let protocolText = sample.protocolHint.isEmpty ? "IP" : sample.protocolHint.uppercased()
        let sizeText = byteCountFormatter.string(fromByteCount: Int64(sample.bytes))
        let timestampText = rowDateFormatter.string(from: sample.timestamp)
        let hostText = sample.tlsServerName
            ?? sample.dnsQueryName
            ?? sample.dnsCname
            ?? sample.registrableDomain
            ?? sample.destinationAddress
            ?? sample.sourceAddress
            ?? sample.flowId
        return PacketRow(
            id: "packet-row-\(sourceIndex)",
            title: "\(kindText) · \(protocolText) \(sample.direction.capitalized) · \(sizeText)",
            subtitle: "\(timestampText) · \(hostText) · \(shortFlowId(sample.flowId))",
            detail: packetDetailText(for: sample)
        )
    }

    /// Creates a display row from one durable detector output.
    private static func makeDetectionRow(from event: DetectionEvent) -> DetectionRow {
        let timestampText = rowDateFormatter.string(from: event.timestamp)
        let hostText = event.host
            ?? event.classification
            ?? (!event.flowId.isEmpty ? event.flowId : nil)
            ?? event.trigger
        let confidence = Int((event.confidence * 100).rounded())
        let byteText = byteCountFormatter.string(fromByteCount: Int64(event.bytes))
        let packetText = event.packetCount.map { " · \($0) packets" } ?? ""
        let durationText = event.durationMs.map { " · \($0)ms" } ?? ""
        let targetText = event.target ?? "unscoped"

        return DetectionRow(
            id: event.id,
            title: "\(event.detectorIdentifier) · \(targetText) · \(confidence)% confidence",
            subtitle: "\(timestampText) · \(event.signal) · \(hostText) · \(byteText)\(packetText)\(durationText)",
            detail: detectionDetailText(for: event)
        )
    }

    /// Refines the user-facing stop summary with host-side disconnect error details when available.
    /// - Parameters:
    ///   - connection: Active VPN connection used to fetch the most recent disconnect error.
    ///   - baseRecord: Last provider stop record written by the tunnel extension.
    private func refreshLastStopDetails(connection: NEVPNConnection?, baseRecord: TunnelStopRecord?) async {
        var summary = trafficSummary

        if status == .disconnecting, pendingUserDisconnectRequest {
            summary.lastStopSummary = "Stopping at user request"
            trafficSummary = summary
            return
        }

        guard status == .disconnected else {
            trafficSummary = summary
            return
        }

        defer {
            pendingUserDisconnectRequest = false
        }

        guard let connection else {
            if summary.lastStopSummary == nil, pendingUserDisconnectRequest {
                summary.lastStopSummary = "Stopped by user"
            }
            trafficSummary = summary
            return
        }

        if let error = await fetchLastDisconnectError(from: connection) {
            let detail = Self.disconnectErrorSummary(error)
            if let baseSummary = summary.lastStopSummary, !baseSummary.isEmpty, baseSummary != detail {
                summary.lastStopSummary = "\(baseSummary): \(detail)"
            } else {
                summary.lastStopSummary = detail
            }
        } else if summary.lastStopSummary == nil, pendingUserDisconnectRequest || baseRecord?.isUserInitiated == true {
            summary.lastStopSummary = "Stopped by user"
        }

        trafficSummary = summary
    }

    /// Bridges `fetchLastDisconnectErrorWithCompletionHandler:` into async code on the main actor.
    /// - Parameter connection: VPN connection to query for the last disconnect error.
    /// - Returns: Most recent disconnect error surfaced by NetworkExtension, if any.
    private func fetchLastDisconnectError(from connection: NEVPNConnection) async -> NSError? {
        await withCheckedContinuation { continuation in
            // Docs: https://developer.apple.com/documentation/networkextension/nevpnconnection/fetchlastdisconnecterror(completionhandler:)
            connection.fetchLastDisconnectError { error in
                continuation.resume(returning: error as NSError?)
            }
        }
    }

    /// Maps disconnect errors into short text suitable for the Overview row.
    /// - Parameter error: Error returned by `NEVPNConnection.fetchLastDisconnectError`.
    /// - Returns: Condensed explanation without raw domain noise unless no better detail exists.
    private static func disconnectErrorSummary(_ error: NSError) -> String {
        if error.domain == NEVPNConnectionErrorDomain {
            switch error.code {
            case 1:
                return "The connection ended after the device overslept"
            case 2:
                return "The connection could not start because no network was available"
            case 3:
                return "The connection ended after an unrecoverable network change"
            case 4:
                return "The VPN configuration was invalid"
            case 5:
                return "The VPN server address could not be resolved"
            case 6:
                return "The VPN server stopped responding"
            case 7:
                return "The VPN server is no longer functioning"
            case 8:
                return "Authentication failed"
            case 9:
                return "The client certificate is invalid"
            case 10:
                return "The client certificate is not valid yet"
            case 11:
                return "The client certificate has expired"
            case 12:
                return "The VPN plug-in failed unexpectedly"
            case 13:
                return "The VPN configuration could not be found"
            case 14:
                return "The VPN plug-in is disabled or out of date"
            case 15:
                return "VPN negotiation failed"
            case 16:
                return "The VPN server disconnected"
            case 17:
                return "The server certificate is invalid"
            case 18:
                return "The server certificate is not valid yet"
            case 19:
                return "The server certificate has expired"
            default:
                break
            }
        }

        let message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        if !message.isEmpty, message != "The operation couldn’t be completed." {
            return message
        }
        return "\(error.domain) (\(error.code))"
    }

    private static let byteCountFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.includesUnit = true
        formatter.isAdaptive = true
        return formatter
    }()

    private static let rowDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter
    }()

    private static let googlePublicResolvers = [
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844"
    ]

    private static func kindDisplayName(_ kind: PacketSampleKind) -> String {
        switch kind {
        case .flowOpen:
            return "Flow Open"
        case .flowSlice:
            return "Flow Slice"
        case .flowClose:
            return "Flow Close"
        case .metadata:
            return "Metadata"
        case .burst:
            return "Burst"
        case .activitySample:
            return "Activity"
        }
    }

    private static func shortFlowId(_ flowId: String) -> String {
        guard !flowId.isEmpty else {
            return "flow n/a"
        }
        return "flow \(flowId.suffix(8))"
    }

    private static func packetDetailText(for sample: PacketSample) -> String? {
        var lines: [String] = []
        var trafficFragments: [String] = []

        if let packetCount = sample.packetCount {
            trafficFragments.append("\(packetCount) packets")
        }
        if let flowPacketCount = sample.flowPacketCount {
            trafficFragments.append("flow \(flowPacketCount) total")
        }
        if let flowByteCount = sample.flowByteCount {
            let flowByteText = byteCountFormatter.string(fromByteCount: Int64(flowByteCount))
            trafficFragments.append("flow \(flowByteText)")
        }
        if let udpPacketCount = sample.udpPacketCount, let tcpPacketCount = sample.tcpPacketCount {
            trafficFragments.append("udp \(udpPacketCount) / tcp \(tcpPacketCount)")
        }
        if let largePacketCount = sample.largePacketCount, let smallPacketCount = sample.smallPacketCount {
            trafficFragments.append("large \(largePacketCount) / small \(smallPacketCount)")
        }

        let tcpSynCount = sample.tcpSynCount ?? 0
        let tcpFinCount = sample.tcpFinCount ?? 0
        let tcpRstCount = sample.tcpRstCount ?? 0
        if tcpSynCount > 0 || tcpFinCount > 0 || tcpRstCount > 0 {
            trafficFragments.append("syn \(tcpSynCount) fin \(tcpFinCount) rst \(tcpRstCount)")
        }

        if let quicInitialCount = sample.quicInitialCount, quicInitialCount > 0 {
            trafficFragments.append("quic initial \(quicInitialCount)")
        }

        if let closeReason = sample.closeReason {
            trafficFragments.append("reason \(closeReason.rawValue)")
        }

        if let burstPacketCount = sample.burstPacketCount, let burstDurationMs = sample.burstDurationMs {
            trafficFragments.append("burst \(burstPacketCount) @ \(burstDurationMs)ms")
        }

        if let leadingBytes200ms = sample.leadingBytes200ms, let leadingPackets200ms = sample.leadingPackets200ms {
            let leading200Text = byteCountFormatter.string(fromByteCount: Int64(leadingBytes200ms))
            trafficFragments.append("lead200 \(leading200Text) / \(leadingPackets200ms)")
        }
        if let leadingBytes600ms = sample.leadingBytes600ms, let leadingPackets600ms = sample.leadingPackets600ms {
            let leading600Text = byteCountFormatter.string(fromByteCount: Int64(leadingBytes600ms))
            trafficFragments.append("lead600 \(leading600Text) / \(leadingPackets600ms)")
        }
        if let burstLargePacketCount = sample.burstLargePacketCount,
           let burstUdpPacketCount = sample.burstUdpPacketCount,
           let burstTcpPacketCount = sample.burstTcpPacketCount {
            trafficFragments.append("burst large \(burstLargePacketCount) udp \(burstUdpPacketCount) tcp \(burstTcpPacketCount)")
        }
        if let burstQuicInitialCount = sample.burstQuicInitialCount, burstQuicInitialCount > 0 {
            trafficFragments.append("burst quic initial \(burstQuicInitialCount)")
        }

        if !trafficFragments.isEmpty {
            lines.append(trafficFragments.joined(separator: " · "))
        }

        let endpointSummary = endpointSummary(for: sample)
        let hostHintSummary = hostHintSummary(for: sample)
        if let endpointSummary, let hostHintSummary {
            lines.append("\(endpointSummary) · \(hostHintSummary)")
        } else if let endpointSummary {
            lines.append(endpointSummary)
        } else if let hostHintSummary {
            lines.append(hostHintSummary)
        }

        let associationSummary = associationAndAttributionSummary(for: sample)
        if let associationSummary {
            lines.append(associationSummary)
        }

        let lineageSummary = lineageAndPathSummary(for: sample)
        if let lineageSummary {
            lines.append(lineageSummary)
        }

        let quicSummary = quicSummary(for: sample)
        if let quicSummary {
            lines.append(quicSummary)
        }

        return lines.isEmpty ? nil : lines.joined(separator: "\n")
    }

    private static func detectionDetailText(for event: DetectionEvent) -> String? {
        guard !event.metadata.isEmpty else {
            return nil
        }

        let sortedPairs = event.metadata
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
        return sortedPairs.joined(separator: " · ")
    }

    private static func endpointSummary(for sample: PacketSample) -> String? {
        let source = endpointLabel(address: sample.sourceAddress, port: sample.sourcePort)
        let destination = endpointLabel(address: sample.destinationAddress, port: sample.destinationPort)

        switch (source, destination) {
        case let (source?, destination?):
            return "\(source) → \(destination)"
        case let (source?, nil):
            return "src \(source)"
        case let (nil, destination?):
            return "dst \(destination)"
        case (nil, nil):
            return nil
        }
    }

    private static func hostHintSummary(for sample: PacketSample) -> String? {
        var fragments: [String] = []

        if let classification = nonEmpty(sample.classification) {
            fragments.append("class \(classification)")
        }
        if let tlsServerName = nonEmpty(sample.tlsServerName) {
            fragments.append("sni \(tlsServerName)")
        }
        if let registrableDomain = nonEmpty(sample.registrableDomain) {
            fragments.append("domain \(registrableDomain)")
        }
        if let dnsQueryName = nonEmpty(sample.dnsQueryName) {
            fragments.append("qname \(dnsQueryName)")
        }
        if let dnsCname = nonEmpty(sample.dnsCname) {
            fragments.append("cname \(dnsCname)")
        }
        if let dnsAnswerAddresses = sample.dnsAnswerAddresses, !dnsAnswerAddresses.isEmpty {
            let shownAnswers = dnsAnswerAddresses.prefix(3).joined(separator: ", ")
            let suffix = dnsAnswerAddresses.count > 3 ? " +" : ""
            fragments.append("answers \(shownAnswers)\(suffix)")
        }

        return fragments.isEmpty ? nil : fragments.joined(separator: " · ")
    }

    private static func associationAndAttributionSummary(for sample: PacketSample) -> String? {
        var fragments: [String] = []

        if let associatedDomain = nonEmpty(sample.associatedDomain) {
            var fragment = "assoc \(associatedDomain)"
            if let associationSource = sample.associationSource {
                fragment += " via \(associationSource.rawValue)"
            }
            if let associationAgeMs = sample.associationAgeMs {
                fragment += " \(associationAgeMs)ms"
            }
            if let associationConfidence = sample.associationConfidence {
                fragment += " \(String(format: "%.2f", associationConfidence))"
            }
            fragments.append(fragment)
        }

        if let serviceFamily = nonEmpty(sample.serviceFamily) {
            var fragment = "service \(serviceFamily)"
            if let serviceFamilyConfidence = sample.serviceFamilyConfidence {
                fragment += " \(String(format: "%.2f", serviceFamilyConfidence))"
            }
            if let serviceAttributionSourceMask = sample.serviceAttributionSourceMask {
                fragment += " mask 0x\(String(serviceAttributionSourceMask, radix: 16))"
            }
            fragments.append(fragment)
        }

        return fragments.isEmpty ? nil : fragments.joined(separator: " · ")
    }

    private static func lineageAndPathSummary(for sample: PacketSample) -> String? {
        var fragments: [String] = []

        if let lineageID = sample.lineageID {
            var fragment = "lineage \(String(lineageID, radix: 16))"
            if let lineageGeneration = sample.lineageGeneration {
                fragment += " g\(lineageGeneration)"
            }
            if let lineageAgeMs = sample.lineageAgeMs {
                fragment += " age \(lineageAgeMs)ms"
            }
            if let lineageReuseGapMs = sample.lineageReuseGapMs {
                fragment += " gap \(lineageReuseGapMs)ms"
            }
            if let lineageReopenCount = sample.lineageReopenCount {
                fragment += " reopen \(lineageReopenCount)"
            }
            if let lineageSiblingCount = sample.lineageSiblingCount {
                fragment += " sib \(lineageSiblingCount)"
            }
            fragments.append(fragment)
        }

        if let pathSummary = pathRegimeSummary(sample) {
            fragments.append(pathSummary)
        }

        return fragments.isEmpty ? nil : fragments.joined(separator: " · ")
    }

    private static func quicSummary(for sample: PacketSample) -> String? {
        var fragments: [String] = []

        if let quicVersion = sample.quicVersion {
            fragments.append("quic v\(quicVersion)")
        }
        if let quicPacketType = nonEmpty(sample.quicPacketType) {
            fragments.append("type \(quicPacketType)")
        }
        if let destinationCID = nonEmpty(sample.quicDestinationConnectionId) {
            fragments.append("dcid \(trimmedIdentifier(destinationCID))")
        }
        if let sourceCID = nonEmpty(sample.quicSourceConnectionId) {
            fragments.append("scid \(trimmedIdentifier(sourceCID))")
        }

        return fragments.isEmpty ? nil : fragments.joined(separator: " · ")
    }

    private static func pathRegimeSummary(_ sample: PacketSample) -> String? {
        guard let pathEpoch = sample.pathEpoch else {
            return nil
        }

        var fragments = ["path \(pathEpoch)"]
        if let interfaceClass = sample.pathInterfaceClass {
            fragments.append(interfaceClass.rawValue)
        }
        if let pathIsExpensive = sample.pathIsExpensive {
            fragments.append(pathIsExpensive ? "expensive" : "not-expensive")
        }
        if let pathIsConstrained = sample.pathIsConstrained {
            fragments.append(pathIsConstrained ? "constrained" : "unconstrained")
        }
        if let pathSupportsDNS = sample.pathSupportsDNS {
            fragments.append(pathSupportsDNS ? "dns" : "no-dns")
        }
        if sample.pathChangedRecently == true {
            fragments.append("recent-change")
        }
        return fragments.joined(separator: " · ")
    }

    private static func endpointLabel(address: String?, port: UInt16?) -> String? {
        guard let address = nonEmpty(address) else {
            return nil
        }
        if let port {
            return "\(address):\(port)"
        }
        return address
    }

    private static func trimmedIdentifier(_ value: String) -> String {
        guard value.count > 12 else {
            return value
        }
        return "\(value.prefix(6))…\(value.suffix(4))"
    }

    private static func hasHostHints(_ sample: PacketSample) -> Bool {
        nonEmpty(sample.classification) != nil ||
            nonEmpty(sample.tlsServerName) != nil ||
            nonEmpty(sample.registrableDomain) != nil ||
            nonEmpty(sample.dnsQueryName) != nil ||
            nonEmpty(sample.dnsCname) != nil
    }

    private static func hasDNSAnswers(_ sample: PacketSample) -> Bool {
        !(sample.dnsAnswerAddresses?.isEmpty ?? true)
    }

    private static func hasDNSAssociation(_ sample: PacketSample) -> Bool {
        nonEmpty(sample.associatedDomain) != nil
    }

    private static func hasLineage(_ sample: PacketSample) -> Bool {
        sample.lineageID != nil
    }

    private static func hasPathRegime(_ sample: PacketSample) -> Bool {
        sample.pathEpoch != nil
    }

    private static func hasServiceAttribution(_ sample: PacketSample) -> Bool {
        nonEmpty(sample.serviceFamily) != nil
    }

    private static func hasQUICIdentity(_ sample: PacketSample) -> Bool {
        sample.quicVersion != nil ||
            nonEmpty(sample.quicPacketType) != nil ||
            nonEmpty(sample.quicDestinationConnectionId) != nil ||
            nonEmpty(sample.quicSourceConnectionId) != nil
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value else {
            return nil
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }

}

private enum VPNStressError: LocalizedError {
    case missingTunnelConnection
    case tunnelDidNotConnect
    case tunnelDidNotDisconnect

    var errorDescription: String? {
        switch self {
        case .missingTunnelConnection:
            return "No tunnel connection is available."
        case .tunnelDidNotConnect:
            return "The tunnel did not reach Connected before the stress run timed out."
        case .tunnelDidNotDisconnect:
            return "The tunnel did not disconnect before the adaptive DNS restart timed out."
        }
    }
}

private struct VPNStressRunner {
    private struct Scenario: Sendable {
        enum Kind: Sendable {
            case captivePortal
            case publicWiFi
            case cellular
            case fiveG
            case loss
            case wifi
            case slowWiFi
            case udpTorture
            case quicTorture
            case tcpChurn
            case cancellationStorm
            case sustainedMixed
        }

        enum EnvironmentRequirement: Sendable {
            case any
            case wifi
            case cellular
            case captivePortal
        }

        let id: String
        let name: String
        let condition: String
        let kind: Kind
        let rounds: Int
        let concurrency: Int
        let timeoutSeconds: TimeInterval
        let interRoundDelayMs: UInt64
        let allowsExpectedFailures: Bool

        nonisolated var environmentRequirement: EnvironmentRequirement {
            switch kind {
            case .captivePortal:
                return .captivePortal
            case .publicWiFi, .wifi, .slowWiFi:
                return .wifi
            case .cellular, .fiveG:
                return .cellular
            case .loss, .udpTorture, .quicTorture, .tcpChurn, .cancellationStorm, .sustainedMixed:
                return .any
            }
        }

        nonisolated var requiresSystemDNS: Bool {
            switch kind {
            case .udpTorture:
                return false
            case .captivePortal,
                    .publicWiFi,
                    .cellular,
                    .fiveG,
                    .loss,
                    .wifi,
                    .slowWiFi,
                    .quicTorture,
                    .tcpChurn,
                    .cancellationStorm,
                    .sustainedMixed:
                return true
            }
        }
    }

    private struct ProbeResult: Sendable {
        let name: String
        let passed: Bool
        let durationMs: Int
        let detail: String
    }

    private let telemetryClient: TunnelTelemetryClient
    private let appGroupID: String

    nonisolated init(telemetryClient: TunnelTelemetryClient, appGroupID: String) {
        self.telemetryClient = telemetryClient
        self.appGroupID = appGroupID
    }

    nonisolated func run(
        connection: NEVPNConnection,
        dnsMode: String,
        effectiveDNS: String,
        pathSummary: String,
        dnsPolicyProvidesResolver: Bool,
        progress: @escaping @Sendable (VPNStressReport) async -> Void
    ) async throws -> VPNStressReport {
        let startedAt = Date()
        var report = VPNStressReport(
            isRunning: true,
            startedAt: startedAt,
            completedAt: nil,
            activeScenario: nil,
            progressText: "Starting",
            dnsMode: dnsMode,
            effectiveDNS: effectiveDNS,
            pathSummary: pathSummary,
            rows: [],
            totalProbes: 0,
            failedProbes: 0,
            blockedProbes: 0,
            savedReportPath: nil
        )

        for (index, scenario) in Self.scenarios.enumerated() {
            try Task.checkCancellation()
            report.activeScenario = scenario.name
            report.progressText = "\(index + 1)/\(Self.scenarios.count) · \(scenario.name)"
            await progress(report)

            let row = await runScenario(
                scenario,
                connection: connection,
                dnsPolicyProvidesResolver: dnsPolicyProvidesResolver
            )
            report.rows.append(row)
            report.totalProbes += row.probeCount
            report.failedProbes += row.failureCount
            if row.blocked {
                report.blockedProbes += row.probeCount
            }
            await progress(report)
        }

        report.isRunning = false
        report.activeScenario = nil
        report.completedAt = Date()
        let blockedSuffix = report.blockedProbes == 0 ? "" : " · \(report.blockedProbes) blocked"
        report.progressText = report.failedProbes == 0
            ? "PASS · \(report.totalProbes) probes\(blockedSuffix)"
            : "FAIL · \(report.failedProbes)/\(report.totalProbes) probes\(blockedSuffix)"
        let savedReportPath = Self.stressReportFileName(for: report.completedAt ?? Date())
        report.savedReportPath = savedReportPath
        do {
            try persist(report, fileName: savedReportPath)
        } catch {
            report.savedReportPath = nil
        }
        await progress(report)
        return report
    }

    nonisolated private func runScenario(
        _ scenario: Scenario,
        connection: NEVPNConnection,
        dnsPolicyProvidesResolver: Bool
    ) async -> VPNStressScenarioRow {
        let startedAt = Date()
        let baselineTelemetry = try? await telemetrySnapshot(connection: connection, timeoutSeconds: min(1, scenario.timeoutSeconds))
        var results: [ProbeResult] = []
        results.reserveCapacity(scenario.rounds * max(1, scenario.concurrency))
        let environmentResult = await environmentProbe(
            for: scenario,
            dnsPolicyProvidesResolver: dnsPolicyProvidesResolver
        )
        results.append(environmentResult)

        guard environmentResult.passed else {
            return VPNStressScenarioRow(
                id: scenario.id,
                name: scenario.name,
                condition: scenario.condition,
                passed: false,
                blocked: true,
                probeCount: results.count,
                failureCount: 0,
                durationMs: elapsedMs(since: startedAt),
                detail: "environment blocked · \(environmentResult.detail)"
            )
        }

        for round in 0..<scenario.rounds {
            if Task.isCancelled {
                break
            }

            let roundResults = await withTaskGroup(of: ProbeResult.self) { group in
                for lane in 0..<scenario.concurrency {
                    group.addTask {
                        await runProbe(for: scenario, round: round, lane: lane)
                    }
                }

                var values: [ProbeResult] = []
                for await value in group {
                    values.append(value)
                }
                return values
            }
            results.append(contentsOf: roundResults)

            if scenario.interRoundDelayMs > 0 {
                try? await Task.sleep(for: .milliseconds(scenario.interRoundDelayMs))
            }
        }

        let telemetryResult = await telemetryProbe(connection: connection, baseline: baselineTelemetry, timeoutSeconds: scenario.timeoutSeconds)
        results.append(telemetryResult)

        let failures = results.filter { !$0.passed }
        let failureCount = failures.count
        let slowest = results.max { $0.durationMs < $1.durationMs }
        let durations = results.map(\.durationMs).sorted()
        let p95Index = durations.isEmpty ? 0 : min(durations.count - 1, Int((Double(durations.count - 1) * 0.95).rounded()))
        let p95 = durations.isEmpty ? 0 : durations[p95Index]
        let telemetrySummary = telemetryResult.detail
        let firstFailures = failures.prefix(8).map { "\($0.name): \($0.detail)" }
        let detail: String
        if firstFailures.isEmpty {
            detail = "p95 \(p95)ms · slowest \(slowest?.durationMs ?? 0)ms · \(slowest?.name ?? "none") · \(telemetrySummary)"
        } else {
            detail = "p95 \(p95)ms · " + firstFailures.joined(separator: " · ")
        }

        return VPNStressScenarioRow(
            id: scenario.id,
            name: scenario.name,
            condition: scenario.condition,
            passed: failureCount == 0,
            blocked: false,
            probeCount: results.count,
            failureCount: failureCount,
            durationMs: elapsedMs(since: startedAt),
            detail: detail
        )
    }

    nonisolated private func environmentProbe(
        for scenario: Scenario,
        dnsPolicyProvidesResolver: Bool
    ) async -> ProbeResult {
        let startedAt = Date()
        switch scenario.environmentRequirement {
        case .any:
            guard scenario.requiresSystemDNS && !dnsPolicyProvidesResolver else {
                return ProbeResult(
                    name: "environment-\(scenario.id)",
                    passed: true,
                    durationMs: elapsedMs(since: startedAt),
                    detail: dnsPolicyProvidesResolver ? "Explicit DNS policy installed" : "No physical path precondition"
                )
            }
            let path = await sampleCurrentPath(timeoutSeconds: min(2.0, scenario.timeoutSeconds))
            return ProbeResult(
                name: "environment-\(scenario.id)",
                passed: path.status == .satisfied && path.supportsDNS,
                durationMs: elapsedMs(since: startedAt),
                detail: environmentDetail(path: path, suffix: "; system DNS required")
            )

        case .wifi:
            let path = await sampleCurrentPath(timeoutSeconds: min(2.0, scenario.timeoutSeconds))
            let passed = path.status == .satisfied
                && path.usesInterfaceType(.wifi)
                && (!scenario.requiresSystemDNS || dnsPolicyProvidesResolver || path.supportsDNS)
            let caveat: String
            switch scenario.kind {
            case .publicWiFi:
                caveat = dnsPolicyProvidesResolver
                    ? "; iOS does not expose whether this Wi-Fi is public, only that Wi-Fi is active; explicit DNS policy installed"
                    : "; iOS does not expose whether this Wi-Fi is public, only that Wi-Fi is active"
            default:
                caveat = dnsPolicyProvidesResolver ? "; explicit DNS policy installed" : ""
            }
            return ProbeResult(
                name: "environment-\(scenario.id)",
                passed: passed,
                durationMs: elapsedMs(since: startedAt),
                detail: environmentDetail(path: path, suffix: caveat)
            )

        case .cellular:
            let path = await sampleCurrentPath(timeoutSeconds: min(2.0, scenario.timeoutSeconds))
            let passed = path.status == .satisfied
                && path.usesInterfaceType(.cellular)
                && (!scenario.requiresSystemDNS || dnsPolicyProvidesResolver || path.supportsDNS)
            let caveat: String
            switch scenario.kind {
            case .fiveG:
                caveat = dnsPolicyProvidesResolver
                    ? "; iOS Network.framework exposes cellular, not radio generation; explicit DNS policy installed"
                    : "; iOS Network.framework exposes cellular, not radio generation"
            default:
                caveat = dnsPolicyProvidesResolver ? "; explicit DNS policy installed" : ""
            }
            return ProbeResult(
                name: "environment-\(scenario.id)",
                passed: passed,
                durationMs: elapsedMs(since: startedAt),
                detail: environmentDetail(path: path, suffix: caveat)
            )

        case .captivePortal:
            return await captivePortalCoverageProbe(timeoutSeconds: min(4.0, scenario.timeoutSeconds))
        }
    }

    nonisolated private func environmentDetail(path: Network.NWPath, suffix: String = "") -> String {
        var detail = Self.pathSummary(path)
        if !path.supportsDNS {
            detail += "; no DNS server configured on this path"
        }
        detail += suffix
        return detail
    }

    nonisolated private func sampleCurrentPath(timeoutSeconds: TimeInterval) async -> Network.NWPath {
        await withCheckedContinuation { continuation in
            let monitor = Network.NWPathMonitor()
            let queue = DispatchQueue(label: "com.vpnbridge.example.stress.path", qos: .utility)
            let gate = OneShot<Network.NWPath>(continuation)
            monitor.pathUpdateHandler = { path in
                if path.status == .satisfied {
                    monitor.cancel()
                    gate.resume(path)
                }
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeoutSeconds) {
                let path = monitor.currentPath
                monitor.cancel()
                gate.resume(path)
            }
        }
    }

    nonisolated private func captivePortalCoverageProbe(timeoutSeconds: TimeInterval) async -> ProbeResult {
        let startedAt = Date()
        let url = URL(string: "http://captive.apple.com/hotspot-detect.html")!
        do {
            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = timeoutSeconds

            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = timeoutSeconds
            configuration.timeoutIntervalForResource = timeoutSeconds
            configuration.waitsForConnectivity = false
            let session = URLSession(configuration: configuration)
            defer { session.invalidateAndCancel() }

            let (data, response) = try await session.data(for: request)
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
            let body = String(data: data.prefix(256), encoding: .utf8) ?? ""
            let cleanAppleSuccess = statusCode == 200 && body.contains("Success")
            return ProbeResult(
                name: "environment-captive-portal",
                passed: !cleanAppleSuccess,
                durationMs: elapsedMs(since: startedAt),
                detail: cleanAppleSuccess
                    ? "Clean Apple captive probe; captive portal condition is not covered"
                    : "Captive-like response observed: HTTP \(statusCode)"
            )
        } catch {
            return ProbeResult(
                name: "environment-captive-portal",
                passed: false,
                durationMs: elapsedMs(since: startedAt),
                detail: "Could not prove captive portal condition: \(error.localizedDescription)"
            )
        }
    }

    nonisolated private static func pathSummary(_ path: Network.NWPath) -> String {
        var interfaces: [String] = []
        if path.usesInterfaceType(.wifi) { interfaces.append("wifi") }
        if path.usesInterfaceType(.cellular) { interfaces.append("cellular") }
        if path.usesInterfaceType(.wiredEthernet) { interfaces.append("wired") }
        if path.usesInterfaceType(.loopback) { interfaces.append("loopback") }
        if interfaces.isEmpty { interfaces.append("other") }

        let status: String
        switch path.status {
        case .satisfied:
            status = "satisfied"
        case .unsatisfied:
            status = "unsatisfied"
        case .requiresConnection:
            status = "requires-connection"
        @unknown default:
            status = "unknown"
        }

        let interfaceSummary = interfaces.joined(separator: "/")
        return "path \(status), interfaces \(interfaceSummary), expensive \(path.isExpensive), constrained \(path.isConstrained), dns \(path.supportsDNS)"
    }

    nonisolated private func runProbe(for scenario: Scenario, round: Int, lane: Int) async -> ProbeResult {
        switch scenario.kind {
        case .captivePortal:
            if lane % 2 == 0 {
                return await httpProbe(
                    name: "captive-apple-\(round)-\(lane)",
                    url: URL(string: "http://captive.apple.com/hotspot-detect.html")!,
                    timeoutSeconds: scenario.timeoutSeconds,
                    expectedBodyFragment: "Success"
                )
            }
            return await httpProbe(
                name: "captive-https-control-\(round)-\(lane)",
                url: URL(string: "https://www.apple.com/library/test/success.html")!,
                timeoutSeconds: scenario.timeoutSeconds,
                expectedBodyFragment: nil
            )

        case .publicWiFi:
            return await mixedInternetProbe(
                name: "public-wifi-\(round)-\(lane)",
                hostIndex: round + lane,
                timeoutSeconds: scenario.timeoutSeconds,
                includeUDP: lane % 3 == 0
            )

        case .cellular:
            return await mixedInternetProbe(
                name: "cellular-\(round)-\(lane)",
                hostIndex: round * 3 + lane,
                timeoutSeconds: scenario.timeoutSeconds,
                includeUDP: lane % 2 == 0
            )

        case .fiveG:
            return await mixedInternetProbe(
                name: "5g-burst-\(round)-\(lane)",
                hostIndex: round * scenario.concurrency + lane,
                timeoutSeconds: scenario.timeoutSeconds,
                includeUDP: lane % 4 == 0
            )

        case .loss:
            if lane % 2 == 0 {
                return await expectedFailureProbe(
                    name: "loss-blackhole-\(round)-\(lane)",
                    timeoutSeconds: min(3.0, scenario.timeoutSeconds)
                )
            }
            return await mixedInternetProbe(
                name: "loss-recovery-\(round)-\(lane)",
                hostIndex: round + lane,
                timeoutSeconds: scenario.timeoutSeconds,
                includeUDP: false
            )

        case .wifi:
            return await mixedInternetProbe(
                name: "wifi-\(round)-\(lane)",
                hostIndex: round + lane,
                timeoutSeconds: scenario.timeoutSeconds,
                includeUDP: lane == 0
            )

        case .slowWiFi:
            try? await Task.sleep(for: .milliseconds(UInt64(250 + (lane * 75))))
            return await mixedInternetProbe(
                name: "slow-wifi-\(round)-\(lane)",
                hostIndex: round + lane,
                timeoutSeconds: scenario.timeoutSeconds,
                includeUDP: lane == 0
            )

        case .udpTorture:
            return await udpDNSRoundTripProbe(
                name: "udp-torture-\(round)-\(lane)",
                resolverIndex: round + lane,
                queryIndex: round * scenario.concurrency + lane,
                timeoutSeconds: scenario.timeoutSeconds
            )

        case .quicTorture:
            return await quicProbe(
                name: "quic-torture-\(round)-\(lane)",
                hostIndex: round * scenario.concurrency + lane,
                timeoutSeconds: scenario.timeoutSeconds
            )

        case .tcpChurn:
            if lane % 4 == 0 {
                return await largeHTTPProbe(
                    name: "tcp-churn-large-\(round)-\(lane)",
                    timeoutSeconds: scenario.timeoutSeconds
                )
            }
            return await tcpProbe(
                name: "tcp-churn-\(round)-\(lane)",
                host: Self.tcpHosts[abs(round + lane) % Self.tcpHosts.count],
                port: 443,
                timeoutSeconds: scenario.timeoutSeconds
            )

        case .cancellationStorm:
            return await cancellationStormProbe(
                name: "cancel-storm-\(round)-\(lane)",
                hostIndex: round * scenario.concurrency + lane,
                timeoutSeconds: scenario.timeoutSeconds
            )

        case .sustainedMixed:
            if lane % 5 == 0 {
                try? await Task.sleep(for: .milliseconds(UInt64(100 + lane * 20)))
            }
            return await mixedInternetProbe(
                name: "sustained-\(round)-\(lane)",
                hostIndex: round * scenario.concurrency + lane,
                timeoutSeconds: scenario.timeoutSeconds,
                includeUDP: lane % 4 == 0
            )
        }
    }

    nonisolated private func mixedInternetProbe(
        name: String,
        hostIndex: Int,
        timeoutSeconds: TimeInterval,
        includeUDP: Bool
    ) async -> ProbeResult {
        if includeUDP {
            return await udpDNSRoundTripProbe(
                name: "\(name)-udp-dns",
                resolverIndex: hostIndex,
                queryIndex: hostIndex,
                timeoutSeconds: timeoutSeconds
            )
        }

        if hostIndex % 11 == 0 {
            return await quicProbe(name: "\(name)-quic", hostIndex: hostIndex, timeoutSeconds: timeoutSeconds)
        }
        if hostIndex % 9 == 0 {
            return await largeHTTPProbe(name: "\(name)-large-https", timeoutSeconds: timeoutSeconds)
        }
        if hostIndex % 4 == 1 {
            return await tcpProbe(
                name: "\(name)-tcp-443",
                host: Self.tcpHosts[abs(hostIndex) % Self.tcpHosts.count],
                port: 443,
                timeoutSeconds: timeoutSeconds
            )
        }

        return await httpProbe(
            name: "\(name)-https",
            url: URL(string: Self.httpsTargets[abs(hostIndex) % Self.httpsTargets.count])!,
            timeoutSeconds: timeoutSeconds,
            expectedBodyFragment: nil
        )
    }

    nonisolated private func httpProbe(
        name: String,
        url: URL,
        timeoutSeconds: TimeInterval,
        expectedBodyFragment: String?
    ) async -> ProbeResult {
        let attempts = expectedBodyFragment == nil ? 2 : 1
        var last = ProbeResult(name: name, passed: false, durationMs: 0, detail: "not started")
        for attempt in 1...attempts {
            let result = await httpProbeAttempt(
                name: attempts == 1 ? name : "\(name)-attempt-\(attempt)",
                url: url,
                timeoutSeconds: timeoutSeconds,
                expectedBodyFragment: expectedBodyFragment
            )
            if result.passed {
                if attempt == 1 {
                    return ProbeResult(name: name, passed: true, durationMs: result.durationMs, detail: result.detail)
                }
                return ProbeResult(
                    name: name,
                    passed: true,
                    durationMs: result.durationMs,
                    detail: "passed after \(attempt) attempts; \(result.detail)"
                )
            }
            last = result
            if attempt < attempts {
                try? await Task.sleep(for: .milliseconds(UInt64(250 * attempt)))
            }
        }

        return ProbeResult(
            name: name,
            passed: false,
            durationMs: last.durationMs,
            detail: "failed after \(attempts) attempts; \(last.detail)"
        )
    }

    nonisolated private func httpProbeAttempt(
        name: String,
        url: URL,
        timeoutSeconds: TimeInterval,
        expectedBodyFragment: String?
    ) async -> ProbeResult {
        let startedAt = Date()
        do {
            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = timeoutSeconds

            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = timeoutSeconds
            configuration.timeoutIntervalForResource = timeoutSeconds
            configuration.waitsForConnectivity = false
            let session = URLSession(configuration: configuration)
            defer { session.invalidateAndCancel() }

            let (data, response) = try await session.data(for: request)
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
            var passed = (200..<400).contains(statusCode) || statusCode == 204
            if let expectedBodyFragment {
                let body = String(decoding: data, as: UTF8.self)
                passed = passed && body.contains(expectedBodyFragment)
            }
            return ProbeResult(
                name: name,
                passed: passed,
                durationMs: elapsedMs(since: startedAt),
                detail: "HTTP \(statusCode) \(url.host ?? url.absoluteString)"
            )
        } catch {
            return ProbeResult(
                name: name,
                passed: false,
                durationMs: elapsedMs(since: startedAt),
                detail: error.localizedDescription
            )
        }
    }

    nonisolated private func tcpProbe(name: String, host: String, port: UInt16, timeoutSeconds: TimeInterval) async -> ProbeResult {
        let startedAt = Date()
        return await withCheckedContinuation { continuation in
            let gate = OneShot<ProbeResult>(continuation)
            guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
                gate.resume(ProbeResult(name: name, passed: false, durationMs: 0, detail: "Invalid port"))
                return
            }

            let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
            let queue = DispatchQueue(label: "relative.example.stress.tcp.\(UUID().uuidString)", qos: .utility)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.cancel()
                    gate.resume(ProbeResult(name: name, passed: true, durationMs: elapsedMs(since: startedAt), detail: "TCP ready \(host):\(port)"))
                case .failed(let error):
                    connection.cancel()
                    gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: error.localizedDescription))
                case .waiting(let error):
                    if elapsedMs(since: startedAt) > Int(timeoutSeconds * 1000) {
                        connection.cancel()
                        gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: "waiting \(error.localizedDescription)"))
                    }
                case .cancelled:
                    break
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeoutSeconds) {
                connection.cancel()
                gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: "timeout"))
            }
        }
    }

    nonisolated private func udpDNSRoundTripProbe(
        name: String,
        resolverIndex: Int,
        queryIndex: Int,
        timeoutSeconds: TimeInterval
    ) async -> ProbeResult {
        let attempts = 3
        var last = ProbeResult(name: name, passed: false, durationMs: 0, detail: "not started")
        var totalDuration = 0

        for attempt in 1...attempts {
            let result = await udpDNSRoundTripAttempt(
                name: "\(name)-attempt-\(attempt)",
                resolverIndex: resolverIndex + attempt - 1,
                queryIndex: queryIndex + attempt - 1,
                timeoutSeconds: timeoutSeconds
            )
            totalDuration += result.durationMs
            if result.passed {
                if attempt == 1 {
                    return ProbeResult(name: name, passed: true, durationMs: result.durationMs, detail: result.detail)
                }
                return ProbeResult(
                    name: name,
                    passed: true,
                    durationMs: totalDuration,
                    detail: "passed after \(attempt) attempts; \(result.detail)"
                )
            }
            last = result
            if attempt < attempts {
                let delay = UInt64(250 * attempt)
                totalDuration += Int(delay)
                try? await Task.sleep(for: .milliseconds(delay))
            }
        }

        return ProbeResult(
            name: name,
            passed: false,
            durationMs: totalDuration,
            detail: "failed after \(attempts) attempts; \(last.detail)"
        )
    }

    nonisolated private func udpDNSRoundTripAttempt(
        name: String,
        resolverIndex: Int,
        queryIndex: Int,
        timeoutSeconds: TimeInterval
    ) async -> ProbeResult {
        let startedAt = Date()
        return await withCheckedContinuation { continuation in
            let gate = OneShot<ProbeResult>(continuation)
            let resolver = Self.udpResolvers[abs(resolverIndex) % Self.udpResolvers.count]
            let query = Self.dnsQueries[abs(queryIndex) % Self.dnsQueries.count]
            let transactionID = UInt16(truncatingIfNeeded: 0x4000 + abs(queryIndex))
            let payload = Self.dnsQueryPayload(transactionID: transactionID, labels: query.split(separator: ".").map(String.init))
            let connection = NWConnection(host: NWEndpoint.Host(resolver), port: 53, using: .udp)
            let queue = DispatchQueue(label: "relative.example.stress.udp.\(UUID().uuidString)", qos: .utility)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: payload, completion: .contentProcessed { error in
                        if let error {
                            connection.cancel()
                            gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: error.localizedDescription))
                        } else {
                            connection.receiveMessage { data, _, _, receiveError in
                                connection.cancel()
                                if let receiveError {
                                    gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: receiveError.localizedDescription))
                                    return
                                }
                                guard let data, data.count >= 12 else {
                                    gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: "DNS response missing"))
                                    return
                                }
                                let responseID = (UInt16(data[0]) << 8) | UInt16(data[1])
                                let isResponse = (data[2] & 0x80) != 0
                                let rcode = data[3] & 0x0F
                                let passed = responseID == transactionID && isResponse && rcode == 0
                                let detail = "UDP DNS \(data.count)b \(resolver) \(query) rcode=\(rcode)"
                                gate.resume(ProbeResult(name: name, passed: passed, durationMs: elapsedMs(since: startedAt), detail: detail))
                            }
                        }
                    })
                case .failed(let error):
                    connection.cancel()
                    gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: error.localizedDescription))
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeoutSeconds) {
                connection.cancel()
                gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: "timeout"))
            }
        }
    }

    nonisolated private func quicProbe(name: String, hostIndex: Int, timeoutSeconds: TimeInterval) async -> ProbeResult {
        let startedAt = Date()
        let host = Self.quicHosts[abs(hostIndex) % Self.quicHosts.count]
        return await withCheckedContinuation { continuation in
            let gate = OneShot<ProbeResult>(continuation)
            let parameters = NWParameters.quic(alpn: ["h3"])
            let connection = NWConnection(host: NWEndpoint.Host(host), port: 443, using: parameters)
            let queue = DispatchQueue(label: "relative.example.stress.quic.\(UUID().uuidString)", qos: .utility)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.cancel()
                    gate.resume(ProbeResult(name: name, passed: true, durationMs: elapsedMs(since: startedAt), detail: "QUIC ready \(host):443 h3"))
                case .failed(let error):
                    connection.cancel()
                    gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: error.localizedDescription))
                case .waiting(let error):
                    if elapsedMs(since: startedAt) > Int(timeoutSeconds * 1000) {
                        connection.cancel()
                        gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: "waiting \(error.localizedDescription)"))
                    }
                case .cancelled:
                    break
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeoutSeconds) {
                connection.cancel()
                gate.resume(ProbeResult(name: name, passed: false, durationMs: elapsedMs(since: startedAt), detail: "QUIC timeout \(host):443"))
            }
        }
    }

    nonisolated private func largeHTTPProbe(name: String, timeoutSeconds: TimeInterval) async -> ProbeResult {
        let startedAt = Date()
        let url = URL(string: "https://speed.cloudflare.com/__down?bytes=262144")!
        do {
            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = timeoutSeconds

            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = timeoutSeconds
            configuration.timeoutIntervalForResource = timeoutSeconds
            configuration.waitsForConnectivity = false
            let session = URLSession(configuration: configuration)
            defer { session.invalidateAndCancel() }

            let (data, response) = try await session.data(for: request)
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
            let passed = (200..<300).contains(statusCode) && data.count >= 131_072
            return ProbeResult(
                name: name,
                passed: passed,
                durationMs: elapsedMs(since: startedAt),
                detail: "HTTPS \(statusCode) \(data.count)b cloudflare-speed"
            )
        } catch {
            return ProbeResult(
                name: name,
                passed: false,
                durationMs: elapsedMs(since: startedAt),
                detail: error.localizedDescription
            )
        }
    }

    nonisolated private func cancellationStormProbe(name: String, hostIndex: Int, timeoutSeconds: TimeInterval) async -> ProbeResult {
        let startedAt = Date()
        let cancelCount = 10
        let tasks = (0..<cancelCount).map { index in
            Task {
                await expectedFailureProbe(
                    name: "\(name)-cancelled-\(index)",
                    timeoutSeconds: min(10.0, timeoutSeconds + 4.0)
                )
            }
        }

        try? await Task.sleep(for: .milliseconds(150))
        tasks.forEach { $0.cancel() }
        for task in tasks {
            _ = await task.value
        }

        async let recoveryHTTP = httpProbe(
            name: "\(name)-recovery-https",
            url: URL(string: Self.httpsTargets[abs(hostIndex) % Self.httpsTargets.count])!,
            timeoutSeconds: timeoutSeconds,
            expectedBodyFragment: nil
        )
        async let recoveryUDP = udpDNSRoundTripProbe(
            name: "\(name)-recovery-udp",
            resolverIndex: hostIndex,
            queryIndex: hostIndex,
            timeoutSeconds: timeoutSeconds
        )
        let results = await [recoveryHTTP, recoveryUDP]
        let failures = results.filter { !$0.passed }
        let passed = failures.isEmpty
        let detail = passed
            ? "Cancelled \(cancelCount) blackhole requests; HTTP and UDP recovered"
            : failures.map { "\($0.name): \($0.detail)" }.joined(separator: " · ")
        return ProbeResult(
            name: name,
            passed: passed,
            durationMs: elapsedMs(since: startedAt),
            detail: detail
        )
    }

    nonisolated private func expectedFailureProbe(name: String, timeoutSeconds: TimeInterval) async -> ProbeResult {
        let startedAt = Date()
        let target = URL(string: "http://203.0.113.1:81/")!
        do {
            var request = URLRequest(url: target)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = timeoutSeconds

            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = timeoutSeconds
            configuration.timeoutIntervalForResource = timeoutSeconds
            configuration.waitsForConnectivity = false
            let session = URLSession(configuration: configuration)
            defer { session.invalidateAndCancel() }

            let (_, response) = try await session.data(for: request)
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
            return ProbeResult(
                name: name,
                passed: false,
                durationMs: elapsedMs(since: startedAt),
                detail: "Blackhole endpoint returned HTTP \(statusCode)"
            )
        } catch {
            return ProbeResult(
                name: name,
                passed: true,
                durationMs: elapsedMs(since: startedAt),
                detail: "Expected failure: \(error.localizedDescription)"
            )
        }
    }

    nonisolated private func telemetryProbe(
        connection: NEVPNConnection,
        baseline: TunnelTelemetrySnapshot?,
        timeoutSeconds: TimeInterval
    ) async -> ProbeResult {
        let startedAt = Date()
        do {
            try await telemetryFlush(connection: connection, timeoutSeconds: min(3, timeoutSeconds))
            let snapshot = try await telemetrySnapshot(connection: connection, timeoutSeconds: timeoutSeconds)
            let acceptedDelta = max(0, snapshot.acceptedBatches - (baseline?.acceptedBatches ?? 0))
            let droppedDelta = max(0, snapshot.droppedBatches - (baseline?.droppedBatches ?? 0))
            let skippedDelta = max(0, snapshot.skippedBatches - (baseline?.skippedBatches ?? 0))
            let evaluatedBatches = acceptedDelta + droppedDelta + skippedDelta
            let droppedRate = evaluatedBatches > 0 ? Double(droppedDelta) / Double(evaluatedBatches) : 0
            let droppedRateText = String(format: "%.1f%%", droppedRate * 100)
            let scope = baseline == nil ? "cumulative" : "delta"
            let detail = "samples \(snapshot.samples.count), \(scope) accepted \(acceptedDelta), dropped \(droppedDelta) (\(droppedRateText)), skipped \(skippedDelta), queued \(snapshot.queuedBatches)"
            let hasTelemetry = !snapshot.samples.isEmpty || acceptedDelta > 0 || snapshot.acceptedBatches > 0
            let telemetryShedIsHealthy = droppedRate <= 0.10
            return ProbeResult(
                name: "telemetry-snapshot",
                passed: hasTelemetry && telemetryShedIsHealthy,
                durationMs: elapsedMs(since: startedAt),
                detail: telemetryShedIsHealthy ? detail : "telemetry shed too high; \(detail)"
            )
        } catch {
            return ProbeResult(
                name: "telemetry-snapshot",
                passed: false,
                durationMs: elapsedMs(since: startedAt),
                detail: error.localizedDescription
            )
        }
    }

    nonisolated private func telemetryFlush(
        connection: NEVPNConnection,
        timeoutSeconds: TimeInterval
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await telemetryClient.flushTelemetry(from: connection)
            }
            group.addTask {
                try await Task.sleep(for: .milliseconds(UInt64(timeoutSeconds * 1000)))
                throw CancellationError()
            }
            try await group.next()
            group.cancelAll()
        }
    }

    nonisolated private func telemetrySnapshot(
        connection: NEVPNConnection,
        timeoutSeconds: TimeInterval
    ) async throws -> TunnelTelemetrySnapshot {
        try await withThrowingTaskGroup(of: TunnelTelemetrySnapshot.self) { group in
            group.addTask {
                try await telemetryClient.snapshot(from: connection, packetLimit: 96)
            }
            group.addTask {
                try await Task.sleep(for: .milliseconds(UInt64(timeoutSeconds * 1000)))
                throw CancellationError()
            }
            let first = try await group.next()
            group.cancelAll()
            return first ?? TunnelTelemetrySnapshot.empty
        }
    }

    nonisolated private static func stressReportFileName(for date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        let stamp = formatter.string(from: date)
            .replacingOccurrences(of: ":", with: "-")
        return "stress-\(stamp).json"
    }

    nonisolated private func persist(_ report: VPNStressReport, fileName: String) throws {
        guard let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            throw VPNStressError.missingTunnelConnection
        }
        let directory = root.appendingPathComponent("StressReports", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(fileName, isDirectory: false)
        let payload = Self.jsonObject(from: report)
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url, options: [.atomic])
    }

    nonisolated private static func jsonObject(from report: VPNStressReport) -> [String: Any] {
        let formatter = ISO8601DateFormatter()
        return [
            "isRunning": report.isRunning,
            "startedAt": report.startedAt.map { formatter.string(from: $0) } as Any,
            "completedAt": report.completedAt.map { formatter.string(from: $0) } as Any,
            "activeScenario": report.activeScenario as Any,
            "progressText": report.progressText,
            "dnsMode": report.dnsMode,
            "effectiveDNS": report.effectiveDNS,
            "pathSummary": report.pathSummary,
            "rows": report.rows.map(jsonObject(from:)),
            "totalProbes": report.totalProbes,
            "failedProbes": report.failedProbes,
            "blockedProbes": report.blockedProbes,
            "savedReportPath": report.savedReportPath as Any
        ]
    }

    nonisolated private static func jsonObject(from row: VPNStressScenarioRow) -> [String: Any] {
        [
            "id": row.id,
            "name": row.name,
            "condition": row.condition,
            "passed": row.passed,
            "blocked": row.blocked,
            "probeCount": row.probeCount,
            "failureCount": row.failureCount,
            "durationMs": row.durationMs,
            "detail": row.detail
        ]
    }

    nonisolated private static let httpsTargets = [
        "https://www.apple.com/library/test/success.html",
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://www.google.com/generate_204",
        "https://www.gstatic.com/generate_204"
    ]

    nonisolated private static let tcpHosts = [
        "www.apple.com",
        "www.cloudflare.com",
        "www.google.com",
        "www.gstatic.com"
    ]

    nonisolated private static let udpResolvers = [
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "9.9.9.9"
    ]

    nonisolated private static let dnsQueries = [
        "example.com",
        "apple.com",
        "cloudflare.com",
        "google.com",
        "gstatic.com"
    ]

    nonisolated private static let quicHosts = [
        "www.cloudflare.com",
        "cloudflare.com",
        "www.google.com",
        "www.gstatic.com"
    ]

    nonisolated private static let scenarios: [Scenario] = [
        Scenario(
            id: "captive-portal",
            name: "Captive portal",
            condition: "Requires an actual captive portal; clean networks fail as not covered",
            kind: .captivePortal,
            rounds: 8,
            concurrency: 3,
            timeoutSeconds: 6,
            interRoundDelayMs: 100,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "public-wifi",
            name: "Public Wi-Fi",
            condition: "Requires Wi-Fi path; public-network traits are manual",
            kind: .publicWiFi,
            rounds: 10,
            concurrency: 5,
            timeoutSeconds: 8,
            interRoundDelayMs: 125,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "cellular",
            name: "Cellular",
            condition: "Requires active cellular path",
            kind: .cellular,
            rounds: 10,
            concurrency: 6,
            timeoutSeconds: 10,
            interRoundDelayMs: 100,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "5g",
            name: "5G burst",
            condition: "Requires cellular path; iOS cannot expose radio generation",
            kind: .fiveG,
            rounds: 8,
            concurrency: 16,
            timeoutSeconds: 8,
            interRoundDelayMs: 50,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "loss",
            name: "Loss recovery",
            condition: "Expected blackhole failures + recovery probes",
            kind: .loss,
            rounds: 8,
            concurrency: 6,
            timeoutSeconds: 6,
            interRoundDelayMs: 150,
            allowsExpectedFailures: true
        ),
        Scenario(
            id: "udp-torture",
            name: "UDP torture",
            condition: "Public resolver DNS round trips over UDP",
            kind: .udpTorture,
            rounds: 18,
            concurrency: 16,
            timeoutSeconds: 8,
            interRoundDelayMs: 40,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "quic-torture",
            name: "QUIC torture",
            condition: "HTTP/3 ALPN QUIC handshakes on UDP 443",
            kind: .quicTorture,
            rounds: 12,
            concurrency: 10,
            timeoutSeconds: 8,
            interRoundDelayMs: 60,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "tcp-churn",
            name: "TCP churn",
            condition: "Rapid TCP opens plus larger HTTPS payloads",
            kind: .tcpChurn,
            rounds: 12,
            concurrency: 20,
            timeoutSeconds: 10,
            interRoundDelayMs: 35,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "cancel-storm",
            name: "Cancel storm",
            condition: "Cancelled blackholes followed by HTTP and UDP recovery",
            kind: .cancellationStorm,
            rounds: 8,
            concurrency: 4,
            timeoutSeconds: 10,
            interRoundDelayMs: 150,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "sustained-mixed",
            name: "Sustained mixed",
            condition: "Longer mixed HTTPS, TCP, UDP, QUIC, and payload run",
            kind: .sustainedMixed,
            rounds: 20,
            concurrency: 12,
            timeoutSeconds: 12,
            interRoundDelayMs: 200,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "wifi",
            name: "Wi-Fi",
            condition: "Requires active Wi-Fi path",
            kind: .wifi,
            rounds: 10,
            concurrency: 8,
            timeoutSeconds: 8,
            interRoundDelayMs: 100,
            allowsExpectedFailures: false
        ),
        Scenario(
            id: "slow-wifi",
            name: "Slow Wi-Fi",
            condition: "Requires Wi-Fi path; uses staggered slow-link style probes",
            kind: .slowWiFi,
            rounds: 8,
            concurrency: 3,
            timeoutSeconds: 18,
            interRoundDelayMs: 900,
            allowsExpectedFailures: false
        )
    ]

    nonisolated private static func dnsQueryPayload(transactionID: UInt16, labels: [String]) -> Data {
        var bytes: [UInt8] = [
            UInt8(transactionID >> 8), UInt8(transactionID & 0x00FF), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ]
        for label in labels {
            bytes.append(UInt8(label.count))
            bytes.append(contentsOf: label.utf8)
        }
        bytes.append(0x00)
        bytes.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        return Data(bytes)
    }

    nonisolated private func elapsedMs(since startedAt: Date) -> Int {
        Self.elapsedMs(since: startedAt)
    }

    nonisolated private static func elapsedMs(since startedAt: Date) -> Int {
        max(0, Int(Date().timeIntervalSince(startedAt) * 1000))
    }
}

nonisolated private func elapsedMs(since startedAt: Date) -> Int {
    max(0, Int(Date().timeIntervalSince(startedAt) * 1000))
}
