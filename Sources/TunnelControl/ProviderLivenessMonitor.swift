import Foundation
import Network
import Observability

/// Extension-wide path and heartbeat monitor that runs outside the dataplane worker queue.
/// Ownership:
/// - `NWPathMonitor` callbacks run on `pathQueue`.
/// - Heartbeat timer events run on `heartbeatQueue`.
/// - Latest path metadata is guarded by `stateQueue`.
final class ProviderLivenessMonitor: @unchecked Sendable {
    /// Lightweight synchronous provider snapshot captured by the heartbeat timer.
    struct Snapshot: Sendable {
        let isStopping: Bool
        let waitingForBackpressureRelief: Bool
        let pendingBatches: Int
        let pendingPackets: Int
        let runtimeInstalled: Bool
        let socksServerInstalled: Bool
        let bridgeInstalled: Bool

        static let empty = Snapshot(
            isStopping: false,
            waitingForBackpressureRelief: false,
            pendingBatches: 0,
            pendingPackets: 0,
            runtimeInstalled: false,
            socksServerInstalled: false,
            bridgeInstalled: false
        )

        var metadata: [String: String] {
            [
                "bridge_installed": bridgeInstalled ? "true" : "false",
                "is_stopping": isStopping ? "true" : "false",
                "pending_batches": String(pendingBatches),
                "pending_packets": String(pendingPackets),
                "runtime_installed": runtimeInstalled ? "true" : "false",
                "socks_server_installed": socksServerInstalled ? "true" : "false",
                "waiting_for_backpressure_relief": waitingForBackpressureRelief ? "true" : "false"
            ]
        }
    }

    typealias SnapshotProvider = @Sendable () -> Snapshot

    private let logger: StructuredLogger
    private let runId: String?
    private let sessionId: String?
    private let snapshotProvider: SnapshotProvider
    // Docs: https://developer.apple.com/documentation/network/nwpathmonitor
    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "com.vpnbridge.tunnel.path-monitor")
    private let heartbeatQueue = DispatchQueue(label: "com.vpnbridge.tunnel.heartbeat")
    private let stateQueue = DispatchQueue(label: "com.vpnbridge.tunnel.path-state")
    private let heartbeatInterval: TimeInterval

    private var heartbeatTimer: DispatchSourceTimer?
    private var started = false
    private var latestPathMetadata: [String: String] = [
        "path": "status=unknown uses=unknown available=unknown expensive=false constrained=false ipv4=false ipv6=false dns=false",
        "path_available": "unknown",
        "path_constrained": "false",
        "path_expensive": "false",
        "path_status": "unknown",
        "path_supports_dns": "false",
        "path_supports_ipv4": "false",
        "path_supports_ipv6": "false",
        "path_uses": "unknown"
    ]

    /// Creates a provider liveness monitor with a synchronous state snapshot source.
    /// - Parameters:
    ///   - logger: Structured logger used for path updates and heartbeat events.
    ///   - runId: Runtime run identifier attached to emitted events.
    ///   - sessionId: Runtime session identifier attached to emitted events.
    ///   - heartbeatInterval: Seconds between heartbeat events.
    ///   - snapshotProvider: Synchronous closure that returns current provider state.
    init(
        logger: StructuredLogger,
        runId: String?,
        sessionId: String?,
        heartbeatInterval: TimeInterval = 5,
        snapshotProvider: @escaping SnapshotProvider
    ) {
        self.logger = logger
        self.runId = runId
        self.sessionId = sessionId
        self.heartbeatInterval = heartbeatInterval
        self.snapshotProvider = snapshotProvider
    }

    /// Starts extension-wide path observation and periodic heartbeats.
    func start() {
        guard !started else { return }
        started = true

        // Docs: https://developer.apple.com/documentation/network/nwpathmonitor/pathupdatehandler
        pathMonitor.pathUpdateHandler = { [weak self] path in
            self?.handlePathUpdate(path)
        }
        // Docs: https://developer.apple.com/documentation/network/nwpathmonitor/start(queue:)
        pathMonitor.start(queue: pathQueue)

        let timer = DispatchSource.makeTimerSource(queue: heartbeatQueue)
        timer.schedule(deadline: .now() + heartbeatInterval, repeating: heartbeatInterval)
        timer.setEventHandler { [weak self] in
            self?.emitHeartbeat()
        }
        timer.resume()
        heartbeatTimer = timer

        Task {
            await logger.log(
                level: .info,
                phase: .lifecycle,
                category: .control,
                component: "ProviderLivenessMonitor",
                event: "heartbeat-started",
                runId: runId,
                sessionId: sessionId,
                message: "Started provider liveness monitor"
            )
        }
    }

    /// Stops path monitoring and suppresses future heartbeat emissions.
    func stop() {
        guard started else { return }
        started = false

        heartbeatTimer?.setEventHandler {}
        heartbeatTimer?.cancel()
        heartbeatTimer = nil

        // Docs: https://developer.apple.com/documentation/network/nwpathmonitor/cancel()
        pathMonitor.pathUpdateHandler = nil
        pathMonitor.cancel()

        Task {
            await logger.log(
                level: .info,
                phase: .lifecycle,
                category: .control,
                component: "ProviderLivenessMonitor",
                event: "heartbeat-stopped",
                runId: runId,
                sessionId: sessionId,
                message: "Stopped provider liveness monitor"
            )
        }
    }

    private func handlePathUpdate(_ path: NWPath) {
        let metadata = Self.metadata(for: path)
        stateQueue.sync {
            latestPathMetadata = metadata
        }

        let level: LogLevel = path.status == .satisfied ? .debug : .warning
        Task {
            await logger.log(
                level: level,
                phase: .path,
                category: .samplerPath,
                component: "ProviderLivenessMonitor",
                event: "path-update",
                runId: runId,
                sessionId: sessionId,
                result: metadata["path_status"],
                message: "Observed provider path update",
                metadata: metadata
            )
        }
    }

    private func emitHeartbeat() {
        let snapshot = snapshotProvider()
        let pathMetadata = stateQueue.sync { latestPathMetadata }
        var metadata = pathMetadata
        for (key, value) in snapshot.metadata {
            metadata[key] = value
        }

        Task {
            await logger.log(
                level: .debug,
                phase: .performance,
                category: .control,
                component: "ProviderLivenessMonitor",
                event: "heartbeat",
                runId: runId,
                sessionId: sessionId,
                result: pathMetadata["path_status"],
                message: "Provider heartbeat",
                metadata: metadata
            )
        }
    }

    private static func metadata(for path: NWPath) -> [String: String] {
        var uses: [String] = []
        if path.usesInterfaceType(.cellular) { uses.append("cellular") }
        if path.usesInterfaceType(.wifi) { uses.append("wifi") }
        if path.usesInterfaceType(.wiredEthernet) { uses.append("wired") }
        if path.usesInterfaceType(.loopback) { uses.append("loopback") }
        if uses.isEmpty { uses.append("other") }

        let availableInterfaces = path.availableInterfaces.map {
            "\(Self.interfaceTypeName($0.type)):\($0.name)"
        }.joined(separator: ",")
        let status = Self.pathStatusName(path.status)
        let summary = "status=\(status) uses=\(uses.joined(separator: ",")) available=\(availableInterfaces) expensive=\(path.isExpensive) constrained=\(path.isConstrained) ipv4=\(path.supportsIPv4) ipv6=\(path.supportsIPv6) dns=\(path.supportsDNS)"

        return [
            "path": summary,
            "path_available": availableInterfaces.isEmpty ? "unknown" : availableInterfaces,
            "path_constrained": path.isConstrained ? "true" : "false",
            "path_expensive": path.isExpensive ? "true" : "false",
            "path_status": status,
            "path_supports_dns": path.supportsDNS ? "true" : "false",
            "path_supports_ipv4": path.supportsIPv4 ? "true" : "false",
            "path_supports_ipv6": path.supportsIPv6 ? "true" : "false",
            "path_uses": uses.joined(separator: ",")
        ]
    }

    private static func interfaceTypeName(_ type: NWInterface.InterfaceType) -> String {
        switch type {
        case .cellular:
            return "cellular"
        case .wifi:
            return "wifi"
        case .wiredEthernet:
            return "wired"
        case .loopback:
            return "loopback"
        case .other:
            return "other"
        @unknown default:
            return "unknown"
        }
    }

    private static func pathStatusName(_ status: NWPath.Status) -> String {
        switch status {
        case .satisfied:
            return "satisfied"
        case .unsatisfied:
            return "unsatisfied"
        case .requiresConnection:
            return "requires-connection"
        @unknown default:
            return "unknown"
        }
    }
}
