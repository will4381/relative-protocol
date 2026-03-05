import Analytics
import Foundation
import NetworkExtension
import Observability
import PacketRelay
import TunnelRuntime

/// Packet tunnel provider that owns startup/shutdown, packet I/O loops, and dataplane wiring.
// Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
/// Queue ownership:
/// - `ioQueue` serializes packet ingress/egress and bridge backpressure transitions.
/// - actor/Task boundaries are used for async runtime, analytics, and logging calls.
open class PacketTunnelProviderShell: NEPacketTunnelProvider {
    /// Provider-owned backlog retained when the bridge is saturated but not failed.
    fileprivate struct PendingOutboundBatch {
        let packets: [Data]
        let families: [Int32]
        var nextIndex: Int

        var remainingPackets: Int {
            max(0, packets.count - nextIndex)
        }

        var remainingBytes: Int {
            guard nextIndex < packets.count else { return 0 }
            return packets[nextIndex...].reduce(0) { $0 + $1.count }
        }
    }

    /// Mutable provider state shared between startup/shutdown tasks and packet I/O callbacks.
    /// Access invariant: every read/write goes through `withState(_:)`.
    private struct ProviderState {
        var logger: StructuredLogger
        var runtime: TunnelRuntime?
        var tunBridge: TunSocketBridge?
        var socksServer: Socks5Server?
        var analyticsPipeline: PacketAnalyticsPipeline?
        var livenessMonitor: ProviderLivenessMonitor?
        var waitingForBackpressureRelief = false
        var isStopping = false
        var pendingOutbound: [PendingOutboundBatch] = []
    }

    /// Snapshot extracted under lock so cleanup can run without holding shared-state synchronization.
    private struct CleanupSnapshot {
        let logger: StructuredLogger
        let runtime: TunnelRuntime?
        let tunBridge: TunSocketBridge?
        let socksServer: Socks5Server?
        let livenessMonitor: ProviderLivenessMonitor?
    }

    private let ioQueue = DispatchQueue(label: "com.vpnbridge.tunnel.io", qos: .userInitiated)
    private let stateLock = NSLock()

    private var state: ProviderState

    private let signposts = SignpostSupport(subsystem: "com.vpnbridge.tunnel", category: "control")

    public override init() {
        let bootstrapLogger = StructuredLogger(
            sink: FanoutLogSink(
                sinks: [
                    OSLogSink(subsystem: "com.vpnbridge.tunnel", category: LogCategory.control.rawValue),
                    InMemoryLogSink()
                ]
            )
        )
        self.state = ProviderState(logger: bootstrapLogger)
        super.init()
    }

    // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/starttunnel(options:completionhandler:)
    /// Tunnel startup entrypoint called by NetworkExtension.
    /// - Parameters:
    ///   - options: Provider start options supplied by the system.
    ///   - completionHandler: Must be called exactly once with startup result.
    open override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        _ = options
        let startupInterval = signposts.begin(.startup, message: "packet-tunnel-start")

        // Docs: https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol/providerconfiguration
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let profile = TunnelProfile.from(providerConfiguration: providerConfig)
        let settings = TunnelNetworkSettingsFactory.makeSettings(profile: profile)

        Task {
            let logger = self.makeLogger(profile: profile)
            do {
                let runtime = TunnelRuntime(
                    clock: SystemClock(),
                    runIdGenerator: RandomRunIdGenerator(),
                    randomSource: SystemRandomSource(),
                    logger: logger
                )
                let analyticsPipeline = try await self.makeAnalyticsPipeline(profile: profile, clock: SystemClock(), logger: logger)

                let settingsInterval = signposts.begin(.settingsApply, message: "setTunnelNetworkSettings")
                try await apply(settings)
                signposts.end(.settingsApply, state: settingsInterval, message: "ok")

                let (socksServer, socksPort) = try await startSocksServer(profile: profile, logger: logger)
                let bridge = try TunSocketBridge(mtu: profile.mtu, queue: ioQueue, logger: logger)
                bridge.onBackpressureRelieved = { [weak self] in
                    self?.resumePacketReadLoopIfNeeded()
                }
                bridge.startReadLoop { [weak self] packets, families in
                    self?.handleInboundPackets(packets, families: families)
                }

                installStartedComponents(
                    logger: logger,
                    runtime: runtime,
                    tunBridge: bridge,
                    socksServer: socksServer,
                    analyticsPipeline: analyticsPipeline
                )

                let dataplaneConfig = makeDataplaneConfig(profile: profile, socksPort: socksPort)
                try await runtime.start(configJSON: dataplaneConfig, tunFD: bridge.engineFD)
                let runtimeSnapshot = await runtime.currentSnapshot()
                let livenessMonitor = makeLivenessMonitor(
                    logger: logger,
                    runId: runtimeSnapshot.runId,
                    sessionId: runtimeSnapshot.sessionId
                )
                installLivenessMonitor(livenessMonitor)
                livenessMonitor.start()

                let relayLoopInterval = signposts.begin(.relayLoop, message: "packet-flow-loop")
                ioQueue.async { [weak self] in
                    self?.startPacketReadLoop()
                }
                signposts.end(.relayLoop, state: relayLoopInterval, message: "started")

                await logger.log(
                    level: .info,
                    phase: .lifecycle,
                    category: .control,
                    component: "PacketTunnelProviderShell",
                    event: "start-success",
                    message: "Tunnel started",
                    metadata: [
                        "socks_port": String(socksPort),
                        "mtu": String(profile.mtu)
                    ]
                )
                signposts.end(.startup, state: startupInterval, message: "ok")
                completionHandler(nil)
            } catch {
                await cleanupAfterFailedStart()
                await logger.log(
                    level: .error,
                    phase: .lifecycle,
                    category: .control,
                    component: "PacketTunnelProviderShell",
                    event: "start-failed",
                    errorCode: String(describing: error),
                    message: "Tunnel failed to start"
                )
                signposts.end(.startup, state: startupInterval, message: "failed")
                completionHandler(error)
            }
        }
    }

    // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel(with:completionhandler:)
    /// Tunnel shutdown entrypoint called by NetworkExtension.
    /// - Parameters:
    ///   - reason: System stop reason for observability.
    ///   - completionHandler: Must be called when cleanup is complete.
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Task {
            let snapshot = takeCleanupSnapshot(markStopping: true)
            do {
                try persistLastStopRecord(for: reason)
            } catch {
                await snapshot.logger.log(
                    level: .error,
                    phase: .storage,
                    category: .control,
                    component: "PacketTunnelProviderShell",
                    event: "persist-last-stop-failed",
                    errorCode: String(describing: error),
                    message: "Failed to persist the last stop reason"
                )
            }

            snapshot.livenessMonitor?.stop()
            snapshot.tunBridge?.stop()
            snapshot.socksServer?.stop()
            if let runtime = snapshot.runtime {
                try? await runtime.stop()
            }

            await snapshot.logger.log(
                level: .info,
                phase: .lifecycle,
                category: .control,
                component: "PacketTunnelProviderShell",
                event: "stop",
                result: Self.stopReasonName(forRawValue: reason.rawValue),
                message: makeStopRecord(for: reason).summary,
                metadata: [
                    "stop_reason": Self.stopReasonName(forRawValue: reason.rawValue),
                    "stop_reason_code": String(reason.rawValue)
                ]
            )
            completionHandler()
        }
    }

    /// Reads packets from `NEPacketTunnelFlow` and forwards them into the bridge.
    /// Stops reading while bridge backpressure is active.
    private func startPacketReadLoop() {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        let shouldRead = withState { state in
            !state.waitingForBackpressureRelief && !state.isStopping && state.pendingOutbound.isEmpty
        }
        guard shouldRead else {
            return
        }

        // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpackets(completionhandler:)
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.ioQueue.async {
                dispatchPrecondition(condition: .onQueue(self.ioQueue))
                let isStopping = self.withState { $0.isStopping }
                guard !isStopping else { return }
                self.handleOutboundPackets(packets, protocols: protocols)
                self.resumeReadLoopAfterWriteIfPossible()
            }
        }
    }

    /// Handles outbound packets flowing device -> dataplane.
    /// - Parameters:
    ///   - packets: Raw IP packets read from `packetFlow`.
    ///   - protocols: Address family hints aligned by index with `packets`.
    private func handleOutboundPackets(_ packets: [Data], protocols: [NSNumber]) {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        let snapshot = withState { state in
            (
                logger: state.logger,
                bridge: state.tunBridge,
                analyticsPipeline: state.analyticsPipeline,
                isStopping: state.isStopping
            )
        }
        guard !snapshot.isStopping, let bridge = snapshot.bridge else {
            return
        }

        var families: [Int32] = []
        families.reserveCapacity(packets.count)

        for index in packets.indices {
            let family = protocols.indices.contains(index) ? protocols[index].int32Value : 0
            families.append(family)
        }

        let batch = PendingOutboundBatch(packets: packets, families: families, nextIndex: 0)
        switch writePendingBatch(batch, bridge: bridge) {
        case .complete:
            if bridge.isBackpressured() {
                withState { state in
                    state.waitingForBackpressureRelief = true
                }
            }
        case .backpressured(let pendingBatch):
            withState { state in
                state.pendingOutbound.append(pendingBatch)
                state.waitingForBackpressureRelief = true
            }
            Task {
                await snapshot.logger.log(
                    level: .notice,
                    phase: .relay,
                    category: .control,
                    component: "PacketTunnelProviderShell",
                    event: "outbound-queued",
                    result: "backpressure",
                    message: "Queued outbound packets while bridge was saturated",
                    metadata: [
                        "queued_packets": String(pendingBatch.remainingPackets),
                        "queued_bytes": String(pendingBatch.remainingBytes)
                    ]
                )
            }
        case .failed(let errorCode):
            failTunnelForBridgeWrite(errorCode: errorCode, logger: snapshot.logger)
        }

        guard let analyticsPipeline = snapshot.analyticsPipeline else {
            return
        }
        Task {
            await analyticsPipeline.ingest(packets: packets, families: families, direction: .outbound)
        }
    }

    /// Handles inbound packets flowing dataplane -> device.
    /// - Parameters:
    ///   - packets: Raw IP packets read from bridge.
    ///   - families: Address family values aligned by index with `packets`.
    private func handleInboundPackets(_ packets: [Data], families: [Int32]) {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        let snapshot = withState { state in
            (
                logger: state.logger,
                analyticsPipeline: state.analyticsPipeline,
                isStopping: state.isStopping
            )
        }
        guard !snapshot.isStopping, !packets.isEmpty else {
            return
        }

        var protocols: [NSNumber] = []
        protocols.reserveCapacity(packets.count)

        for (index, packet) in packets.enumerated() {
            if families.indices.contains(index) {
                protocols.append(NSNumber(value: families[index]))
            } else {
                let inferred: Int32 = packet.first.map {
                    (($0 >> 4) & 0x0F) == 6 ? Int32(AF_INET6) : Int32(AF_INET)
                } ?? Int32(AF_INET)
                protocols.append(NSNumber(value: inferred))
            }
        }

        // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets(_:withprotocols:)
        let success = packetFlow.writePackets(packets, withProtocols: protocols)
        if !success {
            Task {
                await snapshot.logger.log(
                    level: .error,
                    phase: .packetOut,
                    category: .control,
                    component: "PacketTunnelProviderShell",
                    event: "write-packets-failed",
                    message: "Failed to write packets to NEPacketTunnelFlow"
                )
            }
        }

        guard let analyticsPipeline = snapshot.analyticsPipeline else {
            return
        }
        Task {
            await analyticsPipeline.ingest(packets: packets, families: families, direction: .inbound)
        }
    }

    /// Resumes packet read loop after backpressure drops below threshold.
    private func resumePacketReadLoopIfNeeded() {
        ioQueue.async { [weak self] in
            guard let self else { return }
            dispatchPrecondition(condition: .onQueue(self.ioQueue))

            let snapshot = self.withState { state in
                (
                    waiting: state.waitingForBackpressureRelief,
                    isStopping: state.isStopping,
                    bridge: state.tunBridge
                )
            }
            guard snapshot.waiting, !snapshot.isStopping else { return }
            if let bridge = snapshot.bridge, bridge.isBackpressured() {
                return
            }

            switch self.drainPendingOutboundIfPossible() {
            case .progressed:
                self.resumeReadLoopAfterWriteIfPossible()
            case .failed:
                break
            }
        }
    }

    /// Starts local SOCKS5 server used by dataplane for TCP/UDP egress.
    /// - Parameter profile: Active tunnel profile.
    /// - Returns: Bound SOCKS listen port.
    private func startSocksServer(profile: TunnelProfile, logger: StructuredLogger) async throws -> (server: Socks5Server, port: UInt16) {
        let server = Socks5Server(provider: self, queue: ioQueue, mtu: profile.mtu, logger: logger)
        return try await withCheckedThrowingContinuation { continuation in
            server.start(port: profile.engineSocksPort) { result in
                switch result {
                case .success(let port):
                    continuation.resume(returning: (server, port))
                case .failure(let error):
                    server.stop()
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Creates analytics components with deterministic bounds for memory and file growth.
    /// - Parameter profile: Active tunnel profile.
    /// - Returns: Configured analytics pipeline for packet parsing/classification.
    private func makeAnalyticsPipeline(profile: TunnelProfile, clock: any Clock, logger: StructuredLogger) async throws -> PacketAnalyticsPipeline {
        let root = analyticsRootURL(appGroupID: profile.appGroupID)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let metricsStore = MetricsStore(
            capacity: 1024,
            maxBytes: 1_500_000,
            outputURL: root.appendingPathComponent("metrics.json", isDirectory: false),
            clock: clock,
            logger: logger
        )

        let packetStream: PacketSampleStream?
        if profile.packetStreamEnabled {
            packetStream = PacketSampleStream(
                maxBytes: max(1, profile.packetStreamMaxBytes),
                url: root.appendingPathComponent("packet-stream.ndjson", isDirectory: false),
                logger: logger
            )
        } else {
            packetStream = nil
        }

        let classifier = SignatureClassifier(logger: logger)
        let signatureURL = root
            .appendingPathComponent("AppSignatures", isDirectory: true)
            .appendingPathComponent(profile.signatureFileName, isDirectory: false)
        if FileManager.default.fileExists(atPath: signatureURL.path) {
            try? await classifier.load(from: signatureURL)
        }

        return PacketAnalyticsPipeline(
            clock: clock,
            flowTracker: FlowTracker(maxTrackedFlows: 4096, flowTTLSeconds: 300),
            burstTracker: BurstTracker(thresholdMs: 350),
            signatureClassifier: classifier,
            packetStream: packetStream,
            metricsStore: metricsStore,
            logger: logger,
            insightCapacity: 2048
        )
    }

    /// Resolves dataplane runtime config text.
    /// Uses profile JSON when provided, otherwise synthesizes a HEV-compatible YAML config.
    /// - Parameters:
    ///   - profile: Active tunnel profile.
    ///   - socksPort: Bound local SOCKS5 port.
    private func makeDataplaneConfig(profile: TunnelProfile, socksPort: UInt16) -> String {
        let configured = profile.dataplaneConfigJSON.trimmingCharacters(in: .whitespacesAndNewlines)
        if !configured.isEmpty, configured != "{}" {
            return configured
                .replacingOccurrences(of: "${SOCKS_PORT}", with: String(socksPort))
                .replacingOccurrences(of: "${MTU}", with: String(profile.mtu))
                .replacingOccurrences(of: "${IPV4}", with: profile.ipv4Address)
                .replacingOccurrences(of: "${IPV6}", with: profile.ipv6Address)
        }

        var lines: [String] = []
        lines.append("tunnel:")
        lines.append("  name: tun0")
        lines.append("  mtu: \(profile.mtu)")
        lines.append("  multi-queue: false")
        lines.append("  ipv4: \(profile.ipv4Address)")
        if profile.ipv6Enabled {
            lines.append("  ipv6: '\(profile.ipv6Address)'")
        }
        lines.append("")
        lines.append("socks5:")
        lines.append("  port: \(socksPort)")
        lines.append("  address: 127.0.0.1")
        lines.append("  udp: 'udp'")
        lines.append("")
        lines.append("misc:")
        lines.append("  log-file: stderr")
        lines.append("  log-level: \(normalizedEngineLogLevel(profile.engineLogLevel))")
        lines.append("  connect-timeout: 10000")
        lines.append("  tcp-read-write-timeout: 300000")
        lines.append("  udp-read-write-timeout: 60000")
        return lines.joined(separator: "\n")
    }

    /// Maps user-provided log level hints into HEV supported levels.
    /// - Parameter value: Profile-provided log level string.
    private func normalizedEngineLogLevel(_ value: String) -> String {
        let lower = value.lowercased()
        if lower.contains("debug") {
            return "debug"
        }
        if lower.contains("info") {
            return "info"
        }
        if lower.contains("error") {
            return "error"
        }
        return "warn"
    }

    /// Resolves on-device analytics root.
    /// Uses App Group storage when available, otherwise falls back to temporary directory.
    /// - Parameter appGroupID: Optional App Group identifier.
    private func analyticsRootURL(appGroupID: String) -> URL {
        if !appGroupID.isEmpty,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
        {
            return container.appendingPathComponent("Analytics", isDirectory: true)
        }
        return FileManager.default.temporaryDirectory
            .appendingPathComponent("VPNBridge-Analytics", isDirectory: true)
    }

    /// Builds logger fanout (OSLog + JSONL sink) for the active profile.
    /// - Parameter profile: Active tunnel profile.
    private func makeLogger(profile: TunnelProfile) -> StructuredLogger {
        var sinks: [any LogSink] = [
            OSLogSink(subsystem: "com.vpnbridge.tunnel", category: LogCategory.control.rawValue)
        ]

        let rootProvider: any LogRootPathProvider
        if !profile.appGroupID.isEmpty {
            rootProvider = AppGroupLogRootPathProvider(appGroupID: profile.appGroupID)
        } else {
            rootProvider = HarnessLogRootPathProvider(
                root: FileManager.default.temporaryDirectory
                    .appendingPathComponent("VPNBridge-Logs", isDirectory: true)
            )
        }

        let jsonSink = JSONLLogSink(
            rootProvider: rootProvider,
            policy: JSONLRotationPolicy(maxBytesPerFile: 1_048_576, maxFiles: 8, maxTotalBytes: 8_388_608),
            eventQueueLabel: "tunnel"
        )
        sinks.append(jsonSink)

        return StructuredLogger(sink: FanoutLogSink(sinks: sinks))
    }

    /// Creates the extension-wide liveness monitor that observes provider path changes and emits heartbeats.
    /// Decision: keep this outside the dataplane worker queue so liveness breadcrumbs still disappear when the provider itself wedges.
    private func makeLivenessMonitor(
        logger: StructuredLogger,
        runId: String?,
        sessionId: String?
    ) -> ProviderLivenessMonitor {
        ProviderLivenessMonitor(
            logger: logger,
            runId: runId,
            sessionId: sessionId,
            snapshotProvider: { [weak self] in
                self?.livenessSnapshot() ?? .empty
            }
        )
    }

    /// Persists the most recent provider stop reason where host diagnostics can read it after disconnect.
    /// Decision: write this before shutdown cleanup so the containing app can explain user- and system-driven stops.
    /// - Parameter reason: NetworkExtension stop reason delivered to `stopTunnel(with:completionHandler:)`.
    private func persistLastStopRecord(for reason: NEProviderStopReason) throws {
        // Docs: https://developer.apple.com/documentation/networkextension/neproviderstopreason
        // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel(with:completionhandler:)
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let profile = TunnelProfile.from(providerConfiguration: providerConfig)
        let root = analyticsRootURL(appGroupID: profile.appGroupID)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]

        let payload = try encoder.encode(makeStopRecord(for: reason))
        try payload.write(to: root.appendingPathComponent("last-stop.json", isDirectory: false), options: .atomic)
    }

    /// Converts the framework stop enum into a portable record shared with the host app.
    /// - Parameter reason: Stop reason supplied by NetworkExtension.
    private func makeStopRecord(for reason: NEProviderStopReason) -> TunnelStopRecord {
        TunnelStopRecord(
            timestamp: Date(),
            reasonCode: reason.rawValue,
            reasonName: Self.stopReasonName(forRawValue: reason.rawValue)
        )
    }

    /// Maps raw provider stop reason values to stable case labels without relying on SDK-specific enum reflection.
    /// - Parameter rawValue: Raw `NEProviderStopReason` integer.
    private static func stopReasonName(forRawValue rawValue: Int) -> String {
        switch rawValue {
        case 0:
            return "none"
        case 1:
            return "userInitiated"
        case 2:
            return "providerFailed"
        case 3:
            return "noNetworkAvailable"
        case 4:
            return "unrecoverableNetworkChange"
        case 5:
            return "providerDisabled"
        case 6:
            return "authenticationCanceled"
        case 7:
            return "configurationFailed"
        case 8:
            return "idleTimeout"
        case 9:
            return "configurationDisabled"
        case 10:
            return "configurationRemoved"
        case 11:
            return "superceded"
        case 12:
            return "userLogout"
        case 13:
            return "userSwitch"
        case 14:
            return "connectionFailed"
        case 15:
            return "sleep"
        case 16:
            return "appUpdate"
        case 17:
            return "internalError"
        default:
            return "unknown"
        }
    }

    /// Performs a synchronous mutation/read against provider state shared across tasks and callback queues.
    /// The lock scope must stay short and never cross async or blocking work.
    private func withState<T>(_ body: (inout ProviderState) -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body(&state)
    }

    /// Installs fully initialized runtime components into provider state after startup succeeds.
    /// Preconditions: every dependency is ready to be used by packet I/O callbacks.
    private func installStartedComponents(
        logger: StructuredLogger,
        runtime: TunnelRuntime,
        tunBridge: TunSocketBridge,
        socksServer: Socks5Server,
        analyticsPipeline: PacketAnalyticsPipeline
    ) {
        withState { state in
            state.logger = logger
            state.runtime = runtime
            state.tunBridge = tunBridge
            state.socksServer = socksServer
            state.analyticsPipeline = analyticsPipeline
            state.livenessMonitor = nil
            state.waitingForBackpressureRelief = false
            state.isStopping = false
            state.pendingOutbound.removeAll(keepingCapacity: false)
        }
    }

    /// Installs the provider liveness monitor after runtime identifiers become available.
    /// Preconditions: runtime/dataplane startup succeeded and the monitor has not started logging yet.
    private func installLivenessMonitor(_ livenessMonitor: ProviderLivenessMonitor) {
        withState { state in
            state.livenessMonitor = livenessMonitor
        }
    }

    /// Extracts cleanup ownership from shared state.
    /// Postconditions: provider no longer exposes previous bridge/server/runtime references to concurrent callbacks.
    private func takeCleanupSnapshot(markStopping: Bool) -> CleanupSnapshot {
        withState { state in
            if markStopping {
                state.isStopping = true
            }
            state.waitingForBackpressureRelief = false
            state.pendingOutbound.removeAll(keepingCapacity: false)

            let snapshot = CleanupSnapshot(
                logger: state.logger,
                runtime: state.runtime,
                tunBridge: state.tunBridge,
                socksServer: state.socksServer,
                livenessMonitor: state.livenessMonitor
            )
            state.runtime = nil
            state.tunBridge = nil
            state.socksServer = nil
            state.analyticsPipeline = nil
            state.livenessMonitor = nil
            return snapshot
        }
    }

    /// Synchronously captures provider-owned liveness state for the heartbeat timer.
    /// The snapshot intentionally avoids touching dataplane worker state so it remains safe under failure.
    private func livenessSnapshot() -> ProviderLivenessMonitor.Snapshot {
        withState { state in
            ProviderLivenessMonitor.Snapshot(
                isStopping: state.isStopping,
                waitingForBackpressureRelief: state.waitingForBackpressureRelief,
                pendingBatches: state.pendingOutbound.count,
                pendingPackets: state.pendingOutbound.reduce(0) { $0 + $1.remainingPackets },
                runtimeInstalled: state.runtime != nil,
                socksServerInstalled: state.socksServer != nil,
                bridgeInstalled: state.tunBridge != nil
            )
        }
    }

    /// Attempts to write one queued packet batch into the bridge until it completes, saturates, or fails.
    /// Preconditions: caller runs on `ioQueue` so batch ordering remains deterministic.
    private func writePendingBatch(_ batch: PendingOutboundBatch, bridge: TunSocketBridge) -> PendingBatchWriteResult {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        var nextIndex = batch.nextIndex
        while nextIndex < batch.packets.count {
            switch bridge.writePacket(batch.packets[nextIndex], ipVersionHint: batch.families[nextIndex]) {
            case .accepted:
                nextIndex += 1
            case .backpressured:
                return .backpressured(
                    PendingOutboundBatch(
                        packets: batch.packets,
                        families: batch.families,
                        nextIndex: nextIndex
                    )
                )
            case .failed(let errorCode):
                return .failed(errorCode: errorCode)
            }
        }

        return .complete
    }

    /// Drains provider-owned pending outbound batches after the bridge signals relief.
    /// - Returns: Whether draining progressed or hit a terminal bridge failure.
    private func drainPendingOutboundIfPossible() -> PendingDrainOutcome {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        while true {
            let snapshot = withState { state in
                (
                    bridge: state.tunBridge,
                    pendingBatch: state.pendingOutbound.first,
                    logger: state.logger,
                    isStopping: state.isStopping
                )
            }
            guard !snapshot.isStopping else {
                return .progressed
            }
            guard let bridge = snapshot.bridge else {
                withState { state in
                    state.pendingOutbound.removeAll(keepingCapacity: false)
                    state.waitingForBackpressureRelief = false
                }
                return .progressed
            }
            guard let pendingBatch = snapshot.pendingBatch else {
                withState { state in
                    state.waitingForBackpressureRelief = bridge.isBackpressured()
                }
                return .progressed
            }

            switch writePendingBatch(pendingBatch, bridge: bridge) {
            case .complete:
                withState { state in
                    guard !state.pendingOutbound.isEmpty else { return }
                    state.pendingOutbound.removeFirst()
                }
            case .backpressured(let updatedBatch):
                withState { state in
                    guard !state.pendingOutbound.isEmpty else { return }
                    state.pendingOutbound[0] = updatedBatch
                    state.waitingForBackpressureRelief = true
                }
                return .progressed
            case .failed(let errorCode):
                withState { state in
                    state.pendingOutbound.removeAll(keepingCapacity: false)
                    state.waitingForBackpressureRelief = false
                }
                failTunnelForBridgeWrite(errorCode: errorCode, logger: snapshot.logger)
                return .failed
            }
        }
    }

    /// Starts the next `readPackets` cycle only when there is no local backlog and the bridge can accept more data.
    private func resumeReadLoopAfterWriteIfPossible() {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        let shouldResume = withState { state in
            guard !state.isStopping else { return false }
            guard state.pendingOutbound.isEmpty else {
                state.waitingForBackpressureRelief = true
                return false
            }
            if let bridge = state.tunBridge, bridge.isBackpressured() {
                state.waitingForBackpressureRelief = true
                return false
            }
            state.waitingForBackpressureRelief = false
            return true
        }

        if shouldResume {
            startPacketReadLoop()
        }
    }

    /// Converts a terminal bridge write failure into a tunnel cancellation.
    // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/canceltunnelwitherror(_:)
    private func failTunnelForBridgeWrite(errorCode: Int32, logger: StructuredLogger) {
        let shouldCancel = withState { state in
            guard !state.isStopping else { return false }
            state.isStopping = true
            state.waitingForBackpressureRelief = false
            state.pendingOutbound.removeAll(keepingCapacity: false)
            return true
        }
        guard shouldCancel else {
            return
        }

        Task {
            await logger.log(
                level: .error,
                phase: .relay,
                category: .control,
                component: "PacketTunnelProviderShell",
                event: "bridge-write-failed",
                errorCode: String(errorCode),
                message: "Cancelling tunnel after terminal bridge write failure"
            )
        }
        cancelTunnelWithError(TunnelProviderError.bridgeWriteFailed(code: errorCode))
    }

    // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:)
    /// Async wrapper around callback-based `setTunnelNetworkSettings`.
    /// - Parameter settings: Tunnel interface settings to apply.
    private func apply(_ settings: NEPacketTunnelNetworkSettings) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            setTunnelNetworkSettings(settings) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    /// Best-effort cleanup path used when startup fails after partial initialization.
    private func cleanupAfterFailedStart() async {
        let snapshot = takeCleanupSnapshot(markStopping: true)

        snapshot.livenessMonitor?.stop()
        snapshot.tunBridge?.stop()
        snapshot.socksServer?.stop()
        if let runtime = snapshot.runtime {
            try? await runtime.stop()
        }
    }
}

/// `NEPacketTunnelProvider` itself is not `Sendable`, but this shell serializes packet I/O on `ioQueue`
/// and protects cross-context mutable references with `stateLock`.
extension PacketTunnelProviderShell: @unchecked Sendable {}

/// Outcome of draining one provider-owned outbound batch into the bridge.
private enum PendingBatchWriteResult {
    case complete
    case backpressured(PacketTunnelProviderShell.PendingOutboundBatch)
    case failed(errorCode: Int32)
}

/// Outcome of retrying queued outbound traffic after a backpressure signal.
private enum PendingDrainOutcome {
    case progressed
    case failed
}

private enum TunnelProviderError: LocalizedError {
    case bridgeWriteFailed(code: Int32)

    var errorDescription: String? {
        switch self {
        case .bridgeWriteFailed(let code):
            return "Bridge write failed with errno \(code)"
        }
    }
}
