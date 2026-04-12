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
/// - `relayQueue` isolates SOCKS listener + Network.framework connection callbacks from packet I/O.
/// - actor/Task boundaries are used for async runtime, packet intelligence, and logging calls.
open class PacketTunnelProviderShell: NEPacketTunnelProvider {
    private enum HealthSamplePolicy {
        static let minimumIntervalSeconds: TimeInterval = 60
    }

    private enum AppMessagePolicy {
        static let maxPacketLimit = 96
    }

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
        var telemetryWorker: PacketTelemetryWorker?
        var cumulativeOutboundPackets = 0
        var cumulativeOutboundBytes = 0
        var cumulativeInboundPackets = 0
        var cumulativeInboundBytes = 0
        var lastHealthSampleAt: Date?
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
        let telemetryWorker: PacketTelemetryWorker?
    }

    /// One-shot callback wrapper used when framework completion handlers need to cross into `Task`.
    /// Safety invariant: the callback is consumed under `lock`, so callers can safely invoke it from concurrent tasks
    /// without racing a second invocation.
    private final class CallbackBox<Payload>: @unchecked Sendable {
        private let lock = NSLock()
        private var callback: ((Payload) -> Void)?

        init(_ callback: @escaping (Payload) -> Void) {
            self.callback = callback
        }

        func call(_ payload: Payload) {
            lock.lock()
            let callback = self.callback
            self.callback = nil
            lock.unlock()
            callback?(payload)
        }
    }

    private let ioQueue = DispatchQueue(label: "com.vpnbridge.tunnel.io", qos: .userInitiated)
    private let relayQueue = DispatchQueue(label: "com.vpnbridge.tunnel.relay", qos: .userInitiated)
    private let stateLock = NSLock()

    private var state: ProviderState

    private let signposts = SignpostSupport(subsystem: "com.vpnbridge.tunnel", category: "control")

    public override init() {
        let bootstrapLogger = StructuredLogger(
            sink: FanoutLogSink(
                sinks: [
                    MinimumLevelLogSink(
                        minimumLevel: .warning,
                        sink: OSLogSink(subsystem: "com.vpnbridge.tunnel", category: LogCategory.control.rawValue)
                    ),
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
        let completion = CallbackBox<Error?>(completionHandler)

        // Docs: https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol/providerconfiguration
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let profile = TunnelProfile.from(providerConfiguration: providerConfig)
        let settings = TunnelNetworkSettingsFactory.makeSettings(profile: profile)

        Task {
            let logger = self.makeLogger(profile: profile)
            var startupTelemetryWorker: PacketTelemetryWorker?
            var startupSocksServer: Socks5Server?
            var startupBridge: TunSocketBridge?
            do {
                let runtime = TunnelRuntime(
                    clock: SystemClock(),
                    runIdGenerator: RandomRunIdGenerator(),
                    randomSource: SystemRandomSource(),
                    logger: logger
                )
                let telemetryWorker = try await self.makeTelemetryWorker(profile: profile, clock: SystemClock(), logger: logger)
                startupTelemetryWorker = telemetryWorker

                let settingsInterval = signposts.begin(.settingsApply, message: "setTunnelNetworkSettings")
                try await apply(settings)
                signposts.end(.settingsApply, state: settingsInterval, message: "ok")

                let (socksServer, socksPort) = try await startSocksServer(profile: profile, logger: logger)
                startupSocksServer = socksServer
                let bridge = try TunSocketBridge(mtu: profile.mtu, queue: ioQueue, logger: logger)
                startupBridge = bridge
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
                    telemetryWorker: telemetryWorker
                )
                startupTelemetryWorker = nil
                startupSocksServer = nil
                startupBridge = nil

                let dataplaneConfig = makeDataplaneConfig(profile: profile, socksPort: socksPort)
                try await runtime.start(configJSON: dataplaneConfig, tunFD: bridge.engineFD)

                let relayLoopInterval = signposts.begin(.relayLoop, message: "packet-flow-loop")
                ioQueue.async { [weak self] in
                    self?.startPacketReadLoop()
                }
                signposts.end(.relayLoop, state: relayLoopInterval, message: "started")

                await logger.log(
                    level: .notice,
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
                completion.call(nil)
            } catch {
                await cleanupAfterFailedStart(
                    startupTelemetryWorker: startupTelemetryWorker,
                    startupSocksServer: startupSocksServer,
                    startupBridge: startupBridge
                )
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
                completion.call(error)
            }
        }
    }

    // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel(with:completionhandler:)
    /// Tunnel shutdown entrypoint called by NetworkExtension.
    /// - Parameters:
    ///   - reason: System stop reason for observability.
    ///   - completionHandler: Must be called when cleanup is complete.
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let completion = CallbackBox<Void> { _ in completionHandler() }
        Task {
            let snapshot = takeCleanupSnapshot(markStopping: true)
            if let telemetryWorker = snapshot.telemetryWorker {
                await telemetryWorker.stopAndWait()
            }
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

            snapshot.tunBridge?.stop()
            snapshot.socksServer?.stop()
            if let runtime = snapshot.runtime {
                try? await runtime.stop()
            }

            await snapshot.logger.log(
                level: .notice,
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
            completion.call(())
        }
    }

    // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovider/handleappmessage(_:completionhandler:)
    /// Handles bounded foreground snapshot requests from the containing app.
    /// Decision: the app asks for a recent rolling window on demand instead of tailing persisted packet history while
    /// the tunnel is running.
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        let completion = completionHandler.map(CallbackBox<Data?>.init)
        Task { [weak self] in
            guard let self else {
                completion?.call(nil)
                return
            }
            completion?.call(await self.handleTunnelAppMessage(messageData))
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
                telemetryWorker: state.telemetryWorker,
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

        let packetCount = packets.count
        let byteCount = packets.reduce(0) { $0 + $1.count }
        withState { state in
            state.cumulativeOutboundPackets += packetCount
            state.cumulativeOutboundBytes += byteCount
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
            let logger = snapshot.logger
            Task {
                await logger.log(
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

        emitHealthSampleIfNeeded(trigger: "outbound", logger: snapshot.logger)

        guard let telemetryWorker = snapshot.telemetryWorker else {
            return
        }
        schedulePacketTelemetryIngest(
            telemetryWorker,
            packets: packets,
            families: families,
            direction: .outbound,
            logger: snapshot.logger
        )
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
                telemetryWorker: state.telemetryWorker,
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

        let packetCount = packets.count
        let byteCount = packets.reduce(0) { $0 + $1.count }
        withState { state in
            state.cumulativeInboundPackets += packetCount
            state.cumulativeInboundBytes += byteCount
        }

        // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets(_:withprotocols:)
        let success = packetFlow.writePackets(packets, withProtocols: protocols)
        if !success {
            let logger = snapshot.logger
            Task {
                await logger.log(
                    level: .error,
                    phase: .packetOut,
                    category: .control,
                    component: "PacketTunnelProviderShell",
                    event: "write-packets-failed",
                    message: "Failed to write packets to NEPacketTunnelFlow"
                )
            }
        }

        emitHealthSampleIfNeeded(trigger: "inbound", logger: snapshot.logger)

        guard let telemetryWorker = snapshot.telemetryWorker else {
            return
        }
        schedulePacketTelemetryIngest(
            telemetryWorker,
            packets: packets,
            families: families,
            direction: .inbound,
            logger: snapshot.logger
        )
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
        let tcpPathSettings = Socks5TCPPathSettings(
            retryOnBetterPathDuringConnect: true,
            betterPathRetryMinimumElapsed: 0.75,
            multipathServiceType: profile.tcpMultipathHandoverEnabled ? .handover : nil
        )
        let server = Socks5Server(
            provider: self,
            queue: relayQueue,
            mtu: profile.mtu,
            logger: logger,
            tcpPathSettings: tcpPathSettings
        )
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

    /// Creates the detector-focused telemetry worker used by the provider hot path.
    /// - Parameter profile: Active tunnel profile.
    /// - Returns: Configured telemetry worker, or `nil` when telemetry is disabled entirely.
    private func makeTelemetryWorker(profile: TunnelProfile, clock: any Clock, logger: StructuredLogger) async throws -> PacketTelemetryWorker? {
        guard profile.telemetryEnabled else {
            return nil
        }

        let root = analyticsRootURL(appGroupID: profile.appGroupID)

        let packetStream: PacketSampleStream? = if profile.liveTapEnabled {
            PacketSampleStream(
                maxBytes: max(1, profile.liveTapMaxBytes),
                retentionWindowSeconds: 10,
                clock: clock,
                logger: logger
            )
        } else {
            nil
        }

        let classifier = SignatureClassifier(logger: logger)
        let signatureURL: URL
        if !profile.appGroupID.isEmpty {
            signatureURL = try AnalyticsStoragePaths.signatureURL(
                appGroupID: profile.appGroupID,
                fileName: profile.signatureFileName
            )
        } else {
            signatureURL = root
                .appendingPathComponent("AppSignatures", isDirectory: true)
                .appendingPathComponent(profile.signatureFileName, isDirectory: false)
        }
        if FileManager.default.fileExists(atPath: signatureURL.path) {
            try? await classifier.load(from: signatureURL)
        }

        let detectionStoreURL: URL
        if !profile.appGroupID.isEmpty {
            detectionStoreURL = try AnalyticsStoragePaths.detectionsURL(appGroupID: profile.appGroupID)
        } else {
            detectionStoreURL = root
                .appendingPathComponent("Detections", isDirectory: true)
                .appendingPathComponent("detections.json", isDirectory: false)
        }
        let detectionStore = DetectionStore(fileURL: detectionStoreURL)
        let initialDetectionSnapshot = (try? detectionStore.load()) ?? .empty
        let detectors = try await makeDetectors(profile: profile, analyticsRootURL: root, logger: logger)
        if packetStream == nil && detectors.isEmpty {
            return nil
        }

        let pipeline = PacketAnalyticsPipeline(
            clock: clock,
            burstTracker: BurstTracker(
                thresholdMs: 350,
                maxTrackedFlows: 1_024,
                flowTTLSeconds: 60
            ),
            signatureClassifier: classifier
        )

        return PacketTelemetryWorker(
            pipeline: pipeline,
            packetStream: packetStream,
            detectors: detectors,
            initialDetectionSnapshot: initialDetectionSnapshot,
            detectionStore: detectionStore,
            logger: logger,
            includeFlowSlicesInLiveTap: profile.liveTapIncludeFlowSlices
        )
    }

    /// Returns the detector set used by the provider's telemetry worker.
    /// Override this in a subclass to supply custom detectors. The default implementation installs no detectors so
    /// package users opt into product-specific logic explicitly.
    open func makeDetectors(
        profile: TunnelProfile,
        analyticsRootURL: URL,
        logger: StructuredLogger
    ) async throws -> [any TrafficDetector] {
        _ = profile
        _ = analyticsRootURL
        _ = logger
        return []
    }

    private func handleTunnelAppMessage(_ messageData: Data) async -> Data? {
        let snapshot = withState { state in
            (logger: state.logger, telemetryWorker: state.telemetryWorker)
        }

        let response: TunnelTelemetryResponse
        do {
            let request = try TunnelTelemetryMessageCodec.decodeRequest(messageData)
            switch request.command {
            case .snapshot:
                let limit = normalizedPacketLimit(request.packetLimit)
                let telemetrySnapshot: TunnelTelemetrySnapshot
                if let telemetryWorker = snapshot.telemetryWorker {
                    telemetrySnapshot = await telemetryWorker.recentSnapshot(limit: limit)
                } else {
                    telemetrySnapshot = .empty
                }
                response = .snapshot(telemetrySnapshot)

            case .clearRecentEvents:
                if let telemetryWorker = snapshot.telemetryWorker {
                    await telemetryWorker.clearRecentEventsAndWait()
                }
                response = .cleared

            case .clearDetections:
                if let telemetryWorker = snapshot.telemetryWorker {
                    await telemetryWorker.clearDetectionsAndWait()
                }
                response = .cleared
            }
        } catch {
            await snapshot.logger.log(
                level: .warning,
                phase: .lifecycle,
                category: .control,
                component: "PacketTunnelProviderShell",
                event: "handle-app-message-failed",
                errorCode: String(describing: error),
                message: "Ignored invalid app message sent to the tunnel provider"
            )
            response = .failure("invalid-request")
        }

        return try? TunnelTelemetryMessageCodec.encodeResponse(response)
    }

    private func normalizedPacketLimit(_ value: Int?) -> Int? {
        guard let value else {
            return AppMessagePolicy.maxPacketLimit
        }
        return max(0, min(value, AppMessagePolicy.maxPacketLimit))
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
           let root = try? AnalyticsStoragePaths.analyticsRoot(appGroupID: appGroupID) {
            return root
        }
        return FileManager.default.temporaryDirectory
            .appendingPathComponent("VPNBridge-Analytics", isDirectory: true)
    }

    /// Builds logger fanout (OSLog + JSONL sink) for the active profile.
    /// - Parameter profile: Active tunnel profile.
    private func makeLogger(profile: TunnelProfile) -> StructuredLogger {
        var sinks: [any LogSink] = [
            MinimumLevelLogSink(
                minimumLevel: .warning,
                sink: OSLogSink(subsystem: "com.vpnbridge.tunnel", category: LogCategory.control.rawValue)
            )
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
        sinks.append(MinimumLevelLogSink(minimumLevel: .notice, sink: jsonSink))

        return StructuredLogger(sink: FanoutLogSink(sinks: sinks))
    }

    /// Persists the most recent provider stop reason where host diagnostics can read it after disconnect.
    /// Decision: write this before shutdown cleanup so the containing app can explain user- and system-driven stops.
    /// - Parameter reason: NetworkExtension stop reason delivered to `stopTunnel(with:completionHandler:)`.
    private func persistLastStopRecord(for reason: NEProviderStopReason) throws {
        // Docs: https://developer.apple.com/documentation/networkextension/neproviderstopreason
        // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel(with:completionhandler:)
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let profile = TunnelProfile.from(providerConfiguration: providerConfig)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]

        let payload = try encoder.encode(makeStopRecord(for: reason))
        let url: URL
        if !profile.appGroupID.isEmpty {
            url = try AnalyticsStoragePaths.lastStopURL(appGroupID: profile.appGroupID)
        } else {
            url = analyticsRootURL(appGroupID: profile.appGroupID)
                .appendingPathComponent("last-stop.json", isDirectory: false)
        }
        try ProtectedAnalyticsFileIO.writeProtectedData(payload, to: url)
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
        telemetryWorker: PacketTelemetryWorker?
    ) {
        withState { state in
            state.logger = logger
            state.runtime = runtime
            state.tunBridge = tunBridge
            state.socksServer = socksServer
            state.telemetryWorker = telemetryWorker
            state.cumulativeOutboundPackets = 0
            state.cumulativeOutboundBytes = 0
            state.cumulativeInboundPackets = 0
            state.cumulativeInboundBytes = 0
            state.lastHealthSampleAt = nil
            state.waitingForBackpressureRelief = false
            state.isStopping = false
            state.pendingOutbound.removeAll(keepingCapacity: false)
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
                telemetryWorker: state.telemetryWorker
            )
            state.runtime = nil
            state.tunBridge = nil
            state.socksServer = nil
            state.telemetryWorker = nil
            return snapshot
        }
    }

    /// Submits packet batches into the long-lived telemetry worker.
    /// Decision: the provider stays synchronous on `ioQueue`, while one worker task handles parsing, throttling, and stream flushes.
    private func schedulePacketTelemetryIngest(
        _ telemetryWorker: PacketTelemetryWorker,
        packets: [Data],
        families: [Int32],
        direction: PacketDirection,
        logger: StructuredLogger
    ) {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        let admission = telemetryWorker.submit(packets: packets, families: families, direction: direction)
        guard !admission.skipped else {
            return
        }
        guard admission.accepted else {
            if admission.shouldLogSheddingStart {
                let batchBytes = packets.reduce(0) { $0 + $1.count }
                Task {
                    await logger.log(
                        level: .warning,
                        phase: .performance,
                        category: .control,
                        component: "PacketTunnelProviderShell",
                        event: "packet-telemetry-shedding-started",
                        result: "shed",
                        message: "Packet intelligence entered bounded shed mode; see health samples for cumulative drop counts",
                        metadata: [
                            "direction": direction.rawValue,
                            "batch_bytes": String(batchBytes),
                            "dropped_batches": String(admission.droppedBatches),
                            "inflight_batches": String(admission.queuedBatches),
                            "inflight_bytes": String(admission.queuedBytes)
                        ]
                    )
                }
            }
            return
        }
    }

    /// Emits one low-rate health sample into the event log.
    /// Decision: fleet telemetry should be periodic and cheap, not a separate persisted metrics subsystem.
    private func emitHealthSampleIfNeeded(trigger: String, logger: StructuredLogger) {
        dispatchPrecondition(condition: .onQueue(ioQueue))

        let snapshot = withState { state -> (shouldEmit: Bool, metadata: [String: String]) in
            let now = Date()
            if let lastHealthSampleAt = state.lastHealthSampleAt,
               now.timeIntervalSince(lastHealthSampleAt) < HealthSamplePolicy.minimumIntervalSeconds {
                return (false, [:])
            }

            state.lastHealthSampleAt = now
            let pendingPackets = state.pendingOutbound.reduce(0) { $0 + $1.remainingPackets }
            let pendingBytes = state.pendingOutbound.reduce(0) { $0 + $1.remainingBytes }
            let bridgeBackpressured = state.tunBridge?.isBackpressured() ?? false
            let telemetrySnapshot = state.telemetryWorker?.snapshot()

            return (
                true,
                [
                    "trigger": trigger,
                    "outbound_packets_total": String(state.cumulativeOutboundPackets),
                    "outbound_bytes_total": String(state.cumulativeOutboundBytes),
                    "inbound_packets_total": String(state.cumulativeInboundPackets),
                    "inbound_bytes_total": String(state.cumulativeInboundBytes),
                    "pending_outbound_packets": String(pendingPackets),
                    "pending_outbound_bytes": String(pendingBytes),
                    "bridge_backpressured": String(bridgeBackpressured),
                    "waiting_for_backpressure_relief": String(state.waitingForBackpressureRelief),
                    "packet_batches_accepted": String(telemetrySnapshot?.acceptedBatches ?? 0),
                    "packet_batches_inflight": String(telemetrySnapshot?.queuedBatches ?? 0),
                    "packet_bytes_inflight": String(telemetrySnapshot?.queuedBytes ?? 0),
                    "packet_batches_dropped": String(telemetrySnapshot?.droppedBatches ?? 0),
                    "packet_batches_skipped": String(telemetrySnapshot?.skippedBatches ?? 0),
                    "packet_records_buffered": String(telemetrySnapshot?.bufferedRecords ?? 0),
                    "thermal_state": TunnelThermalState(thermalState: telemetrySnapshot?.thermalState).rawValue,
                    "low_power_mode_enabled": String(telemetrySnapshot?.lowPowerModeEnabled ?? false)
                ]
            )
        }

        guard snapshot.shouldEmit else {
            return
        }

        Task {
            await logger.log(
                level: .notice,
                phase: .performance,
                category: .control,
                component: "PacketTunnelProviderShell",
                event: "health-sample",
                result: "sampled",
                message: "Periodic tunnel health sample",
                metadata: snapshot.metadata
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
    /// Decision: startup can fail before freshly created components are published into shared provider state, so this
    /// cleanup path must tear down both staged local resources and anything already installed.
    private func cleanupAfterFailedStart(
        startupTelemetryWorker: PacketTelemetryWorker? = nil,
        startupSocksServer: Socks5Server? = nil,
        startupBridge: TunSocketBridge? = nil
    ) async {
        if let startupTelemetryWorker {
            await startupTelemetryWorker.stopAndWait()
        }
        startupBridge?.stop()
        startupSocksServer?.stop()

        let snapshot = takeCleanupSnapshot(markStopping: true)
        if let telemetryWorker = snapshot.telemetryWorker {
            await telemetryWorker.stopAndWait()
        }

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
