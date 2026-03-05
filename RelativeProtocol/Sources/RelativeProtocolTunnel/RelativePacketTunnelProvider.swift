// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Darwin
import Foundation
import RelativeProtocolCore
@preconcurrency import NetworkExtension

open class RelativePacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = RelativeLog.logger(.tunnel)
    private let parserLogger = RelativeLog.logger(.parser)
    private let metricsLogger = RelativeLog.logger(.metrics)
    private let queue = DispatchQueue(label: "com.relative.protocol.tunnel")
    private let ioQueue = DispatchQueue(label: "com.relative.protocol.tunnel.io", qos: .userInitiated)
    private let metricsQueue = DispatchQueue(label: "com.relative.protocol.tunnel.metrics", qos: .utility)
    private let stateQueue = DispatchQueue(label: "com.relative.protocol.tunnel.state")

    private var configuration: TunnelConfiguration?
    private var flowTracker: FlowTracker?
    private var burstTracker: BurstTracker?
    private var trafficClassifier: TrafficClassifier?
    private var metricsBuffer: MetricsRingBuffer?
    private var metricsStore: MetricsStore?
    private var metricsTimer: DispatchSourceTimer?
    private let metricsWriteQueue = DispatchQueue(label: "com.relative.protocol.metrics.store", qos: .utility)
    private var metricsSampleLimit: Int = 0
    private var metricsSnapshotLimit: Int = 0
    private var packetStreamWriter: PacketSampleStreamWriter?
    private var outboundStreamSampleBuffer: [PacketSample] = []
    private var inboundStreamSampleBuffer: [PacketSample] = []
    private var socksServer: Socks5Server?
    private var tunBridge: TunSocketBridge?
    private var engine: Tun2SocksEngine?
    private var isStopping = false
    private var packetCount: UInt64 = 0
    private var inboundPacketCount: UInt64 = 0
    private var didWarnRelay = false
    private let logPrefix = "RelativePacketTunnelProvider"
    private var waitingForBackpressureRelief = false
    private var relayRestartInProgress = false
    private var defaultPathMonitorTimer: DispatchSourceTimer?
    private var keepaliveTimer: DispatchSourceTimer?
    private var keepaliveSession: Socks5UDPSession?
    private var keepaliveProbeHosts: [String] = []
    private var keepaliveProbeHostIndex = 0
    private var lastObservedPathSignature: String?
    private var lastObservedPathForRestart: NWPath?
    private var pathBeforeSleep: NWPath?
    private var relayRestartAttempts: Int = 0
    private var relayRestartRetryWorkItem: DispatchWorkItem?
    private var reassertingState = false
    private var firstUDPWaitingCapture: UDPWaitingCapture?
    private var lastProviderStopCapture: ProviderStopCapture?
    private var currentRunID: String = UUID().uuidString
    private var currentRunBootCount: Int = 0
    private var previousRunUncleanlyTerminated = false
    private var previousRunID: String?
    private var previousRunStartEpoch: TimeInterval?
    private var previousRunStopEpoch: TimeInterval?

    private static let keepaliveFallbackHosts = [
        "1.1.1.1",
        "8.8.8.8",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888"
    ]
    private static let maxRelayRestartAttempts = 3
    private static let keepaliveDNSQuery = Data([
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01
    ])
    private static let lifecycleBootCountKey = "RelativePacketTunnelProvider.lifecycle.bootCount"
    private static let lifecycleLastRunIDKey = "RelativePacketTunnelProvider.lifecycle.lastRunID"
    private static let lifecycleLastRunStartEpochKey = "RelativePacketTunnelProvider.lifecycle.lastRunStartEpoch"
    private static let lifecycleLastRunStopEpochKey = "RelativePacketTunnelProvider.lifecycle.lastRunStopEpoch"
    private static let lifecycleLastRunStopReasonKey = "RelativePacketTunnelProvider.lifecycle.lastRunStopReason"
    private static let lifecycleLastRunCleanStopKey = "RelativePacketTunnelProvider.lifecycle.lastRunCleanStop"

    private struct UDPWaitingCapture: Sendable {
        let timestampEpoch: TimeInterval
        let level: String
        let component: String
        let message: String
        let pathSignature: String

        var payload: [String: Any] {
            [
                "timestampEpoch": timestampEpoch,
                "level": level,
                "component": component,
                "message": message,
                "pathSignature": pathSignature
            ]
        }
    }

    private struct ProviderStopCapture: Sendable {
        let timestampEpoch: TimeInterval
        let reasonRawValue: Int
        let reasonName: String
        let pathSignature: String

        var payload: [String: Any] {
            [
                "timestampEpoch": timestampEpoch,
                "reasonRawValue": reasonRawValue,
                "reasonName": reasonName,
                "pathSignature": pathSignature
            ]
        }
    }

    public override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        if RelativeLog.isVerbose {
            NSLog("\(logPrefix): startTunnel invoked")
        }
        queue.async {
            self.firstUDPWaitingCapture = nil
            self.lastProviderStopCapture = nil
            self.setIsStopping(false)
            self.setWaitingForBackpressureRelief(false)
            self.relayRestartInProgress = false
            self.relayRestartAttempts = 0
            self.pathBeforeSleep = nil
            self.cancelRelayRestartRetryWorkItem()
            let config = self.loadConfiguration()
            self.configuration = config
            let lifecycleMetadata = self.recordLifecycleStart(appGroupID: config.appGroupID)
            self.logTunnelEvent(
                level: self.previousRunUncleanlyTerminated ? "warning" : "info",
                phase: "lifecycle",
                message: self.previousRunUncleanlyTerminated
                    ? "Tunnel started after previous run ended without clean stop."
                    : "Tunnel start.",
                metadata: lifecycleMetadata
            )
            let settings = self.makeNetworkSettings(from: config)
            var didCompleteStart = false
            let completeStart: (Error?) -> Void = { error in
                guard !didCompleteStart else { return }
                didCompleteStart = true
                completionHandler(error)
            }

            self.setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    if let error {
                        self.logger.error("Failed to apply network settings: \(error.localizedDescription, privacy: .public)")
                        if RelativeLog.isVerbose {
                            NSLog("\(self.logPrefix): setTunnelNetworkSettings failed: \(error.localizedDescription)")
                        }
                        completeStart(error)
                        return
                    }

                    if RelativeLog.isVerbose {
                        self.logger.info("Tunnel network settings applied. IPv6 enabled: \(config.ipv6Enabled, privacy: .public)")
                        NSLog("\(self.logPrefix): network settings applied, starting relay")
                    }
                    self.setupPacketStream(using: config)
                    self.setupMetrics(using: config)
                    self.startRelay(using: config) { [weak self] error in
                        guard let self else { return }
                        self.queue.async {
                            if let error {
                                self.logger.error("Relay start failed after tunnel setup: \(error.localizedDescription, privacy: .public)")
                                if RelativeLog.isVerbose {
                                    NSLog("\(self.logPrefix): relay start failed after setup: \(error.localizedDescription)")
                                }
                                completeStart(error)
                                return
                            }

                            self.startDefaultPathMonitor()
                            self.startKeepaliveTimer(using: config)
                            completeStart(nil)
                        }
                    }
                }
            }
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.setIsStopping(true)
            let stopCapture = ProviderStopCapture(
                timestampEpoch: TunnelTime.nowEpochSeconds(),
                reasonRawValue: reason.rawValue,
                reasonName: String(describing: reason),
                pathSignature: self.lastObservedPathSignature ?? "path:unavailable"
            )
            self.lastProviderStopCapture = stopCapture
            self.recordLifecycleStop(appGroupID: self.configuration?.appGroupID ?? "", reason: reason)
            var stopMetadata: [String: Any] = [
                "providerStopReason": stopCapture.reasonName,
                "providerStopReasonRaw": stopCapture.reasonRawValue,
                "providerStopCapture": stopCapture.payload,
                "lifecycle": self.makeLifecycleMetadata()
            ]
            if let firstUDPWaitingCapture = self.firstUDPWaitingCapture {
                stopMetadata["firstUDPWaitingCapture"] = firstUDPWaitingCapture.payload
            }
            self.logTunnelEvent(
                level: "info",
                phase: "stop",
                message: "Tunnel stopping.",
                metadata: stopMetadata
            )
            self.stopDefaultPathMonitor()
            self.stopKeepaliveTimer()
            self.relayRestartInProgress = false
            self.relayRestartAttempts = 0
            self.pathBeforeSleep = nil
            self.cancelRelayRestartRetryWorkItem()
            self.stopRelayComponents()
            self.metricsQueue.sync {
                self.flushMetricsInternal()
                self.metricsTimer?.cancel()
                self.metricsTimer = nil
                self.metricsBuffer = nil
                self.metricsStore = nil
                self.packetStreamWriter?.close()
                self.packetStreamWriter = nil
                self.outboundStreamSampleBuffer.removeAll(keepingCapacity: false)
                self.inboundStreamSampleBuffer.removeAll(keepingCapacity: false)
                self.flowTracker = nil
                self.burstTracker = nil
                self.trafficClassifier = nil
                self.metricsSampleLimit = 0
                self.metricsSnapshotLimit = 0
            }
            self.setWaitingForBackpressureRelief(false)
            self.setReasserting(false)
            if RelativeLog.isVerbose {
                self.logger.info("Tunnel stopped with reason: \(reason.rawValue, privacy: .public)")
                NSLog("\(self.logPrefix): stopTunnel reason=\(reason.rawValue)")
            }
            completionHandler()
        }
    }

    public override func sleep(completionHandler: @escaping () -> Void) {
        queue.async {
            self.pathBeforeSleep = self.defaultPath
            self.stopDefaultPathMonitor()
            self.stopKeepaliveTimer()
            if RelativeLog.isVerbose {
                self.logger.info("Provider entering sleep; timers paused.")
                NSLog("\(self.logPrefix): sleep received")
            }
            completionHandler()
        }
    }

    public override func wake() {
        queue.async {
            guard !self.isStoppingState() else { return }
            guard let config = self.configuration else { return }
            self.startDefaultPathMonitor()
            self.startKeepaliveTimer(using: config)
            let currentPath = self.defaultPath
            let pathChanged: Bool
            switch (self.pathBeforeSleep, currentPath) {
            case let (before?, current?):
                pathChanged = !current.isEqual(before)
            case (nil, nil):
                pathChanged = false
            default:
                pathChanged = true
            }
            self.pathBeforeSleep = nil

            if pathChanged {
                if self.isRelayActive() {
                    if RelativeLog.isVerbose {
                        self.logger.info("Wake: path changed; keeping relay active without forced restart.")
                        NSLog("\(self.logPrefix): wake path changed; relay kept active")
                    }
                } else {
                    self.restartRelay(reason: "wake-relay-inactive")
                }
            } else if RelativeLog.isVerbose {
                self.logger.info("Wake: path unchanged, skipping relay restart.")
                NSLog("\(self.logPrefix): wake path unchanged, no restart")
            }
        }
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        queue.async {
            completionHandler?(self.handleAppMessageOnQueue(messageData))
        }
    }

    private func handleAppMessageOnQueue(_ messageData: Data) -> Data? {
        let payload = Self.parseAppMessagePayload(from: messageData)
        let command = Self.parseAppMessageCommand(from: payload)

        switch command {
        case "status", "diagnostics":
            return makeAppMessageResponse(command: command, ok: true)
        case "flushmetrics":
            flushMetrics()
            return makeAppMessageResponse(command: command, ok: true)
        case "restartrelay":
            relayRestartAttempts = 0
            cancelRelayRestartRetryWorkItem()
            restartRelay(reason: "app-message")
            return makeAppMessageResponse(command: command, ok: true)
        case "reloadconfiguration":
            configuration = loadConfiguration()
            return makeAppMessageResponse(command: command, ok: true)
        default:
            return makeAppMessageResponse(command: command, ok: false, error: "unsupported-command")
        }
    }

    private static func parseAppMessagePayload(from messageData: Data) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: messageData)) as? [String: Any]
    }

    private static func parseAppMessageCommand(from payload: [String: Any]?) -> String {
        (payload?["command"] as? String ?? payload?["action"] as? String ?? "status")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    private static func parseAppMessageCommand(from messageData: Data) -> String {
        parseAppMessageCommand(from: parseAppMessagePayload(from: messageData))
    }

    private func loadConfiguration() -> TunnelConfiguration {
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let config = TunnelConfiguration(providerConfiguration: providerConfiguration)
        if RelativeLog.isVerbose {
            logger.info("Loaded configuration. relayMode=\(config.relayMode, privacy: .public) mtu=\(config.mtu, privacy: .public)")
        }
        if config.appGroupID.isEmpty {
            logger.error("Missing appGroupID; metrics will be disabled.")
        }
        return config
    }

    private func logTunnelEvent(
        level: String,
        phase: String,
        message: String,
        metadata: [String: Any] = [:]
    ) {
        let metadataString: String
        if metadata.isEmpty {
            metadataString = "{}"
        } else if JSONSerialization.isValidJSONObject(metadata),
                  let data = try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]),
                  let string = String(data: data, encoding: .utf8) {
            metadataString = string
        } else {
            metadataString = "\(metadata)"
        }
        switch level.lowercased() {
        case "error":
            logger.error("phase=\(phase, privacy: .public) message=\(message, privacy: .public) metadata=\(metadataString, privacy: .public)")
        case "warning":
            logger.warning("phase=\(phase, privacy: .public) message=\(message, privacy: .public) metadata=\(metadataString, privacy: .public)")
        default:
            logger.info("phase=\(phase, privacy: .public) message=\(message, privacy: .public) metadata=\(metadataString, privacy: .public)")
        }
    }

    private func currentTunQueueStats() -> TunSocketQueueStats? {
        currentTunBridge()?.queueStats()
    }

    private func currentSocksConnectionCount() -> Int {
        currentSocksServer()?.activeConnectionCount() ?? 0
    }

    private func recordSocksDiagnostic(component: String, level: String, message: String) {
        let normalizedLevel = level.lowercased()
        let formatted = "SOCKS5 \(component): \(message)"
        if component == "udp",
           firstUDPWaitingCapture == nil,
           message.contains("waiting error=") {
            firstUDPWaitingCapture = UDPWaitingCapture(
                timestampEpoch: TunnelTime.nowEpochSeconds(),
                level: normalizedLevel,
                component: component,
                message: formatted,
                pathSignature: lastObservedPathSignature ?? "path:unavailable"
            )
        }
        if RelativeLog.isVerbose {
            logger.debug("SOCKS5 diagnostic event: \(formatted, privacy: .public)")
        }

        guard normalizedLevel == "warning" || normalizedLevel == "error" else {
            return
        }
        logTunnelEvent(
            level: normalizedLevel,
            phase: "network",
            message: formatted,
            metadata: [
                "path": lastObservedPathSignature ?? "path:unavailable",
                "relayRestartInProgress": relayRestartInProgress,
                "reasserting": reassertingState
            ]
        )
    }

    private func lifecycleDefaults(appGroupID: String) -> UserDefaults? {
        guard !appGroupID.isEmpty else { return nil }
        return UserDefaults(suiteName: appGroupID)
    }

    private func makeLifecycleMetadata() -> [String: Any] {
        var metadata: [String: Any] = [
            "runID": currentRunID,
            "bootCount": currentRunBootCount,
            "previousRunUnclean": previousRunUncleanlyTerminated
        ]
        if let previousRunID {
            metadata["previousRunID"] = previousRunID
        }
        if let previousRunStartEpoch {
            metadata["previousRunStartEpoch"] = previousRunStartEpoch
        }
        if let previousRunStopEpoch {
            metadata["previousRunStopEpoch"] = previousRunStopEpoch
        }
        return metadata
    }

    @discardableResult
    private func recordLifecycleStart(appGroupID: String) -> [String: Any] {
        let now = TunnelTime.nowEpochSeconds()
        let newRunID = UUID().uuidString
        var bootCount = 1
        var priorRunID: String?
        var priorRunCleanStop = true
        var priorRunStartEpoch: TimeInterval?
        var priorRunStopEpoch: TimeInterval?

        if let defaults = lifecycleDefaults(appGroupID: appGroupID) {
            priorRunID = defaults.string(forKey: Self.lifecycleLastRunIDKey)
            if defaults.object(forKey: Self.lifecycleLastRunCleanStopKey) != nil {
                priorRunCleanStop = defaults.bool(forKey: Self.lifecycleLastRunCleanStopKey)
            }
            if defaults.object(forKey: Self.lifecycleLastRunStartEpochKey) != nil {
                priorRunStartEpoch = defaults.double(forKey: Self.lifecycleLastRunStartEpochKey)
            }
            if defaults.object(forKey: Self.lifecycleLastRunStopEpochKey) != nil {
                priorRunStopEpoch = defaults.double(forKey: Self.lifecycleLastRunStopEpochKey)
            }
            bootCount = defaults.integer(forKey: Self.lifecycleBootCountKey) + 1
            defaults.set(bootCount, forKey: Self.lifecycleBootCountKey)
            defaults.set(newRunID, forKey: Self.lifecycleLastRunIDKey)
            defaults.set(now, forKey: Self.lifecycleLastRunStartEpochKey)
            defaults.removeObject(forKey: Self.lifecycleLastRunStopEpochKey)
            defaults.removeObject(forKey: Self.lifecycleLastRunStopReasonKey)
            defaults.set(false, forKey: Self.lifecycleLastRunCleanStopKey)
        }

        currentRunID = newRunID
        currentRunBootCount = bootCount
        previousRunID = priorRunID
        previousRunStartEpoch = priorRunStartEpoch
        previousRunStopEpoch = priorRunStopEpoch
        previousRunUncleanlyTerminated = priorRunID != nil && !priorRunCleanStop
        return makeLifecycleMetadata()
    }

    private func recordLifecycleStop(appGroupID: String, reason: NEProviderStopReason) {
        previousRunUncleanlyTerminated = false
        previousRunID = nil
        previousRunStartEpoch = nil
        previousRunStopEpoch = nil
        guard let defaults = lifecycleDefaults(appGroupID: appGroupID) else { return }
        defaults.set(TunnelTime.nowEpochSeconds(), forKey: Self.lifecycleLastRunStopEpochKey)
        defaults.set(String(describing: reason), forKey: Self.lifecycleLastRunStopReasonKey)
        defaults.set(true, forKey: Self.lifecycleLastRunCleanStopKey)
    }

    private func makeNetworkSettings(from config: TunnelConfiguration) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.tunnelRemoteAddress)

        let ipv4 = NEIPv4Settings(addresses: [config.ipv4Address], subnetMasks: [config.ipv4SubnetMask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        #if os(macOS)
        ipv4.router = config.ipv4Router
        #endif
        settings.ipv4Settings = ipv4

        if config.ipv6Enabled {
            let prefix = NSNumber(value: config.ipv6PrefixLength)
            let ipv6 = NEIPv6Settings(addresses: [config.ipv6Address], networkPrefixLengths: [prefix])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }

        let allowIPv6Hosts = shouldAllowLiteralIPv6Hosts(for: config)
        let dnsFilter = sanitizeHosts(config.dnsServers, allowIPv6Literals: allowIPv6Hosts)
        if dnsFilter.droppedIPv6Count > 0 {
            logger.warning(
                "Filtered \(dnsFilter.droppedIPv6Count, privacy: .public) IPv6 DNS server(s); ipv6Enabled=\(config.ipv6Enabled, privacy: .public) defaultPath=\(self.safeDefaultPathSignatureForLogs(), privacy: .public)"
            )
        }
        if !dnsFilter.hosts.isEmpty {
            let dnsSettings = NEDNSSettings(servers: dnsFilter.hosts)
            if isRunningInsideExtensionRuntime() {
                // Explicitly scope this resolver to all domains for full-tunnel behavior.
                dnsSettings.matchDomains = [""]
                dnsSettings.matchDomainsNoSearch = true
            }
            settings.dnsSettings = dnsSettings
        }

        settings.mtu = NSNumber(value: config.mtu)
        settings.tunnelOverheadBytes = NSNumber(value: config.tunnelOverheadBytes)
        return settings
    }

    private func setupMetrics(using config: TunnelConfiguration) {
        guard config.metricsEnabled, !config.appGroupID.isEmpty else { return }
        let sampleLimit = max(1, min(config.metricsRingBufferSize, 200))
        let snapshotLimit = max(1, min(config.maxPendingAnalytics, 60))
        metricsQueue.sync {
            flowTracker = FlowTracker(
                configuration: FlowTrackerConfiguration(
                    burstThreshold: TimeInterval(config.burstThresholdMs) / 1000.0,
                    flowTTL: TimeInterval(config.flowTTLSeconds),
                    maxTrackedFlows: config.maxTrackedFlows
                )
            )
            burstTracker = BurstTracker(
                ttl: TimeInterval(config.flowTTLSeconds),
                maxBursts: max(64, config.maxTrackedFlows * 2)
            )
            let signatureURL = AppSignatureStore.defaultURL(
                appGroupID: config.appGroupID,
                fileName: config.signatureFileName
            )
            trafficClassifier = TrafficClassifier(signatureFileURL: signatureURL)
            metricsSampleLimit = sampleLimit
            metricsSnapshotLimit = snapshotLimit
            metricsBuffer = MetricsRingBuffer(capacity: sampleLimit)
            metricsStore = MetricsStore(
                appGroupID: config.appGroupID,
                maxSnapshots: snapshotLimit,
                maxBytes: 1_500_000,
                format: config.metricsStoreFormat,
                useLock: true
            )
        }

        let timer = DispatchSource.makeTimerSource(queue: metricsQueue)
        timer.schedule(deadline: .now() + config.metricsSnapshotInterval, repeating: config.metricsSnapshotInterval)
        timer.setEventHandler { [weak self] in
            self?.flushMetricsInternal()
        }
        timer.resume()
        metricsTimer = timer
        if RelativeLog.isVerbose {
            metricsLogger.info("Metrics enabled. Snapshot interval: \(config.metricsSnapshotInterval, privacy: .public)s, sample cap: \(sampleLimit, privacy: .public), snapshot cap: \(snapshotLimit, privacy: .public)")
        }
    }

    private func setupPacketStream(using config: TunnelConfiguration) {
        let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: config.appGroupID)
        let streamURL = PacketSampleStreamLocation.makeURL(appGroupID: config.appGroupID)

        guard config.packetStreamEnabled, !config.appGroupID.isEmpty else {
            NSLog("\(logPrefix): packet stream disabled (enabled=\(config.packetStreamEnabled), appGroup=\(config.appGroupID)) container=\(containerURL?.path ?? "nil") stream=\(streamURL?.path ?? "nil")")
            return
        }

        metricsQueue.sync {
            packetStreamWriter = PacketSampleStreamWriter(
                appGroupID: config.appGroupID,
                maxBytes: config.packetStreamMaxBytes,
                useLock: true
            )
        }
        metricsLogger.info("Packet stream enabled. Max bytes: \(config.packetStreamMaxBytes, privacy: .public). Container: \(containerURL?.path ?? "nil", privacy: .public). Stream: \(streamURL?.path ?? "nil", privacy: .public)")
        NSLog("\(logPrefix): packet stream enabled maxBytes=\(config.packetStreamMaxBytes) container=\(containerURL?.path ?? "nil") stream=\(streamURL?.path ?? "nil")")
    }

    private func flushMetrics() {
        metricsQueue.async { [weak self] in
            self?.flushMetricsInternal()
        }
    }

    private func flushMetricsInternal() {
        guard let metricsBuffer, let metricsStore else { return }
        let samples = metricsBuffer.snapshot(limit: metricsSampleLimit > 0 ? metricsSampleLimit : nil)
        metricsBuffer.clear()
        guard !samples.isEmpty else { return }
        let snapshot = MetricsSnapshot(capturedAt: TunnelTime.nowEpochSeconds(), samples: samples)
        metricsWriteQueue.async {
            metricsStore.append(snapshot)
        }
        if RelativeLog.isVerbose {
            metricsLogger.debug("Flushed \(samples.count, privacy: .public) samples.")
        }
    }

    private func startPacketReadLoop() {
        guard !waitingForBackpressureReliefState() else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.ioQueue.async {
                guard !self.isStoppingState() else { return }
                self.handlePackets(packets, protocols: protocols)
                if let tunBridge = self.currentTunBridge(), tunBridge.isBackpressured() {
                    self.setWaitingForBackpressureRelief(true)
                } else {
                    self.startPacketReadLoop()
                }
            }
        }
    }

    private func handlePackets(_ packets: [Data], protocols: [NSNumber]) {
        let timestamp = TunnelTime.nowEpochSeconds()
        for (index, packet) in packets.enumerated() {
            let protoHint = protocols.indices.contains(index) ? protocols[index].int32Value : 0
            if let tunBridge = currentTunBridge() {
                _ = tunBridge.writePacket(packet, ipVersionHint: protoHint)
            }
        }

        metricsQueue.async { [weak self] in
            self?.recordOutboundPackets(packets, protocols: protocols, timestamp: timestamp)
        }
    }

    private func startRelay(using config: TunnelConfiguration, completion: @escaping (Error?) -> Void) {
        guard config.relayMode == "tun2socks" else {
            warnRelayIfNeeded(config)
            completion(nil)
            return
        }

        let socksPort = UInt16(clamping: config.engineSocksPort)
        let socksServer = Socks5Server(provider: self, queue: ioQueue, mtu: config.mtu) { [weak self] component, level, message in
            self?.queue.async {
                self?.recordSocksDiagnostic(component: component, level: level, message: message)
            }
        }
        self.setSocksServer(socksServer)
        socksServer.start(port: socksPort) { [weak self] result in
            guard let self else { return }
            self.queue.async {
                switch result {
                case .success(let port):
                    if RelativeLog.isVerbose {
                        NSLog("\(self.logPrefix): SOCKS5 server ready on port \(port)")
                        self.probeSocksPort(port)
                    }
                    do {
                        let bridge = try TunSocketBridge(mtu: config.mtu, queue: self.ioQueue)
                        self.setTunBridge(bridge)
                        bridge.onBackpressureRelieved = { [weak self] in
                            self?.resumePacketReadLoopIfNeeded()
                        }
                        bridge.startReadLoop { [weak self] packets, families in
                            self?.handleInboundPackets(packets, families: families)
                        }

                        let engine = Tun2SocksEngine()
                        self.setEngine(engine)
                        engine.start(configuration: config, tunFD: bridge.engineFD, socksPort: port)

                        if RelativeLog.isVerbose {
                            self.logger.info("tun2socks engine started on \(port, privacy: .public)")
                            NSLog("\(self.logPrefix): tun2socks engine started")
                        }
                        self.ioQueue.async { [weak self] in
                            self?.startPacketReadLoop()
                        }
                        completion(nil)
                    } catch {
                        self.currentSocksServer()?.stop()
                        self.setSocksServer(nil)
                        self.logger.error("Failed to start tun bridge: \(error.localizedDescription, privacy: .public)")
                        if RelativeLog.isVerbose {
                            NSLog("\(self.logPrefix): Failed to start tun bridge: \(error.localizedDescription)")
                        }
                        completion(error)
                    }
                case .failure(let error):
                    self.logger.error("SOCKS5 server failed to start: \(error.localizedDescription, privacy: .public)")
                    if RelativeLog.isVerbose {
                        NSLog("\(self.logPrefix): SOCKS5 server failed: \(error.localizedDescription)")
                    }
                    self.currentSocksServer()?.stop()
                    self.setSocksServer(nil)
                    completion(error)
                }
            }
        }
    }

    private func stopRelayComponents() {
        currentEngine()?.stop()
        setEngine(nil)
        currentTunBridge()?.stop()
        setTunBridge(nil)
        currentSocksServer()?.stop()
        setSocksServer(nil)
        keepaliveSession?.cancel()
        keepaliveSession = nil
    }

    private func startDefaultPathMonitor() {
        stopDefaultPathMonitor()
        let currentPath = defaultPath
        lastObservedPathSignature = defaultPathSignature(currentPath)
        lastObservedPathForRestart = currentPath
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 2, repeating: 2)
        timer.setEventHandler { [weak self] in
            self?.handleDefaultPathMonitorTick()
        }
        timer.resume()
        defaultPathMonitorTimer = timer
    }

    private func stopDefaultPathMonitor() {
        defaultPathMonitorTimer?.cancel()
        defaultPathMonitorTimer = nil
        lastObservedPathSignature = nil
        lastObservedPathForRestart = nil
    }

    private func startKeepaliveTimer(using config: TunnelConfiguration) {
        stopKeepaliveTimer()
        guard config.relayMode == "tun2socks" else { return }
        guard config.keepaliveIntervalSeconds > 0 else { return }
        keepaliveProbeHosts = keepaliveHosts(for: config)
        keepaliveProbeHostIndex = 0
        let interval = max(10, config.keepaliveIntervalSeconds)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            self?.sendKeepaliveProbeIfNeeded()
        }
        timer.resume()
        keepaliveTimer = timer
    }

    private func stopKeepaliveTimer() {
        keepaliveTimer?.cancel()
        keepaliveTimer = nil
        keepaliveSession?.cancel()
        keepaliveSession = nil
        keepaliveProbeHosts = []
        keepaliveProbeHostIndex = 0
    }

    private func sendKeepaliveProbeIfNeeded() {
        guard !isStoppingState(), !relayRestartInProgress else { return }
        guard let config = configuration, config.relayMode == "tun2socks" else { return }
        guard config.keepaliveIntervalSeconds > 0 else { return }
        guard let path = defaultPath, path.status == .satisfied else {
            keepaliveSession?.cancel()
            keepaliveSession = nil
            if RelativeLog.isVerbose {
                logger.debug("Skipping keepalive probe while default path is unsatisfied.")
            }
            return
        }

        if keepaliveSession == nil {
            if keepaliveProbeHosts.isEmpty {
                keepaliveProbeHosts = keepaliveHosts(for: config)
                keepaliveProbeHostIndex = 0
            }
            guard let endpoint = currentKeepaliveEndpoint() else { return }
            keepaliveSession = makeKeepaliveSession(to: endpoint)
        }
        guard let session = keepaliveSession else { return }
        session.writeDatagram(Self.keepaliveDNSQuery) { [weak self, session] error in
            guard let self else { return }
            guard let error else { return }
            self.queue.async {
                if RelativeLog.isVerbose {
                    self.logger.warning("Keepalive probe failed: \(error.localizedDescription, privacy: .public)")
                }
                if let current = self.keepaliveSession, current === session {
                    self.keepaliveSession?.cancel()
                    self.keepaliveSession = nil
                    self.rotateKeepaliveProbeHost()
                }
            }
        }
    }

    private func makeKeepaliveSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession? {
        guard let portValue = UInt16(endpoint.port),
              let port = Network.NWEndpoint.Port(rawValue: portValue) else {
            if RelativeLog.isVerbose {
                logger.warning("Skipping keepalive probe due to invalid endpoint port \(endpoint.port, privacy: .public).")
            }
            return nil
        }

        let parameters = Network.NWParameters.udp
        if #available(iOS 18.0, macOS 15.0, *) {
            if let virtualInterface = virtualInterface {
                parameters.prohibitedInterfaces = [virtualInterface]
                if RelativeLog.isVerbose {
                    logger.debug("Keepalive UDP prohibiting interface \(virtualInterface.name, privacy: .public)")
                }
            }
        }

        let host = Network.NWEndpoint.Host(endpoint.hostname)
        let connection = Network.NWConnection(host: host, port: port, using: parameters)
        return NWConnectionUDPSessionAdapter(connection, queue: queue)
    }

    private func keepaliveHosts(for config: TunnelConfiguration) -> [String] {
        let allowIPv6Hosts = shouldAllowLiteralIPv6Hosts(for: config)
        let configured = sanitizeHosts(config.dnsServers, allowIPv6Literals: allowIPv6Hosts).hosts
        if !configured.isEmpty {
            return configured
        }
        return sanitizeHosts(Self.keepaliveFallbackHosts, allowIPv6Literals: allowIPv6Hosts).hosts
    }

    private func shouldAllowLiteralIPv6Hosts(for config: TunnelConfiguration) -> Bool {
        // Follow tunnel configuration for IPv6 literals. `defaultPath` here is NetworkExtension.NWPath,
        // which doesn't expose per-family routing capability like Network.NWPath.supportsIPv6.
        config.ipv6Enabled
    }

    private func sanitizeHosts(
        _ hosts: [String],
        allowIPv6Literals: Bool
    ) -> (hosts: [String], droppedIPv6Count: Int) {
        var seen = Set<String>()
        var sanitized: [String] = []
        var droppedIPv6Count = 0
        sanitized.reserveCapacity(hosts.count)

        for host in hosts {
            let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }

            if !allowIPv6Literals && Self.isLiteralIPv6Address(trimmed) {
                droppedIPv6Count += 1
                continue
            }

            let key = trimmed.lowercased()
            guard seen.insert(key).inserted else { continue }
            sanitized.append(trimmed)
        }

        return (sanitized, droppedIPv6Count)
    }

    private static func isLiteralIPv6Address(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private func safeDefaultPathSignatureForLogs() -> String {
        guard isRunningInsideExtensionRuntime() else { return "path:unavailable" }
        return defaultPathSignature(defaultPath)
    }

    private func isRunningInsideExtensionRuntime() -> Bool {
        Bundle.main.bundlePath.hasSuffix(".appex")
    }

    private func currentKeepaliveEndpoint() -> NWHostEndpoint? {
        guard keepaliveProbeHosts.indices.contains(keepaliveProbeHostIndex) else { return nil }
        let host = keepaliveProbeHosts[keepaliveProbeHostIndex]
        return NWHostEndpoint(hostname: host, port: "53")
    }

    private func rotateKeepaliveProbeHost() {
        guard !keepaliveProbeHosts.isEmpty else { return }
        keepaliveProbeHostIndex = (keepaliveProbeHostIndex + 1) % keepaliveProbeHosts.count
        if RelativeLog.isVerbose {
            let host = keepaliveProbeHosts[keepaliveProbeHostIndex]
            logger.info("Rotated keepalive probe host to \(host, privacy: .public)")
        }
    }

    private func handleDefaultPathMonitorTick() {
        guard !isStoppingState() else { return }
        guard let currentPath = defaultPath else { return }
        let diagnosticSignature = defaultPathSignature(currentPath)
        if diagnosticSignature != lastObservedPathSignature {
            lastObservedPathSignature = diagnosticSignature
        }

        guard currentPath.status == .satisfied else { return }
        if let previousPath = lastObservedPathForRestart, currentPath.isEqual(previousPath) {
            return
        }

        lastObservedPathForRestart = currentPath
        if isRelayActive() {
            if RelativeLog.isVerbose {
                logger.info("Path changed; relay remains active without restart.")
                NSLog("\(logPrefix): path changed; relay kept active")
            }
            return
        }

        restartRelay(reason: "path-change-relay-inactive")
    }

    private func restartRelay(reason: String) {
        guard !relayRestartInProgress, !isStoppingState() else { return }
        guard let config = configuration, config.relayMode == "tun2socks" else { return }
        logTunnelEvent(level: "info", phase: "restart", message: "Relay restart requested.", metadata: ["reason": reason])
        let isRetryAttempt = reason.contains("-retry")
        if !isRetryAttempt {
            relayRestartAttempts = 0
        }
        cancelRelayRestartRetryWorkItem()
        relayRestartInProgress = true
        setWaitingForBackpressureRelief(false)
        setReasserting(true)
        stopKeepaliveTimer()
        if RelativeLog.isVerbose {
            logger.info("Re-establishing relay due to \(reason, privacy: .public).")
            NSLog("\(logPrefix): restarting relay, reason=\(reason)")
        }

        stopRelayComponents()
        startRelay(using: config) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.relayRestartInProgress = false
                if let error {
                    self.logger.error("Failed to restart relay (\(reason, privacy: .public)): \(error.localizedDescription, privacy: .public)")
                    if RelativeLog.isVerbose {
                        NSLog("\(self.logPrefix): relay restart failed, reason=\(reason), error=\(error.localizedDescription)")
                    }
                    self.logTunnelEvent(
                        level: "error",
                        phase: "restart",
                        message: "Relay restart failed.",
                        metadata: [
                            "reason": reason,
                            "error": error.localizedDescription
                        ]
                    )
                    self.relayRestartAttempts += 1
                    if self.relayRestartAttempts <= Self.maxRelayRestartAttempts {
                        let delay = pow(2.0, Double(self.relayRestartAttempts))
                        self.logger.warning(
                            "Relay restart failed (attempt \(self.relayRestartAttempts, privacy: .public)/\(Self.maxRelayRestartAttempts, privacy: .public)); retrying in \(delay, privacy: .public)s"
                        )
                        self.logTunnelEvent(
                            level: "warning",
                            phase: "restart",
                            message: "Relay restart retry scheduled.",
                            metadata: [
                                "reason": reason,
                                "attempt": self.relayRestartAttempts,
                                "maxAttempts": Self.maxRelayRestartAttempts,
                                "delaySeconds": delay
                            ]
                        )
                        let retryReason = "\(reason)-retry\(self.relayRestartAttempts)"
                        let workItem = DispatchWorkItem { [weak self] in
                            guard let self else { return }
                            self.relayRestartRetryWorkItem = nil
                            self.restartRelay(reason: retryReason)
                        }
                        self.relayRestartRetryWorkItem = workItem
                        self.queue.asyncAfter(deadline: .now() + delay, execute: workItem)
                        return
                    }

                    self.logger.error("Relay restart exhausted \(Self.maxRelayRestartAttempts, privacy: .public) attempts; cancelling tunnel.")
                    self.relayRestartAttempts = 0
                    self.cancelRelayRestartRetryWorkItem()
                    self.setReasserting(false)
                    self.logTunnelEvent(
                        level: "error",
                        phase: "restart",
                        message: "Relay restart exhausted retries; cancelling tunnel.",
                        metadata: ["reason": reason]
                    )
                    self.cancelTunnelWithError(error)
                    return
                }

                self.relayRestartAttempts = 0
                self.cancelRelayRestartRetryWorkItem()
                self.startKeepaliveTimer(using: config)
                self.setReasserting(false)
                self.logTunnelEvent(
                    level: "info",
                    phase: "restart",
                    message: "Relay restart completed.",
                    metadata: ["reason": reason]
                )
            }
        }
    }

    private func defaultPathSignature(_ path: NWPath?) -> String {
        guard let path else { return "path:nil" }
        let status: String
        switch path.status {
        case .satisfied:
            status = "satisfied"
        case .unsatisfied:
            status = "unsatisfied"
        case .satisfiable:
            status = "satisfiable"
        case .invalid:
            status = "invalid"
        @unknown default:
            status = "unknown"
        }
        let interfaces = [pathDescriptorFingerprint(for: path)]
        return buildPathSignature(
            status: status,
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            interfaces: interfaces
        )
    }

    private func handleInboundPackets(_ packets: [Data], families: [Int32]) {
        guard !isStoppingState() else { return }
        guard !packets.isEmpty else { return }

        var protocols: [NSNumber] = []
        protocols.reserveCapacity(packets.count)
        for (index, packet) in packets.enumerated() {
            if families.indices.contains(index) {
                protocols.append(NSNumber(value: families[index]))
            } else {
                let family: Int32 = packet.first.map { (($0 >> 4) & 0x0F) == 6 ? AF_INET6 : AF_INET } ?? AF_INET
                protocols.append(NSNumber(value: family))
            }
        }

        let success = packetFlow.writePackets(packets, withProtocols: protocols)
        if !success {
            logger.error("Failed to write inbound packets to flow.")
        }

        let timestamp = TunnelTime.nowEpochSeconds()
        metricsQueue.async { [weak self] in
            self?.recordInboundPackets(packets, families: families, timestamp: timestamp)
        }
    }

    private func recordOutboundPackets(_ packets: [Data], protocols: [NSNumber], timestamp: TimeInterval) {
        guard let metricsBuffer else { return }
        let writer = packetStreamWriter
        if writer != nil {
            outboundStreamSampleBuffer.removeAll(keepingCapacity: true)
            outboundStreamSampleBuffer.reserveCapacity(packets.count)
        }

        for (index, packet) in packets.enumerated() {
            let protoHint = protocols.indices.contains(index) ? protocols[index].int32Value : 0
            if let metadata = PacketParser.parse(packet, ipVersionHint: protoHint) {
                let observation = flowTracker?.record(metadata: metadata, timestamp: timestamp) ?? FlowObservation(flowId: 0, burstId: 0)
                let burstMetrics = burstTracker?.record(
                    flowId: observation.flowId,
                    burstId: observation.burstId,
                    timestamp: timestamp,
                    length: metadata.length
                )
                let classification = trafficClassifier?.classify(
                    metadata: metadata,
                    direction: .outbound,
                    timestamp: timestamp
                )
                let sample = PacketSample(
                    timestamp: timestamp,
                    direction: .outbound,
                    ipVersion: metadata.ipVersion,
                    transport: metadata.transport,
                    length: metadata.length,
                    flowId: observation.flowId,
                    burstId: observation.burstId,
                    srcIPAddress: metadata.srcAddress,
                    dstIPAddress: metadata.dstAddress,
                    srcPort: metadata.srcPort,
                    dstPort: metadata.dstPort,
                    dnsQueryName: metadata.dnsQueryName,
                    dnsCname: metadata.dnsCname,
                    dnsAnswerIPAddresses: metadata.dnsAnswerAddresses,
                    registrableDomain: metadata.registrableDomain,
                    tlsServerName: metadata.tlsServerName,
                    quicVersion: metadata.quicVersion,
                    quicPacketType: metadata.quicPacketType,
                    quicDestinationConnectionId: metadata.quicDestinationConnectionId,
                    quicSourceConnectionId: metadata.quicSourceConnectionId,
                    burstMetrics: burstMetrics,
                    trafficClassification: classification
                )
                metricsBuffer.append(sample)
                if writer != nil {
                    outboundStreamSampleBuffer.append(sample)
                }
                self.packetCount &+= 1
                if self.packetCount % 500 == 0 {
                    if RelativeLog.isVerbose {
                        self.logger.info("Observed \(self.packetCount, privacy: .public) outbound packets.")
                    }
                }
                if let dnsQuery = metadata.dnsQueryName, RelativeLog.isVerbose {
                    self.parserLogger.debug("DNS query: \(dnsQuery, privacy: .public)")
                }
            } else {
                if RelativeLog.isVerbose {
                    self.parserLogger.debug("Dropped unparsed packet of length \(packet.count, privacy: .public)")
                }
            }
        }

        if let writer, !outboundStreamSampleBuffer.isEmpty {
            writer.append(outboundStreamSampleBuffer)
        }
    }

    private func recordInboundPackets(_ packets: [Data], families: [Int32], timestamp: TimeInterval) {
        guard let metricsBuffer else { return }
        let writer = packetStreamWriter
        if writer != nil {
            inboundStreamSampleBuffer.removeAll(keepingCapacity: true)
            inboundStreamSampleBuffer.reserveCapacity(packets.count)
        }

        for (index, packet) in packets.enumerated() {
            let family = families.indices.contains(index) ? families[index] : 0
            if let metadata = PacketParser.parse(packet, ipVersionHint: family) {
                let observation = flowTracker?.record(metadata: metadata, timestamp: timestamp) ?? FlowObservation(flowId: 0, burstId: 0)
                let burstMetrics = burstTracker?.record(
                    flowId: observation.flowId,
                    burstId: observation.burstId,
                    timestamp: timestamp,
                    length: metadata.length
                )
                let classification = trafficClassifier?.classify(
                    metadata: metadata,
                    direction: .inbound,
                    timestamp: timestamp
                )
                let sample = PacketSample(
                    timestamp: timestamp,
                    direction: .inbound,
                    ipVersion: metadata.ipVersion,
                    transport: metadata.transport,
                    length: metadata.length,
                    flowId: observation.flowId,
                    burstId: observation.burstId,
                    srcIPAddress: metadata.srcAddress,
                    dstIPAddress: metadata.dstAddress,
                    srcPort: metadata.srcPort,
                    dstPort: metadata.dstPort,
                    dnsQueryName: metadata.dnsQueryName,
                    dnsCname: metadata.dnsCname,
                    dnsAnswerIPAddresses: metadata.dnsAnswerAddresses,
                    registrableDomain: metadata.registrableDomain,
                    tlsServerName: metadata.tlsServerName,
                    quicVersion: metadata.quicVersion,
                    quicPacketType: metadata.quicPacketType,
                    quicDestinationConnectionId: metadata.quicDestinationConnectionId,
                    quicSourceConnectionId: metadata.quicSourceConnectionId,
                    burstMetrics: burstMetrics,
                    trafficClassification: classification
                )
                metricsBuffer.append(sample)
                if writer != nil {
                    inboundStreamSampleBuffer.append(sample)
                }
                self.inboundPacketCount &+= 1
                if self.inboundPacketCount % 500 == 0 {
                    if RelativeLog.isVerbose {
                        self.logger.info("Observed \(self.inboundPacketCount, privacy: .public) inbound packets.")
                    }
                }
            }
        }

        if let writer, !inboundStreamSampleBuffer.isEmpty {
            writer.append(inboundStreamSampleBuffer)
        }
    }

    private func probeSocksPort(_ port: UInt16) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 {
            let err = errno
            if RelativeLog.isVerbose {
                NSLog("\(logPrefix): SOCKS5 probe socket failed errno=\(err)")
            }
            return
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        var inaddr = in_addr()
        _ = inet_pton(AF_INET, "127.0.0.1", &inaddr)
        addr.sin_addr = inaddr

        let result = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if result == 0 {
            if RelativeLog.isVerbose {
                NSLog("\(logPrefix): SOCKS5 probe to 127.0.0.1:\(port) succeeded")
            }
        } else {
            let err = errno
            if RelativeLog.isVerbose {
                NSLog("\(logPrefix): SOCKS5 probe to 127.0.0.1:\(port) failed errno=\(err)")
            }
        }
    }

    private func warnRelayIfNeeded(_ config: TunnelConfiguration) {
        guard !didWarnRelay else { return }
        didWarnRelay = true
        logger.error("Relay engine not configured. Packets are observed but not forwarded.")
        logger.error("Provide a tun2socks or lwIP engine to enable full connectivity.")
    }

    private func isRelayActive() -> Bool {
        currentSocksServer() != nil && currentTunBridge() != nil && currentEngine() != nil
    }

    private func resumePacketReadLoopIfNeeded() {
        ioQueue.async { [weak self] in
            guard let self else { return }
            guard self.waitingForBackpressureReliefState(), !self.isStoppingState() else { return }
            if let tunBridge = self.currentTunBridge(), tunBridge.isBackpressured() {
                return
            }
            self.setWaitingForBackpressureRelief(false)
            self.startPacketReadLoop()
        }
    }

    private func setSocksServer(_ value: Socks5Server?) {
        stateQueue.sync {
            socksServer = value
        }
    }

    private func currentSocksServer() -> Socks5Server? {
        stateQueue.sync {
            socksServer
        }
    }

    private func setTunBridge(_ value: TunSocketBridge?) {
        stateQueue.sync {
            tunBridge = value
        }
    }

    private func currentTunBridge() -> TunSocketBridge? {
        stateQueue.sync {
            tunBridge
        }
    }

    private func setEngine(_ value: Tun2SocksEngine?) {
        stateQueue.sync {
            engine = value
        }
    }

    private func currentEngine() -> Tun2SocksEngine? {
        stateQueue.sync {
            engine
        }
    }

    private func setIsStopping(_ value: Bool) {
        stateQueue.sync {
            isStopping = value
        }
    }

    private func isStoppingState() -> Bool {
        stateQueue.sync {
            isStopping
        }
    }

    private func setWaitingForBackpressureRelief(_ value: Bool) {
        stateQueue.sync {
            waitingForBackpressureRelief = value
        }
    }

    private func waitingForBackpressureReliefState() -> Bool {
        stateQueue.sync {
            waitingForBackpressureRelief
        }
    }

    private func setReasserting(_ value: Bool) {
        reassertingState = value
        reasserting = value
    }

    private func cancelRelayRestartRetryWorkItem() {
        relayRestartRetryWorkItem?.cancel()
        relayRestartRetryWorkItem = nil
    }

    private func makeAppMessageResponse(command: String, ok: Bool, error: String? = nil) -> Data? {
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            var payload: [String: Any] = [
                "ok": ok,
                "command": command,
                "error": error ?? NSNull(),
                "timestamp": TunnelTime.nowEpochSeconds(),
                "defaultPathSignature": "path:unavailable",
                "lifecycle": makeLifecycleMetadata()
            ]
            if let firstUDPWaitingCapture {
                payload["firstUDPWaitingCapture"] = firstUDPWaitingCapture.payload
            }
            if let lastProviderStopCapture {
                payload["lastProviderStopCapture"] = lastProviderStopCapture.payload
            }
            return try? JSONSerialization.data(withJSONObject: payload, options: [])
        }

        var packetCounts: (outbound: UInt64, inbound: UInt64) = (0, 0)
        metricsQueue.sync {
            packetCounts = (packetCount, inboundPacketCount)
        }
        let socksConnections = currentSocksConnectionCount()
        let tunQueueStats = currentTunQueueStats()
        var payload: [String: Any] = [
            "ok": ok,
            "command": command,
            "error": error ?? NSNull(),
            "timestamp": TunnelTime.nowEpochSeconds(),
            "isStopping": isStoppingState(),
            "waitingForBackpressureRelief": waitingForBackpressureReliefState(),
            "relayRestartInProgress": relayRestartInProgress,
            "reasserting": reassertingState,
            "relayMode": configuration?.relayMode ?? "",
            // Avoid touching defaultPath when the provider is not running in an extension context.
            "defaultPathSignature": lastObservedPathSignature ?? "path:unavailable",
            "lastObservedPathSignature": lastObservedPathSignature as Any,
            "outboundPacketCount": packetCounts.outbound,
            "inboundPacketCount": packetCounts.inbound,
            "socksActiveConnections": socksConnections,
            "lifecycle": makeLifecycleMetadata()
        ]
        if let tunQueueStats {
            payload["tunPendingPackets"] = tunQueueStats.pendingPackets
            payload["tunPendingBytes"] = tunQueueStats.pendingBytes
            payload["tunDroppedWrites"] = tunQueueStats.droppedWrites
            payload["tunBackpressured"] = tunQueueStats.backpressured
            payload["tunMaxPendingBytes"] = tunQueueStats.maxPendingBytes
        }
        if let firstUDPWaitingCapture {
            payload["firstUDPWaitingCapture"] = firstUDPWaitingCapture.payload
        }
        if let lastProviderStopCapture {
            payload["lastProviderStopCapture"] = lastProviderStopCapture.payload
        }
        return try? JSONSerialization.data(withJSONObject: payload, options: [])
    }

    private func pathDescriptorFingerprint(for path: NWPath) -> String {
        let descriptor = String(describing: path)
        let digest = UInt64(bitPattern: Int64(descriptor.hashValue))
        return String(digest, radix: 16)
    }

    private func buildPathSignature(
        status: String,
        isExpensive: Bool,
        isConstrained: Bool,
        interfaces: [String]
    ) -> String {
        "\(status)|exp=\(isExpensive)|con=\(isConstrained)|if=\(interfaces.joined(separator: ","))"
    }
}

#if DEBUG
extension RelativePacketTunnelProvider {
    func _test_makeNetworkSettings(from config: TunnelConfiguration) -> NEPacketTunnelNetworkSettings {
        makeNetworkSettings(from: config)
    }

    func _test_buildPathSignature(
        status: String,
        isExpensive: Bool,
        isConstrained: Bool,
        interfaces: [String]
    ) -> String {
        buildPathSignature(
            status: status,
            isExpensive: isExpensive,
            isConstrained: isConstrained,
            interfaces: interfaces
        )
    }

    func _test_keepaliveHosts(for config: TunnelConfiguration) -> [String] {
        keepaliveHosts(for: config)
    }

    static func _test_parseAppMessageCommand(_ messageData: Data) -> String {
        parseAppMessageCommand(from: messageData)
    }
}
#endif
