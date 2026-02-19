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
    private var lastObservedPathSignature: String?
    private var reassertingState = false

    private static let keepaliveEndpoint = NWHostEndpoint(hostname: "1.1.1.1", port: "53")
    private static let keepaliveDNSQuery = Data([
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01
    ])

    public override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        if RelativeLog.isVerbose {
            NSLog("\(logPrefix): startTunnel invoked")
        }
        queue.async {
            self.setIsStopping(false)
            self.setWaitingForBackpressureRelief(false)
            self.relayRestartInProgress = false
            let config = self.loadConfiguration()
            self.configuration = config
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
            self.stopDefaultPathMonitor()
            self.stopKeepaliveTimer()
            self.relayRestartInProgress = false
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
            self.restartRelay(reason: "wake")
        }
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        queue.async {
            completionHandler?(self.handleAppMessageOnQueue(messageData))
        }
    }

    private func handleAppMessageOnQueue(_ messageData: Data) -> Data? {
        let command = Self.parseAppMessageCommand(from: messageData)

        switch command {
        case "status", "diagnostics":
            return makeAppMessageResponse(command: command, ok: true)
        case "flushmetrics":
            flushMetrics()
            return makeAppMessageResponse(command: command, ok: true)
        case "restartrelay":
            restartRelay(reason: "app-message")
            return makeAppMessageResponse(command: command, ok: true)
        case "reloadconfiguration":
            configuration = loadConfiguration()
            return makeAppMessageResponse(command: command, ok: true)
        default:
            return makeAppMessageResponse(command: command, ok: false, error: "unsupported-command")
        }
    }

    private static func parseAppMessageCommand(from messageData: Data) -> String {
        let payload = (try? JSONSerialization.jsonObject(with: messageData)) as? [String: Any]
        return (payload?["command"] as? String ?? payload?["action"] as? String ?? "status")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
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

        if !config.dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: config.dnsServers)
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
                if let tunBridge = self.tunBridge, tunBridge.isBackpressured() {
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
            if let tunBridge {
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
        let socksServer = Socks5Server(provider: self, queue: ioQueue, mtu: config.mtu)
        self.socksServer = socksServer
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
                        self.tunBridge = bridge
                        bridge.onBackpressureRelieved = { [weak self] in
                            self?.resumePacketReadLoopIfNeeded()
                        }
                        bridge.startReadLoop { [weak self] packets, families in
                            self?.handleInboundPackets(packets, families: families)
                        }

                        let engine = Tun2SocksEngine()
                        self.engine = engine
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
                        self.socksServer?.stop()
                        self.socksServer = nil
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
                    self.socksServer?.stop()
                    self.socksServer = nil
                    completion(error)
                }
            }
        }
    }

    private func stopRelayComponents() {
        engine?.stop()
        engine = nil
        tunBridge?.stop()
        tunBridge = nil
        socksServer?.stop()
        socksServer = nil
    }

    private func startDefaultPathMonitor() {
        stopDefaultPathMonitor()
        lastObservedPathSignature = defaultPathSignature(defaultPath)
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
    }

    private func startKeepaliveTimer(using config: TunnelConfiguration) {
        stopKeepaliveTimer()
        guard config.relayMode == "tun2socks" else { return }
        guard config.keepaliveIntervalSeconds > 0 else { return }
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
    }

    private func sendKeepaliveProbeIfNeeded() {
        guard !isStoppingState(), !relayRestartInProgress else { return }
        guard let config = configuration, config.relayMode == "tun2socks" else { return }
        guard config.keepaliveIntervalSeconds > 0 else { return }
        let session = createUDPSessionThroughTunnel(to: Self.keepaliveEndpoint, from: nil)
        session.writeDatagram(Self.keepaliveDNSQuery) { [weak self] error in
            if let error, RelativeLog.isVerbose {
                self?.logger.warning("Keepalive probe failed: \(error.localizedDescription, privacy: .public)")
            }
            session.cancel()
        }
    }

    private func handleDefaultPathMonitorTick() {
        guard !isStoppingState() else { return }
        let currentPath = defaultPath
        let currentSignature = defaultPathSignature(currentPath)
        guard currentSignature != lastObservedPathSignature else { return }
        lastObservedPathSignature = currentSignature
        guard currentPath?.status == .satisfied else { return }
        restartRelay(reason: "path-change")
    }

    private func restartRelay(reason: String) {
        guard !relayRestartInProgress, !isStoppingState() else { return }
        guard let config = configuration, config.relayMode == "tun2socks" else { return }
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
                self.setReasserting(false)
                if let error {
                    self.logger.error("Failed to restart relay (\(reason, privacy: .public)): \(error.localizedDescription, privacy: .public)")
                    if RelativeLog.isVerbose {
                        NSLog("\(self.logPrefix): relay restart failed, reason=\(reason), error=\(error.localizedDescription)")
                    }
                    self.cancelTunnelWithError(error)
                    return
                }
                self.startKeepaliveTimer(using: config)
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

    private func resumePacketReadLoopIfNeeded() {
        ioQueue.async { [weak self] in
            guard let self else { return }
            guard self.waitingForBackpressureReliefState(), !self.isStoppingState() else { return }
            if let tunBridge = self.tunBridge, tunBridge.isBackpressured() {
                return
            }
            self.setWaitingForBackpressureRelief(false)
            self.startPacketReadLoop()
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

    private func makeAppMessageResponse(command: String, ok: Bool, error: String? = nil) -> Data? {
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            let payload: [String: Any] = [
                "ok": ok,
                "command": command,
                "error": error ?? NSNull(),
                "timestamp": TunnelTime.nowEpochSeconds(),
                "defaultPathSignature": "path:unavailable"
            ]
            return try? JSONSerialization.data(withJSONObject: payload, options: [])
        }

        var packetCounts: (outbound: UInt64, inbound: UInt64) = (0, 0)
        metricsQueue.sync {
            packetCounts = (packetCount, inboundPacketCount)
        }
        let payload: [String: Any] = [
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
            "inboundPacketCount": packetCounts.inbound
        ]
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

    static func _test_parseAppMessageCommand(_ messageData: Data) -> String {
        parseAppMessageCommand(from: messageData)
    }
}
#endif
