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
    private var socksServer: Socks5Server?
    private var tunBridge: TunSocketBridge?
    private var engine: Tun2SocksEngine?
    private var isStopping = false
    private var packetCount: UInt64 = 0
    private var inboundPacketCount: UInt64 = 0
    private var didWarnRelay = false
    private let logPrefix = "RelativePacketTunnelProvider"
    private var didCallStartCompletion = false
    private var waitingForBackpressureRelief = false

    public override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        if RelativeLog.isVerbose {
            NSLog("\(logPrefix): startTunnel invoked")
        }
        queue.async {
            let config = self.loadConfiguration()
            self.configuration = config
            let settings = self.makeNetworkSettings(from: config)

            self.setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.logger.error("Failed to apply network settings: \(error.localizedDescription, privacy: .public)")
                    if RelativeLog.isVerbose {
                        NSLog("\(self.logPrefix): setTunnelNetworkSettings failed: \(error.localizedDescription)")
                    }
                    completionHandler(error)
                    return
                }

                if RelativeLog.isVerbose {
                    self.logger.info("Tunnel network settings applied. IPv6 enabled: \(config.ipv6Enabled, privacy: .public)")
                    NSLog("\(self.logPrefix): network settings applied, starting relay")
                }
                if !self.didCallStartCompletion {
                    self.didCallStartCompletion = true
                    completionHandler(nil)
                }
                self.setupPacketStream(using: config)
                self.setupMetrics(using: config)
                self.startRelay(using: config) { [weak self] error in
                    guard let self else { return }
                    if let error {
                        self.logger.error("Relay start failed after tunnel setup: \(error.localizedDescription, privacy: .public)")
                        if RelativeLog.isVerbose {
                            NSLog("\(self.logPrefix): relay start failed after setup: \(error.localizedDescription)")
                        }
                        self.cancelTunnelWithError(error)
                    }
                }
            }
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.isStopping = true
            self.engine?.stop()
            self.engine = nil
            self.tunBridge?.stop()
            self.tunBridge = nil
            self.socksServer?.stop()
            self.socksServer = nil
            self.metricsQueue.sync {
                self.flushMetricsInternal()
                self.metricsTimer?.cancel()
                self.metricsTimer = nil
                self.metricsBuffer = nil
                self.metricsStore = nil
                self.packetStreamWriter?.close()
                self.packetStreamWriter = nil
                self.flowTracker = nil
                self.burstTracker = nil
                self.trafficClassifier = nil
                self.metricsSampleLimit = 0
                self.metricsSnapshotLimit = 0
            }
            self.didCallStartCompletion = false
            self.waitingForBackpressureRelief = false
            if RelativeLog.isVerbose {
                self.logger.info("Tunnel stopped with reason: \(reason.rawValue, privacy: .public)")
                NSLog("\(self.logPrefix): stopTunnel reason=\(reason.rawValue)")
            }
            completionHandler()
        }
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
        settings.tunnelOverheadBytes = 0
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
                useLock: false
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
                useLock: false
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
        let snapshot = MetricsSnapshot(capturedAt: Date().timeIntervalSince1970, samples: samples)
        metricsWriteQueue.async {
            metricsStore.append(snapshot)
        }
        if RelativeLog.isVerbose {
            metricsLogger.debug("Flushed \(samples.count, privacy: .public) samples.")
        }
    }

    private func startPacketReadLoop() {
        guard !waitingForBackpressureRelief else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.ioQueue.async {
                guard !self.isStopping else { return }
                self.handlePackets(packets, protocols: protocols)
                if let tunBridge = self.tunBridge, tunBridge.isBackpressured() {
                    self.waitingForBackpressureRelief = true
                } else {
                    self.startPacketReadLoop()
                }
            }
        }
    }

    private func handlePackets(_ packets: [Data], protocols: [NSNumber]) {
        let timestamp = Date().timeIntervalSince1970
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

    private func handleInboundPackets(_ packets: [Data], families: [Int32]) {
        guard !isStopping else { return }
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

        let timestamp = Date().timeIntervalSince1970
        metricsQueue.async { [weak self] in
            self?.recordInboundPackets(packets, families: families, timestamp: timestamp)
        }
    }

    private func recordOutboundPackets(_ packets: [Data], protocols: [NSNumber], timestamp: TimeInterval) {
        guard let metricsBuffer else { return }
        let writer = packetStreamWriter
        var streamSamples: [PacketSample]?
        if writer != nil {
            streamSamples = []
            streamSamples?.reserveCapacity(packets.count)
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
                let dnsAnswers = metadata.dnsAnswerAddresses?.map { $0.stringValue }
                let srcString = metadata.srcAddress.stringValue
                let dstString = metadata.dstAddress.stringValue
                let sample = PacketSample(
                    timestamp: timestamp,
                    direction: .outbound,
                    ipVersion: metadata.ipVersion,
                    transport: metadata.transport,
                    length: metadata.length,
                    flowId: observation.flowId,
                    burstId: observation.burstId,
                    srcAddress: srcString.isEmpty ? nil : srcString,
                    dstAddress: dstString.isEmpty ? nil : dstString,
                    srcPort: metadata.srcPort,
                    dstPort: metadata.dstPort,
                    dnsQueryName: metadata.dnsQueryName,
                    dnsCname: metadata.dnsCname,
                    dnsAnswerAddresses: dnsAnswers,
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
                streamSamples?.append(sample)
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

        if let writer, let streamSamples, !streamSamples.isEmpty {
            writer.append(streamSamples)
        }
    }

    private func recordInboundPackets(_ packets: [Data], families: [Int32], timestamp: TimeInterval) {
        guard let metricsBuffer else { return }
        let writer = packetStreamWriter
        var streamSamples: [PacketSample]?
        if writer != nil {
            streamSamples = []
            streamSamples?.reserveCapacity(packets.count)
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
                let dnsAnswers = metadata.dnsAnswerAddresses?.map { $0.stringValue }
                let srcString = metadata.srcAddress.stringValue
                let dstString = metadata.dstAddress.stringValue
                let sample = PacketSample(
                    timestamp: timestamp,
                    direction: .inbound,
                    ipVersion: metadata.ipVersion,
                    transport: metadata.transport,
                    length: metadata.length,
                    flowId: observation.flowId,
                    burstId: observation.burstId,
                    srcAddress: srcString.isEmpty ? nil : srcString,
                    dstAddress: dstString.isEmpty ? nil : dstString,
                    srcPort: metadata.srcPort,
                    dstPort: metadata.dstPort,
                    dnsQueryName: metadata.dnsQueryName,
                    dnsCname: metadata.dnsCname,
                    dnsAnswerAddresses: dnsAnswers,
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
                streamSamples?.append(sample)
                self.inboundPacketCount &+= 1
                if self.inboundPacketCount % 500 == 0 {
                    if RelativeLog.isVerbose {
                        self.logger.info("Observed \(self.inboundPacketCount, privacy: .public) inbound packets.")
                    }
                }
            }
        }

        if let writer, let streamSamples, !streamSamples.isEmpty {
            writer.append(streamSamples)
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
            guard self.waitingForBackpressureRelief, !self.isStopping else { return }
            if let tunBridge = self.tunBridge, tunBridge.isBackpressured() {
                return
            }
            self.waitingForBackpressureRelief = false
            self.startPacketReadLoop()
        }
    }
}

#if DEBUG
extension RelativePacketTunnelProvider {
    func _test_makeNetworkSettings(from config: TunnelConfiguration) -> NEPacketTunnelNetworkSettings {
        makeNetworkSettings(from: config)
    }
}
#endif
