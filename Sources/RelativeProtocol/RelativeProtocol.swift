#if canImport(NetworkExtension) && os(iOS)
import Foundation
import NetworkExtension
import Network

// C glue functions
@_silgen_name("rlwip_start") private func rlwip_start() -> Int32
@_silgen_name("rlwip_stop") private func rlwip_stop()
@_silgen_name("rlwip_feed_packet") private func rlwip_feed_packet(_ data: UnsafePointer<UInt8>, _ len: Int) -> Int32
@_silgen_name("rlwip_set_output") private func rlwip_set_output(_ cb: (@convention(c) (UnsafePointer<UInt8>?, Int) -> Void)?)
@_silgen_name("rlwip_set_proxy_output") private func rlwip_set_proxy_output(_ cb: (@convention(c) (UnsafePointer<UInt8>?, Int) -> Void)?)
@_silgen_name("rlwip_drive_timeouts") private func rlwip_drive_timeouts()
@_silgen_name("rlwip_inject_proxynetif") func rlwip_inject_proxynetif(_ data: UnsafePointer<UInt8>, _ len: Int) -> Int32

public final class RelativeProtocolEngine {
    private let packetFlow: NEPacketTunnelFlow
    private let queue = DispatchQueue(label: "com.relativeprotocol.engine")
    private var running = false
    private var readLoopArmed = false
    private lazy var scheduler: PacketScheduler = {
        let scheduler = PacketScheduler(
            rateBytesPerSecond: Int.max,
            tickMs: 10,
            maxEnqueuedBytes: 4 * 1024 * 1024,
            backpressure: { [weak self] paused in
                self?.handleBackpressureChange(paused: paused)
            },
            emit: { [weak self] packets, protocols in
                guard let flow = self?.packetFlow else { return }
                flow.writePackets(packets, withProtocols: protocols)
            }
        )
        return scheduler
    }()
    private var suppressReadRearm = false
    private var passthroughMode = false
    private var tagSchedulers: [String: PacketScheduler] = [:]
    private var backpressureCount = 0
    public var onBackpressureChanged: ((Bool) -> Void)?
    private var pathMonitor: NWPathMonitor?
    private var quiesced = false

    public protocol PolicyProvider: AnyObject {
        func onNewFlow(metadata: FlowMetadata) -> String?
        func updateThrottle(tag: String, bytesPerSecond: Int)
        func shouldDrop(flow: FlowMetadata) -> Bool
    }

    public struct FlowMetadata {
        public let flowID: String
        public let isIPv6: Bool
        public let sourceIP: String
        public let sourcePort: UInt16
        public let destinationIP: String
        public let destinationPort: UInt16
        public let transport: String // "TCP" or "UDP"
    }

    public weak var policyProvider: PolicyProvider?
    // Optional egress connection factory injected by provider
    public var connectionFactory: EgressConnectionFactory?

    public init(packetFlow: NEPacketTunnelFlow) {
        self.packetFlow = packetFlow
    }

    public func start() {
        guard !running else { return }
        logInfo("RelativeProtocolEngine starting")
        logInfo("log-level=\(Logger.shared.getLevel())")
        let sp = Observability.shared.begin("engine_start")
        queue.sync {
            rlwip_set_output(RelativeProtocolEngine.packetOut)
            rlwip_set_proxy_output(RelativeProtocolEngine.proxynetifOut)
            RelativeProtocolEngine._packetFlow = packetFlow
            RelativeProtocolEngine._engineRef = self
        }
        SocketBridge.shared.delegate = self
        SocketBridge.shared.setConnectionFactory(connectionFactory)
        _ = rlwip_start()
        running = true
        armReadLoopIfNeeded()
        armTimerTick()
        scheduler.start()
        enablePathMonitoring()
        Observability.shared.end("engine_start", sp)
    }

#if canImport(NetworkExtension) && os(iOS)
    private func selfProvider() -> NEPacketTunnelProvider? {
        // Best-effort: locate provider via packetFlow
        // There is no direct API from NEPacketTunnelFlow back to provider; rely on static linkage
        return nil
    }
#endif

    public func stop() {
        guard running else { return }
        logInfo("RelativeProtocolEngine stopping")
        rlwip_stop()
        running = false
        scheduler.stop()
        queue.sync { RelativeProtocolEngine._engineRef = nil }
        // Stop per-tag schedulers
        for (_, sch) in tagSchedulers { sch.stop() }
        tagSchedulers.removeAll()
        disablePathMonitoring()
    }

    public func handleInboundTunnelPacket(_ packet: Data) {
        queue.async {
            Metrics.shared.incPacketsIn(bytes: packet.count)
            packet.withUnsafeBytes { bytes in
                if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                    _ = rlwip_feed_packet(base, packet.count)
                }
            }
        }
    }

	// Public ingestion APIs for provider → engine handoff
	public func ingestPacket(_ data: Data, proto: sa_family_t) {
		// proto is currently unused; lwIP determines IP version from header
		handleInboundTunnelPacket(data)
	}

	public func ingestPackets(_ packets: [Data], protocols: [NSNumber]) {
		// protocols array optional; align lengths if provided
		for pkt in packets {
			handleInboundTunnelPacket(pkt)
		}
	}

    private func armReadLoopIfNeeded() {
        guard running, !readLoopArmed else { return }
        readLoopArmed = true
        packetFlow.readPackets { [weak self] packets, _ in
            let sp = Observability.shared.begin("readPackets")
            guard let strongSelf = self else { return }
            if !strongSelf.running {
                strongSelf.readLoopArmed = false
                return
            }
            if !packets.isEmpty {
                logInfo("readPackets: count=\(packets.count)")
                // DEBUG: Log packet ingress details
                logError("PACKET_INGRESS: packet_count=\(packets.count) engine_active=true")
                for (i, packet) in packets.enumerated().prefix(5) {  // Log first 5 packets
                    logError("PACKET_INGRESS[\(i)]: size=\(packet.count)bytes")
                }
            }
            for pkt in packets {
                strongSelf.handleInboundTunnelPacket(pkt)
            }
            strongSelf.readLoopArmed = false
            if !strongSelf.suppressReadRearm {
                strongSelf.armReadLoopIfNeeded()
            }
            Observability.shared.end("readPackets", sp)
        }
    }

    private func armTimerTick() {
        queue.asyncAfter(deadline: .now() + .milliseconds(150)) { [weak self] in
            guard let self = self, self.running else { return }
            rlwip_drive_timeouts()
            self.armTimerTick()
        }
    }

    private func handleBackpressureChange(paused: Bool) {
        queue.async {
            if paused { self.backpressureCount += 1 } else { self.backpressureCount = max(0, self.backpressureCount - 1) }
            let suppressed = self.backpressureCount > 0
            self.suppressReadRearm = suppressed
            logDebug("Backpressure changed: paused=\(paused) suppressed=\(suppressed) count=\(self.backpressureCount)")
            self.onBackpressureChanged?(suppressed)
        }
    }

    private func schedulerForTag(_ tag: String) -> PacketScheduler {
        if let s = tagSchedulers[tag] { return s }
        let s = PacketScheduler(rateBytesPerSecond: Int.max, tickMs: 10, maxEnqueuedBytes: 4 * 1024 * 1024, backpressure: { [weak self] paused in
            self?.handleBackpressureChange(paused: paused)
        }) { [weak self] packets, protocols in
            guard let self = self else { return }
            self.packetFlow.writePackets(packets, withProtocols: protocols)
        }
        s.start()
        tagSchedulers[tag] = s
        return s
    }

    // Path monitoring
    private func enablePathMonitoring() {
        guard pathMonitor == nil else { return }
        if #available(iOS 12.0, macOS 10.14, *) {
            let mon = NWPathMonitor()
            mon.pathUpdateHandler = { path in
                if #available(iOS 13.0, macOS 10.15, *) {
                    logInfo("Path update: status=\(path.status) expensive=\(path.isExpensive) constrained=\(path.isConstrained)")
                } else {
                    logInfo("Path update: status=\(path.status) expensive=\(path.isExpensive)")
                }
            }
            mon.start(queue: queue)
            pathMonitor = mon
        }
    }

    private func disablePathMonitoring() {
        pathMonitor?.cancel()
        pathMonitor = nil
    }

    // Quiesce/resume for sleep handling
    public func quiesce() {
        queue.async {
            self.quiesced = true
            self.suppressReadRearm = true
            logInfo("Engine quiesced")
        }
    }

    public func resume() {
        queue.async {
            self.quiesced = false
            self.suppressReadRearm = false
            self.armReadLoopIfNeeded()
            logInfo("Engine resumed")
        }
    }
}

// Static trampoline to satisfy C function pointer (no captures)
extension RelativeProtocolEngine {
    private static var _packetFlow: NEPacketTunnelFlow?
    private static weak var _engineRef: RelativeProtocolEngine?
    static let packetOut: @convention(c) (UnsafePointer<UInt8>?, Int) -> Void = { pkt, len in
        guard let pkt = pkt, len > 0, let flow = _packetFlow else { 
            logError("PACKET_OUT_ERROR: pkt=\(pkt != nil) len=\(len) flow=\(_packetFlow != nil)")
            return 
        }
        let version = pkt.pointee >> 4
        let proto: NSNumber = (version == 6) ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
        let data = Data(bytes: pkt, count: len)
        // DEBUG: This should be sending packets back to the iOS app through the tunnel
        logError("PACKET_OUT: sending packet back to tunnel, size=\(len)bytes version=\(version)")
        if let engine = _engineRef, !engine.passthroughMode {
            if let tag = TagStore.shared.tagForPacket(bytes: pkt, length: len) {
                engine.schedulerForTag(tag).enqueue(data, proto: proto)
            } else {
                engine.scheduler.enqueue(data, proto: proto)
            }
        } else {
            flow.writePackets([data], withProtocols: [proto])
        }
        Metrics.shared.incPacketsOut(bytes: len)
    }

    // Outbound from lwIP proxynetif → Swift socket bridge
    static let proxynetifOut: @convention(c) (UnsafePointer<UInt8>?, Int) -> Void = { pkt, len in
        guard let pkt = pkt, len > 0 else { return }
        // DEBUG: This should only be called for packets going TO the Internet
        logError("PROXYNETIF_OUT: packet going to Internet, size=\(len)bytes")
        SocketBridge.shared.handleOutgoingIPPacket(packetPtr: pkt, length: len)
    }
}

// Public control APIs
extension RelativeProtocolEngine {
    public func setPassthroughMode(_ enabled: Bool) {
        queue.async { self.passthroughMode = enabled }
    }

    public func updateThrottle(tag: String, bytesPerSecond: Int) {
        // For now, global scheduler; per-tag queues to be added later
        scheduler.setRate(bytesPerSecond: bytesPerSecond)
        // Also apply to UDP per-tag limiter in the bridge
        SocketBridge.shared.setUDPRate(forTag: tag, bytesPerSecond: bytesPerSecond)
        SocketBridge.shared.setTCPRate(forTag: tag, bytesPerSecond: bytesPerSecond)
    }

    // Update path MTU and propagate MSS clamps to the socket bridge
    public func updateMTU(ipv4MTU: Int?, ipv6MTU: Int?) {
        let v4 = ipv4MTU.map { mtu -> UInt16 in
            let mss = max(536, mtu - 20 - 20)
            return UInt16(max(0, min(65535, mss)))
        }
        let v6 = ipv6MTU.map { mtu -> UInt16 in
            let mss = max(536, mtu - 40 - 20)
            return UInt16(max(0, min(65535, mss)))
        }
        let clampV4 = v4 ?? 1360
        let clampV6 = v6 ?? 1220
        SocketBridge.shared.setMSSClamp(ipv4: clampV4, ipv6: clampV6)
    }

    // Convenience: derive MSS clamp(s) from NEPacketTunnelNetworkSettings
    @available(iOS 12.0, *)
    public func updateMTU(from settings: NEPacketTunnelNetworkSettings) {
        let mtuValue = settings.mtu?.intValue
        // If only IPv6 is configured and MTU is unspecified, use 1280 per RFC as safe fallback
        let hasV4 = settings.ipv4Settings != nil
        let hasV6 = settings.ipv6Settings != nil
        let v4mtu: Int? = hasV4 ? mtuValue : nil
        let v6mtu: Int? = hasV6 ? (mtuValue ?? 1280) : nil
        updateMTU(ipv4MTU: v4mtu, ipv6MTU: v6mtu)
    }

    // Public metrics access
    public func metricsSnapshot() -> Any {
        return Metrics.shared.snapshot()
    }
}

// Public logging configuration API
extension RelativeProtocolEngine {
    /// Enable or disable logging at runtime
    public static func setLoggingEnabled(_ enabled: Bool) {
        Logger.shared.setEnabled(enabled)
    }

    /// Set logging level from string (TRACE, DEBUG, INFO, WARN, ERROR)
    public static func setLogLevel(from string: String) {
        Logger.shared.setLevel(from: string)
    }

    /// Set logging level using enum-like strings for convenience
    public static func setLogLevel(_ level: String) {
        setLogLevel(from: level)
    }
}

// Static helpers for OS-bound emission (tun path)
extension RelativeProtocolEngine {
    /// Emit an IP packet directly to the OS via the tunnel flow, bypassing schedulers.
    /// Used for control-plane synthesis (e.g., TCP RST, ICMP) to ensure packets go to the OS path.
    static func emitToTun(_ data: Data) {
        guard let flow = _packetFlow, !data.isEmpty else { return }
        let version = data.first.map { $0 >> 4 } ?? 4
        let proto: NSNumber = (version == 6) ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
        flow.writePackets([data], withProtocols: [proto])
        Metrics.shared.incPacketsOut(bytes: data.count)
    }

    /// Inject Internet-side data back into lwIP via proxynetif on the engine's queue
    static func injectProxynetif(_ data: Data) {
        guard let engine = _engineRef, !data.isEmpty else { return }
        engine.queue.async {
            data.withUnsafeBytes { bytes in
                if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                    _ = rlwip_inject_proxynetif(base, data.count)
                }
            }
        }
    }
    
    /// Send packet directly back to the tunnel (iOS app) without going through lwIP
    static func sendPacketToTunnel(_ data: Data) {
        guard let flow = _packetFlow, !data.isEmpty else { 
            logError("SEND_TO_TUNNEL_ERROR: flow=\(_packetFlow != nil) data_size=\(data.count)")
            return 
        }
        let version = data.first.map { $0 >> 4 } ?? 4
        let proto: NSNumber = (version == 6) ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
        logError("SEND_TO_TUNNEL: Sending packet directly to tunnel, size=\(data.count) version=\(version)")
        flow.writePackets([data], withProtocols: [proto])
        Metrics.shared.incPacketsOut(bytes: data.count)
    }
}

// Bridge classification delegate
extension RelativeProtocolEngine: SocketBridge.Delegate {
    func classify(flow: SocketBridge.FlowIdentity) -> String? {
        let meta = FlowMetadata(
            flowID: flow.flowID,
            isIPv6: flow.isIPv6,
            sourceIP: flow.sourceIP,
            sourcePort: flow.sourcePort,
            destinationIP: flow.destinationIP,
            destinationPort: flow.destinationPort,
            transport: flow.proto
        )
        return policyProvider?.onNewFlow(metadata: meta)
    }
}


// Close iOS-only compilation block
#endif
