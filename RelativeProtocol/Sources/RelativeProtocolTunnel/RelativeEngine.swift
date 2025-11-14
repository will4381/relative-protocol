import Darwin
import Foundation
import Network
import NetworkExtension
import OSLog
import EngineBinary
import RelativeProtocolCore

private typealias BridgeEngineRef = OpaquePointer

public protocol RelativeEngineDelegate: AnyObject {
    func relativeEngine(_ engine: RelativeEngine, didObserveHost host: String, addresses: [String], ttl: TimeInterval)
}

public enum RelativeEngineError: LocalizedError {
    case unableToCreateEngine
    case engineAlreadyRunning
    case engineStartFailed(code: Int32)
    case logSinkInstallFailed
    case hostRuleInstallFailed

    public var errorDescription: String? {
        switch self {
        case .unableToCreateEngine:
            return "Failed to allocate bridge engine"
        case .engineAlreadyRunning:
            return "Engine is already running"
        case .engineStartFailed(let code):
            return "BridgeEngineStart returned \(code)"
        case .logSinkInstallFailed:
            return "Unable to install log sink"
        case .hostRuleInstallFailed:
            return "Unable to install host rule"
        }
    }
}

public final class RelativeEngine {
    public struct Configuration: Sendable {
        public var mtu: UInt32
        public var packetPoolBytes: UInt32
        public var perFlowBytes: UInt32

        public init(mtu: UInt32 = UInt32(DEFAULT_MTU), packetPoolBytes: UInt32 = 2_097_152, perFlowBytes: UInt32 = 262_144) {
            self.mtu = mtu
            self.packetPoolBytes = packetPoolBytes
            self.perFlowBytes = perFlowBytes
        }

        public static let `default` = Configuration()
    }

    public weak var delegate: RelativeEngineDelegate?

    private let packetFlow: NEPacketTunnelFlow
    private let configuration: Configuration
    private var engine: BridgeEngineRef?
    private var callbacks: BridgeCallbacks?
    private var running = false
    private let packetWriter = DispatchQueue(label: "RelativeEngine.packet-writer")
    fileprivate let networkQueue = DispatchQueue(label: "RelativeEngine.network", qos: .userInitiated)
    private let logQueue = DispatchQueue(label: "RelativeEngine.log-handler")
    private let lifecycleLogger = Logger(subsystem: "RelativeProtocolTunnel", category: "FlowLifecycle")
    private lazy var flowManager = FlowManager(engine: self)
    private var context: UnsafeMutableRawPointer?
    private var logSinkBox: LogSinkBox?
    private let dnsHistoryLock = NSLock()
    private var dnsHistory: [DNSObservation] = []
    private let dnsHistoryLimit = 256

    public init(packetFlow: NEPacketTunnelFlow, configuration: Configuration = .default) throws {
        self.packetFlow = packetFlow
        self.configuration = configuration
        _ = RelativeEngine.ensureLinked

        var cfg = BridgeConfig(mtu: configuration.mtu,
                               packet_pool_bytes: configuration.packetPoolBytes,
                               per_flow_bytes: configuration.perFlowBytes)
        guard let pointer = BridgeNewEngine(&cfg) else {
            throw RelativeEngineError.unableToCreateEngine
        }
        self.engine = pointer
        self.context = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
    }

    deinit {
        stop()
        clearLogHandler()
        if let engine {
            BridgeFreeEngine(engine)
        }
    }

    public func start() throws {
        guard let engine else { throw RelativeEngineError.unableToCreateEngine }
        guard !running else { throw RelativeEngineError.engineAlreadyRunning }
        var callbacks = makeCallbacks()
        let status = BridgeEngineStart(engine, &callbacks)
        guard status == 0 else {
            throw RelativeEngineError.engineStartFailed(code: status)
        }
        self.callbacks = callbacks
        running = true
        schedulePacketRead()
    }

    public func stop() {
        guard running, let engine else { return }
        BridgeEngineStop(engine)
        running = false
        flowManager.cancelAll()
    }

    private func schedulePacketRead() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.running, let engine = self.engine else { return }
            for (index, packet) in packets.enumerated() {
                let protoValue: UInt32
                if index < protocols.count {
                    protoValue = UInt32(truncating: protocols[index])
                } else {
                    protoValue = UInt32(AF_INET)
                }
                packet.withUnsafeBytes { buffer in
                    guard let baseAddress = buffer.baseAddress else { return }
                    _ = BridgeEngineHandlePacket(engine,
                                                 baseAddress.assumingMemoryBound(to: UInt8.self),
                                                 buffer.count,
                                                 protoValue)
                }
            }
            if self.running {
                self.schedulePacketRead()
            }
        }
    }

    private func makeCallbacks() -> BridgeCallbacks {
        BridgeCallbacks(
            emit_packets: RelativeEngine.emitPacketsTrampoline,
            request_tcp_dial: RelativeEngine.requestTcpDialTrampoline,
            request_udp_dial: RelativeEngine.requestUdpDialTrampoline,
            tcp_send: RelativeEngine.tcpSendTrampoline,
            udp_send: RelativeEngine.udpSendTrampoline,
            tcp_close: RelativeEngine.tcpCloseTrampoline,
            udp_close: RelativeEngine.udpCloseTrampoline,
            record_dns: RelativeEngine.recordDnsTrampoline,
            context: context
        )
    }

    private func handleEmitPackets(
        packets: UnsafePointer<UnsafePointer<UInt8>?>?,
        sizes: UnsafePointer<size_t>?,
        protocols: UnsafePointer<UInt32>?,
        count: Int
    ) {
        guard count > 0 else { return }
        var datas: [Data] = []
        datas.reserveCapacity(count)
        var protoNumbers: [NSNumber] = []
        protoNumbers.reserveCapacity(count)

        for index in 0..<count {
            guard
                let packetPtr = packets?[index],
                let lengthPtr = sizes
            else { continue }
            let length = Int(lengthPtr[index])
            let data = Data(bytes: packetPtr, count: length)
            datas.append(data)
            if let protoPtr = protocols {
                protoNumbers.append(NSNumber(value: Int32(protoPtr[index])))
            } else {
                protoNumbers.append(NSNumber(value: AF_INET))
            }
        }

        guard !datas.isEmpty else { return }
        packetWriter.async { [packetFlow] in
            packetFlow.writePackets(datas, withProtocols: protoNumbers)
        }
    }

    private func handleTcpDial(host: String, port: UInt16, handle: UInt64) {
        flowManager.requestTcpDial(host: host, port: port, handle: handle)
    }

    private func handleUdpDial(host: String, port: UInt16, handle: UInt64) {
        flowManager.requestUdpDial(host: host, port: port, handle: handle)
    }

    fileprivate func notifyDialSucceeded(handle: UInt64, protocolName: String) {
        logFlowEvent("dial_succeeded", handle: handle, extra: "protocol=\(protocolName)")
        guard let engine else { return }
        BridgeEngineOnDialResult(engine, handle, true, nil)
    }

    fileprivate func notifyDialFailed(handle: UInt64, protocolName: String, message: String) {
        logFlowEvent("dial_failed", handle: handle, extra: "protocol=\(protocolName) reason=\(message)")
        guard let engine else { return }
        message.withCString { pointer in
            BridgeEngineOnDialResult(engine, handle, false, pointer)
        }
    }

    fileprivate func deliverTcp(handle: UInt64, data: Data) {
        guard let engine else { return }
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            _ = BridgeEngineOnTcpReceive(engine, handle, base, buffer.count)
        }
    }

    fileprivate func deliverUdp(handle: UInt64, data: Data) {
        guard let engine else { return }
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            _ = BridgeEngineOnUdpReceive(engine, handle, base, buffer.count)
        }
    }

    fileprivate func notifyTcpClose(handle: UInt64) {
        logFlowEvent("tcp_close", handle: handle, extra: "source=swift")
        guard let engine else { return }
        BridgeEngineOnTcpClose(engine, handle)
    }

    fileprivate func notifyUdpClose(handle: UInt64) {
        logFlowEvent("udp_close", handle: handle, extra: "source=swift")
        guard let engine else { return }
        BridgeEngineOnUdpClose(engine, handle)
    }

    fileprivate func logFlowEvent(_ event: String, handle: UInt64, extra: String? = nil) {
        if let extra, !extra.isEmpty {
            lifecycleLogger.debug("Flow event: \(event, privacy: .public) handle=\(handle, privacy: .public) \(extra, privacy: .public)")
        } else {
            lifecycleLogger.debug("Flow event: \(event, privacy: .public) handle=\(handle, privacy: .public)")
        }
    }

    fileprivate func handleTcpSend(handle: UInt64, payload: UnsafePointer<UInt8>?, length: Int) {
        guard let payload else { return }
        let data = Data(bytes: payload, count: length)
        flowManager.sendTcp(handle: handle, data: data)
    }

    fileprivate func handleUdpSend(handle: UInt64, payload: UnsafePointer<UInt8>?, length: Int) {
        guard let payload else { return }
        let data = Data(bytes: payload, count: length)
        flowManager.sendUdp(handle: handle, data: data)
    }

    fileprivate func handleRecordDns(host: String, addresses: [String], ttl: UInt32) {
        let observation = DNSObservation(
            host: host,
            addresses: addresses,
            ttlSeconds: ttl,
            observedAt: Date()
        )
        dnsHistoryLock.lock()
        dnsHistory.append(observation)
        if dnsHistory.count > dnsHistoryLimit {
            dnsHistory.removeFirst(dnsHistory.count - dnsHistoryLimit)
        }
        dnsHistoryLock.unlock()
        delegate?.relativeEngine(self, didObserveHost: host, addresses: addresses, ttl: TimeInterval(ttl))
    }

    fileprivate func handleTcpCloseFromBridge(handle: UInt64) {
        logFlowEvent("bridge_tcp_close_request", handle: handle)
        flowManager.closeTcpFromBridge(handle: handle)
    }

    fileprivate func handleUdpCloseFromBridge(handle: UInt64) {
        logFlowEvent("bridge_udp_close_request", handle: handle)
        flowManager.closeUdpFromBridge(handle: handle)
    }

    private static let ensureLinked: Bool = {
        BridgeEnsureLinked()
        return true
    }()

    public func recentDnsObservations(limit: Int) -> [DNSObservation] {
        dnsHistoryLock.lock()
        let snapshot = dnsHistory
        dnsHistoryLock.unlock()
        guard limit > 0, snapshot.count > limit else {
            return snapshot
        }
        return Array(snapshot.suffix(limit))
    }

    public func installHostRule(_ rule: HostRuleConfiguration) throws -> UInt64 {
        guard let engine else { throw RelativeEngineError.unableToCreateEngine }
        var ruleID: UInt64 = 0
        let params = rule.action.bridgeParameters
        let success = rule.pattern.withCString { patternPtr -> Bool in
            var config = BridgeHostRuleConfig(
                pattern: patternPtr,
                block: params.block,
                latency_ms: params.latencyMs,
                jitter_ms: params.jitterMs
            )
            return BridgeHostRuleAdd(engine, &config, &ruleID)
        }
        guard success else {
            throw RelativeEngineError.hostRuleInstallFailed
        }
        return ruleID
    }

    public func removeHostRule(_ ruleID: UInt64) -> Bool {
        guard let engine else { return false }
        return BridgeHostRuleRemove(engine, ruleID)
    }

    public func drainTelemetry(maxEvents: Int) -> TelemetryDrainResponse {
        guard let engine, maxEvents > 0 else {
            return TelemetryDrainResponse(events: [], droppedEvents: 0)
        }
        let capacity = max(1, maxEvents)
        var dropped: UInt64 = 0
        var buffer = Array(repeating: BridgeTelemetryEvent(), count: capacity)
        let drained = buffer.withUnsafeMutableBufferPointer { pointer -> Int in
            let count = BridgeTelemetryDrain(engine, pointer.baseAddress, capacity, &dropped)
            return Int(count)
        }
        let events = buffer.prefix(drained).map(RelativeEngine.makeTelemetryEvent)
        return TelemetryDrainResponse(events: events, droppedEvents: dropped)
    }

    // MARK: - Logging

    public enum LogLevel: String, CaseIterable, Sendable {
        case error
        case warn
        case info
        case debug

        fileprivate var cString: String {
            rawValue
        }

        fileprivate static func fromCString(_ value: String) -> LogLevel {
            LogLevel(rawValue: value.lowercased()) ?? .info
        }
    }

    public struct Breadcrumbs: OptionSet, Sendable {
        public let rawValue: UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        public static let device = Breadcrumbs(rawValue: 0b0000_0001)
        public static let flow = Breadcrumbs(rawValue: 0b0000_0010)
        public static let dns = Breadcrumbs(rawValue: 0b0000_0100)
        public static let metrics = Breadcrumbs(rawValue: 0b0000_1000)
        public static let ffi = Breadcrumbs(rawValue: 0b0001_0000)
        public static let poll = Breadcrumbs(rawValue: 0b0010_0000)
        public static let all = Breadcrumbs(rawValue: UInt32.max)
    }

    public struct LogEntry: Sendable {
        public let level: LogLevel
        public let message: String
        public let breadcrumbs: Breadcrumbs
    }

    public func installLogHandler(
        level: LogLevel = .info,
        breadcrumbs: Breadcrumbs = .all,
        handler: @escaping (LogEntry) -> Void
    ) throws {
        let box = LogSinkBox(queue: logQueue, handler: handler)
        var sink = BridgeLogSink(
            log: RelativeEngine.logTrampoline,
            context: UnsafeMutableRawPointer(Unmanaged.passUnretained(box).toOpaque()),
            enabled_breadcrumbs: breadcrumbs.rawValue
        )
        let success = level.cString.withCString { levelPtr in
            BridgeSetLogSink(&sink, levelPtr, nil)
        }
        guard success else {
            throw RelativeEngineError.logSinkInstallFailed
        }
        BridgeSetBreadcrumbMask(breadcrumbs.rawValue)
        logSinkBox = box
    }

    public func clearLogHandler() {
        BridgeSetLogSink(nil, nil, nil)
        BridgeSetBreadcrumbMask(0)
        logSinkBox = nil
    }
}

// MARK: - Flow Management

private final class FlowManager {
    private unowned let engine: RelativeEngine
    private let queue = DispatchQueue(label: "RelativeEngine.flow-manager")
    private var tcpFlows: [UInt64: TCPFlow] = [:]
    private var udpFlows: [UInt64: UDPFlow] = [:]

    init(engine: RelativeEngine) {
        self.engine = engine
    }

    func requestTcpDial(host: String, port: UInt16, handle: UInt64) {
        queue.async {
            guard self.tcpFlows[handle] == nil else { return }
            guard let nwPort = Network.NWEndpoint.Port(rawValue: port) else {
                self.engine.notifyDialFailed(handle: handle, protocolName: "tcp", message: "invalid port")
                return
            }
            let endpoint = Network.NWEndpoint.hostPort(host: Self.makeHost(host), port: nwPort)
            let connection = NWConnection(to: endpoint, using: .tcp)
            let flow = TCPFlow(handle: handle, connection: connection)
            self.tcpFlows[handle] = flow
            self.engine.logFlowEvent("request_tcp_dial", handle: handle, extra: "host=\(host) port=\(port)")
            connection.stateUpdateHandler = { [weak self] state in
                self?.handleTcpState(handle: handle, state: state)
            }
            connection.start(queue: self.engine.networkQueue)
            self.receiveTcp(flow: flow)
        }
    }

    func requestUdpDial(host: String, port: UInt16, handle: UInt64) {
        queue.async {
            guard self.udpFlows[handle] == nil else { return }
            guard let nwPort = Network.NWEndpoint.Port(rawValue: port) else {
                self.engine.notifyDialFailed(handle: handle, protocolName: "udp", message: "invalid port")
                return
            }
            let endpoint = Network.NWEndpoint.hostPort(host: Self.makeHost(host), port: nwPort)
            let params = NWParameters.udp
            let connection = NWConnection(to: endpoint, using: params)
            let flow = UDPFlow(handle: handle, connection: connection)
            self.udpFlows[handle] = flow
            self.engine.logFlowEvent("request_udp_dial", handle: handle, extra: "host=\(host) port=\(port)")
            connection.stateUpdateHandler = { [weak self] state in
                self?.handleUdpState(handle: handle, state: state)
            }
            connection.start(queue: self.engine.networkQueue)
            self.receiveUdp(flow: flow)
        }
    }

    func sendTcp(handle: UInt64, data: Data) {
        queue.async {
            guard let flow = self.tcpFlows[handle] else { return }
            flow.connection.send(content: data, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if let error = error {
                    if flow.reportedReady {
                        self.engine.notifyTcpClose(handle: handle)
                    } else {
                        self.engine.notifyDialFailed(handle: handle, protocolName: "tcp", message: error.localizedDescription)
                    }
                    self.closeTcp(handle: handle)
                }
            })
        }
    }

    func sendUdp(handle: UInt64, data: Data) {
        queue.async {
            guard let flow = self.udpFlows[handle] else { return }
            flow.connection.send(content: data, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if let error = error {
                    if flow.reportedReady {
                        self.engine.notifyUdpClose(handle: handle)
                    } else {
                        self.engine.notifyDialFailed(handle: handle, protocolName: "udp", message: error.localizedDescription)
                    }
                    self.closeUdp(handle: handle)
                }
            })
        }
    }

    func closeTcpFromBridge(handle: UInt64) {
        queue.async {
            self.closeTcp(handle: handle)
        }
    }

    func closeUdpFromBridge(handle: UInt64) {
        queue.async {
            self.closeUdp(handle: handle)
        }
    }

    func cancelAll() {
        queue.async {
            self.tcpFlows.values.forEach { $0.connection.cancel() }
            self.udpFlows.values.forEach { $0.connection.cancel() }
            self.tcpFlows.removeAll()
            self.udpFlows.removeAll()
        }
    }

    private func handleTcpState(handle: UInt64, state: NWConnection.State) {
        switch state {
        case .ready:
            if let flow = tcpFlows[handle], !flow.reportedReady {
                flow.reportedReady = true
                engine.notifyDialSucceeded(handle: handle, protocolName: "tcp")
            }
        case .failed(let error):
            if let flow = tcpFlows[handle], flow.reportedReady {
                engine.notifyTcpClose(handle: handle)
                closeTcp(handle: handle)
            } else {
                engine.notifyDialFailed(handle: handle, protocolName: "tcp", message: error.localizedDescription)
                closeTcp(handle: handle)
            }
        case .cancelled:
            if let flow = tcpFlows[handle], flow.reportedReady {
                engine.notifyTcpClose(handle: handle)
            } else {
                engine.notifyDialFailed(handle: handle, protocolName: "tcp", message: "cancelled")
            }
            closeTcp(handle: handle)
        default:
            break
        }
    }

    private func handleUdpState(handle: UInt64, state: NWConnection.State) {
        switch state {
        case .ready:
            if let flow = udpFlows[handle], !flow.reportedReady {
                flow.reportedReady = true
                engine.notifyDialSucceeded(handle: handle, protocolName: "udp")
            }
        case .failed(let error):
            if let flow = udpFlows[handle], flow.reportedReady {
                engine.notifyUdpClose(handle: handle)
                closeUdp(handle: handle)
            } else {
                engine.notifyDialFailed(handle: handle, protocolName: "udp", message: error.localizedDescription)
                closeUdp(handle: handle)
            }
        case .cancelled:
            if let flow = udpFlows[handle], flow.reportedReady {
                engine.notifyUdpClose(handle: handle)
            } else {
                engine.notifyDialFailed(handle: handle, protocolName: "udp", message: "cancelled")
            }
            closeUdp(handle: handle)
        default:
            break
        }
    }

    private func closeTcp(handle: UInt64) {
        if let flow = tcpFlows.removeValue(forKey: handle) {
            flow.connection.cancel()
        }
    }

    private func closeUdp(handle: UInt64) {
        if let flow = udpFlows.removeValue(forKey: handle) {
            flow.connection.cancel()
        }
    }

    private func receiveTcp(flow: TCPFlow) {
        flow.connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.engine.deliverTcp(handle: flow.handle, data: data)
            }
            if let error = error {
                if flow.reportedReady {
                    self.engine.notifyTcpClose(handle: flow.handle)
                } else {
                    self.engine.notifyDialFailed(handle: flow.handle, protocolName: "tcp", message: error.localizedDescription)
                }
                self.closeTcp(handle: flow.handle)
                return
            }
            if isComplete {
                self.engine.notifyTcpClose(handle: flow.handle)
                self.closeTcp(handle: flow.handle)
                return
            }
            self.receiveTcp(flow: flow)
        }
    }

    private func receiveUdp(flow: UDPFlow) {
        flow.connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.engine.deliverUdp(handle: flow.handle, data: data)
            }
            if let error = error {
                if flow.reportedReady {
                    self.engine.notifyUdpClose(handle: flow.handle)
                } else {
                    self.engine.notifyDialFailed(handle: flow.handle, protocolName: "udp", message: error.localizedDescription)
                }
                self.closeUdp(handle: flow.handle)
                return
            }
            self.receiveUdp(flow: flow)
        }
    }

    private static func makeHost(_ value: String) -> Network.NWEndpoint.Host {
        if let ipv4 = IPv4Address(value) {
            return .ipv4(ipv4)
        }
        if let ipv6 = IPv6Address(value) {
            return .ipv6(ipv6)
        }
        return .name(value, nil)
    }

    private final class TCPFlow {
        let handle: UInt64
        let connection: NWConnection
        var reportedReady = false

        init(handle: UInt64, connection: NWConnection) {
            self.handle = handle
            self.connection = connection
        }
    }

    private final class UDPFlow {
        let handle: UInt64
        let connection: NWConnection
        var reportedReady = false

        init(handle: UInt64, connection: NWConnection) {
            self.handle = handle
            self.connection = connection
        }
    }
}

// MARK: - Callback Trampolines

private extension RelativeEngine {
    static func fromContext(_ context: UnsafeMutableRawPointer?) -> RelativeEngine? {
        guard let context else { return nil }
        return Unmanaged<RelativeEngine>.fromOpaque(context).takeUnretainedValue()
    }

    static let emitPacketsTrampoline: EmitPacketsFn = { packets, sizes, protocols, count, context in
        guard let engine = RelativeEngine.fromContext(context) else { return }
        engine.handleEmitPackets(packets: packets, sizes: sizes, protocols: protocols, count: Int(count))
    }

    static let requestTcpDialTrampoline: DialFn = { host, port, handle, context in
        guard let engine = RelativeEngine.fromContext(context), let host = host else { return }
        engine.handleTcpDial(host: String(cString: host), port: port, handle: handle)
    }

    static let requestUdpDialTrampoline: DialFn = { host, port, handle, context in
        guard let engine = RelativeEngine.fromContext(context), let host = host else { return }
        engine.handleUdpDial(host: String(cString: host), port: port, handle: handle)
    }

    static let tcpSendTrampoline: SendFn = { handle, payload, length, context in
        guard let engine = RelativeEngine.fromContext(context) else { return }
        engine.handleTcpSend(handle: handle, payload: payload, length: Int(length))
    }

    static let udpSendTrampoline: SendFn = { handle, payload, length, context in
        guard let engine = RelativeEngine.fromContext(context) else { return }
        engine.handleUdpSend(handle: handle, payload: payload, length: Int(length))
    }

    static let tcpCloseTrampoline: CloseFn = { handle, _, context in
        guard let engine = RelativeEngine.fromContext(context) else { return }
        engine.handleTcpCloseFromBridge(handle: handle)
    }

    static let udpCloseTrampoline: CloseFn = { handle, _, context in
        guard let engine = RelativeEngine.fromContext(context) else { return }
        engine.handleUdpCloseFromBridge(handle: handle)
    }

    static let recordDnsTrampoline: RecordDnsFn = { host, addresses, count, ttl, context in
        guard let engine = RelativeEngine.fromContext(context), let host = host else { return }
        var values: [String] = []
        if let addresses = addresses {
            for index in 0..<count {
                if let pointer = addresses[index] {
                    values.append(String(cString: pointer))
                }
            }
        }
        engine.handleRecordDns(host: String(cString: host), addresses: values, ttl: ttl)
    }

    private static func makeTelemetryEvent(from raw: BridgeTelemetryEvent) -> TelemetryEvent {
        let timestamp = Date(timeIntervalSince1970: TimeInterval(raw.timestamp_ms) / 1000.0)
        let direction: TelemetryEvent.Direction = raw.direction == 0 ? .clientToNetwork : .networkToClient
        let source = decodeIP(raw.src_ip)
        let destination = decodeIP(raw.dst_ip)
        let flags = TelemetryEvent.Flags(rawValue: raw.flags)
        return TelemetryEvent(
            timestamp: timestamp,
            protocolNumber: raw.protocol,
            direction: direction,
            payloadLength: raw.payload_len,
            source: source,
            destination: destination,
            dnsQuery: decodeQName(raw),
            flags: flags
        )
    }

    private static func decodeIP(_ value: BridgeTelemetryIp) -> String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if value.family == 4 {
            var addr = in_addr()
            withUnsafeBytes(of: value.bytes) { rawBuffer in
                memcpy(&addr, rawBuffer.baseAddress, 4)
            }
            if let result = withUnsafePointer(to: &addr, { inet_ntop(AF_INET, $0, &buffer, socklen_t(INET_ADDRSTRLEN)) }) {
                return String(cString: result)
            }
        } else if value.family == 6 {
            var addr = in6_addr()
            withUnsafeBytes(of: value.bytes) { rawBuffer in
                memcpy(&addr, rawBuffer.baseAddress, 16)
            }
            if let result = withUnsafePointer(to: &addr, { inet_ntop(AF_INET6, $0, &buffer, socklen_t(INET6_ADDRSTRLEN)) }) {
                return String(cString: result)
            }
        }
        return "unknown"
    }

    private static func decodeQName(_ event: BridgeTelemetryEvent) -> String? {
        guard event.dns_qname_len > 0 else { return nil }
        let length = Int(event.dns_qname_len)
        return withUnsafeBytes(of: event.dns_qname) { buffer in
            let bytes = buffer.prefix(length)
            return String(bytes: bytes, encoding: .utf8)
        }
    }

    static let logTrampoline: @convention(c) (
        UnsafePointer<CChar>?,
        UnsafePointer<CChar>?,
        UInt32,
        UnsafeMutableRawPointer?
    ) -> Void = { levelPtr, messagePtr, breadcrumbs, context in
        guard let context else { return }
        let box = Unmanaged<LogSinkBox>.fromOpaque(context).takeUnretainedValue()
        let levelString = levelPtr.map { String(cString: $0) } ?? "info"
        let message = messagePtr.map { String(cString: $0) } ?? ""
        let entry = LogEntry(
            level: LogLevel.fromCString(levelString),
            message: message,
            breadcrumbs: Breadcrumbs(rawValue: breadcrumbs)
        )
        box.emit(entry: entry)
    }
}

private final class LogSinkBox {
    private let queue: DispatchQueue
    private let handler: (RelativeEngine.LogEntry) -> Void

    init(queue: DispatchQueue, handler: @escaping (RelativeEngine.LogEntry) -> Void) {
        self.queue = queue
        self.handler = handler
    }

    func emit(entry: RelativeEngine.LogEntry) {
        queue.async { [handler] in
            handler(entry)
        }
    }
}

private extension HostRuleConfiguration.Action {
    var bridgeParameters: (block: Bool, latencyMs: UInt32, jitterMs: UInt32) {
        switch self {
        case .block:
            return (true, 0, 0)
        case .shape(let latency, let jitter):
            return (false, latency, jitter)
        }
    }
}
