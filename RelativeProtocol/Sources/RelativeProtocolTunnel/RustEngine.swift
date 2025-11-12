//
//  RustEngine.swift
//  RelativeProtocolTunnel
//
//  Created by Codex on 11/30/2025.
//
//  Experimental engine that bridges to the Rust core described in
//  MIGRATION.md. The implementation intentionally tolerates missing symbols
//  so existing consumers continue to fall back to the legacy engine until the
//  new xcframework ships.
//

import Darwin
import Foundation
import Network
import os.log
import RelativeProtocolCore

@_silgen_name("BridgeEnsureLinked")
private func BridgeEnsureLinkedShim() -> Bool

final class RustEngine: Engine, @unchecked Sendable {
    private let configuration: RelativeProtocol.Configuration
    private let logger: Logger
    private let bridge: RustBridge
    let dialTimeoutInterval: TimeInterval = 5.0
    private lazy var logSinkContext = RustLogSinkContext(logger: logger)
    private var engineHandle: UnsafeMutableRawPointer?
    private var callbacksHandle: Unmanaged<RustEngineCallbackContext>?
    private let lock = NSLock()
    private var trackerProvider: (() -> RelativeProtocolTunnel.ForwardHostTracker?)?
    private var logSinkInstalled = false
    private var warnedMissingLogSinkSymbol = false
    private var warnedMissingBreadcrumbSymbol = false

    static func make(
        configuration: RelativeProtocol.Configuration,
        logger: Logger
    ) -> RustEngine? {
        guard let bridge = RustBridge.shared else {
            logger.error("Relative Protocol: Rust engine bridge unavailable (symbols not found)")
            return nil
        }
        return RustEngine(configuration: configuration, logger: logger, bridge: bridge)
    }

    private init(
        configuration: RelativeProtocol.Configuration,
        logger: Logger,
        bridge: RustBridge
    ) {
        self.configuration = configuration
        self.logger = logger
        self.bridge = bridge
    }

    deinit {
        stop()
    }

    func start(callbacks: EngineCallbacks) throws {
        lock.lock()
        defer { lock.unlock() }
        guard engineHandle == nil else { return }

        installLogSinkIfNeeded()

        var bridgeConfig = BridgeConfig(configuration: configuration)
        var maybeHandle: UnsafeMutableRawPointer?
        withUnsafePointer(to: &bridgeConfig) { pointer in
            maybeHandle = bridge.newEngine(UnsafeRawPointer(pointer))
        }
        guard let handle = maybeHandle else {
            throw RelativeProtocol.PackageError.engineStartFailed("Rust bridge returned nil engine handle.")
        }

        let context = RustEngineCallbackContext(
            callbacks: callbacks,
            logger: logger,
            engine: self,
            configuration: configuration
        )
        let retained = Unmanaged.passRetained(context)
        var bridgeCallbacks = BridgeCallbacks(context: retained.toOpaque())

        var status: Int32 = -1
        withUnsafePointer(to: &bridgeCallbacks) { pointer in
            status = bridge.start(handle, UnsafeRawPointer(pointer))
        }
        guard status == 0 else {
            retained.release()
            bridge.free(handle)
            throw RelativeProtocol.PackageError.engineStartFailed("Rust engine start failed (\(status)).")
        }

        callbacksHandle = retained
        engineHandle = handle
        context.enginePointer = handle
        installReadLoop(callbacks: callbacks)
        logger.notice("Relative Protocol: Rust engine boot succeeded")
        if let counters = bridge.copyCounters(handle) {
            logger.debug(
                "Rust engine counters: tcpAdmissionFail=\(counters.tcpAdmissionFail) udpAdmissionFail=\(counters.udpAdmissionFail)"
            )
        }
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = engineHandle else { return }

        bridge.stop(handle)
        bridge.free(handle)
        engineHandle = nil

        if let callbacksHandle {
            let context = callbacksHandle.takeUnretainedValue()
            context.enginePointer = nil
            context.connectionStore.cancelAll()
            callbacksHandle.release()
            self.callbacksHandle = nil
        }

        uninstallLogSinkIfNeeded()
        logger.notice("Relative Protocol: Rust engine stopped")
    }

    private func installLogSinkIfNeeded() {
        guard !logSinkInstalled else {
            applyBreadcrumbMask(desiredBreadcrumbMask())
            return
        }
        guard let setLogSinkFn = bridge.setLogSinkFn else {
            if !warnedMissingLogSinkSymbol {
                logger.debug("Relative Protocol: Rust bridge missing BridgeSetLogSink; log forwarding disabled")
                warnedMissingLogSinkSymbol = true
            }
            applyBreadcrumbMask(desiredBreadcrumbMask())
            return
        }

        let mask = desiredBreadcrumbMask()
        var sink = BridgeLogSink(
            log: rustEngineLogSinkTrampoline,
            context: Unmanaged.passUnretained(logSinkContext).toOpaque(),
            enabled_breadcrumbs: mask
        )
        let level = desiredLogLevel()
        let installed = level.withCString { levelPointer in
            withUnsafePointer(to: &sink) { pointer in
                setLogSinkFn(UnsafeRawPointer(pointer), levelPointer, nil)
            }
        }
        if installed {
            logSinkInstalled = true
            let maskDescription = String(mask, radix: 16)
            logger.notice("Relative Protocol: Rust log sink installed (level=\(level, privacy: .public), mask=0x\(maskDescription, privacy: .public))")
        } else {
            logger.error("Relative Protocol: failed to install Rust log sink")
        }
        applyBreadcrumbMask(mask)
    }

    private func uninstallLogSinkIfNeeded() {
        guard logSinkInstalled else {
            applyBreadcrumbMask(0)
            return
        }
        guard let setLogSinkFn = bridge.setLogSinkFn else {
            applyBreadcrumbMask(0)
            return
        }
        if setLogSinkFn(nil, nil, nil) {
            logSinkInstalled = false
            logger.notice("Relative Protocol: Rust log sink removed")
        } else {
            logger.error("Relative Protocol: failed to remove Rust log sink")
        }
        applyBreadcrumbMask(0)
    }

    private func desiredLogLevel() -> String {
        configuration.logging.enableDebug ? "debug" : "info"
    }

    private func desiredBreadcrumbMask() -> UInt32 {
        var breadcrumbs = configuration.logging.breadcrumbs
        if breadcrumbs.isEmpty && configuration.logging.enableDebug {
            breadcrumbs = .all
        }
        return breadcrumbs.rawValue
    }

    private func applyBreadcrumbMask(_ mask: UInt32) {
        guard let setMaskFn = bridge.setBreadcrumbMaskFn else {
            if mask != 0 && !warnedMissingBreadcrumbSymbol {
                logger.debug("Relative Protocol: Rust bridge missing BridgeSetBreadcrumbMask; breadcrumb filters unavailable")
                warnedMissingBreadcrumbSymbol = true
            }
            return
        }
        setMaskFn(mask)
    }

    private func installReadLoop(callbacks: EngineCallbacks) {
        callbacks.startPacketReadLoop { [weak self] packets, protocols in
            self?.handleOutbound(packets: packets, protocols: protocols)
        }
    }

    private func handleOutbound(packets: [Data], protocols: [NSNumber]) {
        guard
            let engineHandle,
            let handlePacket = bridge.handlePacketFn
        else { return }

        for (index, packet) in packets.enumerated() {
            let protoValue = protocols[safe: index]?.uint32Value ?? packet.afProtocolValue
            packet.withUnsafeBytes { buffer in
                guard
                    buffer.count > 0,
                    let baseAddress = buffer.baseAddress
                else { return }
                _ = handlePacket(engineHandle, baseAddress, buffer.count, protoValue)
            }
        }
    }

    fileprivate func startReceive(
        connection: NWConnection,
        handle: UInt64,
        kind: RustConnectionStore.ConnectionKind,
        context: RustEngineCallbackContext
    ) {
        switch kind {
        case .tcp:
            receiveTCP(
                connection: connection,
                handle: handle,
                context: context
            )
        case .udp:
            receiveUDP(
                connection: connection,
                handle: handle,
                context: context
            )
        }
    }

    private func receiveTCP(
        connection: NWConnection,
        handle: UInt64,
        context: RustEngineCallbackContext
    ) {
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: context.configuration.provider.mtu
        ) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.emitToRust(handle: handle, payload: data, kind: .tcp, context: context)
            }
            if let error {
                context.logger.error("Rust engine TCP handle \(handle) receive error: \(error.localizedDescription)")
                self.handleConnectionClosure(handle: handle, context: context)
                return
            }
            if isComplete {
                self.handleConnectionClosure(handle: handle, context: context)
                return
            }
            self.receiveTCP(connection: connection, handle: handle, context: context)
        }
    }

    private func receiveUDP(
        connection: NWConnection,
        handle: UInt64,
        context: RustEngineCallbackContext
    ) {
        connection.receiveMessage { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.emitToRust(handle: handle, payload: data, kind: .udp, context: context)
            }
            if let error {
                context.logger.error("Rust engine UDP handle \(handle) receive error: \(error.localizedDescription)")
                self.handleConnectionClosure(handle: handle, context: context)
                return
            }
            if data == nil && isComplete {
                context.logger.debug("Rust engine UDP handle \(handle) receive completed with no payload; closing connection")
                self.handleConnectionClosure(handle: handle, context: context)
                return
            }
            if data == nil && !isComplete {
                context.logger.debug("Rust engine UDP handle \(handle) receive produced no payload; waiting for next datagram")
            }
            self.receiveUDP(connection: connection, handle: handle, context: context)
        }
    }

    private func emitToRust(
        handle: UInt64,
        payload: Data,
        kind: RustConnectionStore.ConnectionKind,
        context: RustEngineCallbackContext
    ) {
        guard
            let enginePointer = context.enginePointer
        else { return }
        payload.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            switch kind {
            case .tcp:
                _ = bridge.onTcpReceive(
                    engine: enginePointer,
                    handle: handle,
                    buffer: baseAddress,
                    length: buffer.count
                )
            case .udp:
                _ = bridge.onUdpReceive(
                    engine: enginePointer,
                    handle: handle,
                    buffer: baseAddress,
                    length: buffer.count
                )
            }
        }
    }

fileprivate func handleConnectionClosure(
        handle: UInt64,
        context: RustEngineCallbackContext
    ) {
        guard let enginePointer = context.enginePointer else { return }
        guard let entry = context.connectionStore.remove(handle: handle) else { return }
        let remaining = context.connectionStore.count
        context.logger.notice("Rust engine \(entry.kind.description) handle \(handle) closing; remaining=\(remaining)")
        switch entry.kind {
        case .tcp:
            bridge.onTcpClose(engine: enginePointer, handle: handle)
        case .udp:
            bridge.onUdpClose(engine: enginePointer, handle: handle)
        }
    }

}
struct RustFlowCounters {
    fileprivate let raw: FlowCounters

    var tcpAdmissionFail: UInt64 { raw.tcp_admission_fail }
    var udpAdmissionFail: UInt64 { raw.udp_admission_fail }
    var tcpBackpressureDrops: UInt64 { raw.tcp_backpressure_drops }
    var udpBackpressureDrops: UInt64 { raw.udp_backpressure_drops }
}

struct RustFlowStats {
    fileprivate let raw: FlowStats

    var pollIterations: UInt64 { raw.poll_iterations }
    var framesEmitted: UInt64 { raw.frames_emitted }
    var bytesEmitted: UInt64 { raw.bytes_emitted }
    var tcpFlushEvents: UInt64 { raw.tcp_flush_events }
    var udpFlushEvents: UInt64 { raw.udp_flush_events }
}

struct RustResolverResult {
    let addresses: [String]
    let ttl: TimeInterval?
}

extension RustEngine {
    func makeDNSResolver(
        trackerProvider: @escaping () -> RelativeProtocolTunnel.ForwardHostTracker?
    ) -> RelativeProtocol.Configuration.DNSResolver? {
        guard bridge.canResolveHosts else { return nil }
        installTrackerProvider(trackerProvider)
        return { [weak self] host in
            try await Task.detached(priority: .utility) { [weak self] in
                guard let self else { throw RustResolverError.engineUnavailable }
                return try self.resolveHost(
                    host: host,
                    tracker: trackerProvider()
                )
            }.value
        }
    }

    func installTrackerProvider(_ provider: @escaping () -> RelativeProtocolTunnel.ForwardHostTracker?) {
        lock.lock()
        trackerProvider = provider
        lock.unlock()
    }

    fileprivate func currentTracker() -> RelativeProtocolTunnel.ForwardHostTracker? {
        lock.lock()
        let provider = trackerProvider
        lock.unlock()
        return provider?()
    }

    private func resolveHost(
        host: String,
        tracker: RelativeProtocolTunnel.ForwardHostTracker?
    ) throws -> [String] {
        guard let engineHandle else {
            throw RustResolverError.engineUnavailable
        }
        guard let resolverResult = bridge.resolveHost(engine: engineHandle, host: host) else {
            throw RustResolverError.bridgeUnavailable
        }
        let addresses = resolverResult.addresses
        guard !addresses.isEmpty else {
            throw RustResolverError.lookupFailed("resolver returned no addresses")
        }
        RustEngineMetadataBridge.recordDNS(
            host: host,
            addresses: addresses,
            ttl: resolverResult.ttl,
            tracker: tracker
        )
        return addresses
    }

    fileprivate func reportDialResult(
        handle: UInt64,
        success: Bool,
        reason: String?,
        context: RustEngineCallbackContext
    ) {
        guard let enginePointer = context.enginePointer else { return }
        guard context.connectionStore.markDialCompleted(handle: handle) else { return }
        let sanitizedReason = reason.flatMap { $0.isEmpty ? nil : $0 }
        if success {
            context.logger.debug("Rust engine dial ready for handle \(handle)")
        } else if let message = sanitizedReason {
            context.logger.error("Rust engine dial failed for handle \(handle): \(message, privacy: .public)")
        } else {
            context.logger.error("Rust engine dial failed for handle \(handle)")
        }
        bridge.dialResult(
            enginePointer,
            handle: handle,
            success: success,
            reason: sanitizedReason
        )
    }

    func flowMetricsSnapshot() -> EngineFlowMetrics? {
        guard let engineHandle else { return nil }
        guard
            let counters = bridge.copyCounters(engineHandle),
            let stats = bridge.copyStats(engineHandle)
        else { return nil }
        return EngineFlowMetrics(
            counters: .init(
                tcpAdmissionFail: counters.tcpAdmissionFail,
                udpAdmissionFail: counters.udpAdmissionFail,
                tcpBackpressureDrops: counters.tcpBackpressureDrops,
                udpBackpressureDrops: counters.udpBackpressureDrops
            ),
            stats: .init(
                pollIterations: stats.pollIterations,
                framesEmitted: stats.framesEmitted,
                bytesEmitted: stats.bytesEmitted,
                tcpFlushEvents: stats.tcpFlushEvents,
                udpFlushEvents: stats.udpFlushEvents
            )
        )
    }
}

private enum RustResolverError: LocalizedError {
    case bridgeUnavailable
    case engineUnavailable
    case lookupFailed(String)

    var errorDescription: String? {
        switch self {
        case .bridgeUnavailable:
            return "Rust resolver bridge is unavailable."
        case .engineUnavailable:
            return "Rust engine handle is not ready for DNS resolution."
        case .lookupFailed(let reason):
            return "DNS resolution failed: \(reason)."
        }
    }
}

// MARK: - Bridge loading

private struct BridgeResolveResult {
    var addresses: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    var count: Int
    var storage: UnsafeMutableRawPointer?
    var ttl_seconds: UInt32

    init() {
        self.addresses = nil
        self.count = 0
        self.storage = nil
        self.ttl_seconds = 0
    }

    func toArray() -> [String] {
        guard
            count > 0,
            let addresses
        else { return [] }

        var results: [String] = []
        results.reserveCapacity(count)
        for index in 0..<count {
            if let pointer = addresses[index] {
                results.append(String(cString: pointer))
            }
        }
        return results
    }

    var ttl: TimeInterval? {
        ttl_seconds > 0 ? TimeInterval(ttl_seconds) : nil
    }
}

private struct FlowCounters {
    var tcp_admission_fail: UInt64 = 0
    var udp_admission_fail: UInt64 = 0
    var tcp_backpressure_drops: UInt64 = 0
    var udp_backpressure_drops: UInt64 = 0
}

private struct FlowStats {
    var poll_iterations: UInt64 = 0
    var frames_emitted: UInt64 = 0
    var bytes_emitted: UInt64 = 0
    var tcp_flush_events: UInt64 = 0
    var udp_flush_events: UInt64 = 0
}

private final class RustBridge {
    typealias BridgeNewEngineFn = @convention(c) (UnsafeRawPointer?) -> UnsafeMutableRawPointer?
    typealias BridgeFreeEngineFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias BridgeEngineStartFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeRawPointer?) -> Int32
    typealias BridgeEngineStopFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias BridgeEngineHandlePacketFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeRawPointer?, Int, UInt32) -> Bool
    typealias BridgeEngineOnTcpReceiveFn = @convention(c) (UnsafeMutableRawPointer?, UInt64, UnsafeRawPointer?, Int) -> Bool
    typealias BridgeEngineOnUdpReceiveFn = @convention(c) (UnsafeMutableRawPointer?, UInt64, UnsafeRawPointer?, Int) -> Bool
    typealias BridgeEngineOnCloseFn = @convention(c) (UnsafeMutableRawPointer?, UInt64) -> Void
    typealias BridgeEngineResolveHostFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Int32
    typealias BridgeResolveResultFreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias BridgeEngineDialResultFn = @convention(c) (UnsafeMutableRawPointer?, UInt64, Bool, UnsafePointer<CChar>?) -> Void
    typealias BridgeEngineGetCountersFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias BridgeSetLogSinkFn = @convention(c) (UnsafeRawPointer?, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Bool
    typealias BridgeSetBreadcrumbMaskFn = @convention(c) (UInt32) -> Void
    typealias BridgeEngineGetStatsFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool

    private static let loader = RustBridge()

    static var shared: RustBridge? {
        loader.isReady ? loader : nil
    }

    let newEngineFn: BridgeNewEngineFn?
    let freeEngineFn: BridgeFreeEngineFn?
    let startFn: BridgeEngineStartFn?
    let stopFn: BridgeEngineStopFn?
    let handlePacketFn: BridgeEngineHandlePacketFn?
    let onTcpReceiveFn: BridgeEngineOnTcpReceiveFn?
    let onUdpReceiveFn: BridgeEngineOnUdpReceiveFn?
    let onTcpCloseFn: BridgeEngineOnCloseFn?
    let onUdpCloseFn: BridgeEngineOnCloseFn?
    let resolveHostFn: BridgeEngineResolveHostFn?
    let freeResolveResultFn: BridgeResolveResultFreeFn?
    let dialResultFn: BridgeEngineDialResultFn?
    let getCountersFn: BridgeEngineGetCountersFn?
    let setLogSinkFn: BridgeSetLogSinkFn?
    let setBreadcrumbMaskFn: BridgeSetBreadcrumbMaskFn?
    let getStatsFn: BridgeEngineGetStatsFn?

    private init() {
        _ = BridgeEnsureLinkedShim()
        let handle = dlopen(nil, RTLD_LAZY)
        self.newEngineFn = RustBridge.load(symbol: "BridgeNewEngine", handle: handle, as: BridgeNewEngineFn.self)
        self.freeEngineFn = RustBridge.load(symbol: "BridgeFreeEngine", handle: handle, as: BridgeFreeEngineFn.self)
        self.startFn = RustBridge.load(symbol: "BridgeEngineStart", handle: handle, as: BridgeEngineStartFn.self)
        self.stopFn = RustBridge.load(symbol: "BridgeEngineStop", handle: handle, as: BridgeEngineStopFn.self)
        self.handlePacketFn = RustBridge.load(symbol: "BridgeEngineHandlePacket", handle: handle, as: BridgeEngineHandlePacketFn.self)
        self.onTcpReceiveFn = RustBridge.load(symbol: "BridgeEngineOnTcpReceive", handle: handle, as: BridgeEngineOnTcpReceiveFn.self)
        self.onUdpReceiveFn = RustBridge.load(symbol: "BridgeEngineOnUdpReceive", handle: handle, as: BridgeEngineOnUdpReceiveFn.self)
        self.onTcpCloseFn = RustBridge.load(symbol: "BridgeEngineOnTcpClose", handle: handle, as: BridgeEngineOnCloseFn.self)
        self.onUdpCloseFn = RustBridge.load(symbol: "BridgeEngineOnUdpClose", handle: handle, as: BridgeEngineOnCloseFn.self)
        self.resolveHostFn = RustBridge.load(symbol: "BridgeEngineResolveHost", handle: handle, as: BridgeEngineResolveHostFn.self)
        self.freeResolveResultFn = RustBridge.load(symbol: "BridgeResolveResultFree", handle: handle, as: BridgeResolveResultFreeFn.self)
        self.dialResultFn = RustBridge.load(symbol: "BridgeEngineOnDialResult", handle: handle, as: BridgeEngineDialResultFn.self)
        self.getCountersFn = RustBridge.load(symbol: "BridgeEngineGetCounters", handle: handle, as: BridgeEngineGetCountersFn.self)
        self.setLogSinkFn = RustBridge.load(symbol: "BridgeSetLogSink", handle: handle, as: BridgeSetLogSinkFn.self)
        self.setBreadcrumbMaskFn = RustBridge.load(symbol: "BridgeSetBreadcrumbMask", handle: handle, as: BridgeSetBreadcrumbMaskFn.self)
        self.getStatsFn = RustBridge.load(symbol: "BridgeEngineGetStats", handle: handle, as: BridgeEngineGetStatsFn.self)
    }

    var isReady: Bool {
        newEngineFn != nil &&
            freeEngineFn != nil &&
            startFn != nil &&
            stopFn != nil &&
            handlePacketFn != nil &&
            onTcpReceiveFn != nil &&
            onUdpReceiveFn != nil &&
            onTcpCloseFn != nil &&
            onUdpCloseFn != nil
    }

    var canResolveHosts: Bool {
        resolveHostFn != nil && freeResolveResultFn != nil
    }

    func newEngine(_ config: UnsafeRawPointer?) -> UnsafeMutableRawPointer? {
        guard let fn = newEngineFn else { return nil }
        return fn(config)
    }

    func free(_ engine: UnsafeMutableRawPointer?) {
        guard let fn = freeEngineFn else { return }
        fn(engine)
    }

    func start(_ engine: UnsafeMutableRawPointer?, _ callbacks: UnsafeRawPointer?) -> Int32 {
        guard let fn = startFn else { return -1 }
        return fn(engine, callbacks)
    }

    func stop(_ engine: UnsafeMutableRawPointer?) {
        guard let fn = stopFn else { return }
        fn(engine)
    }

    func onTcpReceive(
        engine: UnsafeMutableRawPointer?,
        handle: UInt64,
        buffer: UnsafeRawPointer?,
        length: Int
    ) -> Bool {
        guard let fn = onTcpReceiveFn else { return false }
        return fn(engine, handle, buffer, length)
    }

    func onUdpReceive(
        engine: UnsafeMutableRawPointer?,
        handle: UInt64,
        buffer: UnsafeRawPointer?,
        length: Int
    ) -> Bool {
        guard let fn = onUdpReceiveFn else { return false }
        return fn(engine, handle, buffer, length)
    }

    func onTcpClose(engine: UnsafeMutableRawPointer?, handle: UInt64) {
        guard let fn = onTcpCloseFn else { return }
        fn(engine, handle)
    }

    func onUdpClose(engine: UnsafeMutableRawPointer?, handle: UInt64) {
        guard let fn = onUdpCloseFn else { return }
        fn(engine, handle)
    }

    func dialResult(
        _ engine: UnsafeMutableRawPointer?,
        handle: UInt64,
        success: Bool,
        reason: String?
    ) {
        guard let fn = dialResultFn else { return }
        if let reason {
            reason.withCString { ptr in
                fn(engine, handle, success, ptr)
            }
        } else {
            fn(engine, handle, success, nil)
        }
    }

    func copyCounters(_ engine: UnsafeMutableRawPointer?) -> RustFlowCounters? {
        guard let fn = getCountersFn else { return nil }
        var counters = FlowCounters()
        let success = withUnsafeMutablePointer(to: &counters) { pointer in
            fn(engine, UnsafeMutableRawPointer(pointer))
        }
        guard success else { return nil }
        return RustFlowCounters(raw: counters)
    }

    func copyStats(_ engine: UnsafeMutableRawPointer?) -> RustFlowStats? {
        guard let fn = getStatsFn else { return nil }
        var stats = FlowStats()
        let success = withUnsafeMutablePointer(to: &stats) { pointer in
            fn(engine, UnsafeMutableRawPointer(pointer))
        }
        guard success else { return nil }
        return RustFlowStats(raw: stats)
    }

    func resolveHost(engine: UnsafeMutableRawPointer?, host: String) -> RustResolverResult? {
        guard
            let fn = resolveHostFn,
            let freeFn = freeResolveResultFn
        else { return nil }

        var result = BridgeResolveResult()
        let status = host.withCString { pointer -> Int32 in
            withUnsafeMutablePointer(to: &result) { buffer in
                fn(engine, pointer, UnsafeMutableRawPointer(buffer))
            }
        }
        guard status == 0 else {
            withUnsafeMutablePointer(to: &result) { buffer in
                freeFn(UnsafeMutableRawPointer(buffer))
            }
            return nil
        }
        let values = result.toArray()
        let ttl = result.ttl
        withUnsafeMutablePointer(to: &result) { buffer in
            freeFn(UnsafeMutableRawPointer(buffer))
        }
        return RustResolverResult(addresses: values, ttl: ttl)
    }

    private static func load<T>(
        symbol: String,
        handle: UnsafeMutableRawPointer?,
        as _: T.Type
    ) -> T? {
        guard let raw = dlsym(handle, symbol) else {
            return nil
        }
        return unsafeBitCast(raw, to: T.self)
    }
}

// MARK: - Callback scaffolding

private final class RustEngineCallbackContext {
    let callbacks: EngineCallbacks
    let logger: Logger
    let connectionStore = RustConnectionStore()
    unowned let engine: RustEngine
    let configuration: RelativeProtocol.Configuration
    var enginePointer: UnsafeMutableRawPointer?
    private let contextID = UUID()

    init(
        callbacks: EngineCallbacks,
        logger: Logger,
        engine: RustEngine,
        configuration: RelativeProtocol.Configuration
    ) {
        self.callbacks = callbacks
        self.logger = logger
        self.engine = engine
        self.configuration = configuration
        logger.notice("Relative Protocol: Rust engine callback context \(self.contextID.uuidString, privacy: .public) created")
    }

    deinit {
        logger.notice("Relative Protocol: Rust engine callback context \(self.contextID.uuidString, privacy: .public) destroyed")
    }
}

private typealias BridgeLogCallback = @convention(c) (
    UnsafePointer<CChar>?,
    UnsafePointer<CChar>?,
    UInt32,
    UnsafeMutableRawPointer?
) -> Void

private struct BridgeLogSink {
    var log: BridgeLogCallback?
    var context: UnsafeMutableRawPointer?
    var enabled_breadcrumbs: UInt32
}

private let rustEngineLogSinkTrampoline: BridgeLogCallback = { levelPointer, messagePointer, breadcrumbs, context in
    guard
        let context
    else { return }
    let sink = Unmanaged<RustLogSinkContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    let level = levelPointer.flatMap { String(cString: $0) }
    let message = messagePointer.flatMap { String(cString: $0) }
    sink.log(level: level, message: message, breadcrumbs: breadcrumbs)
}

private final class RustLogSinkContext {
    private let logger: Logger

    init(logger: Logger) {
        self.logger = logger
    }

    func log(level: String?, message: String?, breadcrumbs: UInt32) {
        guard let message else { return }
        let normalizedLevel = level?.lowercased() ?? "info"
        let entry = "\(message)"
        if breadcrumbs != 0 {
            logger.notice("rp-0x\(String(breadcrumbs, radix: 16)) \(entry, privacy: .public)")
        }
        switch normalizedLevel {
        case "debug":
            logger.info("\(entry, privacy: .public)")
        case "warn", "warning":
            logger.notice("\(entry, privacy: .public)")
        case "error":
            logger.error("\(entry, privacy: .public)")
        case "fatal", "panic", "dpanic":
            logger.fault("\(entry, privacy: .public)")
        default:
            logger.info("\(entry, privacy: .public)")
        }
    }
}

private typealias EmitPacketsTrampoline = @convention(c) (
    UnsafePointer<UnsafePointer<UInt8>?>?,
    UnsafePointer<Int>?,
    UnsafePointer<UInt32>?,
    Int,
    UnsafeMutableRawPointer?
) -> Void

private typealias DialTrampoline = @convention(c) (
    UnsafePointer<CChar>?,
    UInt16,
    UInt64,
    UnsafeMutableRawPointer?
) -> Void

private typealias SendTrampoline = @convention(c) (
    UInt64,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutableRawPointer?
) -> Void

private typealias CloseTrampoline = @convention(c) (
    UInt64,
    UnsafePointer<CChar>?,
    UnsafeMutableRawPointer?
) -> Void

private typealias RecordDNSTrampoline = @convention(c) (
    UnsafePointer<CChar>?,
    UnsafePointer<UnsafePointer<CChar>?>?,
    Int,
    UInt32,
    UnsafeMutableRawPointer?
) -> Void

private struct BridgeCallbacks {
    var emit_packets: EmitPacketsTrampoline?
    var request_tcp_dial: DialTrampoline?
    var request_udp_dial: DialTrampoline?
    var tcp_send: SendTrampoline?
    var udp_send: SendTrampoline?
    var tcp_close: CloseTrampoline?
    var udp_close: CloseTrampoline?
    var record_dns: RecordDNSTrampoline?
    var context: UnsafeMutableRawPointer?

    init(context: UnsafeMutableRawPointer?) {
        self.emit_packets = RustEngineEmitPackets
        self.request_tcp_dial = RustEngineRequestTCPDial
        self.request_udp_dial = RustEngineRequestUDPDial
        self.tcp_send = RustEngineHandleTcpSend
        self.udp_send = RustEngineHandleUdpSend
        self.tcp_close = RustEngineHandleTcpClose
        self.udp_close = RustEngineHandleUdpClose
        self.record_dns = RustEngineHandleRecordDNS
        self.context = context
    }
}

@_cdecl("RustEngineEmitPackets")
private func RustEngineEmitPackets(
    packetsPointer: UnsafePointer<UnsafePointer<UInt8>?>?,
    sizesPointer: UnsafePointer<Int>?,
    protocolsPointer: UnsafePointer<UInt32>?,
    count: Int,
    context: UnsafeMutableRawPointer?
) {
    guard
        count > 0,
        let context,
        let packetsPointer,
        let sizesPointer
    else { return }

    let ctx = Unmanaged<RustEngineCallbackContext>
        .fromOpaque(context)
        .takeUnretainedValue()

    var packets: [Data] = []
    packets.reserveCapacity(count)
    var protocols: [NSNumber] = []
    protocols.reserveCapacity(count)

    for index in 0..<count {
        let length = sizesPointer[index]
        guard length > 0 else { continue }
        guard let packetBase = packetsPointer[index] else { continue }
        let data = Data(bytes: packetBase, count: length)
        packets.append(data)
        let protoValue = protocolsPointer?[index] ?? data.afProtocolValue
        protocols.append(NSNumber(value: Int32(bitPattern: protoValue)))
    }

    guard !packets.isEmpty else { return }
    ctx.callbacks.emitPackets(packets, protocols)
}

@_cdecl("RustEngineRequestTCPDial")
private func RustEngineRequestTCPDial(
    hostPointer: UnsafePointer<CChar>?,
    port: UInt16,
    handle: UInt64,
    context: UnsafeMutableRawPointer?
) {
    RustEngineHandleDial(
        hostPointer: hostPointer,
        port: port,
        handle: handle,
        context: context,
        kind: .tcp
    )
}

@_cdecl("RustEngineRequestUDPDial")
private func RustEngineRequestUDPDial(
    hostPointer: UnsafePointer<CChar>?,
    port: UInt16,
    handle: UInt64,
    context: UnsafeMutableRawPointer?
) {
    RustEngineHandleDial(
        hostPointer: hostPointer,
        port: port,
        handle: handle,
        context: context,
        kind: .udp
    )
}

private func RustEngineHandleDial(
    hostPointer: UnsafePointer<CChar>?,
    port: UInt16,
    handle: UInt64,
    context: UnsafeMutableRawPointer?,
    kind: RustConnectionStore.ConnectionKind
) {
    guard
        let context,
        let hostPointer,
        let host = String(validatingUTF8: hostPointer)
    else { return }
    let ctx = Unmanaged<RustEngineCallbackContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    guard ctx.enginePointer != nil else {
        ctx.logger.error("Rust engine dial requested after engine stopped (handle \(handle))")
        return
    }
    guard let nwPort = NWEndpoint.Port(rawValue: port) else {
        ctx.logger.error("Rust engine dial rejected invalid port \(port)")
        return
    }
    let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: nwPort)
    let connection: NWConnection
    switch kind {
    case .tcp:
        connection = ctx.callbacks.makeTCPConnection(endpoint)
    case .udp:
        connection = ctx.callbacks.makeUDPConnection(endpoint)
    }
    ctx.logger.info("Rust engine requesting \(kind.description.uppercased()) dial to \(host):\(port) (handle \(handle))")
    ctx.connectionStore.register(connection: connection, handle: handle, kind: kind)
    ctx.logger.notice("Rust engine registered dial handle \(handle) kind=\(kind.description) active=\(ctx.connectionStore.count)")

    let queue = DispatchQueue(label: "RelativeProtocolTunnel.RustEngine.Connection.\(handle)")
    var lastPathSummary = "path=unavailable"
    var lastReportedError: String?
    let refreshPathSummary: () -> Void = {
        if let path = connection.currentPath {
            let summary = summarizeNetworkPath(path)
            if summary != "path=unavailable" {
                lastPathSummary = summary
            }
        }
    }
    connection.stateUpdateHandler = { [weak ctx] state in
        guard let ctx else { return }
        guard ctx.enginePointer != nil else {
            ctx.logger.error("Rust engine state update after engine stopped (handle \(handle)) – cancelling connection")
            connection.cancel()
            return
        }
        switch state {
        case .setup, .preparing, .ready, .waiting:
            refreshPathSummary()
        default:
            break
        }
        let pathSummary = lastPathSummary
        switch state {
        case .ready:
            ctx.logger.notice("Rust engine \(kind.description) handle \(handle) connection ready")
            ctx.connectionStore.cancelDialTimeout(handle: handle)
            ctx.engine.reportDialResult(
                handle: handle,
                success: true,
                reason: nil,
                context: ctx
            )
        case .failed(let error):
            let message = error.localizedDescription
            lastReportedError = message
            ctx.logger.error("Rust engine \(kind.description) handle \(handle) failed: \(message)")
            ctx.logger.notice("Rust engine \(kind.description) handle \(handle) failed – path=\(pathSummary, privacy: .public)")
            ctx.connectionStore.cancelDialTimeout(handle: handle)
            ctx.engine.reportDialResult(
                handle: handle,
                success: false,
                reason: message,
                context: ctx
            )
            connection.cancel()
        case .cancelled:
            let cancellationReason = lastReportedError ?? "cancelled"
            ctx.logger.notice("Rust engine \(kind.description) handle \(handle) cancelled by Network.framework – reason=\(cancellationReason, privacy: .public) path=\(pathSummary, privacy: .public)")
            ctx.connectionStore.cancelDialTimeout(handle: handle)
            ctx.engine.reportDialResult(
                handle: handle,
                success: false,
                reason: cancellationReason,
                context: ctx
            )
            ctx.engine.handleConnectionClosure(handle: handle, context: ctx)
        case .waiting(let error):
            let message = error.localizedDescription
            lastReportedError = message
            ctx.logger.notice("Rust engine \(kind.description) handle \(handle) waiting: \(message, privacy: .public) – path=\(pathSummary, privacy: .public)")
        default:
            break
        }
    }
    ctx.engine.startReceive(
        connection: connection,
        handle: handle,
        kind: kind,
        context: ctx
    )
    connection.start(queue: queue)

    let timeoutWork = DispatchWorkItem { [weak ctx] in
        guard let ctx else { return }
        guard ctx.enginePointer != nil else {
            ctx.logger.error("Rust engine dial timeout fired after shutdown (handle \(handle))")
            return
        }
        ctx.logger.error("Rust engine \(kind.description) dial timeout for handle \(handle)")
        ctx.engine.reportDialResult(
            handle: handle,
            success: false,
            reason: "dial_timeout",
            context: ctx
        )
        connection.cancel()
    }
    ctx.connectionStore.setDialTimeout(handle: handle, workItem: timeoutWork)
    queue.asyncAfter(deadline: .now() + ctx.engine.dialTimeoutInterval, execute: timeoutWork)
}

@_cdecl("RustEngineHandleTcpSend")
private func RustEngineHandleTcpSend(
    handle: UInt64,
    payloadPointer: UnsafePointer<UInt8>?,
    length: Int,
    context: UnsafeMutableRawPointer?
) {
    guard
        let context,
        let payloadPointer,
        length > 0
    else { return }
    let ctx = Unmanaged<RustEngineCallbackContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    let data = Data(bytes: payloadPointer, count: length)
    guard ctx.connectionStore.send(handle: handle, payload: data, logger: ctx.logger) else {
        ctx.logger.error("Rust engine attempted TCP send on unknown handle \(handle)")
        return
    }
}

@_cdecl("RustEngineHandleUdpSend")
private func RustEngineHandleUdpSend(
    handle: UInt64,
    payloadPointer: UnsafePointer<UInt8>?,
    length: Int,
    context: UnsafeMutableRawPointer?
) {
    guard
        let context,
        let payloadPointer,
        length > 0
    else { return }
    let ctx = Unmanaged<RustEngineCallbackContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    let data = Data(bytes: payloadPointer, count: length)
    guard ctx.connectionStore.send(handle: handle, payload: data, logger: ctx.logger) else {
        ctx.logger.error("Rust engine attempted UDP send on unknown handle \(handle)")
        return
    }
}

@_cdecl("RustEngineHandleTcpClose")
private func RustEngineHandleTcpClose(
    handle: UInt64,
    messagePointer: UnsafePointer<CChar>?,
    context: UnsafeMutableRawPointer?
) {
    guard let context else { return }
    let ctx = Unmanaged<RustEngineCallbackContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    if let messagePointer, let text = String(validatingUTF8: messagePointer) {
        ctx.logger.debug("Rust engine requested TCP close for \(handle): \(text, privacy: .public)")
    }
    if let entry = ctx.connectionStore.remove(handle: handle) {
        entry.connection.cancel()
    } else {
        ctx.logger.error("Rust engine attempted TCP close on unknown handle \(handle)")
    }
}

@_cdecl("RustEngineHandleUdpClose")
private func RustEngineHandleUdpClose(
    handle: UInt64,
    messagePointer: UnsafePointer<CChar>?,
    context: UnsafeMutableRawPointer?
) {
    guard let context else { return }
    let ctx = Unmanaged<RustEngineCallbackContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    if let messagePointer, let text = String(validatingUTF8: messagePointer) {
        ctx.logger.debug("Rust engine requested UDP close for \(handle): \(text, privacy: .public)")
    }
    if let entry = ctx.connectionStore.remove(handle: handle) {
        entry.connection.cancel()
    } else {
        ctx.logger.error("Rust engine attempted UDP close on unknown handle \(handle)")
    }
}

@_cdecl("RustEngineHandleRecordDNS")
private func RustEngineHandleRecordDNS(
    hostPointer: UnsafePointer<CChar>?,
    addressesPointer: UnsafePointer<UnsafePointer<CChar>?>?,
    count: Int,
    ttlSeconds: UInt32,
    context: UnsafeMutableRawPointer?
) {
    guard
        let context,
        let hostPointer
    else { return }
    let ctx = Unmanaged<RustEngineCallbackContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    let host = String(cString: hostPointer)
    var addresses: [String] = []
    if count > 0, let addressesPointer {
        addresses.reserveCapacity(count)
        for index in 0..<count {
            let pointer = addressesPointer.advanced(by: index).pointee
            if let pointer {
                addresses.append(String(cString: pointer))
            }
        }
    }
    guard !addresses.isEmpty else { return }
    let ttl = ttlSeconds > 0 ? TimeInterval(ttlSeconds) : nil
    RustEngineMetadataBridge.recordDNS(
        host: host,
        addresses: addresses,
        ttl: ttl,
        tracker: ctx.engine.currentTracker()
    )
}

// MARK: - Bridge config

private struct BridgeConfig {
    var mtu: UInt32
    var packet_pool_bytes: UInt32
    var per_flow_bytes: UInt32

    init(configuration: RelativeProtocol.Configuration) {
        self.mtu = UInt32(clamping: configuration.provider.mtu)
        self.packet_pool_bytes = UInt32(clamping: configuration.provider.memory.packetPoolBytes)
        self.per_flow_bytes = UInt32(clamping: configuration.provider.memory.perFlowBytes)
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        guard indices.contains(index) else { return nil }
        return self[index]
    }
}

private extension Data {
    var afProtocolValue: UInt32 {
        guard let firstByte = first else { return UInt32(AF_INET) }
        return (firstByte >> 4) == 6 ? UInt32(AF_INET6) : UInt32(AF_INET)
    }
}

private final class RustConnectionStore {
    enum ConnectionKind: CustomStringConvertible {
        case tcp
        case udp

        var description: String {
            switch self {
            case .tcp: return "tcp"
            case .udp: return "udp"
            }
        }
    }

final class Entry {
    let connection: NWConnection
    let kind: ConnectionKind
        var dialCompleted = false
        var dialTimeout: DispatchWorkItem?

        init(connection: NWConnection, kind: ConnectionKind) {
            self.connection = connection
            self.kind = kind
        }
}
    private var entries: [UInt64: Entry] = [:]
    private let lock = NSLock()

    func register(connection: NWConnection, handle: UInt64, kind: ConnectionKind) {
        lock.lock()
        entries[handle] = Entry(connection: connection, kind: kind)
        lock.unlock()
    }

    func setDialTimeout(handle: UInt64, workItem: DispatchWorkItem) {
        lock.lock()
        if let entry = entries[handle] {
            entry.dialTimeout?.cancel()
            entry.dialTimeout = workItem
        }
        lock.unlock()
    }

    func cancelDialTimeout(handle: UInt64) {
        lock.lock()
        if let entry = entries[handle] {
            entry.dialTimeout?.cancel()
            entry.dialTimeout = nil
        }
        lock.unlock()
    }

    func send(handle: UInt64, payload: Data, logger: Logger) -> Bool {
        guard let entry = entry(handle: handle) else {
            return false
        }
        switch entry.kind {
        case .tcp:
            entry.connection.send(content: payload, completion: .contentProcessed { error in
                if let error {
                    logger.error("Rust engine TCP send error on handle \(handle): \(error.localizedDescription)")
                }
            })
        case .udp:
            entry.connection.send(
                content: payload,
                contentContext: .defaultMessage,
                isComplete: true,
                completion: .contentProcessed { error in
                    if let error {
                        logger.error("Rust engine UDP send error on handle \(handle): \(error.localizedDescription)")
                    }
                }
            )
        }
        return true
    }

    func remove(handle: UInt64) -> Entry? {
        lock.lock()
        let entry = entries.removeValue(forKey: handle)
        entry?.dialTimeout?.cancel()
        entry?.dialTimeout = nil
        lock.unlock()
        return entry
    }

    func markDialCompleted(handle: UInt64) -> Bool {
        lock.lock()
        guard let entry = entries[handle], entry.dialCompleted == false else {
            lock.unlock()
            return false
        }
        entry.dialCompleted = true
        lock.unlock()
        return true
    }

    func cancelAll() {
        let active: [Entry]
        lock.lock()
        active = Array(entries.values)
        entries.removeAll()
        lock.unlock()
        active.forEach { entry in
            entry.dialTimeout?.cancel()
            entry.dialTimeout = nil
            entry.connection.cancel()
        }
    }

    var count: Int {
        lock.lock()
        let value = entries.count
        lock.unlock()
        return value
    }

    func entry(handle: UInt64) -> Entry? {
        lock.lock()
        let entry = entries[handle]
        lock.unlock()
        return entry
    }
}

private func summarizeNetworkPath(_ path: NWPath?) -> String {
    guard let path else { return "path=unavailable" }
    var components: [String] = ["status=\(path.status)"]
    let interfaceTypes: [NWInterface.InterfaceType] = [.wifi, .cellular, .wiredEthernet, .loopback, .other]
    let usedTypes = interfaceTypes
        .filter { path.usesInterfaceType($0) }
        .map { type -> String in
            switch type {
            case .wifi: return "wifi"
            case .cellular: return "cellular"
            case .wiredEthernet: return "ethernet"
            case .loopback: return "loopback"
            case .other: return "other"
            @unknown default: return "unknown"
            }
        }
    if !usedTypes.isEmpty {
        components.append("types=\(usedTypes.joined(separator: ","))")
    }
    components.append("expensive=\(path.isExpensive)")
    components.append("constrained=\(path.isConstrained)")
    return components.joined(separator: " ")
}
