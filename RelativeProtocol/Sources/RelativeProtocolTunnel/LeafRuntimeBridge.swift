#if canImport(Leaf)

import Foundation
import Network
import os.log
import RelativeProtocolCore
import Leaf

typealias LeafPacketCallback = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, Int32) -> Void

@_silgen_name("leaf_tun_bridge_install_callback")
private func leaf_tun_bridge_install_callback(
    _ handle: UnsafeMutablePointer<LeafTunBridgeHandle>?,
    _ ctx: UnsafeMutableRawPointer?,
    _ callback: LeafPacketCallback
)

@_silgen_name("leaf_tun_bridge_clear_callback")
private func leaf_tun_bridge_clear_callback(
    _ handle: UnsafeMutablePointer<LeafTunBridgeHandle>?
)


private enum LeafStatus {
    static let ok: Int32 = 0
    static let ioError: Int32 = 3
}

/// Bridges the Leaf FFI into the tunnel adapter.
final class LeafRuntimeBridge: LeafRuntimeEngine, @unchecked Sendable {
    private enum EngineError: Error {
        case bridgeCreationFailed
        case configurationEncodingFailed
    }

    private static let bridgeCapacity = 512
    private static let runtimeLock = NSLock()
    private static var nextRuntimeID: UInt16 = 1

    private static func allocateRuntimeID() -> UInt16 {
        runtimeLock.lock()
        defer { runtimeLock.unlock() }
        let id = nextRuntimeID
        nextRuntimeID &+= 1
        return id
    }

    private let configuration: RelativeProtocol.Configuration
    private let logger: Logger
    private let stateLock = NSLock()

    private var callbacks: LeafRuntimeCallbacks?
    private var bridgeHandle: UnsafeMutablePointer<LeafTunBridgeHandle>?
    private var runtimeID: UInt16
    private var bridgeTag: String
    private var worker: Thread?
    private var completionSemaphore: DispatchSemaphore?
    private var running = false
    private var configCString: UnsafeMutablePointer<CChar>?
    private var statsTimer: DispatchSourceTimer?
    private let statsQueue = DispatchQueue(label: "RelativeProtocolTunnel.LeafRuntimeBridge.stats", qos: .utility)
    private var lastBridgeCounters = BridgeCounters()

    private struct BridgeCounters {
        var inbound: UInt64 = 0
        var outbound: UInt64 = 0
    }

    init(configuration: RelativeProtocol.Configuration, logger: Logger) {
        self.configuration = configuration
        self.logger = logger
        self.runtimeID = LeafRuntimeBridge.allocateRuntimeID()
        self.bridgeTag = "relative-tun-\(self.runtimeID)"
    }

    func start(callbacks: LeafRuntimeCallbacks) throws {
        try stateLock.withLock {
            guard !running else { return }
            guard let handle = createBridge() else {
                throw EngineError.bridgeCreationFailed
            }
            bridgeHandle = handle
            setEmitCallback(handle: handle)
            self.callbacks = callbacks
            running = true
        }

        callbacks.startPacketReadLoop { [weak self] packets, _ in
            self?.submitInboundPackets(packets)
        }

        do {
            try startRuntimeThread()
            startBridgeStatsLoop()
            logger.notice("Relative Protocol: Leaf engine started (rt=\(self.runtimeID))")
        } catch {
            stateLock.withLock {
                running = false
                self.callbacks = nil
            }
            clearEmitCallback()
            destroyBridge()
            throw error
        }
    }

    func stop() {
        var semaphore: DispatchSemaphore?
        stateLock.withLock {
            guard running else { return }
            running = false
            semaphore = completionSemaphore
        }

        _ = leaf_shutdown(self.runtimeID)
        let timeoutResult = semaphore?.wait(timeout: .now() + 5)
        if timeoutResult == .timedOut {
            logger.warning("Relative Protocol: Leaf runtime shutdown timed out")
        }

        stateLock.withLock {
            callbacks = nil
            completionSemaphore = nil
            worker = nil
        }

        stopBridgeStatsLoop()
        clearEmitCallback()
        destroyBridge()
        logger.notice("Relative Protocol: Leaf engine stopped (rt=\(self.runtimeID))")
    }

    deinit {
        stop()
    }
}

// MARK: - Runtime lifecycle

private extension LeafRuntimeBridge {
    func startRuntimeThread() throws {
        let configString = try buildConfigurationString()
        guard let cString = strdup(configString) else {
            throw EngineError.configurationEncodingFailed
        }

        let semaphore = DispatchSemaphore(value: 0)
        completionSemaphore = semaphore
        configCString = cString

        let thread = Thread { [weak self] in
            guard let self else {
                free(cString)
                semaphore.signal()
                return
            }

            let result = leaf_run_with_config_string(self.runtimeID, cString)
            free(cString)

            if result != LeafStatus.ok {
                self.logger.error("Relative Protocol: Leaf runtime exited with \(result)")
            }

            self.stateLock.withLock {
                self.configCString = nil
                self.running = false
                self.callbacks = nil
                self.worker = nil
                self.completionSemaphore = nil
            }
            semaphore.signal()
        }
        thread.name = "RelativeProtocol.LeafRuntimeBridge.\(self.runtimeID)"
        thread.start()
        worker = thread
    }

    func createBridge() -> UnsafeMutablePointer<LeafTunBridgeHandle>? {
        bridgeTag.withCString { tagPtr in
            leaf_tun_bridge_create(tagPtr, UInt(LeafRuntimeBridge.bridgeCapacity))
        }
    }

    func destroyBridge() {
        guard let handle = bridgeHandle else { return }
        bridgeTag.withCString { tagPtr in
            leaf_tun_bridge_destroy(handle, tagPtr)
        }
        bridgeHandle = nil
        lastBridgeCounters = BridgeCounters()
    }

    func setEmitCallback(handle: UnsafeMutablePointer<LeafTunBridgeHandle>) {
        let context = Unmanaged.passUnretained(self).toOpaque()
        leaf_tun_bridge_install_callback(handle, context, LeafRuntimeBridge.emitPacketThunk)
    }

    func clearEmitCallback() {
        guard let handle = bridgeHandle else { return }
        leaf_tun_bridge_clear_callback(handle)
    }

    func startBridgeStatsLoop() {
        guard configuration.provider.metrics.isEnabled else { return }
        guard statsTimer == nil else { return }
        let interval = max(1.0, configuration.provider.metrics.reportingInterval)
        let timer = DispatchSource.makeTimerSource(queue: statsQueue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            self?.sampleBridgeStats()
        }
        statsTimer = timer
        timer.resume()
    }

    func stopBridgeStatsLoop() {
        statsTimer?.setEventHandler {}
        statsTimer?.cancel()
        statsTimer = nil
        lastBridgeCounters = BridgeCounters()
    }

    func sampleBridgeStats() {
        guard let handle = bridgeHandle else { return }
        var inbound: UInt64 = 0
        var outbound: UInt64 = 0
        leaf_tun_bridge_stats(handle, &inbound, &outbound)
        let deltaIn = inbound &- lastBridgeCounters.inbound
        let deltaOut = outbound &- lastBridgeCounters.outbound
        lastBridgeCounters = BridgeCounters(inbound: inbound, outbound: outbound)
        guard deltaIn > 0 || deltaOut > 0 else { return }
        logger.debug("Relative Protocol: Leaf bridged +\(deltaIn)B inbound, +\(deltaOut)B outbound")
    }
}

// MARK: - Packet handling

private extension LeafRuntimeBridge {
    func submitInboundPackets(_ packets: [Data]) {
        guard let handle = bridgeHandle else { return }
        for packet in packets {
            guard !packet.isEmpty else { continue }
            let result = packet.withUnsafeBytes { rawBuffer -> Int32 in
                guard let base = rawBuffer.baseAddress else { return LeafStatus.ioError }
                let pointer = base.assumingMemoryBound(to: UInt8.self)
                return leaf_tun_bridge_submit_packet(handle, pointer, UInt(packet.count))
            }
            if result != LeafStatus.ok {
                logger.error("Relative Protocol: Leaf submit_packet failed with \(result)")
            }
        }
    }

    func handleOutboundPacket(data: UnsafePointer<UInt8>, length: Int, proto: Int32) {
        guard length > 0 else { return }
        let packet = Data(bytes: data, count: length)
        guard let callbacks = currentCallbacks() else { return }
        callbacks.emitPackets([packet], [NSNumber(value: proto)])
    }

    func currentCallbacks() -> LeafRuntimeCallbacks? {
        stateLock.withLock { callbacks }
    }
}

// MARK: - Configuration

private extension LeafRuntimeBridge {
    func buildConfigurationString() throws -> String {
        let provider = configuration.provider
        var config: [String: Any] = [:]
        config["log"] = logDictionary()
        config["inbounds"] = [tunInboundDictionary(provider: provider)]
        config["outbounds"] = outboundsDictionary()

        if let dns = dnsDictionary() {
            config["dns"] = dns
        }
        if let router = routerDictionary(blockedHosts: provider.policies.blockedHosts) {
            config["router"] = router
        }

        let data = try JSONSerialization.data(withJSONObject: config, options: [])
        guard let string = String(data: data, encoding: .utf8) else {
            throw EngineError.configurationEncodingFailed
        }
        return string
    }

    func logDictionary() -> [String: Any] {
        [
            "level": configuration.logging.enableDebug ? "debug" : "warn",
            "output": "console"
        ]
    }

    func tunInboundDictionary(provider: RelativeProtocol.Configuration.Provider) -> [String: Any] {
        var settings: [String: Any] = [
            "fd": -1,
            "auto": false,
            "name": "relative-tun",
            "address": provider.ipv4.address,
            "gateway": provider.ipv4.remoteAddress,
            "netmask": provider.ipv4.subnetMask,
            "mtu": provider.mtu
        ]
        if let ipv6 = provider.ipv6 {
            if let address = ipv6.addresses.first {
                settings["ipv6_address"] = address
            }
            if let prefix = ipv6.networkPrefixLengths.first {
                settings["ipv6_prefix_length"] = prefix
            }
            if let route = ipv6.includedRoutes.first {
                settings["ipv6_gateway"] = route.destinationAddress
            }
        }
        return [
            "protocol": "tun",
            "tag": bridgeTag,
            "settings": settings
        ]
    }

    func outboundsDictionary() -> [[String: Any]] {
        var outbounds: [[String: Any]] = [
            ["protocol": "direct", "tag": "direct"]
        ]
        if !configuration.provider.policies.blockedHosts.isEmpty {
            outbounds.append(["protocol": "drop", "tag": LeafRuntimeBridge.blockedOutboundTag])
        }
        return outbounds
    }

    func dnsDictionary() -> [String: Any]? {
        let dns = configuration.provider.dns
        guard !dns.servers.isEmpty else { return nil }
        return ["servers": dns.servers]
    }

    func routerDictionary(blockedHosts: [String]) -> [String: Any]? {
        guard !blockedHosts.isEmpty else { return nil }
        var domains: [String] = []
        var suffixes: [String] = []
        var ips: [String] = []

        for raw in blockedHosts {
            let host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty else { continue }
            if LeafRuntimeBridge.isIPAddress(host) {
                ips.append(host)
            } else if host.hasPrefix("*.") {
                suffixes.append(String(host.dropFirst(2)))
            } else if host.hasPrefix(".") {
                suffixes.append(String(host.dropFirst()))
            } else if host.contains("*") {
                suffixes.append(host.replacingOccurrences(of: "*", with: ""))
            } else {
                domains.append(host)
            }
        }

        var rules: [[String: Any]] = []
        if !domains.isEmpty {
            rules.append(["domain": domains, "target": LeafRuntimeBridge.blockedOutboundTag])
        }
        if !suffixes.isEmpty {
            rules.append(["domainSuffix": suffixes, "target": LeafRuntimeBridge.blockedOutboundTag])
        }
        if !ips.isEmpty {
            rules.append(["ip": ips, "target": LeafRuntimeBridge.blockedOutboundTag])
        }
        guard !rules.isEmpty else { return nil }
        return ["rules": rules]
    }

    static let blockedOutboundTag = "blocked"

    static func isIPAddress(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let slash = trimmed.firstIndex(of: "/") {
            let prefix = String(trimmed[..<slash])
            if IPv4Address(prefix) != nil || IPv6Address(prefix) != nil {
                return true
            }
        }
        if IPv4Address(trimmed) != nil { return true }
        if IPv6Address(trimmed) != nil { return true }
        return false
    }
}

// MARK: - Bridged callbacks

private extension LeafRuntimeBridge {
    static let emitPacketThunk: LeafPacketCallback = { context, data, length, proto in
        guard
            let context,
            let data,
            length > 0
        else { return }

        let engine = Unmanaged<LeafRuntimeBridge>.fromOpaque(context).takeUnretainedValue()
        engine.handleOutboundPacket(data: data, length: length, proto: proto)
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}

#endif
