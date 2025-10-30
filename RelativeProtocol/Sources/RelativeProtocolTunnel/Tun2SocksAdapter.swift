//
//  Tun2SocksAdapter.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/20/2025.
//
//  Bridges `NEPacketTunnelProvider` packet flow into the tun2socks core. The
//  adapter owns the read loop, metrics accounting, and hook invocation logic
//  while delegating actual packet processing to the gomobile engine.
//

import Darwin
import Foundation
import Network
import os.log
import os.lock
import RelativeProtocolCore
import AsyncAlgorithms

/// Minimal interface adopted by both the real gomobile bridge and the noop
/// stub. Keeps the adapter decoupled from generated bindings.
protocol Tun2SocksEngine {
    func start(callbacks: Tun2SocksCallbacks) throws
    func stop()
}

/// Callback set passed into the engine so it can interact with the adapter
/// without a hard dependency on `NEPacketTunnelProvider`.
struct Tun2SocksCallbacks {
    let startPacketReadLoop: (@escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) -> Void
    let emitPackets: (_ packets: [Data], _ protocols: [NSNumber]) -> Void
    let makeTCPConnection: (_ endpoint: Network.NWEndpoint) -> Network.NWConnection
    let makeUDPConnection: (_ endpoint: Network.NWEndpoint) -> Network.NWConnection
}

/// Shim used when the gomobile-generated bindings are unavailable. It simply
/// reflects packets back through the tunnel so the provider remains responsive.
final class NoOpTun2SocksEngine: Tun2SocksEngine, @unchecked Sendable {
    private let queue = DispatchQueue(label: "RelativeProtocolTunnel.NoOpEngine")
    private var isRunning = false

    init() {}

    func start(callbacks: Tun2SocksCallbacks) throws {
        isRunning = true
        queue.async { [weak self] in
            guard let self else { return }
            callbacks.startPacketReadLoop { [weak self] packets, protocols in
                guard let self else { return }
                if self.isRunning {
                    callbacks.emitPackets(packets, protocols)
                }
            }
        }
    }

    func stop() {
        isRunning = false
    }
}

/// Coordinates packet I/O between `NEPacketTunnelProvider` and the tun2socks
/// core, enforcing hooks and metrics along the way.
final class Tun2SocksAdapter: @unchecked Sendable {
    private let provider: PacketTunnelProviding
    private let configuration: RelativeProtocol.Configuration
    private let metrics: MetricsCollector?
    private let engine: Tun2SocksEngine
    private let hooks: RelativeProtocol.Configuration.Hooks
    private let logger: Logger
    private let trafficAnalyzer: TrafficAnalyzer?
    private let forwardHostTracker = RelativeProtocolTunnel.ForwardHostTracker()
    private let ioQueue = DispatchQueue(label: "RelativeProtocolTunnel.Tun2SocksAdapter", qos: .userInitiated)
    private let memoryBudget: RelativeProtocol.Configuration.MemoryBudget
    private let packetBudget: ByteBudget
    private let trafficShaper: TrafficShaper?
    private let outboundScheduler: ShapingScheduler
    private let inboundScheduler: ShapingScheduler
    private var shapingPolicyStore: TrafficShapingPolicyStore?
    private var shapingPolicyLock = os_unfair_lock_s()
    private let memorySampler: MemoryFootprintSampler
    private let packetBatchLimit: Int
    private var budgetWarningLock = os_unfair_lock_s()
    private var lastBudgetWarning: TimeInterval = 0
    private var isRunning = false
    private var outboundChannel: AsyncChannel<PacketBatch>?
    private var outboundTask: Task<Void, Never>?
    private var inboundChannel: AsyncChannel<PacketBatch>?
    private var inboundTask: Task<Void, Never>?

    var analyzer: TrafficAnalyzer? {
        trafficAnalyzer
    }

    var hostTracker: RelativeProtocolTunnel.ForwardHostTracker {
        forwardHostTracker
    }

    /// - Parameters:
    ///   - provider: The packet tunnel provider backing the virtual interface.
    ///   - configuration: Runtime configuration describing block lists and
    ///     other policies.
    ///   - metrics: Optional collector that records packet statistics.
    ///   - engine: Concrete engine implementation (gomobile or noop).
    ///   - hooks: Caller-supplied hooks for telemetry and policy decisions.
    init(
        provider: PacketTunnelProviding,
        configuration: RelativeProtocol.Configuration,
        metrics: MetricsCollector?,
        engine: Tun2SocksEngine,
        hooks: RelativeProtocol.Configuration.Hooks,
        logger: Logger
    ) {
        self.provider = provider
        self.configuration = configuration
        self.metrics = metrics
        self.engine = engine
        self.hooks = hooks
        self.logger = logger
        self.memoryBudget = configuration.provider.memory
        self.packetBatchLimit = max(1, configuration.provider.memory.packetBatchLimit)
        self.packetBudget = ByteBudget(limit: configuration.provider.memory.packetPoolBytes)
        self.memorySampler = MemoryFootprintSampler(
            logger: logger,
            sampleInterval: 512
        )
        let shapingStore = TrafficShapingPolicyStore(configuration: configuration.provider.policies.trafficShaping)
        self.trafficShaper = TrafficShaper()
        self.outboundScheduler = ShapingScheduler(label: "RelativeProtocolTunnel.outboundShaper")
        self.inboundScheduler = ShapingScheduler(label: "RelativeProtocolTunnel.inboundShaper")
        if shapingStore.hasPolicies {
            self.shapingPolicyStore = shapingStore
        } else {
            self.shapingPolicyStore = nil
        }
        if let stream = hooks.packetStreamBuilder?() {
            let eventBus = hooks.trafficEventBusBuilder?()
            self.trafficAnalyzer = TrafficAnalyzer(
                stream: stream,
                eventBus: eventBus,
                configuration: .init(redactor: nil)
            )
        } else {
            self.trafficAnalyzer = nil
        }
    }

    /// Boots the engine and begins draining packets from `packetFlow`.
    func start() throws {
        guard !isRunning else { return }
        hooks.eventSink?(.willStart)
        isRunning = true
        prepareInboundPipeline()
        let callbacks = Tun2SocksCallbacks(
            startPacketReadLoop: { [weak self] handler in
                self?.configureOutboundPipeline(handler: handler)
            },
            emitPackets: { [weak self] packets, protocols in
                self?.enqueueInbound(packets: packets, protocols: protocols)
            },
            makeTCPConnection: { [weak self] endpoint in
                self?.makeTCPConnection(endpoint: endpoint) ?? self!.provider.makeTCPConnection(to: endpoint)
            },
            makeUDPConnection: { [weak self] endpoint in
                self?.makeUDPConnection(endpoint: endpoint) ?? self!.provider.makeUDPConnection(to: endpoint, from: nil)
            }
        )
        do {
            try engine.start(callbacks: callbacks)
        } catch {
            isRunning = false
            teardownPipelines()
            throw error
        }
        hooks.eventSink?(.didStart)
    }

    /// Halts packet processing and tears down engine resources.
    func stop() {
        guard isRunning else { return }
        engine.stop()
        isRunning = false
        teardownPipelines()
        hooks.eventSink?(.didStop)
    }

    /// Configures the outbound packet loop that drains the provider and forwards packets.
    private func configureOutboundPipeline(handler: @escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) {
        outboundChannel?.finish()
        outboundTask?.cancel()

        let channel = AsyncChannel<PacketBatch>()
        outboundChannel = channel
        outboundTask = Task { [self, handler, channel] in
            let buffered = channel.buffer(policy: .bounded(packetBatchLimit))
            for await batch in buffered {
                if Task.isCancelled { break }
                await self.processOutbound(batch, handler: handler)
            }
        }
        scheduleRead(into: channel)
    }

    /// Continuously reads from the provider and forwards packets into the outbound channel.
    private func scheduleRead(into channel: AsyncChannel<PacketBatch>) {
        ioQueue.async { [weak self] in
            guard let self else { return }
            guard self.isRunning else { return }
            self.provider.flow.readPackets { [weak self] packets, protocols in
                guard let self else { return }
                guard self.isRunning else { return }

                let totalBytes = Tun2SocksAdapter.totalBytes(in: packets)
                guard totalBytes > 0, !packets.isEmpty else {
                    self.scheduleRead(into: channel)
                    return
                }

                Task { [weak self] in
                    guard let self else { return }
                    if !self.packetBudget.reserve(bytes: totalBytes) {
                        self.recordDroppedBatch(direction: .outbound, bytes: totalBytes, reason: "packet budget exhausted")
                        self.scheduleRead(into: channel)
                        return
                    }
                    self.emitBudgetWarningIfNeeded()
                    let batch = PacketBatch(
                        packets: packets,
                        protocols: protocols,
                        totalBytes: totalBytes,
                        reservedBytes: totalBytes
                    )
                    self.memorySampler.recordPacketBatch(count: batch.packets.count, tag: "outbound")
                    await channel.send(batch)
                    self.scheduleRead(into: channel)
                }
            }
        }
    }

    private func prepareInboundPipeline() {
        inboundChannel?.finish()
        inboundTask?.cancel()

        let channel = AsyncChannel<PacketBatch>()
        inboundChannel = channel
        inboundTask = Task { [self, channel] in
            let buffered = channel.buffer(policy: .bounded(packetBatchLimit))
            for await batch in buffered {
                if Task.isCancelled { break }
                await self.processInbound(batch)
            }
        }
    }

    private func teardownPipelines() {
        outboundChannel?.finish()
        inboundChannel?.finish()
        outboundTask?.cancel()
        inboundTask?.cancel()
        outboundChannel = nil
        inboundChannel = nil
        outboundTask = nil
        inboundTask = nil
        packetBudget.reset()
    }

    private func enqueueInbound(packets: [Data], protocols: [NSNumber]) {
        guard !packets.isEmpty else { return }
        guard isRunning else { return }
        guard let channel = inboundChannel else { return }
        let totalBytes = Tun2SocksAdapter.totalBytes(in: packets)
        guard totalBytes > 0 else { return }
        if !packetBudget.reserve(bytes: totalBytes) {
            recordDroppedBatch(direction: .inbound, bytes: totalBytes, reason: "packet budget exhausted")
            return
        }
        emitBudgetWarningIfNeeded()
        memorySampler.recordPacketBatch(count: packets.count, tag: "inbound")
        let batch = PacketBatch(
            packets: packets,
            protocols: protocols,
            totalBytes: totalBytes,
            reservedBytes: totalBytes
        )
        Task {
            await channel.send(batch)
        }
    }

    private func processOutbound(_ batch: PacketBatch, handler: @escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) async {
        guard isRunning else {
            packetBudget.release(batch.reservedBytes)
            return
        }
        guard !batch.packets.isEmpty else {
            packetBudget.release(batch.reservedBytes)
            return
        }
        let timestamp = Date()
        metrics?.record(direction: .outbound, packets: batch.packets.count, bytes: batch.totalBytes)

        for (index, packet) in batch.packets.enumerated() {
            let proto = batch.protocols[safe: index]?.int32Value ?? packet.afValue
            hooks.packetTap?(.init(direction: .outbound, payload: packet, protocolNumber: proto))
            forwardHostTracker.ingestTLSClientHello(ipPacket: packet, timestamp: timestamp)

            if Tun2SocksAdapter.shouldAnalyze(packet: packet, direction: .outbound) {
                trafficAnalyzer?.ingest(sample: .init(
                    direction: .outbound,
                    payload: packet,
                    protocolNumber: proto
                ))
            }
        }

        let reservedBytes = batch.reservedBytes
        let budget = packetBudget
        let deliver: @Sendable () -> Void = { [weak self] in
            autoreleasepool {
                guard let self else {
                    budget.release(reservedBytes)
                    return
                }
                defer { budget.release(reservedBytes) }
                guard self.isRunning else { return }
                handler(batch.packets, batch.protocols)
            }
        }
        if let delay = await shapingDelay(direction: .outbound, batch: batch, timestamp: timestamp), delay > 0 {
            outboundScheduler.schedule(delay: delay, action: deliver)
        } else {
            deliver()
        }
    }

    private func processInbound(_ batch: PacketBatch) async {
        guard isRunning else {
            packetBudget.release(batch.reservedBytes)
            return
        }
        guard !batch.packets.isEmpty else {
            packetBudget.release(batch.reservedBytes)
            return
        }
        let timestamp = Date()
        metrics?.record(direction: .inbound, packets: batch.packets.count, bytes: batch.totalBytes)

        for (index, packet) in batch.packets.enumerated() {
            let proto = batch.protocols[safe: index]?.int32Value ?? packet.afValue
            hooks.packetTap?(.init(direction: .inbound, payload: packet, protocolNumber: proto))

            forwardHostTracker.ingest(ipPacket: packet, timestamp: timestamp)

            if Tun2SocksAdapter.shouldAnalyze(packet: packet, direction: .inbound) {
                trafficAnalyzer?.ingest(sample: .init(
                    direction: .inbound,
                    payload: packet,
                    protocolNumber: proto
                ))
            }
        }

        let reservedBytes = batch.reservedBytes
        let budget = packetBudget
        let deliver: @Sendable () -> Void = { [weak self] in
            autoreleasepool {
                guard let self else {
                    budget.release(reservedBytes)
                    return
                }
                defer { budget.release(reservedBytes) }
                guard self.isRunning else { return }
                self.provider.flow.writePackets(batch.packets, protocols: batch.protocols)
            }
        }
        if let delay = await shapingDelay(direction: .inbound, batch: batch, timestamp: timestamp), delay > 0 {
            inboundScheduler.schedule(delay: delay, action: deliver)
        } else {
            deliver()
        }
    }

    private func shapingDelay(direction: RelativeProtocol.Direction, batch: PacketBatch, timestamp: Date) async -> TimeInterval? {
        guard let trafficShaper, let shapingPolicyStore = currentShapingPolicyStore() else { return nil }

        var maxDelay: TimeInterval = 0
        var hasMatchingPolicy = false

        for packet in batch.packets {
            guard let metadata = PacketMetadataExtractor.metadata(for: packet, direction: direction) else { continue }
            let host = forwardHostTracker.lookup(ip: metadata.remoteIP, at: timestamp)
            let key = PolicyKey(
                host: host,
                ip: metadata.remoteIP,
                port: metadata.remotePort,
                protocolNumber: metadata.protocolNumber
            )
            guard let policy = shapingPolicyStore.policy(for: key) else { continue }
            hasMatchingPolicy = true
            let delay = await trafficShaper.reserve(policy: policy, key: key, packetBytes: packet.count)
            if delay > maxDelay {
                maxDelay = delay
            }
        }

        guard hasMatchingPolicy else { return nil }
        return maxDelay
    }

    func updateTrafficShaping(configuration: RelativeProtocol.Configuration.TrafficShaping) {
        let store = TrafficShapingPolicyStore(configuration: configuration)
        os_unfair_lock_lock(&shapingPolicyLock)
        shapingPolicyStore = store.hasPolicies ? store : nil
        os_unfair_lock_unlock(&shapingPolicyLock)
    }

    private func currentShapingPolicyStore() -> TrafficShapingPolicyStore? {
        os_unfair_lock_lock(&shapingPolicyLock)
        let store = shapingPolicyStore
        os_unfair_lock_unlock(&shapingPolicyLock)
        return store
    }

    private func emitBudgetWarningIfNeeded() {
        let utilization = packetBudget.utilization
        guard utilization >= 0.85 else { return }
        let now = Date().timeIntervalSince1970
        var shouldLog = false
        os_unfair_lock_lock(&budgetWarningLock)
        if now - lastBudgetWarning >= 5 {
            lastBudgetWarning = now
            shouldLog = true
        }
        os_unfair_lock_unlock(&budgetWarningLock)
        guard shouldLog else { return }
        let percentage = Int(utilization * 100)
        logger.warning("Relative Protocol: packet backlog at \(percentage)% of budget (\(self.packetBudget.currentBytes)/\(self.memoryBudget.packetPoolBytes) bytes)")
    }

    private func recordDroppedBatch(direction: RelativeProtocol.Direction, bytes: Int, reason: String) {
        logger.error("Relative Protocol: dropped \(direction.rawValue) packet batch (\(bytes) bytes) – \(reason)")
        hooks.eventSink?(.didFail("Relative Protocol dropped \(direction.rawValue) packets (\(bytes) bytes): \(reason)"))
    }

    private static func totalBytes(in packets: [Data]) -> Int {
        packets.reduce(0) { $0 + $1.count }
    }

    /// Consults block policies and establishes TCP connections when permitted.
    private func makeTCPConnection(endpoint: Network.NWEndpoint) -> Network.NWConnection? {
        guard case let .hostPort(host, _) = endpoint else {
            return provider.makeTCPConnection(to: endpoint)
        }
        let hostString = host.debugDescription

        if configuration.matchesBlockedHost(hostString) {
            let connection = provider.makeTCPConnection(to: endpoint)
            connection.cancel()
            hooks.eventSink?(.didFail("Relative Protocol: Blocked TCP host \(hostString)"))
            return connection
        }

        return provider.makeTCPConnection(to: endpoint)
    }

    /// Consults block policies and establishes UDP sessions when permitted.
    private func makeUDPConnection(endpoint: Network.NWEndpoint) -> Network.NWConnection? {
        guard case let .hostPort(host, _) = endpoint else {
            return provider.makeUDPConnection(to: endpoint, from: nil)
        }
        let hostString = host.debugDescription

        if configuration.matchesBlockedHost(hostString) {
            let connection = provider.makeUDPConnection(to: endpoint, from: nil)
            connection.cancel()
            hooks.eventSink?(.didFail("Relative Protocol: Blocked UDP host \(hostString)"))
            return connection
        }

        return provider.makeUDPConnection(to: endpoint, from: nil)
    }
}

private struct PacketMetadata {
    var remoteIP: String
    var remotePort: UInt16?
    var protocolNumber: UInt8
}

private enum PacketMetadataExtractor {
    static func metadata(for packet: Data, direction: RelativeProtocol.Direction) -> PacketMetadata? {
        guard let firstByte = packet.first else { return nil }
        let version = firstByte >> 4
        switch version {
        case 4:
            return parseIPv4(packet: packet, direction: direction)
        case 6:
            return parseIPv6(packet: packet, direction: direction)
        default:
            return nil
        }
    }

    private static func parseIPv4(packet: Data, direction: RelativeProtocol.Direction) -> PacketMetadata? {
        guard packet.count >= 20 else { return nil }
        let ihl = Int(packet[0] & 0x0F) * 4
        guard ihl >= 20, packet.count >= ihl else { return nil }
        let proto = packet[9]

        let sourceIP = packet[12..<16]
        let destinationIP = packet[16..<20]
        let remoteIPBytes = direction == .outbound ? destinationIP : sourceIP

        let portBase = ihl
        let remotePort: UInt16?
        if proto == 6 || proto == 17 {
            guard packet.count >= portBase + 4 else { return nil }
            let srcPort = readUInt16(packet, offset: portBase)
            let dstPort = readUInt16(packet, offset: portBase + 2)
            remotePort = direction == .outbound ? dstPort : srcPort
        } else {
            remotePort = nil
        }

        return PacketMetadata(
            remoteIP: ipv4String(remoteIPBytes),
            remotePort: remotePort,
            protocolNumber: proto
        )
    }

    private static func parseIPv6(packet: Data, direction: RelativeProtocol.Direction) -> PacketMetadata? {
        let headerLength = 40
        guard packet.count >= headerLength else { return nil }
        let nextHeader = packet[6]

        let sourceIP = packet[8..<24]
        let destinationIP = packet[24..<40]
        let remoteIPBytes = direction == .outbound ? destinationIP : sourceIP

        let portBase = headerLength
        let remotePort: UInt16?
        if nextHeader == 6 || nextHeader == 17 {
            guard packet.count >= portBase + 4 else { return nil }
            let srcPort = readUInt16(packet, offset: portBase)
            let dstPort = readUInt16(packet, offset: portBase + 2)
            remotePort = direction == .outbound ? dstPort : srcPort
        } else {
            remotePort = nil
        }

        guard let remoteIP = ipv6String(remoteIPBytes) else { return nil }
        return PacketMetadata(
            remoteIP: remoteIP,
            remotePort: remotePort,
            protocolNumber: nextHeader
        )
    }

    private static func readUInt16(_ packet: Data, offset: Int) -> UInt16 {
        guard offset + 1 < packet.count else { return 0 }
        let high = UInt16(packet[offset]) << 8
        let low = UInt16(packet[offset + 1])
        return high | low
    }

    private static func ipv4String(_ bytes: Data.SubSequence) -> String {
        var octets: [String] = []
        octets.reserveCapacity(4)
        for byte in bytes {
            octets.append(String(byte))
        }
        return octets.joined(separator: ".")
    }

    private static func ipv6String(_ bytes: Data.SubSequence) -> String? {
        var address = [UInt8](repeating: 0, count: 16)
        guard bytes.count == 16 else { return nil }
        address.withUnsafeMutableBytes { buffer in
            buffer.copyBytes(from: bytes)
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return address.withUnsafeBytes { pointer in
            guard inet_ntop(AF_INET6, pointer.baseAddress, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return nil
            }
            return String(cString: buffer)
        }
    }
}

private struct PacketBatch: @unchecked Sendable {
    let packets: [Data]
    let protocols: [NSNumber]
    let totalBytes: Int
    let reservedBytes: Int
}

private final class ShapingScheduler: @unchecked Sendable {
    private let queue: DispatchQueue

    init(label: String) {
        queue = DispatchQueue(label: label, qos: .userInitiated, attributes: .concurrent)
    }

    func schedule(delay: TimeInterval, action: @escaping @Sendable () -> Void) {
        guard delay.isFinite, delay > 0 else {
            queue.async(execute: action)
            return
        }
        let nanoseconds = Self.nanoseconds(for: delay)
        let interval = DispatchTimeInterval.nanoseconds(nanoseconds)
        queue.asyncAfter(deadline: .now() + interval, execute: action)
    }

    private static func nanoseconds(for delay: TimeInterval) -> Int {
        let cappedDelay = min(max(delay, 0), Double(Int.max) / 1_000_000_000.0)
        return Int(cappedDelay * 1_000_000_000.0)
    }
}

private final class ByteBudget {
    private let limit: Int
    private var current: Int
    private var lock = os_unfair_lock_s()

    init(limit: Int) {
        self.limit = max(limit, 1)
        self.current = 0
    }

    func reserve(bytes: Int) -> Bool {
        guard bytes > 0 else { return true }
        os_unfair_lock_lock(&lock)
        let prospective = current + bytes
        if prospective > limit {
            os_unfair_lock_unlock(&lock)
            return false
        }
        current = prospective
        os_unfair_lock_unlock(&lock)
        return true
    }

    func release(_ bytes: Int) {
        guard bytes > 0 else { return }
        os_unfair_lock_lock(&lock)
        current = max(0, current - bytes)
        os_unfair_lock_unlock(&lock)
    }

    func reset() {
        os_unfair_lock_lock(&lock)
        current = 0
        os_unfair_lock_unlock(&lock)
    }

    var utilization: Double {
        os_unfair_lock_lock(&lock)
        let ratio = Double(current) / Double(limit)
        os_unfair_lock_unlock(&lock)
        return ratio
    }

    var currentBytes: Int {
        os_unfair_lock_lock(&lock)
        let value = current
        os_unfair_lock_unlock(&lock)
        return value
    }
}

private final class MemoryFootprintSampler {
    private let logger: Logger
    private let sampleInterval: Int
    private var counter: Int
    private var lock = os_unfair_lock_s()

    init(logger: Logger, sampleInterval: Int) {
        self.logger = logger
        self.sampleInterval = max(sampleInterval, 1)
        self.counter = 0
    }

    func recordPacketBatch(count: Int, tag: String) {
        guard count > 0 else { return }
        var shouldSample = false
        os_unfair_lock_lock(&lock)
        counter += count
        if counter >= sampleInterval {
            counter = 0
            shouldSample = true
        }
        os_unfair_lock_unlock(&lock)
        guard shouldSample else { return }
        guard let footprint = MemoryFootprintSampler.currentFootprintMB() else { return }
        logger.notice("Relative Protocol: footprint = \(footprint, format: .fixed(precision: 1), privacy: .public) MB \(tag, privacy: .public)")
    }

    private static func currentFootprintMB() -> Double? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout.size(ofValue: info) / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return Double(info.phys_footprint) / 1_048_576.0
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        guard indices.contains(index) else { return nil }
        return self[index]
    }
}

private extension Tun2SocksAdapter {
    static func shouldAnalyze(packet: Data, direction: RelativeProtocol.Direction) -> Bool {
        return packet.withUnsafeBytes { rawBuffer -> Bool in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
            guard rawBuffer.count >= 1 else { return false }
            let version = base[0] >> 4
            switch version {
            case 4:
                guard rawBuffer.count >= 20 else { return false }
                let offset = direction == .outbound ? 16 : 12
                return isPublicIPv4(bytes: base.advanced(by: offset))
            case 6:
                guard rawBuffer.count >= 40 else { return false }
                let offset = direction == .outbound ? 24 : 8
                return isPublicIPv6(bytes: base.advanced(by: offset))
            default:
                return false
            }
        }
    }

    static func isPublicIPv4(bytes: UnsafePointer<UInt8>) -> Bool {
        let first = bytes[0]
        let second = bytes[1]
        switch first {
        case 0, 10, 127:
            return false
        case 169 where second == 254:
            return false
        case 172 where (16...31).contains(second):
            return false
        case 192 where second == 168:
            return false
        case 100 where (64...127).contains(second):
            return false
        case 198 where (second == 18 || second == 19):
            return false
        case 224...239:
            return false
        case 255:
            return false
        default:
            return true
        }
    }

    static func isPublicIPv6(bytes: UnsafePointer<UInt8>) -> Bool {
        var octets = [UInt8](repeating: 0, count: 16)
        for index in 0..<16 {
            octets[index] = bytes[index]
        }

        if octets.allSatisfy({ $0 == 0 }) { return false }
        if octets.dropLast().allSatisfy({ $0 == 0 }) && octets.last == 1 { return false }
        if (octets[0] & 0xfe) == 0xfc { return false }
        if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 { return false }
        if octets[0] == 0xff { return false }
        if octets[0] == 0x20, octets[1] == 0x01, octets[2] == 0x0d, octets[3] == 0xb8 { return false }

        if isIPv4Mapped(octets) {
            let ipv4 = [octets[12], octets[13], octets[14], octets[15]]
            return ipv4.withUnsafeBufferPointer { buffer in
                buffer.baseAddress.map { isPublicIPv4(bytes: $0) } ?? false
            }
        }

        return (octets[0] & 0xe0) == 0x20
    }

    static func isIPv4Mapped(_ octets: [UInt8]) -> Bool {
        guard octets.count == 16 else { return false }
        for index in 0..<10 where octets[index] != 0 { return false }
        if octets[10] != 0xff || octets[11] != 0xff { return false }
        return true
    }
}

private extension Data {
    var afValue: Int32 {
        guard let firstByte = first else { return Int32(AF_INET) }
        return (firstByte >> 4) == 6 ? Int32(AF_INET6) : Int32(AF_INET)
    }
}
