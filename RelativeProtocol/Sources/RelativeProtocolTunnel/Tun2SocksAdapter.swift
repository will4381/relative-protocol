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

import Foundation
import Network
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
    private let trafficAnalyzer: TrafficAnalyzer?
    private let latencyInjector: RelativeProtocol.Configuration.LatencyInjector?
    private let ioQueue = DispatchQueue(label: "RelativeProtocolTunnel.Tun2SocksAdapter", qos: .userInitiated)
    private var isRunning = false
    private var outboundChannel: AsyncChannel<PacketBatch>?
    private var outboundTask: Task<Void, Never>?
    private var inboundChannel: AsyncChannel<PacketBatch>?
    private var inboundTask: Task<Void, Never>?

    var analyzer: TrafficAnalyzer? {
        trafficAnalyzer
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
        hooks: RelativeProtocol.Configuration.Hooks
    ) {
        self.provider = provider
        self.configuration = configuration
        self.metrics = metrics
        self.engine = engine
        self.hooks = hooks
        self.latencyInjector = hooks.latencyInjector
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
            let buffered = channel.buffer(policy: .bounded(4))
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
            self.provider.flow.readPackets { packets, protocols in
                guard self.isRunning else { return }
                let batch = PacketBatch(packets: packets, protocols: protocols)
                Task {
                    await channel.send(batch)
                }
                // Reschedule the loop.
                self.scheduleRead(into: channel)
            }
        }
    }

    private func prepareInboundPipeline() {
        inboundChannel?.finish()
        inboundTask?.cancel()

        let channel = AsyncChannel<PacketBatch>()
        inboundChannel = channel
        inboundTask = Task { [self, channel] in
            let buffered = channel.buffer(policy: .bounded(4))
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
    }

    private func enqueueInbound(packets: [Data], protocols: [NSNumber]) {
        guard !packets.isEmpty else { return }
        guard isRunning else { return }
        guard let channel = inboundChannel else { return }
        let batch = PacketBatch(packets: packets, protocols: protocols)
        Task {
            await channel.send(batch)
        }
    }

    private func processOutbound(_ batch: PacketBatch, handler: @escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) async {
        guard isRunning else { return }
        await applyLatencyIfNeeded()
        if !batch.packets.isEmpty {
            let totalBytes = batch.packets.reduce(0) { $0 + $1.count }
            metrics?.record(direction: .outbound, packets: batch.packets.count, bytes: totalBytes)
        }
        batch.packets.enumerated().forEach { index, packet in
            let proto = batch.protocols[safe: index]?.int32Value ?? packet.afValue
            hooks.packetTap?(.init(direction: .outbound, payload: packet, protocolNumber: proto))
            trafficAnalyzer?.ingest(sample: .init(
                direction: .outbound,
                payload: packet,
                protocolNumber: proto
            ))
        }
        handler(batch.packets, batch.protocols)
    }

    private func processInbound(_ batch: PacketBatch) async {
        guard isRunning else { return }
        guard !batch.packets.isEmpty else { return }
        await applyLatencyIfNeeded()
        let totalBytes = batch.packets.reduce(0) { $0 + $1.count }
        metrics?.record(direction: .inbound, packets: batch.packets.count, bytes: totalBytes)
        batch.packets.enumerated().forEach { index, packet in
            let proto = batch.protocols[safe: index]?.int32Value ?? packet.afValue
            hooks.packetTap?(.init(direction: .inbound, payload: packet, protocolNumber: proto))
            trafficAnalyzer?.ingest(sample: .init(
                direction: .inbound,
                payload: packet,
                protocolNumber: proto
            ))
        }
        provider.flow.writePackets(batch.packets, protocols: batch.protocols)
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

private struct PacketBatch: @unchecked Sendable {
    let packets: [Data]
    let protocols: [NSNumber]
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        guard indices.contains(index) else { return nil }
        return self[index]
    }
}

private extension Tun2SocksAdapter {
    func applyLatencyIfNeeded() async {
        guard let latencyInjector else { return }
        let endpoint = RelativeProtocol.Configuration.Endpoint(host: "relative.protocol.latency", port: 0, transport: .tcp)
        guard let delay = await latencyInjector(endpoint), delay > 0 else { return }
        let milliseconds = max(delay, 0)
        let maxMilliseconds = Int(UInt64.max / 1_000_000)
        let capped = min(milliseconds, maxMilliseconds)
        let nanoseconds = UInt64(capped) * 1_000_000
        do {
            try await Task.sleep(nanoseconds: nanoseconds)
        } catch {
            // Ignore cancellation so the pipeline can shut down promptly.
        }
    }
}

private extension Data {
    var afValue: Int32 {
        guard let firstByte = first else { return Int32(AF_INET) }
        return (firstByte >> 4) == 6 ? Int32(AF_INET6) : Int32(AF_INET)
    }
}
