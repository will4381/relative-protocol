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
import os.log
import RelativeProtocolCore

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
    private let logger: Logger
    private let queue = DispatchQueue(label: "RelativeProtocolTunnel.NoOpEngine")
    private var isRunning = false
    private let debugLoggingEnabled: Bool

    init(logger: Logger, debugLoggingEnabled: Bool) {
        self.logger = logger
        self.debugLoggingEnabled = debugLoggingEnabled
    }

    func start(callbacks: Tun2SocksCallbacks) throws {
        isRunning = true
        queue.async { [weak self] in
            guard let self else { return }
            callbacks.startPacketReadLoop { [weak self] packets, protocols in
                guard let self else { return }
                if self.debugLoggingEnabled {
                    self.logger.debug("Relative Protocol: Stub engine dropping \(packets.count, privacy: .public) packets")
                }
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
    private let logger: Logger
    private let engine: Tun2SocksEngine
    private let hooks: RelativeProtocol.Configuration.Hooks
    private let debugLoggingEnabled: Bool
    private let ioQueue = DispatchQueue(label: "RelativeProtocolTunnel.Tun2SocksAdapter", qos: .userInitiated)
    private var isRunning = false

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
        self.debugLoggingEnabled = configuration.logging.enableDebug
        logger = Logger(subsystem: "RelativeProtocolTunnel", category: "Tun2SocksAdapter")
    }

    /// Boots the engine and begins draining packets from `packetFlow`.
    func start() throws {
        hooks.eventSink?(.willStart)
        let callbacks = Tun2SocksCallbacks(
            startPacketReadLoop: { [weak self] handler in
                self?.scheduleRead(handler: handler)
            },
            emitPackets: { [weak self] packets, protocols in
                self?.writePackets(packets, protocols: protocols)
            },
            makeTCPConnection: { [weak self] endpoint in
                self?.makeTCPConnection(endpoint: endpoint) ?? self!.provider.makeTCPConnection(to: endpoint)
            },
            makeUDPConnection: { [weak self] endpoint in
                self?.makeUDPConnection(endpoint: endpoint) ?? self!.provider.makeUDPConnection(to: endpoint, from: nil)
            }
        )
        try engine.start(callbacks: callbacks)
        isRunning = true
        hooks.eventSink?(.didStart)
    }

    /// Halts packet processing and tears down engine resources.
    func stop() {
        guard isRunning else { return }
        engine.stop()
        isRunning = false
        hooks.eventSink?(.didStop)
    }

    /// Continuously reads from the provider and forwards packets to the engine.
    private func scheduleRead(handler: @escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) {
        ioQueue.async { [weak self] in
            guard let self else { return }
            self.startReadLoop(handler: handler)
        }
    }

    private func startReadLoop(handler: @escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) {
        provider.flow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            guard self.isRunning else { return }
            self.processInboundPackets(packets, protocols: protocols, handler: handler)
            self.startReadLoop(handler: handler)
        }
    }

    private func processInboundPackets(
        _ packets: [Data],
        protocols: [NSNumber],
        handler: @escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void
    ) {
        guard !packets.isEmpty else {
            handler(packets, protocols)
            return
        }

        var totalBytes = 0
        if let packetTap = hooks.packetTap {
            forEachPacket(packets, protocols: protocols) { packet, proto in
                totalBytes += packet.count
                packetTap(.init(direction: .inbound, payload: packet, protocolNumber: proto))
            }
        }

        if let metrics {
            if totalBytes == 0 {
                totalBytes = totalByteCount(for: packets)
            }
            metrics.record(direction: .inbound, packets: packets.count, bytes: totalBytes)
        }

        handler(packets, protocols)
    }

    /// Writes packets emitted by the engine back to the provider.
    private func writePackets(_ packets: [Data], protocols: [NSNumber]) {
        guard !packets.isEmpty else { return }
        guard isRunning else { return }

        let packetTap = hooks.packetTap
        var totalBytes = 0
        if let packetTap {
            forEachPacket(packets, protocols: protocols) { packet, proto in
                totalBytes += packet.count
                packetTap(.init(direction: .outbound, payload: packet, protocolNumber: proto))
            }
        }

        if let metrics {
            if totalBytes == 0 {
                totalBytes = totalByteCount(for: packets)
            }
            metrics.record(direction: .outbound, packets: packets.count, bytes: totalBytes)
        }
        provider.flow.writePackets(packets, protocols: protocols)
    }

    /// Consults block policies and establishes TCP connections when permitted.
    private func makeTCPConnection(endpoint: Network.NWEndpoint) -> Network.NWConnection? {
        guard case let .hostPort(host, port) = endpoint else {
            return provider.makeTCPConnection(to: endpoint)
        }
        let hostString = host.debugDescription

        if configuration.matchesBlockedHost(hostString) {
            logger.warning("Relative Protocol: Blocking TCP connection to \(hostString, privacy: .public)")
            let connection = provider.makeTCPConnection(to: endpoint)
            connection.cancel()
            hooks.eventSink?(.didFail("Relative Protocol: Blocked TCP host \(hostString)"))
            return connection
        }

        if debugLoggingEnabled {
            logger.debug("Relative Protocol: Opening TCP connection to \(hostString, privacy: .public):\(port.rawValue, privacy: .public)")
        }
        return provider.makeTCPConnection(to: endpoint)
    }

    /// Consults block policies and establishes UDP sessions when permitted.
    private func makeUDPConnection(endpoint: Network.NWEndpoint) -> Network.NWConnection? {
        guard case let .hostPort(host, port) = endpoint else {
            return provider.makeUDPConnection(to: endpoint, from: nil)
        }
        let hostString = host.debugDescription

        if configuration.matchesBlockedHost(hostString) {
            logger.warning("Relative Protocol: Blocking UDP session to \(hostString, privacy: .public)")
            let connection = provider.makeUDPConnection(to: endpoint, from: nil)
            connection.cancel()
            hooks.eventSink?(.didFail("Relative Protocol: Blocked UDP host \(hostString)"))
            return connection
        }

        if debugLoggingEnabled {
            logger.debug("Relative Protocol: Opening UDP session to \(hostString, privacy: .public):\(port.rawValue, privacy: .public)")
        }
        return provider.makeUDPConnection(to: endpoint, from: nil)
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        guard indices.contains(index) else { return nil }
        return self[index]
    }
}

private extension Data {
    var afValue: Int32 {
        guard let firstByte = first else { return Int32(AF_INET) }
        return (firstByte >> 4) == 6 ? Int32(AF_INET6) : Int32(AF_INET)
    }
}

private func totalByteCount(for packets: [Data]) -> Int {
    packets.reduce(into: 0) { $0 += $1.count }
}

private func forEachPacket(
    _ packets: [Data],
    protocols: [NSNumber],
    _ body: (_ packet: Data, _ proto: Int32) -> Void
) {
    let count = packets.count
    guard count > 0 else { return }
    let protocolCount = protocols.count
    if protocolCount == 0 {
        for packet in packets {
            body(packet, packet.afValue)
        }
        return
    }

    withUnsafeTemporaryAllocation(of: Int32.self, capacity: count) { buffer in
        for index in 0..<count {
            if index < protocolCount {
                buffer[index] = protocols[index].int32Value
            } else {
                buffer[index] = packets[index].afValue
            }
        }
        for index in 0..<count {
            body(packets[index], buffer[index])
        }
    }
}
