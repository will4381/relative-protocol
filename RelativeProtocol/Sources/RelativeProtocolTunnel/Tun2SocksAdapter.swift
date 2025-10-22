//
//  Tun2SocksAdapter.swift
//  RelativeProtocolTunnel
//
//  Bridges NEPacketTunnelProvider packet flow into the tun2socks core.
//

import Foundation
import Network
import os.log
import RelativeProtocolCore

protocol Tun2SocksEngine {
    func start(callbacks: Tun2SocksCallbacks) throws
    func stop()
}

struct Tun2SocksCallbacks {
    let startPacketReadLoop: (@escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) -> Void
    let emitPackets: (_ packets: [Data], _ protocols: [NSNumber]) -> Void
    let makeTCPConnection: (_ endpoint: Network.NWEndpoint) -> Network.NWConnection
    let makeUDPConnection: (_ endpoint: Network.NWEndpoint) -> Network.NWConnection
}

/// Shim used prior to wiring up the gomobile-generated bindings. Keeps the tunnel alive and logs activity.
final class NoOpTun2SocksEngine: Tun2SocksEngine, @unchecked Sendable {
    private let logger: Logger
    private let queue = DispatchQueue(label: "RelativeProtocolTunnel.NoOpEngine")
    private var isRunning = false

    init(logger: Logger) {
        self.logger = logger
    }

    func start(callbacks: Tun2SocksCallbacks) throws {
        isRunning = true
        queue.async { [weak self] in
            guard let self else { return }
            callbacks.startPacketReadLoop { [weak self] packets, protocols in
                guard let self else { return }
                self.logger.debug("Relative Protocol: Stub engine dropping \(packets.count, privacy: .public) packets")
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

/// Coordinating object that keeps the packet loop readable from the provider.
final class Tun2SocksAdapter: @unchecked Sendable {
    private let provider: PacketTunnelProviding
    private let configuration: RelativeProtocol.Configuration
    private let metrics: MetricsCollector?
    private let logger: Logger
    private let engine: Tun2SocksEngine
    private let hooks: RelativeProtocol.Configuration.Hooks
    private let ioQueue = DispatchQueue(label: "RelativeProtocolTunnel.Tun2SocksAdapter", qos: .userInitiated)
    private var isRunning = false

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
        logger = Logger(subsystem: "RelativeProtocolTunnel", category: "Tun2SocksAdapter")
    }

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

    func stop() {
        guard isRunning else { return }
        engine.stop()
        isRunning = false
        hooks.eventSink?(.didStop)
    }

    private func scheduleRead(handler: @escaping @Sendable (_ packets: [Data], _ protocols: [NSNumber]) -> Void) {
        ioQueue.async { [weak self] in
            guard let self else { return }
            self.provider.flow.readPackets { packets, protocols in
                self.metrics?.record(direction: .inbound, packets: packets.count, bytes: packets.reduce(0) { $0 + $1.count })
                packets.enumerated().forEach { index, packet in
                    let proto = protocols[safe: index]?.int32Value ?? packet.afValue
                    self.hooks.packetTap?(.init(direction: .inbound, payload: packet, protocolNumber: proto))
                }
                handler(packets, protocols)
                // Reschedule the loop.
                self.scheduleRead(handler: handler)
            }
        }
    }

    private func writePackets(_ packets: [Data], protocols: [NSNumber]) {
        guard !packets.isEmpty else { return }
        metrics?.record(direction: .outbound, packets: packets.count, bytes: packets.reduce(0) { $0 + $1.count })
        packets.enumerated().forEach { index, packet in
            let proto = protocols[safe: index]?.int32Value ?? packet.afValue
            hooks.packetTap?(.init(direction: .outbound, payload: packet, protocolNumber: proto))
        }
        provider.flow.writePackets(packets, protocols: protocols)
    }

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

        logger.debug("Relative Protocol: Opening TCP connection to \(hostString, privacy: .public):\(port.rawValue, privacy: .public)")
        return provider.makeTCPConnection(to: endpoint)
    }

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

        logger.debug("Relative Protocol: Opening UDP session to \(hostString, privacy: .public):\(port.rawValue, privacy: .public)")
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
