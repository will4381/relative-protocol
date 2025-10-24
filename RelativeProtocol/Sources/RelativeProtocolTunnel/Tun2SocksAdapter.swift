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
                    self.logger.notice("Relative Protocol: Stub engine dropping \(packets.count, privacy: .public) packets")
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
        if let batchTap = hooks.packetTapBatch {
            var contexts: [RelativeProtocol.Configuration.PacketContext] = []
            contexts.reserveCapacity(packets.count)
            forEachPacket(packets, protocols: protocols) { packet, proto in
                totalBytes += packet.count
                contexts.append(.init(direction: .inbound, payload: packet, protocolNumber: proto))
            }
            if !contexts.isEmpty { batchTap(contexts) }
        } else if let packetTap = hooks.packetTap {
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

        if debugLoggingEnabled {
            // Log a concise batch summary with a sample packet header to verify
            // packets are reaching the extension.
            let sample = packets.first.flatMap { summarizeIPPacket($0) } ?? "<no-sample>"
            logger.notice("Relative Protocol: Inbound batch packets=\(packets.count, privacy: .public) bytes=\(totalBytes, privacy: .public) sample=\(sample, privacy: .public)")
        }

        handler(packets, protocols)
    }

    /// Writes packets emitted by the engine back to the provider.
    private func writePackets(_ packets: [Data], protocols: [NSNumber]) {
        guard !packets.isEmpty else { return }
        guard isRunning else { return }

        var totalBytes = 0
        if let batchTap = hooks.packetTapBatch {
            var contexts: [RelativeProtocol.Configuration.PacketContext] = []
            contexts.reserveCapacity(packets.count)
            forEachPacket(packets, protocols: protocols) { packet, proto in
                totalBytes += packet.count
                contexts.append(.init(direction: .outbound, payload: packet, protocolNumber: proto))
            }
            if !contexts.isEmpty { batchTap(contexts) }
        } else if let packetTap = hooks.packetTap {
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
        if debugLoggingEnabled {
            // Log a concise batch summary with a sample packet header to verify
            // packets are being emitted out of the extension.
            let sample = packets.first.flatMap { summarizeIPPacket($0) } ?? "<no-sample>"
            logger.notice("Relative Protocol: Outbound batch packets=\(packets.count, privacy: .public) bytes=\(totalBytes, privacy: .public) sample=\(sample, privacy: .public)")
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
            logger.notice("Relative Protocol: Opening TCP connection to \(hostString, privacy: .public):\(port.rawValue, privacy: .public)")
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
            logger.notice("Relative Protocol: Opening UDP session to \(hostString, privacy: .public):\(port.rawValue, privacy: .public)")
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
    for index in 0..<count {
        let proto: Int32 = index < protocolCount ? protocols[index].int32Value : packets[index].afValue
        body(packets[index], proto)
    }
}

// MARK: - Packet summary logging

private func summarizeIPPacket(_ packet: Data) -> String {
    guard let first = packet.first else { return "empty" }
    let version = first >> 4
    if version == 4 {
        return summarizeIPv4(packet)
    } else if version == 6 {
        return summarizeIPv6(packet)
    } else {
        return "v\(version) len=\(packet.count)"
    }
}

private func summarizeIPv4(_ packet: Data) -> String {
    // Minimal IPv4 header is 20 bytes
    guard packet.count >= 20 else { return "ipv4(truncated len=\(packet.count))" }
    let ihl = Int(packet[0] & 0x0F) * 4
    guard ihl >= 20, packet.count >= ihl else { return "ipv4(bad ihl=\(ihl))" }
    let proto = packet[9]
    let src = formatIPv4(packet, start: 12)
    let dst = formatIPv4(packet, start: 16)
    var sport: UInt16? = nil
    var dport: UInt16? = nil
    if packet.count >= ihl + 4, (proto == 6 || proto == 17) { // TCP or UDP
        sport = readBE16(packet, offset: ihl)
        dport = readBE16(packet, offset: ihl + 2)
    }
    let l4 = (proto == 6 ? "tcp" : (proto == 17 ? "udp" : "p\(proto)"))
    if let sp = sport, let dp = dport {
        return "ipv4 \(l4) \(src):\(sp) -> \(dst):\(dp)"
    } else {
        return "ipv4 \(l4) \(src) -> \(dst)"
    }
}

private func summarizeIPv6(_ packet: Data) -> String {
    // IPv6 header is 40 bytes
    guard packet.count >= 40 else { return "ipv6(truncated len=\(packet.count))" }
    let nextHeader = packet[6]
    let src = formatIPv6(packet, start: 8)
    let dst = formatIPv6(packet, start: 24)
    var sport: UInt16? = nil
    var dport: UInt16? = nil
    // Simplification: assume no extension headers when extracting ports
    if packet.count >= 40 + 4, (nextHeader == 6 || nextHeader == 17) {
        sport = readBE16(packet, offset: 40)
        dport = readBE16(packet, offset: 42)
    }
    let l4 = (nextHeader == 6 ? "tcp" : (nextHeader == 17 ? "udp" : "nh\(nextHeader)"))
    if let sp = sport, let dp = dport {
        return "ipv6 \(l4) \(src):\(sp) -> \(dst):\(dp)"
    } else {
        return "ipv6 \(l4) \(src) -> \(dst)"
    }
}

private func readBE16(_ data: Data, offset: Int) -> UInt16? {
    guard offset + 1 < data.count else { return nil }
    return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
}

private func formatIPv4(_ data: Data, start: Int) -> String {
    guard start + 3 < data.count else { return "?.?.?.?" }
    return "\(data[start]).\(data[start+1]).\(data[start+2]).\(data[start+3])"
}

private func formatIPv6(_ data: Data, start: Int) -> String {
    guard start + 15 < data.count else { return "?" }
    // Format as 8 groups of 2 bytes in hex
    var parts: [String] = []
    parts.reserveCapacity(8)
    var idx = start
    for _ in 0..<8 {
        let hi = data[idx]
        let lo = data[idx + 1]
        parts.append(String(format: "%02x%02x", hi, lo))
        idx += 2
    }
    return parts.joined(separator: ":")
}
