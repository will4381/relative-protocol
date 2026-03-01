// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation
import Network
@preconcurrency import NetworkExtension
import RelativeProtocolCore

public struct StandaloneRuntimeOptions: Sendable, Codable {
    public var socksPort: UInt16
    public var mtu: Int
    public var engineLogLevel: String

    public init(
        socksPort: UInt16 = 1080,
        mtu: Int = 1400,
        engineLogLevel: String = "warn"
    ) {
        self.socksPort = socksPort
        self.mtu = mtu
        self.engineLogLevel = engineLogLevel
    }
}

public struct StandaloneRuntimeStatus: Sendable, Codable {
    public let running: Bool
    public let restarting: Bool
    public let socksPort: UInt16
    public let mtu: Int
    public let engineLogLevel: String
    public let restartCount: Int
    public let backpressured: Bool
    public let inboundPacketCount: UInt64
    public let inboundBytes: UInt64
    public let outboundPacketCount: UInt64
    public let outboundBytes: UInt64
    public let uptimeSeconds: Int
    public let lastError: String?
    public let timestamp: TimeInterval
}

public final class StandaloneTunnelRuntime {
    private let queue = DispatchQueue(label: "com.relative.protocol.standalone.runtime")
    private let ioQueue = DispatchQueue(label: "com.relative.protocol.standalone.runtime.io", qos: .userInitiated)
    private let queueKey = DispatchSpecificKey<Void>()

    private var options: StandaloneRuntimeOptions
    private var running = false
    private var restarting = false
    private var restartCount = 0
    private var startTime: Date?
    private var lastError: String?

    private var inboundPacketCount: UInt64 = 0
    private var inboundBytes: UInt64 = 0
    private var outboundPacketCount: UInt64 = 0
    private var outboundBytes: UInt64 = 0

    private var activeSocksPort: UInt16
    private var socksServer: Socks5Server?
    private var tunBridge: TunSocketBridge?
    private var engine: Tun2SocksEngine?
    private var provider: StandaloneConnectionProvider?

    public init(options: StandaloneRuntimeOptions = StandaloneRuntimeOptions()) {
        self.options = options
        self.activeSocksPort = options.socksPort
        queue.setSpecific(key: queueKey, value: ())
    }

    public func start(completion: @escaping (Error?) -> Void) {
        queue.async {
            guard !self.running else {
                completion(nil)
                return
            }
            self.startRelay(options: self.options, completion: completion)
        }
    }

    public func stop(completion: (() -> Void)? = nil) {
        queue.async {
            self.stopRelay()
            self.running = false
            self.restarting = false
            self.startTime = nil
            completion?()
        }
    }

    public func restart(completion: @escaping (Error?) -> Void) {
        queue.async {
            self.restarting = true
            self.stopRelay()
            self.startRelay(options: self.options) { error in
                self.queue.async {
                    self.restarting = false
                    if error == nil {
                        self.restartCount += 1
                    }
                    completion(error)
                }
            }
        }
    }

    public func reload(
        options: StandaloneRuntimeOptions?,
        completion: @escaping (Error?) -> Void
    ) {
        queue.async {
            if let options {
                self.options = options
            }
            self.restarting = true
            self.stopRelay()
            self.startRelay(options: self.options) { error in
                self.queue.async {
                    self.restarting = false
                    if error == nil {
                        self.restartCount += 1
                    }
                    completion(error)
                }
            }
        }
    }

    public func flushMetrics() {
        queue.async {
            self.inboundPacketCount = 0
            self.inboundBytes = 0
            self.outboundPacketCount = 0
            self.outboundBytes = 0
        }
    }

    public func injectPacket(_ packet: Data, ipVersionHint: Int32) -> Bool {
        let work = {
            guard let bridge = self.tunBridge else { return false }
            let success = bridge.writePacket(packet, ipVersionHint: ipVersionHint)
            if success {
                self.outboundPacketCount &+= 1
                self.outboundBytes &+= UInt64(packet.count)
            }
            return success
        }
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            return work()
        }
        return queue.sync(execute: work)
    }

    public func status() -> StandaloneRuntimeStatus {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            return statusLocked()
        }
        return queue.sync { statusLocked() }
    }

    private func statusLocked() -> StandaloneRuntimeStatus {
        let uptime: Int
        if let startTime {
            uptime = max(0, Int(Date().timeIntervalSince(startTime)))
        } else {
            uptime = 0
        }
        return StandaloneRuntimeStatus(
            running: running,
            restarting: restarting,
            socksPort: activeSocksPort,
            mtu: options.mtu,
            engineLogLevel: options.engineLogLevel,
            restartCount: restartCount,
            backpressured: tunBridge?.isBackpressured() ?? false,
            inboundPacketCount: inboundPacketCount,
            inboundBytes: inboundBytes,
            outboundPacketCount: outboundPacketCount,
            outboundBytes: outboundBytes,
            uptimeSeconds: uptime,
            lastError: lastError,
            timestamp: TunnelTime.nowEpochSeconds()
        )
    }

    private func startRelay(options: StandaloneRuntimeOptions, completion: @escaping (Error?) -> Void) {
        let provider = StandaloneConnectionProvider(queue: ioQueue)
        let server = Socks5Server(provider: provider, queue: ioQueue, mtu: options.mtu)
        self.provider = provider
        self.socksServer = server

        server.start(port: options.socksPort) { result in
            self.queue.async {
                switch result {
                case .success(let resolvedPort):
                    do {
                        let bridge = try TunSocketBridge(mtu: options.mtu, queue: self.ioQueue)
                        bridge.startReadLoop { packets, _ in
                            self.queue.async {
                                self.inboundPacketCount &+= UInt64(packets.count)
                                let batchBytes = packets.reduce(UInt64(0)) { $0 + UInt64($1.count) }
                                self.inboundBytes &+= batchBytes
                            }
                        }

                        let engine = Tun2SocksEngine()
                        let config = self.makeConfiguration(
                            socksPort: Int(resolvedPort),
                            mtu: options.mtu,
                            engineLogLevel: options.engineLogLevel
                        )
                        engine.start(configuration: config, tunFD: bridge.engineFD, socksPort: resolvedPort)

                        self.tunBridge = bridge
                        self.engine = engine
                        self.activeSocksPort = resolvedPort
                        self.running = true
                        self.lastError = nil
                        if self.startTime == nil {
                            self.startTime = Date()
                        }
                        completion(nil)
                    } catch {
                        self.lastError = error.localizedDescription
                        self.stopRelay()
                        completion(error)
                    }
                case .failure(let error):
                    self.lastError = error.localizedDescription
                    self.stopRelay()
                    completion(error)
                }
            }
        }
    }

    private func stopRelay() {
        engine?.stop()
        engine = nil
        tunBridge?.stop()
        tunBridge = nil
        socksServer?.stop()
        socksServer = nil
        provider = nil
    }

    private func makeConfiguration(socksPort: Int, mtu: Int, engineLogLevel: String) -> TunnelConfiguration {
        TunnelConfiguration(providerConfiguration: [
            "appGroupID": "standalone.vpn.harness",
            "relayMode": "tun2socks",
            "mtu": mtu,
            "dnsServers": [],
            "ipv6Enabled": true,
            "ipv4Address": "10.0.0.2",
            "ipv4SubnetMask": "255.255.255.0",
            "ipv4Router": "10.0.0.1",
            "ipv6Address": "fd00:1:1:1::2",
            "ipv6PrefixLength": 64,
            "tunnelRemoteAddress": "127.0.0.1",
            "engineSocksPort": socksPort,
            "engineLogLevel": engineLogLevel,
            "metricsEnabled": false,
            "packetStreamEnabled": false,
            "keepaliveIntervalSeconds": 0
        ])
    }
}

private final class StandaloneConnectionProvider: Socks5ConnectionProvider {
    private let queue: DispatchQueue

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound {
        _ = tlsParameters
        _ = delegate
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue) else {
            return FailedTCPOutbound(error: StandaloneRuntimeError.invalidEndpoint)
        }
        let parameters = enableTLS ? NWParameters.tls : NWParameters.tcp
        let host = NWEndpoint.Host(endpoint.hostname)
        let connection = NWConnection(host: host, port: port, using: parameters)
        return NWConnectionTCPAdapter(connection, queue: queue)
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue) else {
            return FailedUDPSession(error: StandaloneRuntimeError.invalidEndpoint)
        }
        let parameters = NWParameters.udp
        let host = NWEndpoint.Host(endpoint.hostname)
        let connection = NWConnection(host: host, port: port, using: parameters)
        return NWConnectionUDPSessionAdapter(connection, queue: queue)
    }
}

private final class FailedTCPOutbound: Socks5TCPOutbound {
    private let error: Error

    init(error: Error) {
        self.error = error
    }

    func readMinimumLength(
        _ minimumLength: Int,
        maximumLength: Int,
        completionHandler: @escaping (Data?, Error?) -> Void
    ) {
        _ = minimumLength
        _ = maximumLength
        completionHandler(nil, error)
    }

    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void) {
        _ = data
        completionHandler(error)
    }

    func cancel() {}
}

private final class FailedUDPSession: Socks5UDPSession {
    private let error: Error

    init(error: Error) {
        self.error = error
    }

    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int) {
        _ = maxDatagrams
        handler(nil, error)
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) {
        _ = datagram
        completionHandler(error)
    }

    func cancel() {}
}

private enum StandaloneRuntimeError: Error {
    case invalidEndpoint
}
