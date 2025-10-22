//
//  GoTun2SocksEngine.swift
//  PacketTunnel
//
//  Bridges the gomobile-generated Tun2Socks bindings into the adapter.
//

#if canImport(Tun2Socks)

import Darwin
import Foundation
import Network
import os.log
import Tun2Socks

final class GoTun2SocksEngine: Tun2SocksEngine, @unchecked Sendable {
    private let configuration: BridgeConfiguration
    private let logger: Logger
    private var callbacks: Tun2SocksCallbacks?
    private var goEngine: BridgeEngine?
    private var packetEmitter: PacketEmitterAdapter?
    private var networkAdapter: NetworkAdapter?
    private let stateQueue = DispatchQueue(label: "PacketTunnel.GoTun2SocksEngine")
    private var running = false

    init(configuration: BridgeConfiguration, logger: Logger) {
        self.configuration = configuration
        self.logger = logger
    }

    func start(callbacks: Tun2SocksCallbacks) throws {
        try stateQueue.sync {
            guard !running else { return }

            let config = BridgeConfig()
            config.mtu = configuration.mtu

            let emitter = PacketEmitterAdapter(callbacks: callbacks)
            let network = NetworkAdapter(
                callbacks: callbacks,
                logger: logger,
                mtu: configuration.mtu
            )

            var creationError: NSError?
            guard let engine = BridgeNewEngine(config, emitter, network, &creationError) else {
                throw creationError ?? NSError(
                    domain: "GoTun2SocksEngine",
                    code: -4,
                    userInfo: [NSLocalizedDescriptionKey: "BridgeNewEngine returned nil without error"]
                )
            }
            network.bind(engine: engine)

            try engine.start()

            goEngine = engine
            packetEmitter = emitter
            networkAdapter = network
            self.callbacks = callbacks
            running = true

            callbacks.startPacketReadLoop { [weak self] packets, protocols in
                guard
                    let self,
                    let engine = self.goEngine
                else { return }

                for (index, packet) in packets.enumerated() {
                    let proto = protocols[safe: index]?.uint32Value ?? packet.afValue
                    let intProto = Int32(truncatingIfNeeded: proto)
                    do {
                        try engine.handlePacket(packet, protocolNumber: intProto)
                    } catch {
                        self.logger.error("handlePacket failed: \(error.localizedDescription, privacy: .public)")
                    }
                }
            }
        }
    }

    func stop() {
        stateQueue.sync {
            guard running else { return }
            networkAdapter?.shutdown()
            goEngine?.stop()

            callbacks = nil
            goEngine = nil
            packetEmitter = nil
            networkAdapter = nil
            running = false
        }
    }
}

// MARK: - Packet emission

private final class PacketEmitterAdapter: NSObject, BridgePacketEmitterProtocol {
    private let callbacks: Tun2SocksCallbacks

    init(callbacks: Tun2SocksCallbacks) {
        self.callbacks = callbacks
    }

    func emitPacket(_ packet: Data?, protocolNumber: Int32) throws {
        guard let packet else {
            throw NSError(domain: "GoTun2SocksEngine", code: -3, userInfo: [NSLocalizedDescriptionKey: "packet is nil"])
        }
        callbacks.emitPackets([packet], [NSNumber(value: protocolNumber)])
    }
}

// MARK: - Network plumbing

private final class NetworkAdapter: NSObject, BridgeNetworkProtocol {
    private let callbacks: Tun2SocksCallbacks
    private let logger: Logger
    private let mtu: Int
    private let lock = DispatchQueue(label: "PacketTunnel.NetworkAdapter.lock")
    private var nextHandle: Int64 = 1
    private var tcpConnections: [Int64: ManagedTCPConnection] = [:]
    private var udpConnections: [Int64: ManagedUDPConnection] = [:]
    private weak var engine: BridgeEngine?

    init(callbacks: Tun2SocksCallbacks, logger: Logger, mtu: Int) {
        self.callbacks = callbacks
        self.logger = logger
        self.mtu = mtu
    }

    func bind(engine: BridgeEngine) {
        lock.sync {
            self.engine = engine
        }
    }

    func shutdown() {
        let (tcp, udp): ([ManagedTCPConnection], [ManagedUDPConnection]) = lock.sync {
            let tcpArray = Array(tcpConnections.values)
            let udpArray = Array(udpConnections.values)
            tcpConnections.removeAll()
            udpConnections.removeAll()
            return (tcpArray, udpArray)
        }
        tcp.forEach { $0.cancel() }
        udp.forEach { $0.cancel() }
    }

    func tcpDial(
        _ host: String?,
        port: Int32,
        timeoutMillis: Int64,
        ret0_: UnsafeMutablePointer<Int64>?
    ) throws {
        guard let host else {
            throw NSError(domain: "GoTun2SocksEngine", code: -1, userInfo: [NSLocalizedDescriptionKey: "host is nil"])
        }
        guard let nwPort = Network.NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
            throw NSError(domain: "GoTun2SocksEngine", code: -2, userInfo: [NSLocalizedDescriptionKey: "invalid port \(port)"])
        }

        let endpoint = Network.NWEndpoint.hostPort(host: Network.NWEndpoint.Host(host), port: nwPort)
        let connection = callbacks.makeTCPConnection(endpoint)
        let handle = nextIdentifier()

        let managed = ManagedTCPConnection(
            handle: handle,
            connection: connection,
            engineProvider: { [weak self] in self?.engine },
            logger: logger,
            mtu: mtu,
            timeoutMillis: timeoutMillis,
            onClosed: { [weak self] identifier in
                _ = self?.removeTCP(handle: identifier)
            }
        )
        managed.activate()
        try managed.waitUntilReady(timeoutMillis: timeoutMillis)

        lock.sync {
            tcpConnections[handle] = managed
        }

        ret0_?.pointee = handle
    }

    func tcpWrite(
        _ handle: Int64,
        payload: Data?,
        ret0_: UnsafeMutablePointer<Int32>?
    ) throws {
        guard let payload else {
            ret0_?.pointee = 0
            return
        }
        guard let connection = tcpConnection(for: handle) else {
            throw NSError(domain: "GoTun2SocksEngine", code: -3, userInfo: [NSLocalizedDescriptionKey: "missing tcp handle \(handle)"])
        }
        let written = try connection.write(data: payload)
        ret0_?.pointee = Int32(written)
    }

    func tcpClose(_ handle: Int64) throws {
        guard let connection = removeTCP(handle: handle) else { return }
        connection.cancel()
    }

    func udpDial(
        _ host: String?,
        port: Int32,
        ret0_: UnsafeMutablePointer<Int64>?
    ) throws {
        guard let host else {
            throw NSError(domain: "GoTun2SocksEngine", code: -4, userInfo: [NSLocalizedDescriptionKey: "host is nil"])
        }
        guard let nwPort = Network.NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
            throw NSError(domain: "GoTun2SocksEngine", code: -5, userInfo: [NSLocalizedDescriptionKey: "invalid port \(port)"])
        }

        let endpoint = Network.NWEndpoint.hostPort(host: Network.NWEndpoint.Host(host), port: nwPort)
        let connection = callbacks.makeUDPConnection(endpoint)
        let handle = nextIdentifier()

        let managed = ManagedUDPConnection(
            handle: handle,
            connection: connection,
            engineProvider: { [weak self] in self?.engine },
            logger: logger,
            onClosed: { [weak self] identifier in
                _ = self?.removeUDP(handle: identifier)
            }
        )
        managed.activate()

        lock.sync {
            udpConnections[handle] = managed
        }
        ret0_?.pointee = handle
    }

    func udpWrite(
        _ handle: Int64,
        payload: Data?,
        ret0_: UnsafeMutablePointer<Int32>?
    ) throws {
        guard let payload else {
            ret0_?.pointee = 0
            return
        }
        guard let connection = udpConnection(for: handle) else {
            throw NSError(domain: "GoTun2SocksEngine", code: -6, userInfo: [NSLocalizedDescriptionKey: "missing udp handle \(handle)"])
        }
        let written = try connection.write(data: payload)
        ret0_?.pointee = Int32(written)
    }

    func udpClose(_ handle: Int64) throws {
        guard let connection = removeUDP(handle: handle) else { return }
        connection.cancel()
    }

    private func tcpConnection(for handle: Int64) -> ManagedTCPConnection? {
        lock.sync {
            tcpConnections[handle]
        }
    }

    private func udpConnection(for handle: Int64) -> ManagedUDPConnection? {
        lock.sync {
            udpConnections[handle]
        }
    }

    private func removeTCP(handle: Int64) -> ManagedTCPConnection? {
        lock.sync {
            tcpConnections.removeValue(forKey: handle)
        }
    }

    private func removeUDP(handle: Int64) -> ManagedUDPConnection? {
        lock.sync {
            udpConnections.removeValue(forKey: handle)
        }
    }

    private func nextIdentifier() -> Int64 {
        lock.sync {
            let identifier = nextHandle
            nextHandle &+= 1
            return identifier
        }
    }
}

// MARK: - TCP Connection Management

private final class ManagedTCPConnection: @unchecked Sendable {
    private let handle: Int64
    private let connection: Network.NWConnection
    private let engineProvider: () -> BridgeEngine?
    private let logger: Logger
    private let mtu: Int
    private let timeoutMillis: Int64
    private let queue: DispatchQueue
    private var closed = false
    private let closeLock = DispatchQueue(label: "PacketTunnel.ManagedTCPConnection.closeLock")
    private let stateLock = DispatchQueue(label: "PacketTunnel.ManagedTCPConnection.stateLock")
    private let readySemaphore = DispatchSemaphore(value: 0)
    private var readyResult: Result<Void, Error>?
    private let onClosed: (Int64) -> Void

    init(
        handle: Int64,
        connection: Network.NWConnection,
        engineProvider: @escaping () -> BridgeEngine?,
        logger: Logger,
        mtu: Int,
        timeoutMillis: Int64,
        onClosed: @escaping (Int64) -> Void
    ) {
        self.handle = handle
        self.connection = connection
        self.engineProvider = engineProvider
        self.logger = logger
        self.mtu = mtu
        self.timeoutMillis = timeoutMillis
        self.queue = DispatchQueue(label: "PacketTunnel.ManagedTCPConnection.\(handle)")
        self.onClosed = onClosed
    }

    func activate() {
        connection.stateUpdateHandler = { [weak self] state in
            self?.handleStateUpdate(state)
        }
        connection.start(queue: queue)
    }

    func waitUntilReady(timeoutMillis: Int64) throws {
        let timeout: DispatchTime
        if timeoutMillis > 0 {
            timeout = .now() + .milliseconds(Int(timeoutMillis))
        } else {
            timeout = .distantFuture
        }

        if readySemaphore.wait(timeout: timeout) == .timedOut {
            cancel()
            throw NSError(domain: "GoTun2SocksEngine", code: -8, userInfo: [NSLocalizedDescriptionKey: "tcp dial timeout"])
        }

        let result = stateLock.sync { readyResult }
        switch result {
        case .success:
            return
        case .failure(let error):
            throw error
        case .none:
            return
        }
    }

    func write(data: Data) throws -> Int {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Int, Error> = .success(data.count)
        connection.send(content: data, completion: .contentProcessed { error in
            if let error {
                result = .failure(error)
            }
            semaphore.signal()
        })

        if timeoutMillis > 0 {
            let timeout = DispatchTime.now() + .milliseconds(Int(timeoutMillis))
            if semaphore.wait(timeout: timeout) == .timedOut {
                cancel()
                throw NSError(domain: "GoTun2SocksEngine", code: -7, userInfo: [NSLocalizedDescriptionKey: "tcp write timeout"])
            }
        } else {
            semaphore.wait()
        }

        switch result {
        case .success(let count):
            return count
        case .failure(let error):
            throw error
        }
    }

    func cancel() {
        closeLock.sync {
            guard !closed else { return }
            closed = true
            connection.cancel()
        }
    }

    private func handleStateUpdate(_ state: Network.NWConnection.State) {
        switch state {
        case .ready:
            signalReady(result: .success(()))
            scheduleReceive()
        case .failed(let error):
            self.logger.error("tcp \(self.handle) failed: \(error.localizedDescription, privacy: .public)")
            signalReady(result: .failure(error))
            notifyClose(reason: error)
        case .cancelled:
            signalReady(result: .failure(NSError(domain: "GoTun2SocksEngine", code: -9, userInfo: [NSLocalizedDescriptionKey: "connection cancelled"])))
            notifyClose(reason: nil)
        case .waiting(let error):
            self.logger.debug("tcp \(self.handle) waiting: \(error.localizedDescription, privacy: .public)")
        default:
            break
        }
    }

    private func signalReady(result: Result<Void, Error>) {
        let shouldSignal: Bool = stateLock.sync {
            guard readyResult == nil else { return false }
            readyResult = result
            return true
        }
        if shouldSignal {
            readySemaphore.signal()
        }
    }

    private func scheduleReceive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: mtu) { [weak self] data, _, isComplete, error in
            guard let self else { return }

            if let data, !data.isEmpty {
                self.engineProvider()?.tcpDidReceive(self.handle, payload: data)
            }

            if let error {
                self.notifyClose(reason: error)
                return
            }

            if isComplete {
                self.notifyClose(reason: nil)
                return
            }

            self.scheduleReceive()
        }
    }

    private func notifyClose(reason: Error?) {
        closeLock.sync {
            guard !closed else { return }
            closed = true
            connection.cancel()
        }
        onClosed(handle)
        do {
            engineProvider()?.tcpDidClose(handle, message: reason?.localizedDescription ?? "")
        }
    }
}

// MARK: - UDP Connection Management

private final class ManagedUDPConnection: @unchecked Sendable {
    private let handle: Int64
    private let connection: Network.NWConnection
    private let engineProvider: () -> BridgeEngine?
    private let logger: Logger
    private let queue = DispatchQueue(label: "PacketTunnel.ManagedUDPConnection")
    private let closeLock = DispatchQueue(label: "PacketTunnel.ManagedUDPConnection.closeLock")
    private var closed = false
    private let onClosed: (Int64) -> Void

    init(
        handle: Int64,
        connection: Network.NWConnection,
        engineProvider: @escaping () -> BridgeEngine?,
        logger: Logger,
        onClosed: @escaping (Int64) -> Void
    ) {
        self.handle = handle
        self.connection = connection
        self.engineProvider = engineProvider
        self.logger = logger
        self.onClosed = onClosed
    }

    func activate() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed(let error):
                self.logger.error("udp \(self.handle) failed: \(error.localizedDescription, privacy: .public)")
                self.notifyClose()
            case .cancelled:
                self.notifyClose()
            default:
                break
            }
        }
        connection.start(queue: queue)
        scheduleReceive()
    }

    func write(data: Data) throws -> Int {
        let semaphore = DispatchSemaphore(value: 0)
        var writeError: Error?
        connection.send(content: data, contentContext: .defaultMessage, isComplete: true, completion: .contentProcessed { error in
            writeError = error
            semaphore.signal()
        })
        semaphore.wait()
        if let writeError {
            throw writeError
        }
        return data.count
    }

    func cancel() {
        closeLock.sync {
            guard !closed else { return }
            closed = true
            connection.cancel()
        }
    }

    private func scheduleReceive() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }

            if let data, !data.isEmpty {
                self.engineProvider()?.udpDidReceive(self.handle, payload: data)
            }

            if let error {
                self.logger.error("udp \(self.handle) read error: \(error.localizedDescription, privacy: .public)")
                self.notifyClose()
                return
            }

            if data == nil {
                self.notifyClose()
                return
            }

            self.scheduleReceive()
        }
    }

    private func notifyClose() {
        cancel()
        onClosed(handle)
        do {
            engineProvider()?.udpDidClose(handle, message: "")
        }
    }
}

// MARK: - Helpers

private extension Array {
    subscript(safe index: Int) -> Element? {
        guard indices.contains(index) else { return nil }
        return self[index]
    }
}

private extension Data {
    var afValue: UInt32 {
        guard let firstByte = first else { return UInt32(AF_INET) }
        return (firstByte >> 4) == 6 ? UInt32(AF_INET6) : UInt32(AF_INET)
    }
}

#endif
