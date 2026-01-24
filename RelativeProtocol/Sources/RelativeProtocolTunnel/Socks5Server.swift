// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation
import Network
@preconcurrency import NetworkExtension
import RelativeProtocolCore

private func interfaceTypeName(_ type: Network.NWInterface.InterfaceType) -> String {
    switch type {
    case .cellular:
        return "cellular"
    case .wifi:
        return "wifi"
    case .wiredEthernet:
        return "wired"
    case .loopback:
        return "loopback"
    case .other:
        return "other"
    @unknown default:
        return "unknown"
    }
}

private func pathStatusName(_ status: Network.NWPath.Status) -> String {
    switch status {
    case .satisfied:
        return "satisfied"
    case .unsatisfied:
        return "unsatisfied"
    case .requiresConnection:
        return "requires-connection"
    @unknown default:
        return "unknown"
    }
}

private func pathSummary(_ path: Network.NWPath?) -> String {
    guard let path else {
        return "status=unknown uses=unknown"
    }
    var uses: [String] = []
    if path.usesInterfaceType(.cellular) { uses.append("cellular") }
    if path.usesInterfaceType(.wifi) { uses.append("wifi") }
    if path.usesInterfaceType(.wiredEthernet) { uses.append("wired") }
    if path.usesInterfaceType(.loopback) { uses.append("loopback") }
    if uses.isEmpty { uses.append("other") }
    let available = path.availableInterfaces.map { "\(interfaceTypeName($0.type)):\($0.name)" }.joined(separator: ",")
    return "status=\(pathStatusName(path.status)) uses=\(uses.joined(separator: ",")) available=\(available) expensive=\(path.isExpensive) constrained=\(path.isConstrained) ipv4=\(path.supportsIPv4) ipv6=\(path.supportsIPv6)"
}

protocol Socks5InboundConnection: AnyObject {
    var stateUpdateHandler: ((NWConnection.State) -> Void)? { get set }
    func start(queue: DispatchQueue)
    func receive(minimumIncompleteLength: Int, maximumLength: Int, completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    func send(content: Data?, completion: NWConnection.SendCompletion)
    func cancel()
}

final class NWConnectionAdapter: Socks5InboundConnection {
    private let connection: NWConnection

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    var stateUpdateHandler: ((NWConnection.State) -> Void)? {
        get { connection.stateUpdateHandler }
        set { connection.stateUpdateHandler = newValue }
    }

    func start(queue: DispatchQueue) {
        connection.start(queue: queue)
    }

    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        connection.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength, completion: completion)
    }

    func send(content: Data?, completion: NWConnection.SendCompletion) {
        connection.send(content: content, completion: completion)
    }

    func cancel() {
        connection.cancel()
    }
}

protocol Socks5TCPOutbound: AnyObject {
    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void)
    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void)
    func cancel()
}

final class NWConnectionTCPAdapter: Socks5TCPOutbound {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let logger = RelativeLog.logger(.tunnel)
    private var didLogReady = false
    private var didLogWaiting = false
    private var didLogFailed = false

    init(_ connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
        self.connection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state)
        }
        self.connection.start(queue: queue)
    }

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: minimumLength, maximumLength: maximumLength) { data, _, isComplete, error in
            if isComplete && (data == nil || data?.isEmpty == true) {
                completionHandler(nil, error)
                return
            }
            completionHandler(data, error)
        }
    }

    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed { error in
            completionHandler(error)
        })
    }

    func cancel() {
        connection.cancel()
    }

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            if !didLogReady {
                didLogReady = true
                if RelativeLog.isVerbose {
                    logger.info("Outbound TCP ready. \(pathSummary(self.connection.currentPath), privacy: .public)")
                }
            }
        case .waiting(let error):
            if !didLogWaiting {
                didLogWaiting = true
                logger.warning("Outbound TCP waiting: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
        case .failed(let error):
            if !didLogFailed {
                didLogFailed = true
                logger.error("Outbound TCP failed: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
        default:
            break
        }
    }
}

final class NWTCPConnectionAdapter: Socks5TCPOutbound {
    private let connection: NWTCPConnection

    init(_ connection: NWTCPConnection) {
        self.connection = connection
    }

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void) {
        connection.readMinimumLength(minimumLength, maximumLength: maximumLength, completionHandler: completionHandler)
    }

    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void) {
        connection.write(data, completionHandler: completionHandler)
    }

    func cancel() {
        connection.cancel()
    }
}

protocol Socks5UDPSession: AnyObject {
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int)
    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void)
    func cancel()
}

final class NWConnectionUDPSessionAdapter: Socks5UDPSession {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private var readHandler: (([Data]?, Error?) -> Void)?
    private var isCancelled = false
    private let logger = RelativeLog.logger(.tunnel)
    private var didLogReady = false
    private var didLogWaiting = false
    private var didLogFailed = false

    init(_ connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
        self.connection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state)
        }
        self.connection.start(queue: queue)
    }

    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int) {
        readHandler = handler
        receiveNext()
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) {
        connection.send(content: datagram, completion: .contentProcessed { error in
            completionHandler(error)
        })
    }

    func cancel() {
        isCancelled = true
        connection.cancel()
    }

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            if !didLogReady {
                didLogReady = true
                if RelativeLog.isVerbose {
                    logger.info("Outbound UDP ready. \(pathSummary(self.connection.currentPath), privacy: .public)")
                }
            }
        case .waiting(let error):
            if !didLogWaiting {
                didLogWaiting = true
                logger.warning("Outbound UDP waiting: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
        case .failed(let error):
            if !didLogFailed {
                didLogFailed = true
                logger.error("Outbound UDP failed: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
        default:
            break
        }
    }

    private func receiveNext() {
        guard !isCancelled else { return }
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.readHandler?(nil, error)
                return
            }
            if let data {
                self.readHandler?([data], nil)
            }
            self.receiveNext()
        }
    }
}

final class NWUDPSessionAdapter: Socks5UDPSession {
    private let session: NWUDPSession

    init(_ session: NWUDPSession) {
        self.session = session
    }

    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int) {
        session.setReadHandler(handler, maxDatagrams: maxDatagrams)
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) {
        session.writeDatagram(datagram, completionHandler: completionHandler)
    }

    func cancel() {
        session.cancel()
    }
}

protocol Socks5ConnectionProvider: AnyObject {
    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound
    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession
}

final class PacketTunnelProviderAdapter: Socks5ConnectionProvider {
    private let provider: NEPacketTunnelProvider
    private let queue: DispatchQueue
    private let logger = RelativeLog.logger(.tunnel)

    init(provider: NEPacketTunnelProvider, queue: DispatchQueue) {
        self.provider = provider
        self.queue = queue
    }

    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound {
        if let outbound = makeNWConnection(to: endpoint, enableTLS: enableTLS) {
            if RelativeLog.isVerbose {
                logger.debug("Outbound TCP using NWConnection to \(endpoint.hostname, privacy: .public):\(endpoint.port, privacy: .public)")
            }
            return outbound
        }

        if RelativeLog.isVerbose {
            logger.debug("Outbound TCP using createTCPConnectionThroughTunnel to \(endpoint.hostname, privacy: .public):\(endpoint.port, privacy: .public)")
        }
        let connection = provider.createTCPConnectionThroughTunnel(
            to: endpoint,
            enableTLS: enableTLS,
            tlsParameters: tlsParameters,
            delegate: delegate
        )
        return NWTCPConnectionAdapter(connection)
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        if let outbound = makeNWUDPSession(to: endpoint) {
            if RelativeLog.isVerbose {
                logger.debug("Outbound UDP using NWConnection to \(endpoint.hostname, privacy: .public):\(endpoint.port, privacy: .public)")
            }
            return outbound
        }

        if RelativeLog.isVerbose {
            logger.debug("Outbound UDP using createUDPSessionThroughTunnel to \(endpoint.hostname, privacy: .public):\(endpoint.port, privacy: .public)")
        }
        let session = provider.createUDPSessionThroughTunnel(to: endpoint, from: nil)
        return NWUDPSessionAdapter(session)
    }

    private func makeNWConnection(to endpoint: NWHostEndpoint, enableTLS: Bool) -> Socks5TCPOutbound? {
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue) else {
            return nil
        }

        let parameters = enableTLS ? NWParameters.tls : NWParameters.tcp
        if #available(iOS 18.0, macOS 15.0, *) {
            if let virtualInterface = provider.virtualInterface {
                parameters.prohibitedInterfaces = [virtualInterface]
                if RelativeLog.isVerbose {
                    logger.debug("Outbound TCP prohibiting interface \(virtualInterface.name, privacy: .public)")
                }
            }
        }

        let host = NWEndpoint.Host(endpoint.hostname)
        let connection = NWConnection(host: host, port: port, using: parameters)
        return NWConnectionTCPAdapter(connection, queue: queue)
    }

    private func makeNWUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession? {
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue) else {
            return nil
        }

        let parameters = NWParameters.udp
        if #available(iOS 18.0, macOS 15.0, *) {
            if let virtualInterface = provider.virtualInterface {
                parameters.prohibitedInterfaces = [virtualInterface]
                if RelativeLog.isVerbose {
                    logger.debug("Outbound UDP prohibiting interface \(virtualInterface.name, privacy: .public)")
                }
            }
        }

        let host = NWEndpoint.Host(endpoint.hostname)
        let connection = NWConnection(host: host, port: port, using: parameters)
        return NWConnectionUDPSessionAdapter(connection, queue: queue)
    }
}

final class Socks5Server {
    private let logger = RelativeLog.logger(.tunnel)
    private let provider: Socks5ConnectionProvider
    private let queue: DispatchQueue
    private let mtu: Int
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: Socks5Connection] = [:]

    init(provider: Socks5ConnectionProvider, queue: DispatchQueue, mtu: Int) {
        self.provider = provider
        self.queue = queue
        self.mtu = mtu
    }

    convenience init(provider: NEPacketTunnelProvider, queue: DispatchQueue, mtu: Int) {
        self.init(provider: PacketTunnelProviderAdapter(provider: provider, queue: queue), queue: queue, mtu: mtu)
    }

    func start(port: UInt16, completion: @escaping (Result<UInt16, Error>) -> Void) {
        let initialPort = port == 0 ? pickEphemeralPort() : port
        startListener(port: initialPort, remainingAttempts: 3, completion: completion)
    }

    private func startListener(port: UInt16, remainingAttempts: Int, completion: @escaping (Result<UInt16, Error>) -> Void) {
        guard let listenPort = NWEndpoint.Port(rawValue: port) else {
            completion(.failure(Socks5ServerError.invalidPort))
            return
        }

        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        if let loopback = IPv4Address("127.0.0.1") {
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(loopback), port: listenPort)
        }

        let listener: NWListener
        do {
            listener = try NWListener(using: parameters, on: .any)
        } catch {
            completion(.failure(error))
            return
        }

        self.listener = listener

            var didComplete = false
            var didProbe = false
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .setup:
                    if RelativeLog.isVerbose {
                        self.logger.debug("SOCKS5 listener state: setup")
                        NSLog("Socks5Server: listener state setup")
                    }
                case .waiting(let error):
                    self.logger.error("SOCKS5 listener waiting: \(error.localizedDescription, privacy: .public)")
                    if RelativeLog.isVerbose {
                        NSLog("Socks5Server: listener waiting: \(error.localizedDescription)")
                    }
                case .ready:
                    if !didComplete {
                        didComplete = true
                        let actualPort = listener.port?.rawValue ?? port
                        completion(.success(actualPort))
                    }
                    let actualPort = listener.port?.rawValue ?? port
                    if RelativeLog.isVerbose {
                        self.logger.info("SOCKS5 server listening on \(actualPort, privacy: .public)")
                        NSLog("Socks5Server: listener ready on port \(actualPort)")
                    }
                    if !didProbe {
                        didProbe = true
                        self.probeLoopback(port: actualPort)
                    }
                case .failed(let error):
                    if self.isAddressInUse(error), remainingAttempts > 0 {
                        didComplete = true
                        let nextPort = self.pickEphemeralPort()
                        self.logger.error("SOCKS5 listener failed on port \(port, privacy: .public); retrying on port \(nextPort, privacy: .public)")
                        if RelativeLog.isVerbose {
                            NSLog("Socks5Server: listener failed on port \(port); retrying on port \(nextPort)")
                        }
                        listener.cancel()
                        self.listener = nil
                        self.startListener(port: nextPort, remainingAttempts: remainingAttempts - 1, completion: completion)
                        return
                    }
                    if !didComplete {
                        didComplete = true
                        completion(.failure(error))
                    }
                    self.logger.error("SOCKS5 listener failed: \(error.localizedDescription, privacy: .public)")
                    if RelativeLog.isVerbose {
                        NSLog("Socks5Server: listener failed: \(error.localizedDescription)")
                    }
                case .cancelled:
                    if RelativeLog.isVerbose {
                        self.logger.debug("SOCKS5 listener cancelled")
                        NSLog("Socks5Server: listener cancelled")
                    }
                default:
                    break
                }
            }

            listener.newConnectionHandler = { [weak self] connection in
                guard let self else { return }
                if RelativeLog.isVerbose {
                    NSLog("Socks5Server: accepted connection \(String(describing: connection.endpoint))")
                }
                let session = Socks5Connection(
                    connection: NWConnectionAdapter(connection),
                    provider: self.provider,
                    queue: self.queue,
                    mtu: self.mtu
                )
                session.onClose = { [weak self] in
                    guard let self else { return }
                    self.connections.removeValue(forKey: ObjectIdentifier(connection))
                }
                self.connections[ObjectIdentifier(connection)] = session
                session.start()
            }

            listener.start(queue: queue)
    }

    private func pickEphemeralPort() -> UInt16 {
        UInt16.random(in: 49152...65535)
    }

    private func isAddressInUse(_ error: NWError) -> Bool {
        switch error {
        case .posix(let code):
            return code == .EADDRINUSE
        default:
            return false
        }
    }

    private func probeLoopback(port: UInt16) {
        guard let endpointPort = Network.NWEndpoint.Port(rawValue: port) else { return }

        let probes: [(Network.NWEndpoint.Host, String)] = [
            (.ipv4(IPv4Address("127.0.0.1")!), "127.0.0.1"),
            (.ipv6(IPv6Address("::1")!), "::1")
        ]

        for (host, label) in probes {
            let parameters = NWParameters.tcp
            parameters.requiredInterfaceType = .loopback

            let connection = NWConnection(host: host, port: endpointPort, using: parameters)
            var finished = false
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if !finished {
                        finished = true
                        if RelativeLog.isVerbose {
                            NSLog("Socks5Server: loopback probe to \(label):\(port) succeeded")
                        }
                        connection.cancel()
                    }
                case .failed(let error):
                    if !finished {
                        finished = true
                        if RelativeLog.isVerbose {
                            NSLog("Socks5Server: loopback probe to \(label):\(port) failed: \(error.localizedDescription)")
                        }
                        connection.cancel()
                    }
                default:
                    break
                }
            }
            connection.start(queue: queue)

            queue.asyncAfter(deadline: .now() + 1.0) {
                if !finished {
                    finished = true
                    if RelativeLog.isVerbose {
                        NSLog("Socks5Server: loopback probe to \(label):\(port) timed out")
                    }
                    connection.cancel()
                }
            }
        }
    }


    func stop() {
        listener?.cancel()
        listener = nil
        connections.values.forEach { $0.stop() }
        connections.removeAll()
    }
}

enum Socks5ServerError: Error {
    case invalidPort
}

final class Socks5Connection {
    private enum State {
        case greeting
        case request
        case tcpProxy(Socks5TCPOutbound)
        case udpProxy(Socks5UDPRelayProtocol)
    }

    private let logger = RelativeLog.logger(.tunnel)
    private let connection: Socks5InboundConnection
    private let provider: Socks5ConnectionProvider
    private let queue: DispatchQueue
    private let mtu: Int
    private let udpRelayFactory: (Socks5ConnectionProvider, DispatchQueue, Int) throws -> Socks5UDPRelayProtocol
    private var buffer = Data()
    private var state: State = .greeting
    private var isClosed = false

    var onClose: (() -> Void)?

    init(
        connection: Socks5InboundConnection,
        provider: Socks5ConnectionProvider,
        queue: DispatchQueue,
        mtu: Int,
        udpRelayFactory: @escaping (Socks5ConnectionProvider, DispatchQueue, Int) throws -> Socks5UDPRelayProtocol = {
            try Socks5UDPRelay(provider: $0, queue: $1, mtu: $2)
        }
    ) {
        self.connection = connection
        self.provider = provider
        self.queue = queue
        self.mtu = mtu
        self.udpRelayFactory = udpRelayFactory
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed(let error):
                self.logger.error("SOCKS5 connection failed: \(error.localizedDescription, privacy: .public)")
                self.stop()
            case .cancelled:
                self.stop()
            default:
                break
            }
        }
        connection.start(queue: queue)
        receive()
    }

    func stop() {
        guard !isClosed else { return }
        isClosed = true
        switch state {
        case .tcpProxy(let outbound):
            outbound.cancel()
        case .udpProxy(let relay):
            relay.stop()
        default:
            break
        }
        connection.cancel()
        onClose?()
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.buffer.append(data)
                self.processBuffer()
            }
            if isComplete || error != nil {
                self.stop()
                return
            }
            self.receive()
        }
    }

    private func processBuffer() {
        switch state {
        case .greeting:
            guard let methods = Socks5Codec.parseGreeting(&buffer) else { return }
            let method: UInt8 = methods.contains(0x00) ? 0x00 : 0xFF
            if RelativeLog.isVerbose {
                logger.debug("SOCKS5 greeting methods: \(methods, privacy: .public) -> \(method, privacy: .public)")
                NSLog("Socks5Connection: greeting methods=\(methods) selected=\(method)")
            }
            connection.send(content: Socks5Codec.buildMethodSelection(method: method), completion: .contentProcessed { _ in })
            if method == 0x00 {
                state = .request
                processBuffer()
            } else {
                stop()
            }
        case .request:
            guard let request = Socks5Codec.parseRequest(&buffer) else { return }
            if RelativeLog.isVerbose {
                logger.debug("SOCKS5 request \(String(describing: request.command), privacy: .public) \(String(describing: request.address), privacy: .public):\(request.port, privacy: .public)")
                NSLog("Socks5Connection: request cmd=\(request.command) addr=\(request.address) port=\(request.port)")
            }
            handleRequest(request)
        case .tcpProxy(let outbound):
            if !buffer.isEmpty {
                forwardToOutbound(buffer, outbound: outbound)
                buffer.removeAll()
            }
        case .udpProxy:
            buffer.removeAll()
        }
    }

    private func handleRequest(_ request: Socks5Request) {
        switch request.command {
        case .connect:
            startTCPProxy(request)
        case .udpAssociate:
            startUDPRelay()
        case .bind:
            sendFailure()
        }
    }

    private func startTCPProxy(_ request: Socks5Request) {
        let host: String
        switch request.address {
        case .ipv4(let value), .ipv6(let value), .domain(let value):
            host = value
        }
        let endpoint = NWHostEndpoint(hostname: host, port: String(request.port))
        if RelativeLog.isVerbose {
            NSLog("Socks5Connection: opening outbound to \(host):\(request.port)")
        }
        let outbound = provider.makeTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)

        state = .tcpProxy(outbound)
        connection.send(content: Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("0.0.0.0"), bindPort: 0), completion: .contentProcessed { _ in })
        readOutbound(outbound)
        processBuffer()
    }

    private func readOutbound(_ outbound: Socks5TCPOutbound) {
        outbound.readMinimumLength(1, maximumLength: 65535) { [weak self] data, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.connection.send(content: data, completion: .contentProcessed { _ in })
            } else if data == nil {
                self.stop()
                return
            }
            if error != nil {
                self.stop()
                return
            }
            self.readOutbound(outbound)
        }
    }

    private func forwardToOutbound(_ data: Data, outbound: Socks5TCPOutbound) {
        outbound.write(data) { [weak self] error in
            if let error {
                self?.logger.error("SOCKS5 outbound write failed: \(error.localizedDescription, privacy: .public)")
                self?.stop()
            }
        }
    }

    private func startUDPRelay() {
        do {
            let relay = try udpRelayFactory(provider, queue, mtu)
            relay.start()
            state = .udpProxy(relay)
            connection.send(
                content: Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("127.0.0.1"), bindPort: relay.port),
                completion: .contentProcessed { _ in }
            )
        } catch {
            logger.error("SOCKS5 UDP relay failed: \(error.localizedDescription, privacy: .public)")
            sendFailure()
        }
    }

    private func sendFailure() {
        connection.send(content: Socks5Codec.buildReply(code: 0x07, bindAddress: .ipv4("0.0.0.0"), bindPort: 0), completion: .contentProcessed { _ in })
        stop()
    }
}