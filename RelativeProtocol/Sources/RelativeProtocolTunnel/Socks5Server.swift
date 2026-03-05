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

@available(iOS 14.2, macOS 11.0, tvOS 14.2, watchOS 7.1, *)
private func unsatisfiedReasonName(_ reason: Network.NWPath.UnsatisfiedReason) -> String {
    switch reason {
    case .notAvailable:
        return "not-available"
    case .cellularDenied:
        return "cellular-denied"
    case .wifiDenied:
        return "wifi-denied"
    case .localNetworkDenied:
        return "local-network-denied"
    case .vpnInactive:
        return "vpn-inactive"
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
    var result = "status=\(pathStatusName(path.status)) uses=\(uses.joined(separator: ",")) expensive=\(path.isExpensive) constrained=\(path.isConstrained) v4=\(path.supportsIPv4) v6=\(path.supportsIPv6) dns=\(path.supportsDNS)"
    if #available(iOS 14.2, macOS 11.0, tvOS 14.2, watchOS 7.1, *),
       path.status != .satisfied {
        result += " reason=\(unsatisfiedReasonName(path.unsatisfiedReason))"
    }
    return result
}

private func isLiteralIPv6Host(_ host: String) -> Bool {
    let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return false }
    return IPv6Address(trimmed) != nil
}

private func isLiteralIPv4Host(_ host: String) -> Bool {
    let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return false }
    return IPv4Address(trimmed) != nil
}

private func preferredIPVersion(
    for endpointHost: String,
    preferIPv4ForDomains: Bool
) -> NWProtocolIP.Options.Version {
    if isLiteralIPv6Host(endpointHost) {
        return .v6
    }
    if isLiteralIPv4Host(endpointHost) {
        return .v4
    }
    return preferIPv4ForDomains ? .v4 : .any
}

@discardableResult
private func applyPreferredIPVersion(
    to parameters: NWParameters,
    endpointHost: String,
    preferIPv4ForDomains: Bool
) -> NWProtocolIP.Options.Version? {
    guard let ipOptions = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options else {
        return nil
    }
    let version = preferredIPVersion(for: endpointHost, preferIPv4ForDomains: preferIPv4ForDomains)
    ipOptions.version = version
    return version
}

private func ipVersionName(_ version: NWProtocolIP.Options.Version) -> String {
    switch version {
    case .any:
        return "any"
    case .v4:
        return "v4"
    case .v6:
        return "v6"
    @unknown default:
        return "unknown"
    }
}

typealias Socks5DiagnosticSink = (_ component: String, _ level: String, _ message: String) -> Void

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
    func onReady(_ completion: @escaping (Result<Void, Error>) -> Void)
    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void)
    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void)
    func cancel()
}

final class NWConnectionTCPAdapter: Socks5TCPOutbound {
    private static let waitingStateLogInterval: TimeInterval = 30
    private static let waitingStateProbeInterval: TimeInterval = 5
    private static let maxEndpointSwitchAttempts = 3

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let logger = RelativeLog.logger(.tunnel)
    private let diagnosticSink: Socks5DiagnosticSink?
    private let endpointHost: String?
    private let isLiteralIPv6Endpoint: Bool
    private let isLiteralIPv4Endpoint: Bool
    private var didLogReady = false
    private var didLogWaiting = false
    private var didLogFailed = false
    private var waitingStateEnteredAt: TimeInterval?
    private var waitingTimeoutTimer: DispatchSourceTimer?
    private var nextWaitingLogElapsed: TimeInterval = 30
    private var waitingEndpointSwitchAttempts = 0
    private var readinessResult: Result<Void, Error>?
    private var readinessHandlers: [(Result<Void, Error>) -> Void] = []

    init(
        _ connection: NWConnection,
        queue: DispatchQueue,
        diagnosticSink: Socks5DiagnosticSink? = nil,
        endpointHost: String? = nil
    ) {
        self.connection = connection
        self.queue = queue
        self.diagnosticSink = diagnosticSink
        self.endpointHost = endpointHost
        self.isLiteralIPv6Endpoint = endpointHost.map(isLiteralIPv6Host) ?? false
        self.isLiteralIPv4Endpoint = endpointHost.map(isLiteralIPv4Host) ?? false
        self.connection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state)
        }
        self.connection.betterPathUpdateHandler = { [weak self] betterPathAvailable in
            guard betterPathAvailable else { return }
            self?.queue.async {
                guard let self else { return }
                guard self.waitingStateEnteredAt != nil else { return }
                self.tryAdvanceToAlternateEndpoint(trigger: "better-path")
            }
        }
        self.connection.start(queue: queue)
    }

    func onReady(_ completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            if let readinessResult = self.readinessResult {
                completion(readinessResult)
            } else {
                self.readinessHandlers.append(completion)
            }
        }
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
        queue.async {
            self.cancelWaitingTimeoutTimer()
            self.resolveReadiness(.failure(Socks5OutboundError.connectionCancelled))
            self.connection.cancel()
        }
    }

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            cancelWaitingTimeoutTimer()
            waitingStateEnteredAt = nil
            nextWaitingLogElapsed = Self.waitingStateLogInterval
            waitingEndpointSwitchAttempts = 0
            resolveReadiness(.success(()))
            didLogWaiting = false
            if !didLogReady {
                didLogReady = true
                diagnosticSink?("tcp", "info", "ready \(pathSummary(self.connection.currentPath))")
                if RelativeLog.isVerbose {
                    logger.info("Outbound TCP ready. \(pathSummary(self.connection.currentPath), privacy: .public)")
                }
            }
        case .waiting(let error):
            if shouldFastFailIPv6NoRoute(waitingError: error) {
                cancelWaitingTimeoutTimer()
                waitingStateEnteredAt = nil
                let host = endpointHost ?? "<unknown>"
                let failure = Socks5OutboundError.ipv6RouteUnavailable(host)
                diagnosticSink?("tcp", "error", "ipv6-no-route host=\(host) \(pathSummary(self.connection.currentPath))")
                logger.error("Outbound TCP no usable IPv6 route for \(host, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
                resolveReadiness(.failure(failure))
                connection.cancel()
                return
            }
            if waitingStateEnteredAt == nil {
                waitingStateEnteredAt = TunnelTime.nowMonotonicSeconds()
                nextWaitingLogElapsed = Self.waitingStateLogInterval
                tryAdvanceToAlternateEndpoint(trigger: "waiting-entered")
            }
            if !didLogWaiting {
                didLogWaiting = true
                diagnosticSink?("tcp", "warning", "waiting error=\(error.localizedDescription) \(pathSummary(self.connection.currentPath))")
                logger.warning("Outbound TCP waiting: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
            scheduleWaitingTimeoutTimer()
        case .failed(let error):
            cancelWaitingTimeoutTimer()
            waitingStateEnteredAt = nil
            nextWaitingLogElapsed = Self.waitingStateLogInterval
            waitingEndpointSwitchAttempts = 0
            resolveReadiness(.failure(error))
            if !didLogFailed {
                didLogFailed = true
                diagnosticSink?("tcp", "error", "failed error=\(error.localizedDescription) \(pathSummary(self.connection.currentPath))")
                logger.error("Outbound TCP failed: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
        case .cancelled:
            cancelWaitingTimeoutTimer()
            waitingStateEnteredAt = nil
            nextWaitingLogElapsed = Self.waitingStateLogInterval
            waitingEndpointSwitchAttempts = 0
            resolveReadiness(.failure(Socks5OutboundError.connectionCancelled))
            diagnosticSink?("tcp", "warning", "cancelled \(pathSummary(self.connection.currentPath))")
        default:
            break
        }
    }

    private func shouldFastFailIPv6NoRoute(waitingError: NWError) -> Bool {
        guard isLiteralIPv6Endpoint else { return false }
        if case .posix(let code) = waitingError {
            switch code {
            case .ENETDOWN, .ENETUNREACH, .EHOSTUNREACH, .EADDRNOTAVAIL:
                return true
            default:
                break
            }
        }
        guard let path = connection.currentPath else { return false }
        if path.status != .satisfied {
            return true
        }
        return !path.supportsIPv6
    }

    private func scheduleWaitingTimeoutTimer() {
        guard waitingTimeoutTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + Self.waitingStateProbeInterval,
            repeating: Self.waitingStateProbeInterval
        )
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            guard self.waitingStateEnteredAt != nil else {
                self.cancelWaitingTimeoutTimer()
                return
            }
            let elapsed: TimeInterval
            if let startedAt = self.waitingStateEnteredAt {
                elapsed = max(0, TunnelTime.nowMonotonicSeconds() - startedAt)
            } else {
                elapsed = Self.waitingStateLogInterval
            }
            if elapsed >= self.nextWaitingLogElapsed {
                self.diagnosticSink?("tcp", "info", "still-waiting elapsed=\(String(format: "%.1f", elapsed))s")
                if RelativeLog.isVerbose {
                    self.logger.info("Outbound TCP still in waiting state after \(elapsed, privacy: .public)s.")
                }
                self.nextWaitingLogElapsed += Self.waitingStateLogInterval
            }
            self.tryAdvanceToAlternateEndpoint(trigger: "waiting-probe")
        }
        timer.resume()
        waitingTimeoutTimer = timer
    }

    private func canTryAlternateEndpoint() -> Bool {
        guard let endpointHost else { return false }
        if endpointHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        return !isLiteralIPv4Endpoint && !isLiteralIPv6Endpoint
    }

    private func tryAdvanceToAlternateEndpoint(trigger: String) {
        guard canTryAlternateEndpoint() else { return }
        guard waitingEndpointSwitchAttempts < Self.maxEndpointSwitchAttempts else { return }
        waitingEndpointSwitchAttempts += 1
        diagnosticSink?("tcp", "info", "waiting-advance-endpoint attempt=\(waitingEndpointSwitchAttempts) trigger=\(trigger)")
        connection.cancelCurrentEndpoint()
    }

    private func cancelWaitingTimeoutTimer() {
        waitingTimeoutTimer?.cancel()
        waitingTimeoutTimer = nil
    }

    private func resolveReadiness(_ result: Result<Void, Error>) {
        guard readinessResult == nil else { return }
        readinessResult = result
        let handlers = readinessHandlers
        readinessHandlers.removeAll(keepingCapacity: false)
        handlers.forEach { $0(result) }
    }
}

final class NWTCPConnectionAdapter: Socks5TCPOutbound {
    private let connection: NWTCPConnection

    init(_ connection: NWTCPConnection) {
        self.connection = connection
    }

    func onReady(_ completion: @escaping (Result<Void, Error>) -> Void) {
        completion(.success(()))
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

final class AdapterFailedTCPOutbound: Socks5TCPOutbound {
    private let error: Error

    init(error: Error) {
        self.error = error
    }

    func onReady(_ completion: @escaping (Result<Void, Error>) -> Void) {
        completion(.failure(error))
    }

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void) {
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

protocol Socks5UDPSession: AnyObject {
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int)
    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void)
    func cancel()
}

final class NWConnectionUDPSessionAdapter: Socks5UDPSession {
    private static let waitingStateLogInterval: TimeInterval = 30
    private static let waitingStateProbeInterval: TimeInterval = 5
    private static let maxEndpointSwitchAttempts = 3

    private let connection: NWConnection
    private let queue: DispatchQueue
    private var readHandler: (([Data]?, Error?) -> Void)?
    private var isCancelled = false
    private let logger = RelativeLog.logger(.tunnel)
    private let diagnosticSink: Socks5DiagnosticSink?
    private let endpointHost: String?
    private let isLiteralIPv6Endpoint: Bool
    private let isLiteralIPv4Endpoint: Bool
    private var immediateFailure: Error?
    private var didLogReady = false
    private var didLogWaiting = false
    private var didLogFailed = false
    private var waitingStateEnteredAt: TimeInterval?
    private var waitingTimeoutTimer: DispatchSourceTimer?
    private var nextWaitingLogElapsed: TimeInterval = 30
    private var waitingEndpointSwitchAttempts = 0

    init(
        _ connection: NWConnection,
        queue: DispatchQueue,
        diagnosticSink: Socks5DiagnosticSink? = nil,
        endpointHost: String? = nil
    ) {
        self.connection = connection
        self.queue = queue
        self.diagnosticSink = diagnosticSink
        self.endpointHost = endpointHost
        self.isLiteralIPv6Endpoint = endpointHost.map(isLiteralIPv6Host) ?? false
        self.isLiteralIPv4Endpoint = endpointHost.map(isLiteralIPv4Host) ?? false
        self.connection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state)
        }
        self.connection.betterPathUpdateHandler = { [weak self] betterPathAvailable in
            guard betterPathAvailable else { return }
            self?.queue.async {
                guard let self else { return }
                guard self.waitingStateEnteredAt != nil else { return }
                self.tryAdvanceToAlternateEndpoint(trigger: "better-path")
            }
        }
        self.connection.start(queue: queue)
    }

    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int) {
        if let immediateFailure {
            handler(nil, immediateFailure)
            return
        }
        readHandler = handler
        receiveNext()
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) {
        if let immediateFailure {
            completionHandler(immediateFailure)
            return
        }
        connection.send(content: datagram, completion: .contentProcessed { error in
            completionHandler(error)
        })
    }

    func cancel() {
        isCancelled = true
        cancelWaitingTimeoutTimer()
        connection.cancel()
    }

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            cancelWaitingTimeoutTimer()
            waitingStateEnteredAt = nil
            nextWaitingLogElapsed = Self.waitingStateLogInterval
            waitingEndpointSwitchAttempts = 0
            didLogWaiting = false
            if !didLogReady {
                didLogReady = true
                diagnosticSink?("udp", "info", "ready \(pathSummary(self.connection.currentPath))")
                if RelativeLog.isVerbose {
                    logger.info("Outbound UDP ready. \(pathSummary(self.connection.currentPath), privacy: .public)")
                }
            }
        case .waiting(let error):
            if shouldFastFailIPv6NoRoute(waitingError: error) {
                cancelWaitingTimeoutTimer()
                waitingStateEnteredAt = nil
                let host = endpointHost ?? "<unknown>"
                let failure = Socks5OutboundError.ipv6RouteUnavailable(host)
                immediateFailure = failure
                diagnosticSink?("udp", "error", "ipv6-no-route host=\(host) \(pathSummary(self.connection.currentPath))")
                logger.error("Outbound UDP no usable IPv6 route for \(host, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
                readHandler?(nil, failure)
                connection.cancel()
                return
            }
            if waitingStateEnteredAt == nil {
                waitingStateEnteredAt = TunnelTime.nowMonotonicSeconds()
                nextWaitingLogElapsed = Self.waitingStateLogInterval
                tryAdvanceToAlternateEndpoint(trigger: "waiting-entered")
            }
            if !didLogWaiting {
                didLogWaiting = true
                diagnosticSink?("udp", "warning", "waiting error=\(error.localizedDescription) \(pathSummary(self.connection.currentPath))")
                logger.warning("Outbound UDP waiting: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
            scheduleWaitingTimeoutTimer()
        case .failed(let error):
            cancelWaitingTimeoutTimer()
            waitingStateEnteredAt = nil
            nextWaitingLogElapsed = Self.waitingStateLogInterval
            waitingEndpointSwitchAttempts = 0
            immediateFailure = error
            readHandler?(nil, error)
            if !didLogFailed {
                didLogFailed = true
                diagnosticSink?("udp", "error", "failed error=\(error.localizedDescription) \(pathSummary(self.connection.currentPath))")
                logger.error("Outbound UDP failed: \(error.localizedDescription, privacy: .public). \(pathSummary(self.connection.currentPath), privacy: .public)")
            }
        case .cancelled:
            cancelWaitingTimeoutTimer()
            waitingStateEnteredAt = nil
            nextWaitingLogElapsed = Self.waitingStateLogInterval
            waitingEndpointSwitchAttempts = 0
            let cancelledError = Socks5OutboundError.connectionCancelled
            immediateFailure = cancelledError
            readHandler?(nil, cancelledError)
            diagnosticSink?("udp", "warning", "cancelled \(pathSummary(self.connection.currentPath))")
        default:
            break
        }
    }

    private func shouldFastFailIPv6NoRoute(waitingError: NWError) -> Bool {
        guard isLiteralIPv6Endpoint else { return false }
        if case .posix(let code) = waitingError {
            switch code {
            case .ENETDOWN, .ENETUNREACH, .EHOSTUNREACH, .EADDRNOTAVAIL:
                return true
            default:
                break
            }
        }
        guard let path = connection.currentPath else { return false }
        if path.status != .satisfied {
            return true
        }
        return !path.supportsIPv6
    }

    private func scheduleWaitingTimeoutTimer() {
        guard waitingTimeoutTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + Self.waitingStateProbeInterval,
            repeating: Self.waitingStateProbeInterval
        )
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            guard !self.isCancelled else { return }
            guard self.waitingStateEnteredAt != nil else {
                self.cancelWaitingTimeoutTimer()
                return
            }
            let elapsed: TimeInterval
            if let startedAt = self.waitingStateEnteredAt {
                elapsed = max(0, TunnelTime.nowMonotonicSeconds() - startedAt)
            } else {
                elapsed = Self.waitingStateLogInterval
            }
            if elapsed >= self.nextWaitingLogElapsed {
                self.diagnosticSink?("udp", "info", "still-waiting elapsed=\(String(format: "%.1f", elapsed))s")
                if RelativeLog.isVerbose {
                    self.logger.info("Outbound UDP still in waiting state after \(elapsed, privacy: .public)s.")
                }
                self.nextWaitingLogElapsed += Self.waitingStateLogInterval
            }
            self.tryAdvanceToAlternateEndpoint(trigger: "waiting-probe")
        }
        timer.resume()
        waitingTimeoutTimer = timer
    }

    private func canTryAlternateEndpoint() -> Bool {
        guard let endpointHost else { return false }
        if endpointHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        return !isLiteralIPv4Endpoint && !isLiteralIPv6Endpoint
    }

    private func tryAdvanceToAlternateEndpoint(trigger: String) {
        guard canTryAlternateEndpoint() else { return }
        guard waitingEndpointSwitchAttempts < Self.maxEndpointSwitchAttempts else { return }
        waitingEndpointSwitchAttempts += 1
        diagnosticSink?("udp", "info", "waiting-advance-endpoint attempt=\(waitingEndpointSwitchAttempts) trigger=\(trigger)")
        connection.cancelCurrentEndpoint()
    }

    private func cancelWaitingTimeoutTimer() {
        waitingTimeoutTimer?.cancel()
        waitingTimeoutTimer = nil
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

final class AdapterFailedUDPSession: Socks5UDPSession {
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
    private let diagnosticSink: Socks5DiagnosticSink?
    private let preferIPv4ForDomainEndpoints: Bool

    init(
        provider: NEPacketTunnelProvider,
        queue: DispatchQueue,
        diagnosticSink: Socks5DiagnosticSink? = nil,
        preferIPv4ForDomainEndpoints: Bool = true
    ) {
        self.provider = provider
        self.queue = queue
        self.diagnosticSink = diagnosticSink
        self.preferIPv4ForDomainEndpoints = preferIPv4ForDomainEndpoints
    }

    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound {
        _ = tlsParameters
        _ = delegate
        let outbound = makeNWConnection(to: endpoint, enableTLS: enableTLS)
        if RelativeLog.isVerbose {
            logger.debug("Outbound TCP using NWConnection to \(endpoint.hostname, privacy: .public):\(endpoint.port, privacy: .public)")
        }
        return outbound
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        let outbound = makeNWUDPSession(to: endpoint)
        if RelativeLog.isVerbose {
            logger.debug("Outbound UDP using NWConnection to \(endpoint.hostname, privacy: .public):\(endpoint.port, privacy: .public)")
        }
        return outbound
    }

    private func makeNWConnection(to endpoint: NWHostEndpoint, enableTLS: Bool) -> Socks5TCPOutbound {
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue) else {
            let error = Socks5OutboundError.invalidEndpointPort(endpoint.port)
            logger.error("Outbound TCP invalid endpoint port: \(endpoint.port, privacy: .public)")
            diagnosticSink?("tcp", "error", "invalid-port value=\(endpoint.port)")
            return AdapterFailedTCPOutbound(error: error)
        }

        let parameters = enableTLS ? NWParameters.tls : NWParameters.tcp
        if #available(iOS 18.0, macOS 15.0, *) {
            if let virtualInterface = provider.virtualInterface {
                parameters.prohibitedInterfaces = [virtualInterface]
                if RelativeLog.isVerbose {
                    logger.debug("Outbound TCP prohibiting interface \(virtualInterface.name, privacy: .public)")
                }
            } else {
                logger.warning("Outbound TCP virtualInterface unavailable; proceeding without prohibitedInterfaces.")
                diagnosticSink?("tcp", "warning", "virtualInterface unavailable; no prohibitedInterfaces")
            }
        } else {
            if RelativeLog.isVerbose {
                logger.warning("Outbound TCP running on platform without prohibitedInterfaces; using NWConnection directly.")
            }
            diagnosticSink?("tcp", "warning", "prohibitedInterfaces unavailable on runtime platform")
        }
        if let chosenVersion = applyPreferredIPVersion(
            to: parameters,
            endpointHost: endpoint.hostname,
            preferIPv4ForDomains: preferIPv4ForDomainEndpoints
        ), RelativeLog.isVerbose {
            logger.debug(
                "Outbound TCP IP version policy host=\(endpoint.hostname, privacy: .public) selected=\(ipVersionName(chosenVersion), privacy: .public)"
            )
        }

        let host = NWEndpoint.Host(endpoint.hostname)
        let connection = NWConnection(host: host, port: port, using: parameters)
        return NWConnectionTCPAdapter(
            connection,
            queue: queue,
            diagnosticSink: diagnosticSink,
            endpointHost: endpoint.hostname
        )
    }

    private func makeNWUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue) else {
            let error = Socks5OutboundError.invalidEndpointPort(endpoint.port)
            logger.error("Outbound UDP invalid endpoint port: \(endpoint.port, privacy: .public)")
            diagnosticSink?("udp", "error", "invalid-port value=\(endpoint.port)")
            return AdapterFailedUDPSession(error: error)
        }

        let parameters = NWParameters.udp
        if #available(iOS 18.0, macOS 15.0, *) {
            if let virtualInterface = provider.virtualInterface {
                parameters.prohibitedInterfaces = [virtualInterface]
                if RelativeLog.isVerbose {
                    logger.debug("Outbound UDP prohibiting interface \(virtualInterface.name, privacy: .public)")
                }
            } else {
                logger.warning("Outbound UDP virtualInterface unavailable; proceeding without prohibitedInterfaces.")
                diagnosticSink?("udp", "warning", "virtualInterface unavailable; no prohibitedInterfaces")
            }
        } else {
            if RelativeLog.isVerbose {
                logger.warning("Outbound UDP running on platform without prohibitedInterfaces; using NWConnection directly.")
            }
            diagnosticSink?("udp", "warning", "prohibitedInterfaces unavailable on runtime platform")
        }
        if let chosenVersion = applyPreferredIPVersion(
            to: parameters,
            endpointHost: endpoint.hostname,
            preferIPv4ForDomains: preferIPv4ForDomainEndpoints
        ), RelativeLog.isVerbose {
            logger.debug(
                "Outbound UDP IP version policy host=\(endpoint.hostname, privacy: .public) selected=\(ipVersionName(chosenVersion), privacy: .public)"
            )
        }

        let host = NWEndpoint.Host(endpoint.hostname)
        let connection = NWConnection(host: host, port: port, using: parameters)
        return NWConnectionUDPSessionAdapter(
            connection,
            queue: queue,
            diagnosticSink: diagnosticSink,
            endpointHost: endpoint.hostname
        )
    }
}

final class Socks5Server {
    private static let listenerBindRetryAttempts = 7
    private static let listenerBindRetryDelay: TimeInterval = 0.2

    private let logger = RelativeLog.logger(.tunnel)
    private let provider: Socks5ConnectionProvider
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<Void>()
    private let mtu: Int
    private let diagnosticSink: Socks5DiagnosticSink?
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: Socks5Connection] = [:]
    private var listenerGeneration: UInt64 = 0
    private var isStopped = true

    init(
        provider: Socks5ConnectionProvider,
        queue: DispatchQueue,
        mtu: Int,
        diagnosticSink: Socks5DiagnosticSink? = nil
    ) {
        self.provider = provider
        self.queue = queue
        self.mtu = mtu
        self.diagnosticSink = diagnosticSink
        self.queue.setSpecific(key: queueKey, value: ())
    }

    convenience init(
        provider: NEPacketTunnelProvider,
        queue: DispatchQueue,
        mtu: Int,
        diagnosticSink: Socks5DiagnosticSink? = nil
    ) {
        self.init(
            provider: PacketTunnelProviderAdapter(provider: provider, queue: queue, diagnosticSink: diagnosticSink),
            queue: queue,
            mtu: mtu,
            diagnosticSink: diagnosticSink
        )
    }

    func activeConnectionCount() -> Int {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            return connections.count
        }
        return queue.sync { connections.count }
    }

    func start(port: UInt16, completion: @escaping (Result<UInt16, Error>) -> Void) {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            startLocked(port: port, completion: completion)
            return
        }
        queue.async {
            self.startLocked(port: port, completion: completion)
        }
    }

    private func startLocked(port: UInt16, completion: @escaping (Result<UInt16, Error>) -> Void) {
        isStopped = false
        listenerGeneration &+= 1
        let generation = listenerGeneration
        let initialPort = port == 0 ? pickEphemeralPort() : port
        startListener(
            port: initialPort,
            remainingAttempts: Self.listenerBindRetryAttempts,
            generation: generation,
            completion: completion
        )
    }

    private func startListener(
        port: UInt16,
        remainingAttempts: Int,
        generation: UInt64,
        completion: @escaping (Result<UInt16, Error>) -> Void
    ) {
        guard !isStopped, generation == listenerGeneration else { return }
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
                    self.diagnosticSink?("listener", "warning", "waiting error=\(error.localizedDescription)")
                    self.logger.error("SOCKS5 listener waiting: \(error.localizedDescription, privacy: .public)")
                    if RelativeLog.isVerbose {
                        NSLog("Socks5Server: listener waiting: \(error.localizedDescription)")
                    }
                case .ready:
                    self.diagnosticSink?("listener", "info", "ready port=\(listener.port?.rawValue ?? port)")
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
                        if RelativeLog.isVerbose {
                            self.probeLoopback(port: actualPort)
                        }
                    }
                case .failed(let error):
                    self.diagnosticSink?("listener", "error", "failed error=\(error.localizedDescription) port=\(port)")
                    if self.isAddressInUse(error), remainingAttempts > 0 {
                        didComplete = true
                        let nextPort = self.pickEphemeralPort()
                        self.logger.error("SOCKS5 listener failed on port \(port, privacy: .public); retrying on port \(nextPort, privacy: .public)")
                        if RelativeLog.isVerbose {
                            NSLog("Socks5Server: listener failed on port \(port); retrying on port \(nextPort)")
                        }
                        listener.cancel()
                        self.listener = nil
                        self.queue.asyncAfter(deadline: .now() + Self.listenerBindRetryDelay) {
                            guard !self.isStopped, generation == self.listenerGeneration else { return }
                            self.startListener(
                                port: nextPort,
                                remainingAttempts: remainingAttempts - 1,
                                generation: generation,
                                completion: completion
                            )
                        }
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
                    self.diagnosticSink?("listener", "warning", "cancelled")
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
                self.diagnosticSink?("listener", "info", "accepted endpoint=\(String(describing: connection.endpoint))")
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
                    self.diagnosticSink?("listener", "info", "closed activeConnections=\(self.connections.count)")
                }
                self.connections[ObjectIdentifier(connection)] = session
                self.diagnosticSink?("listener", "info", "activeConnections=\(self.connections.count)")
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
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            stopLocked()
            return
        }
        queue.sync {
            self.stopLocked()
        }
    }

    private func stopLocked() {
        isStopped = true
        listenerGeneration &+= 1
        listener?.cancel()
        listener = nil
        connections.values.forEach { $0.stop() }
        connections.removeAll()
    }
}

#if DEBUG
func _test_interfaceTypeName(_ type: Network.NWInterface.InterfaceType) -> String {
    interfaceTypeName(type)
}

func _test_pathStatusName(_ status: Network.NWPath.Status) -> String {
    pathStatusName(status)
}

func _test_pathSummary(_ path: Network.NWPath?) -> String {
    pathSummary(path)
}

extension Socks5Server {
    func _test_probeLoopback(port: UInt16) {
        probeLoopback(port: port)
    }

    func _test_isAddressInUse(_ error: NWError) -> Bool {
        isAddressInUse(error)
    }
}
#endif

enum Socks5ServerError: Error {
    case invalidPort
}

enum Socks5OutboundError: Error {
    case invalidEndpointPort(String)
    case waitingStateTimeout
    case connectionCancelled
    case ipv6RouteUnavailable(String)
}

extension Socks5OutboundError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .invalidEndpointPort(let value):
            return "Invalid endpoint port: \(value)"
        case .waitingStateTimeout:
            return "Connection stayed in waiting state for too long."
        case .connectionCancelled:
            return "Connection was cancelled."
        case .ipv6RouteUnavailable(let host):
            return "No usable IPv6 route for destination \(host)."
        }
    }
}

final class Socks5Connection {
    private enum State {
        case greeting
        case request
        case bindPending
        case connectPending(Socks5TCPOutbound)
        case tcpProxy(Socks5TCPOutbound)
        case udpProxy(Socks5UDPRelayProtocol)
    }

    private static let maxBufferBytes = 64 * 1024
    private let logger = RelativeLog.logger(.tunnel)
    private let connection: Socks5InboundConnection
    private let provider: Socks5ConnectionProvider
    private let queue: DispatchQueue
    private let mtu: Int
    private let udpRelayFactory: (Socks5ConnectionProvider, DispatchQueue, Int) throws -> Socks5UDPRelayProtocol
    private var buffer = Data()
    private var state: State = .greeting
    private var isClosed = false
    private var bindListener: NWListener?

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
        case .connectPending(let outbound):
            outbound.cancel()
        case .udpProxy(let relay):
            relay.stop()
        case .bindPending:
            bindListener?.cancel()
            bindListener = nil
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
                if self.buffer.count > Self.maxBufferBytes {
                    self.logger.error("SOCKS5 connection exceeded max buffer size (\(Self.maxBufferBytes, privacy: .public)); closing.")
                    self.stop()
                    return
                }
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
            switch validateGreetingBuffer() {
            case .invalidVersion:
                connection.send(content: Socks5Codec.buildMethodSelection(method: 0xFF), completion: .contentProcessed { [weak self] _ in
                    self?.stop()
                })
                return
            case .invalidCommand, .invalidAddressType:
                connection.send(content: Socks5Codec.buildMethodSelection(method: 0xFF), completion: .contentProcessed { [weak self] _ in
                    self?.stop()
                })
                return
            case .incomplete:
                return
            case .valid:
                break
            }
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
            switch validateRequestBufferPrefix() {
            case .invalidVersion:
                sendFailure(code: 0x01)
                return
            case .invalidCommand:
                sendFailure(code: 0x07)
                return
            case .invalidAddressType:
                sendFailure(code: 0x08)
                return
            case .incomplete:
                return
            case .valid:
                break
            }
            guard let request = Socks5Codec.parseRequest(&buffer) else { return }
            if RelativeLog.isVerbose {
                logger.debug("SOCKS5 request \(String(describing: request.command), privacy: .public) \(String(describing: request.address), privacy: .public):\(request.port, privacy: .public)")
                NSLog("Socks5Connection: request cmd=\(request.command) addr=\(request.address) port=\(request.port)")
            }
            handleRequest(request)
        case .connectPending:
            break
        case .tcpProxy(let outbound):
            if !buffer.isEmpty {
                forwardToOutbound(buffer, outbound: outbound)
                buffer.removeAll()
            }
        case .bindPending:
            break
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
            startBindRelay(request)
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
        state = .connectPending(outbound)
        outbound.onReady { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                guard case .connectPending(let pending) = self.state,
                      ObjectIdentifier(pending) == ObjectIdentifier(outbound) else { return }
                self.state = .tcpProxy(outbound)
                self.connection.send(
                    content: Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("0.0.0.0"), bindPort: 0),
                    completion: .contentProcessed { [weak self] _ in
                        guard let self else { return }
                        self.readOutbound(outbound)
                        self.processBuffer()
                    }
                )
            case .failure(let error):
                self.logger.error("SOCKS5 outbound connection failed before ready: \(error.localizedDescription, privacy: .public)")
                self.sendFailure(code: self.failureReplyCode(for: error))
            }
        }
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

    private func startBindRelay(_ request: Socks5Request) {
        if request.port != 0, NWEndpoint.Port(rawValue: request.port) == nil {
            sendFailure()
            return
        }

        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        parameters.requiredInterfaceType = .loopback
        if request.port != 0,
           let loopback = IPv4Address("127.0.0.1"),
           let bindPort = NWEndpoint.Port(rawValue: request.port) {
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(loopback), port: bindPort)
        }

        let listener: NWListener
        do {
            listener = try NWListener(using: parameters, on: .any)
        } catch {
            logger.error("SOCKS5 BIND listener creation failed: \(error.localizedDescription, privacy: .public)")
            sendFailure()
            return
        }

        bindListener = listener
        state = .bindPending
        var didSendFirstReply = false
        let sendFirstReply: () -> Void = { [weak self, weak listener] in
            guard let self, let listener else { return }
            guard !didSendFirstReply else { return }
            didSendFirstReply = true
            let port = listener.port?.rawValue ?? request.port
            self.connection.send(
                content: Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("127.0.0.1"), bindPort: port),
                completion: .contentProcessed { _ in }
            )
        }

        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                sendFirstReply()
            case .failed(let error):
                self.logger.error("SOCKS5 BIND listener failed: \(error.localizedDescription, privacy: .public)")
                self.sendFailure()
            case .cancelled:
                break
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self, weak listener] inboundConnection in
            guard let self else { return }
            sendFirstReply()
            listener?.cancel()
            self.bindListener = nil

            let outbound = NWConnectionTCPAdapter(inboundConnection, queue: self.queue)
            self.state = .tcpProxy(outbound)
            let port = listener?.port?.rawValue ?? request.port
            self.connection.send(
                content: Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("127.0.0.1"), bindPort: port),
                completion: .contentProcessed { _ in
                    self.readOutbound(outbound)
                    self.processBuffer()
                }
            )
        }

        listener.start(queue: queue)
    }

    private enum ParseStatus {
        case valid
        case incomplete
        case invalidVersion
        case invalidCommand
        case invalidAddressType
    }

    private func validateGreetingBuffer() -> ParseStatus {
        guard !buffer.isEmpty else { return .incomplete }
        guard buffer[buffer.startIndex] == 0x05 else { return .invalidVersion }
        guard buffer.count >= 2 else { return .incomplete }
        let methodCount = Int(buffer[buffer.startIndex + 1])
        return buffer.count >= 2 + methodCount ? .valid : .incomplete
    }

    private func validateRequestBufferPrefix() -> ParseStatus {
        guard !buffer.isEmpty else { return .incomplete }
        guard buffer[buffer.startIndex] == 0x05 else { return .invalidVersion }
        guard buffer.count >= 2 else { return .incomplete }
        guard Socks5Command(rawValue: buffer[buffer.startIndex + 1]) != nil else { return .invalidCommand }
        guard buffer.count >= 4 else { return .incomplete }
        switch buffer[buffer.startIndex + 3] {
        case 0x01, 0x03, 0x04:
            return .valid
        default:
            return .invalidAddressType
        }
    }

    private func failureReplyCode(for error: Error) -> UInt8 {
        if let outboundError = error as? Socks5OutboundError {
            switch outboundError {
            case .ipv6RouteUnavailable:
                return 0x03 // network unreachable
            case .invalidEndpointPort,
                 .connectionCancelled,
                 .waitingStateTimeout:
                return 0x01 // general SOCKS server failure
            }
        }

        if let nwError = error as? NWError {
            switch nwError {
            case .dns:
                return 0x04 // host unreachable
            case .posix(let code):
                switch code {
                case .ENETDOWN, .ENETUNREACH:
                    return 0x03 // network unreachable
                case .EHOSTDOWN, .EHOSTUNREACH, .EADDRNOTAVAIL, .ETIMEDOUT:
                    return 0x04 // host unreachable
                case .ECONNREFUSED:
                    return 0x05 // connection refused
                default:
                    return 0x01 // general failure
                }
            default:
                return 0x01
            }
        }

        return 0x01
    }

    private func sendFailure(code: UInt8 = 0x07) {
        connection.send(
            content: Socks5Codec.buildReply(code: code, bindAddress: .ipv4("0.0.0.0"), bindPort: 0),
            completion: .contentProcessed { [weak self] _ in
                self?.stop()
            }
        )
    }
}
