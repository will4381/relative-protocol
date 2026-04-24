import Foundation
import Network
@preconcurrency import NetworkExtension
import Observability

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

private func durationMilliseconds(_ duration: TimeInterval) -> Int {
    max(0, Int((duration * 1000).rounded()))
}

private func elapsedMilliseconds(since startedAt: Date?, now: Date = Date()) -> Int? {
    guard let startedAt else {
        return nil
    }
    return max(0, Int((now.timeIntervalSince(startedAt) * 1000).rounded()))
}

private extension Result where Success == Void, Failure == Error {
    var failureError: Error? {
        if case .failure(let error) = self {
            return error
        }
        return nil
    }
}

/// Abstraction over inbound SOCKS5 client connection transport.
protocol Socks5InboundConnection: AnyObject {
    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? { get set }
    func start(queue: DispatchQueue)
    func receive(minimumIncompleteLength: Int, maximumLength: Int, completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    func send(content: Data?, completion: NWConnection.SendCompletion)
    func cancel()
}

/// Abstraction over outbound TCP channel used for SOCKS CONNECT.
protocol Socks5TCPOutbound: AnyObject, Sendable {
    /// Waits until the outbound connection is established and ready for I/O.
    /// Completion is delivered at most once per registration.
    /// - Parameter completionHandler: Success when data transfer can begin, failure on terminal connection error.
    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void)
    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping @Sendable (Data?, Error?) -> Void)
    func write(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void)
    func cancel()
}

/// Connection establishment errors surfaced before a SOCKS CONNECT reply is sent.
private enum Socks5OutboundError: LocalizedError {
    case failed(String)
    case timedOut
    case cancelled

    var errorDescription: String? {
        switch self {
        case .failed(let description):
            return description
        case .timedOut:
            return "Outbound connection timed out"
        case .cancelled:
            return "Outbound connection cancelled"
        }
    }
}

enum Socks5UDPDatagramError: LocalizedError, Equatable, Sendable {
    case exceedsMaximumDatagramSize(datagramSize: Int, maximumDatagramSize: Int, pathSummary: String)

    static let datagramTooLargeErrorCode = "udp-datagram-too-large"

    var errorDescription: String? {
        switch self {
        case .exceedsMaximumDatagramSize(let datagramSize, let maximumDatagramSize, _):
            return "UDP datagram size \(datagramSize) exceeds maximumDatagramSize (\(maximumDatagramSize))"
        }
    }

    var errorCode: String {
        switch self {
        case .exceedsMaximumDatagramSize:
            return Self.datagramTooLargeErrorCode
        }
    }
}

struct TCPConnectRetryPolicy: Sendable {
    let attemptPreparingTimeout: TimeInterval
    let retryBackoff: TimeInterval
    let maxAttempts: Int
    let overallTimeout: TimeInterval

    static let `default` = TCPConnectRetryPolicy(
        attemptPreparingTimeout: 8.0,
        retryBackoff: 0.5,
        maxAttempts: 4,
        overallTimeout: 30.0
    )
}

public struct Socks5TCPPathSettings: Sendable {
    public let retryOnBetterPathDuringConnect: Bool
    public let betterPathRetryMinimumElapsed: TimeInterval
    public let multipathServiceType: NWParameters.MultipathServiceType?

    public init(
        retryOnBetterPathDuringConnect: Bool = true,
        betterPathRetryMinimumElapsed: TimeInterval = 0.75,
        multipathServiceType: NWParameters.MultipathServiceType? = nil
    ) {
        self.retryOnBetterPathDuringConnect = retryOnBetterPathDuringConnect
        self.betterPathRetryMinimumElapsed = betterPathRetryMinimumElapsed
        self.multipathServiceType = multipathServiceType
    }

    public static let `default` = Socks5TCPPathSettings()
}

/// Extended outbound provider for SOCKS TCP + UDP backends.
protocol Socks5FullConnectionProvider: Socks5ConnectionProvider {
    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound
}

enum TCPOutboundEvent: Sendable {
    case betterPathAvailable
}

protocol Socks5PathAwareTCPOutbound: Socks5TCPOutbound {
    var eventHandler: ((TCPOutboundEvent) -> Void)? { get set }
    var pathSnapshot: String { get }
}

/// `Socks5InboundConnection` adapter for `NWConnection`.
final class SocksInboundNWConnectionAdapter: @unchecked Sendable, Socks5InboundConnection {
    // Docs: https://developer.apple.com/documentation/network/nwconnection
    private let connection: NWConnection

    /// - Parameter connection: Accepted inbound network connection.
    init(_ connection: NWConnection) {
        self.connection = connection
    }

    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? {
        get { connection.stateUpdateHandler }
        set { connection.stateUpdateHandler = newValue }
    }

    func start(queue: DispatchQueue) {
        // Docs: https://developer.apple.com/documentation/network/nwconnection/start(queue:)
        connection.start(queue: queue)
    }

    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        // Docs: https://developer.apple.com/documentation/network/nwconnection/receive(minimumincompletelength:maximumlength:completion:)
        connection.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength, completion: completion)
    }

    func send(content: Data?, completion: NWConnection.SendCompletion) {
        // Docs: https://developer.apple.com/documentation/network/nwconnection/send(content:contentcontext:iscomplete:completion:)
        connection.send(content: content, completion: completion)
    }

    func cancel() {
        connection.cancel()
    }
}

final class NWConnectionTCPAdapter: @unchecked Sendable, Socks5PathAwareTCPOutbound {
    private static let waitingLogMinimumInterval: TimeInterval = 10

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let logger: StructuredLogger
    private var readyHandlers: [(@Sendable (Result<Void, Error>) -> Void)] = []
    private var readyResult: Result<Void, Error>?
    private var didStart = false
    private var lastKnownPathSummary = "status=unknown uses=unknown"
    var eventHandler: ((TCPOutboundEvent) -> Void)?

    /// - Parameters:
    ///   - connection: Outbound Network.framework connection.
    ///   - queue: Queue used for connection callbacks.
    ///   - logger: Structured logger for state transitions.
    init(_ connection: NWConnection, queue: DispatchQueue, logger: StructuredLogger) {
        self.connection = connection
        self.queue = queue
        self.logger = logger
        connection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state)
        }
        connection.pathUpdateHandler = { [weak self] path in
            self?.handlePathUpdate(path)
        }
        connection.viabilityUpdateHandler = { [weak self] isViable in
            self?.handleViabilityUpdate(isViable)
        }
        connection.betterPathUpdateHandler = { [weak self] betterPathAvailable in
            self?.handleBetterPathUpdate(betterPathAvailable)
        }
    }

    var pathSnapshot: String {
        lastKnownPathSummary
    }

    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void) {
        if let readyResult {
            completionHandler(readyResult)
            return
        }

        readyHandlers.append(completionHandler)
        startIfNeeded()
    }

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        startIfNeeded()
        connection.receive(minimumIncompleteLength: minimumLength, maximumLength: maximumLength) { data, _, isComplete, error in
            if isComplete && (data == nil || data?.isEmpty == true) {
                completionHandler(nil, error)
                return
            }
            completionHandler(data, error)
        }
    }

    func write(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        startIfNeeded()
        connection.send(content: data, completion: .contentProcessed { error in
            completionHandler(error)
        })
    }

    func cancel() {
        finishReadyHandlers(with: .failure(Socks5OutboundError.cancelled))
        connection.cancel()
    }

    private func startIfNeeded() {
        guard !didStart else { return }
        didStart = true
        // Docs: https://developer.apple.com/documentation/network/nwconnection/start(queue:)
        connection.start(queue: queue)
    }

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            finishReadyHandlers(with: .success(()))
            Task {
                await logger.log(
                    level: .debug,
                    phase: .relay,
                    category: .relayTCP,
                    component: "NWConnectionTCPAdapter",
                    event: "ready",
                    message: "Outbound TCP ready",
                    metadata: ["path": lastKnownPathSummary]
                )
            }
        case .waiting(let error):
            Task {
                let path = lastKnownPathSummary
                await logger.logRateLimited(
                    key: "NWConnectionTCPAdapter.waiting.\(error.localizedDescription).\(path)",
                    minimumInterval: Self.waitingLogMinimumInterval,
                    level: .warning,
                    phase: .relay,
                    category: .relayTCP,
                    component: "NWConnectionTCPAdapter",
                    event: "waiting",
                    errorCode: error.localizedDescription,
                    message: "Outbound TCP waiting",
                    metadata: ["path": path]
                )
            }
        case .failed(let error):
            finishReadyHandlers(with: .failure(error))
            Task {
                await logger.log(
                    level: .error,
                    phase: .relay,
                    category: .relayTCP,
                    component: "NWConnectionTCPAdapter",
                    event: "failed",
                    errorCode: error.localizedDescription,
                    message: "Outbound TCP failed",
                    metadata: ["path": lastKnownPathSummary]
                )
            }
        case .cancelled:
            finishReadyHandlers(with: .failure(Socks5OutboundError.cancelled))
        default:
            break
        }
    }

    private func handlePathUpdate(_ path: Network.NWPath) {
        lastKnownPathSummary = pathSummary(path)
        Task {
            await logger.log(
                level: .debug,
                phase: .path,
                category: .relayTCP,
                component: "NWConnectionTCPAdapter",
                event: "path-update",
                result: pathStatusName(path.status),
                message: "Outbound TCP path updated",
                metadata: ["path": lastKnownPathSummary]
            )
        }
    }

    private func handleViabilityUpdate(_ isViable: Bool) {
        Task {
            await logger.log(
                level: .debug,
                phase: .path,
                category: .relayTCP,
                component: "NWConnectionTCPAdapter",
                event: "viability-update",
                result: isViable ? "viable" : "not-viable",
                message: "Outbound TCP viability changed",
                metadata: ["path": lastKnownPathSummary]
            )
        }
    }

    private func handleBetterPathUpdate(_ betterPathAvailable: Bool) {
        guard betterPathAvailable else {
            return
        }
        eventHandler?(.betterPathAvailable)
        Task {
            await logger.log(
                level: .debug,
                phase: .path,
                category: .relayTCP,
                component: "NWConnectionTCPAdapter",
                event: "better-path-available",
                result: "preferred-path",
                message: "Outbound TCP has a better path available",
                metadata: ["path": lastKnownPathSummary]
            )
        }
    }

    private func finishReadyHandlers(with result: Result<Void, Error>) {
        guard readyResult == nil else {
            return
        }
        readyResult = result
        let handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        for handler in handlers {
            handler(result)
        }
    }
}

final class RetryingTCPOutbound: @unchecked Sendable, Socks5TCPOutbound {
    private let queue: DispatchQueue
    private let logger: StructuredLogger
    private let policy: TCPConnectRetryPolicy
    private let pathSettings: Socks5TCPPathSettings
    private let makeAttempt: (_ attemptIndex: Int) -> Socks5PathAwareTCPOutbound

    private var readyHandlers: [(@Sendable (Result<Void, Error>) -> Void)] = []
    private var readyResult: Result<Void, Error>?
    private var activeOutbound: Socks5TCPOutbound?
    private var currentAttempt: Socks5PathAwareTCPOutbound?
    private var currentAttemptIndex = 0
    private var startedAt: Date?
    private var currentAttemptStartedAt: Date?
    private var attemptTimeoutWorkItem: DispatchWorkItem?
    private var overallTimeoutWorkItem: DispatchWorkItem?
    private var retryWorkItem: DispatchWorkItem?
    private var isCancelled = false

    init(
        queue: DispatchQueue,
        logger: StructuredLogger,
        policy: TCPConnectRetryPolicy = .default,
        pathSettings: Socks5TCPPathSettings = .default,
        makeAttempt: @escaping (_ attemptIndex: Int) -> Socks5PathAwareTCPOutbound
    ) {
        self.queue = queue
        self.logger = logger
        self.policy = policy
        self.pathSettings = pathSettings
        self.makeAttempt = makeAttempt
    }

    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void) {
        queue.async {
            if let readyResult = self.readyResult {
                completionHandler(readyResult)
                return
            }

            self.readyHandlers.append(completionHandler)
            if self.startedAt == nil {
                self.startedAt = Date()
                self.armOverallTimeout()
            }
            if self.currentAttempt == nil, self.retryWorkItem == nil {
                self.startAttempt(reason: "initial")
            }
        }
    }

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        queue.async {
            guard let activeOutbound = self.activeOutbound else {
                completionHandler(nil, self.readyResult?.failureError ?? Socks5OutboundError.failed("Outbound TCP not ready"))
                return
            }
            activeOutbound.readMinimumLength(minimumLength, maximumLength: maximumLength, completionHandler: completionHandler)
        }
    }

    func write(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        queue.async {
            guard let activeOutbound = self.activeOutbound else {
                completionHandler(self.readyResult?.failureError ?? Socks5OutboundError.failed("Outbound TCP not ready"))
                return
            }
            activeOutbound.write(data, completionHandler: completionHandler)
        }
    }

    func cancel() {
        queue.async {
            guard !self.isCancelled else { return }
            self.isCancelled = true
            self.cancelScheduledWork()
            self.currentAttempt?.cancel()
            self.activeOutbound?.cancel()
            self.finishReadyHandlers(with: .failure(Socks5OutboundError.cancelled))
        }
    }

    private func startAttempt(reason: String) {
        guard !isCancelled, readyResult == nil else {
            return
        }
        guard currentAttemptIndex < policy.maxAttempts else {
            exhaustRetries(with: Socks5OutboundError.timedOut, event: "connect-exhausted", reason: reason)
            return
        }
        if let overallElapsed = elapsedMilliseconds(since: startedAt),
           overallElapsed >= durationMilliseconds(policy.overallTimeout) {
            exhaustRetries(with: Socks5OutboundError.timedOut, event: "connect-overall-timeout", reason: reason)
            return
        }

        currentAttemptIndex += 1
        let attemptIndex = currentAttemptIndex
        let outbound = makeAttempt(attemptIndex)
        outbound.eventHandler = { [weak self, weak outbound] event in
            guard let self, let outbound else { return }
            self.queue.async {
                self.handleAttemptEvent(event, attemptIndex: attemptIndex, outbound: outbound)
            }
        }
        currentAttempt = outbound
        currentAttemptStartedAt = Date()
        log(
                level: .debug,
                event: "connect-attempt-started",
                result: "attempt-\(attemptIndex)",
                message: "Started outbound TCP connect attempt",
                extraMetadata: [
                    "attempt_index": String(attemptIndex),
                    "max_attempts": String(policy.maxAttempts),
                    "attempt_timeout_ms": String(durationMilliseconds(policy.attemptPreparingTimeout)),
                    "overall_timeout_ms": String(durationMilliseconds(policy.overallTimeout)),
                    "retry_reason": reason,
                    "path": outbound.pathSnapshot
                ]
        )

        armAttemptTimeout(attemptIndex: attemptIndex, outbound: outbound)
        outbound.waitUntilReady { [weak self] result in
            guard let self else { return }
            self.queue.async {
                self.handleAttemptCompletion(result: result, attemptIndex: attemptIndex, outbound: outbound)
            }
        }
    }

    private func handleAttemptEvent(
        _ event: TCPOutboundEvent,
        attemptIndex: Int,
        outbound: Socks5PathAwareTCPOutbound
    ) {
        guard !isCancelled, readyResult == nil else {
            return
        }
        guard currentAttemptIndex == attemptIndex, currentAttempt === outbound, activeOutbound == nil else {
            return
        }

        switch event {
        case .betterPathAvailable:
            guard pathSettings.retryOnBetterPathDuringConnect else {
                return
            }
            let minimumElapsedMs = durationMilliseconds(pathSettings.betterPathRetryMinimumElapsed)
            let attemptElapsedMs = elapsedMilliseconds(since: currentAttemptStartedAt) ?? 0
            guard attemptElapsedMs >= minimumElapsedMs else {
                log(
                    level: .debug,
                    event: "connect-better-path-deferred",
                    result: "attempt-\(attemptIndex)",
                    message: "Ignoring better-path signal because the connect attempt is still young",
                    extraMetadata: [
                        "attempt_index": String(attemptIndex),
                        "minimum_elapsed_ms": String(minimumElapsedMs),
                        "path": outbound.pathSnapshot
                    ]
                )
                return
            }

            attemptTimeoutWorkItem?.cancel()
            attemptTimeoutWorkItem = nil
            currentAttempt = nil
            log(
                level: .notice,
                event: "connect-better-path-retry",
                result: "attempt-\(attemptIndex)",
                message: "Replacing outbound TCP connect attempt because a better path is available",
                extraMetadata: [
                    "attempt_index": String(attemptIndex),
                    "minimum_elapsed_ms": String(minimumElapsedMs),
                    "path": outbound.pathSnapshot
                ]
            )
            outbound.cancel()
            scheduleRetry(
                afterFailure: Socks5OutboundError.failed("Replaced by preferred path"),
                reason: "better-path"
            )
        }
    }

    private func armAttemptTimeout(attemptIndex: Int, outbound: Socks5PathAwareTCPOutbound) {
        attemptTimeoutWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            guard self.readyResult == nil, !self.isCancelled else { return }
            guard self.currentAttemptIndex == attemptIndex, self.currentAttempt === outbound else { return }

            self.log(
                level: .warning,
                event: "connect-timeout",
                result: "attempt-\(attemptIndex)",
                message: "Outbound TCP connect attempt timed out",
                extraMetadata: [
                    "attempt_index": String(attemptIndex),
                    "max_attempts": String(self.policy.maxAttempts),
                    "attempt_timeout_ms": String(durationMilliseconds(self.policy.attemptPreparingTimeout)),
                    "path": outbound.pathSnapshot
                ]
            )
            outbound.cancel()
            self.currentAttempt = nil
            self.scheduleRetry(afterFailure: Socks5OutboundError.timedOut, reason: "preparing-timeout")
        }
        attemptTimeoutWorkItem = workItem
        queue.asyncAfter(deadline: .now() + policy.attemptPreparingTimeout, execute: workItem)
    }

    private func armOverallTimeout() {
        overallTimeoutWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            guard self.readyResult == nil, !self.isCancelled else { return }

            self.currentAttempt?.cancel()
            self.currentAttempt = nil
            self.exhaustRetries(with: Socks5OutboundError.timedOut, event: "connect-overall-timeout", reason: "overall-timeout")
        }
        overallTimeoutWorkItem = workItem
        queue.asyncAfter(deadline: .now() + policy.overallTimeout, execute: workItem)
    }

    private func handleAttemptCompletion(
        result: Result<Void, Error>,
        attemptIndex: Int,
        outbound: Socks5PathAwareTCPOutbound
    ) {
        guard !isCancelled, readyResult == nil else {
            return
        }
        guard currentAttemptIndex == attemptIndex, currentAttempt === outbound else {
            if case .success = result {
                outbound.cancel()
            }
            return
        }

        attemptTimeoutWorkItem?.cancel()
        attemptTimeoutWorkItem = nil

        switch result {
        case .success:
            activeOutbound = outbound
            currentAttempt = nil
            log(
                level: .notice,
                event: "connect-attempt-succeeded",
                result: "attempt-\(attemptIndex)",
                message: "Outbound TCP connect attempt succeeded",
                extraMetadata: [
                    "attempt_index": String(attemptIndex),
                    "max_attempts": String(policy.maxAttempts),
                    "path": outbound.pathSnapshot
                ]
            )
            finishReadyHandlers(with: .success(()))
        case .failure(let error):
            currentAttempt = nil
            log(
                level: .warning,
                event: "connect-attempt-failed",
                result: "attempt-\(attemptIndex)",
                errorCode: error.localizedDescription,
                message: "Outbound TCP connect attempt failed",
                extraMetadata: [
                    "attempt_index": String(attemptIndex),
                    "max_attempts": String(policy.maxAttempts),
                    "path": outbound.pathSnapshot
                ]
            )
            scheduleRetry(afterFailure: error, reason: "attempt-failed")
        }
    }

    private func scheduleRetry(afterFailure error: Error, reason: String) {
        guard !isCancelled, readyResult == nil else {
            return
        }
        guard currentAttemptIndex < policy.maxAttempts else {
            exhaustRetries(with: error, event: "connect-exhausted", reason: reason)
            return
        }
        if let overallElapsed = elapsedMilliseconds(since: startedAt),
           overallElapsed >= durationMilliseconds(policy.overallTimeout) {
            exhaustRetries(with: Socks5OutboundError.timedOut, event: "connect-overall-timeout", reason: reason)
            return
        }

        retryWorkItem?.cancel()
        let nextAttemptIndex = currentAttemptIndex + 1
        log(
            level: .notice,
            event: "connect-retry-scheduled",
            result: "attempt-\(nextAttemptIndex)",
            errorCode: error.localizedDescription,
            message: "Scheduling outbound TCP connect retry",
            extraMetadata: [
                "attempt_index": String(nextAttemptIndex),
                "max_attempts": String(policy.maxAttempts),
                "retry_backoff_ms": String(durationMilliseconds(policy.retryBackoff)),
                "retry_reason": reason
            ]
        )

        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.retryWorkItem = nil
            self.startAttempt(reason: reason)
        }
        retryWorkItem = workItem
        queue.asyncAfter(deadline: .now() + policy.retryBackoff, execute: workItem)
    }

    private func exhaustRetries(with error: Error, event: String, reason: String) {
        cancelScheduledWork()
        currentAttempt = nil
        log(
            level: .error,
            event: event,
            errorCode: error.localizedDescription,
            message: "Outbound TCP connect attempts exhausted",
            extraMetadata: [
                "attempt_index": String(currentAttemptIndex),
                "max_attempts": String(policy.maxAttempts),
                "retry_reason": reason
            ]
        )
        finishReadyHandlers(with: .failure(error))
    }

    private func cancelScheduledWork() {
        attemptTimeoutWorkItem?.cancel()
        attemptTimeoutWorkItem = nil
        overallTimeoutWorkItem?.cancel()
        overallTimeoutWorkItem = nil
        retryWorkItem?.cancel()
        retryWorkItem = nil
    }

    private func finishReadyHandlers(with result: Result<Void, Error>) {
        guard readyResult == nil else {
            return
        }
        cancelScheduledWork()
        readyResult = result
        let handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        for handler in handlers {
            handler(result)
        }
    }

    private func log(
        level: LogLevel,
        event: String,
        result: String? = nil,
        errorCode: String? = nil,
        message: String,
        extraMetadata: [String: String]
    ) {
        var metadata = extraMetadata
        if let attemptElapsed = elapsedMilliseconds(since: currentAttemptStartedAt) {
            metadata["attempt_elapsed_ms"] = String(attemptElapsed)
        }
        if let overallElapsed = elapsedMilliseconds(since: startedAt) {
            metadata["overall_elapsed_ms"] = String(overallElapsed)
        }
        Task {
            await logger.log(
                level: level,
                phase: .relay,
                category: .relayTCP,
                component: "RetryingTCPOutbound",
                event: event,
                result: result,
                errorCode: errorCode,
                message: message,
                metadata: metadata
            )
        }
    }
}

final class NWConnectionUDPSessionAdapter: @unchecked Sendable, Socks5UDPSession {
    private static let waitingLogMinimumInterval: TimeInterval = 10

    private let connection: NWConnection
    private let logger: StructuredLogger
    private var readHandler: (@Sendable (Data?, Error?) -> Void)?
    private var isCancelled = false
    var eventHandler: ((Socks5UDPSessionEvent) -> Void)?

    /// - Parameters:
    ///   - connection: Outbound UDP connection.
    ///   - queue: Queue used for callback delivery.
    ///   - logger: Structured logger for state changes.
    init(_ connection: NWConnection, queue: DispatchQueue, logger: StructuredLogger) {
        self.connection = connection
        self.logger = logger
        connection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state)
        }
        connection.pathUpdateHandler = { [weak self] path in
            self?.handlePathUpdate(path)
        }
        connection.viabilityUpdateHandler = { [weak self] isViable in
            self?.handleViabilityUpdate(isViable)
        }
        connection.betterPathUpdateHandler = { [weak self] betterPathAvailable in
            self?.handleBetterPathUpdate(betterPathAvailable)
        }
        // Docs: https://developer.apple.com/documentation/network/nwconnection/start(queue:)
        connection.start(queue: queue)
    }

    func setReadHandler(_ handler: @escaping @Sendable (Data?, Error?) -> Void) {
        readHandler = handler
        receiveNext()
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        let maximumDatagramSize = connection.maximumDatagramSize
        if maximumDatagramSize > 0, datagram.count > maximumDatagramSize {
            completionHandler(
                Socks5UDPDatagramError.exceedsMaximumDatagramSize(
                    datagramSize: datagram.count,
                    maximumDatagramSize: maximumDatagramSize,
                    pathSummary: pathSummary(connection.currentPath)
                )
            )
            return
        }
        connection.send(content: datagram, completion: .contentProcessed { error in
            completionHandler(error)
        })
    }

    func restart() {
        connection.restart()
    }

    func cancel() {
        isCancelled = true
        connection.cancel()
    }

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            eventHandler?(.ready)
        case .waiting(let error):
            eventHandler?(.waiting)
            Task {
                let path = pathSummary(connection.currentPath)
                await logger.logRateLimited(
                    key: "NWConnectionUDPSessionAdapter.waiting.\(error.localizedDescription).\(path)",
                    minimumInterval: Self.waitingLogMinimumInterval,
                    level: .warning,
                    phase: .relay,
                    category: .relayUDP,
                    component: "NWConnectionUDPSessionAdapter",
                    event: "waiting",
                    errorCode: error.localizedDescription,
                    message: "Outbound UDP waiting",
                    metadata: ["path": path]
                )
            }
        case .failed(let error):
            eventHandler?(.failed)
            Task {
                await logger.log(
                    level: .error,
                    phase: .relay,
                    category: .relayUDP,
                    component: "NWConnectionUDPSessionAdapter",
                    event: "failed",
                    errorCode: error.localizedDescription,
                    message: "Outbound UDP failed",
                    metadata: ["path": pathSummary(connection.currentPath)]
                )
            }
        default:
            break
        }
    }

    private func handlePathUpdate(_ path: Network.NWPath) {
        Task {
            await logger.log(
                level: .debug,
                phase: .path,
                category: .relayUDP,
                component: "NWConnectionUDPSessionAdapter",
                event: "path-update",
                result: pathStatusName(path.status),
                message: "Outbound UDP path updated",
                metadata: ["path": pathSummary(path)]
            )
        }
    }

    private func handleViabilityUpdate(_ isViable: Bool) {
        eventHandler?(.viabilityChanged(isViable))
        Task {
            await logger.log(
                level: .debug,
                phase: .path,
                category: .relayUDP,
                component: "NWConnectionUDPSessionAdapter",
                event: "viability-update",
                result: isViable ? "viable" : "not-viable",
                message: "Outbound UDP viability changed",
                metadata: ["path": pathSummary(connection.currentPath)]
            )
        }
    }

    private func handleBetterPathUpdate(_ betterPathAvailable: Bool) {
        guard betterPathAvailable else {
            return
        }
        eventHandler?(.betterPathAvailable)
        Task {
            await logger.log(
                level: .debug,
                phase: .path,
                category: .relayUDP,
                component: "NWConnectionUDPSessionAdapter",
                event: "better-path-available",
                result: "preferred-path",
                message: "Outbound UDP has a better path available",
                metadata: ["path": pathSummary(connection.currentPath)]
            )
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
                self.readHandler?(data, nil)
            }
            self.receiveNext()
        }
    }
}

/// Provider adapter that always uses Network.framework egress on supported deployment targets.
final class PacketTunnelProviderAdapter: @unchecked Sendable, Socks5FullConnectionProvider {
    private let provider: NEPacketTunnelProvider
    private let queue: DispatchQueue
    private let logger: StructuredLogger
    private let tcpPathSettings: Socks5TCPPathSettings

    /// - Parameters:
    ///   - provider: Active packet tunnel provider.
    ///   - queue: Queue for outbound Network.framework connection callbacks.
    ///   - logger: Structured logger for outbound path events.
    init(
        provider: NEPacketTunnelProvider,
        queue: DispatchQueue,
        logger: StructuredLogger,
        tcpPathSettings: Socks5TCPPathSettings = .default
    ) {
        self.provider = provider
        self.queue = queue
        self.logger = logger
        self.tcpPathSettings = tcpPathSettings
    }

    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound {
        _ = tlsParameters
        _ = delegate
        return makeNWConnection(to: endpoint, enableTLS: enableTLS)
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        makeNWUDPSession(to: endpoint)
    }

    private func makeNWConnection(to endpoint: NWHostEndpoint, enableTLS: Bool) -> Socks5TCPOutbound {
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue)
        else {
            return InvalidEndpointTCPOutbound(logger: logger, hostname: endpoint.hostname, port: endpoint.port)
        }

        return RetryingTCPOutbound(queue: queue, logger: logger, pathSettings: tcpPathSettings) { _ in
            return self.makeSingleNWConnection(host: endpoint.hostname, port: port, enableTLS: enableTLS)
        }
    }

    private func makeNWUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        guard let portValue = UInt16(endpoint.port),
              let port = NWEndpoint.Port(rawValue: portValue)
        else {
            return InvalidEndpointUDPSession(logger: logger, hostname: endpoint.hostname, port: endpoint.port)
        }

        let parameters = NWParameters.udp
        if #available(iOS 18.0, macOS 15.0, *) {
            // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
            if let virtualInterface = provider.virtualInterface {
                parameters.prohibitedInterfaces = [virtualInterface]
            }
        }

        let host = NWEndpoint.Host(endpoint.hostname)
        let connection = NWConnection(host: host, port: port, using: parameters)
        return NWConnectionUDPSessionAdapter(connection, queue: queue, logger: logger)
    }

    private func makeSingleNWConnection(host: String, port: Network.NWEndpoint.Port, enableTLS: Bool) -> Socks5PathAwareTCPOutbound {
        let parameters = enableTLS ? NWParameters.tls : NWParameters.tcp
        if let multipathServiceType = tcpPathSettings.multipathServiceType {
            parameters.multipathServiceType = multipathServiceType
        }
        if #available(iOS 18.0, macOS 15.0, *) {
            // Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
            if let virtualInterface = provider.virtualInterface {
                parameters.prohibitedInterfaces = [virtualInterface]
            }
        }

        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        return NWConnectionTCPAdapter(connection, queue: queue, logger: logger)
    }
}

private final class InvalidEndpointTCPOutbound: @unchecked Sendable, Socks5TCPOutbound {
    private let logger: StructuredLogger
    private let hostname: String
    private let port: String

    init(logger: StructuredLogger, hostname: String, port: String) {
        self.logger = logger
        self.hostname = hostname
        self.port = port
    }

    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void) {
        let error = Socks5OutboundError.failed("Invalid TCP endpoint \(hostname):\(port)")
        Task {
            await logger.log(
                level: .error,
                phase: .relay,
                category: .relayTCP,
                component: "InvalidEndpointTCPOutbound",
                event: "invalid-endpoint",
                errorCode: "invalid-port",
                message: "Refused outbound TCP connection because the endpoint was invalid",
                metadata: ["host": hostname, "port": port]
            )
        }
        completionHandler(.failure(error))
    }

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        _ = minimumLength
        _ = maximumLength
        completionHandler(nil, Socks5OutboundError.failed("Invalid TCP endpoint \(hostname):\(port)"))
    }

    func write(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        _ = data
        completionHandler(Socks5OutboundError.failed("Invalid TCP endpoint \(hostname):\(port)"))
    }

    func cancel() {}
}

private final class InvalidEndpointUDPSession: @unchecked Sendable, Socks5UDPSession {
    private let logger: StructuredLogger
    private let hostname: String
    private let port: String

    init(logger: StructuredLogger, hostname: String, port: String) {
        self.logger = logger
        self.hostname = hostname
        self.port = port
    }

    var eventHandler: ((Socks5UDPSessionEvent) -> Void)?

    func setReadHandler(_ handler: @escaping @Sendable (Data?, Error?) -> Void) {
        let logger = logger
        let hostname = hostname
        let port = port
        Task {
            await logger.log(
                level: .error,
                phase: .relay,
                category: .relayUDP,
                component: "InvalidEndpointUDPSession",
                event: "invalid-endpoint",
                errorCode: "invalid-port",
                message: "Refused outbound UDP session because the endpoint was invalid",
                metadata: ["host": hostname, "port": port]
            )
        }
        handler(nil, Socks5OutboundError.failed("Invalid UDP endpoint \(hostname):\(port)"))
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        _ = datagram
        completionHandler(Socks5OutboundError.failed("Invalid UDP endpoint \(hostname):\(port)"))
    }

    func restart() {}

    func cancel() {}
}

public enum Socks5ServerError: Error {
    case invalidPort
}

/// Local SOCKS5 server that handles CONNECT and UDP ASSOCIATE from the dataplane.
/// Queue ownership: listener state and `connections` map are mutated on `queue`.
public final class Socks5Server: @unchecked Sendable {
    private enum ServerPolicy {
        static let maxConnections = 1024
    }

    private let logger: StructuredLogger
    private let queue: DispatchQueue
    private let mtu: Int
    private let makeConnectionQueue: @Sendable () -> DispatchQueue
    private let providerFactory: @Sendable (DispatchQueue) -> Socks5FullConnectionProvider
    private let queueSpecificKey = DispatchSpecificKey<UInt8>()

    private var listener: NWListener?
    private var connections: [ObjectIdentifier: Socks5Connection] = [:]

    /// - Parameters:
    ///   - provider: Outbound connection provider implementation.
    ///   - queue: Serial queue used for listener + connection events.
    ///   - mtu: MTU hint forwarded to UDP relay handlers.
    ///   - logger: Structured logger for server lifecycle and failures.
    init(provider: Socks5FullConnectionProvider, queue: DispatchQueue, mtu: Int, logger: StructuredLogger) {
        self.providerFactory = { _ in provider }
        self.makeConnectionQueue = { queue }
        self.queue = queue
        self.mtu = mtu
        self.logger = logger
        self.queue.setSpecific(key: queueSpecificKey, value: 1)
    }

    private init(
        queue: DispatchQueue,
        mtu: Int,
        logger: StructuredLogger,
        makeConnectionQueue: @escaping @Sendable () -> DispatchQueue,
        providerFactory: @escaping @Sendable (DispatchQueue) -> Socks5FullConnectionProvider
    ) {
        self.queue = queue
        self.mtu = mtu
        self.logger = logger
        self.makeConnectionQueue = makeConnectionQueue
        self.providerFactory = providerFactory
        self.queue.setSpecific(key: queueSpecificKey, value: 1)
    }

    /// Convenience initializer that binds server egress to `NEPacketTunnelProvider`.
    /// - Parameters:
    ///   - provider: Active packet tunnel provider.
    ///   - queue: Serial queue for listener + connection events.
    ///   - mtu: MTU hint used by UDP relay.
    ///   - logger: Structured logger.
    public convenience init(
        provider: NEPacketTunnelProvider,
        queue: DispatchQueue,
        mtu: Int,
        logger: StructuredLogger,
        tcpPathSettings: Socks5TCPPathSettings = .default
    ) {
        let connectionQueueLabelPrefix = queue.label.isEmpty ? "com.vpnbridge.tunnel.relay.session" : "\(queue.label).session"
        self.init(
            queue: queue,
            mtu: mtu,
            logger: logger,
            makeConnectionQueue: {
                DispatchQueue(label: "\(connectionQueueLabelPrefix).\(UUID().uuidString)", qos: .userInitiated)
            },
            providerFactory: { connectionQueue in
                PacketTunnelProviderAdapter(
                    provider: provider,
                    queue: connectionQueue,
                    logger: logger,
                    tcpPathSettings: tcpPathSettings
                )
            }
        )
    }

    /// Starts SOCKS5 listening on loopback.
    /// - Parameters:
    ///   - port: Requested local port (`0` chooses random ephemeral).
    ///   - completion: Called once with actual bound port or startup error.
    public func start(port: UInt16, completion: @escaping @Sendable (Result<UInt16, Error>) -> Void) {
        let initialPort = port == 0 ? pickEphemeralPort() : port
        startListener(port: initialPort, remainingAttempts: 3, completion: completion)
    }

    /// Stops listener and all active SOCKS sessions.
    public func stop() {
        performOnQueue {
            self.listener?.cancel()
            self.listener = nil
            let sessions = Array(self.connections.values)
            self.connections.removeAll()
            sessions.forEach { $0.stop() }
        }
    }

    private func startListener(port: UInt16, remainingAttempts: Int, completion: @escaping @Sendable (Result<UInt16, Error>) -> Void) {
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
            // Docs: https://developer.apple.com/documentation/network/nwlistener/init(using:on:)
            listener = try NWListener(using: parameters, on: .any)
        } catch {
            Task {
                await logger.log(
                    level: .error,
                    phase: .relay,
                    category: .relayTCP,
                    component: "Socks5Server",
                    event: "listener-create-failed",
                    errorCode: String(describing: error),
                    message: "Failed to create SOCKS5 listener",
                    metadata: ["port": String(port)]
                )
            }
            completion(.failure(error))
            return
        }

        self.listener = listener

        let completionGate = CompletionGate()
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if completionGate.beginCompletion() {
                    completion(.success(listener.port?.rawValue ?? port))
                }
                Task {
                    await self.logger.log(
                        level: .info,
                        phase: .relay,
                        category: .relayTCP,
                        component: "Socks5Server",
                        event: "listener-ready",
                        message: "SOCKS5 listener ready",
                        metadata: ["port": String(listener.port?.rawValue ?? port)]
                    )
                }
            case .failed(let error):
                if self.isAddressInUse(error), remainingAttempts > 0 {
                    _ = completionGate.beginCompletion()
                    listener.cancel()
                    self.listener = nil
                    let nextPort = self.pickEphemeralPort()
                    Task {
                        await self.logger.log(
                            level: .warning,
                            phase: .relay,
                            category: .relayTCP,
                            component: "Socks5Server",
                            event: "listener-port-retry",
                            errorCode: error.localizedDescription,
                            message: "SOCKS5 listener port was already in use; retrying on another port",
                            metadata: [
                                "failed_port": String(port),
                                "next_port": String(nextPort),
                                "remaining_attempts": String(remainingAttempts - 1)
                            ]
                        )
                    }
                    self.startListener(port: nextPort, remainingAttempts: remainingAttempts - 1, completion: completion)
                    return
                }
                if completionGate.beginCompletion() {
                    completion(.failure(error))
                }
                Task {
                    await self.logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayTCP,
                        component: "Socks5Server",
                        event: "listener-failed",
                        errorCode: error.localizedDescription,
                        message: "SOCKS5 listener failed"
                    )
                }
            case .waiting(let error):
                Task {
                    await self.logger.log(
                        level: .warning,
                        phase: .relay,
                        category: .relayTCP,
                        component: "Socks5Server",
                        event: "listener-waiting",
                        errorCode: error.localizedDescription,
                        message: "SOCKS5 listener waiting"
                    )
                }
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            guard self.connections.count < ServerPolicy.maxConnections else {
                connection.cancel()
                Task {
                    await self.logger.log(
                        level: .warning,
                        phase: .relay,
                        category: .relayTCP,
                        component: "Socks5Server",
                        event: "connection-limit-reached",
                        result: "rejected",
                        message: "Rejected inbound SOCKS5 connection because the server connection cap is reached",
                        metadata: [
                            "active_connections": String(self.connections.count),
                            "max_connections": String(ServerPolicy.maxConnections)
                        ]
                    )
                }
                return
            }
            let connectionQueue = self.makeConnectionQueue()
            let session = Socks5Connection(
                connection: SocksInboundNWConnectionAdapter(connection),
                provider: self.providerFactory(connectionQueue),
                queue: connectionQueue,
                mtu: self.mtu,
                logger: self.logger
            )
            session.onClose = { [weak self] in
                self?.performOnQueue {
                    self?.connections.removeValue(forKey: ObjectIdentifier(connection))
                }
            }
            self.connections[ObjectIdentifier(connection)] = session
            session.start()
        }

        // Docs: https://developer.apple.com/documentation/network/nwlistener/start(queue:)
        listener.start(queue: queue)
    }

    private func pickEphemeralPort() -> UInt16 {
        UInt16.random(in: 49_152 ... 65_535)
    }

    private func isAddressInUse(_ error: NWError) -> Bool {
        switch error {
        case .posix(let code):
            return code == .EADDRINUSE
        default:
            return false
        }
    }

    private func performOnQueue(_ work: @escaping () -> Void) {
        if DispatchQueue.getSpecific(key: queueSpecificKey) != nil {
            work()
        } else {
            queue.sync(execute: work)
        }
    }
}

/// One-shot gate used by `NWListener` callbacks to ensure startup completion fires at most once.
/// Safety invariant: `stateUpdateHandler` may be invoked concurrently, so the flag is protected by `lock`.
private final class CompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var didComplete = false

    func beginCompletion() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !didComplete else {
            return false
        }
        didComplete = true
        return true
    }
}

/// Per-client SOCKS connection state machine.
/// Invariant: transitions are serialized by callbacks running on `queue`.
final class Socks5Connection: @unchecked Sendable {
    private enum ConnectionPolicy {
        static let maxBufferedBytes = 256 * 1024
    }

    private enum State {
        case greeting
        case request
        case connectingTCP(Socks5TCPOutbound)
        case tcpProxy(Socks5TCPOutbound)
        case udpProxy(Socks5UDPRelayProtocol)
    }

    private let logger: StructuredLogger
    private let connection: Socks5InboundConnection
    private let provider: Socks5FullConnectionProvider
    private let queue: DispatchQueue
    private let queueSpecificKey = DispatchSpecificKey<UInt8>()
    private let mtu: Int
    private let udpRelayFactory: (Socks5ConnectionProvider, DispatchQueue, Int, StructuredLogger) throws -> Socks5UDPRelayProtocol

    private var buffer = Data()
    private var state: State = .greeting
    private var isClosed = false
    private var inboundReceiveArmed = false
    private var outboundReadArmed = false
    private var outboundWriteInFlight = false
    private var inboundSendInFlight = false

    var onClose: (() -> Void)?

    /// - Parameters:
    ///   - connection: Accepted inbound SOCKS connection.
    ///   - provider: Outbound connection provider.
    ///   - queue: Queue for callback-driven state transitions.
    ///   - mtu: MTU hint passed into UDP relay.
    ///   - logger: Structured logger for connection lifecycle.
    ///   - udpRelayFactory: Factory override used by tests.
    init(
        connection: Socks5InboundConnection,
        provider: Socks5FullConnectionProvider,
        queue: DispatchQueue,
        mtu: Int,
        logger: StructuredLogger,
        udpRelayFactory: @escaping (Socks5ConnectionProvider, DispatchQueue, Int, StructuredLogger) throws -> Socks5UDPRelayProtocol = {
            try Socks5UDPRelay(provider: $0, queue: $1, mtu: $2, logger: $3)
        }
    ) {
        self.connection = connection
        self.provider = provider
        self.queue = queue
        self.mtu = mtu
        self.logger = logger
        self.udpRelayFactory = udpRelayFactory
        self.queue.setSpecific(key: queueSpecificKey, value: 1)
    }

    /// Starts handshake processing for inbound SOCKS connection.
    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed(let error):
                Task {
                    await self.logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayTCP,
                        component: "Socks5Connection",
                        event: "connection-failed",
                        errorCode: error.localizedDescription,
                        message: "SOCKS5 inbound connection failed"
                    )
                }
                self.stop()
            case .cancelled:
                self.stop()
            default:
                break
            }
        }
        connection.start(queue: queue)
        armInboundReceiveIfNeeded()
    }

    /// Idempotently closes this connection and any outbound resources.
    func stop() {
        runOnQueue { [weak self] in
            self?.stopOnQueue()
        }
    }

    private func stopOnQueue() {
        guard !isClosed else { return }
        isClosed = true
        switch state {
        case .connectingTCP(let outbound):
            outbound.cancel()
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

    private func armInboundReceiveIfNeeded() {
        guard !inboundReceiveArmed, shouldReadInbound else {
            return
        }

        inboundReceiveArmed = true
        connection.receive(minimumIncompleteLength: 1, maximumLength: max(65_535, mtu + 256)) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.runOnQueue {
                guard !self.isClosed else { return }
                self.inboundReceiveArmed = false

                if let data, !data.isEmpty {
                    guard self.admitInboundBufferBytes(data.count) else {
                        return
                    }
                    self.buffer.append(data)
                    self.processBuffer()
                }
                if let error {
                    self.logInboundReadFailure(error)
                    self.stop()
                    return
                }
                if isComplete {
                    self.stop()
                    return
                }

                self.armInboundReceiveIfNeeded()
            }
        }
    }

    private var shouldReadInbound: Bool {
        switch state {
        case .connectingTCP:
            return !isClosed
        case .tcpProxy:
            return !outboundWriteInFlight
        default:
            return !isClosed
        }
    }

    private func processBuffer() {
        switch state {
        case .greeting:
            guard let methods = Socks5Codec.parseGreeting(&buffer) else { return }
            let method: UInt8 = methods.contains(0x00) ? 0x00 : 0xFF
            connection.send(content: Socks5Codec.buildMethodSelection(method: method), completion: .contentProcessed { [weak self] error in
                guard let self, let error else { return }
                self.runOnQueue {
                    guard !self.isClosed else { return }
                    self.logInboundWriteFailure(error, event: "greeting-write-failed", message: "SOCKS5 greeting reply write failed")
                    self.stop()
                }
            })
            if method == 0x00 {
                state = .request
                processBuffer()
            } else {
                stop()
            }
        case .request:
            guard let request = Socks5Codec.parseRequest(&buffer) else { return }
            handleRequest(request)
        case .connectingTCP:
            // RFC 1928 requires the server reply before payload forwarding.
            // Any pipelined client bytes are buffered until the outbound channel is ready.
            return
        case .tcpProxy(let outbound):
            guard !buffer.isEmpty, !outboundWriteInFlight else {
                return
            }

            let payload = buffer
            buffer.removeAll(keepingCapacity: false)
            outboundWriteInFlight = true
            forwardToOutbound(payload, outbound: outbound)
        case .udpProxy:
            buffer.removeAll()
        }
    }

    private func admitInboundBufferBytes(_ byteCount: Int) -> Bool {
        guard buffer.count + byteCount <= ConnectionPolicy.maxBufferedBytes else {
            Task {
                await logger.log(
                    level: .warning,
                    phase: .relay,
                    category: .relayTCP,
                    component: "Socks5Connection",
                    event: "inbound-buffer-limit-reached",
                    result: "closed",
                    message: "Closing SOCKS5 connection because inbound buffering exceeded the per-session cap",
                    metadata: [
                        "buffered_bytes": String(buffer.count),
                        "incoming_bytes": String(byteCount),
                        "max_buffered_bytes": String(ConnectionPolicy.maxBufferedBytes)
                    ]
                )
            }
            stop()
            return false
        }
        return true
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
        let outbound = provider.makeTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)

        state = .connectingTCP(outbound)
        outbound.waitUntilReady { [weak self] result in
            guard let self else { return }
            self.runOnQueue {
                guard !self.isClosed else { return }
                switch result {
                case .success:
                    guard case .connectingTCP(let activeOutbound) = self.state,
                          activeOutbound === outbound else {
                        outbound.cancel()
                        return
                    }
                    self.state = .tcpProxy(outbound)
                    self.connection.send(
                        content: Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("0.0.0.0"), bindPort: 0),
                        completion: .contentProcessed { [weak self] error in
                            guard let self else { return }
                            self.runOnQueue {
                                guard !self.isClosed else { return }
                                if let error {
                                    self.logInboundWriteFailure(
                                        error,
                                        event: "connect-reply-write-failed",
                                        message: "SOCKS5 connect success reply write failed"
                                    )
                                    self.stop()
                                    return
                                }
                                self.armOutboundReadIfNeeded(outbound)
                                self.processBuffer()
                                self.armInboundReceiveIfNeeded()
                            }
                        }
                    )
                case .failure(let error):
                    Task {
                        await self.logger.log(
                            level: .error,
                            phase: .relay,
                            category: .relayTCP,
                            component: "Socks5Connection",
                            event: "outbound-connect-failed",
                            errorCode: error.localizedDescription,
                            message: "SOCKS5 outbound connect failed"
                        )
                    }
                    self.sendFailure(replyCode: 0x05)
                }
            }
        }
    }

    private func armOutboundReadIfNeeded(_ outbound: Socks5TCPOutbound) {
        guard !outboundReadArmed, !inboundSendInFlight else {
            return
        }
        guard case .tcpProxy(let activeOutbound) = state,
              activeOutbound === outbound,
              !isClosed else {
            return
        }

        outboundReadArmed = true
        outbound.readMinimumLength(1, maximumLength: 65_535) { [weak self] data, error in
            guard let self else { return }
            self.runOnQueue {
                guard !self.isClosed else { return }
                self.outboundReadArmed = false

                if let data, !data.isEmpty {
                    self.forwardToInbound(data, outbound: outbound)
                    return
                } else if let error {
                    self.logOutboundReadError(error)
                    self.stop()
                    return
                } else if data == nil {
                    self.stop()
                    return
                }

                self.armOutboundReadIfNeeded(outbound)
            }
        }
    }

    private func logOutboundReadError(_ error: any Error) {
        let benignRemoteClose = Self.isBenignOutboundReadClose(error)
        Task {
            await logger.log(
                level: benignRemoteClose ? .notice : .error,
                phase: .relay,
                category: .relayTCP,
                component: "Socks5Connection",
                event: benignRemoteClose ? "outbound-read-closed" : "outbound-read-failed",
                errorCode: error.localizedDescription,
                message: benignRemoteClose ? "SOCKS5 outbound read closed" : "SOCKS5 outbound read failed"
            )
        }
    }

    private static func isBenignOutboundReadClose(_ error: any Error) -> Bool {
        guard let nwError = error as? NWError,
              case .posix(let code) = nwError else {
            return false
        }
        return code == .ENOMSG
    }

    private func forwardToOutbound(_ data: Data, outbound: Socks5TCPOutbound) {
        outbound.write(data) { [weak self] error in
            guard let self else { return }
            self.runOnQueue {
                guard !self.isClosed else { return }
                self.outboundWriteInFlight = false
                if let error {
                    Task {
                        await self.logger.log(
                            level: .error,
                            phase: .relay,
                            category: .relayTCP,
                            component: "Socks5Connection",
                            event: "outbound-write-failed",
                            errorCode: error.localizedDescription,
                            message: "SOCKS5 outbound write failed"
                        )
                    }
                    self.stop()
                    return
                }

                self.processBuffer()
                self.armInboundReceiveIfNeeded()
            }
        }
    }

    private func forwardToInbound(_ data: Data, outbound: Socks5TCPOutbound) {
        inboundSendInFlight = true
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.runOnQueue {
                guard !self.isClosed else { return }
                self.inboundSendInFlight = false
                if let error {
                    Task {
                        await self.logger.log(
                            level: .error,
                            phase: .relay,
                            category: .relayTCP,
                            component: "Socks5Connection",
                            event: "inbound-write-failed",
                            errorCode: error.localizedDescription,
                            message: "SOCKS5 inbound write failed"
                        )
                    }
                    self.stop()
                    return
                }

                self.armOutboundReadIfNeeded(outbound)
            }
        })
    }

    private func logInboundReadFailure(_ error: Error) {
        Task {
            await logger.log(
                level: .error,
                phase: .relay,
                category: .relayTCP,
                component: "Socks5Connection",
                event: "inbound-read-failed",
                errorCode: error.localizedDescription,
                message: "SOCKS5 inbound read failed"
            )
        }
    }

    private func logInboundWriteFailure(_ error: Error, event: String, message: String) {
        Task {
            await logger.log(
                level: .error,
                phase: .relay,
                category: .relayTCP,
                component: "Socks5Connection",
                event: event,
                errorCode: error.localizedDescription,
                message: message
            )
        }
    }

    private func runOnQueue(_ block: @escaping @Sendable () -> Void) {
        if DispatchQueue.getSpecific(key: queueSpecificKey) != nil {
            block()
        } else {
            queue.async(execute: block)
        }
    }

    private func startUDPRelay() {
        do {
            let relay = try udpRelayFactory(provider, queue, mtu, logger)
            relay.start()
            state = .udpProxy(relay)
            connection.send(
                content: Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("127.0.0.1"), bindPort: relay.port),
                completion: .contentProcessed { _ in }
            )
        } catch {
            Task {
                await logger.log(
                    level: .error,
                    phase: .relay,
                    category: .relayUDP,
                    component: "Socks5Connection",
                    event: "udp-relay-failed",
                    errorCode: String(describing: error),
                    message: "SOCKS5 UDP relay failed"
                )
            }
            sendFailure()
        }
    }

    private func sendFailure(replyCode: UInt8 = 0x01) {
        connection.send(
            content: Socks5Codec.buildReply(code: replyCode, bindAddress: .ipv4("0.0.0.0"), bindPort: 0),
            completion: .contentProcessed { _ in }
        )
        stop()
    }
}
