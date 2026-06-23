// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Darwin
import Foundation
import Network
@preconcurrency import NetworkExtension
import Observability

/// One deterministic relay fault case executed by `Socks5FaultInjectionRunner`.
public struct Socks5FaultInjectionRow: Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let fault: String
    public let expectedBehavior: String
    public let passed: Bool
    public let durationMs: Int
    public let detail: String

    public var statusText: String {
        passed ? "PASS" : "FAIL"
    }
}

/// Summary from one local relay fault-injection run.
public struct Socks5FaultInjectionReport: Equatable, Sendable {
    public let startedAt: Date
    public let completedAt: Date
    public let rows: [Socks5FaultInjectionRow]

    public var passed: Bool {
        !rows.isEmpty && rows.allSatisfy(\.passed)
    }

    public var failedRows: Int {
        rows.filter { !$0.passed }.count
    }

    public var summaryText: String {
        passed ? "PASS · \(rows.count) faults" : "FAIL · \(failedRows)/\(rows.count) faults"
    }
}

/// Runs deterministic local relay faults without requiring the physical network to reproduce them.
public final class Socks5FaultInjectionRunner: @unchecked Sendable {
    public init() {}

    public func run() -> Socks5FaultInjectionReport {
        let startedAt = Date()
        let rows = [
            runScenario(
                id: "tcp-waiting-default",
                name: "TCP waiting",
                fault: "Repeated connect waiting events",
                expectedBehavior: "No manual restart; existing attempt can recover",
                body: tcpWaitingDefaultRecovery
            ),
            runScenario(
                id: "tcp-waiting-timeout-retry",
                name: "TCP waiting timeout",
                fault: "Connect waits past attempt timeout",
                expectedBehavior: "Cancel stale attempt and retry within the overall budget",
                body: tcpWaitingTimeoutRetry
            ),
            runScenario(
                id: "tcp-waiting-bounded-restart",
                name: "TCP restart budget",
                fault: "Opt-in waiting restarts receive a burst of waiting events",
                expectedBehavior: "At most one restart per attempt",
                body: tcpWaitingRestartBudget
            ),
            runScenario(
                id: "udp-waiting-replaced",
                name: "UDP waiting",
                fault: "Direct UDP session reports waiting repeatedly",
                expectedBehavior: "Schedule replacement and rotate on the next datagram",
                body: directUDPWaitingReplaced
            ),
            runScenario(
                id: "udp-failed-recreated",
                name: "UDP failed",
                fault: "Direct UDP session reports failed",
                expectedBehavior: "Remove it and create a fresh session on the next datagram",
                body: directUDPFailedRecreated
            ),
            runScenario(
                id: "udp-better-path-replaced",
                name: "UDP better path",
                fault: "Direct UDP session reports a better path",
                expectedBehavior: "Schedule replacement and rotate on the next datagram",
                body: directUDPBetterPathReplaced
            ),
            runScenario(
                id: "tcp-forward-udp-waiting-replaced",
                name: "TCP-carried UDP waiting",
                fault: "TCP-carried UDP session reports waiting repeatedly",
                expectedBehavior: "Schedule replacement and rotate on the next UDP frame",
                body: tcpForwardUDPWaitingReplaced
            ),
            runScenario(
                id: "tcp-forward-udp-better-path-replaced",
                name: "TCP-carried UDP better path",
                fault: "TCP-carried UDP session reports a better path",
                expectedBehavior: "Schedule replacement and rotate on the next UDP frame",
                body: tcpForwardUDPBetterPathReplaced
            )
        ]
        return Socks5FaultInjectionReport(startedAt: startedAt, completedAt: Date(), rows: rows)
    }

    private func runScenario(
        id: String,
        name: String,
        fault: String,
        expectedBehavior: String,
        body: () throws -> String
    ) -> Socks5FaultInjectionRow {
        let startedAt = Date()
        do {
            return Socks5FaultInjectionRow(
                id: id,
                name: name,
                fault: fault,
                expectedBehavior: expectedBehavior,
                passed: true,
                durationMs: Self.elapsedMilliseconds(since: startedAt),
                detail: try body()
            )
        } catch {
            return Socks5FaultInjectionRow(
                id: id,
                name: name,
                fault: fault,
                expectedBehavior: expectedBehavior,
                passed: false,
                durationMs: Self.elapsedMilliseconds(since: startedAt),
                detail: error.localizedDescription
            )
        }
    }

    private func tcpWaitingDefaultRecovery() throws -> String {
        let queue = DispatchQueue(label: "com.vpnbridge.fault.tcp-waiting-default")
        let attempt = FaultTCPOutbound()
        let ready = FaultCompletionBox<Void>()
        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: Self.logger(),
            policy: .init(attemptPreparingTimeout: 1.0, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 2.0)
        ) { _ in
            attempt
        }

        outbound.waitUntilReady { result in
            ready.resume(result)
        }
        queue.sync {
            for _ in 0..<8 {
                attempt.emit(.waiting)
            }
        }
        queue.sync {}
        try require(attempt.restartCount == 0, "default waiting policy restarted \(attempt.restartCount) times")
        attempt.succeedConnect()
        try ready.wait(timeoutSeconds: 1.0)
        return "Observed 8 waiting events, 0 restarts, then recovered on the same TCP attempt."
    }

    private func tcpWaitingTimeoutRetry() throws -> String {
        let queue = DispatchQueue(label: "com.vpnbridge.fault.tcp-waiting-timeout")
        let attempts = LockedBox<[FaultTCPOutbound]>([])
        let secondAttemptCreated = FaultCompletionBox<Void>()
        let ready = FaultCompletionBox<Void>()
        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: Self.logger(),
            policy: .init(attemptPreparingTimeout: 0.05, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 0.4)
        ) { attemptIndex in
            let attempt = FaultTCPOutbound()
            attempts.withValue { $0.append(attempt) }
            if attemptIndex == 2 {
                secondAttemptCreated.resume(.success(()))
            }
            return attempt
        }

        outbound.waitUntilReady { result in
            ready.resume(result)
        }
        queue.sync {
            attempts.value.first?.emit(.waiting)
        }
        queue.sync {}
        try secondAttemptCreated.wait(timeoutSeconds: 1.0)
        attempts.value.last?.succeedConnect()
        try ready.wait(timeoutSeconds: 1.0)
        let snapshot = attempts.value
        try require(snapshot.count == 2, "expected 2 TCP attempts, saw \(snapshot.count)")
        try require(snapshot.first?.restartCount == 0, "waiting timeout path restarted the stale attempt")
        try require(snapshot.first?.cancelled == true, "stale waiting TCP attempt was not cancelled")
        return "Timed-out waiting attempt was cancelled and a second TCP attempt connected."
    }

    private func tcpWaitingRestartBudget() throws -> String {
        let queue = DispatchQueue(label: "com.vpnbridge.fault.tcp-waiting-budget")
        let attempt = FaultTCPOutbound()
        let ready = FaultCompletionBox<Void>()
        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: Self.logger(),
            policy: .init(attemptPreparingTimeout: 1.0, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 2.0),
            pathSettings: .init(
                retryOnBetterPathDuringConnect: true,
                restartWaitingConnectionsDuringConnect: true,
                maximumWaitingRestartsPerAttempt: 1,
                waitingRestartMinimumInterval: 0.0,
                betterPathRetryMinimumElapsed: 0.0,
                multipathServiceType: nil
            )
        ) { _ in
            attempt
        }

        outbound.waitUntilReady { result in
            ready.resume(result)
        }
        queue.sync {
            for _ in 0..<20 {
                attempt.emit(.waiting)
            }
        }
        queue.sync {}
        try require(attempt.restartCount == 1, "restart budget allowed \(attempt.restartCount) restarts")
        attempt.succeedConnect()
        try ready.wait(timeoutSeconds: 1.0)
        return "Opt-in restart path capped 20 waiting events at 1 manual restart."
    }

    private func directUDPWaitingReplaced() throws -> String {
        let context = try DirectUDPContext(label: "com.vpnbridge.fault.udp-waiting")
        defer { context.stop() }

        try context.sendDatagram()
        let session = try context.waitForSession(index: 0)
        context.queue.sync {
            for _ in 0..<5 {
                session.eventHandler?(.waiting)
            }
        }
        try require(session.restartCount == 0, "UDP waiting restarted the session")
        try require(!session.cancelled, "UDP waiting cancelled before replacement datagram")

        try context.sendDatagram()
        let replacement = try context.waitForSession(index: 1)
        try require(session.cancelled, "old UDP waiting session was not cancelled during replacement")
        try require(session !== replacement, "UDP waiting replacement reused the old session")
        try context.waitForWrittenDatagrams(session: replacement, count: 1)
        return "Direct UDP scheduled waiting replacement and rotated on the next datagram."
    }

    private func directUDPFailedRecreated() throws -> String {
        let context = try DirectUDPContext(label: "com.vpnbridge.fault.udp-failed")
        defer { context.stop() }

        try context.sendDatagram()
        let firstSession = try context.waitForSession(index: 0)
        context.queue.sync {
            firstSession.eventHandler?(.failed)
        }
        try require(firstSession.cancelled, "failed UDP session was not cancelled")

        try context.sendDatagram()
        let secondSession = try context.waitForSession(index: 1)
        try require(firstSession !== secondSession, "UDP failure reused the failed session")
        try context.waitForWrittenDatagrams(session: secondSession, count: 1)
        return "Direct UDP removed the failed session and recreated it on the next datagram."
    }

    private func directUDPBetterPathReplaced() throws -> String {
        let context = try DirectUDPContext(label: "com.vpnbridge.fault.udp-better-path")
        defer { context.stop() }

        try context.sendDatagram()
        let firstSession = try context.waitForSession(index: 0)
        context.queue.sync {
            firstSession.eventHandler?(.betterPathAvailable)
            firstSession.eventHandler?(.betterPathAvailable)
        }
        try require(!firstSession.cancelled, "better-path signal cancelled UDP before replacement datagram")

        try context.sendDatagram()
        let secondSession = try context.waitForSession(index: 1)
        try require(firstSession.cancelled, "old UDP session was not cancelled during replacement")
        try require(firstSession !== secondSession, "UDP better-path replacement reused the old session")
        try context.waitForWrittenDatagrams(session: secondSession, count: 1)
        return "Direct UDP deferred better-path replacement until the next datagram."
    }

    private func tcpForwardUDPWaitingReplaced() throws -> String {
        let context = try TCPForwardUDPContext(label: "com.vpnbridge.fault.forward-udp-waiting")
        defer { context.stop() }

        try context.sendFrame()
        let session = try context.waitForSession(index: 0)
        context.queue.sync {
            for _ in 0..<5 {
                session.eventHandler?(.waiting)
            }
        }
        try require(!session.cancelled, "TCP-carried UDP waiting cancelled before replacement frame")

        try context.sendFrame()
        let replacement = try context.waitForSession(index: 1)
        try require(session.cancelled, "old TCP-carried UDP waiting session was not cancelled during replacement")
        try require(session !== replacement, "TCP-carried UDP waiting replacement reused the old session")
        try require(replacement.writtenDatagrams.count == 1, "replacement TCP-carried UDP waiting session did not receive the frame")
        return "TCP-carried UDP scheduled waiting replacement and rotated on the next frame."
    }

    private func tcpForwardUDPBetterPathReplaced() throws -> String {
        let context = try TCPForwardUDPContext(label: "com.vpnbridge.fault.forward-udp-better-path")
        defer { context.stop() }

        try context.sendFrame()
        let firstSession = try context.waitForSession(index: 0)
        context.queue.sync {
            firstSession.eventHandler?(.betterPathAvailable)
            firstSession.eventHandler?(.betterPathAvailable)
        }
        try require(!firstSession.cancelled, "TCP-carried UDP better-path cancelled before replacement frame")

        try context.sendFrame()
        let secondSession = try context.waitForSession(index: 1)
        try require(firstSession.cancelled, "old TCP-carried UDP session was not cancelled during replacement")
        try require(firstSession !== secondSession, "TCP-carried UDP replacement reused the old session")
        try require(secondSession.writtenDatagrams.count == 1, "replacement TCP-carried UDP session did not receive the frame")
        return "TCP-carried UDP deferred better-path replacement until the next frame."
    }

    fileprivate static func logger() -> StructuredLogger {
        StructuredLogger(sink: InMemoryLogSink())
    }

    private static func elapsedMilliseconds(since start: Date) -> Int {
        clampedMilliseconds(Date().timeIntervalSince(start))
    }

    private func require(_ condition: Bool, _ message: String) throws {
        if !condition {
            throw FaultInjectionError(message)
        }
    }
}

private func clampedMilliseconds(_ interval: TimeInterval) -> Int {
    guard interval.isFinite, interval > 0 else {
        return 0
    }
    let milliseconds = (interval * 1_000).rounded()
    guard milliseconds.isFinite else {
        return Int.max
    }
    if milliseconds >= Double(Int.max) {
        return Int.max
    }
    return Int(milliseconds)
}

private struct FaultInjectionError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? {
        message
    }
}

private final class FaultCompletionBox<T>: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var result: Result<T, Error>?

    func resume(_ result: Result<T, Error>) {
        lock.lock()
        guard self.result == nil else {
            lock.unlock()
            return
        }
        self.result = result
        lock.unlock()
        semaphore.signal()
    }

    func wait(timeoutSeconds: TimeInterval) throws -> T {
        let deadline = DispatchTime.now() + timeoutSeconds
        guard semaphore.wait(timeout: deadline) == .success else {
            throw FaultInjectionError("timed out waiting for fault-injection completion")
        }
        lock.lock()
        let result = self.result
        lock.unlock()
        guard let result else {
            throw FaultInjectionError("fault-injection completion was missing")
        }
        return try result.get()
    }
}

private final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue: T

    init(_ value: T) {
        self.storedValue = value
    }

    var value: T {
        lock.lock()
        defer { lock.unlock() }
        return storedValue
    }

    func withValue(_ update: (inout T) -> Void) {
        lock.lock()
        update(&storedValue)
        lock.unlock()
    }
}

private final class FaultTCPOutbound: @unchecked Sendable, Socks5PathAwareTCPOutbound {
    private let lock = NSLock()
    private var readyHandlers: [(@Sendable (Result<Void, Error>) -> Void)] = []
    private var readyResult: Result<Void, Error>?
    private var storedCancelled = false
    private var storedRestartCount = 0
    private var storedEventHandler: ((TCPOutboundEvent) -> Void)?
    var pathSnapshot = "status=unsatisfied uses=wifi expensive=false constrained=false"

    var cancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storedCancelled
    }

    var restartCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedRestartCount
    }

    var eventHandler: ((TCPOutboundEvent) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedEventHandler
        }
        set {
            lock.lock()
            storedEventHandler = newValue
            lock.unlock()
        }
    }

    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void) {
        lock.lock()
        if let readyResult {
            lock.unlock()
            completionHandler(readyResult)
            return
        }
        readyHandlers.append(completionHandler)
        lock.unlock()
    }

    func readMinimumLength(
        _: Int,
        maximumLength _: Int,
        completionHandler _: @escaping @Sendable (Data?, Error?) -> Void
    ) {}

    func write(_ data: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        _ = data
        completionHandler(nil)
    }

    func finishWriting(completionHandler: @escaping @Sendable (Error?) -> Void) {
        completionHandler(nil)
    }

    func cancel() {
        lock.lock()
        storedCancelled = true
        lock.unlock()
    }

    func restart() {
        lock.lock()
        storedRestartCount += 1
        lock.unlock()
    }

    func succeedConnect() {
        complete(.success(()))
    }

    func emit(_ event: TCPOutboundEvent) {
        let handler = eventHandler
        handler?(event)
    }

    private func complete(_ result: Result<Void, Error>) {
        lock.lock()
        guard readyResult == nil else {
            lock.unlock()
            return
        }
        readyResult = result
        let handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        lock.unlock()
        for handler in handlers {
            handler(result)
        }
    }
}

private final class FaultUDPSession: @unchecked Sendable, Socks5UDPSession {
    let endpoint: NWHostEndpoint
    private let lock = NSLock()
    private var readHandler: (@Sendable (Data?, Error?) -> Void)?
    private var storedWrittenDatagrams: [Data] = []
    private var storedCancelled = false
    private var storedRestartCount = 0
    private var storedEventHandler: ((Socks5UDPSessionEvent) -> Void)?

    var writtenDatagrams: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return storedWrittenDatagrams
    }

    var cancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storedCancelled
    }

    var restartCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedRestartCount
    }

    var eventHandler: ((Socks5UDPSessionEvent) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedEventHandler
        }
        set {
            lock.lock()
            storedEventHandler = newValue
            lock.unlock()
        }
    }

    init(endpoint: NWHostEndpoint) {
        self.endpoint = endpoint
    }

    func setReadHandler(_ handler: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock()
        readHandler = handler
        lock.unlock()
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        lock.lock()
        storedWrittenDatagrams.append(datagram)
        lock.unlock()
        completionHandler(nil)
    }

    func restart() {
        lock.lock()
        storedRestartCount += 1
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        storedCancelled = true
        lock.unlock()
    }

    var writtenDatagramCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedWrittenDatagrams.count
    }
}

private final class FaultUDPProvider: @unchecked Sendable, Socks5ConnectionProvider {
    private let lock = NSLock()
    private var storedSessions: [FaultUDPSession] = []

    var sessions: [FaultUDPSession] {
        lock.lock()
        defer { lock.unlock() }
        return storedSessions
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        let session = FaultUDPSession(endpoint: endpoint)
        lock.lock()
        storedSessions.append(session)
        lock.unlock()
        return session
    }
}

private final class FaultProvider: @unchecked Sendable, Socks5FullConnectionProvider {
    private let outbound: FaultTCPOutbound
    private let udpProvider = FaultUDPProvider()

    init(outbound: FaultTCPOutbound = FaultTCPOutbound()) {
        self.outbound = outbound
    }

    var udpSessions: [FaultUDPSession] {
        udpProvider.sessions
    }

    func makeTCPConnection(
        to _: NWHostEndpoint,
        enableTLS _: Bool,
        tlsParameters _: NWTLSParameters?,
        delegate _: (any NWTCPConnectionAuthenticationDelegate)?
    ) -> Socks5TCPOutbound {
        outbound
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        udpProvider.makeUDPSession(to: endpoint)
    }
}

private final class FaultInboundConnection: @unchecked Sendable, Socks5InboundConnection {
    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)?

    private var pendingReceives: [(@Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)] = []
    private(set) var sentPayloads: [Data] = []
    private(set) var cancelled = false

    func start(queue _: DispatchQueue) {}

    func receive(
        minimumIncompleteLength _: Int,
        maximumLength _: Int,
        completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        pendingReceives.append(completion)
    }

    func send(content: Data?, completion: NWConnection.SendCompletion) {
        sentPayloads.append(content ?? Data())
        if case .contentProcessed(let handler) = completion {
            handler(nil)
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        stateUpdateHandler?(.cancelled)
    }

    func push(_ data: Data) {
        guard !pendingReceives.isEmpty else { return }
        let completion = pendingReceives.removeFirst()
        completion(data, nil, false, nil)
    }
}

private final class DirectUDPContext {
    let queue: DispatchQueue
    let provider = FaultUDPProvider()

    private let relay: Socks5UDPRelay
    private let clientSocket: Int32

    init(label: String) throws {
        self.queue = DispatchQueue(label: label)
        self.relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: Socks5FaultInjectionRunner.logger()
        )
        self.clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard clientSocket >= 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
        relay.start()
    }

    func stop() {
        relay.stop()
        close(clientSocket)
    }

    func sendDatagram(
        address: Socks5Address = .ipv4("1.1.1.1"),
        port: UInt16 = 53,
        payload: Data = Data([0x01, 0x02, 0x03, 0x04])
    ) throws {
        guard let frame = Socks5Codec.buildUDPPacket(address: address, port: port, payload: payload) else {
            throw FaultInjectionError("failed to build UDP frame")
        }
        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = relay.port.bigEndian
        destination.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let sent = frame.withUnsafeBytes { buffer -> Int in
            guard let baseAddress = buffer.baseAddress else {
                return -1
            }
            return withUnsafePointer(to: &destination) {
                sendto(
                    clientSocket,
                    baseAddress,
                    frame.count,
                    0,
                    UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self),
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }

        guard sent == frame.count else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
    }

    func waitForSession(index: Int, timeoutSeconds: TimeInterval = 1.0) throws -> FaultUDPSession {
        try wait(timeoutSeconds: timeoutSeconds) {
            let sessions = self.provider.sessions
            guard sessions.indices.contains(index) else {
                return nil
            }
            return sessions[index]
        }
    }

    func waitForWrittenDatagrams(
        session: FaultUDPSession,
        count: Int,
        timeoutSeconds: TimeInterval = 1.0
    ) throws {
        _ = try wait(timeoutSeconds: timeoutSeconds) {
            session.writtenDatagramCount >= count ? true : nil
        }
    }
}

private final class TCPForwardUDPContext {
    let queue: DispatchQueue
    let inbound = FaultInboundConnection()
    let provider = FaultProvider()
    let frame: Data

    private let connection: Socks5Connection

    init(label: String) throws {
        self.queue = DispatchQueue(label: label)
        self.frame = try Self.makeFrame()
        self.connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: Socks5FaultInjectionRunner.logger()
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: Socks5Command.udpForward.rawValue, host: "0.0.0.0", port: 0))
        }
    }

    func stop() {
        connection.stop()
    }

    func sendFrame() throws {
        queue.sync {
            inbound.push(frame)
        }
        _ = try waitForSession(index: 0)
    }

    func waitForSession(index: Int, timeoutSeconds: TimeInterval = 1.0) throws -> FaultUDPSession {
        try wait(timeoutSeconds: timeoutSeconds) {
            let sessions = self.provider.udpSessions
            guard sessions.indices.contains(index) else {
                return nil
            }
            return sessions[index]
        }
    }

    private static let greeting = Data([0x05, 0x01, 0x00])

    private static func makeFrame() throws -> Data {
        guard let frame = Socks5Codec.buildTCPForwardUDPPacket(
            address: .ipv4("1.1.1.1"),
            port: 53,
            payload: Data([0x01])
        ) else {
            throw FaultInjectionError("failed to build TCP-carried UDP frame")
        }
        return frame
    }

    private static func request(command: UInt8, host: String, port: UInt16) -> Data {
        let hostBytes = Array(host.utf8)
        return Data(
            [0x05, command, 0x00, 0x03, UInt8(hostBytes.count)] +
            hostBytes +
            [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)]
        )
    }
}

private func wait<T>(timeoutSeconds: TimeInterval, pollIntervalSeconds: TimeInterval = 0.01, _ body: () -> T?) throws -> T {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    let ticker = DispatchSemaphore(value: 0)
    while Date() < deadline {
        if let value = body() {
            return value
        }
        _ = ticker.wait(timeout: .now() + pollIntervalSeconds)
    }
    throw FaultInjectionError("timed out waiting for relay fault state")
}
