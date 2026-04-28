import Foundation
import Network
@preconcurrency import NetworkExtension
@preconcurrency @testable import PacketRelay
import Observability
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// SOCKS5 relay tests covering connection-establishment correctness.
final class Socks5ServerTests: XCTestCase {
    /// Verifies SOCKS CONNECT success is delayed until the outbound channel is actually ready.
    func testConnectReplyWaitsForOutboundReady() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            XCTAssertEqual(inbound.sentPayloads, [Socks5Codec.buildMethodSelection(method: 0x00)])

            inbound.push(Self.connectRequest(host: "example.com", port: 443))
            XCTAssertEqual(inbound.sentPayloads.count, 1)

            inbound.push(Data("hello".utf8))
            XCTAssertTrue(outbound.writes.isEmpty)

            outbound.succeedConnect()

            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("0.0.0.0"), bindPort: 0)
                ]
            )
            XCTAssertEqual(outbound.writes, [Data("hello".utf8)])
        }
    }

    /// Verifies outbound connection failure produces a SOCKS error reply instead of an optimistic success.
    func testConnectFailureSendsFailureReply() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.failure")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.connectRequest(host: "denied.example", port: 80))
            outbound.failConnect(TestConnectError.refused)

            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x05, bindAddress: .ipv4("0.0.0.0"), bindPort: 0)
                ]
            )
            XCTAssertTrue(inbound.cancelled)
        }
    }

    func testMalformedRequestReservedByteSendsGeneralFailure() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.invalid-rsv")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: 0x01, reserved: 0x01, host: "example.com", port: 443))

            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x01, bindAddress: .ipv4("0.0.0.0"), bindPort: 0)
                ]
            )
            XCTAssertTrue(inbound.cancelled)
        }
    }

    func testBindRequestSendsCommandNotSupported() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.bind")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: 0x02, host: "example.com", port: 443))

            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x07, bindAddress: .ipv4("0.0.0.0"), bindPort: 0)
                ]
            )
            XCTAssertTrue(inbound.cancelled)
        }
    }

    func testUnsupportedCommandSendsCommandNotSupported() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.unsupported-command")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: 0x09, host: "example.com", port: 443))

            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x07, bindAddress: .ipv4("0.0.0.0"), bindPort: 0)
                ]
            )
            XCTAssertTrue(inbound.cancelled)
        }
    }

    /// Verifies inbound client reads pause while one outbound relay write is still in flight.
    func testTCPProxyPausesInboundReadsUntilOutboundWriteCompletes() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.backpressure")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        outbound.autoCompleteWrites = false
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.connectRequest(host: "example.com", port: 443))
            outbound.succeedConnect()

            XCTAssertEqual(inbound.pendingReceiveCount, 1)

            inbound.push(Data("first".utf8))
            XCTAssertEqual(outbound.writes, [Data("first".utf8)])
            XCTAssertEqual(inbound.pendingReceiveCount, 0)

            outbound.completeNextWrite()
            XCTAssertEqual(inbound.pendingReceiveCount, 1)

            inbound.push(Data("second".utf8))
            XCTAssertEqual(outbound.writes, [Data("first".utf8), Data("second".utf8)])
        }
    }

    func testStopRetainsConnectionUntilQueuedCleanupRuns() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.stop-retains")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        var connection: Socks5Connection? = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.suspend()
        connection?.stop()
        connection = nil
        queue.resume()
        queue.sync {}

        XCTAssertTrue(inbound.cancelled)
    }

    func testConnectingTCPBufferLimitClosesConnection() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.buffer-limit")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.connectRequest(host: "example.com", port: 443))
            inbound.push(Data(repeating: 0x41, count: 256 * 1024 + 1))

            XCTAssertTrue(inbound.cancelled)
            XCTAssertTrue(outbound.writes.isEmpty)
        }
    }

    /// Verifies outbound reads wait for the previous inbound send to finish before requesting more data.
    func testTCPProxyPausesOutboundReadsUntilInboundSendCompletes() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.reverse-backpressure")
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.connectRequest(host: "example.com", port: 443))
            outbound.succeedConnect()

            XCTAssertEqual(outbound.readRequests, 1)

            inbound.completeSendsAutomatically = false
            outbound.queueRead(Data("server".utf8))

            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("0.0.0.0"), bindPort: 0),
                    Data("server".utf8)
                ]
            )
            XCTAssertEqual(outbound.readRequests, 1)

            inbound.completeNextSend()
            XCTAssertEqual(outbound.readRequests, 2)
        }
    }

    func testRetryingTCPOutboundRetriesTimedOutAttempt() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-timeout")
        let lock = NSLock()
        var attempts: [ControlledTCPOutbound] = []
        var secondAttempt: ControlledTCPOutbound?
        let secondAttemptCreated = expectation(description: "second attempt created")
        let ready = expectation(description: "retry eventually connects")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            policy: .init(attemptPreparingTimeout: 0.03, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 0.2)
        ) { attemptIndex in
            let attempt = ControlledTCPOutbound()
            lock.lock()
            attempts.append(attempt)
            if attemptIndex == 2 {
                secondAttempt = attempt
            }
            lock.unlock()
            if attemptIndex == 2 {
                secondAttemptCreated.fulfill()
            }
            return attempt
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                ready.fulfill()
            case .failure(let error):
                XCTFail("Expected retry to succeed, got \(error)")
            }
        }

        wait(for: [secondAttemptCreated], timeout: 1.0)

        lock.lock()
        let firstAttempt = attempts.first
        let retryAttempt = secondAttempt
        lock.unlock()

        retryAttempt?.succeedConnect()
        wait(for: [ready], timeout: 1.0)

        XCTAssertTrue(firstAttempt?.cancelled == true)
    }

    func testRetryingTCPOutboundFailsAfterAttemptBudgetExhausted() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-exhausted")
        let lock = NSLock()
        var attempts: [ControlledTCPOutbound] = []
        let failed = expectation(description: "connect fails after retries")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            policy: .init(attemptPreparingTimeout: 0.03, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 0.2)
        ) { _ in
            let attempt = ControlledTCPOutbound()
            lock.lock()
            attempts.append(attempt)
            lock.unlock()
            return attempt
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                XCTFail("Expected timeout after exhausting retries")
            case .failure(let error):
                XCTAssertEqual(error.localizedDescription, "Outbound connection timed out")
                failed.fulfill()
            }
        }

        wait(for: [failed], timeout: 1.0)

        lock.lock()
        let snapshot = attempts
        lock.unlock()

        XCTAssertEqual(snapshot.count, 2)
        XCTAssertTrue(snapshot.allSatisfy(\.cancelled))
    }

    func testRetryingTCPOutboundRetriesWhenBetterPathBecomesAvailable() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-better-path")
        let lock = NSLock()
        var attempts: [ControlledTCPOutbound] = []
        var secondAttempt: ControlledTCPOutbound?
        let firstAttemptCreated = expectation(description: "first attempt created")
        let secondAttemptCreated = expectation(description: "second attempt created")
        let ready = expectation(description: "retry eventually connects")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            policy: .init(attemptPreparingTimeout: 1.0, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 2.0),
            pathSettings: .init(retryOnBetterPathDuringConnect: true, betterPathRetryMinimumElapsed: 0.0, multipathServiceType: nil)
        ) { attemptIndex in
            let attempt = ControlledTCPOutbound()
            lock.lock()
            attempts.append(attempt)
            if attemptIndex == 1 {
                firstAttemptCreated.fulfill()
            }
            if attemptIndex == 2 {
                secondAttempt = attempt
            }
            lock.unlock()
            if attemptIndex == 2 {
                secondAttemptCreated.fulfill()
            }
            return attempt
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                ready.fulfill()
            case .failure(let error):
                XCTFail("Expected better-path retry to succeed, got \(error)")
            }
        }

        wait(for: [firstAttemptCreated], timeout: 1.0)

        lock.lock()
        let firstAttempt = attempts.first
        lock.unlock()
        firstAttempt?.emit(.betterPathAvailable)

        wait(for: [secondAttemptCreated], timeout: 1.0)
        secondAttempt?.succeedConnect()
        wait(for: [ready], timeout: 1.0)

        XCTAssertTrue(firstAttempt?.cancelled == true)
    }

    func testRetryingTCPOutboundRestartsWaitingAttempt() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-waiting")
        let attempt = ControlledTCPOutbound()
        let restarted = expectation(description: "waiting attempt restarted")
        let ready = expectation(description: "waiting attempt eventually connects")
        attempt.onRestart = {
            restarted.fulfill()
        }

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            policy: .init(attemptPreparingTimeout: 1.0, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 2.0),
            pathSettings: .init(retryOnBetterPathDuringConnect: true, betterPathRetryMinimumElapsed: 0.0, multipathServiceType: nil)
        ) { _ in
            attempt
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                ready.fulfill()
            case .failure(let error):
                XCTFail("Expected waiting attempt restart to recover, got \(error)")
            }
        }

        queue.sync {
            attempt.emit(.waiting)
        }

        wait(for: [restarted], timeout: 1.0)
        XCTAssertEqual(attempt.restartCount, 1)
        attempt.succeedConnect()
        wait(for: [ready], timeout: 1.0)
    }

    func testRetryingTCPOutboundHonorsOverallTimeoutBudget() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-overall-timeout")
        let lock = NSLock()
        var attempts: [ControlledTCPOutbound] = []
        let failed = expectation(description: "connect fails after overall timeout")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            policy: .init(attemptPreparingTimeout: 0.2, retryBackoff: 0.01, maxAttempts: 3, overallTimeout: 0.05)
        ) { _ in
            let attempt = ControlledTCPOutbound()
            lock.lock()
            attempts.append(attempt)
            lock.unlock()
            return attempt
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                XCTFail("Expected overall timeout to fail connection")
            case .failure(let error):
                XCTAssertEqual(error.localizedDescription, "Outbound connection timed out")
                failed.fulfill()
            }
        }

        wait(for: [failed], timeout: 1.0)

        lock.lock()
        let snapshot = attempts
        lock.unlock()

        XCTAssertEqual(snapshot.count, 1)
        XCTAssertTrue(snapshot.first?.cancelled == true)
    }

    func testInboundReadFailureIsLoggedBeforeClose() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.inbound-read-failure")
        let sink = InMemoryLogSink()
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: sink)
        )

        queue.sync {
            connection.start()
            inbound.failReceive(.posix(.ECONNRESET))
        }

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5Connection" && $0.event == "inbound-read-failed" }
        }
        XCTAssertTrue(records.contains { $0.component == "Socks5Connection" && $0.event == "inbound-read-failed" })
        XCTAssertTrue(inbound.cancelled)
    }

    func testOutboundReadFailureIsLoggedBeforeClose() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.outbound-read-failure")
        let sink = InMemoryLogSink()
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: sink)
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.connectRequest(host: "example.com", port: 443))
            outbound.succeedConnect()
            outbound.queueRead(nil, error: TestConnectError.refused)
        }

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-failed" }
        }
        XCTAssertTrue(records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-failed" })
        XCTAssertTrue(inbound.cancelled)
    }

    func testOutboundReadENOMSGIsLoggedAsNormalClose() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.outbound-read-close")
        let sink = InMemoryLogSink()
        let inbound = FakeInboundConnection()
        let outbound = ControlledTCPOutbound()
        let provider = FakeProvider(outbound: outbound)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: sink)
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.connectRequest(host: "example.com", port: 443))
            outbound.succeedConnect()
            outbound.queueRead(nil, error: NWError.posix(.ENOMSG))
        }

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-closed" }
        }
        XCTAssertTrue(records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-closed" && $0.level == .notice })
        XCTAssertFalse(records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-failed" })
        XCTAssertTrue(inbound.cancelled)
    }

    private static let greeting = Data([0x05, 0x01, 0x00])

    private static func connectRequest(host: String, port: UInt16) -> Data {
        request(command: 0x01, host: host, port: port)
    }

    private static func request(command: UInt8, reserved: UInt8 = 0x00, host: String, port: UInt16) -> Data {
        let hostBytes = Array(host.utf8)
        return Data(
            [0x05, command, reserved, 0x03, UInt8(hostBytes.count)] +
            hostBytes +
            [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)]
        )
    }
}

private enum TestConnectError: LocalizedError {
    case refused

    var errorDescription: String? {
        switch self {
        case .refused:
            return "connection refused"
        }
    }
}

private final class FakeInboundConnection: Socks5InboundConnection {
    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)?

    private var pendingReceives: [(@Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)] = []
    private var pendingSendCompletions: [(NWError?) -> Void] = []
    private(set) var sentPayloads: [Data] = []
    private(set) var cancelled = false
    var completeSendsAutomatically = true

    var pendingReceiveCount: Int {
        pendingReceives.count
    }

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
            if completeSendsAutomatically {
                handler(nil)
            } else {
                pendingSendCompletions.append(handler)
            }
        }
    }

    func cancel() {
        cancelled = true
        stateUpdateHandler?(.cancelled)
    }

    func push(_ data: Data, isComplete: Bool = false, error: NWError? = nil) {
        XCTAssertFalse(pendingReceives.isEmpty)
        let completion = pendingReceives.removeFirst()
        completion(data, nil, isComplete, error)
    }

    func failReceive(_ error: NWError) {
        XCTAssertFalse(pendingReceives.isEmpty)
        let completion = pendingReceives.removeFirst()
        completion(nil, nil, false, error)
    }

    func completeNextSend(error: NWError? = nil) {
        XCTAssertFalse(pendingSendCompletions.isEmpty)
        let completion = pendingSendCompletions.removeFirst()
        completion(error)
    }
}

private final class ControlledTCPOutbound: @unchecked Sendable, Socks5PathAwareTCPOutbound {
    private var readyHandlers: [(@Sendable (Result<Void, Error>) -> Void)] = []
    private var readyResult: Result<Void, Error>?
    private var pendingReadHandlers: [(@Sendable (Data?, Error?) -> Void)] = []
    private var pendingWriteHandlers: [(@Sendable (Error?) -> Void)] = []
    private var queuedReads: [(Data?, Error?)] = []
    private(set) var writes: [Data] = []
    private(set) var cancelled = false
    private(set) var readRequests = 0
    private(set) var restartCount = 0
    var autoCompleteWrites = true
    var onRestart: (() -> Void)?
    var eventHandler: ((TCPOutboundEvent) -> Void)?
    var pathSnapshot = "status=unknown uses=unknown"

    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void) {
        if let readyResult {
            completionHandler(readyResult)
            return
        }
        readyHandlers.append(completionHandler)
    }

    func readMinimumLength(_: Int, maximumLength _: Int, completionHandler: @escaping @Sendable (Data?, (any Error)?) -> Void) {
        readRequests += 1
        if !queuedReads.isEmpty {
            let next = queuedReads.removeFirst()
            completionHandler(next.0, next.1)
            return
        }
        pendingReadHandlers.append(completionHandler)
    }

    func write(_ data: Data, completionHandler: @escaping @Sendable ((any Error)?) -> Void) {
        writes.append(data)
        if autoCompleteWrites {
            completionHandler(nil)
        } else {
            pendingWriteHandlers.append(completionHandler)
        }
    }

    func cancel() {
        cancelled = true
    }

    func restart() {
        restartCount += 1
        onRestart?()
    }

    func succeedConnect() {
        guard readyResult == nil else { return }
        readyResult = .success(())
        let handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        for handler in handlers {
            handler(.success(()))
        }
    }

    func failConnect(_ error: Error) {
        guard readyResult == nil else { return }
        readyResult = .failure(error)
        let handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        for handler in handlers {
            handler(.failure(error))
        }
    }

    func emit(_ event: TCPOutboundEvent) {
        eventHandler?(event)
    }

    func queueRead(_ data: Data?, error: Error? = nil) {
        if !pendingReadHandlers.isEmpty {
            let handler = pendingReadHandlers.removeFirst()
            handler(data, error)
            return
        }
        queuedReads.append((data, error))
    }

    func completeNextWrite(error: Error? = nil) {
        XCTAssertFalse(pendingWriteHandlers.isEmpty)
        let completion = pendingWriteHandlers.removeFirst()
        completion(error)
    }
}

private final class FakeProvider: Socks5FullConnectionProvider, @unchecked Sendable {
    private let outbound: ControlledTCPOutbound

    init(outbound: ControlledTCPOutbound) {
        self.outbound = outbound
    }

    func makeTCPConnection(
        to _: NWHostEndpoint,
        enableTLS _: Bool,
        tlsParameters _: NWTLSParameters?,
        delegate _: (any NWTCPConnectionAuthenticationDelegate)?
    ) -> any Socks5TCPOutbound {
        outbound
    }

    func makeUDPSession(to _: NWHostEndpoint) -> any Socks5UDPSession {
        fatalError("UDP not exercised in SOCKS CONNECT tests")
    }
}

private func eventuallyFetchRecords(
    from sink: InMemoryLogSink,
    predicate: @escaping ([LogEnvelope]) -> Bool
) async throws -> [LogEnvelope] {
    for _ in 0..<20 {
        let records = await sink.snapshot()
        if predicate(records) {
            return records
        }
        try await Task.sleep(for: .milliseconds(25))
    }
    return await sink.snapshot()
}
