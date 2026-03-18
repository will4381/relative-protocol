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

    private static let greeting = Data([0x05, 0x01, 0x00])

    private static func connectRequest(host: String, port: UInt16) -> Data {
        let hostBytes = Array(host.utf8)
        return Data(
            [0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)] +
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

    func completeNextSend(error: NWError? = nil) {
        XCTAssertFalse(pendingSendCompletions.isEmpty)
        let completion = pendingSendCompletions.removeFirst()
        completion(error)
    }
}

private final class ControlledTCPOutbound: @unchecked Sendable, Socks5TCPOutbound {
    private var readyHandlers: [(@Sendable (Result<Void, Error>) -> Void)] = []
    private var pendingReadHandlers: [(@Sendable (Data?, Error?) -> Void)] = []
    private var pendingWriteHandlers: [(@Sendable (Error?) -> Void)] = []
    private var queuedReads: [(Data?, Error?)] = []
    private(set) var writes: [Data] = []
    private(set) var cancelled = false
    private(set) var readRequests = 0
    var autoCompleteWrites = true

    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void) {
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

    func succeedConnect() {
        let handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        for handler in handlers {
            handler(.success(()))
        }
    }

    func failConnect(_ error: Error) {
        let handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        for handler in handlers {
            handler(.failure(error))
        }
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

private final class FakeProvider: Socks5FullConnectionProvider {
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
