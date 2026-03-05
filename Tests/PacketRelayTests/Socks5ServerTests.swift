import Foundation
import Network
@preconcurrency import NetworkExtension
@testable import PacketRelay
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
    var stateUpdateHandler: ((NWConnection.State) -> Void)?

    private var pendingReceives: [(Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void] = []
    private(set) var sentPayloads: [Data] = []
    private(set) var cancelled = false

    func start(queue _: DispatchQueue) {}

    func receive(
        minimumIncompleteLength _: Int,
        maximumLength _: Int,
        completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
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
        cancelled = true
        stateUpdateHandler?(.cancelled)
    }

    func push(_ data: Data, isComplete: Bool = false, error: NWError? = nil) {
        XCTAssertFalse(pendingReceives.isEmpty)
        let completion = pendingReceives.removeFirst()
        completion(data, nil, isComplete, error)
    }
}

private final class ControlledTCPOutbound: Socks5TCPOutbound {
    private var readyHandlers: [(@Sendable (Result<Void, Error>) -> Void)] = []
    private(set) var writes: [Data] = []
    private(set) var cancelled = false

    func waitUntilReady(completionHandler: @escaping @Sendable (Result<Void, Error>) -> Void) {
        readyHandlers.append(completionHandler)
    }

    func readMinimumLength(_: Int, maximumLength _: Int, completionHandler _: @escaping (Data?, (any Error)?) -> Void) {}

    func write(_ data: Data, completionHandler: @escaping ((any Error)?) -> Void) {
        writes.append(data)
        completionHandler(nil)
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
