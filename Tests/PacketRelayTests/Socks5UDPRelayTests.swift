import Darwin
import Foundation
import Network
@preconcurrency import NetworkExtension
@preconcurrency @testable import PacketRelay
import Observability
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// SOCKS5 UDP relay tests covering bounded session lifecycle behavior.
final class Socks5UDPRelayTests: XCTestCase {
    /// Verifies idle UDP relay sessions are cancelled and removed instead of accumulating indefinitely.
    func testUDPRelayReapsIdleSessions() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp")
        let clock = TestClock(now: Date(timeIntervalSince1970: 0))
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            nowProvider: { clock.now }
        )
        relay.start()
        defer {
            relay.stop()
        }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer {
            close(clientSocket)
        }

        let sessionCreated = expectation(description: "udp session created")
        provider.onCreate = { _ in
            sessionCreated.fulfill()
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        wait(for: [sessionCreated], timeout: 1.0)
        let session = try XCTUnwrap(provider.sessions.first)

        clock.now = clock.now.addingTimeInterval(61)
        queue.sync {
            relay.reapIdleSessions(now: clock.now)
            XCTAssertEqual(relay.activeSessionCount, 0)
        }

        XCTAssertTrue(session.cancelled)
    }

    /// Verifies the relay reopens its localhost socket after a full stop/start cycle.
    func testUDPRelayCanRestartAfterStop() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.restart")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        relay.start()
        let initialPort = relay.port
        XCTAssertNotEqual(initialPort, 0)
        relay.stop()

        let restartedSessionCreated = expectation(description: "udp session created after restart")
        provider.onCreate = { _ in
            restartedSessionCreated.fulfill()
        }

        relay.start()
        XCTAssertNotEqual(relay.port, 0)

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer {
            close(clientSocket)
            relay.stop()
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        wait(for: [restartedSessionCreated], timeout: 1.0)
    }

    /// Verifies an early stop closes the pre-opened socket and a later start recreates it cleanly.
    func testUDPRelayCanStartAfterStopBeforeFirstStart() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.prestop")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        relay.stop()
        XCTAssertEqual(relay.port, 0)

        let sessionCreated = expectation(description: "udp session created after early stop")
        provider.onCreate = { _ in
            sessionCreated.fulfill()
        }

        relay.start()
        XCTAssertNotEqual(relay.port, 0)

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer {
            close(clientSocket)
            relay.stop()
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        wait(for: [sessionCreated], timeout: 1.0)
    }

    func testUDPRelayEvictsSessionAfterWriteFailure() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.write-failure")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        relay.start()
        defer {
            relay.stop()
        }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer { close(clientSocket) }

        let firstCreated = expectation(description: "first udp session created")
        let secondCreated = expectation(description: "second udp session created")
        provider.onCreate = { session in
            if provider.sessions.count == 1 {
                session.nextWriteError = TestUDPError.writeFailed
                firstCreated.fulfill()
            } else if provider.sessions.count == 2 {
                secondCreated.fulfill()
            }
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        wait(for: [firstCreated], timeout: 1.0)
        queue.sync {}
        XCTAssertEqual(relay.activeSessionCount, 0)
        let firstSession = try XCTUnwrap(provider.sessions.first)
        XCTAssertTrue(firstSession.cancelled)

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        wait(for: [secondCreated], timeout: 1.0)
        XCTAssertEqual(relay.activeSessionCount, 1)
    }

    func testUDPRelayRetainsSessionAfterDatagramTooLargeWriteFailure() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.datagram-too-large")
        let sink = InMemoryLogSink()
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: sink)
        )
        relay.start()
        defer {
            relay.stop()
        }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer { close(clientSocket) }

        let created = expectation(description: "udp session created")
        provider.onCreate = { session in
            if provider.sessions.count == 1 {
                session.nextWriteError = Socks5UDPDatagramError.exceedsMaximumDatagramSize(
                    datagramSize: 1_400,
                    maximumDatagramSize: 1_382,
                    pathSummary: "status=satisfied uses=cellular"
                )
                created.fulfill()
            }
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        await fulfillment(of: [created], timeout: 1.0)

        let firstSession = try XCTUnwrap(provider.sessions.first)
        queue.sync {}
        XCTAssertEqual(relay.activeSessionCount, 1)
        XCTAssertFalse(firstSession.cancelled)

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        queue.sync {}
        XCTAssertEqual(provider.sessions.count, 1)
        XCTAssertEqual(relay.activeSessionCount, 1)

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains {
                $0.component == "Socks5UDPRelay" &&
                    $0.event == "write-failed" &&
                    $0.errorCode == "udp-datagram-too-large"
            }
        }
        let record = try XCTUnwrap(records.last(where: { $0.errorCode == "udp-datagram-too-large" }))
        XCTAssertEqual(record.metadata["datagram_size"], "1400")
        XCTAssertEqual(record.metadata["maximum_datagram_size"], "1382")
        XCTAssertEqual(record.metadata["session_retained"], "true")
    }

    func testUDPRelaySchedulesReplacementAfterRepeatedDatagramTooLargeFailures() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.datagram-too-large-replacement")
        let sink = InMemoryLogSink()
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: sink)
        )
        relay.start()
        defer {
            relay.stop()
        }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer { close(clientSocket) }

        let firstCreated = expectation(description: "first udp session created")
        let secondCreated = expectation(description: "replacement udp session created")
        provider.onCreate = { session in
            if provider.sessions.count == 1 {
                session.writeErrors = [
                    Socks5UDPDatagramError.exceedsMaximumDatagramSize(
                        datagramSize: 1_400,
                        maximumDatagramSize: 1_382,
                        pathSummary: "status=satisfied uses=cellular"
                    ),
                    Socks5UDPDatagramError.exceedsMaximumDatagramSize(
                        datagramSize: 1_399,
                        maximumDatagramSize: 1_382,
                        pathSummary: "status=satisfied uses=cellular"
                    ),
                    Socks5UDPDatagramError.exceedsMaximumDatagramSize(
                        datagramSize: 1_398,
                        maximumDatagramSize: 1_382,
                        pathSummary: "status=satisfied uses=cellular"
                    )
                ]
                firstCreated.fulfill()
            } else if provider.sessions.count == 2 {
                secondCreated.fulfill()
            }
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        await fulfillment(of: [firstCreated], timeout: 1.0)

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        queue.sync {}
        XCTAssertEqual(relay.activeSessionCount, 1)
        XCTAssertEqual(provider.sessions.count, 1)
        XCTAssertFalse(provider.sessions[0].cancelled)

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        await fulfillment(of: [secondCreated], timeout: 1.0)
        XCTAssertEqual(relay.activeSessionCount, 1)
        XCTAssertTrue(provider.sessions[0].cancelled)

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains {
                $0.component == "Socks5UDPRelay" &&
                    $0.event == "write-failed" &&
                    $0.metadata["replacement_scheduled"] == "true"
            }
        }
        let record = try XCTUnwrap(records.last(where: { $0.metadata["replacement_scheduled"] == "true" }))
        XCTAssertEqual(record.metadata["oversized_drop_count"], "3")
        XCTAssertEqual(record.metadata["minimum_observed_maximum_datagram_size"], "1382")
    }

    func testUDPRelayReplacesBetterPathSessionImmediately() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.better-path")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        relay.start()
        defer {
            relay.stop()
        }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer { close(clientSocket) }

        let firstCreated = expectation(description: "first udp session created")
        let secondCreated = expectation(description: "second udp session created after path change")
        provider.onCreate = { _ in
            if provider.sessions.count == 1 {
                firstCreated.fulfill()
            } else if provider.sessions.count == 2 {
                secondCreated.fulfill()
            }
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        wait(for: [firstCreated], timeout: 1.0)

        let firstSession = try XCTUnwrap(provider.sessions.first)
        queue.sync {
            firstSession.eventHandler?(.betterPathAvailable)
        }
        wait(for: [secondCreated], timeout: 1.0)

        XCTAssertTrue(firstSession.cancelled)
        XCTAssertEqual(relay.activeSessionCount, 1)
    }

    func testUDPRelayRestartsWaitingSession() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.waiting")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        relay.start()
        defer {
            relay.stop()
        }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer { close(clientSocket) }

        let firstCreated = expectation(description: "first udp session created")
        provider.onCreate = { _ in
            if provider.sessions.count == 1 {
                firstCreated.fulfill()
            }
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        wait(for: [firstCreated], timeout: 1.0)

        let session = try XCTUnwrap(provider.sessions.first)
        queue.sync {
            session.eventHandler?(.waiting)
        }

        XCTAssertEqual(session.restartCount, 1)
        XCTAssertEqual(relay.activeSessionCount, 1)

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        queue.sync {}
        XCTAssertFalse(session.cancelled)
        XCTAssertEqual(provider.sessions.count, 1)
        XCTAssertEqual(relay.activeSessionCount, 1)
    }

    func testUDPRelayKeepsLargeSocksDatagramPayloadIntact() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.large-payload")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 512,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        relay.start()
        defer {
            relay.stop()
        }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer { close(clientSocket) }

        let sessionCreated = expectation(description: "udp session created")
        provider.onCreate = { _ in
            sessionCreated.fulfill()
        }

        let payload = Data(repeating: 0x5A, count: 2_048)
        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53,
            payload: payload
        )

        wait(for: [sessionCreated], timeout: 1.0)
        queue.sync {}
        let session = try XCTUnwrap(provider.sessions.first)
        XCTAssertEqual(session.writtenDatagrams, [payload])
    }

    func testUDPRelayDropsDatagramsFromUnexpectedClientEndpoint() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.client-lock")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        relay.start()
        defer {
            relay.stop()
        }

        let firstClient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(firstClient, 0)
        let secondClient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(secondClient, 0)
        defer {
            close(firstClient)
            close(secondClient)
        }

        let sessionCreated = expectation(description: "first udp session created")
        provider.onCreate = { _ in
            sessionCreated.fulfill()
        }

        try sendClientDatagram(
            socketFD: firstClient,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        wait(for: [sessionCreated], timeout: 1.0)

        try sendClientDatagram(
            socketFD: secondClient,
            relayPort: relay.port,
            destinationAddress: .ipv4("8.8.8.8"),
            destinationPort: 53
        )

        queue.sync {}
        XCTAssertEqual(provider.sessions.count, 1)
        XCTAssertEqual(relay.activeSessionCount, 1)
    }

    private func sendClientDatagram(
        socketFD: Int32,
        relayPort: UInt16,
        destinationAddress: Socks5Address,
        destinationPort: UInt16,
        payload: Data = Data([0x01, 0x02, 0x03, 0x04])
    ) throws {
        let frame = Socks5Codec.buildUDPPacket(
            address: destinationAddress,
            port: destinationPort,
            payload: payload
        )

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = relayPort.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let sent = frame.withUnsafeBytes { buffer -> Int in
            guard let baseAddress = buffer.baseAddress else {
                return -1
            }
            return withUnsafePointer(to: &address) {
                sendto(
                    socketFD,
                    baseAddress,
                    frame.count,
                    0,
                    UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self),
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }

        if sent != frame.count {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
    }
}

private final class TestClock: @unchecked Sendable {
    var now: Date

    init(now: Date) {
        self.now = now
    }
}

private final class FakeUDPProvider: Socks5ConnectionProvider, @unchecked Sendable {
    private(set) var sessions: [FakeUDPSession] = []
    var onCreate: ((FakeUDPSession) -> Void)?

    func makeUDPSession(to _: NWHostEndpoint) -> Socks5UDPSession {
        let session = FakeUDPSession()
        sessions.append(session)
        onCreate?(session)
        return session
    }
}

private final class FakeUDPSession: Socks5UDPSession, @unchecked Sendable {
    private var readHandler: ((Data?, Error?) -> Void)?
    private(set) var cancelled = false
    private(set) var restartCount = 0
    private(set) var writtenDatagrams: [Data] = []
    var nextWriteError: Error?
    var writeErrors: [Error] = []
    var eventHandler: ((Socks5UDPSessionEvent) -> Void)?

    func setReadHandler(_ handler: @escaping (Data?, Error?) -> Void) {
        readHandler = handler
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) {
        writtenDatagrams.append(datagram)
        if !writeErrors.isEmpty {
            completionHandler(writeErrors.removeFirst())
            return
        }
        if let nextWriteError {
            self.nextWriteError = nil
            completionHandler(nextWriteError)
            return
        }
        completionHandler(nil)
    }

    func restart() {
        restartCount += 1
    }

    func cancel() {
        cancelled = true
    }
}

private enum TestUDPError: LocalizedError {
    case writeFailed
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
