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

    func testUDPRelayMarshalsSynchronousReadCallbackThroughQueue() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.sync-read")
        let provider = FakeUDPProvider()
        let relay = try Socks5UDPRelay(
            provider: provider,
            queue: queue,
            mtu: 1_500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )
        relay.start()
        defer { relay.stop() }

        let clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(clientSocket, 0)
        defer { close(clientSocket) }

        let sessionCreated = expectation(description: "udp session created")
        provider.onCreate = { session in
            session.onSetReadHandler = { handler in
                handler(Data([0x01, 0x02, 0x03]), nil)
            }
            sessionCreated.fulfill()
        }

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        wait(for: [sessionCreated], timeout: 1.0)
        queue.sync {}
        XCTAssertEqual(relay.activeSessionCount, 1)
        XCTAssertFalse(try XCTUnwrap(provider.sessions.first).cancelled)
    }

    func testUDPRelayEvictsSessionAfterWriteFailure() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.write-failure")
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

        await fulfillment(of: [firstCreated], timeout: 1.0)
        queue.sync {}
        XCTAssertEqual(relay.activeSessionCount, 0)
        let firstSession = try XCTUnwrap(provider.sessions.first)
        XCTAssertTrue(firstSession.cancelled)
        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5UDPRelay" && $0.event == "write-failed" }
        }
        let record = try XCTUnwrap(
            records.first { $0.component == "Socks5UDPRelay" && $0.event == "write-failed" }
        )
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "53")
        XCTAssertEqual(record.metadata["destination_host_kind"], "ipv4")
        XCTAssertEqual(record.metadata["destination_transport"], "udp")

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )

        await fulfillment(of: [secondCreated], timeout: 1.0)
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
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "53")
        XCTAssertEqual(record.metadata["destination_host_kind"], "ipv4")
        XCTAssertEqual(record.metadata["destination_transport"], "udp")
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
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "53")
        XCTAssertEqual(record.metadata["destination_host_kind"], "ipv4")
        XCTAssertEqual(record.metadata["destination_transport"], "udp")
    }

    func testUDPRelaySchedulesBetterPathReplacementUntilNextDatagram() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.better-path")
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
        let secondCreated = expectation(description: "second udp session created on next datagram")
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
        await fulfillment(of: [firstCreated], timeout: 1.0)

        let firstSession = try XCTUnwrap(provider.sessions.first)
        queue.sync {
            firstSession.eventHandler?(.betterPathAvailable)
            firstSession.eventHandler?(.betterPathAvailable)
        }

        XCTAssertFalse(firstSession.cancelled)
        XCTAssertEqual(provider.sessions.count, 1)
        XCTAssertEqual(relay.activeSessionCount, 1)
        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5UDPRelay" && $0.event == "session-replacement-scheduled" }
        }
        let record = try XCTUnwrap(
            records.first { $0.component == "Socks5UDPRelay" && $0.event == "session-replacement-scheduled" }
        )
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "53")
        XCTAssertEqual(record.metadata["destination_host_kind"], "ipv4")
        XCTAssertEqual(record.metadata["destination_transport"], "udp")

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        await fulfillment(of: [secondCreated], timeout: 1.0)

        XCTAssertTrue(firstSession.cancelled)
        XCTAssertEqual(relay.activeSessionCount, 1)
    }

    func testUDPRelaySchedulesWaitingReplacementUntilNextDatagram() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.waiting")
        let provider = FakeUDPProvider()
        let sink = InMemoryLogSink()
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
        let secondCreated = expectation(description: "second udp session created on next datagram")
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
        await fulfillment(of: [firstCreated], timeout: 1.0)

        let session = try XCTUnwrap(provider.sessions.first)
        queue.sync {
            session.eventHandler?(.waiting)
            session.eventHandler?(.waiting)
            session.eventHandler?(.waiting)
        }

        XCTAssertEqual(session.restartCount, 0)
        XCTAssertFalse(session.cancelled)
        XCTAssertEqual(relay.activeSessionCount, 1)
        XCTAssertEqual(provider.sessions.count, 1)

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        await fulfillment(of: [secondCreated], timeout: 1.0)

        let secondSession = try XCTUnwrap(provider.sessions.last)
        XCTAssertTrue(session.cancelled)
        XCTAssertFalse(secondSession === session)
        XCTAssertEqual(provider.sessions.count, 2)
        XCTAssertEqual(relay.activeSessionCount, 1)
        XCTAssertEqual(session.writtenDatagrams.count, 1)
        XCTAssertEqual(secondSession.writtenDatagrams.count, 1)

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains {
                $0.component == "Socks5UDPRelay"
                    && $0.event == "session-replacement-scheduled"
                    && $0.result == "waiting"
            }
        }
        let replacementRecord = try XCTUnwrap(
            records.first { $0.component == "Socks5UDPRelay" && $0.event == "session-replacement-scheduled" }
        )
        XCTAssertEqual(replacementRecord.result, "waiting")
    }

    func testUDPRelayRemovesFailedSessionAndRecreatesOnNextDatagram() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.failed")
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
            firstSession.eventHandler?(.failed)
        }

        XCTAssertTrue(firstSession.cancelled)
        XCTAssertEqual(relay.activeSessionCount, 0)
        XCTAssertEqual(provider.sessions.count, 1)

        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        wait(for: [secondCreated], timeout: 1.0)

        XCTAssertEqual(provider.sessions.count, 2)
        XCTAssertEqual(relay.activeSessionCount, 1)
    }

    func testUDPRelayClearsScheduledReplacementWhenSessionRecovers() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp.viability-recovers")
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
            session.eventHandler?(.viabilityChanged(false))
            session.eventHandler?(.viabilityChanged(true))
        }

        let secondWrite = expectation(description: "recovered session receives second datagram")
        session.onWrite = { _ in
            if session.writtenDatagrams.count == 2 {
                secondWrite.fulfill()
            }
        }
        try sendClientDatagram(
            socketFD: clientSocket,
            relayPort: relay.port,
            destinationAddress: .ipv4("1.1.1.1"),
            destinationPort: 53
        )
        wait(for: [secondWrite], timeout: 1.0)

        XCTAssertFalse(session.cancelled)
        XCTAssertEqual(provider.sessions.count, 1)
        XCTAssertEqual(relay.activeSessionCount, 1)
        XCTAssertEqual(session.writtenDatagrams.count, 2)
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
        let frame = try XCTUnwrap(Socks5Codec.buildUDPPacket(
            address: destinationAddress,
            port: destinationPort,
            payload: payload
        ))

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
    private let lock = NSLock()
    private var storedSessions: [FakeUDPSession] = []
    private var storedOnCreate: ((FakeUDPSession) -> Void)?

    var onCreate: ((FakeUDPSession) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedOnCreate
        }
        set {
            lock.lock()
            storedOnCreate = newValue
            lock.unlock()
        }
    }

    var sessions: [FakeUDPSession] {
        lock.lock()
        defer { lock.unlock() }
        return storedSessions
    }

    func makeUDPSession(to _: NWHostEndpoint) -> Socks5UDPSession {
        let session = FakeUDPSession()
        let onCreate: ((FakeUDPSession) -> Void)?
        lock.lock()
        storedSessions.append(session)
        onCreate = storedOnCreate
        lock.unlock()
        onCreate?(session)
        return session
    }
}

private final class FakeUDPSession: Socks5UDPSession, @unchecked Sendable {
    private let lock = NSLock()
    private var readHandler: ((Data?, Error?) -> Void)?
    private var storedCancelled = false
    private var storedRestartCount = 0
    private var storedWrittenDatagrams: [Data] = []
    private var storedNextWriteError: Error?
    private var storedWriteErrors: [Error] = []
    private var storedOnWrite: ((Data) -> Void)?
    private var storedOnSetReadHandler: (((Data?, Error?) -> Void) -> Void)?
    private var storedEventHandler: ((Socks5UDPSessionEvent) -> Void)?

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

    var writtenDatagrams: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return storedWrittenDatagrams
    }

    var nextWriteError: Error? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedNextWriteError
        }
        set {
            lock.lock()
            storedNextWriteError = newValue
            lock.unlock()
        }
    }

    var writeErrors: [Error] {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedWriteErrors
        }
        set {
            lock.lock()
            storedWriteErrors = newValue
            lock.unlock()
        }
    }

    var onWrite: ((Data) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedOnWrite
        }
        set {
            lock.lock()
            storedOnWrite = newValue
            lock.unlock()
        }
    }

    var onSetReadHandler: (((Data?, Error?) -> Void) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedOnSetReadHandler
        }
        set {
            lock.lock()
            storedOnSetReadHandler = newValue
            lock.unlock()
        }
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

    func setReadHandler(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        readHandler = handler
        let onSetReadHandler = storedOnSetReadHandler
        lock.unlock()
        onSetReadHandler?(handler)
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) {
        let onWrite: ((Data) -> Void)?
        let error: Error?
        lock.lock()
        storedWrittenDatagrams.append(datagram)
        onWrite = storedOnWrite
        if !storedWriteErrors.isEmpty {
            error = storedWriteErrors.removeFirst()
        } else if let nextWriteError = storedNextWriteError {
            storedNextWriteError = nil
            error = nextWriteError
        } else {
            error = nil
        }
        lock.unlock()

        onWrite?(datagram)
        if let error {
            completionHandler(error)
            return
        }
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

    func deliverRead(datagram: Data?, error: Error? = nil) {
        lock.lock()
        let handler = readHandler
        lock.unlock()
        handler?(datagram, error)
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
