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

    func testConnectFailureClosesAfterFailureReplyFlushes() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.failure-flush")
        let inbound = FakeInboundConnection()
        inbound.completeSendsAutomatically = false
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
            inbound.completeNextSend()
            inbound.push(Self.connectRequest(host: "denied.example", port: 80))
            outbound.failConnect(TestConnectError.refused)

            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x05, bindAddress: .ipv4("0.0.0.0"), bindPort: 0)
                ]
            )
            XCTAssertFalse(inbound.cancelled)
            inbound.completeNextSend()
            XCTAssertTrue(inbound.cancelled)
        }
    }

    func testUnsupportedGreetingClosesAfterMethodSelectionFlushes() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.greeting-flush")
        let inbound = FakeInboundConnection()
        inbound.completeSendsAutomatically = false
        let provider = FakeProvider(outbound: ControlledTCPOutbound())
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink())
        )

        queue.sync {
            connection.start()
            inbound.push(Data([0x05, 0x01, 0x02]))

            XCTAssertEqual(inbound.sentPayloads, [Socks5Codec.buildMethodSelection(method: 0xFF)])
            XCTAssertFalse(inbound.cancelled)
            inbound.completeNextSend()
            XCTAssertTrue(inbound.cancelled)
        }
    }

    func testUDPAssociateReplyFailureStopsRelayAndConnection() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp-associate-reply-failure")
        let inbound = FakeInboundConnection()
        inbound.completeSendsAutomatically = false
        let provider = FakeProvider(outbound: ControlledTCPOutbound())
        let relay = ControlledUDPAssociateRelay(port: 53_000)
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            udpRelayFactory: { _, _, _, _ in relay }
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.completeNextSend()
            inbound.push(Self.request(command: 0x03, host: "0.0.0.0", port: 0))

            XCTAssertTrue(relay.started)
            XCTAssertEqual(
                inbound.sentPayloads,
                [
                    Socks5Codec.buildMethodSelection(method: 0x00),
                    Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("127.0.0.1"), bindPort: relay.port)
                ]
            )
            XCTAssertFalse(relay.stopped)
            XCTAssertFalse(inbound.cancelled)

            inbound.completeNextSend(error: NWError.posix(.ECONNRESET))

            XCTAssertTrue(relay.stopped)
            XCTAssertTrue(inbound.cancelled)
        }
    }

    func testConnectFailureLogsDestinationMetadata() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.failure-metadata")
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
            inbound.push(Self.connectRequest(host: "denied.example", port: 8443))
            outbound.failConnect(TestConnectError.refused)
        }

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-connect-failed" }
        }
        let record = try XCTUnwrap(
            records.first { $0.component == "Socks5Connection" && $0.event == "outbound-connect-failed" }
        )
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "8443")
        XCTAssertEqual(record.metadata["destination_host_kind"], "domain")
        XCTAssertEqual(record.metadata["destination_transport"], "tcp")
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

    func testTCPForwardUDPRelaysDatagramsOverControlConnection() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.forward-udp")
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

        let payload = Data([0x01, 0x02, 0x03])
        let frame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .domain("i.instagram.com"),
                port: 443,
                payload: payload
            )
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: 0x05, host: "0.0.0.0", port: 0))
            inbound.push(frame)
        }

        let session = try XCTUnwrap(provider.udpSessions.first)
        XCTAssertEqual(session.endpoint.hostname, "i.instagram.com")
        XCTAssertEqual(session.endpoint.port, "443")
        XCTAssertEqual(session.writtenDatagrams, [payload])
        XCTAssertEqual(
            inbound.sentPayloads,
            [
                Socks5Codec.buildMethodSelection(method: 0x00),
                Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("0.0.0.0"), bindPort: 0)
            ]
        )

        let responsePayload = Data([0x04, 0x05])
        session.emitRead(responsePayload)
        queue.sync {}

        let responseFrame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .domain("i.instagram.com"),
                port: 443,
                payload: responsePayload
            )
        )
        XCTAssertEqual(inbound.sentPayloads.last, responseFrame)
    }

    func testTCPForwardUDPWaitsForSuccessReplyBeforeProcessingPipelinedFrames() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.forward-udp-reply-order")
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

        let payload = Data([0x09, 0x08, 0x07])
        let frame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .ipv4("1.1.1.1"),
                port: 53,
                payload: payload
            )
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.completeSendsAutomatically = false
            inbound.push(Self.request(command: 0x05, host: "0.0.0.0", port: 0))
            inbound.push(frame)

            XCTAssertTrue(provider.udpSessions.isEmpty)
            inbound.completeNextSend()
        }

        let session = try XCTUnwrap(provider.udpSessions.first)
        XCTAssertEqual(session.writtenDatagrams, [payload])
    }

    func testTCPForwardUDPSchedulesWaitingReplacementUntilNextDatagram() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.forward-udp-waiting")
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

        let frame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .ipv4("1.1.1.1"),
                port: 53,
                payload: Data([0x01])
            )
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: 0x05, host: "0.0.0.0", port: 0))
            inbound.push(frame)
        }

        let firstSession = try XCTUnwrap(provider.udpSessions.first)
        queue.sync {
            firstSession.eventHandler?(.waiting)
            firstSession.eventHandler?(.waiting)
            firstSession.eventHandler?(.waiting)
        }

        XCTAssertFalse(firstSession.cancelled)
        XCTAssertEqual(provider.udpSessions.count, 1)

        queue.sync {
            inbound.push(frame)
        }

        let secondSession = try XCTUnwrap(provider.udpSessions.last)
        XCTAssertTrue(firstSession.cancelled)
        XCTAssertFalse(secondSession === firstSession)
        XCTAssertEqual(provider.udpSessions.count, 2)
        XCTAssertEqual(firstSession.writtenDatagrams, [Data([0x01])])
        XCTAssertEqual(secondSession.writtenDatagrams, [Data([0x01])])
    }

    func testTCPForwardUDPRemovesFailedSessionAndRecreatesOnNextDatagram() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.forward-udp-failed")
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

        let frame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .ipv4("1.1.1.1"),
                port: 53,
                payload: Data([0x01])
            )
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: 0x05, host: "0.0.0.0", port: 0))
            inbound.push(frame)
        }

        let firstSession = try XCTUnwrap(provider.udpSessions.first)
        queue.sync {
            firstSession.eventHandler?(.failed)
        }

        XCTAssertTrue(firstSession.cancelled)
        XCTAssertEqual(provider.udpSessions.count, 1)

        queue.sync {
            inbound.push(frame)
        }

        let secondSession = try XCTUnwrap(provider.udpSessions.last)
        XCTAssertFalse(secondSession === firstSession)
        XCTAssertEqual(provider.udpSessions.count, 2)
        XCTAssertEqual(secondSession.writtenDatagrams, [Data([0x01])])
    }

    func testTCPForwardUDPSchedulesBetterPathReplacementUntilNextDatagram() throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.forward-udp-better-path")
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

        let frame = try XCTUnwrap(
            Socks5Codec.buildTCPForwardUDPPacket(
                address: .ipv4("1.1.1.1"),
                port: 53,
                payload: Data([0x01])
            )
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.request(command: 0x05, host: "0.0.0.0", port: 0))
            inbound.push(frame)
        }

        let firstSession = try XCTUnwrap(provider.udpSessions.first)
        queue.sync {
            firstSession.eventHandler?(.betterPathAvailable)
            firstSession.eventHandler?(.betterPathAvailable)
        }

        XCTAssertFalse(firstSession.cancelled)
        XCTAssertEqual(provider.udpSessions.count, 1)

        queue.sync {
            inbound.push(frame)
        }

        let secondSession = try XCTUnwrap(provider.udpSessions.last)
        XCTAssertTrue(firstSession.cancelled)
        XCTAssertFalse(secondSession === firstSession)
        XCTAssertEqual(provider.udpSessions.count, 2)
        XCTAssertEqual(secondSession.writtenDatagrams, [Data([0x01])])
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

    func testRetryingTCPOutboundLogsDestinationMetadataOnTimeout() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-timeout-metadata")
        let sink = InMemoryLogSink()
        let failed = expectation(description: "connect fails after timeout")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: sink),
            policy: .init(attemptPreparingTimeout: 0.03, retryBackoff: 0.01, maxAttempts: 1, overallTimeout: 0.1),
            endpointMetadata: [
                "destination_host": "api.example.com",
                "destination_port": "443",
                "destination_host_kind": "domain",
                "destination_transport": "tcp"
            ]
        ) { _ in
            ControlledTCPOutbound()
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                XCTFail("Expected timeout after exhausting retries")
            case .failure:
                failed.fulfill()
            }
        }

        await fulfillment(of: [failed], timeout: 1.0)
        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "RetryingTCPOutbound" && $0.event == "connect-timeout" }
        }
        let record = try XCTUnwrap(
            records.first { $0.component == "RetryingTCPOutbound" && $0.event == "connect-timeout" }
        )
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "443")
        XCTAssertEqual(record.metadata["destination_host_kind"], "domain")
        XCTAssertEqual(record.metadata["destination_transport"], "tcp")
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

    func testRetryingTCPOutboundLeavesWaitingAttemptAloneByDefault() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-waiting-default")
        let attempt = ControlledTCPOutbound()
        let ready = expectation(description: "waiting attempt eventually connects")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            policy: .init(attemptPreparingTimeout: 1.0, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 2.0)
        ) { _ in
            attempt
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                ready.fulfill()
            case .failure(let error):
                XCTFail("Expected waiting attempt to recover, got \(error)")
            }
        }

        queue.sync {
            for _ in 0..<5 {
                attempt.emit(.waiting)
            }
        }
        queue.sync {}

        XCTAssertEqual(attempt.restartCount, 0)
        attempt.succeedConnect()
        wait(for: [ready], timeout: 1.0)
    }

    func testRetryingTCPOutboundRestartsWaitingAttemptWhenExplicitlyEnabled() {
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

    func testRetryingTCPOutboundLimitsWaitingRestartStormWhenEnabled() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-waiting-storm")
        let attempt = ControlledTCPOutbound()
        let ready = expectation(description: "bounded waiting attempt eventually connects")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
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
            switch result {
            case .success:
                ready.fulfill()
            case .failure(let error):
                XCTFail("Expected bounded waiting attempt to recover, got \(error)")
            }
        }

        queue.sync {
            for _ in 0..<20 {
                attempt.emit(.waiting)
            }
        }
        queue.sync {}

        XCTAssertEqual(attempt.restartCount, 1)
        attempt.succeedConnect()
        wait(for: [ready], timeout: 1.0)
    }

    func testRetryingTCPOutboundWaitingAttemptTimesOutAndRetriesByDefault() {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.retry-waiting-timeout")
        let lock = NSLock()
        var attempts: [ControlledTCPOutbound] = []
        var firstAttempt: ControlledTCPOutbound?
        var secondAttempt: ControlledTCPOutbound?
        let firstAttemptCreated = expectation(description: "first attempt created")
        let secondAttemptCreated = expectation(description: "second attempt created")
        let ready = expectation(description: "waiting timeout retry eventually connects")

        let outbound = RetryingTCPOutbound(
            queue: queue,
            logger: StructuredLogger(sink: InMemoryLogSink()),
            policy: .init(attemptPreparingTimeout: 0.08, retryBackoff: 0.01, maxAttempts: 2, overallTimeout: 0.4)
        ) { attemptIndex in
            let attempt = ControlledTCPOutbound()
            lock.lock()
            attempts.append(attempt)
            if attemptIndex == 1 {
                firstAttempt = attempt
            } else if attemptIndex == 2 {
                secondAttempt = attempt
            }
            lock.unlock()
            if attemptIndex == 1 {
                firstAttemptCreated.fulfill()
            } else if attemptIndex == 2 {
                secondAttemptCreated.fulfill()
            }
            return attempt
        }

        outbound.waitUntilReady { result in
            switch result {
            case .success:
                ready.fulfill()
            case .failure(let error):
                XCTFail("Expected retry after waiting timeout to succeed, got \(error)")
            }
        }

        wait(for: [firstAttemptCreated], timeout: 1.0)
        queue.sync {
            firstAttempt?.emit(.waiting)
        }

        wait(for: [secondAttemptCreated], timeout: 1.0)
        secondAttempt?.succeedConnect()
        wait(for: [ready], timeout: 1.0)

        lock.lock()
        let snapshot = attempts
        lock.unlock()

        XCTAssertEqual(snapshot.count, 2)
        XCTAssertEqual(snapshot.first?.restartCount, 0)
        XCTAssertTrue(snapshot.first?.cancelled == true)
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

    func testNWConnectionTCPAdapterSnapshotsPathMetadataForAsyncCallbacks() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.tcp-path-snapshot")
        let sink = InMemoryLogSink()
        let connection = NWConnection(host: "127.0.0.1", port: 9, using: .tcp)
        let adapter = NWConnectionTCPAdapter(
            connection,
            queue: queue,
            logger: StructuredLogger(sink: sink)
        )

        adapter.waitUntilReady { _ in }
        let path = try await eventuallyFetchCurrentPath(from: connection)
        connection.pathUpdateHandler?(path)
        connection.viabilityUpdateHandler?(false)
        connection.betterPathUpdateHandler?(true)

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "NWConnectionTCPAdapter" && $0.event == "path-update" } &&
                records.contains { $0.component == "NWConnectionTCPAdapter" && $0.event == "viability-update" } &&
                records.contains { $0.component == "NWConnectionTCPAdapter" && $0.event == "better-path-available" }
        }

        let adapterRecords = records.filter { $0.component == "NWConnectionTCPAdapter" }
        XCTAssertTrue(adapterRecords.allSatisfy { $0.metadata["path"]?.contains("status=") == true })
        XCTAssertTrue(adapter.pathSnapshot.contains("status="))
        adapter.cancel()
        withExtendedLifetime(adapter) {}
    }

    func testNWConnectionUDPSessionAdapterSnapshotsPathMetadataForAsyncCallbacks() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.udp-path-snapshot")
        let sink = InMemoryLogSink()
        let connection = NWConnection(host: "127.0.0.1", port: 9, using: .udp)
        let adapter = NWConnectionUDPSessionAdapter(
            connection,
            queue: queue,
            logger: StructuredLogger(sink: sink),
            endpointMetadata: [
                "destination_host": "8.8.8.8",
                "destination_port": "53",
                "destination_host_kind": "ipv4",
                "destination_transport": "udp"
            ]
        )

        connection.stateUpdateHandler?(.waiting(.posix(.ENETDOWN)))
        let path = try await eventuallyFetchCurrentPath(from: connection)
        connection.pathUpdateHandler?(path)
        connection.viabilityUpdateHandler?(false)
        connection.betterPathUpdateHandler?(true)

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "NWConnectionUDPSessionAdapter" && $0.event == "waiting" } &&
                records.contains { $0.component == "NWConnectionUDPSessionAdapter" && $0.event == "path-update" } &&
                records.contains { $0.component == "NWConnectionUDPSessionAdapter" && $0.event == "viability-update" } &&
                records.contains { $0.component == "NWConnectionUDPSessionAdapter" && $0.event == "better-path-available" }
        }

        let adapterRecords = records.filter { $0.component == "NWConnectionUDPSessionAdapter" }
        XCTAssertTrue(adapterRecords.allSatisfy { $0.metadata["path"]?.contains("status=") == true })
        XCTAssertTrue(adapterRecords.allSatisfy { $0.metadata["destination_host"] == "<redacted>" })
        XCTAssertTrue(adapterRecords.allSatisfy { $0.metadata["destination_port"] == "53" })
        XCTAssertTrue(adapterRecords.allSatisfy { $0.metadata["destination_host_kind"] == "ipv4" })
        XCTAssertTrue(adapterRecords.allSatisfy { $0.metadata["destination_transport"] == "udp" })
        adapter.cancel()
        withExtendedLifetime(adapter) {}
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
        let record = try XCTUnwrap(
            records.first { $0.component == "Socks5Connection" && $0.event == "outbound-read-failed" }
        )
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "443")
        XCTAssertEqual(record.metadata["destination_host_kind"], "domain")
        XCTAssertEqual(record.metadata["destination_transport"], "tcp")
        XCTAssertTrue(inbound.cancelled)
    }

    func testOutboundReadENODATAIsLoggedAsNormalClose() async throws {
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
            outbound.queueRead(nil, error: NWError.posix(.ENODATA))
        }

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-closed" }
        }
        let record = try XCTUnwrap(
            records.first { $0.component == "Socks5Connection" && $0.event == "outbound-read-closed" && $0.level == .notice }
        )
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "443")
        XCTAssertEqual(record.metadata["destination_host_kind"], "domain")
        XCTAssertEqual(record.metadata["destination_transport"], "tcp")
        XCTAssertFalse(records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-failed" })
        XCTAssertTrue(inbound.cancelled)
    }

    func testOutboundReadBridgedENODATAIsLoggedAsNormalClose() async throws {
        let queue = DispatchQueue(label: "com.vpnbridge.tests.socks.outbound-read-bridged-close")
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
        let bridgedError = NSError(
            domain: "Network.NWError",
            code: Int(POSIXErrorCode.ENODATA.rawValue),
            userInfo: [NSLocalizedDescriptionKey: "The operation couldn’t be completed. (Network.NWError error 96 - No message available on STREAM)"]
        )

        queue.sync {
            connection.start()
            inbound.push(Self.greeting)
            inbound.push(Self.connectRequest(host: "example.com", port: 443))
            outbound.succeedConnect()
            outbound.queueRead(nil, error: bridgedError)
        }

        let records = try await eventuallyFetchRecords(from: sink) { records in
            records.contains { $0.component == "Socks5Connection" && $0.event == "outbound-read-closed" }
        }
        let record = try XCTUnwrap(
            records.first { $0.component == "Socks5Connection" && $0.event == "outbound-read-closed" && $0.level == .notice }
        )
        XCTAssertEqual(record.metadata["destination_host"], "<redacted>")
        XCTAssertEqual(record.metadata["destination_port"], "443")
        XCTAssertEqual(record.metadata["destination_host_kind"], "domain")
        XCTAssertEqual(record.metadata["destination_transport"], "tcp")
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
    private let lock = NSLock()
    private var readyHandlers: [(@Sendable (Result<Void, Error>) -> Void)] = []
    private var readyResult: Result<Void, Error>?
    private var pendingReadHandlers: [(@Sendable (Data?, Error?) -> Void)] = []
    private var pendingWriteHandlers: [(@Sendable (Error?) -> Void)] = []
    private var queuedReads: [(Data?, Error?)] = []
    private var storedWrites: [Data] = []
    private var storedCancelled = false
    private var storedReadRequests = 0
    private var storedRestartCount = 0
    private var storedAutoCompleteWrites = true
    private var storedOnRestart: (() -> Void)?
    private var storedEventHandler: ((TCPOutboundEvent) -> Void)?
    private var storedPathSnapshot = "status=unknown uses=unknown"

    var writes: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return storedWrites
    }

    var cancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storedCancelled
    }

    var readRequests: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedReadRequests
    }

    var restartCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedRestartCount
    }

    var autoCompleteWrites: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedAutoCompleteWrites
        }
        set {
            lock.lock()
            storedAutoCompleteWrites = newValue
            lock.unlock()
        }
    }

    var onRestart: (() -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedOnRestart
        }
        set {
            lock.lock()
            storedOnRestart = newValue
            lock.unlock()
        }
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

    var pathSnapshot: String {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedPathSnapshot
        }
        set {
            lock.lock()
            storedPathSnapshot = newValue
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

    func readMinimumLength(_: Int, maximumLength _: Int, completionHandler: @escaping @Sendable (Data?, (any Error)?) -> Void) {
        let queuedRead: (Data?, Error?)?
        lock.lock()
        storedReadRequests += 1
        if !queuedReads.isEmpty {
            queuedRead = queuedReads.removeFirst()
        } else {
            queuedRead = nil
            pendingReadHandlers.append(completionHandler)
        }
        lock.unlock()

        if let queuedRead {
            completionHandler(queuedRead.0, queuedRead.1)
        }
    }

    func write(_ data: Data, completionHandler: @escaping @Sendable ((any Error)?) -> Void) {
        let shouldComplete: Bool
        lock.lock()
        storedWrites.append(data)
        shouldComplete = storedAutoCompleteWrites
        if !shouldComplete {
            pendingWriteHandlers.append(completionHandler)
        }
        lock.unlock()

        if shouldComplete {
            completionHandler(nil)
        }
    }

    func cancel() {
        lock.lock()
        storedCancelled = true
        lock.unlock()
    }

    func restart() {
        let onRestart: (() -> Void)?
        lock.lock()
        storedRestartCount += 1
        onRestart = storedOnRestart
        lock.unlock()
        onRestart?()
    }

    func succeedConnect() {
        let handlers: [(@Sendable (Result<Void, Error>) -> Void)]
        lock.lock()
        guard readyResult == nil else {
            lock.unlock()
            return
        }
        readyResult = .success(())
        handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        lock.unlock()
        for handler in handlers {
            handler(.success(()))
        }
    }

    func failConnect(_ error: Error) {
        let handlers: [(@Sendable (Result<Void, Error>) -> Void)]
        lock.lock()
        guard readyResult == nil else {
            lock.unlock()
            return
        }
        readyResult = .failure(error)
        handlers = readyHandlers
        readyHandlers.removeAll(keepingCapacity: false)
        lock.unlock()
        for handler in handlers {
            handler(.failure(error))
        }
    }

    func emit(_ event: TCPOutboundEvent) {
        lock.lock()
        let handler = storedEventHandler
        lock.unlock()
        handler?(event)
    }

    func queueRead(_ data: Data?, error: Error? = nil) {
        let handler: (@Sendable (Data?, Error?) -> Void)?
        lock.lock()
        if !pendingReadHandlers.isEmpty {
            handler = pendingReadHandlers.removeFirst()
        } else {
            handler = nil
            queuedReads.append((data, error))
        }
        lock.unlock()
        handler?(data, error)
    }

    func completeNextWrite(error: Error? = nil) {
        let completion: (@Sendable (Error?) -> Void)?
        lock.lock()
        if pendingWriteHandlers.isEmpty {
            completion = nil
        } else {
            completion = pendingWriteHandlers.removeFirst()
        }
        lock.unlock()
        guard let completion else {
            XCTFail("Expected a pending write completion")
            return
        }
        completion(error)
    }
}

private final class ControlledUDPSession: @unchecked Sendable, Socks5UDPSession {
    let endpoint: NWHostEndpoint
    private var readHandler: (@Sendable (Data?, Error?) -> Void)?
    private(set) var writtenDatagrams: [Data] = []
    private(set) var cancelled = false
    private(set) var restartCount = 0
    var eventHandler: ((Socks5UDPSessionEvent) -> Void)?

    init(endpoint: NWHostEndpoint) {
        self.endpoint = endpoint
    }

    func setReadHandler(_ handler: @escaping @Sendable (Data?, Error?) -> Void) {
        readHandler = handler
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping @Sendable (Error?) -> Void) {
        writtenDatagrams.append(datagram)
        completionHandler(nil)
    }

    func restart() {
        restartCount += 1
    }

    func cancel() {
        cancelled = true
    }

    func emitRead(_ data: Data?, error: Error? = nil) {
        readHandler?(data, error)
    }
}

private final class ControlledUDPAssociateRelay: Socks5UDPRelayProtocol {
    let port: UInt16
    private(set) var started = false
    private(set) var stopped = false

    init(port: UInt16) {
        self.port = port
    }

    func start() {
        started = true
    }

    func stop() {
        stopped = true
    }
}

private final class FakeProvider: Socks5FullConnectionProvider, @unchecked Sendable {
    private let outbound: ControlledTCPOutbound
    private(set) var udpSessions: [ControlledUDPSession] = []

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

    func makeUDPSession(to endpoint: NWHostEndpoint) -> any Socks5UDPSession {
        let session = ControlledUDPSession(endpoint: endpoint)
        udpSessions.append(session)
        return session
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

private func eventuallyFetchCurrentPath(from connection: NWConnection) async throws -> Network.NWPath {
    for _ in 0..<20 {
        if let path = connection.currentPath {
            return path
        }
        try await Task.sleep(for: .milliseconds(25))
    }
    throw TestPathError.unavailable
}

private enum TestPathError: Error {
    case unavailable
}
