//
//  Tun2SocksAdapterTests.swift
//  RelativeProtocolTunnelTests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Covers adapter lifecycle, packet forwarding, metrics emission, and block
//  policy behaviour using mock providers and engines.
//
import Foundation
import XCTest
import Network
@testable import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class Tun2SocksAdapterTests: XCTestCase {
    private func makeConfiguration(
        packetTap: @escaping @Sendable (RelativeProtocol.Configuration.PacketContext) -> Void,
        blockedHosts: [String] = [],
        eventSink: RelativeProtocol.Configuration.EventSink? = nil
    ) -> RelativeProtocol.Configuration {
        RelativeProtocol.Configuration(
            provider: .init(
                mtu: 1500,
                ipv4: .init(
                    address: "10.0.0.2",
                    subnetMask: "255.255.255.0",
                    remoteAddress: "10.0.0.1"
                ),
                dns: .init(servers: ["1.1.1.1"]),
                metrics: .init(isEnabled: true, reportingInterval: 0.0),
                policies: .init(blockedHosts: blockedHosts)
            ),
            hooks: .init(packetTap: packetTap, eventSink: eventSink),
            logging: .init(enableDebug: false)
        )
    }

    func testStartAndStopLifecycle() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockTun2SocksEngine()
        let configuration = makeConfiguration { _ in }
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)

        try adapter.start()

        wait(for: [readLoopInstalled], timeout: 1.0)
        XCTAssertEqual(engine.startCallCount, 1)

        adapter.stop()
        XCTAssertEqual(engine.stopCallCount, 1)
    }

    func testInboundPacketsForwardedToEngine() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockTun2SocksEngine()
        let configuration = makeConfiguration { _ in }
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)

        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let engineReceived = expectation(description: "engine received packet")
        engine.onReceive = { packets, protocols in
            XCTAssertEqual(packets.count, 1)
            XCTAssertEqual(protocols.count, 1)
            XCTAssertEqual(packets.first, Data([0x45, 0x00]))
            engineReceived.fulfill()
        }

        flow.deliver(packets: [Data([0x45, 0x00])], protocols: [NSNumber(value: Int32(AF_INET))])

        wait(for: [engineReceived], timeout: 1.0)
    }

    func testOutboundPacketsReachPacketFlow() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockTun2SocksEngine()
        let configuration = makeConfiguration { _ in }
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)
        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let packetsWritten = expectation(description: "packets written")
        flow.onWrite = { packets, protocols in
            XCTAssertEqual(packets.count, 1)
            XCTAssertEqual(protocols.count, 1)
            XCTAssertEqual(packets.first, Data([0x60, 0x00]))
            packetsWritten.fulfill()
        }

        engine.emit(packets: [Data([0x60, 0x00])], protocols: [NSNumber(value: Int32(AF_INET6))])

        wait(for: [packetsWritten], timeout: 1.0)
    }

    func testRoundTripEmitsMetricsAndPacketTap() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockTun2SocksEngine()
        let tappedContexts = ThreadSafeArray<RelativeProtocol.Configuration.PacketContext>()
        let configuration = makeConfiguration { context in
            tappedContexts.append(context)
        }

        let metricsExpectation = expectation(description: "metrics emitted twice")
        metricsExpectation.expectedFulfillmentCount = 2
        let snapshots = ThreadSafeArray<RelativeProtocol.MetricsSnapshot>()
        let metrics = MetricsCollector(subsystem: "test", interval: 0.0) { snapshot in
            snapshots.append(snapshot)
            metricsExpectation.fulfill()
        }
        metrics.reset()

        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: metrics,
            engine: engine,
            hooks: configuration.hooks
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)
        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        flow.deliver(packets: [Data([0x45, 0x10, 0x00, 0x00])], protocols: [NSNumber(value: Int32(AF_INET))])
        engine.emit(packets: [Data([0x60, 0x11, 0x00, 0x00])], protocols: [NSNumber(value: Int32(AF_INET6))])

        wait(for: [metricsExpectation], timeout: 1.0)

        let recordedContexts = tappedContexts.values()
        XCTAssertGreaterThanOrEqual(recordedContexts.count, 2)
        XCTAssertTrue(recordedContexts.contains(where: { $0.direction == .inbound }))
        XCTAssertTrue(recordedContexts.contains(where: { $0.direction == .outbound }))

        let recordedSnapshots = snapshots.values()
        XCTAssertEqual(recordedSnapshots.count, 2)
        XCTAssertTrue(recordedSnapshots.contains(where: { $0.inbound.packets > 0 }))
        XCTAssertTrue(recordedSnapshots.contains(where: { $0.outbound.packets > 0 }))

        adapter.stop()
    }

    func testAnalyzerReceivesPacketsWhenStreamProvided() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockTun2SocksEngine()

        var configuration = makeConfiguration { _ in }
        let stream = RelativeProtocol.PacketStream(configuration: .init(bufferDuration: 60))
        configuration.hooks.packetStreamBuilder = { stream }

        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks
        )

        XCTAssertNotNil(adapter.analyzer)

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)

        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        flow.deliver(packets: [Data([0x45, 0x00])], protocols: [NSNumber(value: Int32(AF_INET))])
        engine.emit(packets: [Data([0x60, 0x00])], protocols: [NSNumber(value: Int32(AF_INET6))])

        let snapshotExpectation = expectation(description: "stream recorded samples")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
            stream.snapshot { samples in
                if samples.count >= 2 {
                    snapshotExpectation.fulfill()
                }
            }
        }

        wait(for: [snapshotExpectation], timeout: 1.0)
        adapter.stop()
    }

    func testLifecycleEventsTriggerHooks() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockTun2SocksEngine()
        let events = ThreadSafeArray<RelativeProtocol.Configuration.Event>()
        let configuration = makeConfiguration(
            packetTap: { _ in },
            eventSink: { event in events.append(event) }
        )
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)

        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        adapter.stop()

        let recordedEvents = events.values()
        XCTAssertEqual(recordedEvents.count, 3)
        guard recordedEvents.count == 3 else { return }
        if case .willStart = recordedEvents[0] {} else { XCTFail("First event should be willStart") }
        if case .didStart = recordedEvents[1] {} else { XCTFail("Second event should be didStart") }
        if case .didStop = recordedEvents[2] {} else { XCTFail("Third event should be didStop") }
    }

    func testBlockedTCPHostTriggersFailureEvent() throws {
        let flow = MockPacketFlow()
        let provider = RecordingProvider(flow: flow)
        let engine = MockTun2SocksEngine()
        let failureExpectation = expectation(description: "blocked tcp host reported")
        let configuration = makeConfiguration(
            packetTap: { _ in },
            blockedHosts: ["blocked.test"],
            eventSink: { event in
                if case let .didFail(message) = event, message.contains("blocked.test") {
                    failureExpectation.fulfill()
                }
            }
        )
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)
        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let endpoint = NWEndpoint.hostPort(
            host: .init("blocked.test"),
            port: .init(rawValue: 443)!
        )
        _ = engine.requestTCPConnection(to: endpoint)

        wait(for: [failureExpectation], timeout: 1.0)
        XCTAssertEqual(provider.tcpRequests.count, 1)
        adapter.stop()
    }

    func testBlockedUDPHostTriggersFailureEvent() throws {
        let flow = MockPacketFlow()
        let provider = RecordingProvider(flow: flow)
        let engine = MockTun2SocksEngine()
        let failureExpectation = expectation(description: "blocked udp host reported")
        let configuration = makeConfiguration(
            packetTap: { _ in },
            blockedHosts: ["blocked.test"],
            eventSink: { event in
                if case let .didFail(message) = event, message.contains("blocked.test") {
                    failureExpectation.fulfill()
                }
            }
        )
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)
        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let endpoint = NWEndpoint.hostPort(
            host: .init("blocked.test"),
            port: .init(rawValue: 53)!
        )
        _ = engine.requestUDPConnection(to: endpoint)

        wait(for: [failureExpectation], timeout: 1.0)
        XCTAssertEqual(provider.udpRequests.count, 1)
        adapter.stop()
    }
}

// MARK: - Test doubles

private final class MockTun2SocksEngine: Tun2SocksEngine {
    private(set) var startCallCount = 0
    private(set) var stopCallCount = 0
    var onReceive: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var emitClosure: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var tcpFactory: (@Sendable (NWEndpoint) -> NWConnection)?
    private var udpFactory: (@Sendable (NWEndpoint) -> NWConnection)?

    func start(callbacks: Tun2SocksCallbacks) throws {
        startCallCount += 1
        tcpFactory = callbacks.makeTCPConnection
        udpFactory = callbacks.makeUDPConnection
        callbacks.startPacketReadLoop { [weak self] packets, protocols in
            self?.onReceive?(packets, protocols)
        }
        emitClosure = callbacks.emitPackets
    }

    func stop() {
        stopCallCount += 1
    }

    func emit(packets: [Data], protocols: [NSNumber]) {
        emitClosure?(packets, protocols)
    }

    @discardableResult
    func requestTCPConnection(to endpoint: NWEndpoint) -> NWConnection? {
        tcpFactory?(endpoint)
    }

    @discardableResult
    func requestUDPConnection(to endpoint: NWEndpoint) -> NWConnection? {
        udpFactory?(endpoint)
    }
}

private final class MockPacketFlow: PacketFlowing {
    private var handler: (@Sendable ([Data], [NSNumber]) -> Void)?
    var onRead: (() -> Void)?
    var onWrite: (([Data], [NSNumber]) -> Void)?

    func readPackets(_ handler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        self.handler = handler
        onRead?()
    }

    func writePackets(_ packets: [Data], protocols: [NSNumber]) {
        onWrite?(packets, protocols)
    }

    func deliver(packets: [Data], protocols: [NSNumber]) {
        handler?(packets, protocols)
    }
}

private final class MockProvider: PacketTunnelProviding {
    let flow: PacketFlowing

    init(flow: PacketFlowing) {
        self.flow = flow
    }

    func makeTCPConnection(to remoteEndpoint: Network.NWEndpoint) -> Network.NWConnection {
        fatalError("Not implemented in tests")
    }

    func makeUDPConnection(to remoteEndpoint: Network.NWEndpoint, from localEndpoint: Network.NWEndpoint?) -> Network.NWConnection {
        fatalError("Not implemented in tests")
    }
}

private final class RecordingProvider: PacketTunnelProviding {
    let flow: PacketFlowing
    private let tcpRequestsStorage = ThreadSafeArray<NWEndpoint>()
    private let udpRequestsStorage = ThreadSafeArray<NWEndpoint>()

    var tcpRequests: [NWEndpoint] { tcpRequestsStorage.values() }
    var udpRequests: [NWEndpoint] { udpRequestsStorage.values() }

    init(flow: PacketFlowing) {
        self.flow = flow
    }

    func makeTCPConnection(to remoteEndpoint: NWEndpoint) -> NWConnection {
        tcpRequestsStorage.append(remoteEndpoint)
        return NWConnection(to: remoteEndpoint, using: NWParameters(tls: nil, tcp: NWProtocolTCP.Options()))
    }

    func makeUDPConnection(
        to remoteEndpoint: NWEndpoint,
        from localEndpoint: NWEndpoint?
    ) -> NWConnection {
        udpRequestsStorage.append(remoteEndpoint)
        let params = NWParameters(dtls: nil, udp: NWProtocolUDP.Options())
        return NWConnection(to: remoteEndpoint, using: params)
    }
}

private func fulfillOnce(expectation: XCTestExpectation) -> () -> Void {
    let token = ExpectationOnce(expectation: expectation)
    return {
        token.fulfill()
    }
}

private final class ExpectationOnce {
    private let expectation: XCTestExpectation
    private let lock = NSLock()
    private var fulfilled = false

    init(expectation: XCTestExpectation) {
        self.expectation = expectation
    }

    func fulfill() {
        lock.lock()
        defer { lock.unlock() }
        guard !fulfilled else { return }
        fulfilled = true
        expectation.fulfill()
    }
}

// MARK: - Helpers

private final class ThreadSafeArray<Element>: @unchecked Sendable {
    private var storage: [Element] = []
    private let lock = NSLock()

    func append(_ element: Element) {
        lock.lock()
        defer { lock.unlock() }
        storage.append(element)
    }

    func values() -> [Element] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage.count
    }
}
