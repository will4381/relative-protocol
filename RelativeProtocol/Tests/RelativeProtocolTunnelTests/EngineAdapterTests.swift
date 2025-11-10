//
//  EngineAdapterTests.swift
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
import os.log
@testable import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class EngineAdapterTests: XCTestCase {
    private let testLogger = Logger(subsystem: "RelativeProtocolTests", category: "AdapterTests")

    private func makeIPv4Packet(
        source: (UInt8, UInt8, UInt8, UInt8) = (192, 0, 2, 10),
        destination: (UInt8, UInt8, UInt8, UInt8) = (8, 8, 8, 8)
    ) -> Data {
        var bytes = [UInt8](repeating: 0, count: 20)
        bytes[0] = 0x45 // Version 4, header length 5
        bytes[8] = 64 // TTL
        bytes[9] = 6 // TCP
        bytes[12] = source.0
        bytes[13] = source.1
        bytes[14] = source.2
        bytes[15] = source.3
        bytes[16] = destination.0
        bytes[17] = destination.1
        bytes[18] = destination.2
        bytes[19] = destination.3
        return Data(bytes)
    }

    private func makeIPv6Packet(
        source: [UInt8] = [0x26, 0x07, 0xf8, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        destination: [UInt8] = [0x26, 0x07, 0xf8, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
    ) -> Data {
        precondition(source.count == 16 && destination.count == 16)
        var bytes = [UInt8](repeating: 0, count: 40)
        bytes[0] = 0x60 // Version 6
        for index in 0..<16 {
            bytes[8 + index] = source[index]
            bytes[24 + index] = destination[index]
        }
        bytes[6] = 17 // UDP
        return Data(bytes)
    }

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
        let engine = MockEngine()
        let configuration = makeConfiguration { _ in }
        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
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
        let engine = MockEngine()
        let configuration = makeConfiguration { _ in }
        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)

        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let ipv4Packet = makeIPv4Packet()
        let engineReceived = expectation(description: "engine received packet")
        engine.onReceive = { packets, protocols in
            XCTAssertEqual(packets.count, 1)
            XCTAssertEqual(protocols.count, 1)
            XCTAssertEqual(packets.first, ipv4Packet)
            engineReceived.fulfill()
        }

        flow.deliver(packets: [ipv4Packet], protocols: [NSNumber(value: Int32(AF_INET))])

        wait(for: [engineReceived], timeout: 1.0)
    }

    func testOutboundPacketsReachPacketFlow() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockEngine()
        let configuration = makeConfiguration { _ in }
        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)
        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let packetsWritten = expectation(description: "packets written")
        let ipv6Packet = makeIPv6Packet()
        flow.onWrite = { packets, protocols in
            XCTAssertEqual(packets.count, 1)
            XCTAssertEqual(protocols.count, 1)
            XCTAssertEqual(packets.first, ipv6Packet)
            packetsWritten.fulfill()
        }

        engine.emit(packets: [ipv6Packet], protocols: [NSNumber(value: Int32(AF_INET6))])

        wait(for: [packetsWritten], timeout: 1.0)
    }

    func testTrafficShapingPolicyStoreMatchesHostSuffix() {
        let policy = RelativeProtocol.Configuration.TrafficShapingPolicy(
            fixedLatencyMilliseconds: 50,
            jitterMilliseconds: 10,
            bytesPerSecond: 512_000
        )
        let rule = RelativeProtocol.Configuration.TrafficShapingRule(
            hosts: ["*.example.com"],
            policy: policy
        )
        let shaping = RelativeProtocol.Configuration.TrafficShaping(
            defaultPolicy: nil,
            rules: [rule]
        )
        let store = TrafficShapingPolicyStore(configuration: shaping)

        XCTAssertTrue(store.hasPolicies)

        let key = PolicyKey(
            host: "cdn.example.com",
            ip: "203.0.113.10",
            port: 443,
            protocolNumber: 6
        )

        let matched = store.policy(for: key)
        XCTAssertNotNil(matched)
        XCTAssertEqual(matched?.fixedLatencyMilliseconds, 50)
    }

    func testTrafficShapingPolicyStoreFallsBackToDefault() {
        let defaultPolicy = RelativeProtocol.Configuration.TrafficShapingPolicy(
            fixedLatencyMilliseconds: 25,
            jitterMilliseconds: 0,
            bytesPerSecond: nil
        )
        let shaping = RelativeProtocol.Configuration.TrafficShaping(
            defaultPolicy: defaultPolicy,
            rules: []
        )
        let store = TrafficShapingPolicyStore(configuration: shaping)

        XCTAssertTrue(store.hasPolicies)

        let key = PolicyKey(
            host: nil,
            ip: "198.51.100.2",
            port: 123,
            protocolNumber: 17
        )

        let matched = store.policy(for: key)
        XCTAssertNotNil(matched)
        XCTAssertEqual(matched?.fixedLatencyMilliseconds, 25)
    }

    func testRoundTripEmitsMetricsAndPacketTap() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockEngine()
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

        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: metrics,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)
        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let outboundPacket = makeIPv4Packet()
        let inboundPacket = makeIPv6Packet()
        flow.deliver(packets: [outboundPacket], protocols: [NSNumber(value: Int32(AF_INET))])
        engine.emit(packets: [inboundPacket], protocols: [NSNumber(value: Int32(AF_INET6))])

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
        let engine = MockEngine()

        var configuration = makeConfiguration { _ in }
        let stream = RelativeProtocol.PacketStream(configuration: .init(bufferDuration: 60))
        configuration.hooks.packetStreamBuilder = { stream }

        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
        )

        XCTAssertNotNil(adapter.analyzer)

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)

        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        flow.deliver(packets: [makeIPv4Packet()], protocols: [NSNumber(value: Int32(AF_INET))])
        engine.emit(packets: [makeIPv6Packet()], protocols: [NSNumber(value: Int32(AF_INET6))])

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

    func testPrivateTrafficIsNotBuffered() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockEngine()

        var configuration = makeConfiguration { _ in }
        let stream = RelativeProtocol.PacketStream(configuration: .init(bufferDuration: 60))
        configuration.hooks.packetStreamBuilder = { stream }

        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        flow.onRead = fulfillOnce(expectation: readLoopInstalled)

        try adapter.start()
        wait(for: [readLoopInstalled], timeout: 1.0)

        let privateOutbound = makeIPv4Packet(destination: (192, 168, 1, 1))
        flow.deliver(packets: [privateOutbound], protocols: [NSNumber(value: Int32(AF_INET))])

        let privateInbound = makeIPv6Packet(
            source: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        )
        engine.emit(packets: [privateInbound], protocols: [NSNumber(value: Int32(AF_INET6))])

        let snapshotExpectation = expectation(description: "snapshot complete")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
            stream.snapshot { samples in
                if !samples.isEmpty {
                    let descriptions = samples.map { sample -> String in
                        let direction = sample.direction.rawValue
                        let bytes = sample.byteCount
                        if let metadata = sample.metadata {
                            let remote = metadata.remoteAddress(for: sample.direction)
                            let local = metadata.localAddress(for: sample.direction)
                            let transport: String
                            switch metadata.transport {
                            case let .tcp(sourcePort, destinationPort):
                                transport = "tcp \(sourcePort)->\(destinationPort)"
                            case let .udp(sourcePort, destinationPort):
                                transport = "udp \(sourcePort)->\(destinationPort)"
                            case let .other(number):
                                transport = "proto \(number)"
                            }
                            return "\(direction) \(bytes)B remote=\(remote) local=\(local) \(transport)"
                        }
                        return "\(direction) \(bytes)B"
                    }.joined(separator: "; ")
                    XCTFail("PacketStream captured \(samples.count) samples for private endpoints: \(descriptions)")
                }
                snapshotExpectation.fulfill()
            }
        }

        wait(for: [snapshotExpectation], timeout: 1.0)
        adapter.stop()
    }

    func testLifecycleEventsTriggerHooks() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let engine = MockEngine()
        let events = ThreadSafeArray<RelativeProtocol.Configuration.Event>()
        let configuration = makeConfiguration(
            packetTap: { _ in },
            eventSink: { event in events.append(event) }
        )
        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
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
        let engine = MockEngine()
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
        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
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
        let engine = MockEngine()
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
        let adapter = EngineAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: engine,
            hooks: configuration.hooks,
            logger: testLogger
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

private final class MockEngine: Engine {
    private(set) var startCallCount = 0
    private(set) var stopCallCount = 0
    var onReceive: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var emitClosure: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var tcpFactory: (@Sendable (NWEndpoint) -> NWConnection)?
    private var udpFactory: (@Sendable (NWEndpoint) -> NWConnection)?

    func start(callbacks: EngineCallbacks) throws {
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
