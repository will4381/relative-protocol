//
//  PerformanceTests.swift
//  RelativeProtocolPerformanceTests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//

import XCTest
import Network
import os.log
@testable import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class RelativeProtocolPerformanceTests: XCTestCase {

    func testConfigurationValidationPerformance() throws {
        let configuration = makeTestConfiguration()
        // Warm-up validation to populate caches.
        _ = try configuration.validateOrThrow()

        measure {
            for _ in 0..<500 {
                _ = try? configuration.validateOrThrow()
            }
        }
    }

    func testMetricsCollectorRecordPerformance() {
        _ = makeTestConfiguration() // exercise hook construction path

        let collector = MetricsCollector(
            subsystem: "RelativeProtocolTests",
            interval: 10,
            sink: nil
        )

        measure {
            for _ in 0..<5_000 {
                collector.record(direction: .inbound, packets: 1, bytes: 128)
                collector.record(direction: .outbound, packets: 1, bytes: 256)
            }
        }
    }

    func testAdapterReadLoopPerformance() throws {
        let flow = MockPacketFlow()
        let provider = MockProvider(flow: flow)
        let configuration = makeTestConfiguration()
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: configuration,
            metrics: nil,
            engine: NoOpTun2SocksEngine(
                logger: Logger(subsystem: "RelativeProtocolTests", category: "NoOp"),
                debugLoggingEnabled: configuration.logging.enableDebug
            ),
            hooks: configuration.hooks
        )
        try adapter.start()
        XCTAssertTrue(flow.waitForHandler(timeout: 1), "Adapter did not register read handler in time")
        addTeardownBlock {
            adapter.stop()
            flow.drain()
        }

        let packet = Data(repeating: 0, count: 128)
        let proto: NSNumber = .init(value: AF_INET)

        let iterations = 200

        measure {
            for _ in 0..<iterations {
                flow.trigger(packets: [packet], protocols: [proto])
            }
            flow.drain()
        }
    }

    private func makeTestConfiguration() -> RelativeProtocol.Configuration {
        let provider = RelativeProtocol.Configuration.Provider(
            mtu: 1500,
            ipv4: .init(
                address: "10.0.0.2",
                subnetMask: "255.255.255.0",
                remoteAddress: "198.51.100.1"
            ),
            dns: .init(servers: ["1.1.1.1", "8.8.8.8"]),
            metrics: .init(isEnabled: true, reportingInterval: 5),
            policies: .init(blockedHosts: ["example.com"])
        )

        let hooks = RelativeProtocol.Configuration.Hooks(
            packetTap: { context in
                // Simulate burst classification by examining the first byte.
                if let byte = context.payload.first {
                    _ = (byte & 0xF0) >> 4
                }
            },
            dnsResolver: { host in
                // Pretend to provide dual-stack answers.
                [host, "2001:db8::1"]
            },
            connectionPolicy: { endpoint in
                if endpoint.transport == .tcp && endpoint.port == 80 {
                    return .block(reason: "HTTP disallowed in tests")
                }
                return .allow
            },
            latencyInjector: { endpoint in
                endpoint.transport == .udp ? 25 : nil
            },
            eventSink: { _ in }
        )

        return RelativeProtocol.Configuration(
            provider: provider,
            hooks: hooks,
            logging: .init(enableDebug: true)
        )
    }
}

// MARK: - Test Doubles

private final class MockPacketFlow: PacketFlowing {
    private let queue = DispatchQueue(label: "RelativeProtocolTests.MockPacketFlow")
    private var handler: (@Sendable ([Data], [NSNumber]) -> Void)?
    private let handlerSemaphore = DispatchSemaphore(value: 0)

    func readPackets(_ handler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        self.handler = handler
        handlerSemaphore.signal()
    }

    func writePackets(_ packets: [Data], protocols: [NSNumber]) {
        // No-op: tests ignore outbound writes.
    }

    func trigger(packets: [Data], protocols: [NSNumber]) {
        queue.async { [weak self] in
            self?.handler?(packets, protocols)
        }
    }

    func waitForHandler(timeout: TimeInterval) -> Bool {
        handlerSemaphore.wait(timeout: .now() + timeout) == .success
    }

    func drain() {
        queue.sync {}
    }
}

private final class MockProvider: PacketTunnelProviding {
    let flow: PacketFlowing

    init(flow: PacketFlowing) {
        self.flow = flow
    }

    func makeTCPConnection(to remoteEndpoint: NWEndpoint) -> NWConnection {
        fatalError("MockProvider.makeTCPConnection should not be invoked in performance tests.")
    }

    func makeUDPConnection(
        to remoteEndpoint: NWEndpoint,
        from localEndpoint: NWEndpoint?
    ) -> NWConnection {
        fatalError("MockProvider.makeUDPConnection should not be invoked in performance tests.")
    }
}
