//
//  BridgeHarness.swift
//  PacketTunnel
//
//  Provides a lightweight packet loop simulator for local validation.
//

import Foundation
import Network
import os.log
import Darwin

#if DEBUG

enum BridgeHarnessError: Error {
    case readerNotReady
    case echoTimedOut
}

/// Minimal harness that exercises the adapter + stub engine without needing the host app.
enum BridgeHarness {
    /// Runs an echo simulation through the `NoOpTun2SocksEngine`.
    /// - Parameters:
    ///   - payloads: Raw packets to feed into the adapter.
    ///   - protocolNumbers: Corresponding protocol identifiers (defaults to IPv4).
    ///   - timeout: How long to wait for the echo to appear.
    /// - Returns: The packets emitted back through the packet flow.
    @discardableResult
    static func runEchoSimulation(
        payloads: [Data],
        protocolNumbers: [NSNumber] = [.init(value: AF_INET)],
        timeout: TimeInterval = 1.0
    ) throws -> [Data] {
        precondition(!payloads.isEmpty, "Provide at least one packet")

        let flow = MockPacketFlow()
        let provider = MockPacketTunnelProvider(flow: flow)
        let metrics = BridgeMetrics(subsystem: "PacketTunnelHarness")
        let logger = Logger(subsystem: "PacketTunnelHarness", category: "Harness")
        let engine = NoOpTun2SocksEngine(logger: logger)
        let adapter = Tun2SocksAdapter(
            provider: provider,
            configuration: .default,
            metrics: metrics,
            engine: engine
        )

        try adapter.start()
        defer { adapter.stop() }

        guard flow.waitForReadHandler(timeout: timeout) else {
            throw BridgeHarnessError.readerNotReady
        }

        flow.deliver(packets: payloads, protocols: protocolNumbers)

        guard flow.waitForWrites(minimumCount: 1, timeout: timeout) else {
            throw BridgeHarnessError.echoTimedOut
        }

        return flow.drainWrites().flatMap(\.packets)
    }
}

// MARK: - Mocks

private final class MockPacketFlow: PacketFlowing {
    private let queue = DispatchQueue(label: "PacketTunnel.MockPacketFlow")
    private var readHandler: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var readSemaphore = DispatchSemaphore(value: 0)
    private var writes: [(packets: [Data], protocols: [NSNumber])] = []

    func readPackets(_ handler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        queue.async {
            self.readHandler = handler
            self.readSemaphore.signal()
        }
    }

    func writePackets(_ packets: [Data], protocols: [NSNumber]) {
        queue.async {
            guard !packets.isEmpty else { return }
            self.writes.append((packets, protocols))
        }
    }

    func waitForReadHandler(timeout: TimeInterval) -> Bool {
        readSemaphore.wait(timeout: .now() + timeout) == .success
    }

    func deliver(packets: [Data], protocols: [NSNumber]) {
        queue.async {
            guard let handler = self.readHandler else { return }
            self.readHandler = nil
            handler(packets, protocols)
        }
    }

    func waitForWrites(minimumCount: Int, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var count = 0
            queue.sync {
                count = self.writes.count
            }
            if count >= minimumCount {
                return true
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return false
    }

    func drainWrites() -> [(packets: [Data], protocols: [NSNumber])] {
        var snapshot: [(packets: [Data], protocols: [NSNumber])] = []
        queue.sync {
            snapshot = self.writes
            self.writes.removeAll()
        }
        return snapshot
    }
}

private final class MockPacketTunnelProvider: PacketTunnelProviding {
    let flow: PacketFlowing

    init(flow: PacketFlowing) {
        self.flow = flow
    }

    func makeTCPConnection(to remoteEndpoint: Network.NWEndpoint) -> Network.NWConnection {
        fatalError("TCP connections are not supported in the harness")
    }

    func makeUDPConnection(
        to remoteEndpoint: Network.NWEndpoint,
        from localEndpoint: Network.NWEndpoint?
    ) -> Network.NWConnection {
        fatalError("UDP sessions are not supported in the harness")
    }
}

#endif
