//
//  BridgeMetrics.swift
//  PacketTunnel
//
//  Captures lightweight instrumentation hooks around the bridge.
//

import Foundation
import os.log

final class BridgeMetrics {
    enum Direction {
        case inbound
        case outbound
    }

    private struct Counter {
        var packets: Int = 0
        var bytes: Int = 0
    }

    private let logger: Logger
    private let queue = DispatchQueue(label: "PacketTunnel.BridgeMetrics")
    private var inbound = Counter()
    private var outbound = Counter()
    private var lastReport = Date()

    init(subsystem: String) {
        logger = Logger(subsystem: subsystem, category: "BridgeMetrics")
    }

    func record(direction: Direction, packets: Int, bytes: Int) {
        guard packets > 0 && bytes >= 0 else { return }
        queue.async { [self] in
            switch direction {
            case .inbound:
                self.inbound.packets += packets
                self.inbound.bytes += bytes
            case .outbound:
                self.outbound.packets += packets
                self.outbound.bytes += bytes
            }
            self.emitIfNeeded()
        }
    }

    func reset() {
        queue.async { [self] in
            self.inbound = Counter()
            self.outbound = Counter()
            self.lastReport = Date()
        }
    }

    private func emitIfNeeded() {
        guard Date().timeIntervalSince(lastReport) >= 5 else { return }
        lastReport = Date()
        logger.notice(
            """
            packets_in=\(self.inbound.packets, privacy: .public) bytes_in=\(self.inbound.bytes, privacy: .public) \
            packets_out=\(self.outbound.packets, privacy: .public) bytes_out=\(self.outbound.bytes, privacy: .public)
            """
        )
        self.inbound = Counter()
        self.outbound = Counter()
    }
}
