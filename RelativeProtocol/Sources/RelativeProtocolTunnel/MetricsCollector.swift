//
//  MetricsCollector.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Captures lightweight instrumentation around the tunnel. The collector runs
//  on a private serial queue so log emission and sink callbacks never block the
//  Network Extension packet loop.
//

import Foundation
import os.log
import RelativeProtocolCore

/// Serialises metrics aggregation and emission.
final class MetricsCollector {
    /// Direction the sampled packets travelled.
    enum Direction {
        case inbound
        case outbound
    }

    private struct Counter {
        var packets: Int = 0
        var bytes: Int = 0
    }

    private let logger: Logger
    private let queue = DispatchQueue(label: "RelativeProtocolTunnel.MetricsCollector")
    private var inbound = Counter()
    private var outbound = Counter()
    private var lastReport = Date()
    private let interval: TimeInterval
    private let sink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?

    /// - Parameters:
    ///   - subsystem: OSLog subsystem used for diagnostics.
    ///   - interval: Minimum interval between emissions.
    ///   - sink: Optional consumer that receives aggregated snapshots.
    init(subsystem: String, interval: TimeInterval, sink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?) {
        logger = Logger(subsystem: subsystem, category: "Metrics")
        self.interval = interval
        self.sink = sink
    }

    /// Records a batch of packets and schedules a flush when necessary.
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

    /// Resets counters and reporting window. Use when a new tunnel session
    /// begins.
    func reset() {
        queue.async { [self] in
            self.inbound = Counter()
            self.outbound = Counter()
            self.lastReport = Date()
        }
    }

    /// Emits a metrics snapshot if the configured interval has elapsed.
    private func emitIfNeeded() {
        guard Date().timeIntervalSince(lastReport) >= interval else { return }
        defer {
            lastReport = Date()
            self.inbound = Counter()
            self.outbound = Counter()
        }

        guard inbound.packets > 0 || outbound.packets > 0 else { return }

        let snapshot = RelativeProtocol.MetricsSnapshot(
            timestamp: Date(),
            inbound: .init(packets: inbound.packets, bytes: inbound.bytes),
            outbound: .init(packets: outbound.packets, bytes: outbound.bytes),
            activeTCP: 0,
            activeUDP: 0,
            errors: []
        )

        logger.notice(
            "Relative Protocol: metrics packets_in=\(self.inbound.packets, privacy: .public) bytes_in=\(self.inbound.bytes, privacy: .public) packets_out=\(self.outbound.packets, privacy: .public) bytes_out=\(self.outbound.bytes, privacy: .public)"
        )
        sink?(snapshot)
    }
}
