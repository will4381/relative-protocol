//
//  MetricsCollector.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Captures lightweight instrumentation around the tunnel. A lightweight unfair
//  lock keeps aggregation fast without bouncing work onto additional queues so
//  the Network Extension packet loop stays responsive.
//

import Foundation
import Dispatch
import os.lock
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
    private var inbound = Counter()
    private var outbound = Counter()
    private var lastReportTick: UInt64
    private var lock = os_unfair_lock_s()
    private let interval: TimeInterval
    private let intervalNanoseconds: UInt64
    private let sink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?

    /// - Parameters:
    ///   - subsystem: OSLog subsystem used for diagnostics.
    ///   - interval: Minimum interval between emissions.
    ///   - sink: Optional consumer that receives aggregated snapshots.
    init(subsystem: String, interval: TimeInterval, sink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?) {
        logger = Logger(subsystem: subsystem, category: "Metrics")
        self.interval = interval
        if interval <= 0 {
            intervalNanoseconds = 0
        } else {
            intervalNanoseconds = UInt64((interval * 1_000_000_000).rounded())
        }
        self.sink = sink
        lastReportTick = DispatchTime.now().uptimeNanoseconds
    }

    /// Records a batch of packets and schedules a flush when necessary.
    func record(direction: Direction, packets: Int, bytes: Int) {
        guard packets > 0 && bytes >= 0 else { return }
        let emission = accumulate(direction: direction, packets: packets, bytes: bytes)
        if let emission {
            logger.log(
                level: .info,
                "Relative Protocol: metrics packets_in=\(emission.inboundPackets, privacy: .public) bytes_in=\(emission.inboundBytes, privacy: .public) packets_out=\(emission.outboundPackets, privacy: .public) bytes_out=\(emission.outboundBytes, privacy: .public)"
            )
            sink?(emission.snapshot)
        }
    }

    /// Resets counters and reporting window. Use when a new tunnel session
    /// begins.
    func reset() {
        os_unfair_lock_lock(&lock)
        inbound = Counter()
        outbound = Counter()
        lastReportTick = DispatchTime.now().uptimeNanoseconds
        os_unfair_lock_unlock(&lock)
    }

    /// Aggregates counters under the unfair lock and returns an emission payload when ready.
    private func accumulate(direction: Direction, packets: Int, bytes: Int) -> Emission? {
        let nowTick = DispatchTime.now().uptimeNanoseconds
        var emission: Emission?

        os_unfair_lock_lock(&lock)
        switch direction {
        case .inbound:
            inbound.packets += packets
            inbound.bytes += bytes
        case .outbound:
            outbound.packets += packets
            outbound.bytes += bytes
        }

        let elapsed = nowTick &- lastReportTick
        let shouldEmit = intervalNanoseconds == 0 || elapsed >= intervalNanoseconds
        if shouldEmit, (inbound.packets > 0 || outbound.packets > 0) {
            let timestamp = Date()
            let snapshot = RelativeProtocol.MetricsSnapshot(
                timestamp: timestamp,
                inbound: .init(packets: inbound.packets, bytes: inbound.bytes),
                outbound: .init(packets: outbound.packets, bytes: outbound.bytes),
                activeTCP: 0,
                activeUDP: 0,
                errors: []
            )
            emission = Emission(
                snapshot: snapshot,
                inboundPackets: inbound.packets,
                inboundBytes: inbound.bytes,
                outboundPackets: outbound.packets,
                outboundBytes: outbound.bytes
            )
            inbound = Counter()
            outbound = Counter()
            lastReportTick = nowTick
        }
        os_unfair_lock_unlock(&lock)

        return emission
    }
}

private extension MetricsCollector {
    struct Emission {
        var snapshot: RelativeProtocol.MetricsSnapshot
        var inboundPackets: Int
        var inboundBytes: Int
        var outboundPackets: Int
        var outboundBytes: Int
    }
}
