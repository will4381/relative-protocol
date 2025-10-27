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

    private let queue = DispatchQueue(label: "RelativeProtocolTunnel.MetricsCollector")
    private var inbound = Counter()
    private var outbound = Counter()
    private var activeTCP = 0
    private var activeUDP = 0
    private var errors: [RelativeProtocol.MetricsSnapshot.ErrorEvent] = []
    private var lastReport = Date()
    private let interval: TimeInterval
    private let maxErrorEvents: Int
    private var dirty = false
    private let sink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?

    /// - Parameters:
    ///   - subsystem: OSLog subsystem used for diagnostics.
    ///   - interval: Minimum interval between emissions.
    ///   - sink: Optional consumer that receives aggregated snapshots.
    init(
        subsystem: String,
        interval: TimeInterval,
        maxErrorEvents: Int = 20,
        sink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?
    ) {
        self.interval = interval
        self.maxErrorEvents = maxErrorEvents
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
            self.dirty = true
            self.emitIfNeeded()
        }
    }

    /// Adjusts the currently active TCP/UDP connection counts.
    func adjustActiveConnections(tcpDelta: Int = 0, udpDelta: Int = 0) {
        guard tcpDelta != 0 || udpDelta != 0 else { return }
        queue.async { [self] in
            let newTCP = max(0, self.activeTCP + tcpDelta)
            let newUDP = max(0, self.activeUDP + udpDelta)
            if newTCP != self.activeTCP || newUDP != self.activeUDP {
                self.activeTCP = newTCP
                self.activeUDP = newUDP
                self.dirty = true
            }
            self.emitIfNeeded()
        }
    }

    /// Records an error that should be surfaced in the next snapshot.
    func recordError(_ message: String) {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        queue.async { [self] in
            errors.append(.init(message: trimmed))
            if errors.count > maxErrorEvents {
                errors.removeFirst(errors.count - maxErrorEvents)
            }
            dirty = true
            emitIfNeeded(force: true)
        }
    }

    /// Resets counters and reporting window. Use when a new tunnel session
    /// begins.
    func reset() {
        queue.async { [self] in
            self.inbound = Counter()
            self.outbound = Counter()
            self.activeTCP = 0
            self.activeUDP = 0
            self.errors.removeAll()
            self.lastReport = Date()
            self.dirty = false
        }
    }

    /// Emits a metrics snapshot if the configured interval has elapsed.
    private func emitIfNeeded(force: Bool = false) {
        let now = Date()
        guard force || now.timeIntervalSince(lastReport) >= interval else { return }
        guard dirty else { return }
        guard inbound.packets > 0 || outbound.packets > 0 || !errors.isEmpty || activeTCP > 0 || activeUDP > 0 else {
            dirty = false
            return
        }
        let snapshotErrors = errors
        defer {
            lastReport = now
            self.inbound = Counter()
            self.outbound = Counter()
            self.errors.removeAll()
            self.dirty = false
        }

        let snapshot = RelativeProtocol.MetricsSnapshot(
            timestamp: Date(),
            inbound: .init(packets: inbound.packets, bytes: inbound.bytes),
            outbound: .init(packets: outbound.packets, bytes: outbound.bytes),
            activeTCP: activeTCP,
            activeUDP: activeUDP,
            errors: snapshotErrors
        )

        sink?(snapshot)
    }
}
