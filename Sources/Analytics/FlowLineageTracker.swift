// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation

internal struct FlowLineageSnapshot: Sendable, Equatable {
    let lineageID: UInt64
    let generation: Int
    let ageMs: Int
    let reuseGapMs: Int?
    let reopenCount: Int
    let siblingCount: Int
}

internal struct FlowLineageTracker {
    private struct LineageKey: Hashable, Sendable {
        let transportProtocolNumber: UInt8
        let remoteAddressLength: UInt8
        let remoteAddressHigh: UInt64
        let remoteAddressLow: UInt64
        let remotePort: UInt16
        let quicConnectionIDHash: UInt64?
    }

    private struct LineageState: Sendable {
        let id: UInt64
        let firstSeenAt: Date
        var lastSeenAt: Date
        var lastClosedAt: Date?
        var lastReuseGapMs: Int?
        var generation: Int
        var reopenCount: Int
        var activeFlowCount: Int
    }

    private struct Policy {
        static let ttlSeconds: TimeInterval = 180
        static let maxTrackedLineages = 4_096
        static let minimumSweepIntervalSeconds: TimeInterval = 10
    }

    private var statesByKey: [LineageKey: LineageState] = [:]
    private var flowAssignments: [FlowKey: LineageKey] = [:]
    private var arrivalQueue: ArraySlice<LineageKey> = []
    private var nextLineageID: UInt64 = 1
    private var lastSweepAt: Date?

    mutating func snapshot(for flow: FlowKey, summary: FastPacketSummary, direction: PacketDirection, now: Date) -> FlowLineageSnapshot {
        evictExpiredIfNeeded(now: now)

        if let key = flowAssignments[flow], let state = statesByKey[key] {
            var updated = state
            updated.lastSeenAt = now
            statesByKey[key] = updated
            return makeSnapshot(state: updated, now: now)
        }

        let key = Self.makeKey(summary: summary, direction: direction)
        let existingState = statesByKey[key]
        let existingWasExpired = existingState.map { Self.isExpired($0, now: now) } ?? false
        if existingWasExpired {
            statesByKey.removeValue(forKey: key)
            pruneArrivalQueue()
        }
        var state = statesByKey[key] ?? LineageState(
            id: nextLineageID,
            firstSeenAt: now,
            lastSeenAt: now,
            lastClosedAt: nil,
            lastReuseGapMs: nil,
            generation: 0,
            reopenCount: 0,
            activeFlowCount: 0
        )
        if existingState == nil || existingWasExpired {
            nextLineageID &+= 1
        } else if state.activeFlowCount == 0, let lastClosedAt = state.lastClosedAt {
            state.generation = saturatingAdd(state.generation, 1)
            state.reopenCount = saturatingAdd(state.reopenCount, 1)
            state.lastReuseGapMs = millisecondsBetween(lastClosedAt, and: now)
        }
        state.lastSeenAt = now
        state.activeFlowCount = saturatingAdd(state.activeFlowCount, 1)
        statesByKey[key] = state
        flowAssignments[flow] = key
        arrivalQueue.append(key)
        trimOverflowIfNeeded()
        return makeSnapshot(state: state, now: now)
    }

    mutating func close(flow: FlowKey, now: Date) {
        guard let key = flowAssignments.removeValue(forKey: flow), var state = statesByKey[key] else {
            return
        }
        state.activeFlowCount = max(0, state.activeFlowCount - 1)
        state.lastSeenAt = now
        state.lastClosedAt = now
        statesByKey[key] = state
    }

    private func makeSnapshot(state: LineageState, now: Date) -> FlowLineageSnapshot {
        FlowLineageSnapshot(
            lineageID: state.id,
            generation: state.generation,
            ageMs: millisecondsBetween(state.firstSeenAt, and: now),
            reuseGapMs: state.lastReuseGapMs,
            reopenCount: state.reopenCount,
            siblingCount: max(0, state.activeFlowCount - 1)
        )
    }

    private mutating func evictExpiredIfNeeded(now: Date) {
        guard !statesByKey.isEmpty else {
            return
        }
        if let lastSweepAt,
           now.timeIntervalSince(lastSweepAt) < Policy.minimumSweepIntervalSeconds,
           statesByKey.count <= Policy.maxTrackedLineages {
            return
        }

        lastSweepAt = now
        let expiredKeys = statesByKey.compactMap { key, state in
            Self.isExpired(state, now: now) ? key : nil
        }
        for key in expiredKeys {
            statesByKey.removeValue(forKey: key)
        }
        pruneArrivalQueue(force: !expiredKeys.isEmpty)
    }

    private mutating func trimOverflowIfNeeded() {
        guard statesByKey.count > Policy.maxTrackedLineages else {
            return
        }

        pruneArrivalQueue(force: true)
        while statesByKey.count > Policy.maxTrackedLineages {
            guard let oldest = arrivalQueue.popFirst() else {
                break
            }
            guard let state = statesByKey[oldest], state.activeFlowCount == 0 else {
                continue
            }
            statesByKey.removeValue(forKey: oldest)
        }
        pruneArrivalQueue(force: true)
    }

    private mutating func pruneArrivalQueue(force: Bool = false) {
        guard force || arrivalQueue.startIndex > 128 || arrivalQueue.count > Policy.maxTrackedLineages * 2 else {
            return
        }

        var seen: Set<LineageKey> = []
        var active: [LineageKey] = []
        active.reserveCapacity(statesByKey.count)
        for key in arrivalQueue.reversed() {
            guard statesByKey[key] != nil, seen.insert(key).inserted else {
                continue
            }
            active.append(key)
        }
        arrivalQueue = ArraySlice(active.reversed())
    }

    private static func isExpired(_ state: LineageState, now: Date) -> Bool {
        state.activeFlowCount == 0 && now.timeIntervalSince(state.lastSeenAt) > Policy.ttlSeconds
    }

    private static func makeKey(summary: FastPacketSummary, direction: PacketDirection) -> LineageKey {
        let remoteAddressLength: UInt8
        let remoteAddressHigh: UInt64
        let remoteAddressLow: UInt64
        let remotePort: UInt16
        if direction == .outbound {
            remoteAddressLength = summary.destinationAddressLength
            remoteAddressHigh = summary.destinationAddressHigh
            remoteAddressLow = summary.destinationAddressLow
            remotePort = summary.destinationPort
        } else {
            remoteAddressLength = summary.sourceAddressLength
            remoteAddressHigh = summary.sourceAddressHigh
            remoteAddressLow = summary.sourceAddressLow
            remotePort = summary.sourcePort
        }

        return LineageKey(
            transportProtocolNumber: summary.transportProtocolNumber,
            remoteAddressLength: remoteAddressLength,
            remoteAddressHigh: remoteAddressHigh,
            remoteAddressLow: remoteAddressLow,
            remotePort: remotePort,
            quicConnectionIDHash: Self.hash(summary.quicDestinationConnectionID ?? summary.quicSourceConnectionID)
        )
    }

    private static func hash(_ data: Data?) -> UInt64? {
        guard let data, !data.isEmpty else {
            return nil
        }
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in data {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        return hash
    }
}

private func millisecondsBetween(_ earlier: Date, and later: Date) -> Int {
    let elapsed = later.timeIntervalSince(earlier)
    guard elapsed.isFinite, elapsed > 0 else {
        return 0
    }
    let milliseconds = (elapsed * 1_000).rounded()
    guard milliseconds.isFinite else {
        return Int.max
    }
    if milliseconds >= Double(Int.max) {
        return Int.max
    }
    return Int(milliseconds)
}

private func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? Int.max : value
}
