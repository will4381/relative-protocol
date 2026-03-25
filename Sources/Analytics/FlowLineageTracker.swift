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
    }

    private var statesByKey: [LineageKey: LineageState] = [:]
    private var flowAssignments: [FlowKey: LineageKey] = [:]
    private var arrivalQueue: ArraySlice<LineageKey> = []
    private var nextLineageID: UInt64 = 1

    mutating func snapshot(for flow: FlowKey, summary: FastPacketSummary, direction: PacketDirection, now: Date) -> FlowLineageSnapshot {
        evictExpired(now: now)

        if let key = flowAssignments[flow], let state = statesByKey[key] {
            var updated = state
            updated.lastSeenAt = now
            statesByKey[key] = updated
            return makeSnapshot(state: updated, now: now)
        }

        let key = Self.makeKey(summary: summary, direction: direction)
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
        if statesByKey[key] == nil {
            nextLineageID &+= 1
        } else if state.activeFlowCount == 0, let lastClosedAt = state.lastClosedAt {
            state.generation += 1
            state.reopenCount += 1
            state.lastReuseGapMs = max(0, Int(now.timeIntervalSince(lastClosedAt) * 1_000))
        }
        state.lastSeenAt = now
        state.activeFlowCount += 1
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
            ageMs: max(0, Int(now.timeIntervalSince(state.firstSeenAt) * 1_000)),
            reuseGapMs: state.lastReuseGapMs,
            reopenCount: state.reopenCount,
            siblingCount: max(0, state.activeFlowCount - 1)
        )
    }

    private mutating func evictExpired(now: Date) {
        guard !statesByKey.isEmpty else {
            return
        }

        let expiredKeys = statesByKey.compactMap { key, state in
            state.activeFlowCount == 0 && now.timeIntervalSince(state.lastSeenAt) > Policy.ttlSeconds ? key : nil
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
        for key in arrivalQueue {
            guard statesByKey[key] != nil, seen.insert(key).inserted else {
                continue
            }
            active.append(key)
        }
        arrivalQueue = ArraySlice(active)
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
