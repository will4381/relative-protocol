// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation

public struct BurstMetrics: Codable, Hashable, Sendable {
    public let packetCount: UInt32
    public let byteCount: UInt64
    public let durationMs: UInt32
    public let packetsPerSecond: Double
    public let bytesPerSecond: Double

    public init(packetCount: UInt32, byteCount: UInt64, durationMs: UInt32, packetsPerSecond: Double, bytesPerSecond: Double) {
        self.packetCount = packetCount
        self.byteCount = byteCount
        self.durationMs = durationMs
        self.packetsPerSecond = packetsPerSecond
        self.bytesPerSecond = bytesPerSecond
    }
}

public final class BurstTracker {
    private struct LastSeenHeap {
        struct Entry {
            let key: BurstKey
            let lastSeen: TimeInterval
            let revision: UInt64
        }

        private var storage: [Entry] = []

        mutating func push(_ entry: Entry) {
            storage.append(entry)
            siftUp(from: storage.count - 1)
        }

        mutating func popMin() -> Entry? {
            guard !storage.isEmpty else { return nil }
            if storage.count == 1 {
                return storage.removeLast()
            }
            let minEntry = storage[0]
            storage[0] = storage.removeLast()
            siftDown(from: 0)
            return minEntry
        }

        mutating func removeAll() {
            storage.removeAll(keepingCapacity: false)
        }

        private mutating func siftUp(from index: Int) {
            var child = index
            while child > 0 {
                let parent = (child - 1) / 2
                if storage[child].lastSeen >= storage[parent].lastSeen {
                    break
                }
                storage.swapAt(child, parent)
                child = parent
            }
        }

        private mutating func siftDown(from index: Int) {
            var parent = index
            while true {
                let left = 2 * parent + 1
                let right = left + 1
                var candidate = parent

                if left < storage.count && storage[left].lastSeen < storage[candidate].lastSeen {
                    candidate = left
                }
                if right < storage.count && storage[right].lastSeen < storage[candidate].lastSeen {
                    candidate = right
                }
                if candidate == parent {
                    return
                }
                storage.swapAt(parent, candidate)
                parent = candidate
            }
        }
    }

    private struct BurstKey: Hashable {
        let flowId: UInt64
        let burstId: UInt32
    }

    private struct BurstState {
        var start: TimeInterval
        var last: TimeInterval
        var revision: UInt64
        var packetCount: UInt32
        var byteCount: UInt64
    }

    private let ttl: TimeInterval
    private let maxBursts: Int
    private var states: [BurstKey: BurstState] = [:]
    private var lastSeenHeap = LastSeenHeap()
    private var nextRevision: UInt64 = 0

    public init(ttl: TimeInterval, maxBursts: Int) {
        self.ttl = ttl
        self.maxBursts = maxBursts
    }

    public func record(flowId: UInt64, burstId: UInt32, timestamp: TimeInterval, length: Int) -> BurstMetrics? {
        guard flowId != 0 else { return nil }
        let key = BurstKey(flowId: flowId, burstId: burstId)
        let byteLength = UInt64(max(0, length))
        if var state = states[key] {
            if timestamp - state.last > ttl {
                state = BurstState(
                    start: timestamp,
                    last: timestamp,
                    revision: makeRevision(),
                    packetCount: 1,
                    byteCount: byteLength
                )
            } else {
                state.last = timestamp
                state.revision = makeRevision()
                state.packetCount &+= 1
                state.byteCount &+= byteLength
            }
            states[key] = state
            lastSeenHeap.push(.init(key: key, lastSeen: state.last, revision: state.revision))
            pruneIfNeeded(now: timestamp, excluding: key)
            return makeMetrics(from: state)
        } else {
            let state = BurstState(
                start: timestamp,
                last: timestamp,
                revision: makeRevision(),
                packetCount: 1,
                byteCount: byteLength
            )
            states[key] = state
            lastSeenHeap.push(.init(key: key, lastSeen: state.last, revision: state.revision))
            pruneIfNeeded(now: timestamp, excluding: key)
            return makeMetrics(from: state)
        }
    }

    public func reset() {
        states.removeAll()
        lastSeenHeap.removeAll()
        nextRevision = 0
    }

    private func makeMetrics(from state: BurstState) -> BurstMetrics {
        let duration = max(0.001, state.last - state.start)
        let durationMs = UInt32(duration * 1000.0)
        let pps = Double(state.packetCount) / duration
        let bps = Double(state.byteCount) / duration
        return BurstMetrics(
            packetCount: state.packetCount,
            byteCount: state.byteCount,
            durationMs: durationMs,
            packetsPerSecond: pps,
            bytesPerSecond: bps
        )
    }

    private func pruneIfNeeded(now: TimeInterval, excluding key: BurstKey) {
        if states.count >= maxBursts {
            evictOldest(excluding: key)
        }

        pruneExpired(now: now, excluding: key)
    }

    private func evictOldest(excluding key: BurstKey) {
        var skipped: [LastSeenHeap.Entry] = []
        while let candidate = lastSeenHeap.popMin() {
            guard let state = states[candidate.key], state.revision == candidate.revision else {
                continue
            }
            if candidate.key == key {
                skipped.append(candidate)
                continue
            }
            states.removeValue(forKey: candidate.key)
            break
        }
        if !skipped.isEmpty {
            skipped.forEach { lastSeenHeap.push($0) }
        }
    }

    private func pruneExpired(now: TimeInterval, excluding key: BurstKey) {
        var skipped: [LastSeenHeap.Entry] = []
        while let candidate = lastSeenHeap.popMin() {
            guard let state = states[candidate.key], state.revision == candidate.revision else {
                continue
            }
            if candidate.key == key {
                skipped.append(candidate)
                continue
            }
            if now - state.last > ttl {
                states.removeValue(forKey: candidate.key)
                continue
            }
            lastSeenHeap.push(candidate)
            break
        }
        if !skipped.isEmpty {
            skipped.forEach { lastSeenHeap.push($0) }
        }
    }

    private func makeRevision() -> UInt64 {
        nextRevision &+= 1
        return nextRevision
    }
}
