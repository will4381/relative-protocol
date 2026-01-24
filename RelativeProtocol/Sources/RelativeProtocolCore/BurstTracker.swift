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
    private struct BurstKey: Hashable {
        let flowId: UInt64
        let burstId: UInt32
    }

    private struct BurstState {
        var start: TimeInterval
        var last: TimeInterval
        var packetCount: UInt32
        var byteCount: UInt64
    }

    private let ttl: TimeInterval
    private let maxBursts: Int
    private var states: [BurstKey: BurstState] = [:]

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
                state = BurstState(start: timestamp, last: timestamp, packetCount: 1, byteCount: byteLength)
            } else {
                state.last = timestamp
                state.packetCount &+= 1
                state.byteCount &+= byteLength
            }
            states[key] = state
            pruneIfNeeded(now: timestamp, excluding: key)
            return makeMetrics(from: state)
        } else {
            let state = BurstState(start: timestamp, last: timestamp, packetCount: 1, byteCount: byteLength)
            states[key] = state
            pruneIfNeeded(now: timestamp, excluding: key)
            return makeMetrics(from: state)
        }
    }

    public func reset() {
        states.removeAll()
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
        if states.count >= maxBursts, let oldest = states
            .filter({ $0.key != key })
            .min(by: { $0.value.last < $1.value.last })?.key {
            states.removeValue(forKey: oldest)
        }

        let expired = states.filter { $0.key != key && now - $0.value.last > ttl }
        if !expired.isEmpty {
            expired.keys.forEach { states.removeValue(forKey: $0) }
        }
    }
}