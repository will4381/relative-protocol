// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation

public struct FlowTrackerConfiguration: Sendable {
    public let burstThreshold: TimeInterval
    public let flowTTL: TimeInterval
    public let maxTrackedFlows: Int

    public init(burstThreshold: TimeInterval, flowTTL: TimeInterval, maxTrackedFlows: Int) {
        self.burstThreshold = burstThreshold
        self.flowTTL = flowTTL
        self.maxTrackedFlows = maxTrackedFlows
    }
}

public struct FlowObservation: Sendable {
    public let flowId: UInt64
    public let burstId: UInt32

    public init(flowId: UInt64, burstId: UInt32) {
        self.flowId = flowId
        self.burstId = burstId
    }
}

public final class FlowTracker {
    private typealias HeapEntry = LastSeenHeap<FlowKey>.Entry

    private struct FlowState {
        var baseHash: UInt64
        var generation: UInt32
        var flowId: UInt64
        var lastSeen: TimeInterval
        var revision: UInt64
        var currentBurstId: UInt32
        var lastBurstTimestamp: TimeInterval
    }

    private let configuration: FlowTrackerConfiguration
    private var states: [FlowKey: FlowState] = [:]
    private var lastSeenHeap = LastSeenHeap<FlowKey>()
    private var nextRevision: UInt64 = 0
    private static let minimumHeapCompactionThreshold = 1024

    public init(configuration: FlowTrackerConfiguration) {
        self.configuration = configuration
    }

    public func record(metadata: PacketMetadata, timestamp: TimeInterval) -> FlowObservation {
        guard let srcPort = metadata.srcPort, let dstPort = metadata.dstPort else {
            return FlowObservation(flowId: 0, burstId: 0)
        }

        let flowKey = FlowKey(
            ipVersion: metadata.ipVersion,
            transport: metadata.transport,
            srcAddress: metadata.srcAddress,
            dstAddress: metadata.dstAddress,
            srcPort: srcPort,
            dstPort: dstPort
        )

        if var state = states[flowKey] {
            if timestamp - state.lastSeen > configuration.flowTTL {
                state.generation = state.generation &+ 1
                state.flowId = makeFlowId(baseHash: state.baseHash, generation: state.generation)
                state.currentBurstId = 0
                state.lastBurstTimestamp = timestamp
            } else if timestamp - state.lastBurstTimestamp > configuration.burstThreshold {
                state.currentBurstId = state.currentBurstId &+ 1
                state.lastBurstTimestamp = timestamp
            }
            state.revision = makeRevision()
            state.lastSeen = timestamp
            states[flowKey] = state
            lastSeenHeap.push(.init(key: flowKey, lastSeen: timestamp, revision: state.revision))
            compactHeapIfNeeded()
            pruneIfNeeded(now: timestamp, excluding: flowKey)
            return FlowObservation(flowId: state.flowId, burstId: state.currentBurstId)
        } else {
            let baseHash = hash(flowKey)
            let flowId = makeFlowId(baseHash: baseHash, generation: 0)
            let revision = makeRevision()
            let state = FlowState(
                baseHash: baseHash,
                generation: 0,
                flowId: flowId,
                lastSeen: timestamp,
                revision: revision,
                currentBurstId: 0,
                lastBurstTimestamp: timestamp
            )
            states[flowKey] = state
            lastSeenHeap.push(.init(key: flowKey, lastSeen: timestamp, revision: revision))
            compactHeapIfNeeded()
            pruneIfNeeded(now: timestamp, excluding: flowKey)
            return FlowObservation(flowId: flowId, burstId: 0)
        }
    }

    public func reset() {
        states.removeAll()
        lastSeenHeap.removeAll()
        nextRevision = 0
    }

    private func pruneIfNeeded(now: TimeInterval, excluding flowKey: FlowKey) {
        if states.count >= configuration.maxTrackedFlows {
            evictOldest(excluding: flowKey)
        }

        pruneExpired(now: now, excluding: flowKey)
    }

    private func evictOldest(excluding flowKey: FlowKey) {
        var skipped: [HeapEntry] = []
        while let candidate = lastSeenHeap.popMin() {
            guard let state = states[candidate.key], state.revision == candidate.revision else {
                continue
            }
            if candidate.key == flowKey {
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

    private func pruneExpired(now: TimeInterval, excluding flowKey: FlowKey) {
        var skipped: [HeapEntry] = []
        while let candidate = lastSeenHeap.popMin() {
            guard let state = states[candidate.key], state.revision == candidate.revision else {
                continue
            }
            if candidate.key == flowKey {
                skipped.append(candidate)
                continue
            }
            if now - state.lastSeen > configuration.flowTTL {
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

    private func hash(_ key: FlowKey) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        func update(_ byte: UInt8) {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }

        update(key.ipVersion.rawValue)
        update(key.transport.rawValue)
        key.srcAddress.bytes.forEach { update($0) }
        key.dstAddress.bytes.forEach { update($0) }
        update(UInt8(key.srcPort >> 8))
        update(UInt8(key.srcPort & 0xFF))
        update(UInt8(key.dstPort >> 8))
        update(UInt8(key.dstPort & 0xFF))
        return hash
    }

    private func makeFlowId(baseHash: UInt64, generation: UInt32) -> UInt64 {
        baseHash ^ (UInt64(generation) << 32)
    }

    private func makeRevision() -> UInt64 {
        nextRevision &+= 1
        return nextRevision
    }

    private func compactHeapIfNeeded() {
        let activeFlows = max(1, states.count)
        let threshold = max(Self.minimumHeapCompactionThreshold, activeFlows * 4)
        guard lastSeenHeap.count > threshold else { return }
        rebuildHeapFromCurrentState()
    }

    private func rebuildHeapFromCurrentState() {
        lastSeenHeap.removeAll()
        for (key, state) in states {
            lastSeenHeap.push(.init(key: key, lastSeen: state.lastSeen, revision: state.revision))
        }
    }
}

#if DEBUG
extension FlowTracker {
    var _test_heapEntryCount: Int {
        lastSeenHeap.count
    }
}
#endif
