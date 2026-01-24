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
    private struct FlowState {
        var baseHash: UInt64
        var generation: UInt32
        var flowId: UInt64
        var lastSeen: TimeInterval
        var currentBurstId: UInt32
        var lastBurstTimestamp: TimeInterval
    }

    private let configuration: FlowTrackerConfiguration
    private var states: [FlowKey: FlowState] = [:]

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
            state.lastSeen = timestamp
            states[flowKey] = state
            pruneIfNeeded(now: timestamp, excluding: flowKey)
            return FlowObservation(flowId: state.flowId, burstId: state.currentBurstId)
        } else {
            let baseHash = hash(flowKey)
            let flowId = makeFlowId(baseHash: baseHash, generation: 0)
            let state = FlowState(
                baseHash: baseHash,
                generation: 0,
                flowId: flowId,
                lastSeen: timestamp,
                currentBurstId: 0,
                lastBurstTimestamp: timestamp
            )
            states[flowKey] = state
            pruneIfNeeded(now: timestamp, excluding: flowKey)
            return FlowObservation(flowId: flowId, burstId: 0)
        }
    }

    public func reset() {
        states.removeAll()
    }

    private func pruneIfNeeded(now: TimeInterval, excluding flowKey: FlowKey) {
        if states.count >= configuration.maxTrackedFlows {
            if let oldest = states
                .filter({ $0.key != flowKey })
                .min(by: { $0.value.lastSeen < $1.value.lastSeen })?.key {
                states.removeValue(forKey: oldest)
            }
        }

        let expired = states.filter { $0.key != flowKey && now - $0.value.lastSeen > configuration.flowTTL }
        if !expired.isEmpty {
            expired.keys.forEach { states.removeValue(forKey: $0) }
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
}