import Foundation

/// Stable flow identity key used by flow/burst analytics.
public struct FlowKey: Hashable, Sendable, Codable {
    public let src: String
    public let dst: String
    public let proto: String

    /// - Parameters:
    ///   - src: Source endpoint identity (IP or host token).
    ///   - dst: Destination endpoint identity (IP or host token).
    ///   - proto: Transport protocol hint (for example, `tcp` or `udp`).
    public init(src: String, dst: String, proto: String) {
        self.src = src
        self.dst = dst
        self.proto = proto
    }
}

/// Aggregated flow statistics retained by `FlowTracker`.
public struct FlowRecord: Sendable, Equatable {
    public let key: FlowKey
    public let firstSeen: Date
    public var lastSeen: Date
    public var bytes: Int

    /// - Parameters:
    ///   - key: Stable flow identity.
    ///   - firstSeen: Timestamp of first observed packet in this flow.
    ///   - lastSeen: Timestamp of most recent observed packet.
    ///   - bytes: Total bytes accumulated for this flow.
    public init(key: FlowKey, firstSeen: Date, lastSeen: Date, bytes: Int) {
        self.key = key
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.bytes = bytes
    }
}

/// Bounded flow tracker that evicts stale entries and enforces a max flow set.
public actor FlowTracker {
    private let maxTrackedFlows: Int
    private let flowTTLSeconds: TimeInterval
    private var flows: [FlowKey: FlowRecord] = [:]

    /// Creates a bounded flow tracker with time-based eviction.
    /// - Parameters:
    ///   - maxTrackedFlows: Max number of flow records retained in memory.
    ///   - flowTTLSeconds: Max idle age before a flow is evicted.
    public init(maxTrackedFlows: Int, flowTTLSeconds: TimeInterval) {
        self.maxTrackedFlows = maxTrackedFlows
        self.flowTTLSeconds = flowTTLSeconds
    }

    /// Records bytes for a flow at timestamp `now`, creating/evicting entries as needed.
    /// - Parameters:
    ///   - flow: Flow identity key.
    ///   - bytes: Byte count to add to the flow.
    ///   - now: Observation timestamp used for TTL and ordering.
    public func record(flow: FlowKey, bytes: Int, now: Date) {
        evictExpired(now: now)
        if var existing = flows[flow] {
            existing.lastSeen = now
            existing.bytes += bytes
            flows[flow] = existing
            return
        }

        if flows.count >= maxTrackedFlows,
           let oldest = flows.values.min(by: { $0.lastSeen < $1.lastSeen }) {
            flows.removeValue(forKey: oldest.key)
        }

        flows[flow] = FlowRecord(key: flow, firstSeen: now, lastSeen: now, bytes: bytes)
    }

    /// Returns all currently tracked flows in unspecified order.
    public func snapshot() -> [FlowRecord] {
        Array(flows.values)
    }

    private func evictExpired(now: Date) {
        flows = flows.filter { now.timeIntervalSince($0.value.lastSeen) <= flowTTLSeconds }
    }
}

/// One completed burst window returned by `BurstTracker`.
public struct BurstSample: Sendable, Equatable {
    public let flow: FlowKey
    public let burstDurationMs: Int
    public let packetCount: Int
}

/// Detects packet bursts by measuring inter-arrival gaps per flow.
public actor BurstTracker {
    private let thresholdMs: Int
    private var lastPacketAt: [FlowKey: Date] = [:]
    private var burstCounts: [FlowKey: Int] = [:]

    /// Creates a burst tracker with gap-based burst segmentation.
    /// - Parameter thresholdMs: Max inter-packet gap that still counts as same burst.
    public init(thresholdMs: Int) {
        self.thresholdMs = thresholdMs
    }

    /// Records one packet event and optionally emits the previous completed burst.
    /// - Parameters:
    ///   - flow: Flow identity key.
    ///   - now: Packet timestamp.
    /// - Returns: Completed burst when a new burst boundary is detected; otherwise `nil`.
    public func recordPacket(flow: FlowKey, now: Date) -> BurstSample? {
        defer { lastPacketAt[flow] = now }
        guard let previous = lastPacketAt[flow] else {
            burstCounts[flow] = 1
            return nil
        }

        let deltaMs = Int((now.timeIntervalSince(previous) * 1000).rounded())
        if deltaMs <= thresholdMs {
            burstCounts[flow, default: 1] += 1
            return nil
        }

        let packetCount = burstCounts[flow, default: 1]
        burstCounts[flow] = 1
        return BurstSample(flow: flow, burstDurationMs: deltaMs, packetCount: packetCount)
    }
}
