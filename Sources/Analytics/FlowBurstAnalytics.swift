import Darwin
import Foundation

/// Stable flow identity used by burst tracking, aggregation, and live-tap grouping.
/// Decision: production traffic uses the numeric path so packet accounting can stay allocation-light,
/// while tests can still construct text-only keys when no packed network identity exists.
public struct FlowKey: Hashable, Sendable, Codable {
    private let textSource: String?
    private let textDestination: String?
    private let textProtocol: String?

    fileprivate let flowHash: UInt64?
    fileprivate let reverseFlowHash: UInt64?
    fileprivate let ipVersion: UInt8?
    fileprivate let transportProtocolNumber: UInt8?
    fileprivate let sourceAddressLength: UInt8?
    fileprivate let destinationAddressLength: UInt8?
    fileprivate let sourceAddressHigh: UInt64?
    fileprivate let sourceAddressLow: UInt64?
    fileprivate let destinationAddressHigh: UInt64?
    fileprivate let destinationAddressLow: UInt64?
    fileprivate let sourcePort: UInt16?
    fileprivate let destinationPort: UInt16?

    /// - Parameters:
    ///   - src: Source endpoint identity used in tests or text-only call sites.
    ///   - dst: Destination endpoint identity used in tests or text-only call sites.
    ///   - proto: Transport protocol hint (for example, `tcp` or `udp`).
    public init(src: String, dst: String, proto: String) {
        self.textSource = src
        self.textDestination = dst
        self.textProtocol = proto
        self.flowHash = nil
        self.reverseFlowHash = nil
        self.ipVersion = nil
        self.transportProtocolNumber = nil
        self.sourceAddressLength = nil
        self.destinationAddressLength = nil
        self.sourceAddressHigh = nil
        self.sourceAddressLow = nil
        self.destinationAddressHigh = nil
        self.destinationAddressLow = nil
        self.sourcePort = nil
        self.destinationPort = nil
    }

    init(
        flowHash: UInt64,
        reverseFlowHash: UInt64,
        ipVersion: UInt8,
        transportProtocolNumber: UInt8,
        sourceAddressLength: UInt8,
        destinationAddressLength: UInt8,
        sourceAddressHigh: UInt64,
        sourceAddressLow: UInt64,
        destinationAddressHigh: UInt64,
        destinationAddressLow: UInt64,
        sourcePort: UInt16,
        destinationPort: UInt16
    ) {
        self.textSource = nil
        self.textDestination = nil
        self.textProtocol = nil
        self.flowHash = flowHash
        self.reverseFlowHash = reverseFlowHash
        self.ipVersion = ipVersion
        self.transportProtocolNumber = transportProtocolNumber
        self.sourceAddressLength = sourceAddressLength
        self.destinationAddressLength = destinationAddressLength
        self.sourceAddressHigh = sourceAddressHigh
        self.sourceAddressLow = sourceAddressLow
        self.destinationAddressHigh = destinationAddressHigh
        self.destinationAddressLow = destinationAddressLow
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
    }

    /// Source endpoint text for diagnostics and tests.
    public var src: String {
        if let textSource {
            return textSource
        }
        guard let sourceAddressLength,
              let sourceAddressHigh,
              let sourceAddressLow else {
            return ""
        }
        let address = Self.addressString(high: sourceAddressHigh, low: sourceAddressLow, length: Int(sourceAddressLength))
        guard let sourcePort, sourcePort != 0 else {
            return address
        }
        return "\(address):\(sourcePort)"
    }

    /// Destination endpoint text for diagnostics and tests.
    public var dst: String {
        if let textDestination {
            return textDestination
        }
        guard let destinationAddressLength,
              let destinationAddressHigh,
              let destinationAddressLow else {
            return ""
        }
        let address = Self.addressString(high: destinationAddressHigh, low: destinationAddressLow, length: Int(destinationAddressLength))
        guard let destinationPort, destinationPort != 0 else {
            return address
        }
        return "\(address):\(destinationPort)"
    }

    /// Transport protocol hint used in logs and tests.
    public var proto: String {
        if let textProtocol {
            return textProtocol
        }
        guard let transportProtocolNumber else {
            return "ip"
        }
        switch transportProtocolNumber {
        case 6:
            return "tcp"
        case 17:
            return "udp"
        case 1:
            return "icmp"
        case 58:
            return "icmpv6"
        default:
            return String(transportProtocolNumber)
        }
    }

    /// Stable hex identifier used for live-tap grouping and detector state.
    var stableIdentifierHex: String {
        if let flowHash {
            let hex = String(flowHash, radix: 16, uppercase: false)
            if hex.count >= 16 {
                return hex
            }
            return String(repeating: "0", count: 16 - hex.count) + hex
        }

        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in "\(src)|\(dst)|\(proto)".utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        let hex = String(hash, radix: 16, uppercase: false)
        if hex.count >= 16 {
            return hex
        }
        return String(repeating: "0", count: 16 - hex.count) + hex
    }

    public static func == (lhs: FlowKey, rhs: FlowKey) -> Bool {
        if lhs.flowHash != nil || rhs.flowHash != nil {
            return lhs.flowHash == rhs.flowHash &&
                lhs.reverseFlowHash == rhs.reverseFlowHash &&
                lhs.ipVersion == rhs.ipVersion &&
                lhs.transportProtocolNumber == rhs.transportProtocolNumber &&
                lhs.sourceAddressLength == rhs.sourceAddressLength &&
                lhs.destinationAddressLength == rhs.destinationAddressLength &&
                lhs.sourceAddressHigh == rhs.sourceAddressHigh &&
                lhs.sourceAddressLow == rhs.sourceAddressLow &&
                lhs.destinationAddressHigh == rhs.destinationAddressHigh &&
                lhs.destinationAddressLow == rhs.destinationAddressLow &&
                lhs.sourcePort == rhs.sourcePort &&
                lhs.destinationPort == rhs.destinationPort
        }

        return lhs.textSource == rhs.textSource &&
            lhs.textDestination == rhs.textDestination &&
            lhs.textProtocol == rhs.textProtocol
    }

    public func hash(into hasher: inout Hasher) {
        if let flowHash {
            hasher.combine(0)
            hasher.combine(flowHash)
            hasher.combine(reverseFlowHash)
            hasher.combine(ipVersion)
            hasher.combine(transportProtocolNumber)
            hasher.combine(sourceAddressLength)
            hasher.combine(destinationAddressLength)
            hasher.combine(sourceAddressHigh)
            hasher.combine(sourceAddressLow)
            hasher.combine(destinationAddressHigh)
            hasher.combine(destinationAddressLow)
            hasher.combine(sourcePort)
            hasher.combine(destinationPort)
            return
        }

        hasher.combine(1)
        hasher.combine(textSource)
        hasher.combine(textDestination)
        hasher.combine(textProtocol)
    }

    private static func addressString(high: UInt64, low: UInt64, length: Int) -> String {
        guard length == 4 || length == 16 else {
            return ""
        }

        var bytes = [UInt8](repeating: 0, count: 16)
        var highBE = high.bigEndian
        var lowBE = low.bigEndian
        let highBytes = withUnsafeBytes(of: &highBE) { Array($0) }
        let lowBytes = withUnsafeBytes(of: &lowBE) { Array($0) }
        bytes.replaceSubrange(0..<8, with: highBytes)
        bytes.replaceSubrange(8..<16, with: lowBytes)

        if length == 4 {
            var address = in_addr()
            _ = bytes.withUnsafeBytes { rawBuffer in
                memcpy(&address, rawBuffer.baseAddress!.advanced(by: 12), 4)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            let result = withUnsafePointer(to: &address) {
                inet_ntop(AF_INET, UnsafeRawPointer($0), &buffer, socklen_t(INET_ADDRSTRLEN))
            }
            return result == nil ? "" : String(cString: buffer)
        }

        var address = in6_addr()
        _ = bytes.withUnsafeBytes { rawBuffer in
            memcpy(&address, rawBuffer.baseAddress!, 16)
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = withUnsafePointer(to: &address) {
            inet_ntop(AF_INET6, UnsafeRawPointer($0), &buffer, socklen_t(INET6_ADDRSTRLEN))
        }
        return result == nil ? "" : String(cString: buffer)
    }
}

/// One completed burst window returned by `BurstTracker`.
public struct BurstSample: Sendable, Equatable {
    public let flow: FlowKey
    public let burstDurationMs: Int
    public let packetCount: Int
}

/// Detects packet bursts by measuring inter-arrival gaps per flow.
/// Decision: this type uses one internal lock instead of actor isolation because it sits on the per-packet hot path
/// and is already owned by the telemetry pipeline. The lock keeps tests and future callers safe without paying an
/// actor hop for every tracked packet.
public final class BurstTracker: @unchecked Sendable {
    private enum EvictionPolicy {
        static let minimumSweepIntervalSeconds: TimeInterval = 10
    }

    private let lock = NSLock()
    private let thresholdMs: Int
    private let maxTrackedFlows: Int
    private let flowTTLSeconds: TimeInterval
    private var lastPacketAt: [FlowKey: Date] = [:]
    private var burstCounts: [FlowKey: Int] = [:]
    private var arrivalQueue: ArraySlice<FlowKey> = []
    private var lastSweepAt: Date?

    /// Creates a burst tracker with gap-based burst segmentation.
    /// - Parameters:
    ///   - thresholdMs: Max inter-packet gap that still counts as same burst.
    ///   - maxTrackedFlows: Max number of flow burst states retained in memory.
    ///   - flowTTLSeconds: Max idle age before a burst state is evicted.
    public init(
        thresholdMs: Int,
        maxTrackedFlows: Int = 4_096,
        flowTTLSeconds: TimeInterval = 120
    ) {
        self.thresholdMs = thresholdMs
        self.maxTrackedFlows = max(1, maxTrackedFlows)
        self.flowTTLSeconds = max(1, flowTTLSeconds)
    }

    /// Records one packet event and optionally emits the previous completed burst.
    /// - Parameters:
    ///   - flow: Flow identity key.
    ///   - now: Packet timestamp.
    /// - Returns: Completed burst when a new burst boundary is detected; otherwise `nil`.
    public func recordPacket(flow: FlowKey, now: Date) -> BurstSample? {
        lock.lock()
        defer { lock.unlock() }

        maybeEvictExpired(now: now)
        if lastPacketAt[flow] == nil {
            evictOldestIfNeeded()
            arrivalQueue.append(flow)
        }

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

    /// Returns the number of burst states currently retained in memory.
    func trackedFlowCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return lastPacketAt.count
    }

    /// Explicitly removes one tracked flow.
    /// Decision: the analytics pipeline clears burst state on flow-close and synthetic lifecycle eviction so a
    /// recycled 5-tuple does not inherit stale burst history.
    func removeFlow(flow: FlowKey) {
        lock.lock()
        defer { lock.unlock() }
        remove(flow: flow)
        pruneArrivalQueueIfNeeded(force: true)
    }

    private func maybeEvictExpired(now: Date) {
        if let lastSweepAt,
           now.timeIntervalSince(lastSweepAt) < EvictionPolicy.minimumSweepIntervalSeconds,
           lastPacketAt.count < maxTrackedFlows {
            return
        }

        lastSweepAt = now
        let expiredFlows = lastPacketAt.compactMap { flow, lastSeen in
            now.timeIntervalSince(lastSeen) > flowTTLSeconds ? flow : nil
        }
        for flow in expiredFlows {
            remove(flow: flow)
        }
        pruneArrivalQueueIfNeeded(force: !expiredFlows.isEmpty)
    }

    private func evictOldestIfNeeded() {
        guard lastPacketAt.count >= maxTrackedFlows else {
            return
        }
        while let candidate = arrivalQueue.popFirst() {
            guard lastPacketAt[candidate] != nil else {
                continue
            }
            remove(flow: candidate)
            pruneArrivalQueueIfNeeded()
            return
        }
    }

    private func remove(flow: FlowKey) {
        lastPacketAt.removeValue(forKey: flow)
        burstCounts.removeValue(forKey: flow)
    }

    private func pruneArrivalQueueIfNeeded(force: Bool = false) {
        let queueLimit = max(maxTrackedFlows * 4, 256)
        guard force || arrivalQueue.startIndex > 128 || arrivalQueue.count > queueLimit else {
            return
        }

        var seen: Set<FlowKey> = []
        var activeQueue: [FlowKey] = []
        activeQueue.reserveCapacity(min(lastPacketAt.count, maxTrackedFlows))

        for flow in arrivalQueue {
            guard lastPacketAt[flow] != nil, seen.insert(flow).inserted else {
                continue
            }
            activeQueue.append(flow)
        }

        arrivalQueue = ArraySlice(activeQueue)
    }
}
