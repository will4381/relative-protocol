import Foundation

public final class MetricsRingBuffer {
    private var storage: [PacketSample?]
    private var head: Int = 0
    private var count: Int = 0

    public let capacity: Int

    public init(capacity: Int) {
        self.capacity = max(1, capacity)
        self.storage = Array(repeating: nil, count: self.capacity)
    }

    public func append(_ sample: PacketSample) {
        storage[head] = sample
        head = (head + 1) % capacity
        count = min(count + 1, capacity)
    }

    public func snapshot(limit: Int? = nil) -> [PacketSample] {
        guard count > 0 else { return [] }
        let snapshotCount: Int
        if let limit {
            snapshotCount = max(0, min(limit, count))
        } else {
            snapshotCount = count
        }
        guard snapshotCount > 0 else { return [] }
        var result: [PacketSample] = []
        result.reserveCapacity(snapshotCount)
        let start = (head - snapshotCount + capacity) % capacity
        for index in 0..<snapshotCount {
            let position = (start + index) % capacity
            if let sample = storage[position] {
                result.append(sample)
            }
        }
        return result
    }

    public func clear() {
        storage = Array(repeating: nil, count: capacity)
        head = 0
        count = 0
    }
}
