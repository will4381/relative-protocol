import Foundation

/// Tiny lock-protected cache used by synchronous analytics helpers.
/// Safety invariant: every read/write goes through `lock`, so this reference type is safe to share across
/// concurrency domains even though it contains mutable storage.
final class BoundedCache<Key: Hashable, Value>: @unchecked Sendable {
    private let countLimit: Int
    private let lock = NSLock()
    private var values: [Key: Value] = [:]
    private var insertionOrder: [Key] = []
    private var nextEvictionIndex = 0

    init(countLimit: Int) {
        self.countLimit = max(1, countLimit)
    }

    func value(for key: Key) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    func insert(_ value: Value, for key: Key) {
        lock.lock()
        defer { lock.unlock() }

        if values.updateValue(value, forKey: key) == nil {
            insertionOrder.append(key)
        }

        while values.count > countLimit, nextEvictionIndex < insertionOrder.count {
            let evictedKey = insertionOrder[nextEvictionIndex]
            nextEvictionIndex += 1
            values.removeValue(forKey: evictedKey)
        }

        // Periodically compact the logical ring so eviction stays O(1)-ish without unbounded array growth.
        if nextEvictionIndex >= 512, nextEvictionIndex * 2 >= insertionOrder.count {
            insertionOrder.removeFirst(nextEvictionIndex)
            nextEvictionIndex = 0
        }
    }
}
