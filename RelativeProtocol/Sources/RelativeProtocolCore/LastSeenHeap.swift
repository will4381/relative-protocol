// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation

struct LastSeenHeap<Key: Hashable> {
    struct Entry {
        let key: Key
        let lastSeen: TimeInterval
        let revision: UInt64
    }

    private var storage: [Entry] = []

    var count: Int { storage.count }

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
