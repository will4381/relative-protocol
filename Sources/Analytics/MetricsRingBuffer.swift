import Foundation

/// Bounded ring buffer used to keep analytics snapshots in memory under memory pressure.
public struct MetricsRingBuffer<Element: Sendable>: Sendable {
    private var storage: [Element] = []
    private let capacity: Int

    /// Creates a ring buffer with fixed capacity.
    /// - Parameter capacity: Max retained elements. Values below `1` are clamped to `1`.
    public init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    /// Current number of retained elements.
    public var count: Int {
        storage.count
    }

    /// Appends one element, evicting the oldest entry when capacity is reached.
    /// - Parameter element: Element to append.
    public mutating func append(_ element: Element) {
        if storage.count == capacity {
            storage.removeFirst()
        }
        storage.append(element)
    }

    /// Returns a copy of buffer contents in insertion order.
    public func snapshot() -> [Element] {
        storage
    }
}

/// Serializable metric point persisted by `MetricsStore`.
public struct MetricRecord: Codable, Sendable, Equatable {
    public let name: String
    public let value: Double
    public let timestamp: Date

    /// - Parameters:
    ///   - name: Metric identifier.
    ///   - value: Numeric metric value.
    ///   - timestamp: Observation timestamp.
    public init(name: String, value: Double, timestamp: Date) {
        self.name = name
        self.value = value
        self.timestamp = timestamp
    }
}
