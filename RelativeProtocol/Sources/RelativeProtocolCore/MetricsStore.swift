import Foundation

public final class MetricsStore {
    public static let defaultKey = "metrics.snapshots"

    private let defaults: UserDefaults?
    private let key: String
    private let maxSnapshots: Int
    private let maxBytes: Int

    public init(
        appGroupID: String,
        key: String = MetricsStore.defaultKey,
        maxSnapshots: Int,
        maxBytes: Int = 1_500_000
    ) {
        self.defaults = UserDefaults(suiteName: appGroupID)
        self.key = key
        self.maxSnapshots = max(1, maxSnapshots)
        self.maxBytes = max(1, maxBytes)
    }

    public func append(_ snapshot: MetricsSnapshot) {
        guard let defaults else { return }
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(snapshot) else { return }
        guard data.count <= maxBytes else { return }
        var existing = defaults.array(forKey: key) as? [Data] ?? []
        var totalBytes = existing.reduce(0) { $0 + $1.count }
        while !existing.isEmpty && (totalBytes + data.count > maxBytes || existing.count >= maxSnapshots) {
            let removed = existing.removeFirst()
            totalBytes -= removed.count
        }
        if totalBytes + data.count > maxBytes {
            return
        }
        existing.append(data)
        defaults.set(existing, forKey: key)
    }

    public func load() -> [MetricsSnapshot] {
        guard let defaults else { return [] }
        let decoder = JSONDecoder()
        let existing = defaults.array(forKey: key) as? [Data] ?? []
        return existing.compactMap { data in
            try? decoder.decode(MetricsSnapshot.self, from: data)
        }
    }

    public func clear() {
        defaults?.removeObject(forKey: key)
    }
}
