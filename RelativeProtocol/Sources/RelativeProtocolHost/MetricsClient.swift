import Foundation
import RelativeProtocolCore

public struct MetricsClient {
    private let store: MetricsStore

    public init(appGroupID: String, maxSnapshots: Int = 512) {
        self.store = MetricsStore(appGroupID: appGroupID, maxSnapshots: maxSnapshots)
    }

    public func loadSnapshots() -> [MetricsSnapshot] {
        store.load()
    }

    public func clear() {
        store.clear()
    }
}
