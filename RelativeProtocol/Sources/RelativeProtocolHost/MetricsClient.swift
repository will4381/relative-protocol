// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Foundation
import RelativeProtocolCore

public struct MetricsClient {
    private let store: MetricsStore

    public init(
        appGroupID: String,
        maxSnapshots: Int = 512,
        format: MetricsStoreFormat = .json
    ) {
        self.store = MetricsStore(appGroupID: appGroupID, maxSnapshots: maxSnapshots, format: format)
    }

    public func loadSnapshots() -> [MetricsSnapshot] {
        store.load()
    }

    public func clear() {
        store.clear()
    }
}
