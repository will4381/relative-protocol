// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

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