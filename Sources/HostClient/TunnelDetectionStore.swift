import Analytics
import Foundation

/// Host-side reader for persisted detector outputs.
/// Decision: the containing app can recover detector state after long background periods without relying on the raw
/// packet tap to stay durable.
public struct TunnelDetectionStore: Sendable {
    public let appGroupID: String

    public init(appGroupID: String) {
        self.appGroupID = appGroupID
    }

    public func load() throws -> DetectionSnapshot? {
        try DetectionStore(fileURL: AnalyticsStoragePaths.detectionsURL(appGroupID: appGroupID)).load()
    }

    public func clear() throws {
        try DetectionStore(fileURL: AnalyticsStoragePaths.detectionsURL(appGroupID: appGroupID)).clear()
    }
}
