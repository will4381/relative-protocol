import Analytics
import Foundation

/// Host-side reader for the latest persisted tunnel stop breadcrumb.
/// Decision: keep only the tiny stop artifact in shared storage so the app can explain disconnects even when the
/// tunnel is no longer running.
public struct TunnelStopStore: Sendable {
    public let appGroupID: String

    public init(appGroupID: String) {
        self.appGroupID = appGroupID
    }

    public func load() throws -> TunnelStopRecord? {
        let url = try lastStopURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(TunnelStopRecord.self, from: Data(contentsOf: url))
    }

    public func clear() throws {
        let url = try lastStopURL()
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    private func lastStopURL() throws -> URL {
        try AnalyticsStoragePaths.lastStopURL(appGroupID: appGroupID)
    }
}
