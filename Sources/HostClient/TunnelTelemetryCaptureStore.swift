import Analytics
import Foundation

public enum TunnelTelemetryCaptureStoreError: LocalizedError {
    case noCaptureInfo
    case noCaptureFile(String)
    case invalidCaptureLine

    public var errorDescription: String? {
        switch self {
        case .noCaptureInfo:
            return "No telemetry capture info is available."
        case .noCaptureFile(let sessionID):
            return "No telemetry capture file exists for session '\(sessionID)'."
        case .invalidCaptureLine:
            return "Telemetry capture export contained an invalid NDJSON line."
        }
    }
}

/// Host-side reader/exporter for session-scoped detector telemetry captures.
/// Decision: the containing app owns export/copy so the tunnel only has to finalize one protected App Group file.
public struct TunnelTelemetryCaptureStore: Sendable {
    public let appGroupID: String

    public init(appGroupID: String) {
        self.appGroupID = appGroupID
    }

    public func loadLatestInfo() throws -> TelemetryCaptureInfo? {
        let url = try AnalyticsStoragePaths.telemetryCaptureCurrentInfoURL(appGroupID: appGroupID)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        return try decodeInfo(from: url)
    }

    public func loadInfo(sessionID: String) throws -> TelemetryCaptureInfo? {
        let url = try AnalyticsStoragePaths.telemetryCaptureInfoURL(appGroupID: appGroupID, sessionID: sessionID)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        return try decodeInfo(from: url)
    }

    public func captureURL(sessionID: String) throws -> URL {
        let url = try AnalyticsStoragePaths.telemetryCaptureRecordsURL(appGroupID: appGroupID, sessionID: sessionID)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw TunnelTelemetryCaptureStoreError.noCaptureFile(sessionID)
        }
        return url
    }

    @discardableResult
    public func exportCapture(sessionID: String, to destinationURL: URL) throws -> URL {
        let sourceURL = try captureURL(sessionID: sessionID)
        return try TelemetryCaptureExporter.exportRecords(from: sourceURL, to: destinationURL)
    }

    @discardableResult
    public func exportLatestCapture(to destinationURL: URL) throws -> URL {
        guard let info = try loadLatestInfo(), let sessionID = info.sessionID else {
            throw TunnelTelemetryCaptureStoreError.noCaptureInfo
        }
        return try exportCapture(sessionID: sessionID, to: destinationURL)
    }

    private func decodeInfo(from url: URL) throws -> TelemetryCaptureInfo {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(TelemetryCaptureInfo.self, from: Data(contentsOf: url))
    }
}
