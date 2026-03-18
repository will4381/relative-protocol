import Foundation
import Observability

/// Shared App Group path helpers for tunnel analytics artifacts.
/// Decision: host readers and the tunnel extension should resolve one canonical directory layout so path changes do not
/// drift across modules.
public enum AnalyticsStoragePaths {
    public enum Error: LocalizedError {
        case containerUnavailable(String)

        public var errorDescription: String? {
            switch self {
            case .containerUnavailable(let appGroupID):
                return "Shared container is unavailable for App Group '\(appGroupID)'."
            }
        }
    }

    public static func analyticsRoot(appGroupID: String) throws -> URL {
        do {
            let container = try SharedContainerRootResolver.resolve(appGroupID: appGroupID)
            return container.appendingPathComponent("Analytics", isDirectory: true)
        } catch SharedContainerRootResolver.Error.unavailableContainer(let appGroupID) {
            throw Error.containerUnavailable(appGroupID)
        }
    }

    public static func detectionsURL(appGroupID: String) throws -> URL {
        try analyticsRoot(appGroupID: appGroupID)
            .appendingPathComponent("Detections", isDirectory: true)
            .appendingPathComponent("detections.json", isDirectory: false)
    }

    public static func lastStopURL(appGroupID: String) throws -> URL {
        try analyticsRoot(appGroupID: appGroupID)
            .appendingPathComponent("last-stop.json", isDirectory: false)
    }

    public static func signaturesRoot(appGroupID: String) throws -> URL {
        try analyticsRoot(appGroupID: appGroupID)
            .appendingPathComponent("AppSignatures", isDirectory: true)
    }

    public static func signatureURL(appGroupID: String, fileName: String) throws -> URL {
        try signaturesRoot(appGroupID: appGroupID)
            .appendingPathComponent(fileName, isDirectory: false)
    }
}

/// Shared file-protection helpers for tiny persisted analytics artifacts.
/// Decision: detector summaries and stop breadcrumbs should be unreadable while the device is locked, even if that
/// means writes can fail and get retried later.
public enum ProtectedAnalyticsFileIO {
    private static var protectionAttributes: [FileAttributeKey: Any] {
#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        [.protectionKey: FileProtectionType.complete]
#else
        [:]
#endif
    }

    private static var writeOptions: Data.WritingOptions {
#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        [.atomic, .completeFileProtection]
#else
        [.atomic]
#endif
    }

    private static func excludeFromBackupIfNeeded(_ url: URL) throws {
#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        // Docs: https://developer.apple.com/documentation/foundation/urlresourcevalues
        // Docs: https://developer.apple.com/documentation/foundation/nsurl/setresourcevalues(_:)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(values)
#endif
    }

    public static func createProtectedDirectory(at url: URL) throws {
        // Docs: https://developer.apple.com/documentation/foundation/filemanager/createdirectory(atpath:withintermediatedirectories:attributes:)
        try FileManager.default.createDirectory(
            atPath: url.path,
            withIntermediateDirectories: true,
            attributes: protectionAttributes
        )
        try excludeFromBackupIfNeeded(url)
    }

    public static func writeProtectedData(_ data: Data, to url: URL) throws {
        let root = url.deletingLastPathComponent()
        try createProtectedDirectory(at: root)

        // Docs: https://developer.apple.com/documentation/foundation/data/write(to:options:)
        try data.write(to: url, options: writeOptions)
        if !protectionAttributes.isEmpty {
            try FileManager.default.setAttributes(protectionAttributes, ofItemAtPath: url.path)
        }
        try excludeFromBackupIfNeeded(url)
    }
}
