import Foundation

/// Resolves the root directory where JSONL log files should be written.
public protocol LogRootPathProvider: Sendable {
    /// Resolves the directory where active/rotated JSONL files should live.
    /// - Returns: Root directory URL for JSONL logs.
    /// - Throws: Provider-specific resolution errors.
    func resolveRootPath() throws -> URL
}

/// Production root provider that resolves an app group container path.
public struct AppGroupLogRootPathProvider: LogRootPathProvider {
    public let appGroupID: String

    /// Creates an app-group-backed log root provider.
    /// - Parameter appGroupID: App Group identifier used to resolve shared container.
    public init(appGroupID: String) {
        self.appGroupID = appGroupID
    }

    /// Resolves shared App Group logs root.
    /// - Returns: `<app-group-container>/Logs`.
    /// - Throws: `SharedContainerRootResolver.Error.unavailableContainer` when group container cannot be resolved.
    public func resolveRootPath() throws -> URL {
        let container = try SharedContainerRootResolver.resolve(appGroupID: appGroupID)
        return container.appendingPathComponent("Logs", isDirectory: true)
    }
}

/// Harness/test root provider that points at a deterministic local directory.
public struct HarnessLogRootPathProvider: LogRootPathProvider {
    public let root: URL

    /// Creates a fixed-root provider for harness and tests.
    /// - Parameter root: Pre-resolved root directory.
    public init(root: URL) {
        self.root = root
    }

    /// Returns the configured harness root path.
    public func resolveRootPath() throws -> URL {
        root
    }
}
