import Foundation

/// Shared App Group container resolver used by analytics and logging paths.
/// Decision: package modules should agree on one container root resolver so shared-storage layout changes do not drift.
public enum SharedContainerRootResolver {
    public enum Error: LocalizedError {
        case unavailableContainer(String)

        public var errorDescription: String? {
            switch self {
            case .unavailableContainer(let appGroupID):
                return "Shared container is unavailable for App Group '\(appGroupID)'."
            }
        }
    }

    // Docs: https://developer.apple.com/documentation/foundation/filemanager/containerurl(forsecurityapplicationgroupidentifier:)
    public static func resolve(appGroupID: String) throws -> URL {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) else {
            throw Error.unavailableContainer(appGroupID)
        }
        return container
    }
}
