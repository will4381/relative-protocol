// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation

/// Shared App Group container resolver used by analytics and logging paths.
/// Decision: package modules should agree on one container root resolver so shared-storage layout changes do not drift.
public enum SharedContainerRootResolver {
    public enum Error: LocalizedError {
        case unavailableContainer(String)
        case unsupportedPlatform(String)

        public var errorDescription: String? {
            switch self {
            case .unavailableContainer(let appGroupID):
                return "Shared container is unavailable for App Group '\(appGroupID)'."
            case .unsupportedPlatform(let appGroupID):
                return "Shared container App Group '\(appGroupID)' is only available on Apple platforms."
            }
        }
    }

    // Docs: https://developer.apple.com/documentation/foundation/filemanager/containerurl(forsecurityapplicationgroupidentifier:)
    public static func resolve(appGroupID: String) throws -> URL {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS) || os(visionOS)
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) else {
            throw Error.unavailableContainer(appGroupID)
        }
        return container
#else
        throw Error.unsupportedPlatform(appGroupID)
#endif
    }
}
