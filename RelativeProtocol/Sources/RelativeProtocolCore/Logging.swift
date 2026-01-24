// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation
import os

public enum RelativeLogCategory: String {
    case tunnel
    case parser
    case metrics
    case flow
}

public enum RelativeLog {
    public static let isVerbose: Bool = {
        let env = ProcessInfo.processInfo.environment["RELATIVE_VERBOSE_LOGS"]?.lowercased()
        let enabled = env == "1" || env == "true" || env == "yes"
        #if DEBUG
        return enabled
        #else
        return false
        #endif
    }()

    public static func logger(_ category: RelativeLogCategory) -> Logger {
        Logger(subsystem: "com.relative.protocol", category: category.rawValue)
    }
}