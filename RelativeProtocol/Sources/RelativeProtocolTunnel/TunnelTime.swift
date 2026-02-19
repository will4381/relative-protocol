// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation

enum TunnelTime {
    // Approximate UNIX epoch by anchoring once and using monotonic uptime in hot paths.
    private static let epochOffset = Date().timeIntervalSince1970 - ProcessInfo.processInfo.systemUptime

    @inline(__always)
    static func nowEpochSeconds() -> TimeInterval {
        ProcessInfo.processInfo.systemUptime + epochOffset
    }

    @inline(__always)
    static func nowMonotonicSeconds() -> TimeInterval {
        ProcessInfo.processInfo.systemUptime
    }
}
