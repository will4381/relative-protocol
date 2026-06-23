// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
#if canImport(os)
import os
#else
/// Portable placeholder for Apple signpost interval state on platforms without the `os` module.
public struct OSSignpostIntervalState: Sendable {}
#endif

/// Named signpost intervals required for runtime performance inspection.
public enum SignpostName: String, Sendable, CaseIterable {
    case startup
    case settingsApply = "settings-apply"
    case connectionEstablishment = "connection-establishment"
    case relayLoop = "relay-loop"
    case analyticsFlush = "analytics-flush"
}

/// Lightweight signpost facade that allows callers to avoid direct OSSignposter usage.
public final class SignpostSupport: @unchecked Sendable {
#if canImport(os)
    // Docs: https://developer.apple.com/documentation/os/ossignposter
    private let signposter: OSSignposter
#endif

    /// Creates a signposter scoped to `subsystem` and `category`.
    /// - Parameters:
    ///   - subsystem: Unified logging subsystem identifier.
    ///   - category: Unified logging category used for signposts.
    public init(subsystem: String, category: String) {
#if canImport(os)
        self.signposter = OSSignposter(subsystem: subsystem, category: category)
#else
        _ = subsystem
        _ = category
#endif
    }

    // Docs: https://developer.apple.com/documentation/os/ossignposter/begininterval(_:id:_:)
    /// Starts an interval signpost when signposting is enabled.
    /// - Parameters:
    ///   - name: Stable interval name.
    ///   - message: Optional public message attached to interval start.
    /// - Returns: Interval state token used to finish the interval, or `nil` when signposting is disabled.
    @discardableResult
    public func begin(_ name: SignpostName, message: String = "") -> OSSignpostIntervalState? {
#if canImport(os)
        guard signposter.isEnabled else {
            return nil
        }
        return signposter.beginInterval(name.staticName, "\(message, privacy: .public)")
#else
        _ = name
        _ = message
        return nil
#endif
    }

    // Docs: https://developer.apple.com/documentation/os/ossignposter/endinterval(_:_:_:)
    /// Ends a previously started interval signpost.
    /// - Parameters:
    ///   - name: Interval name used at start time.
    ///   - state: State token returned by `begin`.
    ///   - message: Optional public message attached to interval end.
    public func end(_ name: SignpostName, state: OSSignpostIntervalState?, message: String = "") {
#if canImport(os)
        guard let state else {
            return
        }
        signposter.endInterval(name.staticName, state, "\(message, privacy: .public)")
#else
        _ = name
        _ = state
        _ = message
#endif
    }

    // Docs: https://developer.apple.com/documentation/os/ossignposter/emitevent(_:id:_:)
    /// Emits a point-in-time signpost event.
    /// - Parameters:
    ///   - name: Stable event name.
    ///   - message: Optional public message attached to the event.
    public func emit(_ name: SignpostName, message: String = "") {
#if canImport(os)
        guard signposter.isEnabled else {
            return
        }
        signposter.emitEvent(name.staticName, "\(message, privacy: .public)")
#else
        _ = name
        _ = message
#endif
    }
}

#if canImport(os)
private extension SignpostName {
    var staticName: StaticString {
        switch self {
        case .startup:
            return "startup"
        case .settingsApply:
            return "settings-apply"
        case .connectionEstablishment:
            return "connection-establishment"
        case .relayLoop:
            return "relay-loop"
        case .analyticsFlush:
            return "analytics-flush"
        }
    }
}
#endif
