import Foundation

/// Persisted tunnel stop reason written by the extension and read by host apps.
/// Invariant: `reasonCode` stores the exact `NEProviderStopReason.rawValue` observed by the provider.
public struct TunnelStopRecord: Codable, Sendable, Equatable {
    public let timestamp: Date
    public let reasonCode: Int
    public let reasonName: String

    /// - Parameters:
    ///   - timestamp: Time when the provider was asked to stop.
    ///   - reasonCode: Raw `NEProviderStopReason` integer supplied by NetworkExtension.
    ///   - reasonName: Stable case label persisted for diagnostics and forward compatibility.
    public init(timestamp: Date, reasonCode: Int, reasonName: String) {
        self.timestamp = timestamp
        self.reasonCode = reasonCode
        self.reasonName = reasonName
    }

    /// True when the stop was explicitly initiated by the user or Settings.
    public var isUserInitiated: Bool {
        reasonCode == 1
    }

    /// Human-readable summary mapped from Apple's provider stop reason codes.
    public var summary: String {
        Self.summary(forReasonCode: reasonCode, reasonName: reasonName)
    }

    /// - Parameters:
    ///   - reasonCode: Raw provider stop reason code.
    ///   - reasonName: Persisted case label used as a fallback for unknown values.
    /// - Returns: Short UI-safe explanation of why the tunnel stopped.
    public static func summary(forReasonCode reasonCode: Int, reasonName: String) -> String {
        switch reasonCode {
        case 0:
            return "Stopped without a reported reason"
        case 1:
            return "Stopped by user"
        case 2:
            return "Stopped because the provider failed"
        case 3:
            return "Stopped because no network was available"
        case 4:
            return "Stopped after an unrecoverable network change"
        case 5:
            return "Stopped because the provider was disabled"
        case 6:
            return "Stopped because authentication was canceled"
        case 7:
            return "Stopped because the configuration failed"
        case 8:
            return "Stopped after being idle too long"
        case 9:
            return "Stopped because the configuration was disabled"
        case 10:
            return "Stopped because the configuration was removed"
        case 11:
            return "Stopped because another VPN configuration took over"
        case 12:
            return "Stopped because the user logged out"
        case 13:
            return "Stopped because the active user changed"
        case 14:
            return "Stopped because the connection failed"
        case 15:
            return "Stopped because the device went to sleep"
        case 16:
            return "Stopped because the app or extension was updated"
        case 17:
            return "Stopped because NetworkExtension reported an internal error"
        default:
            let trimmedName = reasonName.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmedName.isEmpty {
                return "Stopped for an unknown reason"
            }
            return "Stopped (\(trimmedName))"
        }
    }
}
