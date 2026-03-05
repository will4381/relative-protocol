import Foundation

/// Expected dataplane API/ABI versions used to reject incompatible binaries.
public struct DataplaneVersion: Sendable, Equatable {
    public let apiVersion: UInt16
    public let abiVersion: UInt16

    /// - Parameters:
    ///   - apiVersion: Semantic API contract version.
    ///   - abiVersion: ABI layout/version used for binary compatibility checks.
    public init(apiVersion: UInt16, abiVersion: UInt16) {
        self.apiVersion = apiVersion
        self.abiVersion = abiVersion
    }

    public static let current = DataplaneVersion(apiVersion: 1, abiVersion: 1)
}

/// Coarse dataplane lifecycle state surfaced by the C callback contract.
public enum DataplaneState: UInt32, Sendable {
    case created = 0
    case running = 1
    case stopped = 2
    case unknown = 999

    init(raw: UInt32) {
        self = DataplaneState(rawValue: raw) ?? .unknown
    }
}

/// Snapshot structure for dataplane packet counters.
public struct DataplaneStats: Sendable, Equatable {
    public let packetsIn: UInt64
    public let packetsOut: UInt64
    public let bytesIn: UInt64
    public let bytesOut: UInt64

    /// - Parameters:
    ///   - packetsIn: Number of inbound packets seen by dataplane.
    ///   - packetsOut: Number of outbound packets emitted by dataplane.
    ///   - bytesIn: Number of inbound bytes seen by dataplane.
    ///   - bytesOut: Number of outbound bytes emitted by dataplane.
    public init(packetsIn: UInt64, packetsOut: UInt64, bytesIn: UInt64, bytesOut: UInt64) {
        self.packetsIn = packetsIn
        self.packetsOut = packetsOut
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

/// Swift-side callback hooks executed on the C bridge callback queue.
public struct DataplaneCallbacks: Sendable {
    public let onLog: @Sendable (String) -> Void
    public let onState: @Sendable (DataplaneState) -> Void

    /// - Parameters:
    ///   - onLog: Callback for dataplane log lines.
    ///   - onState: Callback for dataplane lifecycle state transitions.
    public init(
        onLog: @escaping @Sendable (String) -> Void,
        onState: @escaping @Sendable (DataplaneState) -> Void
    ) {
        self.onLog = onLog
        self.onState = onState
    }

    public static let noop = DataplaneCallbacks(onLog: { _ in }, onState: { _ in })
}

/// Errors surfaced by the Swift dataplane bridge.
public enum DataplaneError: Error, Sendable, Equatable {
    case versionMismatch(expected: DataplaneVersion, actual: DataplaneVersion)
    case createFailed
    case startFailed(code: Int32)
    case stopFailed(code: Int32)
    case statsFailed(code: Int32)
    case destroyed
}
