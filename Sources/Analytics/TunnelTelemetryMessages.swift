import Foundation

public enum TunnelTelemetryProtocolVersion {
    public static let current = 1
}

/// Typed thermal state surfaced to the containing app.
/// Contract: this is the stable package-owned domain for thermal reporting in `TunnelTelemetrySnapshot`.
public enum TunnelThermalState: String, Codable, Sendable, Equatable {
    case nominal
    case fair
    case serious
    case critical
    case unknown

    public init(thermalState: ProcessInfo.ThermalState?) {
        guard let thermalState else {
            self = .unknown
            return
        }

        switch thermalState {
        case .nominal:
            self = .nominal
        case .fair:
            self = .fair
        case .serious:
            self = .serious
        case .critical:
            self = .critical
        @unknown default:
            self = .unknown
        }
    }
}

/// Commands supported by the tunnel's app-message control channel.
public enum TunnelTelemetryCommand: String, Codable, Sendable, Equatable {
    case snapshot
    case clearRecentEvents
    case clearDetections
    case flush
}

/// Request sent from the containing app to the packet tunnel provider.
/// Decision: the foreground app asks for bounded snapshots instead of tailing a continuously persisted packet log.
public struct TunnelTelemetryRequest: Codable, Sendable, Equatable {
    public let version: Int
    public let command: TunnelTelemetryCommand
    public let packetLimit: Int?

    public init(
        version: Int = TunnelTelemetryProtocolVersion.current,
        command: TunnelTelemetryCommand,
        packetLimit: Int? = nil
    ) {
        self.version = version
        self.command = command
        self.packetLimit = packetLimit
    }

    public static func snapshot(packetLimit: Int? = nil) -> TunnelTelemetryRequest {
        TunnelTelemetryRequest(command: .snapshot, packetLimit: packetLimit)
    }

    public static let clearRecentEvents = TunnelTelemetryRequest(command: .clearRecentEvents)
    public static let clearDetections = TunnelTelemetryRequest(command: .clearDetections)
    public static let flush = TunnelTelemetryRequest(command: .flush)
}

/// Foreground snapshot returned by the packet tunnel provider.
/// Ownership: this payload is intentionally compact so it can cross `sendProviderMessage` without turning the app
/// refresh path into another always-on telemetry hotspot.
public struct TunnelTelemetrySnapshot: Codable, Sendable, Equatable {
    public let samples: [PacketSample]
    public let retainedSampleCount: Int
    public let retainedBytes: Int
    public let oldestSampleAt: Date?
    public let latestSampleAt: Date?
    public let acceptedBatches: Int
    public let queuedBatches: Int
    public let queuedBytes: Int
    public let droppedBatches: Int
    public let skippedBatches: Int
    public let bufferedRecords: Int
    public let thermalState: TunnelThermalState
    public let lowPowerModeEnabled: Bool
    public let detections: DetectionSnapshot

    public init(
        samples: [PacketSample],
        retainedSampleCount: Int,
        retainedBytes: Int,
        oldestSampleAt: Date?,
        latestSampleAt: Date?,
        acceptedBatches: Int,
        queuedBatches: Int,
        queuedBytes: Int,
        droppedBatches: Int,
        skippedBatches: Int,
        bufferedRecords: Int,
        thermalState: TunnelThermalState,
        lowPowerModeEnabled: Bool,
        detections: DetectionSnapshot
    ) {
        self.samples = samples
        self.retainedSampleCount = retainedSampleCount
        self.retainedBytes = retainedBytes
        self.oldestSampleAt = oldestSampleAt
        self.latestSampleAt = latestSampleAt
        self.acceptedBatches = acceptedBatches
        self.queuedBatches = queuedBatches
        self.queuedBytes = queuedBytes
        self.droppedBatches = droppedBatches
        self.skippedBatches = skippedBatches
        self.bufferedRecords = bufferedRecords
        self.thermalState = thermalState
        self.lowPowerModeEnabled = lowPowerModeEnabled
        self.detections = detections
    }

    public static let empty = TunnelTelemetrySnapshot(
        samples: [],
        retainedSampleCount: 0,
        retainedBytes: 0,
        oldestSampleAt: nil,
        latestSampleAt: nil,
        acceptedBatches: 0,
        queuedBatches: 0,
        queuedBytes: 0,
        droppedBatches: 0,
        skippedBatches: 0,
        bufferedRecords: 0,
        thermalState: .unknown,
        lowPowerModeEnabled: false,
        detections: .empty
    )
}

/// App-message response returned by the packet tunnel provider.
public struct TunnelTelemetryResponse: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable, Equatable {
        case snapshot
        case cleared
        case flushed
        case failure
    }

    public let version: Int
    public let kind: Kind
    public let snapshot: TunnelTelemetrySnapshot?
    public let message: String?

    public init(
        version: Int = TunnelTelemetryProtocolVersion.current,
        kind: Kind,
        snapshot: TunnelTelemetrySnapshot? = nil,
        message: String? = nil
    ) {
        self.version = version
        self.kind = kind
        self.snapshot = snapshot
        self.message = message
    }

    public static func snapshot(_ snapshot: TunnelTelemetrySnapshot) -> TunnelTelemetryResponse {
        TunnelTelemetryResponse(kind: .snapshot, snapshot: snapshot, message: nil)
    }

    public static let cleared = TunnelTelemetryResponse(kind: .cleared)

    public static let flushed = TunnelTelemetryResponse(kind: .flushed)

    public static func failure(_ message: String) -> TunnelTelemetryResponse {
        TunnelTelemetryResponse(kind: .failure, snapshot: nil, message: message)
    }
}

/// Shared request/response codec for `NETunnelProviderSession.sendProviderMessage`.
/// Decision: both sides use the same JSON encoder/decoder configuration so the app and the tunnel stay in lockstep
/// without duplicate date-formatting logic. Payloads also carry an explicit schema version so drift fails with a
/// clear compatibility error instead of a generic decode mismatch.
public enum TunnelTelemetryMessageCodec {
    public enum Error: LocalizedError, Equatable {
        case unsupportedVersion(Int)

        public var errorDescription: String? {
            switch self {
            case .unsupportedVersion(let version):
                return "Unsupported tunnel telemetry message version: \(version)"
            }
        }
    }

    public static func encodeRequest(_ request: TunnelTelemetryRequest) throws -> Data {
        try makeEncoder().encode(request)
    }

    public static func decodeRequest(_ data: Data) throws -> TunnelTelemetryRequest {
        let request = try makeDecoder().decode(TunnelTelemetryRequest.self, from: data)
        try validate(version: request.version)
        return request
    }

    public static func encodeResponse(_ response: TunnelTelemetryResponse) throws -> Data {
        try makeEncoder().encode(response)
    }

    public static func decodeResponse(_ data: Data) throws -> TunnelTelemetryResponse {
        let response = try makeDecoder().decode(TunnelTelemetryResponse.self, from: data)
        try validate(version: response.version)
        return response
    }

    private static func validate(version: Int) throws {
        guard version == TunnelTelemetryProtocolVersion.current else {
            throw Error.unsupportedVersion(version)
        }
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}
