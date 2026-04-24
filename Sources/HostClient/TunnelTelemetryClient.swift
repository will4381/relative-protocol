import Analytics
import Foundation
@preconcurrency import NetworkExtension

public enum TunnelTelemetryClientError: LocalizedError {
    case invalidSession
    case providerReturnedNoResponse
    case providerFailure(String)
    case unexpectedResponseKind(String)

    public var errorDescription: String? {
        switch self {
        case .invalidSession:
            return "The VPN connection does not expose a tunnel provider session."
        case .providerReturnedNoResponse:
            return "The tunnel provider did not return telemetry data."
        case .providerFailure(let message):
            return "The tunnel provider reported an error: \(message)"
        case .unexpectedResponseKind(let kind):
            return "The tunnel provider returned an unexpected response kind: \(kind)"
        }
    }
}

/// Foreground client for live tunnel telemetry snapshots.
/// Decision: poll the provider on demand while the app is active, instead of treating the live tap as another
/// always-on shared-storage feed.
public struct TunnelTelemetryClient: Sendable {
    public init() {}

    public func snapshot(from connection: NEVPNConnection, packetLimit: Int? = nil) async throws -> TunnelTelemetrySnapshot {
        guard let session = connection as? NETunnelProviderSession else {
            throw TunnelTelemetryClientError.invalidSession
        }
        return try await snapshot(from: session, packetLimit: packetLimit)
    }

    public func snapshot(from session: NETunnelProviderSession, packetLimit: Int? = nil) async throws -> TunnelTelemetrySnapshot {
        let response = try await send(
            TunnelTelemetryRequest.snapshot(packetLimit: packetLimit),
            through: session
        )
        switch response.kind {
        case .snapshot:
            guard let snapshot = response.snapshot else {
                throw TunnelTelemetryClientError.providerReturnedNoResponse
            }
            return snapshot
        case .failure:
            throw TunnelTelemetryClientError.providerFailure(response.message ?? "unknown")
        case .cleared, .flushed:
            throw TunnelTelemetryClientError.unexpectedResponseKind(response.kind.rawValue)
        }
    }

    public func clearRecentEvents(from connection: NEVPNConnection) async throws {
        guard let session = connection as? NETunnelProviderSession else {
            throw TunnelTelemetryClientError.invalidSession
        }
        try await clearRecentEvents(from: session)
    }

    public func clearRecentEvents(from session: NETunnelProviderSession) async throws {
        let response = try await send(.clearRecentEvents, through: session)
        if response.kind == .failure {
            throw TunnelTelemetryClientError.providerFailure(response.message ?? "unknown")
        }
        guard response.kind == .cleared else {
            throw TunnelTelemetryClientError.unexpectedResponseKind(response.kind.rawValue)
        }
    }

    public func flushTelemetry(from connection: NEVPNConnection) async throws {
        guard let session = connection as? NETunnelProviderSession else {
            throw TunnelTelemetryClientError.invalidSession
        }
        try await flushTelemetry(from: session)
    }

    public func flushTelemetry(from session: NETunnelProviderSession) async throws {
        let response = try await send(.flush, through: session)
        if response.kind == .failure {
            throw TunnelTelemetryClientError.providerFailure(response.message ?? "unknown")
        }
        guard response.kind == .flushed else {
            throw TunnelTelemetryClientError.unexpectedResponseKind(response.kind.rawValue)
        }
    }

    public func clearDetections(from connection: NEVPNConnection) async throws {
        guard let session = connection as? NETunnelProviderSession else {
            throw TunnelTelemetryClientError.invalidSession
        }
        try await clearDetections(from: session)
    }

    public func clearDetections(from session: NETunnelProviderSession) async throws {
        let response = try await send(.clearDetections, through: session)
        if response.kind == .failure {
            throw TunnelTelemetryClientError.providerFailure(response.message ?? "unknown")
        }
        guard response.kind == .cleared else {
            throw TunnelTelemetryClientError.unexpectedResponseKind(response.kind.rawValue)
        }
    }

    private func send(_ request: TunnelTelemetryRequest, through session: NETunnelProviderSession) async throws -> TunnelTelemetryResponse {
        let requestData = try TunnelTelemetryMessageCodec.encodeRequest(request)
        let responseData = try await sendProviderMessage(requestData, through: session)
        return try TunnelTelemetryMessageCodec.decodeResponse(responseData)
    }

    // Docs: https://developer.apple.com/documentation/networkextension/netunnelprovidersession/sendprovidermessage(_:responsehandler:)
    /// Bridges the tunnel provider's message callback into async/await for the foreground app.
    private func sendProviderMessage(_ request: Data, through session: NETunnelProviderSession) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(request) { response in
                    guard let response else {
                        continuation.resume(throwing: TunnelTelemetryClientError.providerReturnedNoResponse)
                        return
                    }
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
