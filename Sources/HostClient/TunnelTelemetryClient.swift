import Analytics
import Dispatch
import Foundation
@preconcurrency import NetworkExtension

public enum TunnelTelemetryClientError: LocalizedError {
    case invalidSession
    case providerReturnedNoResponse
    case providerFailure(String)
    case unexpectedResponseKind(String)
    case providerTimedOut(TimeInterval)

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
        case .providerTimedOut(let seconds):
            return "The tunnel provider did not respond within \(seconds) seconds."
        }
    }
}

private final class ProviderMessageContinuationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?

    init(_ continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
    }

    func resume(returning data: Data) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: data)
    }

    func resume(throwing error: Error) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(throwing: error)
    }
}

/// Foreground client for live tunnel telemetry snapshots.
/// Decision: poll the provider on demand while the app is active, instead of treating the live tap as another
/// always-on shared-storage feed.
public struct TunnelTelemetryClient: Sendable {
    private static let defaultProviderMessageTimeout: TimeInterval = 3

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
            let box = ProviderMessageContinuationBox(continuation)
            let timeoutSeconds = Self.defaultProviderMessageTimeout
            let timeout = DispatchWorkItem {
                box.resume(throwing: TunnelTelemetryClientError.providerTimedOut(timeoutSeconds))
            }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeoutSeconds, execute: timeout)
            do {
                try session.sendProviderMessage(request) { response in
                    timeout.cancel()
                    guard let response else {
                        box.resume(throwing: TunnelTelemetryClientError.providerReturnedNoResponse)
                        return
                    }
                    box.resume(returning: response)
                }
            } catch {
                timeout.cancel()
                box.resume(throwing: error)
            }
        }
    }
}
