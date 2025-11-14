import Foundation
import NetworkExtension
import RelativeProtocolCore

@MainActor
public final class RelativeVPNController {
    public enum ControllerError: LocalizedError {
        case managerUnavailable
        case startFailed(Error)
        case tunnelNotConnected
        case messageFailed

        public var errorDescription: String? {
            switch self {
            case .managerUnavailable:
                return "Tunnel manager is not available"
            case .startFailed(let error):
                return "Unable to start tunnel (\(error.localizedDescription))"
            case .tunnelNotConnected:
                return "Tunnel is not connected"
            case .messageFailed:
                return "Unable to communicate with tunnel provider"
            }
        }
    }

    private var manager: NETunnelProviderManager?

    public init() {}

    public var connectionStatus: NEVPNStatus {
        manager?.connection.status ?? .invalid
    }

    public var connection: NEVPNConnection? {
        manager?.connection
    }

    public func prepareIfNeeded(descriptor: TunnelDescriptor) async throws {
        if let manager, manager.protocolConfiguration != nil {
            try await configure(descriptor: descriptor)
            return
        }

        let managers = try await Self.loadManagers()
        if let existing = managers.first(where: {
            guard let proto = $0.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == descriptor.providerBundleIdentifier
        }) {
            manager = existing
        } else {
            manager = NETunnelProviderManager()
        }
        try await configure(descriptor: descriptor)
    }

    public func configure(descriptor: TunnelDescriptor) async throws {
        guard let manager else {
            throw ControllerError.managerUnavailable
        }

        let proto = manager.protocolConfiguration as? NETunnelProviderProtocol ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = descriptor.providerBundleIdentifier
        proto.serverAddress = descriptor.configuration.serverAddress
        proto.providerConfiguration = descriptor.configuration.providerConfigurationDictionary()

        manager.localizedDescription = descriptor.localizedDescription
        manager.protocolConfiguration = proto
        manager.isEnabled = true

        try await Self.save(manager)
        try await Self.reload(manager)
    }

    public func connect() async throws {
        guard let manager else { throw ControllerError.managerUnavailable }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            throw ControllerError.startFailed(error)
        }
    }

    public func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    public func fetchDnsHistory(limit: Int = 100) async throws -> [DNSObservation] {
        let request = DNSHistoryRequest(limit: limit)
        let response = try await sendCommand(.dnsHistory(request))
        guard let observations = response.dnsResponse?.observations else {
            throw ControllerError.messageFailed
        }
        return observations
    }

    public func installHostRule(_ rule: HostRuleConfiguration) async throws -> HostRuleInstallResult {
        let response = try await sendCommand(.installHostRules([rule]))
        guard let result = response.hostRuleResults?.first else {
            throw ControllerError.messageFailed
        }
        return result
    }

    public func removeHostRule(ruleID: UInt64) async throws -> HostRuleRemovalResult {
        let response = try await sendCommand(.removeHostRule(.init(ruleID: ruleID)))
        guard let result = response.hostRuleRemoval else {
            throw ControllerError.messageFailed
        }
        return result
    }

    public func drainTelemetry(maxEvents: Int) async throws -> TelemetryDrainResponse {
        let response = try await sendCommand(.drainTelemetry(.init(maxEvents: maxEvents)))
        guard let telemetry = response.telemetryResponse else {
            throw ControllerError.messageFailed
        }
        return telemetry
    }

    // MARK: - Helpers

    private static func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    private static func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private static func reload(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func sendCommand(_ command: TunnelCommand) async throws -> TunnelResponse {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw ControllerError.managerUnavailable
        }
        guard session.status == .connected else {
            throw ControllerError.tunnelNotConnected
        }
        let payload = try JSONEncoder().encode(command)
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(payload) { response in
                    guard
                        let response,
                        let decoded = try? JSONDecoder().decode(TunnelResponse.self, from: response)
                    else {
                        continuation.resume(throwing: ControllerError.messageFailed)
                        return
                    }
                    continuation.resume(returning: decoded)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
