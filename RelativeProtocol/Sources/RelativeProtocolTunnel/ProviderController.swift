import Foundation
import NetworkExtension
import OSLog
import RelativeProtocolCore

public final class ProviderController {
    public enum ControllerError: LocalizedError {
        case missingProvider
        case configurationFailed(String)

        public var errorDescription: String? {
            switch self {
            case .missingProvider:
                return "Packet tunnel provider is unavailable"
            case .configurationFailed(let reason):
                return reason
            }
        }
    }

    private weak var provider: NEPacketTunnelProvider?
    private var engine: RelativeEngine?
    private var configuration: RelativeProtocol.Configuration?
    private let logger = Logger(subsystem: "RelativeProtocolTunnel", category: "Engine")

    public init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    public func start(
        configuration: RelativeProtocol.Configuration,
        completion: @escaping (Error?) -> Void
    ) {
        guard let provider else {
            completion(ControllerError.missingProvider)
            return
        }

        configurationDidChange(configuration)

        applyNetworkSettings(configuration) { [weak self] error in
            guard let self else { return }
            if let error {
                completion(error)
                return
            }

            do {
                let engineConfig = RelativeEngine.Configuration(
                    mtu: UInt32(configuration.mtu),
                    packetPoolBytes: UInt32(configuration.packetPoolBytes),
                    perFlowBytes: UInt32(configuration.perFlowBufferBytes)
                )
                let engine = try RelativeEngine(packetFlow: provider.packetFlow, configuration: engineConfig)
                try? engine.installLogHandler(level: .debug, breadcrumbs: .all) { [weak self] entry in
                    let logType = entry.level.osLogType
                    self?.logger.log(level: logType, "\(entry.message, privacy: .public)")
                }
                self.engine = engine
                try engine.start()
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    public func stop(reason: NEProviderStopReason, completion: @escaping () -> Void) {
        _ = reason
        engine?.stop()
        engine = nil
        completion()
    }

    private func configurationDidChange(_ configuration: RelativeProtocol.Configuration) {
        self.configuration = configuration
    }

    private func applyNetworkSettings(
        _ configuration: RelativeProtocol.Configuration,
        completion: @escaping (Error?) -> Void
    ) {
        guard let provider else {
            completion(ControllerError.missingProvider)
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.serverAddress)
        settings.mtu = NSNumber(value: configuration.mtu)

        let ipv4 = NEIPv4Settings(
            addresses: [configuration.interface.address],
            subnetMasks: [configuration.interface.subnetMask]
        )

        var routes: [NEIPv4Route] = []
        for route in configuration.routes {
            if route.isDefault {
                routes.append(.default())
            } else {
                routes.append(NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask))
            }
        }
        ipv4.includedRoutes = routes
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: configuration.dns.servers)
        dns.searchDomains = configuration.dns.searchDomains
        settings.dnsSettings = dns

        provider.setTunnelNetworkSettings(settings) { error in
            if let error {
                completion(ControllerError.configurationFailed(error.localizedDescription))
            } else {
                completion(nil)
            }
        }
    }

    public func recentDnsObservations(limit: Int) -> [DNSObservation] {
        engine?.recentDnsObservations(limit: limit) ?? []
    }

    public func installHostRules(_ rules: [HostRuleConfiguration]) -> [HostRuleInstallResult] {
        guard let engine else { return rules.map { HostRuleInstallResult(requestID: $0.id, pattern: $0.pattern, action: $0.action, ruleID: nil, errorMessage: "engine unavailable") } }
        return rules.map { rule in
            do {
                let ruleID = try engine.installHostRule(rule)
                return HostRuleInstallResult(requestID: rule.id, pattern: rule.pattern, action: rule.action, ruleID: ruleID)
            } catch {
                return HostRuleInstallResult(requestID: rule.id,
                                             pattern: rule.pattern,
                                             action: rule.action,
                                             ruleID: nil,
                                             errorMessage: error.localizedDescription)
            }
        }
    }

    public func removeHostRule(ruleID: UInt64) -> HostRuleRemovalResult {
        let removed = engine?.removeHostRule(ruleID) ?? false
        return HostRuleRemovalResult(ruleID: ruleID, removed: removed)
    }

    public func drainTelemetry(maxEvents: Int) -> TelemetryDrainResponse {
        guard let engine else { return TelemetryDrainResponse(events: [], droppedEvents: 0) }
        return engine.drainTelemetry(maxEvents: maxEvents)
    }
}

private extension RelativeEngine.LogLevel {
    var osLogType: OSLogType {
        switch self {
        case .error:
            return .error
        case .warn:
            return .default
        case .info:
            return .info
        case .debug:
            return .debug
        }
    }
}
