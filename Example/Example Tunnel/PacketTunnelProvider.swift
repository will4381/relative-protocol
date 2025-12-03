import NetworkExtension
import RelativeProtocolCore
import RelativeProtocolTunnel
import os.log

private let log = OSLog(subsystem: "com.relative.tunnel", category: "PacketTunnelProvider")

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var controller = ProviderController(provider: self)

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        os_log(.default, log: log, "[RPDBG] startTunnel: providerConfig keys=%{public}@", providerConfig?.keys.joined(separator: ", ") ?? "nil")
        if let configData = providerConfig?["configuration"] as? Data {
            os_log(.default, log: log, "[RPDBG] startTunnel: configuration data size=%d", configData.count)
        } else {
            os_log(.default, log: log, "[RPDBG] startTunnel: NO configuration data - will use defaults!")
        }
        let configuration = RelativeProtocol.Configuration.load(from: providerConfig)
        os_log(.default, log: log, "[RPDBG] startTunnel: loaded config logging.enabled=%{public}@", configuration.logging.enabled ? "true" : "false")
        controller.start(configuration: configuration, completion: completionHandler)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        controller.stop(reason: reason, completion: completionHandler)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else {
            return
        }
        let decoder = JSONDecoder()
        let encoder = JSONEncoder()
        if let command = try? decoder.decode(TunnelCommand.self, from: messageData),
           let response = handle(command: command) {
            completionHandler(try? encoder.encode(response))
            return
        }
        completionHandler(nil)
    }

    private func handle(command: TunnelCommand) -> TunnelResponse? {
        switch command.kind {
        case .dnsHistory:
            guard let request = command.dnsRequest else { return nil }
            let observations = controller.recentDnsObservations(limit: request.limit)
            return .dnsHistory(.init(observations: observations))
        case .installHostRules:
            let rules = command.hostRules ?? []
            let results = controller.installHostRules(rules)
            return .hostRuleResults(results)
        case .removeHostRule:
            guard let request = command.removalRequest else { return nil }
            let result = controller.removeHostRule(ruleID: request.ruleID)
            return .hostRuleRemoval(result)
        case .telemetryDrain:
            guard let request = command.telemetryRequest else { return nil }
            let response = controller.drainTelemetry(maxEvents: request.maxEvents)
            return .telemetry(response)
        }
    }
}
