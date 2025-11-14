import NetworkExtension
import RelativeProtocolCore
import RelativeProtocolTunnel

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var controller = ProviderController(provider: self)

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let configuration = RelativeProtocol.Configuration.load(
            from: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        )
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
        if let request = try? decoder.decode(DNSHistoryRequest.self, from: messageData) {
            let observations = controller.recentDnsObservations(limit: max(0, request.limit))
            let response = TunnelResponse.dnsHistory(.init(observations: observations))
            completionHandler(try? encoder.encode(response))
            return
        }
        completionHandler(nil)
    }

    private func handle(command: TunnelCommand) -> TunnelResponse? {
        switch command.kind {
        case .dnsHistory:
            let limit = max(0, command.dnsRequest?.limit ?? 0)
            let observations = controller.recentDnsObservations(limit: limit)
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
