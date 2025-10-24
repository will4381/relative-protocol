//
//  PacketTunnelProvider.swift
//  Example Tunnel
//
//  Created by Will Kusch on 10/23/25.
//

import NetworkExtension
import Network
import OSLog
import RelativeProtocolTunnel
import RelativeProtocolCore

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "relative.example", category: "PacketTunnelProvider")
    private lazy var controller = RelativeProtocolTunnel.ProviderController(provider: self)

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration as? [String: NSObject]
        var configuration = RelativeProtocol.Configuration.load(from: providerConfig)

        // Respect the host application's logging preference; do not force debug logs on.
        var hooks = configuration.hooks
        hooks.eventSink = { [weak self] (event: RelativeProtocol.Configuration.Event) in
            switch event {
            case .willStart: self?.logger.notice("Tunnel willStart")
            case .didStart: self?.logger.notice("Tunnel didStart")
            case .didStop: self?.logger.notice("Tunnel didStop")
            case .didFail(let message): self?.logger.error("Tunnel didFail: \(message, privacy: .public)")
            }
        }
        hooks.packetTap = { [weak self] context in
            guard let self else { return }
            let direction = context.direction == .inbound ? "inbound" : "outbound"
            self.logger.debug("PacketTap \(direction, privacy: .public) bytes=\(context.payload.count, privacy: .public) proto=\(context.protocolNumber, privacy: .public)")
        }
        configuration.hooks = hooks

        controller.start(configuration: configuration, completion: completionHandler)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        controller.stop(reason: reason, completion: completionHandler)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Intercept "probe" messages from the host to test direct network reachability
        if let text = String(data: messageData, encoding: .utf8), text.hasPrefix("probe") {
            performProbe { result in
                completionHandler?(Data(result.utf8))
            }
            return
        }
        controller.handleAppMessage(messageData, completionHandler: completionHandler)
    }
}

// MARK: - Probe

private extension PacketTunnelProvider {
    /// Attempts to establish a TCP connection to 1.1.1.1:443 using NWConnection
    /// with parameters that avoid utun recursion, then reports a one-line result.
    func performProbe(completion: @escaping (String) -> Void) {
        let params = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        params.allowLocalEndpointReuse = true
        params.prohibitedInterfaceTypes = [.loopback, .other]

        let connection = NWConnection(host: "1.1.1.1", port: 443, using: params)
        let queue = DispatchQueue(label: "relative.example.probe")
        var finished = false

        func finish(_ message: String) {
            if finished { return }
            finished = true
            connection.cancel()
            completion(message)
        }

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                finish("ok")
            case .waiting(let error):
                finish("waiting: \(error.localizedDescription)")
            case .failed(let error):
                finish("error: \(error.localizedDescription)")
            case .cancelled:
                finish("cancelled")
            default:
                break
            }
        }

        connection.start(queue: queue)

        // Timeout after 5 seconds
        queue.asyncAfter(deadline: .now() + 5.0) { finish("timeout") }
    }
}
