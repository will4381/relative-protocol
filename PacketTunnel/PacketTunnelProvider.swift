//
//  PacketTunnelProvider.swift
//  PacketTunnel
//
//  Entry point for the Network Extension packet tunnel.
//

import NetworkExtension
import os.log

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "PacketTunnel", category: "Provider")
    private lazy var metrics = BridgeMetrics(subsystem: "PacketTunnel")
    private var adapter: Tun2SocksAdapter?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration as? [String: NSObject]
        let configuration = BridgeConfiguration.load(from: providerConfig)
        logger.notice("Starting tunnel (mtu=\(configuration.mtu, privacy: .public))")

        configureNetworkSettings(configuration: configuration) { [weak self] error in
            guard let self else {
                completionHandler(error)
                return
            }
            guard error == nil else {
                self.logger.error("Failed to apply tunnel settings: \(String(describing: error), privacy: .public)")
                completionHandler(error)
                return
            }
            do {
                try self.bootBridge(configuration: configuration)
                completionHandler(nil)
            } catch {
                self.logger.error("Failed to start bridge: \(String(describing: error), privacy: .public)")
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.notice("Stopping tunnel (reason=\(reason.rawValue, privacy: .public))")
        adapter?.stop()
        adapter = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard !messageData.isEmpty else {
            completionHandler?(nil)
            return
        }
        completionHandler?(Data("ack".utf8))
    }

    // MARK: - Private

    private func configureNetworkSettings(configuration: BridgeConfiguration, completion: @escaping (Error?) -> Void) {
        metrics.reset()
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.remoteAddress)
        settings.mtu = NSNumber(value: configuration.mtu)

        let ipv4Settings = NEIPv4Settings(addresses: [configuration.ipv4Address], subnetMasks: [configuration.ipv4SubnetMask])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4Settings

        if !configuration.dnsServers.isEmpty {
            let dnsSettings = NEDNSSettings(servers: configuration.dnsServers)
            dnsSettings.matchDomains = [""]
            settings.dnsSettings = dnsSettings
        }

        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    private func bootBridge(configuration: BridgeConfiguration) throws {
        let engine: Tun2SocksEngine
#if canImport(Tun2Socks)
        engine = GoTun2SocksEngine(
            configuration: configuration,
            logger: Logger(subsystem: "PacketTunnel", category: "GoTun2Socks")
        )
#else
        engine = NoOpTun2SocksEngine(logger: Logger(subsystem: "PacketTunnel", category: "NoOpTun2Socks"))
#endif
        let adapter = Tun2SocksAdapter(
            provider: self,
            configuration: configuration,
            metrics: metrics,
            engine: engine
        )
        try adapter.start()
        self.adapter = adapter
    }
}
