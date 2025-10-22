//
//  TunnelProvider.swift
//  RelativeProtocolTunnel
//
//  High-level façade that coordinates the Network Extension tunnel using
//  RelativeProtocol configuration and the tun2socks engine.
//

import Foundation
import NetworkExtension
import os.log
import RelativeProtocolCore

public enum RelativeProtocolTunnel {}

public extension RelativeProtocolTunnel {
    final class ProviderController {
        private unowned let provider: NEPacketTunnelProvider
        private let logger: Logger
        private var metrics: MetricsCollector?
        private var adapter: Tun2SocksAdapter?
        private var configuration: RelativeProtocol.Configuration?

        public init(provider: NEPacketTunnelProvider, logger: Logger = Logger(subsystem: "RelativeProtocolTunnel", category: "Provider")) {
            self.provider = provider
            self.logger = logger
        }

        public func start(configuration: RelativeProtocol.Configuration, completion: @escaping (Error?) -> Void) {
            do {
                let messages = try configuration.validateOrThrow()
                for message in messages where !message.isError {
                    logger.warning("Relative Protocol: Configuration warning – \(message.message, privacy: .public)")
                }
            } catch {
                let packageError = error as? RelativeProtocol.PackageError ?? RelativeProtocol.PackageError.invalidConfiguration([error.localizedDescription])
                logger.error("Relative Protocol: \(packageError.localizedDescription, privacy: .public)")
                configuration.hooks.eventSink?(.didFail(packageError.localizedDescription))
                completion(packageError)
                return
            }

            logger.notice("Relative Protocol: Starting tunnel (mtu=\(configuration.provider.mtu, privacy: .public))")
            self.configuration = configuration

            let metricsCollector: MetricsCollector?
            if configuration.provider.metrics.isEnabled {
                metricsCollector = MetricsCollector(
                    subsystem: "RelativeProtocolTunnel",
                    interval: configuration.provider.metrics.reportingInterval,
                    sink: nil
                )
                metricsCollector?.reset()
            } else {
                metricsCollector = nil
            }
            self.metrics = metricsCollector

            applyNetworkSettings(configuration: configuration) { [weak self] error in
                guard let self else {
                    completion(error)
                    return
                }
                guard error == nil else {
                    let message = error?.localizedDescription ?? "Unknown system error."
                    let packageError = RelativeProtocol.PackageError.networkSettingsFailed(message)
                    self.logger.error("Relative Protocol: \(packageError.localizedDescription, privacy: .public)")
                    configuration.hooks.eventSink?(.didFail(packageError.localizedDescription))
                    completion(packageError)
                    return
                }

                do {
                    try self.bootBridge(configuration: configuration, metrics: metricsCollector)
                    completion(nil)
                } catch {
                    let packageError = error as? RelativeProtocol.PackageError ?? RelativeProtocol.PackageError.engineStartFailed(error.localizedDescription)
                    self.logger.error("Relative Protocol: \(packageError.localizedDescription, privacy: .public)")
                    configuration.hooks.eventSink?(.didFail(packageError.localizedDescription))
                    completion(packageError)
                }
            }
        }

        public func stop(reason: NEProviderStopReason, completion: @escaping () -> Void) {
            logger.notice("Relative Protocol: Stopping tunnel (reason=\(reason.rawValue, privacy: .public))")
            adapter?.stop()
            adapter = nil
            metrics = nil
            completion()
        }

        public func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
            guard !messageData.isEmpty else {
                completionHandler?(nil)
                return
            }
            completionHandler?(Data("ack".utf8))
        }

        // MARK: - Private

        private func applyNetworkSettings(configuration: RelativeProtocol.Configuration, completion: @escaping (Error?) -> Void) {
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.provider.ipv4.remoteAddress)
            settings.mtu = NSNumber(value: configuration.provider.mtu)

            let ipv4 = configuration.provider.ipv4
            let ipv4Settings = NEIPv4Settings(addresses: [ipv4.address], subnetMasks: [ipv4.subnetMask])
            let routes = ipv4.includedRoutes.isEmpty ? [RelativeProtocol.Configuration.Route.default] : ipv4.includedRoutes
            ipv4Settings.includedRoutes = routes.map { route in
                NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
            }
            settings.ipv4Settings = ipv4Settings

            let dns = configuration.provider.dns
            if !dns.servers.isEmpty {
                let dnsSettings = NEDNSSettings(servers: dns.servers)
                dnsSettings.matchDomains = dns.matchDomains
                dnsSettings.searchDomains = dns.searchDomains
                settings.dnsSettings = dnsSettings
            }

            provider.setTunnelNetworkSettings(settings, completionHandler: completion)
        }

        private func bootBridge(configuration: RelativeProtocol.Configuration, metrics: MetricsCollector?) throws {
            let engine: Tun2SocksEngine
            #if canImport(Tun2Socks)
            engine = GoTun2SocksEngine(
                configuration: configuration,
                logger: Logger(subsystem: "RelativeProtocolTunnel", category: "GoTun2Socks")
            )
            #else
            engine = NoOpTun2SocksEngine(logger: Logger(subsystem: "RelativeProtocolTunnel", category: "NoOpTun2Socks"))
            #endif

            let adapter = Tun2SocksAdapter(
                provider: provider,
                configuration: configuration,
                metrics: metrics,
                engine: engine,
                hooks: configuration.hooks
            )
            do {
                try adapter.start()
            } catch {
                throw RelativeProtocol.PackageError.engineStartFailed(error.localizedDescription)
            }
            self.adapter = adapter
        }
    }
}
