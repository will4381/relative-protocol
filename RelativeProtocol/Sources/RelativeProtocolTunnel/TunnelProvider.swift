//
//  TunnelProvider.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  High-level façade that coordinates the Network Extension tunnel using
//  Relative Protocol configuration and the embedded engine. The
//  controller encapsulates all glue necessary to bridge Apple’s
//  `NEPacketTunnelProvider` APIs with the packaged bindings.
//

import Foundation
import NetworkExtension
import os.log
import RelativeProtocolCore

public enum RelativeProtocolTunnel {}

public extension RelativeProtocolTunnel {
    /// Production-ready orchestrator for an `NEPacketTunnelProvider`. Host code
    /// delegates lifecycle events to this controller instead of re-implementing
    /// the engine wiring or packet plumbing.
    final class ProviderController {
        private unowned let provider: NEPacketTunnelProvider
        private let logger: Logger
        private var metrics: MetricsCollector?
        private var adapter: EngineAdapter?
        private var configuration: RelativeProtocol.Configuration?
        private var trafficAnalyzer: TrafficAnalyzer?
        private var filterCoordinator: FilterCoordinator?
        private var filterConfiguration: FilterConfiguration = .init()
        private var pendingFilterInstallers: [(@Sendable (FilterCoordinator) -> Void)] = []

        public var forwardHostTracker: ForwardHostTracker? {
            adapter?.hostTracker
        }

        /// - Parameters:
        ///   - provider: The Network Extension provider the controller manages.
        ///   - logger: Optional custom logger for diagnostics.
        public init(provider: NEPacketTunnelProvider, logger: Logger = Logger(subsystem: "RelativeProtocolTunnel", category: "Provider")) {
            self.provider = provider
            self.logger = logger
        }

        /// Starts the tunnel by validating configuration, applying network
        /// settings, and spinning up the engine.
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

        /// Stops the tunnel and releases engine resources.
        public func stop(reason: NEProviderStopReason, completion: @escaping () -> Void) {
            adapter?.stop()
            adapter = nil
            metrics = nil
            trafficAnalyzer = nil
            filterCoordinator = nil
            pendingFilterInstallers.removeAll()
            completion()
        }

        /// Updates the filter configuration used when the tunnel boots. Must be
        /// called before `start(configuration:completion:)`.
        public func setFilterConfiguration(_ configuration: FilterConfiguration) {
            guard adapter == nil else { return }
            filterConfiguration = configuration
        }

        /// Allows callers to register filters once the coordinator becomes
        /// available. If the tunnel is already running the closure executes
        /// immediately; otherwise it is deferred until startup completes.
        public func configureFilters(_ builder: @escaping @Sendable (FilterCoordinator) -> Void) {
            if let coordinator = filterCoordinator {
                builder(coordinator)
            } else {
                pendingFilterInstallers.append(builder)
            }
        }

        /// Updates traffic shaping policies on the active adapter without requiring a tunnel restart.
        public func updateTrafficShaping(_ shaping: RelativeProtocol.Configuration.TrafficShaping) {
            if var current = configuration {
                current.provider.policies.trafficShaping = shaping
                configuration = current
            }
            adapter?.updateTrafficShaping(configuration: shaping)
        }

        /// Handles messages received from the host app.
        public func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
            guard !messageData.isEmpty else {
                completionHandler?(nil)
                return
            }
            completionHandler?(Data("ack".utf8))
        }

        // MARK: - Private

        /// Applies IP addressing, MTU, and DNS settings to the virtual interface.
        private func applyNetworkSettings(configuration: RelativeProtocol.Configuration, completion: @escaping (Error?) -> Void) {
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.provider.ipv4.remoteAddress)
            settings.mtu = NSNumber(value: configuration.provider.mtu)

            let ipv4 = configuration.provider.ipv4
            let ipv4Settings = NEIPv4Settings(addresses: [ipv4.address], subnetMasks: [ipv4.subnetMask])
            let routes = ipv4.includedRoutes.isEmpty ? [RelativeProtocol.Configuration.Route.default] : ipv4.includedRoutes
            ipv4Settings.includedRoutes = routes.map { route in
                NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
            }
            if !ipv4.excludedRoutes.isEmpty {
                ipv4Settings.excludedRoutes = ipv4.excludedRoutes.map { route in
                    NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.subnetMask)
                }
            }
            settings.ipv4Settings = ipv4Settings
            if let ipv6 = configuration.provider.ipv6 {
                let prefixLengths = ipv6.networkPrefixLengths.map { NSNumber(value: $0) }
                let ipv6Settings = NEIPv6Settings(addresses: ipv6.addresses, networkPrefixLengths: prefixLengths)
                if !ipv6.includedRoutes.isEmpty {
                    ipv6Settings.includedRoutes = ipv6.includedRoutes.map { route in
                        NEIPv6Route(destinationAddress: route.destinationAddress, networkPrefixLength: NSNumber(value: route.networkPrefixLength))
                    }
                }
                if !ipv6.excludedRoutes.isEmpty {
                    ipv6Settings.excludedRoutes = ipv6.excludedRoutes.map { route in
                        NEIPv6Route(destinationAddress: route.destinationAddress, networkPrefixLength: NSNumber(value: route.networkPrefixLength))
                    }
                }
                settings.ipv6Settings = ipv6Settings
            }

            let dns = configuration.provider.dns
            if !dns.servers.isEmpty {
                let dnsSettings = NEDNSSettings(servers: dns.servers)
                dnsSettings.matchDomains = dns.matchDomains
                dnsSettings.searchDomains = dns.searchDomains
                settings.dnsSettings = dnsSettings
            }

            provider.setTunnelNetworkSettings(settings, completionHandler: completion)
        }

        /// Constructs the engine/adapter pair and starts processing
        /// packets.
        private func bootBridge(configuration: RelativeProtocol.Configuration, metrics: MetricsCollector?) throws {
            let engine: Engine
            #if canImport(Engine)
            engine = BundledEngine(
                configuration: configuration,
                logger: Logger(subsystem: "RelativeProtocolTunnel", category: "BundledEngine")
            )
#else
        engine = NoOpEngine()
#endif

            let adapter = EngineAdapter(
                provider: provider,
                configuration: configuration,
                metrics: metrics,
                engine: engine,
                hooks: configuration.hooks,
                logger: logger
            )
            do {
                try adapter.start()
            } catch {
                throw RelativeProtocol.PackageError.engineStartFailed(error.localizedDescription)
            }
            self.adapter = adapter
            self.trafficAnalyzer = adapter.analyzer
            if let analyzer = self.trafficAnalyzer {
                let coordinator = FilterCoordinator(analyzer: analyzer, configuration: filterConfiguration)
                self.filterCoordinator = coordinator
                let installers = self.pendingFilterInstallers
                self.pendingFilterInstallers.removeAll()
                installers.forEach { $0(coordinator) }
            } else {
                self.filterCoordinator = nil
            }
        }
    }
}
