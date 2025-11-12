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
        private var metricsSink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?
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
            logger.notice("Relative Protocol: start requested – includeAll=\(configuration.provider.includeAllNetworks, privacy: .public) mtu=\(configuration.provider.mtu, privacy: .public)")
            do {
                let messages = try configuration.validateOrThrow()
                logger.notice("Relative Protocol: configuration validation completed (\(messages.count, privacy: .public) warnings/errors)")
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
                    sink: metricsSink
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
                    self.logger.notice("Relative Protocol: network settings committed; booting engine bridge")
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
            logger.notice(
                "Relative Protocol: stop requested – reason=\(reason.rawValue, privacy: .public) adapterActive=\(self.adapter != nil, privacy: .public) filters=\(self.filterCoordinator != nil, privacy: .public)"
            )
            adapter?.stop()
            adapter = nil
            metrics = nil
            trafficAnalyzer = nil
            filterCoordinator = nil
            pendingFilterInstallers.removeAll()
            logger.notice("Relative Protocol: stop completed")
            completion()
        }

        /// Updates the filter configuration used when the tunnel boots. Must be
        /// called before `start(configuration:completion:)`.
        public func setFilterConfiguration(_ configuration: FilterConfiguration) {
            guard adapter == nil else { return }
            filterConfiguration = configuration
            logger.debug(
                "Relative Protocol: filter configuration updated – interval=\(configuration.evaluationInterval, privacy: .public)"
            )
        }

        /// Allows callers to register filters once the coordinator becomes
        /// available. If the tunnel is already running the closure executes
        /// immediately; otherwise it is deferred until startup completes.
        public func configureFilters(_ builder: @escaping @Sendable (FilterCoordinator) -> Void) {
            if let coordinator = filterCoordinator {
                logger.notice("Relative Protocol: filter coordinator ready – executing installer immediately")
                builder(coordinator)
            } else {
                logger.notice("Relative Protocol: deferring filter installer until tunnel boots")
                pendingFilterInstallers.append(builder)
            }
        }

        /// Updates traffic shaping policies on the active adapter without requiring a tunnel restart.
        public func updateTrafficShaping(_ shaping: RelativeProtocol.Configuration.TrafficShaping) {
            if var current = configuration {
                current.provider.policies.trafficShaping = shaping
                configuration = current
            }
            logger.notice(
                "Relative Protocol: updating traffic shaping – defaultLatency=\(shaping.defaultPolicy?.fixedLatencyMilliseconds ?? 0, privacy: .public)ms rules=\(shaping.rules.count, privacy: .public)"
            )
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

        /// Allows hosts to observe metrics snapshots for logging or UI.
        public func setMetricsSink(_ sink: (@Sendable (RelativeProtocol.MetricsSnapshot) -> Void)?) {
            metricsSink = sink
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
            logger.notice(
                "Relative Protocol: applying network settings – ipv4=\(ipv4.address, privacy: .public)/\(ipv4.subnetMask, privacy: .public) routes=\(routes.count, privacy: .public) mtu=\(configuration.provider.mtu, privacy: .public)"
            )
            provider.setTunnelNetworkSettings(settings, completionHandler: completion)
        }

        /// Constructs the engine/adapter pair and starts processing
        /// packets.
        private func bootBridge(configuration: RelativeProtocol.Configuration, metrics: MetricsCollector?) throws {
            var runtimeConfiguration = configuration
            let trackerProvider: () -> RelativeProtocolTunnel.ForwardHostTracker? = { [weak self] in
                self?.adapter?.hostTracker
            }

            let engine: Engine
            if let rustEngine = RustEngine.make(
                configuration: configuration,
                logger: Logger(subsystem: "RelativeProtocolTunnel", category: "RustEngine")
            ) {
                logger.notice("Relative Protocol: Rust engine selected for tunnel")
                rustEngine.installTrackerProvider(trackerProvider)
                if let engineResolver = rustEngine.makeDNSResolver(trackerProvider: trackerProvider) {
                    runtimeConfiguration.hooks.dnsResolver = RustDNSResolverAdapter.mergedResolver(
                        hooksResolver: runtimeConfiguration.hooks.dnsResolver,
                        engineResolver: engineResolver,
                        tracker: trackerProvider
                    )
                }
                engine = rustEngine
            } else {
                logger.warning("Relative Protocol: Rust engine unavailable; using bundled engine")
                #if canImport(Engine)
                engine = BundledEngine(
                    configuration: runtimeConfiguration,
                    logger: Logger(subsystem: "RelativeProtocolTunnel", category: "BundledEngine")
                )
                #else
                engine = NoOpEngine()
                #endif
            }

            let adapter = EngineAdapter(
                provider: provider,
                configuration: runtimeConfiguration,
                metrics: metrics,
                engine: engine,
                hooks: runtimeConfiguration.hooks,
                logger: logger
            )
            logger.notice(
                "Relative Protocol: initializing engine adapter – packetPool=\(runtimeConfiguration.provider.memory.packetPoolBytes, privacy: .public) bytes batchLimit=\(runtimeConfiguration.provider.memory.packetBatchLimit, privacy: .public)"
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
                if !installers.isEmpty {
                    logger.notice("Relative Protocol: executing \(installers.count, privacy: .public) pending filter installers")
                }
                installers.forEach { $0(coordinator) }
            } else {
                logger.warning("Relative Protocol: filter coordinator unavailable (packet stream missing)")
                self.filterCoordinator = nil
            }
            self.configuration = runtimeConfiguration
            logger.notice("Relative Protocol: engine adapter started – analyzerPresent=\(self.trafficAnalyzer != nil, privacy: .public)")
        }
    }
}
