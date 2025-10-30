//
//  VPNManager.swift
//  Example
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/27/2025.
//
//  Coordinates host-side tunnel control by mirroring `RelativeProtocolHost.Controller`
//  publishers into app state and exposing helper probes for diagnostics.
//

import Foundation
import Combine
import OSLog
@preconcurrency import NetworkExtension
import RelativeProtocolCore
import RelativeProtocolHost

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var isBusy = false
    @Published private(set) var configurationReady = false
    @Published private(set) var lastErrorMessage: String?
    @Published private(set) var lastProbeResult: String?
    @Published private(set) var lastHTTPProbeResult: String?
    @Published private(set) var siteSummaries: [ExampleSiteSummary] = []
    @Published private(set) var totalObservedSites: Int = 0
    @Published private(set) var lastControlError: String?
    @Published private(set) var isFetchingSites = false
    @Published private(set) var shapingConfiguration = TrafficShapingConfiguration()

    private let controller = RelativeProtocolHost.Controller()
    private var cancellables: Set<AnyCancellable> = []
    private let logger = Logger(subsystem: "relative.example", category: "VPNManager")
    private var pendingApplyTask: Task<Void, Never>?

    deinit {
        pendingApplyTask?.cancel()
    }

    private init() {
        controller.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] value in self?.status = value }
            .store(in: &cancellables)

        controller.$isBusy
            .receive(on: DispatchQueue.main)
            .sink { [weak self] value in self?.isBusy = value }
            .store(in: &cancellables)

        controller.$isConfigured
            .receive(on: DispatchQueue.main)
            .sink { [weak self] value in
                guard let self else { return }
                self.configurationReady = value
                if value {
                    self.scheduleShapingApply()
                }
            }
            .store(in: &cancellables)

        controller.$lastError
            .receive(on: DispatchQueue.main)
            .sink { [weak self] message in
                self?.lastErrorMessage = message
            }
            .store(in: &cancellables)
    }

    func prepare() async {
        guard !configurationReady else { return }
        let descriptor = makeDescriptor()

        do {
            try await controller.prepareIfNeeded(descriptor: descriptor)
            lastErrorMessage = controller.lastError
            scheduleShapingApply()
        } catch {
            lastErrorMessage = error.localizedDescription
            logger.error("prepare failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    func connect() async {
        do {
            // Ensure configuration is up to date before connecting.
            try await controller.configure(descriptor: makeDescriptor())
            try await controller.connect()
            lastErrorMessage = controller.lastError
        } catch {
            lastErrorMessage = error.localizedDescription
        }
    }

    func disconnect() {
        controller.disconnect()
    }

    func probe() async {
        lastProbeResult = "Running…"
        let result = await RelativeProtocolHost.Probe.tcp(host: "1.1.1.1", port: 443)
        if let latency = result.duration {
            lastProbeResult = "\(result.message) (\(Int(latency * 1000)) ms)"
        } else {
            lastProbeResult = result.message
        }
    }

    func probeHTTP() async {
        guard let url = URL(string: "https://www.apple.com/library/test/success.html") else {
            lastHTTPProbeResult = "error: invalid URL"
            return
        }
        lastHTTPProbeResult = "Running…"
        let result = await RelativeProtocolHost.Probe.https(url: url)
        if let latency = result.duration {
            lastHTTPProbeResult = "\(result.message) (\(Int(latency * 1000)) ms)"
        } else {
            lastHTTPProbeResult = result.message
        }
    }

    func fetchSites(limit: Int = 50) async {
        guard status == .connected else {
            lastControlError = "VPN not connected"
            return
        }
        guard configurationReady else { return }
        isFetchingSites = true
        defer { isFetchingSites = false }

        do {
            let response: ExampleSitesResponse = try await controller.controlChannel.send(
                ExampleAppCommand(command: "events", value: nil, limit: limit),
                expecting: ExampleSitesResponse.self
            )
            siteSummaries = response.sites.sorted { $0.lastSeen > $1.lastSeen }
            totalObservedSites = response.total
            lastControlError = nil
            logger.notice("fetchSites succeeded with \(response.sites.count, privacy: .public) entries")
        } catch let error as RelativeProtocolHost.ControlChannel.Error {
            lastControlError = describe(controlError: error)
        } catch {
            lastControlError = error.localizedDescription
        }
    }

    func setDefaultLatency(_ value: Double) {
        let clamped = max(0, min(500, value))
        var config = shapingConfiguration
        guard config.defaultLatencyMs != clamped else { return }
        config.defaultLatencyMs = clamped
        shapingConfiguration = config
        scheduleShapingApply()
    }

    func setDefaultBandwidth(_ value: Double) {
        let clamped = max(0, min(4096, value))
        var config = shapingConfiguration
        guard config.defaultBandwidthKbps != clamped else { return }
        config.defaultBandwidthKbps = clamped
        shapingConfiguration = config
        scheduleShapingApply()
    }

    func addRule(pattern: String) {
        let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var config = shapingConfiguration
        if config.rules.contains(where: { $0.pattern.caseInsensitiveCompare(trimmed) == .orderedSame }) {
            return
        }
        config.rules.append(.init(pattern: trimmed))
        shapingConfiguration = config
        scheduleShapingApply()
    }

    func setRulePattern(_ pattern: String, for id: UUID) {
        let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        var config = shapingConfiguration
        guard let index = config.rules.firstIndex(where: { $0.id == id }) else { return }
        if config.rules[index].pattern == trimmed { return }
        config.rules[index].pattern = trimmed
        shapingConfiguration = config
        scheduleShapingApply()
    }

    func setRuleLatency(_ value: Double, for id: UUID) {
        var config = shapingConfiguration
        guard let index = config.rules.firstIndex(where: { $0.id == id }) else { return }
        let clamped = max(0, min(500, value))
        if config.rules[index].latencyMs == clamped { return }
        config.rules[index].latencyMs = clamped
        shapingConfiguration = config
        scheduleShapingApply()
    }

    func setRuleBandwidth(_ value: Double, for id: UUID) {
        var config = shapingConfiguration
        guard let index = config.rules.firstIndex(where: { $0.id == id }) else { return }
        let clamped = max(0, min(4096, value))
        if config.rules[index].bandwidthKbps == clamped { return }
        config.rules[index].bandwidthKbps = clamped
        shapingConfiguration = config
        scheduleShapingApply()
    }

    func removeRule(id: UUID) {
        var config = shapingConfiguration
        guard let index = config.rules.firstIndex(where: { $0.id == id }) else { return }
        config.rules.remove(at: index)
        shapingConfiguration = config
        scheduleShapingApply()
    }

    func clearSites() async {
        guard status == .connected else {
            lastControlError = "VPN not connected"
            return
        }
        do {
            let response: ExampleAckResponse = try await controller.controlChannel.send(
                ExampleAppCommand(command: "clearEvents", value: nil, limit: nil),
                expecting: ExampleAckResponse.self
            )
            totalObservedSites = response.total
            siteSummaries = []
            lastControlError = nil
        } catch let error as RelativeProtocolHost.ControlChannel.Error {
            lastControlError = describe(controlError: error)
        } catch {
            lastControlError = error.localizedDescription
        }
    }

    private func describe(controlError: RelativeProtocolHost.ControlChannel.Error) -> String {
        switch controlError {
        case .tunnelUnavailable:
            return "tunnel unavailable"
        case .tunnelNotConnected:
            return "VPN not connected"
        case .sessionUnavailable:
            return "control session unavailable"
        case .noResponse:
            return "no response from tunnel"
        case .encodingFailed(let error):
            return "encode failed: \(error.localizedDescription)"
        case .decodingFailed(let error):
            return "decode failed: \(error.localizedDescription)"
        }
    }

    private func makeDescriptor() -> RelativeProtocolHost.TunnelDescriptor {
        let configuration = makeConfiguration()
        return RelativeProtocolHost.TunnelDescriptor(
            providerBundleIdentifier: "relative-companies.Example.Example-Tunnel",
            localizedDescription: "Relative Protocol Example",
            configuration: configuration,
            includeAllNetworks: false,
            excludeLocalNetworks: false,
            excludeAPNs: true,
            validateConfiguration: true
        )
    }

    private func makeConfiguration() -> RelativeProtocol.Configuration {
        let interface = RelativeProtocol.Configuration.Interface(
            address: "10.0.0.2",
            subnetMask: "255.255.255.0",
            remoteAddress: "10.0.0.1"
        )

        let appleIPv6Exclusions: [RelativeProtocol.Configuration.IPv6Route] = [
            .destination("2403:300::", prefixLength: 32),
            .destination("2620:149::", prefixLength: 32)
        ]

        let ipv6 = RelativeProtocol.Configuration.IPv6(
            addresses: ["fd00:1::2"],
            networkPrefixLengths: [64],
            excludedRoutes: appleIPv6Exclusions
        )

        return RelativeProtocol.Configuration.fullTunnel(
            interface: interface,
            dnsServers: ["1.1.1.1"],
            includeAllNetworks: false,
            excludeLocalNetworks: false,
            excludedIPv4Routes: [
                .destination("17.0.0.0", subnetMask: "255.0.0.0")
            ],
            ipv6: ipv6,
            metrics: .init(isEnabled: false),
            policies: .init(
                blockedHosts: [],
                trafficShaping: shapingConfiguration.toRelativeConfiguration()
            ),
            memory: .init(
                packetPoolBytes: 4 * 1_048_576,
                perFlowBytes: 64 * 1_024,
                packetBatchLimit: 4,
                maxConcurrentNetworkSends: 64
            ),
            logging: .init(enableDebug: false)
        )
    }

    private func scheduleShapingApply() {
        pendingApplyTask?.cancel()
        guard configurationReady else { return }
        pendingApplyTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard let self, !Task.isCancelled else { return }
            await self.applyShapingConfiguration()
        }
    }

    private func applyShapingConfiguration() async {
        do {
            try await controller.configure(descriptor: makeDescriptor())
            lastErrorMessage = controller.lastError
            if status == .connected {
                do {
                    let command = ExampleShapingUpdateCommand(
                        shaping: shapingConfiguration.toExamplePayload()
                    )
                    let _: ExampleAckResponse = try await controller.controlChannel.send(
                        command,
                        expecting: ExampleAckResponse.self
                    )
                } catch {
                    lastErrorMessage = error.localizedDescription
                }
            }
        } catch {
            lastErrorMessage = error.localizedDescription
        }
    }
}

extension VPNManager {
    struct TrafficShapingConfiguration: Equatable {
        var defaultLatencyMs: Double
        var defaultBandwidthKbps: Double
        var rules: [TrafficShapingRuleConfig]

        init(
            defaultLatencyMs: Double = 0,
            defaultBandwidthKbps: Double = 0,
            rules: [TrafficShapingRuleConfig] = []
        ) {
            self.defaultLatencyMs = defaultLatencyMs
            self.defaultBandwidthKbps = defaultBandwidthKbps
            self.rules = rules
        }

        fileprivate func toRelativeConfiguration() -> RelativeProtocol.Configuration.TrafficShaping {
            let defaultPolicy = Self.makePolicy(latencyMs: defaultLatencyMs, bandwidthKbps: defaultBandwidthKbps)
            let compiledRules: [RelativeProtocol.Configuration.TrafficShapingRule] = rules.compactMap { rule in
                let trimmed = rule.pattern.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else { return nil }
                guard let policy = Self.makePolicy(latencyMs: rule.latencyMs, bandwidthKbps: rule.bandwidthKbps) else {
                    return nil
                }
                let tokens = trimmed.split(whereSeparator: { $0 == "," || $0 == " " }).map {
                    String($0).trimmingCharacters(in: .whitespacesAndNewlines)
                }.filter { !$0.isEmpty }
                var seen: Set<String> = []
                let normalized = tokens.compactMap { token -> String? in
                    let lowercased = token.lowercased()
                    guard !lowercased.isEmpty, seen.insert(lowercased).inserted else { return nil }
                    return token
                }.ifEmptyReplace(with: [trimmed])
                return .init(
                    hosts: normalized,
                    ports: [],
                    policy: policy
                )
            }
            return .init(
                defaultPolicy: defaultPolicy,
                rules: compiledRules
            )
        }

        fileprivate func toExamplePayload() -> ExampleTrafficShapingPayload {
            ExampleTrafficShapingPayload(
                defaultLatencyMs: defaultLatencyMs,
                defaultBandwidthKbps: defaultBandwidthKbps,
                rules: rules.map { rule in
                    ExampleTrafficShapingRulePayload(
                        pattern: rule.pattern,
                        latencyMs: rule.latencyMs,
                        bandwidthKbps: rule.bandwidthKbps
                    )
                }
            )
        }

        private static func makePolicy(latencyMs: Double, bandwidthKbps: Double) -> RelativeProtocol.Configuration.TrafficShapingPolicy? {
            let latency = max(0, Int(latencyMs.rounded()))
            let bytesPerSecond = bandwidthKbps > 0 ? max(256, Int(((bandwidthKbps * 1000.0) / 8.0).rounded())) : nil
            guard latency > 0 || bytesPerSecond != nil else { return nil }
            let jitter = latency > 0 ? max(10, min(250, Int((latencyMs * 0.25).rounded()))) : 0
            return .init(
                fixedLatencyMilliseconds: latency,
                jitterMilliseconds: jitter,
                bytesPerSecond: bytesPerSecond
            )
        }
    }

    struct TrafficShapingRuleConfig: Identifiable, Equatable {
        var id: UUID
        var pattern: String
        var latencyMs: Double
        var bandwidthKbps: Double

        init(
            id: UUID = UUID(),
            pattern: String,
            latencyMs: Double = 200,
            bandwidthKbps: Double = 256
        ) {
            self.id = id
            self.pattern = pattern
            self.latencyMs = max(0, latencyMs)
            self.bandwidthKbps = max(0, bandwidthKbps)
        }
    }
}

private extension Array where Element == String {
    func ifEmptyReplace(with fallback: [String]) -> [String] {
        isEmpty ? fallback : self
    }
}

private struct ExampleShapingUpdateCommand: Encodable {
    var command = "setShaping"
    var shaping: ExampleTrafficShapingPayload
}

private struct ExampleTrafficShapingPayload: Encodable {
    var defaultLatencyMs: Double
    var defaultBandwidthKbps: Double
    var rules: [ExampleTrafficShapingRulePayload]
}

private struct ExampleTrafficShapingRulePayload: Encodable {
    var pattern: String
    var latencyMs: Double
    var bandwidthKbps: Double
}

private struct ExampleAppCommand: Encodable {
    var command: String
    var value: Int?
    var limit: Int?
}

struct ExampleSiteSummary: Codable, Identifiable {
    var remoteIP: String
    var host: String?
    var site: String?
    var firstSeen: Date
    var lastSeen: Date
    var inboundBytes: Int
    var outboundBytes: Int
    var inboundPackets: Int
    var outboundPackets: Int

    var id: String { site ?? host ?? remoteIP }
    var displayName: String { site ?? host ?? remoteIP }
    var totalBytes: Int { inboundBytes + outboundBytes }
}

private struct ExampleSitesResponse: Decodable {
    var sites: [ExampleSiteSummary]
    var total: Int
}

private struct ExampleAckResponse: Decodable {
    var command: String
    var total: Int
}

private struct ExampleErrorResponse: Decodable {
    var command: String
    var error: String
}

extension NEVPNStatus {
    var isActive: Bool {
        switch self { case .connected, .connecting, .reasserting: return true; default: return false }
    }
    var displayTitle: String {
        switch self {
        case .invalid: return "Not Configured"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        @unknown default: return "Unknown"
        }
    }
}
