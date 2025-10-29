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

    private let controller = RelativeProtocolHost.Controller()
    private var cancellables: Set<AnyCancellable> = []
    private let logger = Logger(subsystem: "relative.example", category: "VPNManager")

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
            .sink { [weak self] value in self?.configurationReady = value }
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
            policies: .init(blockedHosts: []),
            logging: .init(enableDebug: false)
        )
    }
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
