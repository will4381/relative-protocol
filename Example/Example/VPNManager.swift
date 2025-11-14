import Combine
import Foundation
import NetworkExtension
import RelativeProtocolCore
import RelativeProtocolHost

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published private(set) var status: VPNStatus = .disconnected
    @Published private(set) var isBusy = false
    @Published private(set) var configurationReady = false
    @Published private(set) var lastErrorMessage: String?
    @Published private(set) var dnsHistory: [DNSObservation] = []
    @Published private(set) var hostRules: [HostRuleState] = []
    @Published private(set) var telemetryEvents: [TelemetryEvent] = []

    private let controller = RelativeVPNController()
    private let descriptor: TunnelDescriptor
    private var statusObserver: NSObjectProtocol?

    private init() {
        descriptor = TunnelDescriptor(
            localizedDescription: "Relative Protocol",
            providerBundleIdentifier: "relative-companies.Example.Example-Tunnel",
            configuration: .default
        )

        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.updateStatusFromController()
        }

        updateStatusFromController()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func prepare() async {
        guard !configurationReady else { return }
        isBusy = true
        lastErrorMessage = nil
        do {
            try await controller.prepareIfNeeded(descriptor: descriptor)
            configurationReady = true
        } catch {
            lastErrorMessage = "Prepare failed: \(error.localizedDescription)"
        }
        isBusy = false
        updateStatusFromController()
    }

    func connect() async {
        guard configurationReady else {
            lastErrorMessage = "Call prepare() before connecting"
            return
        }
        isBusy = true
        lastErrorMessage = nil
        do {
            try await controller.connect()
        } catch {
            lastErrorMessage = error.localizedDescription
        }
        isBusy = false
        updateStatusFromController()
    }

    func disconnect() async {
        controller.disconnect()
        dnsHistory = []
        hostRules = []
        telemetryEvents = []
        updateStatusFromController()
    }

    func refreshDnsHistory(limit: Int = 100) async {
        guard status.isActive else { return }
        do {
            let records = try await controller.fetchDnsHistory(limit: limit)
            dnsHistory = records
        } catch {
            lastErrorMessage = "DNS fetch failed: \(error.localizedDescription)"
        }
    }

    func installHostRule(pattern: String, action: HostRuleConfiguration.Action) async {
        guard status.isActive else {
            lastErrorMessage = "Connect before installing host rules"
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let configuration = HostRuleConfiguration(pattern: pattern, action: action)
            let result = try await controller.installHostRule(configuration)
            if let ruleID = result.ruleID {
                let state = HostRuleState(requestID: result.requestID,
                                          ruleID: ruleID,
                                          pattern: result.pattern,
                                          action: result.action)
                hostRules.append(state)
            } else {
                lastErrorMessage = result.errorMessage ?? "Failed to install host rule"
            }
        } catch {
            lastErrorMessage = "Host rule failed: \(error.localizedDescription)"
        }
    }

    func removeHostRule(_ rule: HostRuleState) async {
        guard status.isActive else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await controller.removeHostRule(ruleID: rule.ruleID)
            if result.removed {
                hostRules.removeAll { $0.ruleID == rule.ruleID }
            } else {
                lastErrorMessage = "Rule \(rule.pattern) could not be removed"
            }
        } catch {
            lastErrorMessage = "Remove failed: \(error.localizedDescription)"
        }
    }

    func drainTelemetry(maxEvents: Int = 128) async {
        guard status.isActive else { return }
        do {
            let response = try await controller.drainTelemetry(maxEvents: maxEvents)
            telemetryEvents.append(contentsOf: response.events)
            let maxStored = 512
            if telemetryEvents.count > maxStored {
                telemetryEvents.removeFirst(telemetryEvents.count - maxStored)
            }
            if response.droppedEvents > 0 {
                lastErrorMessage = "Telemetry dropped \(response.droppedEvents) events – consider draining more often."
            }
        } catch {
            lastErrorMessage = "Telemetry drain failed: \(error.localizedDescription)"
        }
    }

    private func updateStatusFromController() {
        status = VPNStatus(controller.connectionStatus)
    }
}

struct HostRuleState: Identifiable, Equatable {
    let id = UUID()
    let requestID: UUID
    let ruleID: UInt64
    let pattern: String
    let action: HostRuleConfiguration.Action
}

enum VPNStatus {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case invalid

    init(_ status: NEVPNStatus) {
        switch status {
        case .connected: self = .connected
        case .connecting, .reasserting: self = .connecting
        case .disconnecting: self = .disconnecting
        case .disconnected: self = .disconnected
        default: self = .invalid
        }
    }

    var isActive: Bool {
        if case .connected = self { return true }
        return false
    }

    var displayTitle: String {
        switch self {
        case .connected: return "Connected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .disconnected: return "Disconnected"
        case .invalid: return "Unavailable"
        }
    }
}
