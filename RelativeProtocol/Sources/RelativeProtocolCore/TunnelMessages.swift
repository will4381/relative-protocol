import Foundation

public enum TunnelCommandKind: String, Codable, Sendable {
    case dnsHistory
    case installHostRules
    case removeHostRule
    case telemetryDrain
}

public enum TunnelResponseKind: String, Codable, Sendable {
    case dnsHistory
    case hostRuleResults
    case hostRuleRemoval
    case telemetry
}

public struct TunnelCommand: Codable, Sendable {
    public let kind: TunnelCommandKind
    public let dnsRequest: DNSHistoryRequest?
    public let hostRules: [HostRuleConfiguration]?
    public let removalRequest: HostRuleRemovalRequest?
    public let telemetryRequest: TelemetryDrainRequest?

    public init(kind: TunnelCommandKind,
                dnsRequest: DNSHistoryRequest? = nil,
                hostRules: [HostRuleConfiguration]? = nil,
                removalRequest: HostRuleRemovalRequest? = nil,
                telemetryRequest: TelemetryDrainRequest? = nil) {
        self.kind = kind
        self.dnsRequest = dnsRequest
        self.hostRules = hostRules
        self.removalRequest = removalRequest
        self.telemetryRequest = telemetryRequest
    }

    public static func dnsHistory(_ request: DNSHistoryRequest) -> TunnelCommand {
        TunnelCommand(kind: .dnsHistory, dnsRequest: request)
    }

    public static func installHostRules(_ rules: [HostRuleConfiguration]) -> TunnelCommand {
        TunnelCommand(kind: .installHostRules, hostRules: rules)
    }

    public static func removeHostRule(_ request: HostRuleRemovalRequest) -> TunnelCommand {
        TunnelCommand(kind: .removeHostRule, removalRequest: request)
    }

    public static func drainTelemetry(_ request: TelemetryDrainRequest) -> TunnelCommand {
        TunnelCommand(kind: .telemetryDrain, telemetryRequest: request)
    }
}

public struct TunnelResponse: Codable, Sendable {
    public let kind: TunnelResponseKind
    public let dnsResponse: DNSHistoryResponse?
    public let hostRuleResults: [HostRuleInstallResult]?
    public let hostRuleRemoval: HostRuleRemovalResult?
    public let telemetryResponse: TelemetryDrainResponse?

    public init(kind: TunnelResponseKind,
                dnsResponse: DNSHistoryResponse? = nil,
                hostRuleResults: [HostRuleInstallResult]? = nil,
                hostRuleRemoval: HostRuleRemovalResult? = nil,
                telemetryResponse: TelemetryDrainResponse? = nil) {
        self.kind = kind
        self.dnsResponse = dnsResponse
        self.hostRuleResults = hostRuleResults
        self.hostRuleRemoval = hostRuleRemoval
        self.telemetryResponse = telemetryResponse
    }

    public static func dnsHistory(_ response: DNSHistoryResponse) -> TunnelResponse {
        TunnelResponse(kind: .dnsHistory, dnsResponse: response)
    }

    public static func hostRuleResults(_ results: [HostRuleInstallResult]) -> TunnelResponse {
        TunnelResponse(kind: .hostRuleResults, hostRuleResults: results)
    }

    public static func hostRuleRemoval(_ result: HostRuleRemovalResult) -> TunnelResponse {
        TunnelResponse(kind: .hostRuleRemoval, hostRuleRemoval: result)
    }

    public static func telemetry(_ response: TelemetryDrainResponse) -> TunnelResponse {
        TunnelResponse(kind: .telemetry, telemetryResponse: response)
    }
}
