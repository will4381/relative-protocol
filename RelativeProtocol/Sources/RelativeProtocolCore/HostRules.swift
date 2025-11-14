import Foundation

public struct HostRuleConfiguration: Codable, Equatable, Identifiable, Sendable {
    public enum Action: Codable, Equatable, Sendable {
        case block
        case shape(latencyMs: UInt32, jitterMs: UInt32)
    }

    public let id: UUID
    public var pattern: String
    public var action: Action

    public init(id: UUID = UUID(), pattern: String, action: Action) {
        self.id = id
        self.pattern = pattern
        self.action = action
    }
}

public struct HostRuleInstallResult: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID { requestID }
    public let requestID: UUID
    public let pattern: String
    public let action: HostRuleConfiguration.Action
    public let ruleID: UInt64?
    public let errorMessage: String?

    public init(requestID: UUID,
                pattern: String,
                action: HostRuleConfiguration.Action,
                ruleID: UInt64?,
                errorMessage: String? = nil) {
        self.requestID = requestID
        self.pattern = pattern
        self.action = action
        self.ruleID = ruleID
        self.errorMessage = errorMessage
    }

    public var succeeded: Bool {
        ruleID != nil && errorMessage == nil
    }
}

public struct HostRuleRemovalRequest: Codable, Sendable {
    public let ruleID: UInt64

    public init(ruleID: UInt64) {
        self.ruleID = ruleID
    }
}

public struct HostRuleRemovalResult: Codable, Sendable {
    public let ruleID: UInt64
    public let removed: Bool

    public init(ruleID: UInt64, removed: Bool) {
        self.ruleID = ruleID
        self.removed = removed
    }
}
