import Foundation

/// Normalized severity for structured tunnel events.
public enum LogLevel: String, Codable, Sendable {
    case trace
    case debug
    case info
    case notice
    case warning
    case error
    case fault
}

/// Lifecycle phase classification used across all first-party modules.
public enum LogPhase: String, Codable, Sendable, CaseIterable {
    case lifecycle
    case config
    case networkSettings = "network-settings"
    case path
    case relay
    case packetIn = "packet-in"
    case packetOut = "packet-out"
    case dns
    case analytics
    case storage
    case performance
    case harness
}

/// Fixed category vocabulary so downstream tooling can index reliably.
public enum LogCategory: String, Codable, Sendable, CaseIterable {
    case control
    case relayTCP = "relay.tcp"
    case relayUDP = "relay.udp"
    case dataplane
    case liveTap = "live.tap"
    case analyticsClassifier = "analytics.classifier"
}

/// Structured event contract shared by OSLog and JSONL sinks.
public struct LogEnvelope: Codable, Sendable, Equatable {
    public let timestamp: Date
    public let level: LogLevel
    public let phase: LogPhase
    public let component: String
    public let event: String
    public let runId: String?
    public let sessionId: String?
    public let connId: String?
    public let flowId: String?
    public let traceId: String?
    public let result: String?
    public let errorCode: String?
    public let message: String
    public let metadata: [String: String]

    /// Creates one structured log event envelope.
    /// - Parameters:
    ///   - timestamp: Event timestamp.
    ///   - level: Event severity.
    ///   - phase: Runtime phase classification.
    ///   - component: Component or type emitting the event.
    ///   - event: Event name within the component.
    ///   - runId: Optional run identifier.
    ///   - sessionId: Optional session identifier.
    ///   - connId: Optional connection identifier.
    ///   - flowId: Optional flow identifier.
    ///   - traceId: Optional trace identifier.
    ///   - result: Optional result classification.
    ///   - errorCode: Optional machine-readable error code.
    ///   - message: Human-readable event message.
    ///   - metadata: Additional string metadata values.
    public init(
        timestamp: Date = Date(),
        level: LogLevel,
        phase: LogPhase,
        component: String,
        event: String,
        runId: String? = nil,
        sessionId: String? = nil,
        connId: String? = nil,
        flowId: String? = nil,
        traceId: String? = nil,
        result: String? = nil,
        errorCode: String? = nil,
        message: String,
        metadata: [String: String] = [:]
    ) {
        self.timestamp = timestamp
        self.level = level
        self.phase = phase
        self.component = component
        self.event = event
        self.runId = runId
        self.sessionId = sessionId
        self.connId = connId
        self.flowId = flowId
        self.traceId = traceId
        self.result = result
        self.errorCode = errorCode
        self.message = message
        self.metadata = metadata
    }
}

/// Redacts endpoint metadata before serialization to satisfy privacy constraints.
public struct EndpointMetadataRedactor: Sendable {
    private static let explicitHostKeys: Set<String> = [
        "host",
        "hostname",
        "domain",
        "address",
        "remotehost",
        "localhost",
        "sourcehost",
        "destinationhost",
        "remoteaddress",
        "localaddress",
        "sourceaddress",
        "destinationaddress",
        "servername",
        "server",
        "tlsservername",
        "registrabledomain",
        "dnsqueryname",
        "dnscname"
    ]

    private static let explicitPortKeys: Set<String> = [
        "port",
        "remoteport",
        "localport",
        "sourceport",
        "destinationport"
    ]

    public var redactHost: Bool
    public var redactPort: Bool

    /// Creates a metadata redactor with configurable endpoint redaction.
    /// - Parameters:
    ///   - redactHost: Whether common host/domain/address keys should be replaced by `<redacted>`.
    ///   - redactPort: Whether common port keys should be replaced by `<redacted>`.
    public init(redactHost: Bool = true, redactPort: Bool = false) {
        self.redactHost = redactHost
        self.redactPort = redactPort
    }

    /// Redacts configured endpoint keys from metadata.
    /// - Parameter metadata: Input metadata dictionary.
    /// - Returns: Redacted metadata dictionary.
    public func redact(_ metadata: [String: String]) -> [String: String] {
        var redacted = metadata
        for key in redacted.keys {
            if redactHost, Self.isHostKey(key) {
                redacted[key] = "<redacted>"
                continue
            }
            if redactPort, Self.isPortKey(key) {
                redacted[key] = "<redacted>"
            }
        }
        return redacted
    }

    private static func isHostKey(_ key: String) -> Bool {
        let normalized = normalize(key)
        if explicitHostKeys.contains(normalized) {
            return true
        }
        return normalized.hasSuffix("host") ||
            normalized.hasSuffix("hostname") ||
            normalized.hasSuffix("domain") ||
            normalized.hasSuffix("address") ||
            normalized.hasSuffix("servername") ||
            normalized.hasSuffix("queryname") ||
            normalized.hasSuffix("cname")
    }

    private static func isPortKey(_ key: String) -> Bool {
        let normalized = normalize(key)
        if explicitPortKeys.contains(normalized) {
            return true
        }
        return normalized.hasSuffix("port")
    }

    private static func normalize(_ key: String) -> String {
        String(
            key.unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) }
        ).lowercased()
    }
}
