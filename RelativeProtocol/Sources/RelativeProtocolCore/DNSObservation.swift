import Foundation

public struct DNSObservation: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let host: String
    public let addresses: [String]
    public let ttlSeconds: UInt32
    public let observedAt: Date

    public init(
        id: UUID = UUID(),
        host: String,
        addresses: [String],
        ttlSeconds: UInt32,
        observedAt: Date = Date()
    ) {
        self.id = id
        self.host = host
        self.addresses = addresses
        self.ttlSeconds = ttlSeconds
        self.observedAt = observedAt
    }
}

public struct DNSHistoryRequest: Codable, Sendable {
    public let limit: Int

    public init(limit: Int) {
        self.limit = limit
    }
}

public struct DNSHistoryResponse: Codable, Sendable {
    public let observations: [DNSObservation]

    public init(observations: [DNSObservation]) {
        self.observations = observations
    }
}

public enum DNSAppMessageKind: String, Codable, Sendable {
    case historyRequest
    case historyResponse
    case streamRequest
    case streamResponse
}

public struct DNSAppMessage: Codable, Sendable {
    public let kind: DNSAppMessageKind
    public let historyRequest: DNSHistoryRequest?
    public let historyResponse: DNSHistoryResponse?
    public let observation: DNSObservation?

    public init(kind: DNSAppMessageKind,
                historyRequest: DNSHistoryRequest? = nil,
                historyResponse: DNSHistoryResponse? = nil,
                observation: DNSObservation? = nil) {
        self.kind = kind
        self.historyRequest = historyRequest
        self.historyResponse = historyResponse
        self.observation = observation
    }

    public static func historyRequest(_ request: DNSHistoryRequest) -> DNSAppMessage {
        DNSAppMessage(kind: .historyRequest, historyRequest: request)
    }

    public static func historyResponse(_ response: DNSHistoryResponse) -> DNSAppMessage {
        DNSAppMessage(kind: .historyResponse, historyResponse: response)
    }

    public static var streamRequest: DNSAppMessage {
        DNSAppMessage(kind: .streamRequest)
    }

    public static func streamResponse(_ observation: DNSObservation?) -> DNSAppMessage {
        DNSAppMessage(kind: .streamResponse, observation: observation)
    }
}
