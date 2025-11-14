import Foundation

public struct TelemetryDrainRequest: Codable, Sendable {
    public let maxEvents: Int

    public init(maxEvents: Int) {
        self.maxEvents = max(1, maxEvents)
    }
}

public struct TelemetryDrainResponse: Codable, Sendable {
    public let events: [TelemetryEvent]
    public let droppedEvents: UInt64

    public init(events: [TelemetryEvent], droppedEvents: UInt64) {
        self.events = events
        self.droppedEvents = droppedEvents
    }
}

public struct TelemetryEvent: Codable, Identifiable, Sendable {
    public enum Direction: String, Codable, Sendable {
        case clientToNetwork
        case networkToClient
    }

    public struct Flags: OptionSet, Codable, Sendable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }

        public static let dns = Flags(rawValue: 0x01)
        public static let dnsResponse = Flags(rawValue: 0x02)
        public static let policyBlock = Flags(rawValue: 0x04)
        public static let policyShape = Flags(rawValue: 0x08)
    }

    public let id: UUID
    public let timestamp: Date
    public let protocolNumber: UInt8
    public let direction: Direction
    public let payloadLength: UInt32
    public let source: String
    public let destination: String
    public let dnsQuery: String?
    public let flags: Flags

    public init(
        id: UUID = UUID(),
        timestamp: Date,
        protocolNumber: UInt8,
        direction: Direction,
        payloadLength: UInt32,
        source: String,
        destination: String,
        dnsQuery: String?,
        flags: Flags
    ) {
        self.id = id
        self.timestamp = timestamp
        self.protocolNumber = protocolNumber
        self.direction = direction
        self.payloadLength = payloadLength
        self.source = source
        self.destination = destination
        self.dnsQuery = dnsQuery
        self.flags = flags
    }
}
