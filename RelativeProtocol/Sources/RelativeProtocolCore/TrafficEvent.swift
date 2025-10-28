//
//  TrafficEvent.swift
//  RelativeProtocolCore
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 11/07/2025.
//
//  Defines the public traffic event model used by filters and host consumers.
//

import Foundation

public extension RelativeProtocol {
    /// Confidence level assigned to generated traffic events.
    enum TrafficConfidence: String, Codable, Sendable {
        case low
        case medium
        case high
    }

    /// Classification for traffic-derived events. Applications may extend the
    /// vocabulary by storing additional information in `details`.
    enum TrafficCategory: String, Codable, Sendable {
        case observation
        case burst
        case policy
        case custom
    }

    /// General-purpose event surfaced by the tunnel to interested observers.
    struct TrafficEvent: Codable, Sendable, Identifiable {
        public var id: UUID
        public var timestamp: Date
        public var category: TrafficCategory
        public var confidence: TrafficConfidence
        public var details: [String: String]

        public init(
            id: UUID = UUID(),
            timestamp: Date = Date(),
            category: TrafficCategory,
            confidence: TrafficConfidence = .medium,
            details: [String: String] = [:]
        ) {
            self.id = id
            self.timestamp = timestamp
            self.category = category
            self.confidence = confidence
            self.details = details
        }
    }

    /// Sanitizes sensitive payloads before events leave the extension.
    struct TrafficRedactor: Sendable {
        public var shouldStripPayloads: Bool
        public var shouldRedactHosts: Bool
        public var redactionToken: String
        public var allowList: Set<String>

        public init(
            shouldStripPayloads: Bool = true,
            shouldRedactHosts: Bool = false,
            redactionToken: String = "redacted",
            allowList: Set<String> = []
        ) {
            self.shouldStripPayloads = shouldStripPayloads
            self.shouldRedactHosts = shouldRedactHosts
            self.redactionToken = redactionToken
            self.allowList = allowList
        }

        /// Returns a copy of the provided event with allowed keys left intact.
        public func sanitize(event: TrafficEvent) -> TrafficEvent {
            guard shouldRedactHosts || shouldStripPayloads else { return event }
            var details = event.details
            if shouldStripPayloads {
                details.removeValue(forKey: "payload")
            }
            if shouldRedactHosts {
                for (key, value) in details {
                    guard key.lowercased().contains("host") || key.lowercased().contains("domain") else { continue }
                    if allowList.contains(value) { continue }
                    details[key] = redactionToken
                }
            }
            return TrafficEvent(
                id: event.id,
                timestamp: event.timestamp,
                category: event.category,
                confidence: event.confidence,
                details: details
            )
        }
    }
}
