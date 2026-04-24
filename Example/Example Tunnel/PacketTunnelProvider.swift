// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Analytics
import Foundation
import Observability
import TunnelControl

/// Example tunnel entrypoint that forwards all provider behavior to the shared packet tunnel shell.
final class PacketTunnelProvider: PacketTunnelProviderShell, @unchecked Sendable {
    override func makeDetectors(
        profile: TunnelProfile,
        analyticsRootURL: URL,
        logger: StructuredLogger
    ) async throws -> [any TrafficDetector] {
        _ = profile
        _ = analyticsRootURL
        _ = logger
        return [ExampleCDNDomainDetector()]
    }
}

/// Minimal custom detector used by the Example app.
/// It emits one durable detection per new flow whose metadata resolves to a known TikTok or Instagram CDN domain.
private final class ExampleCDNDomainDetector: TrafficDetector {
    private enum Policy {
        static let flowTTLSeconds: TimeInterval = 120
        static let maxTrackedFlows = 512
        static let evictionSweepIntervalSeconds: TimeInterval = 15
    }

    /// Source used to attribute how the detector learned about a CDN host.
    /// Decision: the Example detector should demonstrate confidence scoring across multiple corroborating hints
    /// instead of collapsing everything to one fixed score.
    private enum HostEvidence: String {
        case tlsServerName = "tls-server-name"
        case registrableDomain = "registrable-domain"
        case dnsCname = "dns-cname"
        case dnsQueryName = "dns-query-name"
    }

    private enum Surface: String {
        case tiktok
        case instagramReels = "instagram-reels"
    }

    private struct EvidenceMatch {
        let host: String
        let source: HostEvidence
        let target: String
    }

    let identifier = "example-cdn-domain"

    /// The Example app opts into the richer detector/debug surface so the foreground live tap can expose
    /// association, lineage, regime, and attribution fields for inspection.
    var requirements: DetectorRequirements {
        DetectorRequirements(
            recordKinds: Set(PacketSampleKind.allCases),
            featureFamilies: [
                .packetShape,
                .controlSignals,
                .burstShape,
                .hostHints,
                .quicIdentity,
                .dnsAnswerAddresses,
                .dnsAssociation,
                .lineage,
                .pathRegime,
                .serviceAttribution
            ],
            preferredFlowSliceIntervalMs: 250
        )
    }

    private var seenFlows: [String: Date] = [:]
    private var lastEvictionAt: Date?

    func ingest(_ records: DetectorRecordCollection) -> [DetectionEvent] {
        guard !records.isEmpty else {
            return []
        }

        var events: [DetectionEvent] = []
        events.reserveCapacity(2)

        for record in records where record.kind == .metadata || record.kind == .flowOpen {
            let flowID = Self.flowIdentifier(for: record)
            maybeEvictExpiredFlows(now: record.timestamp)
            guard seenFlows[flowID] == nil else {
                continue
            }

            let evidenceMatches = Self.matchingEvidence(for: record)
            guard let primaryEvidence = evidenceMatches.first else {
                continue
            }

            seenFlows[flowID] = record.timestamp
            let confidence = Self.confidence(for: record, evidenceMatches: evidenceMatches)
            events.append(
                DetectionEvent(
                    id: "\(identifier)-\(primaryEvidence.target)-\(Int(record.timestamp.timeIntervalSince1970 * 1000))",
                    detectorIdentifier: identifier,
                    signal: "cdn-domain-match",
                    target: primaryEvidence.target,
                    timestamp: record.timestamp,
                    confidence: confidence,
                    trigger: record.kind.rawValue,
                    flowId: flowID,
                    host: primaryEvidence.host,
                    classification: record.classification,
                    bytes: record.bytes,
                    packetCount: record.packetCount,
                    durationMs: record.burstDurationMs,
                    metadata: [
                        "host": primaryEvidence.host,
                        "host_source": primaryEvidence.source.rawValue,
                        "matched_sources": evidenceMatches.map(\.source.rawValue).joined(separator: ","),
                        "matched_source_count": String(evidenceMatches.count)
                    ]
                )
            )
        }

        return events
    }

    func reset() {
        seenFlows.removeAll(keepingCapacity: false)
        lastEvictionAt = nil
    }

    private func maybeEvictExpiredFlows(now: Date) {
        if let lastEvictionAt,
           now.timeIntervalSince(lastEvictionAt) < Policy.evictionSweepIntervalSeconds,
           seenFlows.count < Policy.maxTrackedFlows {
            return
        }

        lastEvictionAt = now
        seenFlows = seenFlows.filter { now.timeIntervalSince($0.value) <= Policy.flowTTLSeconds }
        if seenFlows.count <= Policy.maxTrackedFlows {
            return
        }

        let survivors = seenFlows
            .sorted { $0.value > $1.value }
            .prefix(Policy.maxTrackedFlows)
            .map { ($0.key, $0.value) }
        seenFlows = Dictionary(uniqueKeysWithValues: survivors)
    }

    private static func target(for host: String) -> String? {
        switch surface(forHost: host, classification: nil) {
        case .tiktok:
            return "tiktok-cdn"
        case .instagramReels:
            return "instagram-cdn"
        case nil:
            return nil
        }
    }

    private static func matchingEvidence(for record: DetectorRecord) -> [EvidenceMatch] {
        var matches: [EvidenceMatch] = []

        let candidates: [(String?, HostEvidence)] = [
            (record.tlsServerName, .tlsServerName),
            (record.registrableDomain, .registrableDomain),
            (record.dnsCname, .dnsCname),
            (record.dnsQueryName, .dnsQueryName)
        ]

        for (rawHost, source) in candidates {
            guard let host = nonEmpty(rawHost),
                  let target = target(for: host) else {
                continue
            }
            matches.append(EvidenceMatch(host: host, source: source, target: target))
        }

        return matches
    }

    private static func confidence(for record: DetectorRecord, evidenceMatches: [EvidenceMatch]) -> Double {
        guard let primaryEvidence = evidenceMatches.first else {
            return 0.5
        }

        var value: Double
        switch primaryEvidence.source {
        case .tlsServerName:
            value = 0.74
        case .registrableDomain:
            value = 0.66
        case .dnsCname:
            value = 0.6
        case .dnsQueryName:
            value = 0.54
        }

        if evidenceMatches.count >= 2 {
            value += 0.08
        }
        if evidenceMatches.count >= 3 {
            value += 0.05
        }
        if evidenceMatches.count >= 4 {
            value += 0.03
        }

        if let surface = surface(forHost: primaryEvidence.host, classification: record.classification) {
            value += hostSpecificityBoost(forHost: primaryEvidence.host, surface: surface)
            value += classificationConfidenceBoost(for: surface, classification: record.classification)
        }
        if record.kind == .metadata {
            value += 0.02
        }
        if record.destinationPort == 443 {
            value += 0.02
        }
        if record.bytes >= 64 * 1024 {
            value += 0.02
        } else if record.bytes >= 16 * 1024 {
            value += 0.01
        }
        if (record.packetCount ?? 0) >= 6 {
            value += 0.01
        }

        return min(value, 0.97)
    }

    private static func surface(forHost host: String?, classification: String?) -> Surface? {
        let host = host?.lowercased() ?? ""
        let classification = classification?.lowercased() ?? ""

        if matchesTikTok(host: host) || classification.contains("tiktok") {
            return .tiktok
        }
        if matchesInstagram(host: host) || classification.contains("instagram") || classification.contains("reels") {
            return .instagramReels
        }
        return nil
    }

    private static func matchesTikTok(host: String) -> Bool {
        let fragments = [
            "tiktok",
            "musical.ly",
            "byteoversea",
            "ibytedtos",
            "ibyteimg",
            "snssdk",
            "bytecdn"
        ]
        return fragments.contains(where: host.contains)
    }

    private static func matchesInstagram(host: String) -> Bool {
        let fragments = [
            "instagram",
            "cdninstagram",
            "fbcdn",
            "fbsbx"
        ]
        return fragments.contains(where: host.contains)
    }

    private static func hostSpecificityBoost(forHost host: String, surface: Surface) -> Double {
        let host = host.lowercased()
        let strongFragments: [String]
        let mediumFragments: [String]

        switch surface {
        case .tiktok:
            strongFragments = ["tiktokcdn", "bytecdn", "ibytedtos", "ibyteimg"]
            mediumFragments = ["tiktokv", "musical.ly"]
        case .instagramReels:
            strongFragments = ["cdninstagram", "fbcdn"]
            mediumFragments = ["fbsbx"]
        }

        if strongFragments.contains(where: host.contains) {
            return 0.07
        }
        if mediumFragments.contains(where: host.contains) {
            return 0.04
        }
        return 0.01
    }

    private static func classificationConfidenceBoost(for surface: Surface, classification: String?) -> Double {
        let classification = classification?.lowercased() ?? ""
        switch surface {
        case .tiktok:
            return classification.contains("tiktok") ? 0.04 : 0
        case .instagramReels:
            return (classification.contains("instagram") || classification.contains("reels")) ? 0.04 : 0
        }
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value else {
            return nil
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func flowIdentifier(for record: DetectorRecord) -> String {
        if let flowHash = record.flowHash {
            return String(format: "%016llx", flowHash)
        }
        if let textFlowId = record.textFlowId, !textFlowId.isEmpty {
            return textFlowId
        }
        return [
            record.direction,
            record.protocolHint,
            String(record.sourcePort ?? 0),
            String(record.destinationPort ?? 0)
        ].joined(separator: ":")
    }
}
