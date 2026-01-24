// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation

public struct TrafficClassification: Codable, Hashable, Sendable {
    public let label: String?
    public let domain: String?
    public let cdn: String?
    public let asn: String?
    public let confidence: Double
    public let reasons: [String]

    public init(label: String?, domain: String?, cdn: String?, asn: String?, confidence: Double, reasons: [String]) {
        self.label = label
        self.domain = domain
        self.cdn = cdn
        self.asn = asn
        self.confidence = confidence
        self.reasons = reasons
    }
}

public final class TrafficClassifier {
    private struct CacheEntry {
        var domain: String
        var label: String?
        var cdn: String?
        var asn: String?
        var confidence: Double
        var lastSeen: TimeInterval
        var expiresAt: TimeInterval
        var source: String
    }

    private let ttlDNS: TimeInterval
    private let ttlTLS: TimeInterval
    private let ttlCache: TimeInterval
    private let maxEntries: Int
    private var ipCache: [String: CacheEntry] = [:]
    private var signatures: [AppSignature]
    private let signatureFileURL: URL?
    private var signatureFileModified: Date?
    private var lastSignatureCheck: TimeInterval = 0
    private let signatureCheckInterval: TimeInterval

    public init(
        ttlDNS: TimeInterval = 180,
        ttlTLS: TimeInterval = 600,
        ttlCache: TimeInterval = 300,
        maxEntries: Int = 4096,
        signatures: [AppSignature] = [],
        signatureFileURL: URL? = nil,
        signatureCheckInterval: TimeInterval = 5.0
    ) {
        self.ttlDNS = ttlDNS
        self.ttlTLS = ttlTLS
        self.ttlCache = ttlCache
        self.maxEntries = maxEntries
        self.signatures = Self.normalizeSignatures(signatures)
        self.signatureFileURL = signatureFileURL
        self.signatureCheckInterval = signatureCheckInterval
        if signatureFileURL != nil {
            reloadSignaturesIfNeeded(now: Date().timeIntervalSince1970, force: true)
        }
    }

    public func classify(metadata: PacketMetadata, direction: PacketDirection, timestamp: TimeInterval) -> TrafficClassification? {
        prune(now: timestamp)
        reloadSignaturesIfNeeded(now: timestamp, force: false)

        let remoteIP = remoteAddress(for: metadata, direction: direction)
        let dnsName = metadata.dnsCname ?? metadata.dnsQueryName
        let tlsName = metadata.tlsServerName
        let registrable = DomainNormalizer.registrableDomain(from: tlsName ?? dnsName ?? metadata.registrableDomain)

        if let answers = metadata.dnsAnswerAddresses, let domain = DomainNormalizer.registrableDomain(from: dnsName ?? metadata.registrableDomain) {
            let cdn = cdnProvider(for: dnsName ?? domain)
            let asn = asnForProvider(cdn)
            let label = appLabel(for: domain)
            for address in answers {
                updateCache(
                    ip: address.stringValue,
                    domain: domain,
                    label: label,
                    cdn: cdn,
                    asn: asn,
                    confidence: 0.6,
                    timestamp: timestamp,
                    ttl: ttlDNS,
                    source: "dns"
                )
            }
        }

        if let tlsName, !remoteIP.isEmpty {
            let domain = DomainNormalizer.registrableDomain(from: tlsName) ?? tlsName
            let cdn = cdnProvider(for: tlsName)
            let asn = asnForProvider(cdn)
            let label = appLabel(for: domain)
            updateCache(
                ip: remoteIP,
                domain: domain,
                label: label,
                cdn: cdn,
                asn: asn,
                confidence: 0.85,
                timestamp: timestamp,
                ttl: ttlTLS,
                source: "tls"
            )
        }

        var reasons: [String] = []
        var confidence: Double = 0.0
        var domain = registrable
        var label = domain.flatMap(appLabel(for:))
        var cdn = cdnProvider(for: tlsName ?? dnsName ?? domain)
        var asn = asnForProvider(cdn)

        if let tlsName {
            reasons.append("tls_sni=\(tlsName)")
            confidence = max(confidence, 0.8)
        } else if let dnsName {
            reasons.append("dns=\(dnsName)")
            confidence = max(confidence, 0.6)
        }

        if let cached = cachedEntry(for: remoteIP, now: timestamp) {
            if domain == nil { domain = cached.domain }
            if label == nil { label = cached.label }
            if cdn == nil { cdn = cached.cdn }
            if asn == nil { asn = cached.asn }
            reasons.append("ip_cache=\(cached.domain)")
            confidence = max(confidence, cached.confidence * 0.8)
        }

        if let label {
            reasons.append("app=\(label)")
            confidence = max(confidence, 0.7)
        }

        if let cdn {
            reasons.append("cdn=\(cdn)")
            confidence = max(confidence, 0.3)
        }

        if let asn {
            reasons.append("asn=\(asn)")
        }

        guard domain != nil || label != nil || cdn != nil else { return nil }
        let cappedConfidence = min(1.0, max(0.0, confidence))
        return TrafficClassification(
            label: label,
            domain: domain,
            cdn: cdn,
            asn: asn,
            confidence: cappedConfidence,
            reasons: reasons
        )
    }

    public func reset() {
        ipCache.removeAll()
    }

    public func updateSignatures(_ signatures: [AppSignature]) {
        self.signatures = Self.normalizeSignatures(signatures)
    }

    public func reloadSignatures() {
        reloadSignaturesIfNeeded(now: Date().timeIntervalSince1970, force: true)
    }

    private func remoteAddress(for metadata: PacketMetadata, direction: PacketDirection) -> String {
        switch direction {
        case .outbound:
            return metadata.dstAddress.stringValue
        case .inbound:
            return metadata.srcAddress.stringValue
        }
    }

    private func cachedEntry(for ip: String, now: TimeInterval) -> CacheEntry? {
        guard let entry = ipCache[ip], entry.expiresAt > now else { return nil }
        return entry
    }

    private func updateCache(
        ip: String,
        domain: String,
        label: String?,
        cdn: String?,
        asn: String?,
        confidence: Double,
        timestamp: TimeInterval,
        ttl: TimeInterval,
        source: String
    ) {
        guard !ip.isEmpty else { return }
        let entry = CacheEntry(
            domain: domain,
            label: label,
            cdn: cdn,
            asn: asn,
            confidence: confidence,
            lastSeen: timestamp,
            expiresAt: timestamp + ttl,
            source: source
        )
        ipCache[ip] = entry
        if ipCache.count > maxEntries {
            prune(now: timestamp)
        }
    }

    private func prune(now: TimeInterval) {
        if ipCache.count > maxEntries {
            let sorted = ipCache.sorted { $0.value.lastSeen < $1.value.lastSeen }
            let overflow = max(0, ipCache.count - maxEntries)
            if overflow > 0 {
                for idx in 0..<overflow {
                    ipCache.removeValue(forKey: sorted[idx].key)
                }
            }
        }
        let expired = ipCache.filter { now > $0.value.expiresAt }
        if !expired.isEmpty {
            expired.keys.forEach { ipCache.removeValue(forKey: $0) }
        }
    }

    private func appLabel(for domain: String?) -> String? {
        guard let domain else { return nil }
        let lower = domain.lowercased()
        for signature in signatures {
            if signature.domains.contains(where: { matchesDomain(lower, signatureDomain: $0) }) {
                return signature.label
            }
        }
        return nil
    }

    private func matchesDomain(_ candidate: String, signatureDomain: String) -> Bool {
        if candidate == signatureDomain { return true }
        return candidate.hasSuffix("." + signatureDomain)
    }

    private func cdnProvider(for domain: String?) -> String? {
        guard let domain else { return nil }
        let lower = domain.lowercased()
        for provider in CDNProvider.providers {
            if provider.suffixes.contains(where: { lower.hasSuffix($0) }) {
                return provider.name
            }
        }
        return nil
    }

    private func asnForProvider(_ provider: String?) -> String? {
        guard let provider else { return nil }
        return CDNProvider.providers.first { $0.name == provider }?.asn
    }

    private func reloadSignaturesIfNeeded(now: TimeInterval, force: Bool) {
        guard let signatureFileURL else { return }
        if !force, now - lastSignatureCheck < signatureCheckInterval {
            return
        }
        lastSignatureCheck = now
        let attributes = try? FileManager.default.attributesOfItem(atPath: signatureFileURL.path)
        let modified = attributes?[.modificationDate] as? Date
        if force || modified != signatureFileModified {
            let loaded = AppSignatureStore.loadValidated(from: signatureFileURL)
            if !loaded.isEmpty {
                signatures = Self.normalizeSignatures(loaded)
            }
            if let modified {
                signatureFileModified = modified
            }
        }
    }

    private static func normalizeSignatures(_ signatures: [AppSignature]) -> [AppSignature] {
        signatures.map { signature in
            let domains = signature.domains
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { !$0.isEmpty }
            return AppSignature(label: signature.label, domains: domains)
        }
    }
}

private struct CDNProvider {
    let name: String
    let asn: String?
    let suffixes: [String]

    static let providers: [CDNProvider] = [
        CDNProvider(name: "akamai", asn: "AS20940", suffixes: [
            "akamaitechnologies.com",
            "akamai.net",
            "akamaized.net",
            "edgekey.net",
            "edgesuite.net",
            "akadns.net",
            "akahd.net",
            "akamaiedge.net"
        ]),
        CDNProvider(name: "cloudflare", asn: "AS13335", suffixes: [
            "cloudflare.com",
            "cloudflare.net",
            "cf-ipfs.com"
        ]),
        CDNProvider(name: "fastly", asn: "AS54113", suffixes: [
            "fastly.net",
            "fastlylb.net",
            "fastly.com"
        ]),
        CDNProvider(name: "cloudfront", asn: "AS16509", suffixes: [
            "cloudfront.net"
        ]),
        CDNProvider(name: "google", asn: "AS15169", suffixes: [
            "googleusercontent.com",
            "gvt1.com",
            "gvt2.com"
        ]),
        CDNProvider(name: "meta", asn: "AS32934", suffixes: [
            "fbcdn.net",
            "facebook.com",
            "fbsbx.com"
        ]),
        CDNProvider(name: "apple", asn: "AS714", suffixes: [
            "apple.com",
            "icloud.com",
            "mzstatic.com",
            "apple-dns.net"
        ])
    ]
}