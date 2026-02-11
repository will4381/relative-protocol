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
    private struct LastSeenHeap {
        struct Entry {
            let key: String
            let lastSeen: TimeInterval
            let revision: UInt64
        }

        private var storage: [Entry] = []

        mutating func push(_ entry: Entry) {
            storage.append(entry)
            siftUp(from: storage.count - 1)
        }

        mutating func popMin() -> Entry? {
            guard !storage.isEmpty else { return nil }
            if storage.count == 1 {
                return storage.removeLast()
            }
            let minEntry = storage[0]
            storage[0] = storage.removeLast()
            siftDown(from: 0)
            return minEntry
        }

        mutating func removeAll() {
            storage.removeAll(keepingCapacity: false)
        }

        private mutating func siftUp(from index: Int) {
            var child = index
            while child > 0 {
                let parent = (child - 1) / 2
                if storage[child].lastSeen >= storage[parent].lastSeen {
                    break
                }
                storage.swapAt(child, parent)
                child = parent
            }
        }

        private mutating func siftDown(from index: Int) {
            var parent = index
            while true {
                let left = 2 * parent + 1
                let right = left + 1
                var candidate = parent

                if left < storage.count && storage[left].lastSeen < storage[candidate].lastSeen {
                    candidate = left
                }
                if right < storage.count && storage[right].lastSeen < storage[candidate].lastSeen {
                    candidate = right
                }
                if candidate == parent {
                    return
                }
                storage.swapAt(parent, candidate)
                parent = candidate
            }
        }
    }

    private struct ExpiryHeap {
        struct Entry {
            let key: String
            let expiresAt: TimeInterval
            let revision: UInt64
        }

        private var storage: [Entry] = []

        mutating func push(_ entry: Entry) {
            storage.append(entry)
            siftUp(from: storage.count - 1)
        }

        mutating func popMin() -> Entry? {
            guard !storage.isEmpty else { return nil }
            if storage.count == 1 {
                return storage.removeLast()
            }
            let minEntry = storage[0]
            storage[0] = storage.removeLast()
            siftDown(from: 0)
            return minEntry
        }

        mutating func removeAll() {
            storage.removeAll(keepingCapacity: false)
        }

        private mutating func siftUp(from index: Int) {
            var child = index
            while child > 0 {
                let parent = (child - 1) / 2
                if storage[child].expiresAt >= storage[parent].expiresAt {
                    break
                }
                storage.swapAt(child, parent)
                child = parent
            }
        }

        private mutating func siftDown(from index: Int) {
            var parent = index
            while true {
                let left = 2 * parent + 1
                let right = left + 1
                var candidate = parent

                if left < storage.count && storage[left].expiresAt < storage[candidate].expiresAt {
                    candidate = left
                }
                if right < storage.count && storage[right].expiresAt < storage[candidate].expiresAt {
                    candidate = right
                }
                if candidate == parent {
                    return
                }
                storage.swapAt(parent, candidate)
                parent = candidate
            }
        }
    }

    private struct CacheEntry {
        var domain: String
        var label: String?
        var cdn: String?
        var asn: String?
        var confidence: Double
        var lastSeen: TimeInterval
        var expiresAt: TimeInterval
        var revision: UInt64
        var source: String
    }

    private let ttlDNS: TimeInterval
    private let ttlTLS: TimeInterval
    private let ttlCache: TimeInterval
    private let maxEntries: Int
    private var ipCache: [String: CacheEntry] = [:]
    private var lastSeenHeap = LastSeenHeap()
    private var expiryHeap = ExpiryHeap()
    private var nextRevision: UInt64 = 0
    private var signatures: [AppSignature]
    private var labelLookupCache: [String: String?] = [:]
    private var cdnLookupCache: [String: String?] = [:]
    private var asnLookupCache: [String: String?] = [:]
    private let lookupCacheLimit = 4096
    private let signatureFileURL: URL?
    private var signatureFileModified: Date?
    private var nextSignatureCheckAt: TimeInterval = 0
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
        if signatureFileURL != nil, timestamp >= nextSignatureCheckAt {
            reloadSignaturesIfNeeded(now: timestamp, force: false)
        }

        let remoteIP = remoteAddress(for: metadata, direction: direction)
        let dnsName = metadata.dnsCname ?? metadata.dnsQueryName
        let tlsName = metadata.tlsServerName
        let primaryName = tlsName ?? dnsName ?? metadata.registrableDomain
        let registrable = DomainNormalizer.registrableDomain(from: primaryName)

        if let answers = metadata.dnsAnswerAddresses,
           let domain = DomainNormalizer.registrableDomain(from: dnsName ?? metadata.registrableDomain) {
            let cdn = cdnProvider(for: dnsName ?? domain)
            let asn = asnForProvider(cdn)
            let label = appLabel(for: dnsName ?? domain)
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
            let label = appLabel(for: tlsName)
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
        var label = appLabel(for: tlsName ?? dnsName ?? domain)
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
        lastSeenHeap.removeAll()
        expiryHeap.removeAll()
        nextRevision = 0
        labelLookupCache.removeAll(keepingCapacity: false)
        cdnLookupCache.removeAll(keepingCapacity: false)
        asnLookupCache.removeAll(keepingCapacity: false)
    }

    public func updateSignatures(_ signatures: [AppSignature]) {
        self.signatures = Self.normalizeSignatures(signatures)
        labelLookupCache.removeAll(keepingCapacity: false)
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
        let revision = makeRevision()
        let entry = CacheEntry(
            domain: domain,
            label: label,
            cdn: cdn,
            asn: asn,
            confidence: confidence,
            lastSeen: timestamp,
            expiresAt: timestamp + ttl,
            revision: revision,
            source: source
        )
        ipCache[ip] = entry
        lastSeenHeap.push(.init(key: ip, lastSeen: timestamp, revision: revision))
        expiryHeap.push(.init(key: ip, expiresAt: timestamp + ttl, revision: revision))
        if ipCache.count > maxEntries {
            pruneOverflow()
        }
    }

    private func prune(now: TimeInterval) {
        pruneOverflow()
        pruneExpired(now: now)
    }

    private func pruneOverflow() {
        var overflow = max(0, ipCache.count - maxEntries)
        while overflow > 0, let candidate = lastSeenHeap.popMin() {
            guard let entry = ipCache[candidate.key], entry.revision == candidate.revision else {
                continue
            }
            ipCache.removeValue(forKey: candidate.key)
            overflow -= 1
        }
    }

    private func pruneExpired(now: TimeInterval) {
        while let candidate = expiryHeap.popMin() {
            guard let entry = ipCache[candidate.key], entry.revision == candidate.revision else {
                continue
            }
            if now > entry.expiresAt {
                ipCache.removeValue(forKey: candidate.key)
                continue
            }
            expiryHeap.push(candidate)
            break
        }
    }

    private func appLabel(for domain: String?) -> String? {
        guard let domain else { return nil }
        let lower = domain.lowercased()
        if let cached = labelLookupCache[lower] {
            return cached
        }
        for signature in signatures {
            if signature.domains.contains(where: { matchesDomain(lower, signatureDomain: $0) }) {
                cacheLookup(&labelLookupCache, key: lower, value: signature.label)
                return signature.label
            }
        }
        cacheLookup(&labelLookupCache, key: lower, value: nil)
        return nil
    }

    private func matchesDomain(_ candidate: String, signatureDomain: String) -> Bool {
        if signatureDomain.contains("*") {
            return wildcardMatch(candidate, pattern: signatureDomain)
        }
        if candidate == signatureDomain { return true }
        return candidate.hasSuffix("." + signatureDomain)
    }

    private func wildcardMatch(_ candidate: String, pattern: String) -> Bool {
        let candidateLabels = candidate.split(separator: ".")
        let patternLabels = pattern.split(separator: ".")
        guard candidateLabels.count == patternLabels.count else { return false }

        for (candidateLabel, patternLabel) in zip(candidateLabels, patternLabels) {
            if !wildcardMatchLabel(candidateLabel, pattern: patternLabel) {
                return false
            }
        }
        return true
    }

    private func wildcardMatchLabel(_ candidate: Substring, pattern: Substring) -> Bool {
        var cIndex = candidate.startIndex
        var pIndex = pattern.startIndex
        var starIndex: Substring.Index?
        var matchIndex: Substring.Index?

        while cIndex < candidate.endIndex {
            if pIndex < pattern.endIndex, pattern[pIndex] == candidate[cIndex] {
                cIndex = candidate.index(after: cIndex)
                pIndex = pattern.index(after: pIndex)
                continue
            }
            if pIndex < pattern.endIndex, pattern[pIndex] == "*" {
                starIndex = pIndex
                matchIndex = cIndex
                pIndex = pattern.index(after: pIndex)
                continue
            }
            if let star = starIndex, let match = matchIndex {
                pIndex = pattern.index(after: star)
                let nextMatch = candidate.index(after: match)
                matchIndex = nextMatch
                cIndex = nextMatch
                continue
            }
            return false
        }

        while pIndex < pattern.endIndex, pattern[pIndex] == "*" {
            pIndex = pattern.index(after: pIndex)
        }
        return pIndex == pattern.endIndex
    }

    private func cdnProvider(for domain: String?) -> String? {
        guard let domain else { return nil }
        let lower = domain.lowercased()
        if let cached = cdnLookupCache[lower] {
            return cached
        }
        for provider in CDNProvider.providers {
            if provider.suffixes.contains(where: { lower.hasSuffix($0) }) {
                cacheLookup(&cdnLookupCache, key: lower, value: provider.name)
                return provider.name
            }
        }
        cacheLookup(&cdnLookupCache, key: lower, value: nil)
        return nil
    }

    private func asnForProvider(_ provider: String?) -> String? {
        guard let provider else { return nil }
        if let cached = asnLookupCache[provider] {
            return cached
        }
        let asn = CDNProvider.providers.first { $0.name == provider }?.asn
        cacheLookup(&asnLookupCache, key: provider, value: asn)
        return asn
    }

    private func reloadSignaturesIfNeeded(now: TimeInterval, force: Bool) {
        guard let signatureFileURL else { return }
        if !force, now < nextSignatureCheckAt {
            return
        }
        nextSignatureCheckAt = now + signatureCheckInterval
        let attributes = try? FileManager.default.attributesOfItem(atPath: signatureFileURL.path)
        let modified = attributes?[.modificationDate] as? Date
        if force || modified != signatureFileModified {
            let loaded = AppSignatureStore.loadValidated(from: signatureFileURL)
            if !loaded.isEmpty {
                signatures = Self.normalizeSignatures(loaded)
                labelLookupCache.removeAll(keepingCapacity: false)
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

    private func cacheLookup(_ cache: inout [String: String?], key: String, value: String?) {
        cache[key] = value
        if cache.count > lookupCacheLimit {
            cache.removeAll(keepingCapacity: true)
        }
    }

    private func makeRevision() -> UInt64 {
        nextRevision &+= 1
        return nextRevision
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
