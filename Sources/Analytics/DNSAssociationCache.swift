import Foundation

internal struct DNSAssociationSnapshot: Sendable, Equatable {
    let associatedDomain: String
    let source: DetectorAssociationSource
    let ageMs: Int
    let confidence: Double
}

internal struct DNSAssociationCache {
    private struct AddressKey: Hashable, Sendable {
        let length: UInt8
        let high: UInt64
        let low: UInt64
    }

    private struct Entry: Sendable {
        let associatedDomain: String
        let source: DetectorAssociationSource
        let storedAt: Date
        let confidence: Double
    }

    private enum Policy {
        static let ttlSeconds: TimeInterval = 60
        static let maxEntries = 4_096
        static let minimumSweepIntervalSeconds: TimeInterval = 10
    }

    private var entries: [AddressKey: Entry] = [:]
    private var arrivalQueue: ArraySlice<AddressKey> = []
    private var lastSweepAt: Date?

    mutating func record(metadata: PacketMetadata, classification: String?, now: Date) {
        guard let answers = metadata.dnsAnswerAddresses, !answers.isEmpty else {
            return
        }

        let associatedDomain = metadata.registrableDomain
            ?? DomainNormalizer.registrableDomain(from: metadata.dnsCname)
            ?? DomainNormalizer.registrableDomain(from: metadata.dnsQueryName)
            ?? classification
        guard let associatedDomain, !associatedDomain.isEmpty else {
            return
        }

        evictExpiredIfNeeded(now: now)

        for address in answers {
            let key = Self.key(for: address)
            entries[key] = Entry(
                associatedDomain: associatedDomain,
                source: .dnsAnswer,
                storedAt: now,
                confidence: classification == nil ? 0.82 : 0.9
            )
            arrivalQueue.append(key)
        }

        trimOverflowIfNeeded()
    }

    mutating func associate(summary: FastPacketSummary, direction: PacketDirection, now: Date) -> DNSAssociationSnapshot? {
        evictExpiredIfNeeded(now: now)
        let key = Self.remoteAddressKey(for: summary, direction: direction)
        guard let entry = entries[key] else {
            return nil
        }
        guard !Self.isExpired(entry, now: now) else {
            entries.removeValue(forKey: key)
            pruneArrivalQueue()
            return nil
        }
        let ageMs = millisecondsBetween(entry.storedAt, and: now)
        return DNSAssociationSnapshot(
            associatedDomain: entry.associatedDomain,
            source: entry.source,
            ageMs: ageMs,
            confidence: entry.confidence
        )
    }

    private mutating func evictExpiredIfNeeded(now: Date) {
        guard !entries.isEmpty else {
            return
        }
        if let lastSweepAt,
           now.timeIntervalSince(lastSweepAt) < Policy.minimumSweepIntervalSeconds,
           entries.count <= Policy.maxEntries {
            return
        }

        lastSweepAt = now
        let expiredKeys = entries.compactMap { key, entry in
            Self.isExpired(entry, now: now) ? key : nil
        }
        for key in expiredKeys {
            entries.removeValue(forKey: key)
        }
        pruneArrivalQueue(force: !expiredKeys.isEmpty)
    }

    private mutating func trimOverflowIfNeeded() {
        guard entries.count > Policy.maxEntries else {
            return
        }

        pruneArrivalQueue(force: true)
        while entries.count > Policy.maxEntries {
            guard let oldest = arrivalQueue.popFirst() else {
                break
            }
            entries.removeValue(forKey: oldest)
        }
        pruneArrivalQueue(force: true)
    }

    private mutating func pruneArrivalQueue(force: Bool = false) {
        guard force || arrivalQueue.startIndex > 128 || arrivalQueue.count > Policy.maxEntries * 2 else {
            return
        }

        var seen: Set<AddressKey> = []
        var active: [AddressKey] = []
        active.reserveCapacity(entries.count)
        for key in arrivalQueue {
            guard entries[key] != nil, seen.insert(key).inserted else {
                continue
            }
            active.append(key)
        }
        arrivalQueue = ArraySlice(active)
    }

    private static func isExpired(_ entry: Entry, now: Date) -> Bool {
        now.timeIntervalSince(entry.storedAt) > Policy.ttlSeconds
    }

    private static func remoteAddressKey(for summary: FastPacketSummary, direction: PacketDirection) -> AddressKey {
        if direction == .outbound {
            return AddressKey(
                length: summary.destinationAddressLength,
                high: summary.destinationAddressHigh,
                low: summary.destinationAddressLow
            )
        }
        return AddressKey(
            length: summary.sourceAddressLength,
            high: summary.sourceAddressHigh,
            low: summary.sourceAddressLow
        )
    }

    private static func key(for address: IPAddress) -> AddressKey {
        let bytes = [UInt8](address.bytes)
        var high: UInt64 = 0
        var low: UInt64 = 0
        if bytes.count == 4 {
            for index in 0..<4 {
                low |= UInt64(bytes[index]) << UInt64((3 - index) * 8)
            }
        } else {
            for index in 0..<8 {
                high |= UInt64(bytes[index]) << UInt64((7 - index) * 8)
            }
            for index in 0..<8 {
                low |= UInt64(bytes[index + 8]) << UInt64((7 - index) * 8)
            }
        }
        return AddressKey(length: UInt8(bytes.count), high: high, low: low)
    }
}

private func millisecondsBetween(_ earlier: Date, and later: Date) -> Int {
    let elapsed = later.timeIntervalSince(earlier)
    guard elapsed.isFinite, elapsed > 0 else {
        return 0
    }
    let milliseconds = (elapsed * 1_000).rounded()
    guard milliseconds.isFinite else {
        return Int.max
    }
    if milliseconds >= Double(Int.max) {
        return Int.max
    }
    return Int(milliseconds)
}
