//
//  ForwardHostTracker.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 11/27/2025.
//
//  Maintains short-lived mappings between resolved hostnames and remote IP
//  addresses so traffic analysis can attribute CDN edges to their originating
//  services.
//

import Foundation
import Darwin
import OSLog

public extension RelativeProtocolTunnel {
    final class ForwardHostTracker: @unchecked Sendable {
        private struct Entry {
            var host: String
            var expiresAt: Date
        }

        private let defaultTTL: TimeInterval
        private let log = Logger(subsystem: "relative.protocol.tunnel", category: "ForwardHostTracker")
        private let queue = DispatchQueue(label: "RelativeProtocolTunnel.ForwardHostTracker", attributes: .concurrent)
        private var ipToEntry: [String: Entry] = [:]

        public init(defaultTTL: TimeInterval = 600) {
            self.defaultTTL = max(1, defaultTTL)
        }

        public func record(host: String, addresses: [String], ttl: TimeInterval?, timestamp: Date = Date()) {
            let sanitized = addresses.filter { !$0.isEmpty }
            guard !host.isEmpty, !sanitized.isEmpty else { return }
            let lifetime = max(1, ttl ?? defaultTTL)
            let expiry = timestamp.addingTimeInterval(lifetime)
            purgeExpired(at: timestamp)
            queue.async(flags: .barrier) {
                for ip in sanitized {
                    self.ipToEntry[ip] = Entry(host: host, expiresAt: expiry)
                    self.log.notice("tracking host \(host, privacy: .public) -> \(ip, privacy: .public) ttl=\(Int(lifetime), privacy: .public)s expires=\(expiry.timeIntervalSince1970, privacy: .public)")
                }
            }
        }

        public func ingest(ipPacket: Data, timestamp: Date = Date()) {
            for mapping in DNSMessageParser.extractMappings(from: ipPacket) {
                record(host: mapping.host, addresses: mapping.addresses, ttl: mapping.ttl, timestamp: timestamp)
            }
        }

        public func ingestTLSClientHello(ipPacket: Data, timestamp: Date = Date()) {
            guard let mapping = TLSClientHelloParser.extractMapping(from: ipPacket) else { return }
            record(host: mapping.host, addresses: [mapping.address], ttl: nil, timestamp: timestamp)
        }

        public func lookup(ip: String, at timestamp: Date = Date()) -> String? {
            purgeExpired(at: timestamp)
            return queue.sync {
                guard let entry = ipToEntry[ip], entry.expiresAt > timestamp else { return nil }
                return entry.host
            }
        }

        public func purgeExpired(at timestamp: Date = Date()) {
            queue.async(flags: .barrier) {
                self.ipToEntry = self.ipToEntry.filter { $0.value.expiresAt > timestamp }
            }
        }
    }
}

enum DNSMessageParser {
    struct Mapping {
        var host: String
        var addresses: [String]
        var ttl: TimeInterval?
    }

    static func extractMappings(from ipPacket: Data) -> [Mapping] {
        guard let udpPayload = extractDNSPayload(from: ipPacket) else { return [] }
        return extractMappings(fromDNSPayload: udpPayload)
    }

    private static func extractDNSPayload(from packet: Data) -> Data? {
        guard let firstByte = packet.first else { return nil }
        let version = firstByte >> 4

        switch version {
        case 4:
            let ihl = Int(firstByte & 0x0F) * 4
            guard ihl >= 20, packet.count >= ihl else { return nil }
            let protocolNumber = packet[9]
            guard protocolNumber == 17 else { return nil } // UDP
            let payload = packet[ihl...]
            return extractDNSPayloadFromUDPPayload(payload)
        case 6:
            let headerLength = 40
            guard packet.count >= headerLength else { return nil }
            let nextHeader = packet[6]
            guard nextHeader == 17 else { return nil } // UDP
            let payload = packet[headerLength...]
            return extractDNSPayloadFromUDPPayload(payload)
        default:
            return nil
        }
    }

    private static func extractDNSPayloadFromUDPPayload(_ payload: Data.SubSequence) -> Data? {
        guard payload.count >= 8 else { return nil }
        let srcPort = UInt16(payload[payload.startIndex]) << 8 | UInt16(payload[payload.startIndex + 1])
        let dstPort = UInt16(payload[payload.startIndex + 2]) << 8 | UInt16(payload[payload.startIndex + 3])
        guard srcPort == 53 || dstPort == 53 else { return nil }
        return Data(payload.dropFirst(8))
    }

    private static func extractMappings(fromDNSPayload payload: Data) -> [Mapping] {
        guard payload.count >= 12 else { return [] }
        let flags = readUInt16(payload, offset: 2)
        let isResponse = (flags & 0x8000) != 0
        guard isResponse else { return [] }

        let qdCount = Int(readUInt16(payload, offset: 4))
        let anCount = Int(readUInt16(payload, offset: 6))
        var index = 12
        var questions: [String] = []

        for _ in 0..<qdCount {
            guard let name = readName(payload, index: &index) else { return [] }
            questions.append(name)
            index += 4
            if index > payload.count { return [] }
        }

        guard anCount > 0 else { return [] }
        var cnameParents: [String: String] = [:] // child(lowercased) -> parent(lowercased)
        var results: [String: (addresses: Set<String>, ttl: UInt32?)] = [:]

        for _ in 0..<anCount {
            guard let name = readName(payload, index: &index) else { return [] }
            guard index + 10 <= payload.count else { return [] }
            let type = readUInt16(payload, offset: index)
            _ = readUInt16(payload, offset: index + 2)
            let ttl = readUInt32(payload, offset: index + 4)
            let rdLength = Int(readUInt16(payload, offset: index + 8))
            let rdataStart = index + 10
            let rdataEnd = rdataStart + rdLength
            guard rdataEnd <= payload.count else { return [] }
            index = rdataEnd

            switch type {
            case 5: // CNAME
                var offset = rdataStart
                if let target = readName(payload, index: &offset) {
                    cnameParents[target.lowercased()] = name.lowercased()
                }
            case 1, 28:
                guard let address = addressString(for: type, data: payload[rdataStart..<rdataEnd]) else {
                    continue
                }
                let canonical = canonicalHost(for: name, aliases: cnameParents, questions: questions)
                var entry = results[canonical] ?? (addresses: Set<String>(), ttl: nil)
                entry.addresses.insert(address)
                if let existing = entry.ttl {
                    entry.ttl = min(existing, ttl)
                } else {
                    entry.ttl = ttl
                }
                results[canonical] = entry
            default:
                continue
            }
        }

        return results.map { key, value in
            Mapping(host: key, addresses: Array(value.addresses), ttl: value.ttl.map { TimeInterval($0) })
        }
    }

    private static func canonicalHost(for name: String, aliases: [String: String], questions: [String]) -> String {
        let lowerName = name.lowercased()
        var current = lowerName
        var visited: Set<String> = []
        while let parent = aliases[current], !visited.contains(parent) {
            visited.insert(current)
            current = parent
        }
        if let match = questions.first(where: { $0.lowercased() == current }) {
            return match
        }
        return questions.first ?? name
    }

    private static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        guard offset + 1 < data.count else { return 0 }
        return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    private static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        guard offset + 3 < data.count else { return 0 }
        return (UInt32(data[offset]) << 24)
            | (UInt32(data[offset + 1]) << 16)
            | (UInt32(data[offset + 2]) << 8)
            | UInt32(data[offset + 3])
    }

    private static func readName(_ data: Data, index: inout Int) -> String? {
        var labels: [String] = []
        var currentIndex = index
        var seenOffsets: Set<Int> = []
        var pointerReturnIndex: Int?
        var jumped = false

        while currentIndex < data.count {
            let length = Int(data[currentIndex])
            if length == 0 {
                currentIndex += 1
                break
            }
            if length & 0xC0 == 0xC0 {
                guard currentIndex + 1 < data.count else { return nil }
                let pointer = ((length & 0x3F) << 8) | Int(data[currentIndex + 1])
                guard pointer < data.count else { return nil }
                if seenOffsets.contains(pointer) { return nil }
                seenOffsets.insert(pointer)
                if pointerReturnIndex == nil {
                    pointerReturnIndex = currentIndex + 2
                }
                currentIndex = pointer
                jumped = true
                continue
            }
            let start = currentIndex + 1
            let end = start + length
            guard end <= data.count else { return nil }
            if let label = String(bytes: data[start..<end], encoding: .utf8) {
                labels.append(label)
            }
            currentIndex = end
        }

        if jumped {
            index = pointerReturnIndex ?? currentIndex
        } else {
            index = currentIndex
        }

        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    private static func addressString(for recordType: UInt16, data: Data.SubSequence) -> String? {
        switch recordType {
        case 1 where data.count == 4:
            return data.map { String($0) }.joined(separator: ".")
        case 28 where data.count == 16:
            return data.withUnsafeBytes { raw -> String? in
                guard let base = raw.baseAddress else { return nil }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, base, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
                return nil
            }
        default:
            return nil
        }
    }
}
