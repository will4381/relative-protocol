// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif

internal enum DetectorRecordDerivation {
    static func remoteAddress(direction: String, sourceAddress: String?, destinationAddress: String?) -> String? {
        direction == PacketDirection.inbound.rawValue ? sourceAddress : destinationAddress
    }

    static func remotePort(direction: String, sourcePort: UInt16?, destinationPort: UInt16?) -> UInt16? {
        direction == PacketDirection.inbound.rawValue ? sourcePort : destinationPort
    }

    static func localAddress(direction: String, sourceAddress: String?, destinationAddress: String?) -> String? {
        direction == PacketDirection.inbound.rawValue ? destinationAddress : sourceAddress
    }

    static func localPort(direction: String, sourcePort: UInt16?, destinationPort: UInt16?) -> UInt16? {
        direction == PacketDirection.inbound.rawValue ? destinationPort : sourcePort
    }

    static func endpoint(protocolHint: String, address: String?, port: UInt16?) -> String? {
        guard let address, !address.isEmpty, let port else {
            return nil
        }
        let host = address.contains(":") ? "[\(address)]" : address
        return "\(protocolHint.lowercased())://\(host):\(port)"
    }

    static func flowIdentity(
        protocolHint: String,
        direction: String,
        sourceAddress: String?,
        sourcePort: UInt16?,
        destinationAddress: String?,
        destinationPort: UInt16?,
        flowId: String,
        lineageId: UInt64?,
        generation: Int?
    ) -> FlowIdentity {
        let remoteAddress = remoteAddress(direction: direction, sourceAddress: sourceAddress, destinationAddress: destinationAddress)
        let remotePort = remotePort(direction: direction, sourcePort: sourcePort, destinationPort: destinationPort)
        return FlowIdentity(
            protocolName: protocolHint,
            localAddress: localAddress(direction: direction, sourceAddress: sourceAddress, destinationAddress: destinationAddress),
            localPort: localPort(direction: direction, sourcePort: sourcePort, destinationPort: destinationPort),
            remoteAddress: remoteAddress,
            remotePort: remotePort,
            direction: direction,
            flowId: flowId,
            lineageId: lineageId,
            generation: generation
        )
    }

    static func ownerKey(sourceBundleId: String?, sourceAppIdentifier: String?, remoteEndpoint: String?, flowId: String) -> String {
        if let sourceBundleId = normalizedLabel(sourceBundleId) {
            return "app:\(sourceBundleId)"
        }
        if let sourceAppIdentifier = normalizedLabel(sourceAppIdentifier) {
            return "app:\(sourceAppIdentifier)"
        }
        if let remoteEndpoint, !remoteEndpoint.isEmpty {
            return "endpoint:\(remoteEndpoint)"
        }
        return "flow:\(flowId)"
    }

    static func normalizedLabel(_ value: String?) -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !value.isEmpty else {
            return nil
        }
        return value
    }
}

public struct AddressScopePrefix: Sendable, Equatable {
    public let family: String
    public let confidence: Double
    let addressLength: UInt8
    let high: UInt64
    let low: UInt64
    let prefixLength: UInt8

    public init?(
        cidr: String,
        family: String,
        confidence: Double = 0.72
    ) {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2,
              let parsed = Self.parseAddress(parts[0]),
              let prefixLength = UInt8(parts[1]),
              prefixLength <= parsed.addressLength * 8 else {
            return nil
        }
        self.family = family
        self.confidence = max(0, min(confidence, 1))
        self.addressLength = parsed.addressLength
        self.high = parsed.high
        self.low = parsed.low
        self.prefixLength = prefixLength
    }

    func contains(addressLength: UInt8, high: UInt64, low: UInt64) -> Bool {
        guard self.addressLength == addressLength else {
            return false
        }
        if addressLength == 4 {
            return Self.matchesIPv4Prefix(lhs: UInt32(self.low & 0xffff_ffff), rhs: UInt32(low & 0xffff_ffff), prefixLength: prefixLength)
        }
        return Self.matchesPrefix(lhsHigh: self.high, lhsLow: self.low, rhsHigh: high, rhsLow: low, prefixLength: prefixLength)
    }

    private static func parseAddress(_ value: String) -> (addressLength: UInt8, high: UInt64, low: UInt64)? {
        #if os(Linux)
        let ipv4Family = AF_INET
        let ipv6Family = AF_INET6
        #else
        let ipv4Family = AF_INET
        let ipv6Family = AF_INET6
        #endif

        var ipv4 = in_addr()
        if value.withCString({ inet_pton(ipv4Family, $0, &ipv4) }) == 1 {
            let bytes = withUnsafeBytes(of: ipv4) { Array($0) }
            return packedAddress(bytes: [UInt8](repeating: 0, count: 12) + bytes)
                .map { (4, $0.high, $0.low) }
        }

        var ipv6 = in6_addr()
        if value.withCString({ inet_pton(ipv6Family, $0, &ipv6) }) == 1 {
            let bytes = withUnsafeBytes(of: ipv6) { Array($0) }
            return packedAddress(bytes: bytes).map { (16, $0.high, $0.low) }
        }

        return nil
    }

    private static func packedAddress(bytes: [UInt8]) -> (high: UInt64, low: UInt64)? {
        guard bytes.count == 16 else {
            return nil
        }
        let high = bytes[0..<8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let low = bytes[8..<16].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return (high, low)
    }

    private static func matchesPrefix(lhsHigh: UInt64, lhsLow: UInt64, rhsHigh: UInt64, rhsLow: UInt64, prefixLength: UInt8) -> Bool {
        if prefixLength == 0 {
            return true
        }
        if prefixLength <= 64 {
            let shift = 64 - UInt64(prefixLength)
            let mask = UInt64.max << shift
            return (lhsHigh & mask) == (rhsHigh & mask)
        }
        let lowPrefix = UInt64(prefixLength - 64)
        let lowMask = UInt64.max << (64 - lowPrefix)
        return lhsHigh == rhsHigh && (lhsLow & lowMask) == (rhsLow & lowMask)
    }

    private static func matchesIPv4Prefix(lhs: UInt32, rhs: UInt32, prefixLength: UInt8) -> Bool {
        if prefixLength == 0 {
            return true
        }
        let shift = 32 - UInt32(prefixLength)
        let mask = UInt32.max << shift
        return (lhs & mask) == (rhs & mask)
    }
}

public struct AddressScopeClassifier: Sendable, Equatable {
    public struct Match: Sendable, Equatable {
        public let family: String
        public let source: AddressScopeSource
        public let confidence: Double
    }

    public let prefixes: [AddressScopePrefix]

    public init(prefixes: [AddressScopePrefix] = []) {
        self.prefixes = prefixes
    }

    public static let empty = AddressScopeClassifier()

    func classify(addressLength: UInt8?, high: UInt64?, low: UInt64?) -> Match? {
        guard let addressLength, let high, let low else {
            return nil
        }
        for prefix in prefixes where prefix.contains(addressLength: addressLength, high: high, low: low) {
            return Match(family: prefix.family, source: .prefix, confidence: prefix.confidence)
        }
        return nil
    }
}
