//
//  DNSClient.swift
//  RelativeProtocolCore
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/27/2025.
//
//  Wraps system DNS primitives in async helpers for forward and reverse lookups
//  without blocking the caller's executor.
//

import Foundation
import Dispatch
import Darwin

public extension RelativeProtocol {
    /// Lightweight DNS helper that performs forward and reverse lookups using
    /// the system resolver. Calls are executed on a background queue to avoid
    /// blocking the caller's executor.
    struct DNSClient: Sendable {
        public enum LookupError: Swift.Error, Sendable {
            case invalidInput
            case systemError(code: Int32)
        }

        public struct ForwardLookup: Sendable {
            public var ipv4Addresses: [String]
            public var ipv6Addresses: [String]

            public init(ipv4Addresses: [String] = [], ipv6Addresses: [String] = []) {
                self.ipv4Addresses = ipv4Addresses
                self.ipv6Addresses = ipv6Addresses
            }
        }

        public init() {}

        /// Resolves the supplied host name to IPv4/IPv6 string literals.
        public func resolve(host: String) async throws -> ForwardLookup {
            try await Self.performOnBackgroundQueue {
                try Self.performResolve(host: host)
            }
        }

        /// Performs a reverse lookup for the supplied IPv4 or IPv6 address.
        public func reverseLookup(address: String) async throws -> String? {
            try await Self.performOnBackgroundQueue {
                try Self.performReverseLookup(address: address)
            }
        }
    }
}

private extension RelativeProtocol.DNSClient {
    static func performResolve(host: String) throws -> ForwardLookup {
        guard !host.isEmpty else { throw LookupError.invalidInput }

        var hints = addrinfo()
        hints.ai_flags = AI_ADDRCONFIG
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = Int32(SOCK_STREAM)
        hints.ai_protocol = IPPROTO_TCP

        var resultPointer: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &resultPointer)
        guard status == 0 else {
            throw LookupError.systemError(code: status)
        }
        defer { if let pointer = resultPointer { freeaddrinfo(pointer) } }

        var ipv4: [String] = []
        var ipv6: [String] = []

        var cursor = resultPointer
        while let info = cursor?.pointee {
            guard let addr = info.ai_addr else {
                cursor = info.ai_next
                continue
            }
            switch Int32(info.ai_family) {
            case AF_INET:
                let ipv4Addr = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                var addressCopy = ipv4Addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &addressCopy, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
                    cursor = info.ai_next
                    continue
                }
                ipv4.append(String(cString: buffer))
            case AF_INET6:
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let sockaddrIn6Ptr = UnsafeRawPointer(addr).assumingMemoryBound(to: sockaddr_in6.self)
                var address = sockaddrIn6Ptr.pointee.sin6_addr
                guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                    cursor = info.ai_next
                    continue
                }
                ipv6.append(String(cString: buffer))
            default:
                break
            }
            cursor = info.ai_next
        }

        return ForwardLookup(ipv4Addresses: ipv4, ipv6Addresses: ipv6)
    }

    static func performReverseLookup(address: String) throws -> String? {
        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))

        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = 0
            addr.sin_addr = ipv4

            let result = withUnsafePointer(to: &addr) { pointer -> Int32 in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addrPtr in
                    getnameinfo(addrPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &hostname, socklen_t(hostname.count), nil, 0, NI_NAMEREQD)
                }
            }
            if result == 0 {
                return String(cString: hostname)
            }
            if result == EAI_NONAME {
                return nil
            }
            throw LookupError.systemError(code: result)
        }

        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = 0
            addr.sin6_flowinfo = 0
            addr.sin6_addr = ipv6
            addr.sin6_scope_id = 0

            let result = withUnsafePointer(to: &addr) { pointer -> Int32 in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addrPtr in
                    getnameinfo(addrPtr, socklen_t(MemoryLayout<sockaddr_in6>.size), &hostname, socklen_t(hostname.count), nil, 0, NI_NAMEREQD)
                }
            }
            if result == 0 {
                return String(cString: hostname)
            }
            if result == EAI_NONAME {
                return nil
            }
            throw LookupError.systemError(code: result)
        }

        throw LookupError.invalidInput
    }

    static func performOnBackgroundQueue<Result>(
        _ operation: @escaping () throws -> Result
    ) async throws -> Result {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                do {
                    continuation.resume(returning: try operation())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
