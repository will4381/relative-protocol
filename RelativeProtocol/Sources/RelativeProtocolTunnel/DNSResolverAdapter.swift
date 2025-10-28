//
//  DNSResolverAdapter.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Codex on 11/19/2025.
//
//  Provides convenience helpers that bridge the optional AsyncDNSResolver
//  dependency into the lightweight `RelativeProtocol.Configuration.DNSResolver`
//  hook so host applications can resolve hostnames without rewriting boilerplate.
//

import Foundation
import RelativeProtocolCore

#if canImport(AsyncDNSResolver)
import AsyncDNSResolver
#endif

public enum DNSResolverFactory {
    /// Builds a resolver closure backed by the Swift Async DNS Resolver package.
    /// Host applications may install the returned closure onto
    /// `RelativeProtocol.Configuration.Hooks.dnsResolver`.
    ///
    /// The resolver attempts to fetch both A and AAAA records. If both lookups
    /// fail the underlying error is rethrown; otherwise the collected addresses
    /// (as strings) are returned with duplicates removed.
    @available(macOS 11, iOS 15, tvOS 15, watchOS 8, *)
    public static func asyncSystemResolver() throws -> RelativeProtocol.Configuration.DNSResolver {
        #if canImport(AsyncDNSResolver)
        let resolver = try AsyncDNSResolver()
        return { host in
            var results: Set<String> = []
            var firstError: Error?

            do {
                let records = try await resolver.queryA(name: host)
                results.formUnion(records.map { $0.address.address })
            } catch {
                firstError = error
            }

            do {
                let records = try await resolver.queryAAAA(name: host)
                results.formUnion(records.map { $0.address.address })
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }

            if results.isEmpty, let error = firstError {
                throw error
            }

            return Array(results)
        }
        #else
        throw NSError(
            domain: "RelativeProtocolTunnel",
            code: -10,
            userInfo: [NSLocalizedDescriptionKey: "swift-async-dns-resolver is not available on this platform."]
        )
        #endif
    }
}
