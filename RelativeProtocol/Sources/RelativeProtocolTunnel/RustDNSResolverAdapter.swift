//
//  RustDNSResolverAdapter.swift
//  RelativeProtocolTunnel
//
//  Created by Codex on 11/30/2025.
//

import Foundation
import RelativeProtocolCore

enum RustDNSResolverAdapter {
    static func mergedResolver(
        hooksResolver: RelativeProtocol.Configuration.DNSResolver?,
        engineResolver: @escaping RelativeProtocol.Configuration.DNSResolver,
        tracker: @escaping () -> RelativeProtocolTunnel.ForwardHostTracker?
    ) -> RelativeProtocol.Configuration.DNSResolver {
        if let hooksResolver {
            return { host in
                let addresses = try await hooksResolver(host)
                if !addresses.isEmpty {
                    RustEngineMetadataBridge.recordDNS(
                        host: host,
                        addresses: addresses,
                        ttl: nil,
                        tracker: tracker()
                    )
                    return addresses
                }
                return try await engineResolver(host)
            }
        } else {
            return { host in
                try await engineResolver(host)
            }
        }
    }
}
