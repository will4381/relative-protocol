//
//  RustEngineMetadataBridge.swift
//  RelativeProtocolTunnel
//
//  Created by Codex on 11/30/2025.
//

import Foundation

enum RustEngineMetadataBridge {
    static func recordDNS(
        host: String,
        addresses: [String],
        ttl: TimeInterval?,
        tracker: RelativeProtocolTunnel.ForwardHostTracker?
    ) {
        tracker?.record(host: host, addresses: addresses, ttl: ttl)
    }

    static func recordQUIC(
        host: String,
        address: String,
        tracker: RelativeProtocolTunnel.ForwardHostTracker?
    ) {
        tracker?.record(host: host, addresses: [address], ttl: nil)
    }
}
