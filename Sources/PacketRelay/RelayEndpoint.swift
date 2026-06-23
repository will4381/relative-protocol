// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation

/// Immutable relay transport compatibility configuration.
public struct RelayEndpoint: Sendable, Equatable {
    /// Legacy metadata retained for source compatibility. The dataplane does not use this as an egress destination.
    public let host: String
    /// Legacy metadata retained for source compatibility. The dataplane does not use this as an egress destination.
    public let port: UInt16
    /// `true` selects UDP transport; `false` selects TCP transport.
    public let useUDP: Bool

    /// Creates a relay endpoint value.
    /// - Parameters:
    ///   - host: Legacy relay hostname or IP metadata. Runtime egress is determined by SOCKS requests.
    ///   - port: Legacy relay destination port metadata. Runtime egress is determined by SOCKS requests.
    ///   - useUDP: Transport selector.
    public init(host: String, port: UInt16, useUDP: Bool) {
        self.host = host
        self.port = port
        self.useUDP = useUDP
    }
}
