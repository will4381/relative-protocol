import Foundation

/// Immutable relay destination and transport configuration.
public struct RelayEndpoint: Sendable, Equatable {
    /// DNS name or literal IP for the upstream relay.
    public let host: String
    /// TCP/UDP destination port on the relay.
    public let port: UInt16
    /// `true` selects UDP transport; `false` selects TCP transport.
    public let useUDP: Bool

    /// Creates a relay endpoint value.
    /// - Parameters:
    ///   - host: Relay hostname or IP.
    ///   - port: Relay destination port.
    ///   - useUDP: Transport selector.
    public init(host: String, port: UInt16, useUDP: Bool) {
        self.host = host
        self.port = port
        self.useUDP = useUDP
    }
}
