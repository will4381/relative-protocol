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

/// Normalized connection state exposed by relay adapters.
public enum RelayConnectionState: Sendable, Equatable {
    case setup
    case ready
    case waiting
    case failed(String)
    case cancelled
}

/// Interface for a started relay connection implementation.
/// Ownership: instances are retained by `PacketRelayCoordinator`.
public protocol RelayConnection: AnyObject, Sendable {
    /// Called when connection lifecycle state changes.
    var stateUpdate: (@Sendable (RelayConnectionState) -> Void)? { get set }
    /// Called when path metadata changes.
    var pathUpdate: (@Sendable ([String: String]) -> Void)? { get set }
    /// Begins asynchronous connection establishment.
    func start()
    /// Sends a payload best-effort on the underlying connection.
    /// - Parameter data: Payload to forward.
    func send(_ data: Data)
    /// Cancels the connection and releases underlying resources.
    func cancel()
}

/// Factory for creating relay connections for a given endpoint.
public protocol RelayConnectionFactory: Sendable {
    /// Constructs a connection bound to the supplied endpoint.
    /// - Parameter endpoint: Destination transport details.
    func makeConnection(endpoint: RelayEndpoint) -> RelayConnection
}
