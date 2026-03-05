import Foundation
import Network

/// `RelayConnection` implementation backed by `NWConnection`.
/// Queue ownership: all Network.framework callbacks are delivered on `queue`.
final class NWConnectionAdapter: RelayConnection, @unchecked Sendable {
    // Docs: https://developer.apple.com/documentation/network/nwconnection
    private let connection: NWConnection
    private let queue: DispatchQueue

    var stateUpdate: (@Sendable (RelayConnectionState) -> Void)?
    var pathUpdate: (@Sendable ([String: String]) -> Void)?

    /// Creates a Network.framework connection adapter.
    /// - Parameters:
    ///   - endpoint: Host/port and transport protocol.
    ///   - queue: Callback delivery queue for connection events.
    init(endpoint: RelayEndpoint, queue: DispatchQueue) {
        self.queue = queue
        let host = NWEndpoint.Host(endpoint.host)
        let port = NWEndpoint.Port(rawValue: endpoint.port) ?? .https
        let parameters: NWParameters = endpoint.useUDP ? .udp : .tcp
        self.connection = NWConnection(host: host, port: port, using: parameters)

        // Docs: https://developer.apple.com/documentation/network/nwconnection/stateupdatehandler
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else {
                return
            }
            switch state {
            case .setup:
                self.stateUpdate?(.setup)
            case .ready:
                self.stateUpdate?(.ready)
            case .waiting(let error):
                self.stateUpdate?(.waiting)
                self.pathUpdate?(["waiting_error": error.localizedDescription])
            case .failed(let error):
                self.stateUpdate?(.failed(error.localizedDescription))
            case .cancelled:
                self.stateUpdate?(.cancelled)
            default:
                self.pathUpdate?(["state": "other"])
            }
        }

        // Docs: https://developer.apple.com/documentation/network/nwconnection/pathupdatehandler
        connection.pathUpdateHandler = { [weak self] path in
            guard let self else {
                return
            }
            self.pathUpdate?(path.metadata)
        }
    }

    func start() {
        // Docs: https://developer.apple.com/documentation/network/nwconnection/start(queue:)
        connection.start(queue: queue)
    }

    /// Sends payload data best-effort over the active connection.
    /// - Parameter data: Serialized payload to write.
    func send(_ data: Data) {
        // Docs: https://developer.apple.com/documentation/network/nwconnection/send(content:contentcontext:iscomplete:completion:)
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    /// Cancels the underlying network connection and releases resources.
    // Docs: https://developer.apple.com/documentation/network/nwconnection/cancel()
    func cancel() {
        connection.cancel()
    }
}

private extension NWPath {
    // Docs: https://developer.apple.com/documentation/network/nwpath
    var metadata: [String: String] {
        [
            "status": String(describing: status),
            "supports_ipv4": supportsIPv4 ? "true" : "false",
            "supports_ipv6": supportsIPv6 ? "true" : "false",
            "supports_dns": supportsDNS ? "true" : "false",
            "is_expensive": isExpensive ? "true" : "false"
        ]
    }
}

public struct NWRelayConnectionFactory: RelayConnectionFactory {
    private let queue: DispatchQueue

    /// - Parameter queue: Dispatch queue used by all created `NWConnection` instances.
    public init(queue: DispatchQueue = DispatchQueue(label: "relay.connection.queue")) {
        self.queue = queue
    }

    /// - Parameter endpoint: Destination transport details.
    /// - Returns: Relay connection configured for the provided endpoint.
    public func makeConnection(endpoint: RelayEndpoint) -> RelayConnection {
        NWConnectionAdapter(endpoint: endpoint, queue: queue)
    }
}
