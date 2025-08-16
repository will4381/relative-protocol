// Compile this glue only for iOS where RelativeProtocolEngine exists
#if os(iOS)
import Foundation
import Network
import NetworkExtension
import RelativeProtocol

public enum RelativeProtocolNE {
    public static func makeFactory(provider: NEPacketTunnelProvider) -> EgressConnectionFactory {
        return EgressConnectionFactory(
            makeTCP: { host, port, _ in
                // Use regular NWConnection which automatically bypasses the tunnel when created from within Network Extension
                let params = NWParameters.tcp
                // DO NOT prohibit .other interface - that was causing the routing loop
                // iOS automatically prevents Network Extension connections from routing through the tunnel
                params.allowLocalEndpointReuse = true
                params.preferNoProxies = true
                
                let endpoint: NWEndpoint
                if let ipv4 = IPv4Address(host) {
                    endpoint = NWEndpoint.hostPort(host: .ipv4(ipv4), port: .init(rawValue: port)!)
                } else if let ipv6 = IPv6Address(host) {
                    endpoint = NWEndpoint.hostPort(host: .ipv6(ipv6), port: .init(rawValue: port)!)
                } else {
                    endpoint = NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
                }
                
                return BypassTCPTransport(endpoint: endpoint, params: params)
            },
            makeUDP: { host, port, _ in
                // Use regular NWConnection which automatically bypasses the tunnel when created from within Network Extension
                let params = NWParameters.udp
                // DO NOT prohibit .other interface - that was causing the routing loop
                // iOS automatically prevents Network Extension connections from routing through the tunnel
                params.allowLocalEndpointReuse = true
                params.preferNoProxies = true
                
                let endpoint: NWEndpoint
                if let ipv4 = IPv4Address(host) {
                    endpoint = NWEndpoint.hostPort(host: .ipv4(ipv4), port: .init(rawValue: port)!)
                } else if let ipv6 = IPv6Address(host) {
                    endpoint = NWEndpoint.hostPort(host: .ipv6(ipv6), port: .init(rawValue: port)!)
                } else {
                    endpoint = NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
                }
                
                return BypassUDPTransport(endpoint: endpoint, params: params)
            }
        )
    }

    // One-liner helper
    public static func configure(engine: RelativeProtocolEngine, with provider: NEPacketTunnelProvider) {
        engine.connectionFactory = makeFactory(provider: provider)
    }
}

// TCP Transport using regular NWConnection that automatically bypasses tunnel from Network Extension
final class BypassTCPTransport: NSObject, TCPTransport {
    private let connection: NWConnection
    var stateChanged: ((TransportState) -> Void)?

    init(endpoint: NWEndpoint, params: NWParameters) {
        self.connection = NWConnection(to: endpoint, using: params)
        super.init()
        self.connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .setup, .preparing:
                self.stateChanged?(.preparing)
            case .ready:
                self.stateChanged?(.ready)
            case .waiting:
                self.stateChanged?(.waiting)
            case .failed(let err):
                self.stateChanged?(.failed(err))
            case .cancelled:
                self.stateChanged?(.cancelled)
            @unknown default:
                self.stateChanged?(.failed(nil))
            }
        }
    }

    func start(queue: DispatchQueue) {
        connection.start(queue: queue)
    }

    func send(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    func closeWrite() {
        connection.send(content: nil, completion: .contentProcessed { _ in })
    }

    func receive(minimumIncompleteLength: Int, maximumLength: Int, handler: @escaping (Data?, Bool, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength) { data, _, isComplete, error in
            handler(data, isComplete, error)
        }
    }

    func cancel() {
        connection.cancel()
    }
}

// UDP Transport using regular NWConnection that automatically bypasses tunnel from Network Extension
final class BypassUDPTransport: NSObject, UDPTransport {
    private let connection: NWConnection
    var stateChanged: ((TransportState) -> Void)?

    init(endpoint: NWEndpoint, params: NWParameters) {
        self.connection = NWConnection(to: endpoint, using: params)
        super.init()
        self.connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .setup, .preparing:
                self.stateChanged?(.preparing)
            case .ready:
                self.stateChanged?(.ready)
            case .waiting:
                self.stateChanged?(.waiting)
            case .failed(let err):
                self.stateChanged?(.failed(err))
            case .cancelled:
                self.stateChanged?(.cancelled)
            @unknown default:
                self.stateChanged?(.failed(nil))
            }
        }
    }

    func start(queue: DispatchQueue) {
        connection.start(queue: queue)
    }

    func send(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    func receiveMessage(handler: @escaping (Data?, Error?) -> Void) {
        connection.receiveMessage { data, _, _, error in
            handler(data, error)
        }
    }

    func cancel() {
        connection.cancel()
    }
}

// Non-iOS builds: keep an empty shim to satisfy the target
#else
// Intentionally empty; iOS-only glue
#endif

