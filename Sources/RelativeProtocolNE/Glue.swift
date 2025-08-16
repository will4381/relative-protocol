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
                // Use provider's createTCPConnectionThroughTunnel to bypass the VPN tunnel
                let endpoint = NetworkExtension.NWHostEndpoint(hostname: host, port: String(port))
                let tcpConnection = provider.createTCPConnectionThroughTunnel(
                    to: endpoint,
                    enableTLS: false,
                    tlsParameters: nil,
                    delegate: nil
                )
                return ProviderTCPTransport(connection: tcpConnection)
            },
            makeUDP: { host, port, _ in
                // Use provider's createUDPSessionThroughTunnel to bypass the VPN tunnel
                let endpoint = NetworkExtension.NWHostEndpoint(hostname: host, port: String(port))
                let udpSession = provider.createUDPSessionThroughTunnel(
                    to: endpoint,
                    from: nil
                )
                return ProviderUDPTransport(session: udpSession)
            }
        )
    }

    // One-liner helper
    public static func configure(engine: RelativeProtocolEngine, with provider: NEPacketTunnelProvider) {
        engine.connectionFactory = makeFactory(provider: provider)
    }
}

// TCP Transport wrapper for NWTCPConnection that bypasses the tunnel
final class ProviderTCPTransport: NSObject, TCPTransport {
    private let connection: NWTCPConnection
    private var queue: DispatchQueue?
    var stateChanged: ((TransportState) -> Void)?

    init(connection: NWTCPConnection) {
        self.connection = connection
        super.init()
    }

    func start(queue: DispatchQueue) {
        self.queue = queue
        // Tunnel bypass connections are essentially ready immediately
        // Report ready state after a brief delay to ensure handlers are set up
        queue.asyncAfter(deadline: .now() + .milliseconds(10)) { [weak self] in
            self?.stateChanged?(.ready)
        }
    }

    func send(_ data: Data) {
        connection.write(data) { error in
            // Handle write completion if needed
        }
    }

    func closeWrite() {
        connection.write(Data()) { _ in }
    }

    func receive(minimumIncompleteLength: Int, maximumLength: Int, handler: @escaping (Data?, Bool, Error?) -> Void) {
        connection.readMinimumLength(minimumIncompleteLength, maximumLength: maximumLength) { data, error in
            if let error = error {
                handler(nil, true, error)
            } else {
                handler(data, false, nil)
                // Continue reading
                if data != nil {
                    self.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength, handler: handler)
                }
            }
        }
    }

    func cancel() {
        connection.cancel()
    }
}

// UDP Transport wrapper for NWUDPSession that bypasses the tunnel
final class ProviderUDPTransport: NSObject, UDPTransport {
    private let session: NWUDPSession
    private var queue: DispatchQueue?
    var stateChanged: ((TransportState) -> Void)?

    init(session: NWUDPSession) {
        self.session = session
        super.init()
    }

    func start(queue: DispatchQueue) {
        self.queue = queue
        // Tunnel bypass sessions are essentially ready immediately
        // Report ready state after a brief delay to ensure handlers are set up
        queue.asyncAfter(deadline: .now() + .milliseconds(10)) { [weak self] in
            self?.stateChanged?(.ready)
        }
    }

    func send(_ data: Data) {
        session.writeDatagram(data) { error in
            // Handle write completion if needed
        }
    }

    func receiveMessage(handler: @escaping (Data?, Error?) -> Void) {
        // NWUDPSession uses setReadHandler for continuous reading
        session.setReadHandler({ datagrams, error in
            if let error = error {
                handler(nil, error)
            } else if let datagrams = datagrams, !datagrams.isEmpty {
                // Send first datagram
                handler(datagrams.first, nil)
            } else {
                handler(nil, nil)
            }
        }, maxDatagrams: 1)
    }

    func cancel() {
        session.cancel()
    }
}

// Non-iOS builds: keep an empty shim to satisfy the target
#else
// Intentionally empty; iOS-only glue
#endif

