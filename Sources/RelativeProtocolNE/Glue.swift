// Compile this glue only for iOS where RelativeProtocolEngine exists
#if os(iOS)
import Foundation
import Network
import NetworkExtension
import RelativeProtocol

public enum RelativeProtocolNE {
    public static func makeFactory(provider: NEPacketTunnelProvider) -> EgressConnectionFactory {
        // Derive preferred interface type from provider's defaultPath
        // Keep selection simple and portable across SDK variations
        let preferredType: NWInterface.InterfaceType? = nil
        return EgressConnectionFactory(
            makeTCP: { host, port, _ in
                let params = NWParameters.tcp
                params.prohibitedInterfaceTypes = [.other]
                if let t = preferredType { params.requiredInterfaceType = t }
                return GlueTCPTransport(host: host, port: port, params: params)
            },
            makeUDP: { host, port, _ in
                let params = NWParameters.udp
                params.prohibitedInterfaceTypes = [.other]
                if let t = preferredType { params.requiredInterfaceType = t }
                return GlueUDPTransport(host: host, port: port, params: params)
            }
        )
    }

    // One-liner helper
    public static func configure(engine: RelativeProtocolEngine, with provider: NEPacketTunnelProvider) {
        engine.connectionFactory = makeFactory(provider: provider)
    }
}

// Local NE-backed adapters; hidden behind the factory and not exported in core target
final class GlueTCPTransport: NSObject, TCPTransport {
    private let conn: NWConnection
    var stateChanged: ((TransportState) -> Void)?

    init(host: String, port: UInt16, params: NWParameters) {
        let endpoint = NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
        self.conn = NWConnection(to: endpoint, using: params)
        super.init()
        self.conn.stateUpdateHandler = { [weak self] state in
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

    func start(queue: DispatchQueue) { conn.start(queue: queue) }
    func send(_ data: Data) { conn.send(content: data, completion: .contentProcessed { _ in }) }
    func closeWrite() { conn.send(content: nil, completion: .contentProcessed { _ in }) }
    func receive(minimumIncompleteLength: Int, maximumLength: Int, handler: @escaping (Data?, Bool, Error?) -> Void) {
        conn.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength) { data, _, isComplete, error in
            handler(data, isComplete, error)
        }
    }
    func cancel() { conn.cancel() }
}

final class GlueUDPTransport: NSObject, UDPTransport {
    private let conn: NWConnection
    var stateChanged: ((TransportState) -> Void)?

    init(host: String, port: UInt16, params: NWParameters) {
        let endpoint = NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
        self.conn = NWConnection(to: endpoint, using: params)
        super.init()
        self.conn.stateUpdateHandler = { [weak self] state in
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

    func start(queue: DispatchQueue) { conn.start(queue: queue) }
    func send(_ data: Data) { conn.send(content: data, completion: .contentProcessed { _ in }) }
    func receiveMessage(handler: @escaping (Data?, Error?) -> Void) {
        conn.receiveMessage { data, _, _, error in
            handler(data, error)
        }
    }
    func cancel() { conn.cancel() }
}

// Non-iOS builds: keep an empty shim to satisfy the target
#else
// Intentionally empty; iOS-only glue
#endif

