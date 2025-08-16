// Compile this glue only for iOS where RelativeProtocolEngine exists
#if os(iOS)
import Foundation
import Network
import NetworkExtension
import RelativeProtocol

// Local logging helper (this target cannot access RelativeProtocol's internal logger)
private func neLog(_ level: String, _ message: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    print("[RelativeProtocolNE][\(ts)][\(level)] \(message)")
}

public enum RelativeProtocolNE {
    public static func makeFactory(provider: NEPacketTunnelProvider) -> EgressConnectionFactory {
        return EgressConnectionFactory(
            makeTCP: { host, port, _ in
                let params = Network.NWParameters.tcp
                params.allowLocalEndpointReuse = true
                params.preferNoProxies = true
                // Ensure we use the underlying physical network and not the TUN (which is .other)
                params.prohibitedInterfaceTypes = [.other]
                
                let endpoint: Network.NWEndpoint
                if let ipv4 = Network.IPv4Address(host) {
                    endpoint = Network.NWEndpoint.hostPort(host: .ipv4(ipv4), port: .init(rawValue: port)!)
                } else if let ipv6 = Network.IPv6Address(host) {
                    endpoint = Network.NWEndpoint.hostPort(host: .ipv6(ipv6), port: .init(rawValue: port)!)
                } else {
                    endpoint = Network.NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
                }
                
                return BypassTCPTransport(endpoint: endpoint, params: params)
            },
            makeUDP: { host, port, _ in
                let params = Network.NWParameters.udp
                params.allowLocalEndpointReuse = true
                params.preferNoProxies = true
                // Ensure we use the underlying physical network and not the TUN (which is .other)
                params.prohibitedInterfaceTypes = [.other]
                
                let endpoint: Network.NWEndpoint
                if let ipv4 = Network.IPv4Address(host) {
                    endpoint = Network.NWEndpoint.hostPort(host: .ipv4(ipv4), port: .init(rawValue: port)!)
                } else if let ipv6 = Network.IPv6Address(host) {
                    endpoint = Network.NWEndpoint.hostPort(host: .ipv6(ipv6), port: .init(rawValue: port)!)
                } else {
                    endpoint = Network.NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
                }
                
                return BypassUDPTransport(endpoint: endpoint, params: params)
            }
        )
    }
    
    // Helper to find available physical interfaces
    private static func getPhysicalInterface(type: Network.NWInterface.InterfaceType) -> Network.NWInterface? {
        // Check if interface is available via path monitor
        let pathMonitor = Network.NWPathMonitor(requiredInterfaceType: type)
        let semaphore = DispatchSemaphore(value: 0)
        var foundInterface: Network.NWInterface?
        
        pathMonitor.pathUpdateHandler = { path in
            if path.status == .satisfied {
                foundInterface = path.availableInterfaces.first { $0.type == type }
            }
            semaphore.signal()
        }
        
        let queue = DispatchQueue(label: "interface-check")
        pathMonitor.start(queue: queue)
        
        // Wait briefly for path update
        _ = semaphore.wait(timeout: .now() + 0.1)
        pathMonitor.cancel()
        
        return foundInterface
    }

    // One-liner helper
    public static func configure(engine: RelativeProtocolEngine, with provider: NEPacketTunnelProvider) {
        engine.connectionFactory = makeFactory(provider: provider)
    }
}

// TCP Transport using regular NWConnection that automatically bypasses tunnel from Network Extension
final class BypassTCPTransport: NSObject, TCPTransport {
    private let connection: Network.NWConnection
    var stateChanged: ((TransportState) -> Void)?

    init(endpoint: Network.NWEndpoint, params: Network.NWParameters) {
        self.connection = Network.NWConnection(to: endpoint, using: params)
        super.init()
        self.connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .setup, .preparing:
                self.stateChanged?(.preparing)
            case .ready:
                self.stateChanged?(.ready)
                let path = self.connection.currentPath
                let ifaceStr: String = {
                    if let p = path {
                        if p.usesInterfaceType(.wifi) { return "wifi" }
                        if p.usesInterfaceType(.cellular) { return "cellular" }
                        if p.usesInterfaceType(.wiredEthernet) { return "wiredEthernet" }
                        if p.usesInterfaceType(.loopback) { return "loopback" }
                        if p.usesInterfaceType(.other) { return "other" }
                    }
                    return "unknown"
                }()
                neLog("INFO", "egress ready proto=TCP endpoint=\(self.connection.endpoint) iface=\(ifaceStr) v4=\(path?.supportsIPv4 ?? false) v6=\(path?.supportsIPv6 ?? false) expensive=\(path?.isExpensive ?? false) constrained=\(path?.isConstrained ?? false)")
            case .waiting:
                self.stateChanged?(.waiting)
                neLog("INFO", "egress waiting proto=TCP endpoint=\(self.connection.endpoint)")
            case .failed(let err):
                self.stateChanged?(.failed(err))
                neLog("WARN", "egress failed proto=TCP endpoint=\(self.connection.endpoint) error=\(String(describing: err))")
            case .cancelled:
                self.stateChanged?(.cancelled)
                neLog("INFO", "egress cancelled proto=TCP endpoint=\(self.connection.endpoint)")
            @unknown default:
                self.stateChanged?(.failed(nil))
            }
        }
    }

    func start(queue: DispatchQueue) {
        neLog("INFO", "egress start proto=TCP endpoint=\(connection.endpoint)")
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
    private let connection: Network.NWConnection
    var stateChanged: ((TransportState) -> Void)?

    init(endpoint: Network.NWEndpoint, params: Network.NWParameters) {
        self.connection = Network.NWConnection(to: endpoint, using: params)
        super.init()
        self.connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .setup, .preparing:
                self.stateChanged?(.preparing)
            case .ready:
                self.stateChanged?(.ready)
                let path = self.connection.currentPath
                let ifaceStr: String = {
                    if let p = path {
                        if p.usesInterfaceType(.wifi) { return "wifi" }
                        if p.usesInterfaceType(.cellular) { return "cellular" }
                        if p.usesInterfaceType(.wiredEthernet) { return "wiredEthernet" }
                        if p.usesInterfaceType(.loopback) { return "loopback" }
                        if p.usesInterfaceType(.other) { return "other" }
                    }
                    return "unknown"
                }()
                neLog("INFO", "egress ready proto=UDP endpoint=\(self.connection.endpoint) iface=\(ifaceStr) v4=\(path?.supportsIPv4 ?? false) v6=\(path?.supportsIPv6 ?? false) expensive=\(path?.isExpensive ?? false) constrained=\(path?.isConstrained ?? false)")
            case .waiting:
                self.stateChanged?(.waiting)
                neLog("INFO", "egress waiting proto=UDP endpoint=\(self.connection.endpoint)")
            case .failed(let err):
                self.stateChanged?(.failed(err))
                neLog("WARN", "egress failed proto=UDP endpoint=\(self.connection.endpoint) error=\(String(describing: err))")
            case .cancelled:
                self.stateChanged?(.cancelled)
                neLog("INFO", "egress cancelled proto=UDP endpoint=\(self.connection.endpoint)")
            @unknown default:
                self.stateChanged?(.failed(nil))
            }
        }
    }

    func start(queue: DispatchQueue) {
        neLog("INFO", "egress start proto=UDP endpoint=\(connection.endpoint)")
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

