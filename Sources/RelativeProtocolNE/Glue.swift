// Compile this glue only for iOS where RelativeProtocolEngine exists
#if os(iOS)
import Foundation
import Network
import NetworkExtension
import RelativeProtocol

// Type aliases to disambiguate between Network and NetworkExtension frameworks
typealias NEEndpoint = NetworkExtension.NWHostEndpoint
typealias NWEndpoint = Network.NWEndpoint

// Local logging helper (this target cannot access RelativeProtocol's internal logger)
private func neLog(_ level: String, _ message: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    print("[RelativeProtocolNE][\(ts)][\(level)] \(message)")
}

public enum RelativeProtocolNE {
    public static func makeFactory(provider: NEPacketTunnelProvider) -> EgressConnectionFactory {
        return EgressConnectionFactory(
            makeTCP: { host, port, _ in
                return BypassTCPTransport(provider: provider, host: host, port: port)
            },
            makeUDP: { host, port, _ in
                return BypassUDPTransport(provider: provider, host: host, port: port)
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

// TCP Transport using regular NWConnection (should automatically bypass tunnel per iOS design)
final class BypassTCPTransport: NSObject, TCPTransport {
    private let connection: Network.NWConnection
    private let host: String
    private let port: UInt16
    var stateChanged: ((TransportState) -> Void)?

    init(provider: NEPacketTunnelProvider, host: String, port: UInt16) {
        self.host = host
        self.port = port
        
        // Create standard Network framework endpoint
        let endpoint: Network.NWEndpoint
        if let ipv4 = Network.IPv4Address(host) {
            endpoint = Network.NWEndpoint.hostPort(host: .ipv4(ipv4), port: .init(rawValue: port)!)
        } else if let ipv6 = Network.IPv6Address(host) {
            endpoint = Network.NWEndpoint.hostPort(host: .ipv6(ipv6), port: .init(rawValue: port)!)
        } else {
            endpoint = Network.NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
        }
        
        // Use regular TCP parameters - iOS should automatically exclude from tunnel
        let params = Network.NWParameters.tcp
        
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
                let ifaceInfo = self.describeInterface(path)
                neLog("INFO", "egress ready proto=TCP endpoint=\(self.host):\(self.port) \(ifaceInfo)")
            case .waiting(let err):
                self.stateChanged?(.waiting)
                neLog("INFO", "egress waiting proto=TCP endpoint=\(self.host):\(self.port) error=\(String(describing: err))")
            case .failed(let err):
                self.stateChanged?(.failed(err))
                neLog("WARN", "egress failed proto=TCP endpoint=\(self.host):\(self.port) error=\(String(describing: err))")
            case .cancelled:
                self.stateChanged?(.cancelled)
                neLog("INFO", "egress cancelled proto=TCP endpoint=\(self.host):\(self.port)")
            @unknown default:
                self.stateChanged?(.failed(nil))
                neLog("WARN", "egress unknown state proto=TCP endpoint=\(self.host):\(self.port)")
            }
        }
    }
    
    private func describeInterface(_ path: Network.NWPath?) -> String {
        guard let path = path else { return "iface=unknown" }
        
        var parts: [String] = []
        
        // Interface type
        if path.usesInterfaceType(.wifi) { parts.append("iface=wifi") }
        else if path.usesInterfaceType(.cellular) { parts.append("iface=cellular") }
        else if path.usesInterfaceType(.wiredEthernet) { parts.append("iface=ethernet") }
        else if path.usesInterfaceType(.other) { parts.append("iface=other") }
        else if path.usesInterfaceType(.loopback) { parts.append("iface=loopback") }
        else { parts.append("iface=unknown") }
        
        // Show actual interface name if available
        if let interface = path.availableInterfaces.first {
            parts.append("name=\(interface.name)")
        }
        
        return parts.joined(separator: " ")
    }

    func start(queue: DispatchQueue) {
        neLog("INFO", "egress start proto=TCP endpoint=\(host):\(port)")
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

// UDP Transport using regular NWConnection (should automatically bypass tunnel per iOS design)
final class BypassUDPTransport: NSObject, UDPTransport {
    private let connection: Network.NWConnection
    private let host: String
    private let port: UInt16
    var stateChanged: ((TransportState) -> Void)?

    init(provider: NEPacketTunnelProvider, host: String, port: UInt16) {
        self.host = host
        self.port = port
        
        // Create standard Network framework endpoint
        let endpoint: Network.NWEndpoint
        if let ipv4 = Network.IPv4Address(host) {
            endpoint = Network.NWEndpoint.hostPort(host: .ipv4(ipv4), port: .init(rawValue: port)!)
        } else if let ipv6 = Network.IPv6Address(host) {
            endpoint = Network.NWEndpoint.hostPort(host: .ipv6(ipv6), port: .init(rawValue: port)!)
        } else {
            endpoint = Network.NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
        }
        
        // Use regular UDP parameters - iOS should automatically exclude from tunnel
        let params = Network.NWParameters.udp
        
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
                let ifaceInfo = self.describeInterface(path)
                neLog("INFO", "egress ready proto=UDP endpoint=\(self.host):\(self.port) \(ifaceInfo)")
            case .waiting(let err):
                self.stateChanged?(.waiting)
                neLog("INFO", "egress waiting proto=UDP endpoint=\(self.host):\(self.port) error=\(String(describing: err))")
            case .failed(let err):
                self.stateChanged?(.failed(err))
                neLog("WARN", "egress failed proto=UDP endpoint=\(self.host):\(self.port) error=\(String(describing: err))")
            case .cancelled:
                self.stateChanged?(.cancelled)
                neLog("INFO", "egress cancelled proto=UDP endpoint=\(self.host):\(self.port)")
            @unknown default:
                self.stateChanged?(.failed(nil))
                neLog("WARN", "egress unknown state proto=UDP endpoint=\(self.host):\(self.port)")
            }
        }
    }
    
    private func describeInterface(_ path: Network.NWPath?) -> String {
        guard let path = path else { return "iface=unknown" }
        
        var parts: [String] = []
        
        // Interface type
        if path.usesInterfaceType(.wifi) { parts.append("iface=wifi") }
        else if path.usesInterfaceType(.cellular) { parts.append("iface=cellular") }
        else if path.usesInterfaceType(.wiredEthernet) { parts.append("iface=ethernet") }
        else if path.usesInterfaceType(.other) { parts.append("iface=other") }
        else if path.usesInterfaceType(.loopback) { parts.append("iface=loopback") }
        else { parts.append("iface=unknown") }
        
        // Show actual interface name if available
        if let interface = path.availableInterfaces.first {
            parts.append("name=\(interface.name)")
        }
        
        return parts.joined(separator: " ")
    }

    func start(queue: DispatchQueue) {
        neLog("INFO", "egress start proto=UDP endpoint=\(host):\(port)")
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

