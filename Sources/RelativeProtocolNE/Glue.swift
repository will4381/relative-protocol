// Compile this glue only for iOS where RelativeProtocolEngine exists
#if os(iOS)
import Foundation
import Network
import NetworkExtension
import RelativeProtocol

// Type aliases to disambiguate between Network and NetworkExtension frameworks
typealias NEEndpoint = NetworkExtension.NWHostEndpoint
typealias NWEndpoint = Network.NWEndpoint

// Enhanced logging function for detailed TCP debugging
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
    static func getPhysicalInterface(type: Network.NWInterface.InterfaceType) -> Network.NWInterface? {
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
        
        // Configure TCP parameters with debugging
        let params = Network.NWParameters.tcp
        
        // Disable path restrictions to ensure the connection can use any available interface
        params.prohibitedInterfaceTypes = []
        params.prohibitExpensivePaths = false
        
        // Set service class for better routing
        params.serviceClass = .responsiveData
        
        neLog("DEBUG", "Creating TCP connection to \(host):\(port) with params: prohibitedTypes=\(params.prohibitedInterfaceTypes?.count ?? 0) expensive=\(params.prohibitExpensivePaths)")
        
        self.connection = Network.NWConnection(to: endpoint, using: params)
        super.init()
        
        self.connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            
            // Enhanced logging to debug TCP issues
            let path = self.connection.currentPath
            let pathInfo = self.describeInterface(path) + " status=\(path?.status ?? .unsatisfied)"
            
            // Additional debugging for path viability
            if let path = path {
                let viableInfo = "isExpensive=\(path.isExpensive) isConstrained=\(path.isConstrained) hasIPv4=\(path.supportsIPv4) hasIPv6=\(path.supportsIPv6) hasDNS=\(path.supportsDNS)"
                neLog("DEBUG", "TCP path viability \(self.host):\(self.port) \(viableInfo)")
                
                // Deep dive into why connection might be stuck
                if path.status == .satisfied {
                    neLog("DEBUG", "TCP path satisfied but connection stuck in state for \(self.host):\(self.port)")
                    let interfaceNames = path.availableInterfaces.map { "\($0.name)-\(String(describing: $0.type))" }.joined(separator: ", ")
                    neLog("DEBUG", "Available interfaces: \(interfaceNames)")
                } else {
                    neLog("WARN", "TCP path not satisfied: \(path.status) for \(self.host):\(self.port)")
                }
            }
            
            switch state {
            case .setup:
                neLog("DEBUG", "TCP setup \(self.host):\(self.port) \(pathInfo)")
                self.stateChanged?(.preparing)
            case .preparing:
                neLog("DEBUG", "TCP preparing \(self.host):\(self.port) \(pathInfo)")
                
                // Set up a timer to detect if we're stuck in preparing
                DispatchQueue.global().asyncAfter(deadline: .now() + 5.0) {
                    if case .preparing = self.connection.state {
                        neLog("WARN", "TCP STUCK in preparing for 5s: \(self.host):\(self.port) - this indicates routing issues")
                        if let currentPath = self.connection.currentPath {
                            neLog("WARN", "Stuck path details: status=\(currentPath.status) interfaces=\(currentPath.availableInterfaces.count)")
                        }
                    }
                }
                
                self.stateChanged?(.preparing)
            case .ready:
                neLog("INFO", "TCP READY \(self.host):\(self.port) \(pathInfo)")
                self.stateChanged?(.ready)
            case .waiting(let err):
                neLog("WARN", "TCP waiting \(self.host):\(self.port) error=\(String(describing: err)) \(pathInfo)")
                self.stateChanged?(.waiting)
            case .failed(let err):
                neLog("ERROR", "TCP FAILED \(self.host):\(self.port) error=\(String(describing: err)) \(pathInfo)")
                self.stateChanged?(.failed(err))
            case .cancelled:
                neLog("INFO", "TCP cancelled \(self.host):\(self.port) \(pathInfo)")
                self.stateChanged?(.cancelled)
            @unknown default:
                neLog("ERROR", "TCP unknown state \(self.host):\(self.port) \(pathInfo)")
                self.stateChanged?(.failed(nil))
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
        neLog("INFO", "Starting TCP connection to \(host):\(port)")
        neLog("INFO", "egress start proto=TCP endpoint=\(host):\(port)")
        
        // Add better error handling
        connection.start(queue: queue)
        
        // Set up a watchdog to detect connection hangs
        DispatchQueue.global().asyncAfter(deadline: .now() + 10.0) {
            if case .preparing = self.connection.state {
                neLog("ERROR", "TCP connection HUNG for 10s: \(self.host):\(self.port) - connection never established")
                // Don't cancel automatically, just log the issue
            }
        }
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
        
        // Configure UDP parameters with explicit options (matching what works)
        let params = Network.NWParameters.udp
        
        // Disable path restrictions to ensure the connection can use any available interface
        params.prohibitedInterfaceTypes = []
        
        // Allow using any available interface
        params.prohibitExpensivePaths = false
        
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

