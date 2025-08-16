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

// TCP Transport using NEPacketTunnelProvider's createTCPConnectionThroughTunnel for proper bypass
final class BypassTCPTransport: NSObject, TCPTransport {
    private let connection: NWTCPConnection
    private let host: String
    private let port: UInt16
    var stateChanged: ((TransportState) -> Void)?

    init(provider: NEPacketTunnelProvider, host: String, port: UInt16) {
        self.host = host
        self.port = port
        
        // Create NetworkExtension endpoint
        let neEndpoint = NetworkExtension.NWHostEndpoint(hostname: host, port: "\(port)")
        
        // Use NetworkExtension's bypass API to create connection outside tunnel
        self.connection = provider.createTCPConnectionThroughTunnel(to: neEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        super.init()
        
        // Monitor connection state using KVO since NWTCPConnection doesn't have stateUpdateHandler
        self.connection.addObserver(self, forKeyPath: "state", options: [.new], context: nil)
    }
    
    deinit {
        self.connection.removeObserver(self, forKeyPath: "state")
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == "state" {
            switch connection.state {
            case .invalid:
                self.stateChanged?(.failed(nil))
                neLog("WARN", "egress invalid proto=TCP endpoint=\(host):\(port)")
            case .connecting:
                self.stateChanged?(.preparing)
            case .waiting:
                self.stateChanged?(.waiting)
                neLog("INFO", "egress waiting proto=TCP endpoint=\(host):\(port)")
            case .connected:
                self.stateChanged?(.ready)
                neLog("INFO", "egress ready proto=TCP endpoint=\(host):\(port)")
            case .disconnected:
                self.stateChanged?(.cancelled)
                neLog("INFO", "egress disconnected proto=TCP endpoint=\(host):\(port)")
            case .cancelled:
                self.stateChanged?(.cancelled)
                neLog("INFO", "egress cancelled proto=TCP endpoint=\(host):\(port)")
            @unknown default:
                self.stateChanged?(.failed(nil))
                neLog("WARN", "egress unknown state proto=TCP endpoint=\(host):\(port)")
            }
        }
    }

    func start(queue: DispatchQueue) {
        neLog("INFO", "egress start proto=TCP endpoint=\(host):\(port)")
        // NWTCPConnection doesn't have explicit start, it connects automatically
    }

    func send(_ data: Data) {
        connection.write(data) { error in
            if let error = error {
                neLog("WARN", "tcp send error endpoint=\(self.host):\(self.port) error=\(error)")
            }
        }
    }

    func closeWrite() {
        connection.writeClose()
    }

    func receive(minimumIncompleteLength: Int, maximumLength: Int, handler: @escaping (Data?, Bool, Error?) -> Void) {
        connection.readMinimumLength(minimumIncompleteLength, maximumLength: maximumLength) { data, error in
            let isComplete = error != nil || data == nil
            handler(data, isComplete, error)
        }
    }

    func cancel() {
        connection.cancel()
    }
}

// UDP Transport using NEPacketTunnelProvider's createUDPSessionThroughTunnel for proper bypass
final class BypassUDPTransport: NSObject, UDPTransport {
    private let session: NWUDPSession
    private let host: String
    private let port: UInt16
    var stateChanged: ((TransportState) -> Void)?

    init(provider: NEPacketTunnelProvider, host: String, port: UInt16) {
        self.host = host
        self.port = port
        
        // Create NetworkExtension endpoint
        let neEndpoint = NetworkExtension.NWHostEndpoint(hostname: host, port: "\(port)")
        
        // Use NetworkExtension's bypass API to create UDP session outside tunnel
        self.session = provider.createUDPSessionThroughTunnel(to: neEndpoint, from: nil)
        super.init()
        
        // Monitor session state
        self.session.addObserver(self, forKeyPath: "state", options: [.new], context: nil)
    }
    
    deinit {
        self.session.removeObserver(self, forKeyPath: "state")
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == "state" {
            switch session.state {
            case .invalid:
                self.stateChanged?(.failed(nil))
                neLog("WARN", "egress invalid proto=UDP endpoint=\(host):\(port)")
            case .waiting:
                self.stateChanged?(.waiting)
                neLog("INFO", "egress waiting proto=UDP endpoint=\(host):\(port)")
            case .preparing:
                self.stateChanged?(.preparing)
            case .ready:
                self.stateChanged?(.ready)
                neLog("INFO", "egress ready proto=UDP endpoint=\(host):\(port)")
            case .cancelled:
                self.stateChanged?(.cancelled)
                neLog("INFO", "egress cancelled proto=UDP endpoint=\(host):\(port)")
            case .failed:
                self.stateChanged?(.failed(nil))
                neLog("WARN", "egress failed proto=UDP endpoint=\(host):\(port)")
            @unknown default:
                self.stateChanged?(.failed(nil))
            }
        }
    }

    func start(queue: DispatchQueue) {
        neLog("INFO", "egress start proto=UDP endpoint=\(host):\(port)")
        // UDP sessions start automatically, no explicit start needed
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            // Give the session a moment to initialize, then check state
            if let state = self?.session.state {
                if state == .ready {
                    self?.stateChanged?(.ready)
                }
            }
        }
    }

    func send(_ data: Data) {
        session.writeDatagram(data) { error in
            if let error = error {
                neLog("WARN", "udp send error endpoint=\(self.host):\(self.port) error=\(error)")
            }
        }
    }

    func receiveMessage(handler: @escaping (Data?, Error?) -> Void) {
        session.setReadHandler({ [weak self] datagrams, error in
            if let error = error {
                handler(nil, error)
                return
            }
            
            // Process first datagram if available
            if let first = datagrams?.first {
                handler(first, nil)
            } else {
                handler(nil, nil)
            }
            
            // Continue reading
            self?.receiveMessage(handler: handler)
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

