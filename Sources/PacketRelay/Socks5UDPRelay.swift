import Darwin
import Foundation
import Network
@preconcurrency import NetworkExtension
import Observability

/// Minimal lifecycle for per-connection UDP relay helpers.
protocol Socks5UDPRelayProtocol: AnyObject {
    var port: UInt16 { get }
    func start()
    func stop()
}

/// UDP session abstraction used by SOCKS relay to support Network/NetworkExtension backends.
protocol Socks5UDPSession: AnyObject {
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int)
    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void)
    func cancel()
}

/// Factory interface used by relay to create outbound UDP sessions.
protocol Socks5ConnectionProvider: AnyObject {
    // Docs: https://developer.apple.com/documentation/networkextension/nwhostendpoint
    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession
}

/// SOCKS5 UDP ASSOCIATE relay bound to localhost.
/// Queue ownership: all socket I/O and session mutation happen on `queue`.
final class Socks5UDPRelay: Socks5UDPRelayProtocol {
    private struct SessionKey: Hashable {
        let address: Socks5Address
        let port: UInt16
    }

    private struct SessionEntry {
        let session: Socks5UDPSession
    }

    private let logger: StructuredLogger
    private let provider: Socks5ConnectionProvider
    private let queue: DispatchQueue
    private let mtu: Int

    private var socketFD: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var sessions: [SessionKey: SessionEntry] = [:]
    private var clientAddress = sockaddr_storage()
    private var clientAddressLen: socklen_t = 0

    private(set) var port: UInt16 = 0

    /// - Parameters:
    ///   - provider: Outbound session provider.
    ///   - queue: Serial queue for socket I/O and state.
    ///   - mtu: Max expected datagram size.
    ///   - logger: Structured logger for relay events.
    init(provider: Socks5ConnectionProvider, queue: DispatchQueue, mtu: Int, logger: StructuredLogger) throws {
        self.provider = provider
        self.queue = queue
        self.mtu = max(256, mtu)
        self.logger = logger
        try openSocket()
    }

    /// Starts local UDP socket read loop for SOCKS5 UDP ASSOCIATE traffic.
    func start() {
        guard socketFD >= 0 else { return }
        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainReadable()
        }
        source.setCancelHandler { [socketFD] in
            close(socketFD)
        }
        source.resume()
        readSource = source
    }

    /// Stops socket read loop and cancels all outbound UDP sessions.
    func stop() {
        readSource?.cancel()
        readSource = nil
        sessions.values.forEach { $0.session.cancel() }
        sessions.removeAll()
    }

    private func drainReadable() {
        let bufferSize = mtu + 256
        var buffer = [UInt8](repeating: 0, count: bufferSize)

        while true {
            var addr = sockaddr_storage()
            var addrLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let bytes = recvfrom(socketFD, &buffer, buffer.count, 0, withUnsafeMutablePointer(to: &addr) {
                UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self)
            }, &addrLen)
            if bytes < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    break
                }
                Task {
                    await logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayUDP,
                        component: "Socks5UDPRelay",
                        event: "recv-failed",
                        errorCode: String(errno),
                        message: "UDP relay recvfrom failed"
                    )
                }
                break
            }
            guard bytes > 0 else { break }

            guard let packet = buffer.withUnsafeBufferPointer({ ptr in
                Socks5Codec.parseUDPPacket(ptr, count: bytes)
            }) else {
                continue
            }

            clientAddress = addr
            clientAddressLen = addrLen

            let key = SessionKey(address: packet.address, port: packet.port)
            let entry = sessions[key] ?? createSession(for: key)
            entry.session.writeDatagram(packet.payload) { [weak self] error in
                guard let self, let error else { return }
                Task {
                    await self.logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayUDP,
                        component: "Socks5UDPRelay",
                        event: "write-failed",
                        errorCode: String(describing: error),
                        message: "UDP relay write failed"
                    )
                }
            }
        }
    }

    private func createSession(for key: SessionKey) -> SessionEntry {
        let hostString: String
        switch key.address {
        case .ipv4(let value), .ipv6(let value), .domain(let value):
            hostString = value
        }
        // Docs: https://developer.apple.com/documentation/networkextension/nwhostendpoint
        let endpoint = NWHostEndpoint(hostname: hostString, port: String(key.port))
        let session = provider.makeUDPSession(to: endpoint)
        session.setReadHandler({ [weak self] datagrams, error in
            guard let self else { return }
            if let error {
                Task {
                    await self.logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayUDP,
                        component: "Socks5UDPRelay",
                        event: "read-failed",
                        errorCode: String(describing: error),
                        message: "UDP relay read failed"
                    )
                }
                return
            }
            guard let datagrams, !datagrams.isEmpty else { return }
            for datagram in datagrams {
                let response = Socks5Codec.buildUDPPacket(address: key.address, port: key.port, payload: datagram)
                self.sendToClient(response)
            }
        }, maxDatagrams: 32)

        let entry = SessionEntry(session: session)
        sessions[key] = entry
        return entry
    }

    private func sendToClient(_ data: Data) {
        guard clientAddressLen > 0 else { return }
        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            let sent = withUnsafePointer(to: &clientAddress) {
                sendto(socketFD, base, data.count, 0, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), clientAddressLen)
            }
            if sent < 0, errno != EAGAIN, errno != EWOULDBLOCK {
                Task {
                    await logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayUDP,
                        component: "Socks5UDPRelay",
                        event: "send-failed",
                        errorCode: String(errno),
                        message: "UDP relay sendto failed"
                    )
                }
            }
        }
    }

    private func openSocket() throws {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(0).bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &addr) {
            bind(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
        }
        guard bindResult == 0 else {
            close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        var actual = sockaddr_in()
        var actualLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &actual) {
            getsockname(fd, UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self), &actualLen)
        }
        if nameResult == 0 {
            port = UInt16(bigEndian: actual.sin_port)
        }

        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 {
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }

        socketFD = fd
    }
}
