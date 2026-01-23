import Darwin
import Foundation
import XCTest
import NetworkExtension
@testable import RelativeProtocolTunnel

final class Socks5UDPRelayTests: XCTestCase {
    func testRelayWritesDatagramsToSession() throws {
        let queue = DispatchQueue(label: "socks5.udp.relay.write")
        let session = CapturingUDPSession()
        let provider = FakeUDPProvider(session: session)
        let relay = try Socks5UDPRelay(provider: provider, queue: queue, mtu: 1500)
        relay.start()
        defer { relay.stop() }

        let payload = Data([0x01, 0x02, 0x03])
        let packet = Socks5Codec.buildUDPPacket(address: .ipv4("8.8.8.8"), port: 53, payload: payload)

        let client = try UDPTestClient()
        defer { client.close() }

        let writeExpectation = expectation(description: "udp write")
        session.writeExpectation = writeExpectation

        try client.send(to: relay.port, data: packet)

        wait(for: [writeExpectation], timeout: 1.0)

        XCTAssertEqual(session.writes.first, payload)
        XCTAssertEqual(provider.lastHost, "8.8.8.8")
        XCTAssertEqual(provider.lastPort, "53")
    }

    func testRelayForwardsSessionDatagramsToClient() throws {
        let queue = DispatchQueue(label: "socks5.udp.relay.read")
        let session = CapturingUDPSession()
        let provider = FakeUDPProvider(session: session)
        let relay = try Socks5UDPRelay(provider: provider, queue: queue, mtu: 1500)
        relay.start()
        defer { relay.stop() }

        let client = try UDPTestClient()
        defer { client.close() }

        let primingPayload = Data([0x10, 0x11])
        let primePacket = Socks5Codec.buildUDPPacket(address: .ipv4("1.1.1.1"), port: 53, payload: primingPayload)

        let writeExpectation = expectation(description: "udp write")
        session.writeExpectation = writeExpectation

        try client.send(to: relay.port, data: primePacket)
        wait(for: [writeExpectation], timeout: 1.0)

        let responsePayload = Data([0xAA, 0xBB, 0xCC])
        session.simulateIncoming([responsePayload])

        let response = try client.receive(maxSize: 2048, timeout: 1.0)
        let parsed = Socks5Codec.parseUDPPacket(response)
        XCTAssertEqual(parsed?.address, .ipv4("1.1.1.1"))
        XCTAssertEqual(parsed?.port, 53)
        XCTAssertEqual(parsed?.payload, responsePayload)
    }
}

private final class CapturingUDPSession: Socks5UDPSession {
    private(set) var writes: [Data] = []
    private var readHandler: (([Data]?, Error?) -> Void)?
    var writeExpectation: XCTestExpectation?

    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int) {
        readHandler = handler
    }

    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) {
        writes.append(datagram)
        writeExpectation?.fulfill()
        completionHandler(nil)
    }

    func cancel() {}

    func simulateIncoming(_ datagrams: [Data]) {
        readHandler?(datagrams, nil)
    }
}

private final class FakeUDPProvider: Socks5ConnectionProvider {
    private let session: CapturingUDPSession
    private(set) var lastHost: String?
    private(set) var lastPort: String?

    init(session: CapturingUDPSession) {
        self.session = session
    }

    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound {
        return FakeTCPOutbound()
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        lastHost = endpoint.hostname
        lastPort = endpoint.port
        return session
    }
}

private final class FakeTCPOutbound: Socks5TCPOutbound {
    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void) {}
    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }
    func cancel() {}
}

private final class UDPTestClient {
    private let fd: Int32
    private var addr = sockaddr_in()

    init() throws {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EINVAL) }

        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(0).bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &addr) {
            bind(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
        }
        guard bindResult == 0 else {
            Darwin.close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
    }

    func send(to port: UInt16, data: Data) throws {
        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = in_port_t(port).bigEndian
        destination.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let sent = data.withUnsafeBytes { buffer -> ssize_t in
            guard let base = buffer.baseAddress else { return -1 }
            return withUnsafePointer(to: &destination) {
                sendto(fd, base, buffer.count, 0, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard sent == data.count else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
    }

    func receive(maxSize: Int, timeout: TimeInterval) throws -> Data {
        var tv = timeval()
        tv.tv_sec = Int(timeout)
        tv.tv_usec = __darwin_suseconds_t((timeout - floor(timeout)) * 1_000_000)
        var tvCopy = tv
        let setResult = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tvCopy, socklen_t(MemoryLayout<timeval>.size))
        guard setResult == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        var buffer = [UInt8](repeating: 0, count: maxSize)
        let bytes = recvfrom(fd, &buffer, buffer.count, 0, nil, nil)
        if bytes < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK {
                throw POSIXError(.ETIMEDOUT)
            }
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
        return Data(buffer[0..<bytes])
    }

    func close() {
        Darwin.close(fd)
    }
}
