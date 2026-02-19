// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Darwin
import Foundation
import Network
@preconcurrency import NetworkExtension
import XCTest
@testable import RelativeProtocolTunnel

final class Socks5ServerEdgeTests: XCTestCase {
    func testConnectionAcceptsBindCommandAndReturnsFirstReply() {
        let queue = DispatchQueue(label: "socks5.connection.bind")
        let inbound = EdgeFakeInboundConnection()
        let outbound = EdgeFakeTCPOutbound()
        let provider = EdgeFakeProvider(outbound: outbound)
        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1200)
        connection.start()
        defer { connection.stop() }

        var handshake = Data([0x05, 0x01, 0x00])
        handshake.append(buildBindRequest())
        inbound.enqueueInbound(handshake)

        for _ in 0..<50 {
            flush(queue)
            if inbound.sent.count >= 2 {
                break
            }
            usleep(20_000)
        }

        XCTAssertEqual(inbound.sent.count, 2)
        XCTAssertEqual(inbound.sent.first, Socks5Codec.buildMethodSelection(method: 0x00))
        guard let reply = inbound.sent.last else {
            return XCTFail("Expected BIND reply")
        }
        XCTAssertEqual(reply[1], 0x00)
        XCTAssertFalse(inbound.cancelled)
    }

    func testConnectionClosesWhenInputBufferExceedsMaximum() {
        let queue = DispatchQueue(label: "socks5.connection.buffer.limit")
        let inbound = EdgeFakeInboundConnection()
        let outbound = EdgeFakeTCPOutbound()
        let provider = EdgeFakeProvider(outbound: outbound)
        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1200)
        connection.start()

        var payload = Data([0x05, 0x01, 0x00]) // valid greeting
        payload.append(contentsOf: [0x05, 0x01, 0x00, 0x09]) // invalid ATYP keeps parse blocked
        payload.append(Data(repeating: 0xAA, count: 70_000))
        inbound.enqueueInbound(payload)
        flush(queue)

        XCTAssertTrue(inbound.cancelled)
    }

    func testConnectionRejectsUnsupportedAuthMethods() {
        let queue = DispatchQueue(label: "socks5.connection.auth.reject")
        let inbound = EdgeFakeInboundConnection()
        let provider = EdgeFakeProvider(outbound: EdgeFakeTCPOutbound())
        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1200)
        connection.start()

        inbound.enqueueInbound(Data([0x05, 0x02, 0x01, 0x02]))
        flush(queue)

        XCTAssertEqual(inbound.sent, [Socks5Codec.buildMethodSelection(method: 0xFF)])
        XCTAssertTrue(inbound.cancelled)
    }

    func testConnectionStopsWhenOutboundReadReturnsNil() {
        let queue = DispatchQueue(label: "socks5.connection.read.nil")
        let inbound = EdgeFakeInboundConnection()
        let outbound = EdgeFakeTCPOutbound()
        let provider = EdgeFakeProvider(outbound: outbound)
        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1200)
        connection.start()

        var handshake = Data([0x05, 0x01, 0x00])
        handshake.append(buildConnectRequest(host: "example.com", port: 80))
        inbound.enqueueInbound(handshake)
        flush(queue)

        outbound.emitRead(nil, error: nil)
        flush(queue)
        XCTAssertTrue(inbound.cancelled)
    }

    func testConnectionStopsWhenOutboundReadErrors() {
        let queue = DispatchQueue(label: "socks5.connection.read.error")
        let inbound = EdgeFakeInboundConnection()
        let outbound = EdgeFakeTCPOutbound()
        let provider = EdgeFakeProvider(outbound: outbound)
        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1200)
        connection.start()

        var handshake = Data([0x05, 0x01, 0x00])
        handshake.append(buildConnectRequest(host: "example.com", port: 80))
        inbound.enqueueInbound(handshake)
        flush(queue)

        outbound.emitRead(nil, error: NSError(domain: "test", code: 42))
        flush(queue)
        XCTAssertTrue(inbound.cancelled)
    }

    func testConnectionStopsWhenOutboundWriteFails() {
        let queue = DispatchQueue(label: "socks5.connection.write.error")
        let inbound = EdgeFakeInboundConnection()
        let outbound = EdgeFakeTCPOutbound()
        outbound.nextWriteError = NSError(domain: "test", code: 43)
        let provider = EdgeFakeProvider(outbound: outbound)
        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1200)
        connection.start()

        var handshake = Data([0x05, 0x01, 0x00])
        handshake.append(buildConnectRequest(host: "example.com", port: 80))
        inbound.enqueueInbound(handshake)
        flush(queue)

        inbound.enqueueInbound(Data([0xde, 0xad, 0xbe, 0xef]))
        flush(queue)
        XCTAssertTrue(inbound.cancelled)
    }

    func testUDPRelayFactoryFailureReturnsFailureReply() {
        let queue = DispatchQueue(label: "socks5.connection.udp.factory.failure")
        let inbound = EdgeFakeInboundConnection()
        let provider = EdgeFakeProvider(outbound: EdgeFakeTCPOutbound())
        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1200,
            udpRelayFactory: { _, _, _ in
                throw NSError(domain: "relay", code: 1)
            }
        )
        connection.start()

        var handshake = Data([0x05, 0x01, 0x00])
        handshake.append(buildUDPAssociateRequest())
        inbound.enqueueInbound(handshake)
        flush(queue)

        XCTAssertEqual(inbound.sent.count, 2)
        XCTAssertEqual(inbound.sent.first, Socks5Codec.buildMethodSelection(method: 0x00))
        guard let reply = inbound.sent.last else {
            return XCTFail("Missing failure reply")
        }
        XCTAssertEqual(reply[1], 0x07)
        XCTAssertTrue(inbound.cancelled)
    }

    func testServerStartAcceptsConnectionsAndForwardsRequests() throws {
        let queue = DispatchQueue(label: "socks5.server.edge.start")
        let provider = EdgeRecordingProvider(outbound: EdgeFakeTCPOutbound())
        let server = Socks5Server(provider: provider, queue: queue, mtu: 1500)

        var startedPort: UInt16?
        let started = expectation(description: "server started")
        server.start(port: 0) { result in
            switch result {
            case .success(let port):
                startedPort = port
            case .failure(let error):
                XCTFail("Expected success, got \(error)")
            }
            started.fulfill()
        }
        wait(for: [started], timeout: 2.0)

        guard let port = startedPort else {
            server.stop()
            return XCTFail("Missing started port")
        }

        let client = try EdgeTCPClient(port: port)
        defer {
            client.close()
            server.stop()
        }

        var handshake = Data([0x05, 0x01, 0x00])
        handshake.append(buildConnectRequest(host: "example.com", port: 80))
        try client.send(handshake)

        let methodSelection = try client.receive(expectedLength: 2)
        XCTAssertEqual(methodSelection, Socks5Codec.buildMethodSelection(method: 0x00))

        let reply = try client.receive(expectedLength: 10)
        XCTAssertEqual(reply.first, 0x05)
        XCTAssertEqual(reply[1], 0x00)
        XCTAssertEqual(provider.lastHost, "example.com")
        XCTAssertEqual(provider.lastPort, "80")
    }

    func testBindCommandAcceptsInboundConnectionAndRelaysTraffic() throws {
        let queue = DispatchQueue(label: "socks5.server.edge.bind")
        let provider = EdgeRecordingProvider(outbound: EdgeFakeTCPOutbound())
        let server = Socks5Server(provider: provider, queue: queue, mtu: 1500)

        var startedPort: UInt16?
        let started = expectation(description: "server started")
        server.start(port: 0) { result in
            if case .success(let port) = result {
                startedPort = port
            }
            started.fulfill()
        }
        wait(for: [started], timeout: 2.0)

        guard let port = startedPort else {
            server.stop()
            return XCTFail("Missing started port")
        }

        let socksClient = try EdgeTCPClient(port: port)
        defer {
            socksClient.close()
            server.stop()
        }

        var handshake = Data([0x05, 0x01, 0x00])
        handshake.append(buildBindRequest())
        try socksClient.send(handshake)

        let methodSelection = try socksClient.receive(expectedLength: 2)
        XCTAssertEqual(methodSelection, Socks5Codec.buildMethodSelection(method: 0x00))

        let firstReply = try socksClient.receive(expectedLength: 10, timeout: 2.0)
        XCTAssertEqual(firstReply[1], 0x00)
        let bindPort = UInt16(firstReply[8]) << 8 | UInt16(firstReply[9])
        XCTAssertGreaterThan(bindPort, 0)

        let inboundPeer = try EdgeTCPClient(port: bindPort)
        defer { inboundPeer.close() }

        let secondReply = try socksClient.receive(expectedLength: 10, timeout: 2.0)
        XCTAssertEqual(secondReply[1], 0x00)

        let messageToPeer = Data("hello-bind".utf8)
        try socksClient.send(messageToPeer)
        let peerData = try inboundPeer.receive(expectedLength: 64, timeout: 2.0)
        XCTAssertEqual(peerData, messageToPeer)

        let messageToSocks = Data("reply-bind".utf8)
        try inboundPeer.send(messageToSocks)
        let socksData = try socksClient.receive(expectedLength: 64, timeout: 2.0)
        XCTAssertEqual(socksData, messageToSocks)
    }

    func testServerStopIsSafeWithoutStart() {
        let server = Socks5Server(
            provider: EdgeFakeProvider(outbound: EdgeFakeTCPOutbound()),
            queue: DispatchQueue(label: "socks5.server.stop.no.start"),
            mtu: 1200
        )
        server.stop()
        server.stop()
    }

    func testServerRetriesWhenRequestedPortIsInUse() throws {
        let occupied = try EdgeTCPListener()
        defer { occupied.close() }

        let queue = DispatchQueue(label: "socks5.server.retry.inuse")
        let provider = EdgeRecordingProvider(outbound: EdgeFakeTCPOutbound())
        let server = Socks5Server(provider: provider, queue: queue, mtu: 1200)
        defer { server.stop() }

        let started = expectation(description: "server started on fallback port")
        var resolvedPort: UInt16?
        server.start(port: occupied.port) { result in
            if case .success(let port) = result {
                resolvedPort = port
            }
            started.fulfill()
        }
        wait(for: [started], timeout: 2.0)

        let port = try XCTUnwrap(resolvedPort)
        XCTAssertNotEqual(port, occupied.port)
    }

    func testServerStopPreventsDelayedRetryRebind() throws {
        let occupied = try EdgeTCPListener()
        defer { occupied.close() }

        let queue = DispatchQueue(label: "socks5.server.retry.cancelled")
        let provider = EdgeRecordingProvider(outbound: EdgeFakeTCPOutbound())
        let server = Socks5Server(provider: provider, queue: queue, mtu: 1200)

        let completion = expectation(description: "start completion should not fire after stop")
        completion.isInverted = true

        server.start(port: occupied.port) { _ in
            completion.fulfill()
        }
        server.stop()

        wait(for: [completion], timeout: 0.7)
    }

    func testProbeLoopbackHelperExecutesWithoutCrashing() throws {
        let listener = try EdgeTCPListener()
        defer { listener.close() }

        let queue = DispatchQueue(label: "socks5.server.probe.loopback")
        let server = Socks5Server(
            provider: EdgeFakeProvider(outbound: EdgeFakeTCPOutbound()),
            queue: queue,
            mtu: 1200
        )

        server._test_probeLoopback(port: listener.port)

        let settled = expectation(description: "probe settled")
        queue.asyncAfter(deadline: .now() + 1.2) {
            settled.fulfill()
        }
        wait(for: [settled], timeout: 2.0)
    }

    func testAddressInUseDetectionHelper() {
        let server = Socks5Server(
            provider: EdgeFakeProvider(outbound: EdgeFakeTCPOutbound()),
            queue: DispatchQueue(label: "socks5.server.addr.in.use"),
            mtu: 1200
        )
        XCTAssertTrue(server._test_isAddressInUse(.posix(.EADDRINUSE)))
        XCTAssertFalse(server._test_isAddressInUse(.posix(.ECONNREFUSED)))
    }
}

private final class EdgeFakeInboundConnection: Socks5InboundConnection {
    var stateUpdateHandler: ((NWConnection.State) -> Void)?
    private var pendingReceive: ((Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)?
    private var queuedData: [(Data, Bool)] = []
    private var queue: DispatchQueue?
    private(set) var sent: [Data] = []
    private(set) var cancelled = false

    func start(queue: DispatchQueue) {
        self.queue = queue
        stateUpdateHandler?(.ready)
    }

    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        if let next = queuedData.first {
            queuedData.removeFirst()
            completion(next.0, nil, next.1, nil)
        } else {
            pendingReceive = completion
        }
    }

    func send(content: Data?, completion: NWConnection.SendCompletion) {
        if let content {
            sent.append(content)
        }
        switch completion {
        case .contentProcessed(let handler):
            handler(nil)
        case .idempotent:
            break
        @unknown default:
            break
        }
    }

    func cancel() {
        cancelled = true
        stateUpdateHandler?(.cancelled)
    }

    func enqueueInbound(_ data: Data, isComplete: Bool = false) {
        let work = {
            if let pending = self.pendingReceive {
                self.pendingReceive = nil
                pending(data, nil, isComplete, nil)
            } else {
                self.queuedData.append((data, isComplete))
            }
        }
        if let queue {
            queue.async(execute: work)
        } else {
            work()
        }
    }
}

private final class EdgeFakeTCPOutbound: Socks5TCPOutbound {
    private var readHandler: ((Data?, Error?) -> Void)?
    private(set) var writes: [Data] = []
    private(set) var cancelled = false
    var nextWriteError: Error?

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void) {
        readHandler = completionHandler
    }

    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void) {
        writes.append(data)
        let error = nextWriteError
        nextWriteError = nil
        completionHandler(error)
    }

    func cancel() {
        cancelled = true
    }

    func emitRead(_ data: Data?, error: Error?) {
        readHandler?(data, error)
    }
}

private final class EdgeFakeProvider: Socks5ConnectionProvider {
    private let outbound: EdgeFakeTCPOutbound

    init(outbound: EdgeFakeTCPOutbound) {
        self.outbound = outbound
    }

    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound {
        outbound
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        EdgeFakeUDPSession()
    }
}

private final class EdgeRecordingProvider: Socks5ConnectionProvider {
    private let outbound: EdgeFakeTCPOutbound
    private(set) var lastHost: String?
    private(set) var lastPort: String?

    init(outbound: EdgeFakeTCPOutbound) {
        self.outbound = outbound
    }

    func makeTCPConnection(
        to endpoint: NWHostEndpoint,
        enableTLS: Bool,
        tlsParameters: NWTLSParameters?,
        delegate: NWTCPConnectionAuthenticationDelegate?
    ) -> Socks5TCPOutbound {
        lastHost = endpoint.hostname
        lastPort = endpoint.port
        return outbound
    }

    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession {
        EdgeFakeUDPSession()
    }
}

private final class EdgeFakeUDPSession: Socks5UDPSession {
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int) {}
    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }
    func cancel() {}
}

private final class EdgeTCPClient {
    private let fd: Int32

    init(port: UInt16) throws {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EINVAL) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            connect(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
        }
        guard result == 0 else {
            Darwin.close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
    }

    func send(_ data: Data) throws {
        let sent = data.withUnsafeBytes { ptr -> ssize_t in
            guard let base = ptr.baseAddress else { return -1 }
            return Darwin.send(fd, base, ptr.count, 0)
        }
        guard sent == data.count else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
    }

    func receive(expectedLength: Int, timeout: TimeInterval = 1.0) throws -> Data {
        var tv = timeval()
        tv.tv_sec = Int(timeout)
        tv.tv_usec = __darwin_suseconds_t((timeout - floor(timeout)) * 1_000_000)
        var copy = tv
        let set = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &copy, socklen_t(MemoryLayout<timeval>.size))
        guard set == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        var buffer = [UInt8](repeating: 0, count: expectedLength)
        let read = Darwin.recv(fd, &buffer, buffer.count, 0)
        if read < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK {
                throw POSIXError(.ETIMEDOUT)
            }
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
        return Data(buffer[0..<read])
    }

    func close() {
        Darwin.close(fd)
    }
}

private final class EdgeTCPListener {
    private let fd: Int32
    let port: UInt16

    init() throws {
        let localFD = socket(AF_INET, SOCK_STREAM, 0)
        guard localFD >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EINVAL) }

        var reuse: Int32 = 1
        _ = setsockopt(localFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(0).bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &addr) {
            Darwin.bind(localFD, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
        }
        guard bindResult == 0 else {
            Darwin.close(localFD)
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        guard Darwin.listen(localFD, 1) == 0 else {
            Darwin.close(localFD)
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        var actual = sockaddr_in()
        var actualLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) {
            Darwin.getsockname(localFD, UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self), &actualLen)
        }
        fd = localFD
        port = UInt16(bigEndian: actual.sin_port)
    }

    func close() {
        Darwin.close(fd)
    }
}

private func buildConnectRequest(host: String, port: UInt16) -> Data {
    var data = Data([0x05, 0x01, 0x00, 0x03, UInt8(host.utf8.count)])
    data.append(contentsOf: host.utf8)
    data.append(UInt8((port >> 8) & 0xFF))
    data.append(UInt8(port & 0xFF))
    return data
}

private func buildBindRequest() -> Data {
    Data([
        0x05, 0x02, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ])
}

private func buildUDPAssociateRequest() -> Data {
    Data([
        0x05, 0x03, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ])
}

private func flush(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
    let expectation = XCTestExpectation(description: "queue flush")
    queue.async { expectation.fulfill() }
    let result = XCTWaiter.wait(for: [expectation], timeout: timeout)
    XCTAssertEqual(result, .completed)
}
