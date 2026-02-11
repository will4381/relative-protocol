// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation
import Network
@preconcurrency import NetworkExtension
import XCTest
@testable import RelativeProtocolTunnel

final class Socks5AdapterEdgeTests: XCTestCase {
    func testPathHelperNameMappings() {
        XCTAssertEqual(_test_interfaceTypeName(.cellular), "cellular")
        XCTAssertEqual(_test_interfaceTypeName(.wifi), "wifi")
        XCTAssertEqual(_test_interfaceTypeName(.wiredEthernet), "wired")
        XCTAssertEqual(_test_interfaceTypeName(.loopback), "loopback")
        XCTAssertEqual(_test_interfaceTypeName(.other), "other")

        XCTAssertEqual(_test_pathStatusName(.satisfied), "satisfied")
        XCTAssertEqual(_test_pathStatusName(.unsatisfied), "unsatisfied")
        XCTAssertEqual(_test_pathStatusName(.requiresConnection), "requires-connection")
        XCTAssertEqual(_test_pathSummary(nil), "status=unknown uses=unknown")
    }

    func testNWTCPConnectionAdapterReadWriteCancel() {
        let connection = FakeNWTCPConnection()
        let adapter = NWTCPConnectionAdapter(connection)
        let read = expectation(description: "tcp read callback")
        let write = expectation(description: "tcp write callback")

        adapter.readMinimumLength(1, maximumLength: 1024) { data, error in
            XCTAssertEqual(data, Data([0x01, 0x02]))
            XCTAssertNil(error)
            read.fulfill()
        }

        adapter.write(Data([0xAA, 0xBB])) { error in
            XCTAssertNil(error)
            write.fulfill()
        }

        connection.emitRead(Data([0x01, 0x02]), error: nil)

        wait(for: [read, write], timeout: 1.0)
        XCTAssertEqual(connection.writes, [Data([0xAA, 0xBB])])

        adapter.cancel()
        XCTAssertTrue(connection.cancelled)
    }

    func testNWUDPSessionAdapterReadWriteCancel() {
        let session = FakeNWUDPSession()
        let adapter = NWUDPSessionAdapter(session)
        let read = expectation(description: "udp read callback")
        let write = expectation(description: "udp write callback")

        adapter.setReadHandler({ datagrams, error in
            XCTAssertEqual(datagrams, [Data([0x10])])
            XCTAssertNil(error)
            read.fulfill()
        }, maxDatagrams: 8)

        adapter.writeDatagram(Data([0x20])) { error in
            XCTAssertNil(error)
            write.fulfill()
        }

        session.emitRead([Data([0x10])], error: nil)

        wait(for: [read, write], timeout: 1.0)
        XCTAssertEqual(session.writes, [Data([0x20])])

        adapter.cancel()
        XCTAssertTrue(session.cancelled)
    }

    func testPacketTunnelProviderAdapterUsesNWConnectionsForValidPorts() {
        let provider = RelativePacketTunnelProvider()
        let adapter = PacketTunnelProviderAdapter(provider: provider, queue: DispatchQueue(label: "adapter.valid"))

        let tcp = adapter.makeTCPConnection(
            to: NWHostEndpoint(hostname: "127.0.0.1", port: "443"),
            enableTLS: false,
            tlsParameters: nil,
            delegate: nil
        )
        let udp = adapter.makeUDPSession(to: NWHostEndpoint(hostname: "127.0.0.1", port: "53"))

        XCTAssertTrue(tcp is NWConnectionTCPAdapter)
        XCTAssertTrue(udp is NWConnectionUDPSessionAdapter)

        tcp.cancel()
        udp.cancel()
    }

    func testPacketTunnelProviderAdapterFallsBackForInvalidPorts() {
        let provider = RelativePacketTunnelProvider()
        let adapter = PacketTunnelProviderAdapter(provider: provider, queue: DispatchQueue(label: "adapter.fallback"))

        let tcp = adapter.makeTCPConnection(
            to: NWHostEndpoint(hostname: "example.com", port: "not-a-port"),
            enableTLS: false,
            tlsParameters: nil,
            delegate: nil
        )
        let udp = adapter.makeUDPSession(to: NWHostEndpoint(hostname: "example.com", port: "still-invalid"))

        XCTAssertTrue(tcp is NWTCPConnectionAdapter)
        XCTAssertTrue(udp is NWUDPSessionAdapter)

        tcp.cancel()
        udp.cancel()
    }

    func testNWConnectionTCPAdapterHandlesConnectionFailure() {
        let queue = DispatchQueue(label: "adapter.tcp.failure")
        let unusedPort = reserveUnusedPort()
        let connection = NWConnection(host: .ipv4(IPv4Address("127.0.0.1")!), port: unusedPort, using: .tcp)
        let adapter = NWConnectionTCPAdapter(connection, queue: queue)

        let failed = expectation(description: "tcp failure read callback")
        adapter.readMinimumLength(1, maximumLength: 64) { data, error in
            if data == nil && error != nil {
                failed.fulfill()
            }
        }

        wait(for: [failed], timeout: 2.0)
        adapter.cancel()
    }
}

private final class FakeNWTCPConnection: NWTCPConnection {
    private var readHandler: ((Data?, Error?) -> Void)?
    private(set) var writes: [Data] = []
    private(set) var cancelled = false

    override func readMinimumLength(
        _ minimum: Int,
        maximumLength maximum: Int,
        completionHandler: @escaping (Data?, (any Error)?) -> Void
    ) {
        _ = minimum
        _ = maximum
        readHandler = completionHandler
    }

    override func write(_ data: Data, completionHandler: @escaping ((any Error)?) -> Void) {
        writes.append(data)
        completionHandler(nil)
    }

    override func cancel() {
        cancelled = true
    }

    func emitRead(_ data: Data?, error: Error?) {
        readHandler?(data, error)
    }
}

private final class FakeNWUDPSession: NWUDPSession {
    private var readHandler: (([Data]?, Error?) -> Void)?
    private(set) var writes: [Data] = []
    private(set) var cancelled = false

    override func setReadHandler(_ handler: @escaping ([Data]?, (any Error)?) -> Void, maxDatagrams: Int) {
        _ = maxDatagrams
        readHandler = handler
    }

    override func writeDatagram(_ datagram: Data, completionHandler: @escaping ((any Error)?) -> Void) {
        writes.append(datagram)
        completionHandler(nil)
    }

    override func cancel() {
        cancelled = true
    }

    func emitRead(_ datagrams: [Data]?, error: Error?) {
        readHandler?(datagrams, error)
    }
}

private func reserveUnusedPort() -> Network.NWEndpoint.Port {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    precondition(fd >= 0)
    defer { close(fd) }

    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = in_port_t(0).bigEndian
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

    let bindResult = withUnsafePointer(to: &addr) {
        bind(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
    }
    precondition(bindResult == 0)

    var actual = sockaddr_in()
    var actualLen = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &actual) {
        getsockname(fd, UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self), &actualLen)
    }

    let portValue = UInt16(bigEndian: actual.sin_port)
    guard let port = Network.NWEndpoint.Port(rawValue: portValue) else {
        return Network.NWEndpoint.Port(rawValue: 65535)!
    }
    return port
}
