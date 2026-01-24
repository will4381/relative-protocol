// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation
import XCTest
import Network
@preconcurrency import NetworkExtension
@testable import RelativeProtocolTunnel

final class Socks5ConnectionTests: XCTestCase {
    func testConnectHandshakeAndForward() {
        let queue = DispatchQueue(label: "socks5.connection.test")
        let inbound = FakeInboundConnection()
        let outbound = FakeTCPOutbound()
        let provider = FakeProvider(outbound: outbound)

        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1500)
        connection.start()

        let greeting = Data([0x05, 0x01, 0x00])
        let request = buildDomainConnectRequest(host: "example.com", port: 80)
        var handshake = Data()
        handshake.append(greeting)
        handshake.append(request)
        inbound.enqueueInbound(handshake)

        waitOnQueue(queue)

        XCTAssertEqual(inbound.sent.count, 2)
        XCTAssertEqual(inbound.sent.first, Socks5Codec.buildMethodSelection(method: 0x00))
        XCTAssertEqual(inbound.sent.last, Socks5Codec.buildReply(code: 0x00, bindAddress: .ipv4("0.0.0.0"), bindPort: 0))
        XCTAssertEqual(provider.lastHost, "example.com")
        XCTAssertEqual(provider.lastPort, "80")

        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        inbound.enqueueInbound(payload)

        waitOnQueue(queue)

        XCTAssertEqual(outbound.writes.first, payload)
    }

    func testUnsupportedAuthMethodClosesConnection() {
        let queue = DispatchQueue(label: "socks5.connection.test.auth")
        let inbound = FakeInboundConnection()
        let provider = FakeProvider(outbound: FakeTCPOutbound())
        let connection = Socks5Connection(connection: inbound, provider: provider, queue: queue, mtu: 1200)
        connection.start()

        inbound.enqueueInbound(Data([0x05, 0x01, 0x02]))

        waitOnQueue(queue)

        XCTAssertEqual(inbound.sent, [Socks5Codec.buildMethodSelection(method: 0xFF)])
        XCTAssertTrue(inbound.cancelled)
    }

    func testUDPAssociateReplyUsesRelayPort() {
        let queue = DispatchQueue(label: "socks5.connection.test.udp")
        let inbound = FakeInboundConnection()
        let provider = FakeProvider(outbound: FakeTCPOutbound())
        let relay = FakeUDPRelay(port: 43210)

        let connection = Socks5Connection(
            connection: inbound,
            provider: provider,
            queue: queue,
            mtu: 1500,
            udpRelayFactory: { _, _, _ in relay }
        )
        connection.start()

        let greeting = Data([0x05, 0x01, 0x00])
        let request = buildUDPAssociateRequest()
        var handshake = Data()
        handshake.append(greeting)
        handshake.append(request)
        inbound.enqueueInbound(handshake)

        waitOnQueue(queue)

        XCTAssertEqual(inbound.sent.count, 2)
        XCTAssertEqual(inbound.sent.first, Socks5Codec.buildMethodSelection(method: 0x00))

        guard let reply = inbound.sent.last, let parsed = parseReply(reply) else {
            XCTFail("Missing UDP associate reply")
            return
        }
        XCTAssertEqual(parsed.code, 0x00)
        XCTAssertEqual(parsed.address, .ipv4("127.0.0.1"))
        XCTAssertEqual(parsed.port, relay.port)
        XCTAssertTrue(relay.started)
    }
}

private final class FakeInboundConnection: Socks5InboundConnection {
    var stateUpdateHandler: ((NWConnection.State) -> Void)?
    private var pendingReceive: ((Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)?
    private var queuedData: [Data] = []
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
            completion(next, nil, false, nil)
        } else {
            pendingReceive = completion
        }
    }

    func send(content: Data?, completion: NWConnection.SendCompletion) {
        if let data = content {
            sent.append(data)
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
            if let handler = self.pendingReceive {
                self.pendingReceive = nil
                handler(data, nil, isComplete, nil)
            } else {
                self.queuedData.append(data)
            }
        }
        if let queue = queue {
            queue.async(execute: work)
        } else {
            work()
        }
    }
}

private final class FakeTCPOutbound: Socks5TCPOutbound {
    private(set) var writes: [Data] = []
    private var readHandler: ((Data?, Error?) -> Void)?
    private(set) var cancelled = false

    func readMinimumLength(_ minimumLength: Int, maximumLength: Int, completionHandler: @escaping (Data?, Error?) -> Void) {
        readHandler = completionHandler
    }

    func write(_ data: Data, completionHandler: @escaping (Error?) -> Void) {
        writes.append(data)
        completionHandler(nil)
    }

    func cancel() {
        cancelled = true
    }
}

private final class FakeProvider: Socks5ConnectionProvider {
    private let outbound: Socks5TCPOutbound
    private(set) var lastHost: String?
    private(set) var lastPort: String?

    init(outbound: Socks5TCPOutbound) {
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
        FakeUDPSession()
    }
}

private final class FakeUDPSession: Socks5UDPSession {
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void, maxDatagrams: Int) {}
    func writeDatagram(_ datagram: Data, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }
    func cancel() {}
}

private final class FakeUDPRelay: Socks5UDPRelayProtocol {
    let port: UInt16
    private(set) var started = false
    private(set) var stopped = false

    init(port: UInt16) {
        self.port = port
    }

    func start() {
        started = true
    }

    func stop() {
        stopped = true
    }
}

private func buildDomainConnectRequest(host: String, port: UInt16) -> Data {
    var data = Data([0x05, 0x01, 0x00, 0x03, UInt8(host.utf8.count)])
    data.append(contentsOf: host.utf8)
    data.append(UInt8((port >> 8) & 0xFF))
    data.append(UInt8(port & 0xFF))
    return data
}

private func buildUDPAssociateRequest() -> Data {
    return Data([
        0x05, 0x03, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ])
}

private func parseReply(_ data: Data) -> (code: UInt8, address: Socks5Address, port: UInt16)? {
    guard data.count >= 7 else { return nil }
    guard data[data.startIndex] == 0x05 else { return nil }
    let code = data[data.startIndex + 1]
    let atyp = data[data.startIndex + 3]
    var index = data.startIndex + 4

    guard let address = parseAddress(from: data, atyp: atyp, index: &index) else { return nil }
    guard data.count >= index + 2 else { return nil }
    let port = UInt16(data[index]) << 8 | UInt16(data[index + 1])
    return (code, address, port)
}

private func parseAddress(from data: Data, atyp: UInt8, index: inout Int) -> Socks5Address? {
    switch atyp {
    case 0x01:
        guard data.count >= index + 4 else { return nil }
        let addrData = data.subdata(in: index..<index + 4)
        index += 4
        var bytes = [UInt8](repeating: 0, count: 4)
        addrData.copyBytes(to: &bytes, count: 4)
        let address = bytes.map(String.init).joined(separator: ".")
        return .ipv4(address)
    case 0x04:
        guard data.count >= index + 16 else { return nil }
        let addrData = data.subdata(in: index..<index + 16)
        index += 16
        let hex = addrData.map { String(format: "%02x", $0) }.joined()
        return .ipv6(hex)
    case 0x03:
        guard data.count > index else { return nil }
        let length = Int(data[index])
        index += 1
        guard data.count >= index + length else { return nil }
        let domainData = data.subdata(in: index..<index + length)
        index += length
        guard let domain = String(data: domainData, encoding: .utf8) else { return nil }
        return .domain(domain)
    default:
        return nil
    }
}

private func waitOnQueue(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
    let expectation = XCTestExpectation(description: "queue flush")
    queue.async {
        expectation.fulfill()
    }
    let result = XCTWaiter.wait(for: [expectation], timeout: timeout)
    XCTAssertEqual(result, .completed)
}