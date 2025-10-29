//
//  ForwardHostTrackerTests.swift
//  RelativeProtocolTunnelTests
//
//  Created by Codex on 10/28/2025.
//

import XCTest
import Dispatch
@testable import RelativeProtocolTunnel

final class ForwardHostTrackerTests: XCTestCase {
    func testTLSClientHelloParserReturnsServerNameAndAddress() {
        let host = "example.com"
        let remoteIP = "203.0.113.10"
        let packet = Self.makeIPv4ClientHello(host: host, remoteIP: remoteIP)

        guard let mapping = TLSClientHelloParser.extractMapping(from: packet) else {
            XCTFail("Expected SNI mapping")
            return
        }

        XCTAssertEqual(mapping.host, host)
        XCTAssertEqual(mapping.address, remoteIP)
    }

    func testTrackerRecordsServerNameFromClientHello() {
        let tracker = RelativeProtocolTunnel.ForwardHostTracker(defaultTTL: 60)
        let host = "example.com"
        let remoteIP = "203.0.113.10"
        let packet = Self.makeIPv4ClientHello(host: host, remoteIP: remoteIP)

        tracker.ingestTLSClientHello(ipPacket: packet)

        let expectation = XCTestExpectation(description: "Tracker records mapping")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) {
            let recorded = tracker.lookup(ip: remoteIP)
            XCTAssertEqual(recorded, host)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }
}

private extension ForwardHostTrackerTests {
    static func makeIPv4ClientHello(host: String, remoteIP: String) -> Data {
        let tls = makeTLSClientHelloPayload(host: host)
        var packet = Data()

        // IPv4 header
        packet.append(0x45) // Version 4, IHL 5
        packet.append(0x00) // DSCP/ECN
        let totalLength = UInt16(20 + 20 + tls.count)
        packet.append(UInt8(totalLength >> 8))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00]) // Identification
        packet.append(contentsOf: [0x40, 0x00]) // Flags + Fragment offset
        packet.append(0x40) // TTL
        packet.append(0x06) // Protocol (TCP)
        packet.append(contentsOf: [0x00, 0x00]) // Header checksum placeholder
        packet.append(contentsOf: ipv4Bytes("192.0.2.1"))
        packet.append(contentsOf: ipv4Bytes(remoteIP))

        // TCP header
        var tcp = Data()
        tcp.append(contentsOf: [0xC3, 0x50]) // Source port 50000
        tcp.append(contentsOf: [0x01, 0xBB]) // Destination port 443
        tcp.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Sequence
        tcp.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Ack
        tcp.append(0x50) // Data offset (5 * 4 = 20 bytes), flags cleared
        tcp.append(0x18) // PSH + ACK (arbitrary for test)
        tcp.append(contentsOf: [0x72, 0x10]) // Window size
        tcp.append(contentsOf: [0x00, 0x00]) // Checksum placeholder
        tcp.append(contentsOf: [0x00, 0x00]) // Urgent pointer

        packet.append(tcp)
        packet.append(tls)
        return packet
    }

    static func makeTLSClientHelloPayload(host: String) -> Data {
        var handshakeBody = Data()
        handshakeBody.append(contentsOf: [0x03, 0x03]) // client_version
        handshakeBody.append(Data(repeating: 0x00, count: 32)) // random
        handshakeBody.append(0x00) // session_id_length
        handshakeBody.append(contentsOf: [0x00, 0x02]) // cipher_suites_length
        handshakeBody.append(contentsOf: [0x13, 0x01]) // TLS_AES_128_GCM_SHA256
        handshakeBody.append(0x01) // compression_methods_length
        handshakeBody.append(0x00) // compression method null

        var extensions = Data()
        let hostBytes = Array(host.utf8)
        var serverNameEntry = Data()
        serverNameEntry.append(0x00) // name_type host_name
        let hostLength = UInt16(hostBytes.count)
        serverNameEntry.append(UInt8(hostLength >> 8))
        serverNameEntry.append(UInt8(hostLength & 0xFF))
        serverNameEntry.append(contentsOf: hostBytes)

        let serverNameListLength = UInt16(serverNameEntry.count)
        var sniExtensionData = Data()
        sniExtensionData.append(UInt8(serverNameListLength >> 8))
        sniExtensionData.append(UInt8(serverNameListLength & 0xFF))
        sniExtensionData.append(serverNameEntry)

        let sniLength = UInt16(sniExtensionData.count)
        extensions.append(0x00)
        extensions.append(0x00)
        extensions.append(UInt8(sniLength >> 8))
        extensions.append(UInt8(sniLength & 0xFF))
        extensions.append(sniExtensionData)

        let extensionsLength = UInt16(extensions.count)
        handshakeBody.append(UInt8(extensionsLength >> 8))
        handshakeBody.append(UInt8(extensionsLength & 0xFF))
        handshakeBody.append(extensions)

        let handshakeLength = UInt32(handshakeBody.count)
        var handshake = Data()
        handshake.append(0x01) // ClientHello
        handshake.append(UInt8((handshakeLength >> 16) & 0xFF))
        handshake.append(UInt8((handshakeLength >> 8) & 0xFF))
        handshake.append(UInt8(handshakeLength & 0xFF))
        handshake.append(handshakeBody)

        let recordLength = UInt16(handshake.count)
        var record = Data()
        record.append(0x16) // Handshake
        record.append(0x03)
        record.append(0x03)
        record.append(UInt8(recordLength >> 8))
        record.append(UInt8(recordLength & 0xFF))
        record.append(handshake)
        return record
    }

    static func ipv4Bytes(_ ip: String) -> [UInt8] {
        return ip.split(separator: ".").compactMap { UInt8($0) }
    }
}
