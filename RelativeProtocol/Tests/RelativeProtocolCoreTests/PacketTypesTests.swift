// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import XCTest
import RelativeProtocolCore

final class PacketTypesTests: XCTestCase {
    func testPacketSampleIPAddressInitializerEncodesStringFields() throws {
        let src = try XCTUnwrap(IPAddress(bytes: Data([192, 0, 2, 10])))
        let dst = try XCTUnwrap(IPAddress(bytes: Data([198, 51, 100, 20])))
        let answer = try XCTUnwrap(IPAddress(bytes: Data([203, 0, 113, 15])))

        let sample = PacketSample(
            timestamp: 12.5,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 150,
            flowId: 99,
            burstId: 3,
            srcIPAddress: src,
            dstIPAddress: dst,
            srcPort: 1234,
            dstPort: 53,
            dnsQueryName: "example.com",
            dnsCname: nil,
            dnsAnswerIPAddresses: [answer],
            registrableDomain: "example.com",
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )

        XCTAssertEqual(sample.srcAddress, "192.0.2.10")
        XCTAssertEqual(sample.dstAddress, "198.51.100.20")
        XCTAssertEqual(sample.dnsAnswerAddresses, ["203.0.113.15"])

        let data = try JSONEncoder().encode(sample)
        let decodedJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(decodedJSON["srcAddress"] as? String, "192.0.2.10")
        XCTAssertEqual(decodedJSON["dstAddress"] as? String, "198.51.100.20")
        XCTAssertEqual(decodedJSON["dnsAnswerAddresses"] as? [String], ["203.0.113.15"])

        let roundTrip = try JSONDecoder().decode(PacketSample.self, from: data)
        XCTAssertEqual(roundTrip.srcAddress, "192.0.2.10")
        XCTAssertEqual(roundTrip.dstAddress, "198.51.100.20")
        XCTAssertEqual(roundTrip.dnsAnswerAddresses, ["203.0.113.15"])
    }

    func testPacketSampleDecodePreservesNonIPAddressStrings() throws {
        let json = """
        {
          "timestamp": 1,
          "direction": "inbound",
          "ipVersion": 4,
          "transport": 17,
          "length": 64,
          "flowId": 1,
          "burstId": 1,
          "srcAddress": "host.local",
          "dstAddress": "198.51.100.2",
          "dnsAnswerAddresses": ["not-an-ip", "203.0.113.8"]
        }
        """.data(using: .utf8)!

        let decoded = try JSONDecoder().decode(PacketSample.self, from: json)
        XCTAssertEqual(decoded.srcAddress, "host.local")
        XCTAssertEqual(decoded.dstAddress, "198.51.100.2")
        XCTAssertEqual(decoded.dnsAnswerAddresses, ["not-an-ip", "203.0.113.8"])
    }
}
