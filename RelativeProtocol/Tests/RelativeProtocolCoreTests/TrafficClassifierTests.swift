// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import XCTest
import RelativeProtocolCore

final class TrafficClassifierTests: XCTestCase {
    func testClassifyFromDNS() {
        let classifier = TrafficClassifier(signatures: [
            AppSignature(label: "tiktok", domains: ["tiktok.com", "tiktokcdn.com"])
        ])
        let metadata = makeMetadata(
            dstAddress: [23, 63, 26, 233],
            dnsQuery: "api.tiktok.com",
            tlsServerName: nil
        )

        let classification = classifier.classify(metadata: metadata, direction: .outbound, timestamp: 1.0)
        XCTAssertNotNil(classification)
        XCTAssertEqual(classification?.label, "tiktok")
        XCTAssertEqual(classification?.domain, "tiktok.com")
    }

    func testClassifyFromTLS() {
        let classifier = TrafficClassifier(signatures: [])
        let metadata = makeMetadata(
            dstAddress: [1, 1, 1, 1],
            dnsQuery: nil,
            tlsServerName: "video.edgekey.net"
        )

        let classification = classifier.classify(metadata: metadata, direction: .outbound, timestamp: 2.0)
        XCTAssertNotNil(classification)
        XCTAssertEqual(classification?.cdn, "akamai")
        XCTAssertEqual(classification?.asn, "AS20940")
    }

    func testUsesIPCache() {
        let classifier = TrafficClassifier(
            ttlDNS: 60,
            ttlTLS: 60,
            ttlCache: 60,
            maxEntries: 128,
            signatures: [
                AppSignature(label: "tiktok", domains: ["tiktokcdn.com"])
            ]
        )
        let dnsMetadata = makeMetadata(
            dstAddress: [203, 0, 113, 10],
            dnsQuery: "video.tiktokcdn.com",
            tlsServerName: nil
        )

        _ = classifier.classify(metadata: dnsMetadata, direction: .outbound, timestamp: 10.0)

        let ipOnlyMetadata = makeMetadata(
            dstAddress: [203, 0, 113, 10],
            dnsQuery: nil,
            tlsServerName: nil
        )
        let classification = classifier.classify(metadata: ipOnlyMetadata, direction: .outbound, timestamp: 11.0)
        XCTAssertNotNil(classification)
        XCTAssertEqual(classification?.label, "tiktok")
    }

    func testDomainBoundaryMatching() {
        let classifier = TrafficClassifier(signatures: [
            AppSignature(label: "tiktok", domains: ["tiktok.com"])
        ])
        let badMetadata = makeMetadata(
            dstAddress: [203, 0, 113, 20],
            dnsQuery: "notiktok.com",
            tlsServerName: nil
        )
        let goodMetadata = makeMetadata(
            dstAddress: [203, 0, 113, 21],
            dnsQuery: "api.tiktok.com",
            tlsServerName: nil
        )

        let bad = classifier.classify(metadata: badMetadata, direction: .outbound, timestamp: 1.0)
        XCTAssertNotNil(bad)
        XCTAssertNil(bad?.label)

        let good = classifier.classify(metadata: goodMetadata, direction: .outbound, timestamp: 2.0)
        XCTAssertNotNil(good)
        XCTAssertEqual(good?.label, "tiktok")
    }

    private func makeMetadata(dstAddress: [UInt8], dnsQuery: String?, tlsServerName: String?) -> PacketMetadata {
        let src = IPAddress(bytes: Data([192, 0, 2, 1]))!
        let dst = IPAddress(bytes: Data(dstAddress))!
        let answers: [IPAddress]? = dnsQuery == nil ? nil : [dst]
        return PacketMetadata(
            ipVersion: .v4,
            transport: .udp,
            srcAddress: src,
            dstAddress: dst,
            srcPort: 12345,
            dstPort: 443,
            length: 120,
            dnsQueryName: dnsQuery,
            dnsCname: nil,
            dnsAnswerAddresses: answers,
            registrableDomain: nil,
            tlsServerName: tlsServerName,
            quicVersion: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
    }
}
