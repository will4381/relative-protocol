// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Darwin
import Foundation
import XCTest
import RelativeProtocolCore

final class TrafficClassifierEdgeTests: XCTestCase {
    func testReturnsNilWhenNoSignalsExist() {
        let classifier = TrafficClassifier(signatures: [])
        let metadata = makeMetadata(dst: [203, 0, 113, 10])

        let classification = classifier.classify(metadata: metadata, direction: .outbound, timestamp: 1.0)
        XCTAssertNil(classification)
    }

    func testInboundDirectionUsesSourceAddressForIPCache() {
        let classifier = TrafficClassifier(signatures: [
            AppSignature(label: "tiktok", domains: ["tiktokcdn.com"])
        ])
        let ip = [203, 0, 113, 77]
        let prime = makeMetadata(
            dst: ip,
            dnsQuery: "video.tiktokcdn.com",
            answers: [ip]
        )
        _ = classifier.classify(metadata: prime, direction: .outbound, timestamp: 10.0)

        let inbound = makeMetadata(
            src: ip,
            dst: [192, 0, 2, 20]
        )
        let classification = classifier.classify(metadata: inbound, direction: .inbound, timestamp: 11.0)

        XCTAssertEqual(classification?.label, "tiktok")
    }

    func testCacheEntryExpiresAfterBoundary() {
        let classifier = TrafficClassifier(
            ttlDNS: 5,
            ttlTLS: 5,
            ttlCache: 5,
            signatures: [AppSignature(label: "svc", domains: ["example.com"])]
        )
        let ip = [198, 51, 100, 10]
        let prime = makeMetadata(dst: ip, dnsQuery: "api.example.com", answers: [ip])
        _ = classifier.classify(metadata: prime, direction: .outbound, timestamp: 100.0)

        let ipOnly = makeMetadata(dst: ip)
        let beforeExpiry = classifier.classify(metadata: ipOnly, direction: .outbound, timestamp: 104.9)
        let atBoundary = classifier.classify(metadata: ipOnly, direction: .outbound, timestamp: 105.0)

        XCTAssertNotNil(beforeExpiry)
        XCTAssertNil(atBoundary)
    }

    func testOverflowEvictsLeastRecentlySeenEntry() {
        let classifier = TrafficClassifier(
            ttlDNS: 60,
            ttlTLS: 60,
            ttlCache: 60,
            maxEntries: 3,
            signatures: [AppSignature(label: "svc", domains: ["one.test", "two.test", "three.test", "four.test"])]
        )

        let ip1 = [198, 51, 100, 1]
        let ip2 = [198, 51, 100, 2]
        let ip3 = [198, 51, 100, 3]
        let ip4 = [198, 51, 100, 4]

        _ = classifier.classify(metadata: makeMetadata(dst: ip1, dnsQuery: "a.one.test", answers: [ip1]), direction: .outbound, timestamp: 1.0)
        _ = classifier.classify(metadata: makeMetadata(dst: ip2, dnsQuery: "a.two.test", answers: [ip2]), direction: .outbound, timestamp: 2.0)
        _ = classifier.classify(metadata: makeMetadata(dst: ip3, dnsQuery: "a.three.test", answers: [ip3]), direction: .outbound, timestamp: 3.0)
        _ = classifier.classify(metadata: makeMetadata(dst: ip1, dnsQuery: "a.one.test", answers: [ip1]), direction: .outbound, timestamp: 4.0)
        _ = classifier.classify(metadata: makeMetadata(dst: ip4, dnsQuery: "a.four.test", answers: [ip4]), direction: .outbound, timestamp: 5.0)

        XCTAssertNotNil(classifier.classify(metadata: makeMetadata(dst: ip1), direction: .outbound, timestamp: 5.1))
        XCTAssertNil(classifier.classify(metadata: makeMetadata(dst: ip2), direction: .outbound, timestamp: 5.1))
        XCTAssertNotNil(classifier.classify(metadata: makeMetadata(dst: ip3), direction: .outbound, timestamp: 5.1))
        XCTAssertNotNil(classifier.classify(metadata: makeMetadata(dst: ip4), direction: .outbound, timestamp: 5.1))
    }

    func testSameTimestampChurnRetainsHotCacheEntry() {
        let classifier = TrafficClassifier(
            ttlDNS: 120,
            ttlTLS: 120,
            ttlCache: 120,
            maxEntries: 3,
            signatures: [AppSignature(label: "svc", domains: ["old.test", "hot.test", "new.test"])]
        )

        let oldIP = [203, 0, 113, 10]
        let hotIP = [203, 0, 113, 11]
        let newIP = [203, 0, 113, 12]
        let overflowIP = [203, 0, 113, 13]

        _ = classifier.classify(metadata: makeMetadata(dst: oldIP, dnsQuery: "a.old.test", answers: [oldIP]), direction: .outbound, timestamp: 1.0)
        _ = classifier.classify(metadata: makeMetadata(dst: hotIP, dnsQuery: "a.hot.test", answers: [hotIP]), direction: .outbound, timestamp: 2.0)
        for _ in 0..<2_000 {
            _ = classifier.classify(metadata: makeMetadata(dst: hotIP, dnsQuery: "a.hot.test", answers: [hotIP]), direction: .outbound, timestamp: 2.0)
        }
        _ = classifier.classify(metadata: makeMetadata(dst: newIP, dnsQuery: "a.new.test", answers: [newIP]), direction: .outbound, timestamp: 3.0)
        _ = classifier.classify(metadata: makeMetadata(dst: overflowIP, dnsQuery: "a.new.test", answers: [overflowIP]), direction: .outbound, timestamp: 3.1)

        XCTAssertNotNil(classifier.classify(metadata: makeMetadata(dst: hotIP), direction: .outbound, timestamp: 3.2))
        XCTAssertNil(classifier.classify(metadata: makeMetadata(dst: oldIP), direction: .outbound, timestamp: 3.2))
    }

    func testWildcardDomainDoesNotMatchDifferentLabelCounts() {
        let classifier = TrafficClassifier(signatures: [
            AppSignature(label: "svc", domains: ["*.tiktokcdn.com"])
        ])
        let metadata = makeMetadata(
            dst: [203, 0, 113, 20],
            dnsQuery: "a.b.tiktokcdn.com"
        )
        let classification = classifier.classify(metadata: metadata, direction: .outbound, timestamp: 1.0)

        XCTAssertNotNil(classification)
        XCTAssertNil(classification?.label)
    }

    func testUpdateSignaturesNormalizesAndApplies() {
        let classifier = TrafficClassifier(signatures: [])
        classifier.updateSignatures([
            AppSignature(label: "social", domains: [" Example.COM "])
        ])

        let metadata = makeMetadata(dst: [203, 0, 113, 30], dnsQuery: "api.example.com")
        let classification = classifier.classify(metadata: metadata, direction: .outbound, timestamp: 1.0)
        XCTAssertEqual(classification?.label, "social")
    }

    func testAutoReloadSignaturesAfterInterval() throws {
        let url = try makeTempSignatureURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        AppSignatureStore.write([AppSignature(label: "old", domains: ["old.example"])], to: url)

        let classifier = TrafficClassifier(
            signatures: [],
            signatureFileURL: url,
            signatureCheckInterval: 0.05
        )
        let now = Date().timeIntervalSince1970
        let oldMetadata = makeMetadata(dst: [198, 51, 100, 40], dnsQuery: "api.old.example")
        XCTAssertEqual(classifier.classify(metadata: oldMetadata, direction: .outbound, timestamp: now)?.label, "old")

        usleep(70_000)
        AppSignatureStore.write([AppSignature(label: "new", domains: ["new.example"])], to: url)

        let newMetadata = makeMetadata(dst: [198, 51, 100, 41], dnsQuery: "api.new.example")
        let classification = classifier.classify(metadata: newMetadata, direction: .outbound, timestamp: now + 0.2)
        XCTAssertEqual(classification?.label, "new")
    }

    func testDoesNotReloadBeforeCheckInterval() throws {
        let url = try makeTempSignatureURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        AppSignatureStore.write([AppSignature(label: "old", domains: ["old.example"])], to: url)
        let classifier = TrafficClassifier(
            signatures: [],
            signatureFileURL: url,
            signatureCheckInterval: 10.0
        )
        let now = Date().timeIntervalSince1970
        XCTAssertEqual(
            classifier.classify(
                metadata: makeMetadata(dst: [198, 51, 100, 50], dnsQuery: "api.old.example"),
                direction: .outbound,
                timestamp: now
            )?.label,
            "old"
        )

        usleep(20_000)
        AppSignatureStore.write([AppSignature(label: "new", domains: ["new.example"])], to: url)

        let newResult = classifier.classify(
            metadata: makeMetadata(dst: [198, 51, 100, 51], dnsQuery: "api.new.example"),
            direction: .outbound,
            timestamp: now + 1.0
        )
        XCTAssertNil(newResult?.label)
    }

    func testInvalidForcedReloadKeepsExistingSignatures() throws {
        let url = try makeTempSignatureURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        AppSignatureStore.write([AppSignature(label: "stable", domains: ["stable.example"])], to: url)
        let classifier = TrafficClassifier(signatures: [], signatureFileURL: url, signatureCheckInterval: 0.01)

        try Data("not-json".utf8).write(to: url, options: .atomic)
        classifier.reloadSignatures()

        let result = classifier.classify(
            metadata: makeMetadata(dst: [198, 51, 100, 60], dnsQuery: "api.stable.example"),
            direction: .outbound,
            timestamp: Date().timeIntervalSince1970
        )
        XCTAssertEqual(result?.label, "stable")
    }

    func testDNSCnameIsPreferredOverQueryName() {
        let classifier = TrafficClassifier(signatures: [
            AppSignature(label: "cname_app", domains: ["cname.example.com"])
        ])

        let metadata = makeMetadata(
            dst: [203, 0, 113, 70],
            dnsQuery: "query.example.com",
            dnsCname: "api.cname.example.com"
        )
        let classification = classifier.classify(metadata: metadata, direction: .outbound, timestamp: 1.0)

        XCTAssertEqual(classification?.label, "cname_app")
        XCTAssertTrue(classification?.reasons.contains("dns=api.cname.example.com") ?? false)
    }

    func testIPCacheReasonIsIncludedWhenUsingCachedEntry() {
        let classifier = TrafficClassifier(signatures: [
            AppSignature(label: "cached", domains: ["cached.example"])
        ])
        let ip = [203, 0, 113, 88]
        _ = classifier.classify(
            metadata: makeMetadata(dst: ip, dnsQuery: "api.cached.example", answers: [ip]),
            direction: .outbound,
            timestamp: 1.0
        )

        let classification = classifier.classify(
            metadata: makeMetadata(dst: ip),
            direction: .outbound,
            timestamp: 1.2
        )
        XCTAssertTrue(classification?.reasons.contains(where: { $0.hasPrefix("ip_cache=") }) ?? false)
    }

    private func makeMetadata(
        src: [Int] = [192, 0, 2, 1],
        dst: [Int],
        dnsQuery: String? = nil,
        dnsCname: String? = nil,
        tlsServerName: String? = nil,
        answers: [[Int]]? = nil,
        registrableDomain: String? = nil
    ) -> PacketMetadata {
        let srcBytes = src.map(UInt8.init(clamping:))
        let dstBytes = dst.map(UInt8.init(clamping:))
        let srcAddress = IPAddress(bytes: Data(srcBytes))!
        let dstAddress = IPAddress(bytes: Data(dstBytes))!
        let answerAddresses = answers?.compactMap { answer in
            IPAddress(bytes: Data(answer.map(UInt8.init(clamping:))))
        }
        return PacketMetadata(
            ipVersion: .v4,
            transport: .udp,
            srcAddress: srcAddress,
            dstAddress: dstAddress,
            srcPort: 12345,
            dstPort: 443,
            length: 128,
            dnsQueryName: dnsQuery,
            dnsCname: dnsCname,
            dnsAnswerAddresses: answerAddresses,
            registrableDomain: registrableDomain,
            tlsServerName: tlsServerName,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil
        )
    }

    private func makeTempSignatureURL() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("TrafficClassifierEdge-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("signatures.json")
    }
}
