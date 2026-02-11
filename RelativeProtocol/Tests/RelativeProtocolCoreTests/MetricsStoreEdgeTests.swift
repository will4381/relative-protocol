// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation
import XCTest
import RelativeProtocolCore

final class MetricsStoreEdgeTests: XCTestCase {
    func testJSONTrimsToMaxSnapshots() {
        let context = makeContext(suffix: "json-trim")
        defer { cleanup(context: context) }

        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 2,
            maxBytes: 50_000,
            format: .json
        )
        store.clear()

        store.append(makeSnapshot(id: 1, capturedAt: 1.0))
        store.append(makeSnapshot(id: 2, capturedAt: 2.0))
        store.append(makeSnapshot(id: 3, capturedAt: 3.0))

        let loaded = store.load()
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded.map(\.capturedAt), [2.0, 3.0])
    }

    func testNDJSONTrimsByMaxBytes() throws {
        let context = makeContext(suffix: "ndjson-bytes")
        defer { cleanup(context: context) }

        let snapshot1 = makeSnapshot(id: 10, capturedAt: 10.0)
        let snapshot2 = makeSnapshot(id: 11, capturedAt: 11.0)
        let lineSize = try JSONEncoder().encode(snapshot1).count + 1

        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 10,
            maxBytes: lineSize + 4,
            format: .ndjson
        )
        store.clear()
        store.append(snapshot1)
        store.append(snapshot2)

        let loaded = store.load()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.capturedAt, 11.0)
    }

    func testRejectsSnapshotLargerThanMaxBytes() {
        let context = makeContext(suffix: "reject-large")
        defer { cleanup(context: context) }

        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 5,
            maxBytes: 150,
            format: .json
        )
        store.clear()

        var longName = String(repeating: "a", count: 800)
        longName.append(".example.com")
        let sample = PacketSample(
            timestamp: 1,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 80,
            flowId: 1,
            burstId: 1,
            srcAddress: "10.0.0.1",
            dstAddress: "1.1.1.1",
            srcPort: 1234,
            dstPort: 53,
            dnsQueryName: longName,
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            registrableDomain: "example.com",
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            burstMetrics: nil,
            trafficClassification: nil
        )
        store.append(MetricsSnapshot(capturedAt: 1.0, samples: [sample]))

        XCTAssertTrue(store.load().isEmpty)
    }

    func testClearRemovesSnapshots() {
        let context = makeContext(suffix: "clear")
        defer { cleanup(context: context) }

        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 5,
            maxBytes: 50_000,
            format: .json
        )
        store.clear()
        store.append(makeSnapshot(id: 21, capturedAt: 1.0))
        XCTAssertEqual(store.load().count, 1)

        store.clear()
        XCTAssertTrue(store.load().isEmpty)
    }

    func testCorruptJSONReturnsEmpty() throws {
        let context = makeContext(suffix: "corrupt-json")
        defer { cleanup(context: context) }

        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 5,
            maxBytes: 50_000,
            format: .json
        )
        store.clear()
        let url = storeFileURL(from: store) ?? context.url
        try Data("{not-valid-json".utf8).write(to: url, options: .atomic)

        XCTAssertTrue(store.load().isEmpty)
    }

    func testNDJSONSkipsInvalidLines() throws {
        let context = makeContext(suffix: "ndjson-invalid")
        defer { cleanup(context: context) }

        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 10,
            maxBytes: 100_000,
            format: .ndjson
        )
        store.clear()
        let url = storeFileURL(from: store) ?? context.url

        let encoder = JSONEncoder()
        var payload = Data()
        payload.append(try encoder.encode(makeSnapshot(id: 1, capturedAt: 1.0)))
        payload.append(0x0A)
        payload.append(Data("not-json".utf8))
        payload.append(0x0A)
        payload.append(try encoder.encode(makeSnapshot(id: 3, capturedAt: 3.0)))
        payload.append(0x0A)
        try payload.write(to: url, options: .atomic)

        let reloaded = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 10,
            maxBytes: 100_000,
            format: .ndjson
        )
        let loaded = reloaded.load()
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded.map(\.capturedAt), [1.0, 3.0])
    }

    func testManyAppendsStayWithinConfiguredLimits() {
        let context = makeContext(suffix: "many-appends")
        defer { cleanup(context: context) }

        let maxBytes = 4_000
        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 10,
            maxBytes: maxBytes,
            format: .json
        )
        store.clear()

        for index in 0..<200 {
            store.append(makeSnapshot(id: UInt64(index + 1), capturedAt: Double(index)))
        }

        let loaded = store.load()
        XCTAssertLessThanOrEqual(loaded.count, 10)
        let url = storeFileURL(from: store) ?? context.url
        let size = fileSize(at: url)
        XCTAssertLessThanOrEqual(size, maxBytes)
    }

    func testRoundTripPreservesOptionalMetadataFields() {
        let context = makeContext(suffix: "metadata-roundtrip")
        defer { cleanup(context: context) }

        let store = MetricsStore(
            appGroupID: context.appGroupID,
            key: context.key,
            maxSnapshots: 5,
            maxBytes: 200_000,
            format: .json
        )
        store.clear()

        let burst = BurstMetrics(
            packetCount: 3,
            byteCount: 900,
            durationMs: 250,
            packetsPerSecond: 12,
            bytesPerSecond: 3600
        )
        let classification = TrafficClassification(
            label: "social",
            domain: "example.com",
            cdn: "akamai",
            asn: "AS20940",
            confidence: 0.91,
            reasons: ["dns=api.example.com", "app=social"]
        )
        let sample = PacketSample(
            timestamp: 5,
            direction: .inbound,
            ipVersion: .v6,
            transport: .tcp,
            length: 1280,
            flowId: 44,
            burstId: 9,
            srcAddress: "2001:db8::1",
            dstAddress: "2001:db8::2",
            srcPort: 443,
            dstPort: 54000,
            dnsQueryName: "api.example.com",
            dnsCname: "edge.example.com",
            dnsAnswerAddresses: ["203.0.113.9"],
            registrableDomain: "example.com",
            tlsServerName: "api.example.com",
            quicVersion: 1,
            quicPacketType: .initial,
            quicDestinationConnectionId: "abcd",
            quicSourceConnectionId: "ef01",
            burstMetrics: burst,
            trafficClassification: classification
        )
        store.append(MetricsSnapshot(capturedAt: 5.0, samples: [sample]))

        guard let loaded = store.load().first?.samples.first else {
            return XCTFail("Expected stored sample")
        }
        XCTAssertEqual(loaded.dnsAnswerAddresses, ["203.0.113.9"])
        XCTAssertEqual(loaded.burstMetrics, burst)
        XCTAssertEqual(loaded.trafficClassification, classification)
        XCTAssertEqual(loaded.quicDestinationConnectionId, "abcd")
        XCTAssertEqual(loaded.quicSourceConnectionId, "ef01")
    }

    private func makeSnapshot(id: UInt64, capturedAt: TimeInterval) -> MetricsSnapshot {
        let sample = PacketSample(
            timestamp: capturedAt,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 120,
            flowId: id,
            burstId: 1,
            srcAddress: "192.0.2.2",
            dstAddress: "198.51.100.2",
            srcPort: 1234,
            dstPort: 53,
            dnsQueryName: "host\(id).example.com",
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            registrableDomain: "example.com",
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            burstMetrics: nil,
            trafficClassification: nil
        )
        return MetricsSnapshot(capturedAt: capturedAt, samples: [sample])
    }

    private func makeContext(suffix: String) -> (appGroupID: String, key: String, url: URL) {
        let appGroupID = "group.metrics.edge.\(UUID().uuidString)"
        let key = "metrics-\(suffix)-\(UUID().uuidString)"
        let url = makeStoreURL(appGroupID: appGroupID, key: key)
        return (appGroupID, key, url)
    }

    private func makeStoreURL(appGroupID: String, key: String) -> URL {
        let fileManager = FileManager.default
        let caches = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first ?? fileManager.temporaryDirectory
        let dir = caches.appendingPathComponent("RelativeProtocolMetrics", isDirectory: true)
        try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        let sanitizedGroup = sanitizeForFilename(appGroupID)
        let sanitizedKey = sanitizeForFilename(key)
        return dir.appendingPathComponent("\(sanitizedGroup).\(sanitizedKey).json")
    }

    private func sanitizeForFilename(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        return value.unicodeScalars
            .map { allowed.contains($0) ? String($0) : "_" }
            .joined()
    }

    private func cleanup(context: (appGroupID: String, key: String, url: URL)) {
        try? FileManager.default.removeItem(at: context.url)
    }

    private func fileSize(at url: URL) -> Int {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes?[.size] as? NSNumber)?.intValue ?? 0
    }

    private func storeFileURL(from store: MetricsStore) -> URL? {
        let mirror = Mirror(reflecting: store)
        return mirror.children.first(where: { $0.label == "fileURL" })?.value as? URL
    }
}
