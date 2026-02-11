// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Darwin
import Foundation
import XCTest
import RelativeProtocolCore

final class PacketSampleStreamEdgeTests: XCTestCase {
    func testReadAllRoundTrip() {
        let context = makeContext(suffix: "roundtrip")
        defer { cleanup(context) }

        let writer = PacketSampleStreamWriter(
            appGroupID: context.appGroupID,
            key: context.key,
            maxBytes: 200_000
        )
        writer.append([makeSample(id: 1, timestamp: 1), makeSample(id: 2, timestamp: 2)])
        writer.close()

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        let loaded = reader.readAll()
        XCTAssertEqual(loaded.map(\.flowId), [1, 2])
    }

    func testReadNewReturnsOnlyNewSamplesFromOffset() {
        let context = makeContext(suffix: "incremental")
        defer { cleanup(context) }

        let writer = PacketSampleStreamWriter(appGroupID: context.appGroupID, key: context.key, maxBytes: 200_000)
        writer.append([makeSample(id: 1, timestamp: 1), makeSample(id: 2, timestamp: 2)])

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        let first = reader.readNew(sinceOffset: 0)
        XCTAssertEqual(first.samples.map(\.flowId), [1, 2])

        writer.append([makeSample(id: 3, timestamp: 3)])
        writer.close()

        let second = reader.readNew(sinceOffset: first.nextOffset)
        XCTAssertEqual(second.samples.map(\.flowId), [3])
    }

    func testReadNewSkipsPartialTrailingLine() throws {
        let context = makeContext(suffix: "partial-line")
        defer { cleanup(context) }

        let writer = PacketSampleStreamWriter(appGroupID: context.appGroupID, key: context.key, maxBytes: 200_000)
        writer.append([makeSample(id: 1, timestamp: 1)])
        writer.close()

        let partial = Data("{\"timestamp\":".utf8)
        let handle = try FileHandle(forWritingTo: context.url)
        handle.seekToEndOfFile()
        handle.write(partial)
        handle.closeFile()

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        let result = reader.readNew(sinceOffset: 0)
        XCTAssertEqual(result.samples.map(\.flowId), [1])

        let fileSize = fileByteCount(at: context.url)
        XCTAssertLessThan(result.nextOffset, UInt64(fileSize))
    }

    func testReadNewResetsOffsetWhenPastEOF() {
        let context = makeContext(suffix: "offset-reset")
        defer { cleanup(context) }

        let writer = PacketSampleStreamWriter(appGroupID: context.appGroupID, key: context.key, maxBytes: 200_000)
        writer.append([makeSample(id: 1, timestamp: 1)])
        writer.close()

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        let result = reader.readNew(sinceOffset: 9_999_999)

        XCTAssertEqual(result.samples.map(\.flowId), [1])
        XCTAssertGreaterThan(result.nextOffset, 0)
    }

    func testCursorDetectsFileReplacementAndReadsFromStart() throws {
        let context = makeContext(suffix: "cursor-replace")
        defer { cleanup(context) }

        let writer = PacketSampleStreamWriter(appGroupID: context.appGroupID, key: context.key, maxBytes: 200_000)
        writer.append([makeSample(id: 1, timestamp: 1)])
        writer.close()

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        var cursor = PacketStreamCursor()
        let first = reader.readNew(cursor: &cursor)
        XCTAssertEqual(first.map(\.flowId), [1])
        XCTAssertGreaterThan(cursor.offset, 0)

        usleep(20_000)
        let encoded = try JSONEncoder().encode(makeSample(id: 2, timestamp: 2))
        var payload = Data()
        payload.append(encoded)
        payload.append(0x0A)
        try payload.write(to: context.url, options: .atomic)

        let second = reader.readNew(cursor: &cursor)
        XCTAssertEqual(second.map(\.flowId), [2])
    }

    func testWriterRotatesWhenMaxBytesExceeded() throws {
        let context = makeContext(suffix: "rotation")
        defer { cleanup(context) }

        let sample = makeSample(id: 1, timestamp: 1)
        let lineSize = try JSONEncoder().encode(sample).count + 1
        let writer = PacketSampleStreamWriter(
            appGroupID: context.appGroupID,
            key: context.key,
            maxBytes: lineSize + 4
        )
        writer.append([sample])
        writer.append([makeSample(id: 2, timestamp: 2)])
        writer.close()

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        let loaded = reader.readAll()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.flowId, 2)
    }

    func testAppendEmptyBatchDoesNotCreateSamples() {
        let context = makeContext(suffix: "empty-batch")
        defer { cleanup(context) }

        let writer = PacketSampleStreamWriter(appGroupID: context.appGroupID, key: context.key, maxBytes: 200_000)
        writer.append([])
        writer.close()

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        XCTAssertTrue(reader.readAll().isEmpty)
    }

    func testReadAllSkipsMalformedLines() throws {
        let context = makeContext(suffix: "malformed-lines")
        defer { cleanup(context) }

        let encoder = JSONEncoder()
        var payload = Data()
        payload.append(try encoder.encode(makeSample(id: 1, timestamp: 1)))
        payload.append(0x0A)
        payload.append(Data("malformed".utf8))
        payload.append(0x0A)
        payload.append(try encoder.encode(makeSample(id: 3, timestamp: 3)))
        payload.append(0x0A)
        try payload.write(to: context.url, options: .atomic)

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        let loaded = reader.readAll()
        XCTAssertEqual(loaded.map(\.flowId), [1, 3])
    }

    func testWriterCloseIsIdempotent() {
        let context = makeContext(suffix: "close-idempotent")
        defer { cleanup(context) }

        let writer = PacketSampleStreamWriter(appGroupID: context.appGroupID, key: context.key, maxBytes: 200_000)
        writer.append([makeSample(id: 1, timestamp: 1)])
        writer.close()
        writer.close()

        let reader = PacketSampleStreamReader(appGroupID: context.appGroupID, key: context.key)
        XCTAssertEqual(reader.readAll().count, 1)
    }

    private func makeSample(id: UInt64, timestamp: TimeInterval) -> PacketSample {
        PacketSample(
            timestamp: timestamp,
            direction: .outbound,
            ipVersion: .v4,
            transport: .udp,
            length: 128,
            flowId: id,
            burstId: 0,
            srcAddress: "192.0.2.10",
            dstAddress: "198.51.100.20",
            srcPort: 1234,
            dstPort: 443,
            dnsQueryName: nil,
            dnsCname: nil,
            dnsAnswerAddresses: nil,
            registrableDomain: nil,
            tlsServerName: nil,
            quicVersion: nil,
            quicPacketType: nil,
            quicDestinationConnectionId: nil,
            quicSourceConnectionId: nil,
            burstMetrics: nil,
            trafficClassification: nil
        )
    }

    private func makeContext(suffix: String) -> (appGroupID: String, key: String, url: URL) {
        let appGroupID = "group.packet.stream.\(UUID().uuidString)"
        let key = "stream-\(suffix)-\(UUID().uuidString)"
        let url = PacketSampleStreamLocation.makeURL(appGroupID: appGroupID, key: key)!
        return (appGroupID, key, url)
    }

    private func cleanup(_ context: (appGroupID: String, key: String, url: URL)) {
        try? FileManager.default.removeItem(at: context.url)
    }

    private func fileByteCount(at url: URL) -> Int {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.size] as? NSNumber)?.intValue ?? 0
    }
}
