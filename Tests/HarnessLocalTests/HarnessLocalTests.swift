// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
@testable import HarnessLocal
import Observability
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// Harness replay decoding and determinism tests.
final class HarnessLocalTests: XCTestCase {
    /// Verifies scenario JSON decoding preserves replay seed and timing controls.
    func testScenarioDecodingIncludesSeedAndTiming() throws {
        let url = Bundle.module.url(forResource: "ReplayScenario", withExtension: "json")
        let scenario = try HarnessScenario.load(from: XCTUnwrap(url))

        XCTAssertEqual(scenario.id, "replay-smoke")
        XCTAssertEqual(scenario.seed, 42)
        XCTAssertEqual(scenario.timing.stepIntervalMs, 10)
    }

    /// Verifies deterministic scenarios produce stable summaries across runs.
    func testReplayDeterminismProducesStableSummary() async throws {
        let url = Bundle.module.url(forResource: "ReplayScenario", withExtension: "json")
        let scenario = try HarnessScenario.load(from: XCTUnwrap(url))

        let logger = StructuredLogger(sink: InMemoryLogSink())
        let runner = HarnessRunner(logger: logger)
        let tempRoot = FileManager.default.temporaryDirectory

        let first = try await runner.run(
            scenario: scenario,
            adapter: SyntheticFlowAdapter(),
            rootPath: tempRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        )
        let second = try await runner.run(
            scenario: scenario,
            adapter: SyntheticFlowAdapter(),
            rootPath: tempRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        )

        XCTAssertEqual(first.scenarioID, second.scenarioID)
        XCTAssertEqual(first.packetCount, second.packetCount)
        XCTAssertEqual(first.runtimeState, second.runtimeState)
    }

    /// Verifies classic PCAP replay turns captured IP packets into deterministic harness samples.
    func testClassicPcapReplayProducesPacketSamples() async throws {
        let tempRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
        let pcapURL = tempRoot.appendingPathComponent("raw-ip.pcap")
        try makeClassicPcap(linkType: 101, packets: [makeIPv4TCPPacket()]).write(to: pcapURL)

        let logger = StructuredLogger(sink: InMemoryLogSink())
        let runner = HarnessRunner(logger: logger)
        let result = try await runner.run(
            scenario: makeScenario(id: "pcap-smoke"),
            adapter: PcapReplayAdapter(fileURL: pcapURL),
            rootPath: tempRoot
        )

        XCTAssertEqual(result.scenarioID, "pcap-smoke")
        XCTAssertEqual(result.packetCount, 1)
        XCTAssertEqual(result.runtimeState, .running)
    }

    /// Verifies the local harness fails clearly for PCAPNG until a pcapng parser is added.
    func testPcapNGReplayFailsWithSpecificError() async throws {
        let tempRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
        let pcapURL = tempRoot.appendingPathComponent("capture.pcapng")
        try Data([0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00]).write(to: pcapURL)

        let logger = StructuredLogger(sink: InMemoryLogSink())
        let runner = HarnessRunner(logger: logger)

        do {
            _ = try await runner.run(
                scenario: makeScenario(id: "pcapng"),
                adapter: PcapReplayAdapter(fileURL: pcapURL),
                rootPath: tempRoot
            )
            XCTFail("Expected PCAPNG replay to fail")
        } catch let error as PcapReplayError {
            XCTAssertEqual(error, .unsupportedPcapNG)
        }
    }

    /// Verifies replay metadata does not invent TCP/UDP ports for IPv4 non-initial fragments.
    func testLocalPacketSampleOmitsPortsForIPv4NonInitialFragments() {
        let sample = LocalPacketSampleFactory.makeSample(
            packet: makeIPv4TCPPacket(fragmentOffset: 1),
            timestamp: Date(timeIntervalSince1970: 1),
            direction: "out",
            sequence: 1
        )

        XCTAssertEqual(sample.ipVersion, 4)
        XCTAssertEqual(sample.transportProtocolNumber, 6)
        XCTAssertEqual(sample.sourceAddress, "10.0.0.2")
        XCTAssertEqual(sample.destinationAddress, "93.184.216.34")
        XCTAssertNil(sample.sourcePort)
        XCTAssertNil(sample.destinationPort)
    }

    /// Verifies replay metadata walks IPv6 extension headers before reading UDP ports.
    func testLocalPacketSampleParsesPortsAfterIPv6HopByHopHeader() {
        let sample = LocalPacketSampleFactory.makeSample(
            packet: makeIPv6UDPWithHopByHopPacket(),
            timestamp: Date(timeIntervalSince1970: 1),
            direction: "out",
            sequence: 1
        )

        XCTAssertEqual(sample.ipVersion, 6)
        XCTAssertEqual(sample.transportProtocolNumber, 17)
        XCTAssertEqual(sample.sourcePort, 1234)
        XCTAssertEqual(sample.destinationPort, 53)
    }

    /// Verifies replay metadata does not read UDP ports out of IPv6 non-initial fragments.
    func testLocalPacketSampleOmitsPortsForIPv6NonInitialFragments() {
        let sample = LocalPacketSampleFactory.makeSample(
            packet: makeIPv6UDPFragmentPacket(fragmentField: 0x0008),
            timestamp: Date(timeIntervalSince1970: 1),
            direction: "out",
            sequence: 1
        )

        XCTAssertEqual(sample.ipVersion, 6)
        XCTAssertEqual(sample.transportProtocolNumber, 17)
        XCTAssertNil(sample.sourcePort)
        XCTAssertNil(sample.destinationPort)
    }
}

private func makeScenario(id: String) -> HarnessScenario {
    HarnessScenario(
        id: id,
        durationSeconds: 1,
        seed: 7,
        inputProfile: "test",
        timing: HarnessTiming(startTimeISO8601: "1970-01-01T00:00:00Z", stepIntervalMs: 1),
        steps: []
    )
}

private func makeClassicPcap(linkType: UInt32, packets: [Data]) -> Data {
    var data = Data([0xd4, 0xc3, 0xb2, 0xa1])
    appendLittleEndian(UInt16(2), to: &data)
    appendLittleEndian(UInt16(4), to: &data)
    appendLittleEndian(UInt32(0), to: &data)
    appendLittleEndian(UInt32(0), to: &data)
    appendLittleEndian(UInt32(65_535), to: &data)
    appendLittleEndian(linkType, to: &data)

    for (index, packet) in packets.enumerated() {
        appendLittleEndian(UInt32(index + 1), to: &data)
        appendLittleEndian(UInt32(0), to: &data)
        appendLittleEndian(UInt32(packet.count), to: &data)
        appendLittleEndian(UInt32(packet.count), to: &data)
        data.append(packet)
    }
    return data
}

private func appendLittleEndian(_ value: UInt16, to data: inout Data) {
    var littleEndian = value.littleEndian
    withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
}

private func appendLittleEndian(_ value: UInt32, to data: inout Data) {
    var littleEndian = value.littleEndian
    withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
}

private func makeIPv4TCPPacket() -> Data {
    makeIPv4TCPPacket(fragmentOffset: 0)
}

private func makeIPv4TCPPacket(fragmentOffset: UInt16) -> Data {
    var packet = [UInt8](repeating: 0, count: 40)
    packet[0] = 0x45
    packet[2] = 0
    packet[3] = UInt8(packet.count)
    packet[6] = UInt8(fragmentOffset >> 8)
    packet[7] = UInt8(fragmentOffset & 0x00ff)
    packet[8] = 64
    packet[9] = 6
    packet[12 ... 15] = [10, 0, 0, 2]
    packet[16 ... 19] = [93, 184, 216, 34]
    packet[20] = 0x30
    packet[21] = 0x39
    packet[22] = 0x01
    packet[23] = 0xbb
    packet[32] = 0x50
    packet[33] = 0x02
    return Data(packet)
}

private func makeIPv6UDPWithHopByHopPacket() -> Data {
    var packet = [UInt8](repeating: 0, count: 56)
    packet[0] = 0x60
    writeBigEndian(UInt16(16), to: &packet, at: 4)
    packet[6] = 0
    packet[7] = 64
    packet[8 ... 23] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1
    ]
    packet[24 ... 39] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2
    ]
    packet[40] = 17
    packet[41] = 0
    writeBigEndian(UInt16(1234), to: &packet, at: 48)
    writeBigEndian(UInt16(53), to: &packet, at: 50)
    writeBigEndian(UInt16(8), to: &packet, at: 52)
    return Data(packet)
}

private func makeIPv6UDPFragmentPacket(fragmentField: UInt16) -> Data {
    var packet = [UInt8](repeating: 0, count: 56)
    packet[0] = 0x60
    writeBigEndian(UInt16(16), to: &packet, at: 4)
    packet[6] = 44
    packet[7] = 64
    packet[8 ... 23] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1
    ]
    packet[24 ... 39] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2
    ]
    packet[40] = 17
    writeBigEndian(fragmentField, to: &packet, at: 42)
    writeBigEndian(UInt16(1234), to: &packet, at: 48)
    writeBigEndian(UInt16(53), to: &packet, at: 50)
    writeBigEndian(UInt16(8), to: &packet, at: 52)
    return Data(packet)
}

private func writeBigEndian(_ value: UInt16, to packet: inout [UInt8], at offset: Int) {
    packet[offset] = UInt8(value >> 8)
    packet[offset + 1] = UInt8(value & 0x00ff)
}
