// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

@testable import Analytics
import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif
import XCTest

/// Seeded fuzz coverage for the packet parsers.
/// These parsers consume attacker-controlled bytes inside the tunnel extension, where a crash kills the
/// whole VPN. Device testing cannot explore this input space, so it is exercised deterministically here.
final class PacketParserFuzzTests: XCTestCase {
    private struct SeededGenerator: RandomNumberGenerator {
        var state: UInt64

        mutating func next() -> UInt64 {
            state = 6_364_136_223_846_793_005 &* state &+ 1_442_695_040_888_963_407
            return state
        }
    }

    /// Pure random buffers: both parsers must return without crashing for arbitrary bytes.
    func testParsersSurviveRandomBuffers() {
        var generator = SeededGenerator(state: 0xDEAD_BEEF)

        for _ in 0..<2_000 {
            let length = Int.random(in: 0...256, using: &generator)
            let bytes = (0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) }
            let data = Data(bytes)
            let hint: Int32? = [nil, Int32(AF_INET), Int32(AF_INET6)].randomElement(using: &generator) ?? nil

            _ = PacketParser.parse(data, ipVersionHint: hint)
            _ = FastPacketSummary(data: data, ipVersionHint: hint)
        }
    }

    /// Random buffers behind valid IPv4/UDP framing so the inner DNS/QUIC/TLS parsers are actually reached.
    func testTransportPayloadParsersSurviveRandomPayloads() {
        var generator = SeededGenerator(state: 0xCAFE_F00D)
        let interestingPorts: [UInt16] = [53, 443, 8_443]

        for _ in 0..<1_500 {
            let payloadLength = Int.random(in: 0...192, using: &generator)
            let payload = Data((0..<payloadLength).map { _ in UInt8.random(in: 0...255, using: &generator) })
            let destinationPort = interestingPorts.randomElement(using: &generator) ?? 443

            let packet = Self.makeIPv4UDPPacket(
                sourcePort: UInt16.random(in: 1_024...65_535, using: &generator),
                destinationPort: destinationPort,
                payload: payload
            )
            let metadata = PacketParser.parse(packet, ipVersionHint: nil)
            XCTAssertEqual(metadata?.transport, .udp)
            _ = FastPacketSummary(data: packet, ipVersionHint: nil)
        }
    }

    /// Mutation fuzz over the RFC 9001 Client Initial: any single-byte corruption must either fail header
    /// parsing or fail AEAD authentication. It must never crash or fabricate a different server name.
    func testMutatedQuicInitialNeverFabricatesServerName() throws {
        let quicPayload = try XCTUnwrap(Self.rfc9001ClientInitial())
        var generator = SeededGenerator(state: 0x9001_9001)

        for _ in 0..<400 {
            var mutated = quicPayload
            let index = Int.random(in: 0..<mutated.count, using: &generator)
            let flip = UInt8.random(in: 1...255, using: &generator)
            mutated[index] ^= flip

            let packet = Self.makeIPv4UDPPacket(sourcePort: 50_000, destinationPort: 443, payload: mutated)
            let metadata = PacketParser.parse(packet, ipVersionHint: nil)
            if let serverName = metadata?.tlsServerName {
                XCTAssertEqual(
                    serverName,
                    "example.com",
                    "corruption at byte \(index) xor \(flip) must not fabricate an SNI"
                )
            }
        }
    }

    /// Truncation fuzz over the RFC 9001 Client Initial at every parser boundary region.
    func testTruncatedQuicInitialNeverCrashes() throws {
        let quicPayload = try XCTUnwrap(Self.rfc9001ClientInitial())
        var generator = SeededGenerator(state: 0x9001_0002)

        var truncationPoints = Set(0...64)
        for _ in 0..<64 {
            truncationPoints.insert(Int.random(in: 0..<quicPayload.count, using: &generator))
        }

        for keptBytes in truncationPoints.sorted() {
            let packet = Self.makeIPv4UDPPacket(
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Data(quicPayload.prefix(keptBytes))
            )
            let metadata = PacketParser.parse(packet, ipVersionHint: nil)
            XCTAssertNil(metadata?.tlsServerName, "truncation at \(keptBytes) bytes must not produce an SNI")
        }
    }

    /// Malicious DNS responses with pointer loops and hostile label lengths must terminate without recursion blowups.
    func testHostileDNSCompressionPointersTerminate() {
        // Self-referential pointer: name at offset 12 points back to itself.
        var selfLoop = Data([0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
        selfLoop.append(contentsOf: [0xC0, 0x0C])
        selfLoop.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        let packet = Self.makeIPv4UDPPacket(sourcePort: 53, destinationPort: 50_000, payload: selfLoop)
        _ = PacketParser.parse(packet, ipVersionHint: nil)

        // Two pointers chasing each other.
        var pingPong = Data([0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        pingPong.append(contentsOf: [0xC0, 0x0E, 0xC0, 0x0C])
        let pingPongPacket = Self.makeIPv4UDPPacket(sourcePort: 53, destinationPort: 50_000, payload: pingPong)
        _ = PacketParser.parse(pingPongPacket, ipVersionHint: nil)
    }

    private static func rfc9001ClientInitial() -> Data? {
        // Reuses the vetted vector embedded in PacketParserQuicInitialTests by decoding the canonical
        // first/last bytes as a sanity gate.
        guard let payload = PacketParserQuicInitialTests.rfc9001ClientInitialPayload() else {
            return nil
        }
        guard payload.count == 1_200, payload.first == 0xC0, payload.last == 0x34 else {
            return nil
        }
        return payload
    }

    private static func makeIPv4UDPPacket(sourcePort: UInt16, destinationPort: UInt16, payload: Data) -> Data {
        let udpLength = 8 + payload.count
        let totalLength = 20 + udpLength

        var packet = Data(capacity: totalLength)
        packet.append(0x45)
        packet.append(0x00)
        packet.append(UInt8((totalLength >> 8) & 0xFF))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        packet.append(0x40)
        packet.append(17)
        packet.append(contentsOf: [0x00, 0x00])
        packet.append(contentsOf: [10, 0, 0, 2])
        packet.append(contentsOf: [93, 184, 216, 34])
        packet.append(UInt8((sourcePort >> 8) & 0xFF))
        packet.append(UInt8(sourcePort & 0xFF))
        packet.append(UInt8((destinationPort >> 8) & 0xFF))
        packet.append(UInt8(destinationPort & 0xFF))
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00])
        packet.append(payload)
        return packet
    }
}
