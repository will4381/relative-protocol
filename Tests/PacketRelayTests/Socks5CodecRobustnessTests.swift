// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
@testable import PacketRelay
import XCTest

/// Adversarial and boundary coverage for the SOCKS5 codec.
/// Decision: these inputs are attacker-controlled bytes from the dataplane stream, so the codec must hold its
/// invariants for arbitrary input, not just well-formed handshakes.
final class Socks5CodecRobustnessTests: XCTestCase {
    /// Deterministic generator so fuzz failures reproduce exactly from the seed in the failure message.
    private struct SeededGenerator: RandomNumberGenerator {
        var state: UInt64

        mutating func next() -> UInt64 {
            state = 6_364_136_223_846_793_005 &* state &+ 1_442_695_040_888_963_407
            return state
        }
    }

    /// Regression: `parseRequest` must use absolute `Data` indices so it parses correctly from a slice whose
    /// `startIndex` is not zero.
    func testParseRequestFromNonZeroBasedSlice() {
        var request = Data([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 20, 0x01, 0xBB])
        let prefixLength = 7
        var prefixed = Data(repeating: 0xAA, count: prefixLength)
        prefixed.append(request)

        var slice = prefixed[prefixLength...]
        XCTAssertNotEqual(slice.startIndex, 0)

        let parsedFromSlice = Socks5Codec.parseRequest(&slice)
        let parsedFromZeroBased = Socks5Codec.parseRequest(&request)
        XCTAssertEqual(parsedFromSlice, parsedFromZeroBased)
        XCTAssertEqual(parsedFromSlice?.command, .connect)
        XCTAssertEqual(parsedFromSlice?.address, .ipv4("192.168.1.20"))
        XCTAssertEqual(parsedFromSlice?.port, 443)
        XCTAssertTrue(slice.isEmpty)
    }

    /// Locks in the allocation-light IPv4 formatter across 1-, 2-, and 3-digit octet boundaries.
    func testIPv4AddressFormattingBoundaries() {
        let cases: [(octets: [UInt8], expected: String)] = [
            ([0, 0, 0, 0], "0.0.0.0"),
            ([0, 9, 10, 99], "0.9.10.99"),
            ([100, 101, 199, 200], "100.101.199.200"),
            ([255, 255, 255, 255], "255.255.255.255"),
            ([127, 0, 0, 1], "127.0.0.1")
        ]

        for testCase in cases {
            var datagram = Data([0x00, 0x00, 0x00, 0x01])
            datagram.append(contentsOf: testCase.octets)
            datagram.append(contentsOf: [0x00, 0x35, 0xDE, 0xAD])

            let packet = [UInt8](datagram).withUnsafeBufferPointer { pointer in
                Socks5Codec.parseUDPPacket(pointer, count: datagram.count)
            }
            XCTAssertEqual(packet?.address, .ipv4(testCase.expected))
            XCTAssertEqual(packet?.port, 53)
            XCTAssertEqual(packet?.payload, Data([0xDE, 0xAD]))
        }
    }

    func testUDPPacketBuildParseRoundTrip() {
        var generator = SeededGenerator(state: 0x5F5F_0001)
        let addresses: [Socks5Address] = [
            .ipv4("10.20.30.40"),
            .ipv6("2001:db8::1"),
            .domain("relay.example.com")
        ]

        for address in addresses {
            for _ in 0..<32 {
                let port = UInt16.random(in: 0...UInt16.max, using: &generator)
                let payloadLength = Int.random(in: 0...512, using: &generator)
                let payload = Data((0..<payloadLength).map { _ in UInt8.random(in: 0...255, using: &generator) })

                guard let encoded = Socks5Codec.buildUDPPacket(address: address, port: port, payload: payload) else {
                    XCTFail("Failed to build datagram for \(address)")
                    return
                }

                let decoded = [UInt8](encoded).withUnsafeBufferPointer { pointer in
                    Socks5Codec.parseUDPPacket(pointer, count: encoded.count)
                }
                XCTAssertEqual(decoded?.address, address)
                XCTAssertEqual(decoded?.port, port)
                XCTAssertEqual(decoded?.payload, payload)
            }
        }
    }

    func testTCPForwardUDPBuildParseRoundTrip() {
        var generator = SeededGenerator(state: 0x5F5F_0002)
        let addresses: [Socks5Address] = [
            .ipv4("198.51.100.7"),
            .ipv6("2001:db8:1234::42"),
            .domain("forward.example.org")
        ]

        for address in addresses {
            for _ in 0..<32 {
                let port = UInt16.random(in: 0...UInt16.max, using: &generator)
                let payloadLength = Int.random(in: 0...512, using: &generator)
                let payload = Data((0..<payloadLength).map { _ in UInt8.random(in: 0...255, using: &generator) })

                guard let frame = Socks5Codec.buildTCPForwardUDPPacket(address: address, port: port, payload: payload) else {
                    XCTFail("Failed to build frame for \(address)")
                    return
                }

                guard case .packet(let decoded, let consumedBytes) = Socks5Codec.parseTCPForwardUDPPacket(frame) else {
                    XCTFail("Failed to parse round-trip frame for \(address)")
                    return
                }
                XCTAssertEqual(consumedBytes, frame.count)
                XCTAssertEqual(decoded.address, address)
                XCTAssertEqual(decoded.port, port)
                XCTAssertEqual(decoded.payload, payload)
            }
        }
    }

    /// Arbitrary bytes through every codec parser: no crash, and structural invariants hold.
    func testCodecParsersHoldInvariantsUnderSeededFuzz() {
        var generator = SeededGenerator(state: 0xFEED_F00D)

        for iteration in 0..<2_000 {
            let length = Int.random(in: 0...384, using: &generator)
            let bytes = (0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) }
            let data = Data(bytes)

            _ = Socks5Codec.hasInvalidGreetingPrefix(data)
            _ = Socks5Codec.requestFailureReplyCode(data)

            var greetingBuffer = data
            if Socks5Codec.parseGreeting(&greetingBuffer) != nil {
                XCTAssertLessThanOrEqual(greetingBuffer.count, data.count, "iteration \(iteration)")
            }

            var requestBuffer = data
            if let request = Socks5Codec.parseRequest(&requestBuffer) {
                XCTAssertLessThan(requestBuffer.count, data.count, "iteration \(iteration)")
                if case .domain(let name) = request.address {
                    XCTAssertLessThanOrEqual(name.utf8.count, Int(UInt8.max), "iteration \(iteration)")
                }
            }

            _ = bytes.withUnsafeBufferPointer { pointer in
                Socks5Codec.parseUDPPacket(pointer, count: bytes.count)
            }

            switch Socks5Codec.parseTCPForwardUDPPacket(data) {
            case .packet(_, let consumedBytes):
                XCTAssertGreaterThan(consumedBytes, 0, "iteration \(iteration)")
                XCTAssertLessThanOrEqual(consumedBytes, data.count, "iteration \(iteration)")
            case .needsMoreData, .invalid:
                break
            }
        }
    }

    /// Same fuzz corpus against non-zero-based slices so index-domain regressions stay caught.
    func testCodecParsersHoldInvariantsUnderSlicedFuzz() {
        var generator = SeededGenerator(state: 0xFEED_F00E)

        for iteration in 0..<500 {
            let prefixLength = Int.random(in: 1...32, using: &generator)
            let length = Int.random(in: 0...256, using: &generator)
            var prefixed = Data((0..<prefixLength).map { _ in UInt8.random(in: 0...255, using: &generator) })
            let payloadStart = prefixed.count
            prefixed.append(contentsOf: (0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) })

            var slice = prefixed[payloadStart...]
            XCTAssertNotEqual(slice.startIndex, 0, "iteration \(iteration)")

            _ = Socks5Codec.hasInvalidGreetingPrefix(slice)
            _ = Socks5Codec.requestFailureReplyCode(slice)
            _ = Socks5Codec.parseRequest(&slice)

            let frameSlice = prefixed[payloadStart...]
            switch Socks5Codec.parseTCPForwardUDPPacket(frameSlice) {
            case .packet(_, let consumedBytes):
                XCTAssertGreaterThan(consumedBytes, 0, "iteration \(iteration)")
                XCTAssertLessThanOrEqual(consumedBytes, frameSlice.count, "iteration \(iteration)")
            case .needsMoreData, .invalid:
                break
            }
        }
    }
}
