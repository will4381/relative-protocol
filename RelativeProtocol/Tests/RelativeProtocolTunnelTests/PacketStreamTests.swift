//
//  PacketStreamTests.swift
//  RelativeProtocolTunnelTests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 11/07/2025.
//
//  Confirms packet stream buffering honours retention windows and delivers
//  snapshots to observers in order.
//
import XCTest
import RelativeProtocolCore
@testable import RelativeProtocolTunnel
import Darwin

final class PacketStreamTests: XCTestCase {
    func testBufferRespectsDuration() {
        let configuration = RelativeProtocol.PacketStream.Configuration(bufferDuration: 30)
        let stream = RelativeProtocol.PacketStream(configuration: configuration)
        let expectation = expectation(description: "snapshot")
        let base = Date()

        // Older sample should be purged once a newer packet arrives.
        let stale = RelativeProtocol.PacketSample(
            timestamp: base.addingTimeInterval(-40),
            direction: .inbound,
            payload: Data([0x01]),
            protocolNumber: Int32(AF_INET)
        )
        let fresh = RelativeProtocol.PacketSample(
            timestamp: base,
            direction: .inbound,
            payload: Data([0x02]),
            protocolNumber: Int32(AF_INET)
        )

        stream.process(stale)
        stream.process(fresh)

        stream.snapshot { samples in
            XCTAssertEqual(samples.count, 1)
            XCTAssertEqual(samples.first?.byteCount, 1)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }
}
