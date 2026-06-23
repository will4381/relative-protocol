// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Darwin
import Foundation
@preconcurrency import NetworkExtension
@testable import TunnelControl
import XCTest

final class NetworkExtensionContractSimulatorTests: XCTestCase {
    func testStartAppliesDocumentedPacketTunnelSettingsAndTransitionsToConnected() throws {
        let simulator = NetworkExtensionContractSimulator(providerConfiguration: makeRuntimeProviderConfiguration())

        let result = try simulator.startTunnel(options: ["reason": "test" as NSString])
        let snapshot = TunnelNetworkSettingsSnapshot.capture(result.settings)

        XCTAssertEqual(simulator.status, .connected)
        XCTAssertEqual(result.options?["reason"] as? NSString, "test")
        XCTAssertEqual(result.profile.appGroupID, "group.example")
        XCTAssertEqual(simulator.appliedSettings.count, 1)
        XCTAssertEqual(
            simulator.events.map(\.name),
            ["initialized", "startTunnel", "setTunnelNetworkSettings", "connected"]
        )

        XCTAssertEqual(snapshot.tunnelRemoteAddress, "127.0.0.1")
        XCTAssertEqual(snapshot.ipv4Addresses, ["10.0.0.2"])
        XCTAssertEqual(snapshot.ipv4SubnetMasks, ["255.255.255.0"])
        XCTAssertTrue(snapshot.hasIPv4DefaultRoute)
        XCTAssertEqual(snapshot.ipv6Addresses, ["fd00:1::2"])
        XCTAssertEqual(snapshot.ipv6PrefixLengths, [64])
        XCTAssertTrue(snapshot.hasIPv6DefaultRoute)
        XCTAssertEqual(snapshot.dnsKind, .cleartext)
        XCTAssertEqual(snapshot.dnsServers, TunnelDNSStrategy.defaultPublicResolvers)
        XCTAssertEqual(snapshot.mtu, 1_280)
        XCTAssertNil(snapshot.tunnelOverheadBytes)
    }

    func testSettingsApplicationFailureFailsStartAndRestoresDisconnectedStatus() {
        let simulator = NetworkExtensionContractSimulator(providerConfiguration: makeRuntimeProviderConfiguration())
        simulator.nextSettingsError = "route-install-failed"

        XCTAssertThrowsError(try simulator.startTunnel()) { error in
            XCTAssertEqual(
                error as? NetworkExtensionContractSimulator.Error,
                .settingsApplicationFailed("route-install-failed")
            )
        }

        XCTAssertEqual(simulator.status, .disconnected)
        XCTAssertEqual(
            simulator.events.map(\.name),
            ["initialized", "startTunnel", "startTunnelFailed"]
        )
        XCTAssertTrue(simulator.appliedSettings.isEmpty)
    }

    func testPacketFlowReadWaitsForNextBatchAndWriteCapturesInboundPackets() {
        let flow = MockPacketTunnelFlow()
        let outboundPacket = Data([0x45, 0x00, 0x00, 0x14])
        let inboundPacket = Data([0x60, 0x00, 0x00, 0x00])
        var receivedBatch: MockPacketTunnelFlow.PacketBatch?

        flow.readPackets { packets, protocols in
            receivedBatch = MockPacketTunnelFlow.PacketBatch(packets: packets, protocols: protocols)
        }

        XCTAssertNil(receivedBatch)
        XCTAssertEqual(flow.readRequests, 1)

        flow.enqueueReadBatch(
            MockPacketTunnelFlow.PacketBatch(
                packets: [outboundPacket],
                protocols: [NSNumber(value: AF_INET)]
            )
        )

        XCTAssertEqual(receivedBatch?.packets, [outboundPacket])
        XCTAssertEqual(receivedBatch?.protocols.map(\.int32Value), [AF_INET])

        flow.writeResults = [false]
        let writeSucceeded = flow.writePackets([inboundPacket], withProtocols: [NSNumber(value: AF_INET6)])

        XCTAssertFalse(writeSucceeded)
        XCTAssertEqual(flow.writtenBatches.count, 1)
        XCTAssertEqual(flow.writtenBatches.first?.packets, [inboundPacket])
        XCTAssertEqual(flow.writtenBatches.first?.protocols.map(\.int32Value), [AF_INET6])
    }

    func testPacketObjectFlowMirrorsModernNEPacketAPIs() {
        let flow = MockPacketTunnelFlow()
        let packet = NEPacket(data: Data([0x45, 0x00, 0x00, 0x14]), protocolFamily: sa_family_t(AF_INET))
        var receivedPackets: [NEPacket] = []

        flow.readPacketObjects { packets in
            receivedPackets = packets
        }

        flow.enqueuePacketObjectReadBatch(MockPacketTunnelFlow.PacketObjectBatch(packets: [packet]))
        XCTAssertEqual(flow.packetObjectReadRequests, 1)
        XCTAssertEqual(receivedPackets.map(\.data), [packet.data])
        XCTAssertEqual(receivedPackets.map { Int32($0.protocolFamily) }, [AF_INET])

        XCTAssertTrue(flow.writePacketObjects([packet]))
        XCTAssertEqual(flow.writtenPacketObjectBatches.count, 1)
        XCTAssertEqual(flow.writtenPacketObjectBatches.first?.packets.map(\.data), [packet.data])
    }

    func testReassertingStopCancelAndProviderMessagesFollowSessionContract() throws {
        let simulator = NetworkExtensionContractSimulator(providerConfiguration: makeRuntimeProviderConfiguration())
        _ = try simulator.startTunnel()

        simulator.setReasserting(true)
        XCTAssertEqual(simulator.status, .reasserting)
        simulator.setReasserting(false)
        XCTAssertEqual(simulator.status, .connected)

        simulator.appMessageHandler = { message in
            XCTAssertEqual(String(data: message, encoding: .utf8), "snapshot")
            return Data("ok".utf8)
        }
        let response = simulator.handleAppMessage(Data("snapshot".utf8))
        XCTAssertEqual(String(data: try XCTUnwrap(response), encoding: .utf8), "ok")

        try simulator.stopTunnel(with: .userInitiated)
        XCTAssertEqual(simulator.status, .disconnected)
        XCTAssertEqual(simulator.events.suffix(2).map(\.name), ["stopTunnel", "disconnected"])
        XCTAssertEqual(simulator.events.last?.stopReasonRawValue, NEProviderStopReason.userInitiated.rawValue)

        simulator.cancelTunnelWithError(nil)
        XCTAssertEqual(simulator.status, .disconnected)
        XCTAssertEqual(simulator.events.suffix(2).map(\.name), ["cancelTunnelWithError", "disconnected"])
    }

    private func makeRuntimeProviderConfiguration() -> [String: Any] {
        [
            "appGroupID": "group.example",
            "tunnelRemoteAddress": "127.0.0.1",
            "mtu": 1_280,
            "ipv6Enabled": true,
            "ipv4Address": "10.0.0.2",
            "ipv4SubnetMask": "255.255.255.0",
            "ipv4Router": "10.0.0.1",
            "ipv6Address": "fd00:1::2",
            "ipv6PrefixLength": 64,
            "dnsStrategy": [
                "type": "cleartext",
                "servers": TunnelDNSStrategy.defaultPublicResolvers,
                "matchDomains": [""],
                "matchDomainsNoSearch": true,
                "allowFailover": false
            ],
            "engineSocksPort": 0,
            "engineLogLevel": "warn",
            "telemetryEnabled": true,
            "liveTapEnabled": false,
            "liveTapIncludeFlowSlices": false,
            "liveTapMaxBytes": 5_000_000,
            "signatureFileName": "app_signatures.json",
            "relayHost": "127.0.0.1",
            "relayPort": 1080,
            "relayUDP": false,
            "dataplaneConfigJSON": "{}"
        ]
    }
}
