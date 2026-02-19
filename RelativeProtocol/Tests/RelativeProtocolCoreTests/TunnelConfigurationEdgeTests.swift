// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import XCTest
import RelativeProtocolCore

final class TunnelConfigurationEdgeTests: XCTestCase {
    func testUnknownMetricsFormatFallsBackToJSON() {
        let config = TunnelConfiguration(providerConfiguration: [
            "metricsStoreFormat": "protobuf"
        ])
        XCTAssertEqual(config.metricsStoreFormat, .json)
    }

    func testStringBooleanParsingSupportsCommonVariants() {
        let config = TunnelConfiguration(providerConfiguration: [
            "metricsEnabled": "YES",
            "packetStreamEnabled": "false",
            "ipv6Enabled": "True"
        ])

        XCTAssertTrue(config.metricsEnabled)
        XCTAssertFalse(config.packetStreamEnabled)
        XCTAssertTrue(config.ipv6Enabled)
    }

    func testEmptyStringValuesUseDefaults() {
        let config = TunnelConfiguration(providerConfiguration: [
            "relayMode": "",
            "signatureFileName": "",
            "tunnelRemoteAddress": ""
        ])

        XCTAssertEqual(config.relayMode, "tun2socks")
        XCTAssertEqual(config.signatureFileName, AppSignatureStore.defaultFileName)
        XCTAssertEqual(config.tunnelRemoteAddress, "127.0.0.1")
    }

    func testInvalidDNSShapeFallsBackToDefault() {
        let config = TunnelConfiguration(providerConfiguration: [
            "dnsServers": "1.1.1.1"
        ])
        XCTAssertEqual(config.dnsServers, [])
    }

    func testNegativeKeepaliveIntervalClampsToZero() {
        let config = TunnelConfiguration(providerConfiguration: [
            "keepaliveIntervalSeconds": -5
        ])
        XCTAssertEqual(config.keepaliveIntervalSeconds, 0)
    }

    func testInvalidNumericRangesAreClamped() {
        let config = TunnelConfiguration(providerConfiguration: [
            "mtu": 0,
            "engineSocksPort": 99_999,
            "metricsRingBufferSize": -20,
            "metricsSnapshotInterval": -1,
            "packetStreamMaxBytes": 0,
            "flowTTLSeconds": 0,
            "maxTrackedFlows": -1,
            "maxPendingAnalytics": 0,
            "tunnelOverheadBytes": -3
        ])

        XCTAssertEqual(config.mtu, 576)
        XCTAssertEqual(config.engineSocksPort, 1080)
        XCTAssertEqual(config.metricsRingBufferSize, 1)
        XCTAssertEqual(config.metricsSnapshotInterval, 1)
        XCTAssertEqual(config.packetStreamMaxBytes, 65_536)
        XCTAssertEqual(config.flowTTLSeconds, 1)
        XCTAssertEqual(config.maxTrackedFlows, 1)
        XCTAssertEqual(config.maxPendingAnalytics, 1)
        XCTAssertEqual(config.tunnelOverheadBytes, 0)
    }

    func testInvalidIPAddressesFallBackToDefaults() {
        let config = TunnelConfiguration(providerConfiguration: [
            "ipv4Address": "999.999.0.1",
            "ipv4SubnetMask": "invalid-mask",
            "ipv4Router": "router",
            "ipv6Address": "this-is-not-ipv6",
            "tunnelRemoteAddress": "also-not-an-ip"
        ])

        XCTAssertEqual(config.ipv4Address, "10.0.0.2")
        XCTAssertEqual(config.ipv4SubnetMask, "255.255.255.0")
        XCTAssertEqual(config.ipv4Router, "10.0.0.1")
        XCTAssertEqual(config.ipv6Address, "fd00:1:1:1::2")
        XCTAssertEqual(config.tunnelRemoteAddress, "127.0.0.1")
    }
}
