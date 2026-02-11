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
}
