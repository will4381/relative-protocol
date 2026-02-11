// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import XCTest
@testable import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class RelativePacketTunnelProviderEdgeTests: XCTestCase {
    func testMakeNetworkSettingsIncludesIPv6AndDNS() {
        let provider = RelativePacketTunnelProvider()
        let config = TunnelConfiguration(providerConfiguration: [
            "tunnelRemoteAddress": "203.0.113.10",
            "ipv4Address": "10.1.0.2",
            "ipv4SubnetMask": "255.255.255.0",
            "ipv4Router": "10.1.0.1",
            "ipv6Enabled": true,
            "ipv6Address": "fd00:1:1:1::9",
            "ipv6PrefixLength": 64,
            "dnsServers": ["1.1.1.1", "8.8.8.8"],
            "mtu": 1420
        ])

        let settings = provider._test_makeNetworkSettings(from: config)
        XCTAssertEqual(settings.tunnelRemoteAddress, "203.0.113.10")
        XCTAssertEqual(settings.ipv4Settings?.addresses, ["10.1.0.2"])
        XCTAssertEqual(settings.ipv4Settings?.subnetMasks, ["255.255.255.0"])
        XCTAssertEqual(settings.ipv6Settings?.addresses, ["fd00:1:1:1::9"])
        XCTAssertEqual(settings.dnsSettings?.servers, ["1.1.1.1", "8.8.8.8"])
        XCTAssertEqual(settings.mtu?.intValue, 1420)
    }

    func testMakeNetworkSettingsOmitsIPv6WhenDisabled() {
        let provider = RelativePacketTunnelProvider()
        let config = TunnelConfiguration(providerConfiguration: [
            "ipv6Enabled": false,
            "dnsServers": [],
            "mtu": 1300
        ])

        let settings = provider._test_makeNetworkSettings(from: config)
        XCTAssertNil(settings.ipv6Settings)
        XCTAssertNil(settings.dnsSettings)
        XCTAssertEqual(settings.mtu?.intValue, 1300)
    }
}
