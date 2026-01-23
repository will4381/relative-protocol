import XCTest
@testable import RelativeProtocolCore

final class TunnelConfigurationTests: XCTestCase {
    func testDefaultsAreApplied() {
        let config = TunnelConfiguration(providerConfiguration: [:])

        XCTAssertEqual(config.appGroupID, "")
        XCTAssertEqual(config.relayMode, "tun2socks")
        XCTAssertEqual(config.mtu, 1500)
        XCTAssertTrue(config.ipv6Enabled)
        XCTAssertEqual(config.dnsServers, [])
        XCTAssertEqual(config.enginePacketPoolBytes, 2_097_152)
        XCTAssertEqual(config.enginePerFlowBufferBytes, 16_384)
        XCTAssertEqual(config.engineMaxFlows, 512)
        XCTAssertEqual(config.engineSocksPort, 1080)
        XCTAssertEqual(config.engineLogLevel, "")
        XCTAssertTrue(config.metricsEnabled)
        XCTAssertEqual(config.metricsRingBufferSize, 2048)
        XCTAssertEqual(config.metricsSnapshotInterval, 1.0)
        XCTAssertEqual(config.burstThresholdMs, 350)
        XCTAssertEqual(config.flowTTLSeconds, 300)
        XCTAssertEqual(config.maxTrackedFlows, 2048)
        XCTAssertEqual(config.maxPendingAnalytics, 512)

        XCTAssertEqual(config.ipv4Address, "10.0.0.2")
        XCTAssertEqual(config.ipv4SubnetMask, "255.255.255.0")
        XCTAssertEqual(config.ipv4Router, "10.0.0.1")
        XCTAssertEqual(config.ipv6Address, "fd00:1:1:1::2")
        XCTAssertEqual(config.ipv6PrefixLength, 64)
        XCTAssertEqual(config.tunnelRemoteAddress, "127.0.0.1")
    }

    func testParsesMixedTypes() {
        let config = TunnelConfiguration(providerConfiguration: [
            "appGroupID": "group.test",
            "relayMode": "observe",
            "mtu": "1400",
            "ipv6Enabled": "0",
            "dnsServers": ["1.1.1.1", "8.8.8.8"],
            "enginePacketPoolBytes": NSNumber(value: 4096),
            "enginePerFlowBufferBytes": "8192",
            "engineMaxFlows": NSNumber(value: 1024),
            "engineSocksPort": "1081",
            "engineLogLevel": "debug",
            "metricsEnabled": NSNumber(value: 0),
            "metricsRingBufferSize": "128",
            "metricsSnapshotInterval": "2.5",
            "burstThresholdMs": "400",
            "flowTTLSeconds": NSNumber(value: 120),
            "maxTrackedFlows": "4096",
            "maxPendingAnalytics": NSNumber(value: 256),
            "ipv4Address": "10.1.0.2",
            "ipv4SubnetMask": "255.255.0.0",
            "ipv4Router": "10.1.0.1",
            "ipv6Address": "fd00::1",
            "ipv6PrefixLength": "72",
            "tunnelRemoteAddress": "10.0.0.1"
        ])

        XCTAssertEqual(config.appGroupID, "group.test")
        XCTAssertEqual(config.relayMode, "observe")
        XCTAssertEqual(config.mtu, 1400)
        XCTAssertFalse(config.ipv6Enabled)
        XCTAssertEqual(config.dnsServers, ["1.1.1.1", "8.8.8.8"])
        XCTAssertEqual(config.enginePacketPoolBytes, 4096)
        XCTAssertEqual(config.enginePerFlowBufferBytes, 8192)
        XCTAssertEqual(config.engineMaxFlows, 1024)
        XCTAssertEqual(config.engineSocksPort, 1081)
        XCTAssertEqual(config.engineLogLevel, "debug")
        XCTAssertFalse(config.metricsEnabled)
        XCTAssertEqual(config.metricsRingBufferSize, 128)
        XCTAssertEqual(config.metricsSnapshotInterval, 2.5)
        XCTAssertEqual(config.burstThresholdMs, 400)
        XCTAssertEqual(config.flowTTLSeconds, 120)
        XCTAssertEqual(config.maxTrackedFlows, 4096)
        XCTAssertEqual(config.maxPendingAnalytics, 256)
        XCTAssertEqual(config.ipv4Address, "10.1.0.2")
        XCTAssertEqual(config.ipv4SubnetMask, "255.255.0.0")
        XCTAssertEqual(config.ipv4Router, "10.1.0.1")
        XCTAssertEqual(config.ipv6Address, "fd00::1")
        XCTAssertEqual(config.ipv6PrefixLength, 72)
        XCTAssertEqual(config.tunnelRemoteAddress, "10.0.0.1")
    }

    func testStringArrayFiltersNonStrings() {
        let config = TunnelConfiguration(providerConfiguration: [
            "dnsServers": ["1.1.1.1", 2, "8.8.8.8"]
        ])
        XCTAssertEqual(config.dnsServers, ["1.1.1.1", "8.8.8.8"])
    }
}
