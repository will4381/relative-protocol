import Foundation
@preconcurrency import NetworkExtension
import PacketRelay
@testable import TunnelControl
import XCTest

final class TunnelControlTests: XCTestCase {
    func testTunnelProfileDefaultsDisableTCPMultipathHandover() {
        let profile = TunnelProfile.from(providerConfiguration: [:])
        XCTAssertFalse(profile.tcpMultipathHandoverEnabled)
    }

    func testTunnelProfileParsesTCPMultipathHandoverFlag() {
        let profile = TunnelProfile.from(providerConfiguration: [
            "tcpMultipathHandoverEnabled": true
        ])
        XCTAssertTrue(profile.tcpMultipathHandoverEnabled)
    }

    func testTunnelProfileManagerPersistsTCPMultipathHandoverFlag() throws {
        let manager = NETunnelProviderManager()
        let profile = TunnelProfile(
            appGroupID: "group.example",
            tunnelRemoteAddress: "127.0.0.1",
            mtu: 1500,
            ipv6Enabled: true,
            tcpMultipathHandoverEnabled: true,
            ipv4Address: "10.0.0.2",
            ipv4SubnetMask: "255.255.255.0",
            ipv4Router: "10.0.0.1",
            ipv6Address: "fd00:1::2",
            ipv6PrefixLength: 64,
            dnsServers: ["1.1.1.1"],
            engineSocksPort: 1080,
            engineLogLevel: "warn",
            telemetryEnabled: true,
            liveTapEnabled: false,
            liveTapIncludeFlowSlices: false,
            liveTapMaxBytes: 5_000_000,
            signatureFileName: "app_signatures.json",
            relayEndpoint: RelayEndpoint(host: "127.0.0.1", port: 1080, useUDP: false),
            dataplaneConfigJSON: "{}"
        )

        TunnelProfileManager.configure(
            manager: manager,
            profile: profile,
            providerBundleIdentifier: "com.example.tunnel",
            localizedDescription: "Test Tunnel"
        )

        let proto = try XCTUnwrap(manager.protocolConfiguration as? NETunnelProviderProtocol)
        let flag = (proto.providerConfiguration?["tcpMultipathHandoverEnabled"] as? NSNumber)?.boolValue
        XCTAssertEqual(flag, true)
    }
}
