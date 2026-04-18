import Foundation
@preconcurrency import NetworkExtension
import PacketRelay
@testable import TunnelControl
import XCTest

final class TunnelControlTests: XCTestCase {
    func testTunnelProfileDefaultsUseRecommendedDNSAndMTUStrategy() {
        let profile = TunnelProfile.from(providerConfiguration: [:])
        XCTAssertFalse(profile.tcpMultipathHandoverEnabled)
        XCTAssertEqual(profile.mtu, 1_280)
        XCTAssertEqual(profile.mtuStrategy, .recommendedGeneric)
        XCTAssertEqual(profile.dnsStrategy, .recommendedDefault)
    }

    func testTunnelProfileParsesTCPMultipathHandoverFlag() {
        let profile = TunnelProfile.from(providerConfiguration: [
            "tcpMultipathHandoverEnabled": true
        ])
        XCTAssertTrue(profile.tcpMultipathHandoverEnabled)
    }

    func testTunnelProfilePreservesEphemeralEngineSocksPort() {
        let profile = TunnelProfile.from(providerConfiguration: [
            "engineSocksPort": 0
        ])

        XCTAssertEqual(profile.engineSocksPort, 0)
    }

    func testTunnelProfileParsesAutomaticTunnelOverheadAndHTTPSDNSStrategy() {
        let profile = TunnelProfile.from(providerConfiguration: [
            "mtu": 1_280,
            "mtuStrategy": "automaticTunnelOverhead",
            "tunnelOverheadBytes": 80,
            "dnsStrategy": [
                "type": "https",
                "servers": ["1.1.1.1", "1.0.0.1"],
                "serverURL": "https://dns.example/dns-query",
                "matchDomains": ["corp.example"],
                "matchDomainsNoSearch": true,
                "allowFailover": true
            ]
        ])

        XCTAssertEqual(profile.mtuStrategy, .automaticTunnelOverhead(80))
        XCTAssertEqual(
            profile.dnsStrategy,
            .https(
                servers: ["1.1.1.1", "1.0.0.1"],
                serverURL: "https://dns.example/dns-query",
                matchDomains: ["corp.example"],
                matchDomainsNoSearch: true,
                allowFailover: true
            )
        )
    }

    func testTunnelProfileManagerPersistsDNSAndMTUStrategies() throws {
        let manager = NETunnelProviderManager()
        let profile = makeProfile(
            mtu: 1_280,
            mtuStrategy: .automaticTunnelOverhead(80),
            dnsStrategy: .tls(
                servers: ["1.1.1.1", "1.0.0.1"],
                serverName: "one.one.one.one",
                matchDomains: ["corp.example"],
                matchDomainsNoSearch: true,
                allowFailover: true
            ),
            tcpMultipathHandoverEnabled: true
        )

        TunnelProfileManager.configure(
            manager: manager,
            profile: profile,
            providerBundleIdentifier: "com.example.tunnel",
            localizedDescription: "Test Tunnel"
        )

        let proto = try XCTUnwrap(manager.protocolConfiguration as? NETunnelProviderProtocol)
        let configuration = try XCTUnwrap(proto.providerConfiguration)
        let flag = (configuration["tcpMultipathHandoverEnabled"] as? NSNumber)?.boolValue
        XCTAssertEqual(flag, true)
        XCTAssertEqual(configuration["mtuStrategy"] as? String, "automaticTunnelOverhead")
        XCTAssertEqual((configuration["tunnelOverheadBytes"] as? NSNumber)?.intValue, 80)
        XCTAssertEqual(configuration["dnsServers"] as? [String], ["1.1.1.1", "1.0.0.1"])
        let dnsStrategy = try XCTUnwrap(configuration["dnsStrategy"] as? [String: Any])
        XCTAssertEqual(dnsStrategy["type"] as? String, "tls")
        XCTAssertEqual(dnsStrategy["serverName"] as? String, "one.one.one.one")
        XCTAssertEqual(dnsStrategy["matchDomains"] as? [String], ["corp.example"])
    }

    func testTunnelProfileManagerPreservesUnknownProviderConfigurationKeys() throws {
        let manager = NETunnelProviderManager()
        let existingProto = NETunnelProviderProtocol()
        existingProto.providerBundleIdentifier = "com.example.tunnel"
        existingProto.serverAddress = "127.0.0.1"
        existingProto.providerConfiguration = [
            "appGroupID": "group.example",
            "mtuStrategy": "automaticTunnelOverhead",
            "tunnelOverheadBytes": 92,
            "vpnConfigVersion": 4,
            "hostOwnedFlag": "keep-me"
        ]
        manager.protocolConfiguration = existingProto

        let profile = makeProfile(
            mtu: 1_280,
            mtuStrategy: .fixed(1_280),
            dnsStrategy: .cleartext(servers: TunnelDNSStrategy.defaultPublicResolvers),
            tcpMultipathHandoverEnabled: true
        )

        TunnelProfileManager.configure(
            manager: manager,
            profile: profile,
            providerBundleIdentifier: "com.example.tunnel",
            localizedDescription: "Test Tunnel"
        )

        let proto = try XCTUnwrap(manager.protocolConfiguration as? NETunnelProviderProtocol)
        let configuration = try XCTUnwrap(proto.providerConfiguration)
        XCTAssertEqual((configuration["vpnConfigVersion"] as? NSNumber)?.intValue, 4)
        XCTAssertEqual(configuration["hostOwnedFlag"] as? String, "keep-me")
        XCTAssertEqual((configuration["mtu"] as? NSNumber)?.intValue, 1_280)
        XCTAssertEqual(configuration["mtuStrategy"] as? String, "fixed")
        XCTAssertNil(configuration["tunnelOverheadBytes"])
    }

    func testTunnelProfileManagerPreservesHostOwnedKeysAcrossRepeatedReconfigure() throws {
        let manager = NETunnelProviderManager()
        let existingProto = NETunnelProviderProtocol()
        existingProto.providerBundleIdentifier = "com.example.tunnel"
        existingProto.serverAddress = "127.0.0.1"
        existingProto.providerConfiguration = [
            "appGroupID": "group.example",
            "vpnConfigVersion": 4,
            "hostOwnedFlag": "keep-me"
        ]
        manager.protocolConfiguration = existingProto

        TunnelProfileManager.configure(
            manager: manager,
            profile: makeProfile(
                mtu: 1_280,
                mtuStrategy: .fixed(1_280),
                dnsStrategy: .cleartext(servers: TunnelDNSStrategy.defaultPublicResolvers),
                tcpMultipathHandoverEnabled: true
            ),
            providerBundleIdentifier: "com.example.tunnel",
            localizedDescription: "Test Tunnel"
        )

        TunnelProfileManager.configure(
            manager: manager,
            profile: makeProfile(
                mtu: 1_280,
                mtuStrategy: .automaticTunnelOverhead(80),
                dnsStrategy: .tls(
                    servers: ["1.1.1.1", "1.0.0.1"],
                    serverName: "one.one.one.one"
                ),
                tcpMultipathHandoverEnabled: true
            ),
            providerBundleIdentifier: "com.example.tunnel",
            localizedDescription: "Test Tunnel"
        )

        let proto = try XCTUnwrap(manager.protocolConfiguration as? NETunnelProviderProtocol)
        let configuration = try XCTUnwrap(proto.providerConfiguration)
        XCTAssertEqual((configuration["vpnConfigVersion"] as? NSNumber)?.intValue, 4)
        XCTAssertEqual(configuration["hostOwnedFlag"] as? String, "keep-me")
        XCTAssertEqual(configuration["mtuStrategy"] as? String, "automaticTunnelOverhead")
        XCTAssertEqual((configuration["tunnelOverheadBytes"] as? NSNumber)?.intValue, 80)
        XCTAssertEqual(configuration["dnsServers"] as? [String], ["1.1.1.1", "1.0.0.1"])
        let dnsStrategy = try XCTUnwrap(configuration["dnsStrategy"] as? [String: Any])
        XCTAssertEqual(dnsStrategy["type"] as? String, "tls")
        XCTAssertEqual(dnsStrategy["serverName"] as? String, "one.one.one.one")
    }

    func testSettingsFactoryUsesFixedMTUAndCleartextDNS() throws {
        let profile = makeProfile(
            appGroupID: "group.example",
            mtu: 1_280,
            mtuStrategy: .fixed(1_280),
            dnsStrategy: .cleartext(
                servers: TunnelDNSStrategy.defaultPublicResolvers,
                matchDomains: ["corp.example"],
                matchDomainsNoSearch: true,
                allowFailover: true
            )
        )

        let settings = TunnelNetworkSettingsFactory.makeSettings(profile: profile)
        XCTAssertEqual(settings.mtu?.intValue, 1_280)
        XCTAssertNil(settings.tunnelOverheadBytes)
        let dnsSettings = try XCTUnwrap(settings.dnsSettings)
        XCTAssertEqual(dnsSettings.servers, TunnelDNSStrategy.defaultPublicResolvers)
        XCTAssertEqual(dnsSettings.matchDomains, ["corp.example"])
        XCTAssertTrue(dnsSettings.matchDomainsNoSearch)
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, *) {
            XCTAssertTrue(dnsSettings.allowFailover)
        }
    }

    func testSettingsFactoryUsesTunnelOverheadAndNoDNSOverride() {
        let profile = makeProfile(
            mtu: 1_280,
            mtuStrategy: .automaticTunnelOverhead(80),
            dnsStrategy: .noOverride
        )

        let settings = TunnelNetworkSettingsFactory.makeSettings(profile: profile)
        XCTAssertNil(settings.mtu)
        XCTAssertEqual(settings.tunnelOverheadBytes?.intValue, 80)
        XCTAssertNil(settings.dnsSettings)
    }

    func testSettingsFactoryBuildsTLSAndHTTPSDNSSettings() throws {
        let tlsProfile = makeProfile(
            dnsStrategy: .tls(
                servers: ["1.1.1.1", "1.0.0.1"],
                serverName: "one.one.one.one"
            )
        )
        let tlsSettings = TunnelNetworkSettingsFactory.makeSettings(profile: tlsProfile)
        let dnsTLS = try XCTUnwrap(tlsSettings.dnsSettings as? NEDNSOverTLSSettings)
        XCTAssertEqual(dnsTLS.servers, ["1.1.1.1", "1.0.0.1"])
        XCTAssertEqual(dnsTLS.serverName, "one.one.one.one")

        let httpsProfile = makeProfile(
            dnsStrategy: .https(
                servers: ["1.1.1.1", "1.0.0.1"],
                serverURL: "https://dns.example/dns-query"
            )
        )
        let httpsSettings = TunnelNetworkSettingsFactory.makeSettings(profile: httpsProfile)
        let dnsHTTPS = try XCTUnwrap(httpsSettings.dnsSettings as? NEDNSOverHTTPSSettings)
        XCTAssertEqual(dnsHTTPS.servers, ["1.1.1.1", "1.0.0.1"])
        XCTAssertEqual(dnsHTTPS.serverURL?.absoluteString, "https://dns.example/dns-query")
    }

    private func makeProfile(
        appGroupID: String = "group.example",
        mtu: Int = 1_280,
        mtuStrategy: TunnelMTUStrategy? = nil,
        dnsStrategy: TunnelDNSStrategy? = nil,
        tcpMultipathHandoverEnabled: Bool = false
    ) -> TunnelProfile {
        TunnelProfile(
            appGroupID: appGroupID,
            tunnelRemoteAddress: "127.0.0.1",
            mtu: mtu,
            mtuStrategy: mtuStrategy,
            ipv6Enabled: true,
            tcpMultipathHandoverEnabled: tcpMultipathHandoverEnabled,
            ipv4Address: "10.0.0.2",
            ipv4SubnetMask: "255.255.255.0",
            ipv4Router: "10.0.0.1",
            ipv6Address: "fd00:1::2",
            ipv6PrefixLength: 64,
            dnsServers: dnsStrategy?.servers ?? TunnelDNSStrategy.defaultPublicResolvers,
            dnsStrategy: dnsStrategy,
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
    }
}
