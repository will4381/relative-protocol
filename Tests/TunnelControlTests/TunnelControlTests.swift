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
        XCTAssertEqual(profile.dnsServers, TunnelDNSStrategy.defaultPublicResolvers)
    }

    func testRuntimeProfileValidationFailsClosedForEmptyProviderConfiguration() {
        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: [:])) { error in
            guard case TunnelProfileValidationError.missingRequiredKeys(let keys) = error else {
                XCTFail("Expected missingRequiredKeys, got \(error)")
                return
            }
            XCTAssertTrue(keys.contains("appGroupID"))
            XCTAssertTrue(keys.contains("engineSocksPort"))
        }
    }

    func testRuntimeProfileValidationRejectsUnsafeRawDataplaneConfig() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dataplaneConfigJSON"] = """
        tunnel:
          name: tun0
        misc:
          pid-file: /tmp/vpnbridge.pid
        """

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(error as? TunnelProfileValidationError, .unsafeDataplaneConfig("pid-file"))
        }
    }

    func testRuntimeProfileValidationRejectsSpacedAndQuotedRawDataplaneConfigKeys() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dataplaneConfigJSON"] = """
        misc:
          log-file : /tmp/vpnbridge.log
        """

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(error as? TunnelProfileValidationError, .unsafeDataplaneConfig("log-file"))
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["dataplaneConfigJSON"] = """
        misc:
          "pid-file": "/tmp/vpnbridge.pid"
        """

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(error as? TunnelProfileValidationError, .unsafeDataplaneConfig("pid-file"))
        }
    }

    func testRuntimeProfileValidationRejectsSignaturePathTraversal() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["signatureFileName"] = "../app_signatures.json"

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "signatureFileName", reason: "must be a single file name without path separators")
            )
        }
    }

    func testRuntimeProfileValidationRejectsMalformedNetworkAddresses() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["ipv4Address"] = "10.0.0.999"

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "ipv4Address", reason: "must be a valid IPv4 address")
            )
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["ipv4SubnetMask"] = "255.0.255.0"

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "ipv4SubnetMask", reason: "must be a contiguous IPv4 subnet mask")
            )
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["tunnelRemoteAddress"] = "bad/host"

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "tunnelRemoteAddress", reason: "must be a hostname or IP literal without whitespace")
            )
        }
    }

    func testRuntimeProfileValidationRejectsOutOfRangePortsBeforeClamping() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["engineSocksPort"] = -1

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "engineSocksPort", reason: "must be in 0...65535")
            )
        }
    }

    func testRuntimeProfileValidationIgnoresLegacyRelayHostAndPort() throws {
        var configuration = makeRuntimeProviderConfiguration()
        configuration.removeValue(forKey: "relayHost")
        configuration.removeValue(forKey: "relayPort")
        _ = try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)

        configuration["relayHost"] = "bad host"
        configuration["relayPort"] = 70_000
        _ = try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)
    }

    func testRuntimeProfileValidationRejectsOutOfRangeMTUBeforeClamping() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["mtu"] = 70_000

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "mtu", reason: "must be in 1280...65535")
            )
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["mtu"] = true

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "mtu", reason: "must be in 1280...65535")
            )
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["mtuStrategy"] = "automaticTunnelOverhead"
        configuration["tunnelOverheadBytes"] = true

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "tunnelOverheadBytes", reason: "must be in 0...65535")
            )
        }
    }

    func testRuntimeProfileValidationRejectsIncompleteEncryptedDNS() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "tls",
            "servers": ["1.1.1.1"]
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(
                    key: "dnsStrategy.serverName",
                    reason: "must be a DNS-over-TLS server name without whitespace"
                )
            )
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "https",
            "servers": ["1.1.1.1"],
            "serverURL": "http://dns.example/dns-query"
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "dnsStrategy.serverURL", reason: "must be an HTTPS URL with a host")
            )
        }
    }

    func testRuntimeProfileValidationRejectsMixedProviderStringArrays() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dnsServers"] = ["1.1.1.1", 123]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "dnsServers", reason: "must be an array of strings")
            )
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "cleartext",
            "servers": ["1.1.1.1", 123],
            "matchDomains": [""]
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "dnsStrategy.servers", reason: "must be an array of strings")
            )
        }

        configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "cleartext",
            "servers": ["1.1.1.1"],
            "matchDomains": ["", 123]
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "dnsStrategy.matchDomains", reason: "must be an array of strings")
            )
        }
    }

    func testRuntimeProfileValidationAcceptsDefaultDNSMatchDomain() throws {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "https",
            "servers": ["8.8.8.8", "8.8.4.4"],
            "serverURL": "https://dns.google/dns-query",
            "matchDomains": [""]
        ]

        let profile = try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)
        XCTAssertEqual(
            profile.dnsStrategy,
            .https(
                servers: ["8.8.8.8", "8.8.4.4"],
                serverURL: "https://dns.google/dns-query",
                matchDomains: [""]
            )
        )
    }

    func testRuntimeProfileValidationRejectsWhitespaceDNSMatchDomain() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "https",
            "servers": ["8.8.8.8", "8.8.4.4"],
            "serverURL": "https://dns.google/dns-query",
            "matchDomains": [" "]
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(
                    key: "dnsStrategy.matchDomains",
                    reason: "must contain domain names without whitespace; use an empty string only for the default domain"
                )
            )
        }
    }

    func testRuntimeProfileValidationRejectsEmptyDNSMatchDomainList() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "cleartext",
            "servers": ["1.1.1.1"],
            "matchDomains": []
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(
                    key: "dnsStrategy.matchDomains",
                    reason: "must include at least one domain selector; use an empty string for the default domain"
                )
            )
        }
    }

    func testRuntimeProfileValidationRejectsMalformedDNSMatchDomain() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["dnsStrategy"] = [
            "type": "cleartext",
            "servers": ["1.1.1.1"],
            "matchDomains": ["bad/domain"]
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(
                    key: "dnsStrategy.matchDomains",
                    reason: "must contain domain names without whitespace; use an empty string only for the default domain"
                )
            )
        }
    }

    func testRuntimeProfileValidationAcceptsCompleteProviderConfiguration() throws {
        let profile = try TunnelProfile.validatedRuntimeProfile(providerConfiguration: makeRuntimeProviderConfiguration())
        XCTAssertEqual(profile.appGroupID, "group.example")
        XCTAssertEqual(profile.engineSocksPort, 0)
        XCTAssertEqual(profile.dnsStrategy, .recommendedDefault)
        XCTAssertEqual(profile.dnsServers, TunnelDNSStrategy.defaultPublicResolvers)
    }

    func testRuntimeProfileValidationRejectsMalformedIncludedIPv4Routes() {
        var configuration = makeRuntimeProviderConfiguration()
        configuration["ipv4IncludedRoutes"] = [
            [
                "destinationAddress": "203.0.113.999",
                "subnetMask": "255.255.255.255"
            ]
        ]

        XCTAssertThrowsError(try TunnelProfile.validatedRuntimeProfile(providerConfiguration: configuration)) { error in
            XCTAssertEqual(
                error as? TunnelProfileValidationError,
                .invalidValue(key: "ipv4IncludedRoutes", reason: "destinationAddress must be a valid IPv4 address")
            )
        }
    }

    func testAutomaticTunnelOverheadUsesSafeInternalMTUBuffer() {
        let profile = TunnelProfile.from(providerConfiguration: [
            "mtuStrategy": "automaticTunnelOverhead",
            "tunnelOverheadBytes": 80
        ])

        XCTAssertEqual(profile.mtuStrategy, .automaticTunnelOverhead(80))
        XCTAssertEqual(profile.mtu, TunnelMTUStrategy.automaticBufferMTUHint)
    }

    func testTunnelProfileParsesTCPMultipathHandoverFlag() {
        let profile = TunnelProfile.from(providerConfiguration: [
            "tcpMultipathHandoverEnabled": true
        ])
        XCTAssertTrue(profile.tcpMultipathHandoverEnabled)
    }

    func testTunnelProfileParsesIncludedIPv4Routes() {
        let profile = TunnelProfile.from(providerConfiguration: [
            "ipv4IncludedRoutes": [
                [
                    "destinationAddress": "203.0.113.10",
                    "subnetMask": "255.255.255.255"
                ]
            ]
        ])

        XCTAssertEqual(
            profile.ipv4RouteStrategy,
            .includedRoutes([
                TunnelIPv4Route(destinationAddress: "203.0.113.10", subnetMask: "255.255.255.255")
            ])
        )
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
            tcpMultipathHandoverEnabled: true,
            ipv4RouteStrategy: .includedRoutes([
                TunnelIPv4Route(destinationAddress: "203.0.113.10", subnetMask: "255.255.255.255")
            ])
        )

        TunnelProfileManager.configure(
            manager: manager,
            profile: profile,
            providerBundleIdentifier: "com.example.tunnel",
            localizedDescription: "Test Tunnel"
        )

        let proto = try XCTUnwrap(manager.protocolConfiguration as? NETunnelProviderProtocol)
        let configuration = try XCTUnwrap(proto.providerConfiguration)
        XCTAssertEqual((configuration["vpnBridgeProfileVersion"] as? NSNumber)?.intValue, TunnelProfileManager.currentProviderConfigurationVersion)
        let flag = (configuration["tcpMultipathHandoverEnabled"] as? NSNumber)?.boolValue
        XCTAssertEqual(flag, true)
        XCTAssertEqual(configuration["mtuStrategy"] as? String, "automaticTunnelOverhead")
        XCTAssertEqual((configuration["tunnelOverheadBytes"] as? NSNumber)?.intValue, 80)
        let routes = try XCTUnwrap(configuration["ipv4IncludedRoutes"] as? [[String: String]])
        XCTAssertEqual(routes, [["destinationAddress": "203.0.113.10", "subnetMask": "255.255.255.255"]])
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
            "relayHost": "legacy.example",
            "relayPort": 9_999,
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
        XCTAssertNil(configuration["relayHost"])
        XCTAssertNil(configuration["relayPort"])
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

    func testSettingsFactoryInstallsIncludedIPv4Routes() {
        let profile = makeProfile(
            ipv4RouteStrategy: .includedRoutes([
                TunnelIPv4Route(destinationAddress: "203.0.113.10", subnetMask: "255.255.255.255")
            ])
        )

        let settings = TunnelNetworkSettingsFactory.makeSettings(profile: profile)
        let routes = settings.ipv4Settings?.includedRoutes ?? []
        XCTAssertEqual(routes.count, 1)
        XCTAssertEqual(routes.first?.destinationAddress, "203.0.113.10")
        XCTAssertEqual(routes.first?.destinationSubnetMask, "255.255.255.255")
    }

    func testSettingsFactoryInstallsDefaultDNSForFullTunnel() throws {
        let profile = makeProfile(
            mtu: 1_280,
            mtuStrategy: .automaticTunnelOverhead(80),
            dnsStrategy: .recommendedDefault
        )

        let settings = TunnelNetworkSettingsFactory.makeSettings(profile: profile)
        let dnsSettings = try XCTUnwrap(settings.dnsSettings)
        XCTAssertEqual(dnsSettings.servers, TunnelDNSStrategy.defaultPublicResolvers)
        XCTAssertEqual(dnsSettings.matchDomains, [""])
        XCTAssertTrue(dnsSettings.matchDomainsNoSearch)
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, *) {
            XCTAssertFalse(dnsSettings.allowFailover)
        }
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

    func testSettingsFactoryDropsInvalidDirectDNSSettings() {
        let emptyServers = makeProfile(dnsServers: [], dnsStrategy: nil)
        XCTAssertNil(TunnelNetworkSettingsFactory.makeSettings(profile: emptyServers).dnsSettings)

        let malformedServer = makeProfile(dnsStrategy: .cleartext(servers: ["not an ip"]))
        XCTAssertNil(TunnelNetworkSettingsFactory.makeSettings(profile: malformedServer).dnsSettings)

        let malformedTLS = makeProfile(
            dnsStrategy: .tls(servers: ["1.1.1.1"], serverName: "bad/name")
        )
        XCTAssertNil(TunnelNetworkSettingsFactory.makeSettings(profile: malformedTLS).dnsSettings)

        let malformedHTTPS = makeProfile(
            dnsStrategy: .https(servers: ["1.1.1.1"], serverURL: "http://dns.example/dns-query")
        )
        XCTAssertNil(TunnelNetworkSettingsFactory.makeSettings(profile: malformedHTTPS).dnsSettings)

        let emptyMatchDomains = makeProfile(
            dnsStrategy: .cleartext(servers: ["1.1.1.1"], matchDomains: [])
        )
        XCTAssertNil(TunnelNetworkSettingsFactory.makeSettings(profile: emptyMatchDomains).dnsSettings)

        let malformedMatchDomain = makeProfile(
            dnsStrategy: .cleartext(servers: ["1.1.1.1"], matchDomains: ["bad/domain"])
        )
        XCTAssertNil(TunnelNetworkSettingsFactory.makeSettings(profile: malformedMatchDomain).dnsSettings)
    }

    func testDataplaneConfigHonorsRelayUDPTransportMode() {
        let tcpCarriedUDPConfig = PacketTunnelProviderShell.makeDataplaneConfig(
            profile: makeProfile(relayUseUDP: false),
            socksPort: 1080
        )
        XCTAssertFalse(tcpCarriedUDPConfig.contains("  udp: 'udp'"))

        let udpOverUDPConfig = PacketTunnelProviderShell.makeDataplaneConfig(
            profile: makeProfile(relayUseUDP: true),
            socksPort: 1080
        )
        XCTAssertTrue(udpOverUDPConfig.contains("  udp: 'udp'"))
    }

    private func makeProfile(
        appGroupID: String = "group.example",
        mtu: Int = 1_280,
        mtuStrategy: TunnelMTUStrategy? = nil,
        dnsServers: [String]? = nil,
        dnsStrategy: TunnelDNSStrategy? = nil,
        tcpMultipathHandoverEnabled: Bool = false,
        relayUseUDP: Bool = false,
        ipv4RouteStrategy: TunnelIPv4RouteStrategy? = nil
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
            ipv4RouteStrategy: ipv4RouteStrategy,
            ipv6Address: "fd00:1::2",
            ipv6PrefixLength: 64,
            dnsServers: dnsServers ?? dnsStrategy?.servers ?? TunnelDNSStrategy.defaultPublicResolvers,
            dnsStrategy: dnsStrategy,
            engineSocksPort: 1080,
            engineLogLevel: "warn",
            telemetryEnabled: true,
            liveTapEnabled: false,
            liveTapIncludeFlowSlices: false,
            liveTapMaxBytes: 5_000_000,
            signatureFileName: "app_signatures.json",
            relayEndpoint: RelayEndpoint(host: "127.0.0.1", port: 1080, useUDP: relayUseUDP),
            dataplaneConfigJSON: "{}"
        )
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
