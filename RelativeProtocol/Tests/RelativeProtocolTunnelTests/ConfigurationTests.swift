import XCTest
@testable import RelativeProtocolCore

final class ConfigurationTests: XCTestCase {
    func testValidateOrThrowThrowsForInvalidIPv4() {
        var provider = RelativeProtocol.Configuration.Provider.default
        provider.ipv4.address = "999.0.0.1"
        let configuration = RelativeProtocol.Configuration(provider: provider)

        XCTAssertThrowsError(try configuration.validateOrThrow()) { error in
            guard case RelativeProtocol.PackageError.invalidConfiguration(let issues) = error else {
                XCTFail("Unexpected error type \(error)")
                return
            }
            XCTAssertTrue(issues.contains(where: { $0.contains("IPv4 address") }))
        }
    }

    func testProviderConfigurationDictionaryRoundTrips() {
        let provider = RelativeProtocol.Configuration.Provider(
            mtu: 1500,
            ipv4: .init(
                address: "10.0.0.2",
                subnetMask: "255.255.255.0",
                remoteAddress: "198.51.100.1"
            ),
            dns: .init(servers: ["1.1.1.1"], searchDomains: ["example.com"], matchDomains: ["example.com"]),
            metrics: .init(isEnabled: false, reportingInterval: 30),
            policies: .init(blockedHosts: ["blocked.example"], latencyRules: [.global(50)])
        )
        let configuration = RelativeProtocol.Configuration(
            provider: provider,
            hooks: .init(),
            logging: .init(enableDebug: true)
        )

        let dictionary = configuration.providerConfigurationDictionary()
        XCTAssertFalse(dictionary.isEmpty)

        let decoded = RelativeProtocol.Configuration.load(from: dictionary)
        XCTAssertEqual(decoded, configuration)
        XCTAssertEqual(decoded.provider.metrics.reportingInterval, 30)
        XCTAssertFalse(decoded.provider.metrics.isEnabled)
    }

    func testMatchesBlockedHostIsCaseInsensitive() {
        var provider = RelativeProtocol.Configuration.Provider.default
        provider.policies = .init(blockedHosts: ["Example.com"])
        let configuration = RelativeProtocol.Configuration(provider: provider)

        XCTAssertTrue(configuration.matchesBlockedHost("sub.example.COM"))
        XCTAssertFalse(configuration.matchesBlockedHost("allowed.example.net"))
    }

    func testPackageErrorDescriptionsAreReadable() {
        let invalid = RelativeProtocol.PackageError.invalidConfiguration(["MTU too low"])
        XCTAssertEqual(
            invalid.localizedDescription,
            "Invalid Relative Protocol configuration: MTU too low."
        )

        let network = RelativeProtocol.PackageError.networkSettingsFailed("timeout")
        XCTAssertEqual(
            network.localizedDescription,
            "Failed to apply Relative Protocol network settings: timeout."
        )

        let engine = RelativeProtocol.PackageError.engineStartFailed("boom")
        XCTAssertEqual(
            engine.localizedDescription,
            "Unable to start Relative Protocol engine: boom."
        )
    }

    func testValidationMessageHelpersExposeSeverity() {
        let warning = RelativeProtocol.Configuration.ValidationMessage.warning("Heads up")
        XCTAssertEqual(warning.message, "Heads up")
        XCTAssertEqual(warning.severityLabel, "warning")
        XCTAssertFalse(warning.isError)

        let error = RelativeProtocol.Configuration.ValidationMessage.error("Broken")
        XCTAssertEqual(error.message, "Broken")
        XCTAssertEqual(error.severityLabel, "error")
        XCTAssertTrue(error.isError)
    }
}
