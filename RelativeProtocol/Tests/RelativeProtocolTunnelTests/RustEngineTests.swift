import os.log
import XCTest
import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class RustEngineTests: XCTestCase {
    func testRustEngineUnavailableWithoutBridgeSymbols() {
        let configuration = RelativeProtocol.Configuration()
        let logger = Logger(subsystem: "RelativeProtocolTunnelTests", category: "RustEngine")
        XCTAssertNil(
            RustEngine.make(configuration: configuration, logger: logger),
            "RustEngine should gracefully decline initialization when bridge symbols are missing."
        )
    }

    func testMergedResolverPrefersHooksWhenPopulated() async throws {
        let tracker = RelativeProtocolTunnel.ForwardHostTracker()
        let hooksCounter = ResolverCounter()
        let engineCounter = ResolverCounter()

        let hooksResolver: RelativeProtocol.Configuration.DNSResolver = { _ in
            await hooksCounter.increment()
            return ["203.0.113.1"]
        }
        let engineResolver: RelativeProtocol.Configuration.DNSResolver = { _ in
            await engineCounter.increment()
            return ["198.51.100.2"]
        }

        let merged = RustDNSResolverAdapter.mergedResolver(
            hooksResolver: hooksResolver,
            engineResolver: engineResolver,
            tracker: { tracker }
        )

        let addresses = try await merged("example.com")
        XCTAssertEqual(addresses, ["203.0.113.1"])
        let hooksValue = await hooksCounter.current()
        let engineValue = await engineCounter.current()
        XCTAssertEqual(hooksValue, 1)
        XCTAssertEqual(engineValue, 0)
        XCTAssertEqual(tracker.lookup(ip: "203.0.113.1"), "example.com")
    }

    func testMergedResolverFallsBackWhenHooksEmpty() async throws {
        let engineCounter = ResolverCounter()
        let engineResolver: RelativeProtocol.Configuration.DNSResolver = { _ in
            await engineCounter.increment()
            return ["198.51.100.2"]
        }

        let merged = RustDNSResolverAdapter.mergedResolver(
            hooksResolver: { _ in [] },
            engineResolver: engineResolver,
            tracker: { nil }
        )

        let addresses = try await merged("fallback.test")
        XCTAssertEqual(addresses, ["198.51.100.2"])
        let engineValue = await engineCounter.current()
        XCTAssertEqual(engineValue, 1)
    }
}

private actor ResolverCounter {
    private var value = 0

    func increment() {
        value += 1
    }

    func current() -> Int {
        value
    }
}
