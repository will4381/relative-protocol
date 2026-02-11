// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation
import XCTest
@testable import RelativeProtocolCore
@testable import RelativeProtocolTunnel

final class Tun2SocksEngineEdgeTests: XCTestCase {
    func testStartBuildsConfigAndRunsMainClosure() {
        let queue = DispatchQueue(label: "tun2socks.engine.start")
        let started = expectation(description: "engine started")
        let releaseRun = DispatchSemaphore(value: 0)
        var runCount = 0
        var capturedTunFD: Int32 = -1
        var quitCount = 0

        let engine = Tun2SocksEngine(
            queue: queue,
            runMain: { bytes, count, tunFD in
                _ = bytes
                _ = count
                runCount += 1
                capturedTunFD = tunFD
                started.fulfill()
                _ = releaseRun.wait(timeout: .now() + 1.0)
                return 0
            },
            quitMain: {
                quitCount += 1
            }
        )

        let configuration = makeConfiguration(
            engineLogLevel: "debug",
            ipv6Enabled: true,
            ipv6Address: "fd00:1:1:1::7"
        )

        engine.start(configuration: configuration, tunFD: 42, socksPort: 1081)
        wait(for: [started], timeout: 1.0)

        XCTAssertEqual(runCount, 1)
        XCTAssertEqual(capturedTunFD, 42)
        XCTAssertTrue(engine._test_isRunning)

        guard let configString = engine._test_configString else {
            return XCTFail("Expected config string")
        }
        XCTAssertTrue(configString.contains("port: 1081"))
        XCTAssertTrue(configString.contains("log-level: debug"))
        XCTAssertTrue(configString.contains("ipv6: 'fd00:1:1:1::7'"))

        engine.stop()
        XCTAssertEqual(quitCount, 1)
        XCTAssertFalse(engine._test_isRunning)
        XCTAssertNil(engine._test_configString)

        releaseRun.signal()
        flush(queue)
    }

    func testStartIsIgnoredWhileAlreadyRunning() {
        let queue = DispatchQueue(label: "tun2socks.engine.duplicate")
        let started = expectation(description: "engine started once")
        let releaseRun = DispatchSemaphore(value: 0)
        var runCount = 0

        let engine = Tun2SocksEngine(
            queue: queue,
            runMain: { _, _, _ in
                runCount += 1
                started.fulfill()
                _ = releaseRun.wait(timeout: .now() + 1.0)
                return 0
            },
            quitMain: {}
        )

        let configuration = makeConfiguration(engineLogLevel: "warn")
        engine.start(configuration: configuration, tunFD: 11, socksPort: 9000)
        wait(for: [started], timeout: 1.0)
        engine.start(configuration: configuration, tunFD: 12, socksPort: 9001)

        XCTAssertEqual(runCount, 1)

        engine.stop()
        releaseRun.signal()
        flush(queue)
    }

    func testStopDoesNothingWhenEngineIsNotRunning() {
        var quitCount = 0
        let engine = Tun2SocksEngine(
            runMain: { _, _, _ in 0 },
            quitMain: { quitCount += 1 }
        )

        engine.stop()
        XCTAssertEqual(quitCount, 0)
        XCTAssertFalse(engine._test_isRunning)
        XCTAssertNil(engine._test_configString)
    }

    func testConfigLogLevelFallbackMapsToWarn() {
        let queue = DispatchQueue(label: "tun2socks.engine.loglevel")
        let started = expectation(description: "engine started")
        let releaseRun = DispatchSemaphore(value: 0)

        let engine = Tun2SocksEngine(
            queue: queue,
            runMain: { _, _, _ in
                started.fulfill()
                _ = releaseRun.wait(timeout: .now() + 1.0)
                return 0
            },
            quitMain: {}
        )

        let configuration = makeConfiguration(engineLogLevel: "totally-unknown", ipv6Enabled: false)
        engine.start(configuration: configuration, tunFD: 9, socksPort: 7777)
        wait(for: [started], timeout: 1.0)

        let configString = try? XCTUnwrap(engine._test_configString)
        XCTAssertNotNil(configString)
        XCTAssertTrue(configString?.contains("log-level: warn") ?? false)
        XCTAssertFalse(configString?.contains("  ipv6:") ?? true)

        engine.stop()
        releaseRun.signal()
        flush(queue)
    }
}

private func makeConfiguration(
    engineLogLevel: String,
    ipv6Enabled: Bool = true,
    ipv6Address: String = "fd00:1:1:1::2"
) -> TunnelConfiguration {
    TunnelConfiguration(providerConfiguration: [
        "appGroupID": "group.relative.tests",
        "relayMode": "tun2socks",
        "mtu": 1400,
        "ipv4Address": "10.0.0.2",
        "ipv6Enabled": ipv6Enabled,
        "ipv6Address": ipv6Address,
        "engineLogLevel": engineLogLevel
    ])
}

private func flush(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
    let expectation = XCTestExpectation(description: "queue flushed")
    queue.async { expectation.fulfill() }
    XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: timeout), .completed)
}
