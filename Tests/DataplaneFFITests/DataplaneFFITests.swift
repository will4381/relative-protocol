import DataplaneFFI
import Observability
import XCTest

// Docs: https://developer.apple.com/documentation/xctest/xctestcase
/// Dataplane bridge contract tests.
final class DataplaneFFITests: XCTestCase {
    private let deterministicLocalConfig = "{\"mode\":\"deterministic-local\"}"

    /// Verifies that compiled and runtime dataplane versions match the current contract.
    func testVersionMatchesExpectedContract() throws {
        XCTAssertNoThrow(try DataplaneHandle.validateCompatibility(expected: .current))
    }

    /// Verifies version mismatch handling fails fast.
    func testVersionMismatchFailsFast() {
        XCTAssertThrowsError(
            try DataplaneHandle.validateCompatibility(
                expected: DataplaneVersion(apiVersion: 99, abiVersion: 99)
            )
        )
    }

    /// Verifies invalid tunnel descriptors are rejected by dataplane start.
    func testStartRejectsInvalidTunnelDescriptor() async throws {
        let logger = StructuredLogger(sink: InMemoryLogSink())
        let handle = try DataplaneHandle(configJSON: deterministicLocalConfig, callbacks: .noop, logger: logger)
        await XCTAssertThrowsErrorAsync(try await handle.start(tunFD: -1))
    }

    /// Verifies stats query remains available after a successful start.
    func testStatsReadableAfterStart() async throws {
        let logger = StructuredLogger(sink: InMemoryLogSink())
        let handle = try DataplaneHandle(configJSON: deterministicLocalConfig, callbacks: .noop, logger: logger)
        try await handle.start(tunFD: 0)
        let stats = try await handle.stats()
        XCTAssertEqual(stats.bytesIn, 0)
        XCTAssertEqual(stats.bytesOut, 0)
        try await handle.stop()
        await handle.destroy()
    }
}

private extension XCTestCase {
    /// Async helper mirroring `XCTAssertThrowsError` semantics.
    /// - Parameters:
    ///   - expression: Async throwing expression expected to fail.
    ///   - file: Caller file for assertion reporting.
    ///   - line: Caller line for assertion reporting.
    func XCTAssertThrowsErrorAsync(
        _ expression: @autoclosure () async throws -> some Any,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail("Expected error", file: file, line: line)
        } catch {
            XCTAssertTrue(true, file: file, line: line)
        }
    }
}
