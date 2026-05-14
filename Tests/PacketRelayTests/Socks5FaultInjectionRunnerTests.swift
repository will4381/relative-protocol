import PacketRelay
import XCTest

final class Socks5FaultInjectionRunnerTests: XCTestCase {
    func testBuiltInFaultInjectionScenariosPass() {
        let report = Socks5FaultInjectionRunner().run()

        XCTAssertTrue(report.passed, report.rows.map { "\($0.id): \($0.detail)" }.joined(separator: "\n"))
        XCTAssertEqual(report.rows.count, 8)
        XCTAssertEqual(
            Set(report.rows.map(\.id)),
            [
                "tcp-waiting-default",
                "tcp-waiting-timeout-retry",
                "tcp-waiting-bounded-restart",
                "udp-waiting-retained",
                "udp-failed-recreated",
                "udp-better-path-replaced",
                "tcp-forward-udp-waiting-retained",
                "tcp-forward-udp-better-path-replaced"
            ]
        )
    }
}
