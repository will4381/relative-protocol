import XCTest
import Network
import os.log
@testable import RelativeProtocolTunnel

final class NoOpTun2SocksEngineTests: XCTestCase {
    func testEchoesPacketsWhileRunning() throws {
        let engine = NoOpTun2SocksEngine(
            logger: Logger(subsystem: "RelativeProtocolTests", category: "NoOp"),
            debugLoggingEnabled: true
        )

        let readLoopInstalled = expectation(description: "read loop installed")
        let firstEmission = expectation(description: "first packet echoed")
        let noEmissionAfterStop = expectation(description: "no packets after stop")
        noEmissionAfterStop.isInverted = true

        var readHandler: (([Data], [NSNumber]) -> Void)?
        var emissionCount = 0

        let callbacks = Tun2SocksCallbacks(
            startPacketReadLoop: { handler in
                readHandler = handler
                readLoopInstalled.fulfill()
            },
            emitPackets: { packets, protocols in
                emissionCount += 1
                if emissionCount == 1 {
                    XCTAssertEqual(packets, [Data([0x45, 0x00])])
                    XCTAssertEqual(protocols, [NSNumber(value: Int32(AF_INET))])
                    firstEmission.fulfill()
                } else {
                    noEmissionAfterStop.fulfill()
                }
            },
            makeTCPConnection: { endpoint in
                NWConnection(to: endpoint, using: NWParameters(tls: nil, tcp: NWProtocolTCP.Options()))
            },
            makeUDPConnection: { endpoint in
                NWConnection(to: endpoint, using: NWParameters(dtls: nil, udp: NWProtocolUDP.Options()))
            }
        )

        try engine.start(callbacks: callbacks)
        wait(for: [readLoopInstalled], timeout: 1.0)

        readHandler?([Data([0x45, 0x00])], [NSNumber(value: Int32(AF_INET))])
        wait(for: [firstEmission], timeout: 1.0)

        engine.stop()

        readHandler?([Data([0x45, 0x01])], [NSNumber(value: Int32(AF_INET))])
        wait(for: [noEmissionAfterStop], timeout: 0.2)
        XCTAssertEqual(emissionCount, 1)
    }
}
