// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation
import HevSocks5Tunnel
import RelativeProtocolCore

final class Tun2SocksEngine {
    private let logger = RelativeLog.logger(.tunnel)
    private let queue: DispatchQueue
    private let stateQueue = DispatchQueue(label: "com.relative.protocol.tun2socks.state")
    private let runMain: (_ bytes: UnsafePointer<UInt8>, _ count: UInt32, _ tunFD: Int32) -> Int32
    private let quitMain: () -> Void
    private var configData: Data?
    private var running = false

    init(
        queue: DispatchQueue = DispatchQueue(label: "com.relative.protocol.tun2socks"),
        runMain: @escaping (_ bytes: UnsafePointer<UInt8>, _ count: UInt32, _ tunFD: Int32) -> Int32 = { bytes, count, tunFD in
            hev_socks5_tunnel_main_from_str(bytes, count, tunFD)
        },
        quitMain: @escaping () -> Void = {
            hev_socks5_tunnel_quit()
        }
    ) {
        self.queue = queue
        self.runMain = runMain
        self.quitMain = quitMain
    }

    func start(configuration: TunnelConfiguration, tunFD: Int32, socksPort: UInt16) {
        guard !isRunning() else { return }
        setRunning(true)

        let configString = buildConfigString(configuration: configuration, socksPort: socksPort)
        if RelativeLog.isVerbose {
            NSLog("Tun2SocksEngine: socks5 address=127.0.0.1 port=\(socksPort)")
            NSLog("Tun2SocksEngine: starting with tunFD=\(tunFD) socksPort=\(socksPort)")
        }
        let data = Data(configString.utf8)
        configData = data

        queue.async { [weak self] in
            guard let self else { return }
            let result = data.withUnsafeBytes { rawBuffer -> Int32 in
                guard let base = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                    return -1
                }
                return self.runMain(base, UInt32(data.count), tunFD)
            }
            if RelativeLog.isVerbose {
                self.logger.info("tun2socks exited with code \(result, privacy: .public)")
                NSLog("Tun2SocksEngine: exited with code \(result)")
            }
            self.setRunning(false)
        }
    }

    func stop() {
        guard isRunning() else { return }
        if RelativeLog.isVerbose {
            NSLog("Tun2SocksEngine: stop requested")
        }
        quitMain()
        setRunning(false)
        configData = nil
    }

    private func isRunning() -> Bool {
        stateQueue.sync { running }
    }

    private func setRunning(_ value: Bool) {
        stateQueue.sync {
            running = value
        }
    }

    private func buildConfigString(configuration: TunnelConfiguration, socksPort: UInt16) -> String {
        let tcpBufferSize = Self.clamp(configuration.enginePerFlowBufferBytes, min: 4_096, max: 1_048_576)
        let udpRecvBufferSize = Self.clamp(configuration.enginePacketPoolBytes, min: 65_536, max: 16_777_216)
        let maxSessionCount = max(0, configuration.engineMaxFlows)
        let logLevel = configuration.engineLogLevel.lowercased()
        let mappedLevel: String
        if logLevel.contains("debug") {
            mappedLevel = "debug"
        } else if logLevel.contains("info") {
            mappedLevel = "info"
        } else if logLevel.contains("error") {
            mappedLevel = "error"
        } else {
            mappedLevel = "warn"
        }

        var lines: [String] = []
        lines.append("tunnel:")
        lines.append("  name: tun0")
        lines.append("  mtu: \(configuration.mtu)")
        lines.append("  multi-queue: false")
        lines.append("  ipv4: \(configuration.ipv4Address)")
        if configuration.ipv6Enabled {
            lines.append("  ipv6: '\(configuration.ipv6Address)'")
        }
        lines.append("")
        lines.append("socks5:")
        lines.append("  port: \(socksPort)")
        lines.append("  address: 127.0.0.1")
        lines.append("  udp: 'udp'")
        lines.append("")
        lines.append("misc:")
        lines.append("  tcp-buffer-size: \(tcpBufferSize)")
        lines.append("  udp-recv-buffer-size: \(udpRecvBufferSize)")
        lines.append("  max-session-count: \(maxSessionCount)")
        lines.append("  log-file: stderr")
        lines.append("  log-level: \(mappedLevel)")
        lines.append("  connect-timeout: 10000")
        lines.append("  tcp-read-write-timeout: 300000")
        lines.append("  udp-read-write-timeout: 60000")
        return lines.joined(separator: "\n")
    }

    private static func clamp(_ value: Int, min minValue: Int, max maxValue: Int) -> Int {
        if value < minValue {
            return minValue
        }
        if value > maxValue {
            return maxValue
        }
        return value
    }
}

#if DEBUG
extension Tun2SocksEngine {
    var _test_isRunning: Bool {
        isRunning()
    }

    var _test_configString: String? {
        guard let configData else { return nil }
        return String(data: configData, encoding: .utf8)
    }
}
#endif
