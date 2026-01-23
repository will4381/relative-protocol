import Foundation
import HevSocks5Tunnel
import RelativeProtocolCore

final class Tun2SocksEngine {
    private let logger = RelativeLog.logger(.tunnel)
    private let queue = DispatchQueue(label: "com.relative.protocol.tun2socks")
    private var configData: Data?
    private var isRunning = false

    func start(configuration: TunnelConfiguration, tunFD: Int32, socksPort: UInt16) {
        guard !isRunning else { return }
        isRunning = true

        let configString = buildConfigString(configuration: configuration, socksPort: socksPort)
        NSLog("Tun2SocksEngine: socks5 address=127.0.0.1 port=\(socksPort)")
        NSLog("Tun2SocksEngine: starting with tunFD=\(tunFD) socksPort=\(socksPort)")
        let data = Data(configString.utf8)
        configData = data

        queue.async { [weak self] in
            guard let self else { return }
            let result = data.withUnsafeBytes { rawBuffer -> Int32 in
                guard let base = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                    return -1
                }
                return hev_socks5_tunnel_main_from_str(base, UInt32(data.count), tunFD)
            }
            self.logger.info("tun2socks exited with code \(result, privacy: .public)")
            NSLog("Tun2SocksEngine: exited with code \(result)")
            self.isRunning = false
        }
    }

    func stop() {
        guard isRunning else { return }
        NSLog("Tun2SocksEngine: stop requested")
        hev_socks5_tunnel_quit()
        isRunning = false
        configData = nil
    }

    private func buildConfigString(configuration: TunnelConfiguration, socksPort: UInt16) -> String {
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
        lines.append("  log-file: stderr")
        lines.append("  log-level: \(mappedLevel)")
        lines.append("  connect-timeout: 10000")
        lines.append("  tcp-read-write-timeout: 300000")
        lines.append("  udp-read-write-timeout: 60000")
        return lines.joined(separator: "\n")
    }
}
