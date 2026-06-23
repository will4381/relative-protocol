// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
import HarnessTunSupport
import Observability
import TunnelRuntime

#if os(Linux)
import Glibc
#else
import Darwin
#endif

public enum TunHarnessError: Error, CustomStringConvertible {
    case unavailable(errno: Int32)
    case invalidDuration
    case invalidSocksPort(UInt16)

    public var description: String {
        switch self {
        case .unavailable(let errno):
            return "TUN harness unavailable or failed to open device: errno=\(errno)"
        case .invalidDuration:
            return "TUN harness duration must be positive"
        case .invalidSocksPort(let port):
            return "Invalid SOCKS port \(port)"
        }
    }
}

public struct TunRuntimeOptions: Sendable, Equatable {
    public let requestedName: String?
    public let includePacketInfo: Bool
    public let mtu: Int
    public let ipv4Address: String
    public let ipv6Address: String?
    public let socksHost: String
    public let socksPort: UInt16
    public let durationSeconds: TimeInterval
    public let engineLogLevel: String

    public init(
        requestedName: String? = nil,
        includePacketInfo: Bool = false,
        mtu: Int = 1280,
        ipv4Address: String = "10.90.0.2",
        ipv6Address: String? = nil,
        socksHost: String = "127.0.0.1",
        socksPort: UInt16 = 1080,
        durationSeconds: TimeInterval = 10,
        engineLogLevel: String = "warn"
    ) {
        self.requestedName = requestedName
        self.includePacketInfo = includePacketInfo
        self.mtu = mtu
        self.ipv4Address = ipv4Address
        self.ipv6Address = ipv6Address
        self.socksHost = socksHost
        self.socksPort = socksPort
        self.durationSeconds = durationSeconds
        self.engineLogLevel = engineLogLevel
    }
}

public struct TunHarnessRunResult: Sendable, Equatable {
    public let interfaceName: String
    public let runtimeState: RuntimeState
    public let durationSeconds: TimeInterval

    public init(interfaceName: String, runtimeState: RuntimeState, durationSeconds: TimeInterval) {
        self.interfaceName = interfaceName
        self.runtimeState = runtimeState
        self.durationSeconds = durationSeconds
    }
}

public extension HarnessRunner {
    func runTun(options: TunRuntimeOptions, rootPath: URL) async throws -> TunHarnessRunResult {
        _ = rootPath
        guard options.durationSeconds.isFinite,
              options.durationSeconds > 0,
              options.durationSeconds <= 86_400 else {
            throw TunHarnessError.invalidDuration
        }
        let runDurationNanoseconds = UInt64(options.durationSeconds * 1_000_000_000)
        guard options.socksPort > 0 else {
            throw TunHarnessError.invalidSocksPort(options.socksPort)
        }

        let device = try TunPacketDevice.open(requestedName: options.requestedName, includePacketInfo: options.includePacketInfo)
        defer {
            device.close()
        }

        let logger = StructuredLogger(sink: InMemoryLogSink())
        let runtime = TunnelRuntime(
            clock: SystemClock(),
            runIdGenerator: RandomRunIdGenerator(),
            randomSource: SystemRandomSource(),
            logger: logger
        )
        let config = TunDataplaneConfig.make(interfaceName: device.interfaceName, options: options)

        do {
            try await runtime.start(configJSON: config, tunFD: device.fd)
            try await Task.sleep(nanoseconds: runDurationNanoseconds)
            let snapshot = await runtime.currentSnapshot()
            try await runtime.stop()
            return TunHarnessRunResult(
                interfaceName: device.interfaceName,
                runtimeState: snapshot.state,
                durationSeconds: options.durationSeconds
            )
        } catch {
            try? await runtime.stop()
            throw error
        }
    }
}

private enum TunDataplaneConfig {
    static func make(interfaceName: String, options: TunRuntimeOptions) -> String {
        var lines: [String] = []
        lines.append("tunnel:")
        lines.append("  name: \(interfaceName)")
        lines.append("  mtu: \(max(576, options.mtu))")
        lines.append("  multi-queue: false")
        lines.append("  ipv4: \(options.ipv4Address)")
        if let ipv6Address = options.ipv6Address {
            lines.append("  ipv6: '\(ipv6Address)'")
        }
        lines.append("")
        lines.append("socks5:")
        lines.append("  port: \(options.socksPort)")
        lines.append("  address: \(options.socksHost)")
        lines.append("")
        lines.append("misc:")
        lines.append("  log-file: stderr")
        lines.append("  log-level: \(normalizedLogLevel(options.engineLogLevel))")
        lines.append("  task-stack-size: 65536")
        lines.append("  max-session-count: 1024")
        lines.append("  udp-recv-buffer-size: 131072")
        lines.append("  connect-timeout: 10000")
        lines.append("  tcp-read-write-timeout: 300000")
        return lines.joined(separator: "\n")
    }

    private static func normalizedLogLevel(_ value: String) -> String {
        switch value.lowercased() {
        case "debug", "info", "warn", "error":
            return value.lowercased()
        default:
            return "warn"
        }
    }
}

private final class TunPacketDevice: @unchecked Sendable {
    let fd: Int32
    let interfaceName: String
    private var closed = false

    private init(fd: Int32, interfaceName: String) {
        self.fd = fd
        self.interfaceName = interfaceName
    }

    static func open(requestedName: String?, includePacketInfo: Bool) throws -> TunPacketDevice {
        var errnoValue: CInt = 0
        var nameBuffer = [CChar](repeating: 0, count: 64)
        let fd: Int32
        if let requestedName {
            fd = requestedName.withCString { requestedNamePointer in
                rp_harness_open_tun(
                    requestedNamePointer,
                    includePacketInfo ? 1 : 0,
                    &nameBuffer,
                    nameBuffer.count,
                    &errnoValue
                )
            }
        } else {
            fd = rp_harness_open_tun(
                nil,
                includePacketInfo ? 1 : 0,
                &nameBuffer,
                nameBuffer.count,
                &errnoValue
            )
        }

        guard fd >= 0 else {
            throw TunHarnessError.unavailable(errno: Int32(errnoValue))
        }

        let interfaceName = String(cString: nameBuffer)
        return TunPacketDevice(fd: fd, interfaceName: interfaceName)
    }

    func close() {
        guard !closed else {
            return
        }
        closed = true
        _ = rp_harness_close_fd(fd)
    }

    deinit {
        close()
    }
}
