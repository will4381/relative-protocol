import Foundation
import Observability

private enum HarnessUsageError: Error, CustomStringConvertible {
    case missingArgument(String)
    case invalidArgument(String)

    var description: String {
        switch self {
        case .missingArgument(let argument):
            return "Missing required argument: \(argument)"
        case .invalidArgument(let argument):
            return "Invalid argument: \(argument)"
        }
    }
}

private enum HarnessCommand {
    case synthetic(URL)
    case pcap(URL, HarnessScenario, PcapReplayOptions)
    case tun(TunRuntimeOptions)
}

private let usageText = """
Usage:
  HarnessLocal <scenario.json>
  HarnessLocal --pcap <capture.pcap> [--max-packets N] [--direction outbound|inbound] [--scenario scenario.json]
  HarnessLocal --tun [--name rp0] [--duration seconds] [--mtu bytes] [--ipv4 address] [--ipv6 address] [--socks-host host] [--socks-port port] [--include-packet-info] [--log-level warn]
"""

/// CLI entrypoint for deterministic local harness runs.
private func runHarness() async -> Int32 {
    do {
        let command = try parseCommand(Array(CommandLine.arguments.dropFirst()))

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("HarnessLocal-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sink = InMemoryLogSink()
        let logger = StructuredLogger(sink: sink)
        let runner = HarnessRunner(logger: logger)

        switch command {
        case .synthetic(let scenarioURL):
            let scenario = try HarnessScenario.load(from: scenarioURL)
            let result = try await runner.run(scenario: scenario, adapter: SyntheticFlowAdapter(), rootPath: root)
            print([
                "scenario": result.scenarioID,
                "state": result.runtimeState.rawValue,
                "packets": String(result.packetCount)
            ])
        case .pcap(let pcapURL, let scenario, let options):
            let result = try await runner.run(
                scenario: scenario,
                adapter: PcapReplayAdapter(fileURL: pcapURL, options: options),
                rootPath: root
            )
            print([
                "scenario": result.scenarioID,
                "state": result.runtimeState.rawValue,
                "packets": String(result.packetCount),
                "source": "pcap"
            ])
        case .tun(let options):
            let result = try await runner.runTun(options: options, rootPath: root)
            print([
                "interface": result.interfaceName,
                "state": result.runtimeState.rawValue,
                "duration": String(result.durationSeconds),
                "source": "tun"
            ])
        }

        return 0
    } catch let error as HarnessUsageError {
        writeStandardError("HarnessLocal usage error: \(error)\n\(usageText)\n")
        return 1
    } catch {
        writeStandardError("HarnessLocal error: \(error)\n")
        return 2
    }
}

private func writeStandardError(_ message: String) {
    guard let data = message.data(using: .utf8) else {
        return
    }
    FileHandle.standardError.write(data)
}

private func parseCommand(_ args: [String]) throws -> HarnessCommand {
    guard let first = args.first else {
        throw HarnessUsageError.missingArgument("command")
    }

    switch first {
    case "--pcap":
        guard args.count >= 2 else {
            throw HarnessUsageError.missingArgument("capture.pcap")
        }
        let pcapURL = URL(fileURLWithPath: args[1])
        let maximumPackets = try optionalIntValue(args, flag: "--max-packets")
        let direction = try optionalStringValue(args, flag: "--direction") ?? "outbound"
        let scenarioURL = try optionalStringValue(args, flag: "--scenario").map(URL.init(fileURLWithPath:))
        let scenario = try scenarioURL.map(HarnessScenario.load(from:)) ?? defaultScenario(id: "pcap-replay")
        return .pcap(
            pcapURL,
            scenario,
            PcapReplayOptions(maximumPackets: maximumPackets, direction: direction)
        )
    case "--tun":
        let requestedName = try optionalStringValue(args, flag: "--name")
        let duration = try optionalDoubleValue(args, flag: "--duration") ?? 10
        let mtu = try optionalIntValue(args, flag: "--mtu") ?? 1280
        let ipv4 = try optionalStringValue(args, flag: "--ipv4") ?? "10.90.0.2"
        let ipv6 = try optionalStringValue(args, flag: "--ipv6")
        let socksHost = try optionalStringValue(args, flag: "--socks-host") ?? "127.0.0.1"
        let socksPort = try parseUInt16(args, flag: "--socks-port", defaultValue: 1080)
        let logLevel = try optionalStringValue(args, flag: "--log-level") ?? "warn"
        return .tun(
            TunRuntimeOptions(
                requestedName: requestedName,
                includePacketInfo: args.contains("--include-packet-info"),
                mtu: mtu,
                ipv4Address: ipv4,
                ipv6Address: ipv6,
                socksHost: socksHost,
                socksPort: socksPort,
                durationSeconds: duration,
                engineLogLevel: logLevel
            )
        )
    default:
        guard !first.hasPrefix("--") else {
            throw HarnessUsageError.invalidArgument(first)
        }
        return .synthetic(URL(fileURLWithPath: first))
    }
}

private func optionalStringValue(_ args: [String], flag: String) throws -> String? {
    guard let index = args.firstIndex(of: flag) else {
        return nil
    }
    let valueIndex = args.index(after: index)
    guard args.indices.contains(valueIndex) else {
        throw HarnessUsageError.missingArgument(flag)
    }
    return args[valueIndex]
}

private func optionalIntValue(_ args: [String], flag: String) throws -> Int? {
    guard let value = try optionalStringValue(args, flag: flag) else {
        return nil
    }
    guard let parsed = Int(value) else {
        throw HarnessUsageError.invalidArgument("\(flag) \(value)")
    }
    return parsed
}

private func optionalDoubleValue(_ args: [String], flag: String) throws -> Double? {
    guard let value = try optionalStringValue(args, flag: flag) else {
        return nil
    }
    guard let parsed = Double(value) else {
        throw HarnessUsageError.invalidArgument("\(flag) \(value)")
    }
    return parsed
}

private func parseUInt16(_ args: [String], flag: String, defaultValue: UInt16) throws -> UInt16 {
    guard let raw = try optionalIntValue(args, flag: flag) else {
        return defaultValue
    }
    guard let parsed = UInt16(exactly: raw) else {
        throw HarnessUsageError.invalidArgument("\(flag) \(raw)")
    }
    return parsed
}

private func defaultScenario(id: String) -> HarnessScenario {
    HarnessScenario(
        id: id,
        durationSeconds: 10,
        seed: 1,
        inputProfile: "pcap",
        timing: HarnessTiming(startTimeISO8601: "1970-01-01T00:00:00Z", stepIntervalMs: 1),
        steps: []
    )
}

exit(await runHarness())
