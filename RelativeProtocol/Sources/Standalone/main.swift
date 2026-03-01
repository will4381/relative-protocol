import Foundation
import Network
import RelativeProtocolTunnel

private struct CLIOptions {
    var socksPort: UInt16 = 1080
    var controlPort: UInt16 = 19090
    var mtu: Int = 1400
    var engineLogLevel: String = "warn"
    var statusIntervalMs: Int = 2000

    static func parse(arguments: [String]) throws -> CLIOptions {
        var options = CLIOptions()
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--help", "-h":
                throw StandaloneExit.help
            case "--socks-port":
                index += 1
                options.socksPort = try parseUInt16(arguments, at: index, name: "--socks-port")
            case "--control-port":
                index += 1
                options.controlPort = try parseUInt16(arguments, at: index, name: "--control-port")
            case "--mtu":
                index += 1
                options.mtu = try parseInt(arguments, at: index, name: "--mtu")
            case "--engine-log-level":
                index += 1
                options.engineLogLevel = try parseString(arguments, at: index, name: "--engine-log-level")
            case "--status-interval-ms":
                index += 1
                options.statusIntervalMs = try parseInt(arguments, at: index, name: "--status-interval-ms")
            default:
                throw StandaloneError.invalidArgument(argument)
            }
            index += 1
        }

        guard options.statusIntervalMs >= 250 else {
            throw StandaloneError.invalidValue("--status-interval-ms", "\(options.statusIntervalMs)")
        }
        guard options.mtu >= 576 else {
            throw StandaloneError.invalidValue("--mtu", "\(options.mtu)")
        }

        return options
    }
}

private enum StandaloneExit: Error {
    case help
}

private enum StandaloneError: Error, CustomStringConvertible {
    case invalidArgument(String)
    case missingValue(String)
    case invalidValue(String, String)
    case listenerStartFailure(String)
    case controlPortInvalid(UInt16)

    var description: String {
        switch self {
        case .invalidArgument(let arg):
            return "Unknown argument: \(arg)"
        case .missingValue(let name):
            return "Missing value for \(name)"
        case .invalidValue(let name, let value):
            return "Invalid value for \(name): \(value)"
        case .listenerStartFailure(let message):
            return "Failed to start control listener: \(message)"
        case .controlPortInvalid(let port):
            return "Invalid control port: \(port)"
        }
    }
}

private func parseUInt16(_ arguments: [String], at index: Int, name: String) throws -> UInt16 {
    guard index < arguments.count else { throw StandaloneError.missingValue(name) }
    guard let value = UInt16(arguments[index]) else {
        throw StandaloneError.invalidValue(name, arguments[index])
    }
    return value
}

private func parseInt(_ arguments: [String], at index: Int, name: String) throws -> Int {
    guard index < arguments.count else { throw StandaloneError.missingValue(name) }
    guard let value = Int(arguments[index]) else {
        throw StandaloneError.invalidValue(name, arguments[index])
    }
    return value
}

private func parseString(_ arguments: [String], at index: Int, name: String) throws -> String {
    guard index < arguments.count else { throw StandaloneError.missingValue(name) }
    return arguments[index]
}

private struct ControlRequest: Decodable {
    let command: String
    let id: String?
    let socksPort: UInt16?
    let mtu: Int?
    let engineLogLevel: String?
}

private struct ControlEnvelope: Encodable {
    let ok: Bool
    let command: String
    let id: String?
    let timestamp: TimeInterval
    let details: [String: String]
    let status: StandaloneRuntimeStatus?
    let error: String?
}

private final class StandaloneController {
    private let runtime: StandaloneTunnelRuntime
    private let queue = DispatchQueue(label: "com.relative.protocol.standalone.control")
    private let encoder = JSONEncoder()
    private let stopSemaphore: DispatchSemaphore

    init(runtime: StandaloneTunnelRuntime, stopSemaphore: DispatchSemaphore) {
        self.runtime = runtime
        self.stopSemaphore = stopSemaphore
    }

    func handle(_ request: ControlRequest, reply: @escaping (Data) -> Void) {
        let command = normalizeCommand(request.command)
        switch command {
        case "status":
            let status = runtime.status()
            let response = makeResponse(
                ok: true,
                command: command,
                id: request.id,
                status: status,
                details: ["message": "ok"],
                error: nil
            )
            reply(response)
        case "flush-metrics":
            runtime.flushMetrics()
            let status = runtime.status()
            let response = makeResponse(
                ok: true,
                command: command,
                id: request.id,
                status: status,
                details: ["message": "metrics flushed"],
                error: nil
            )
            reply(response)
        case "restart-relay":
            runtime.restart { [weak self] error in
                guard let self else { return }
                let status = self.runtime.status()
                let response = self.makeResponse(
                    ok: error == nil,
                    command: command,
                    id: request.id,
                    status: status,
                    details: ["message": error == nil ? "relay restarted" : "relay restart failed"],
                    error: error?.localizedDescription
                )
                reply(response)
            }
        case "reload-config":
            let options = StandaloneRuntimeOptions(
                socksPort: request.socksPort ?? runtime.status().socksPort,
                mtu: request.mtu ?? runtime.status().mtu,
                engineLogLevel: request.engineLogLevel ?? runtime.status().engineLogLevel
            )
            runtime.reload(options: options) { [weak self] error in
                guard let self else { return }
                let status = self.runtime.status()
                let response = self.makeResponse(
                    ok: error == nil,
                    command: command,
                    id: request.id,
                    status: status,
                    details: ["message": error == nil ? "configuration reloaded" : "reload failed"],
                    error: error?.localizedDescription
                )
                reply(response)
            }
        case "stop":
            let status = runtime.status()
            let response = makeResponse(
                ok: true,
                command: command,
                id: request.id,
                status: status,
                details: ["message": "stopping"],
                error: nil
            )
            reply(response)
            queue.asyncAfter(deadline: .now() + 0.1) { [weak self] in
                self?.runtime.stop()
                self?.stopSemaphore.signal()
            }
        default:
            let response = makeResponse(
                ok: false,
                command: request.command,
                id: request.id,
                status: nil,
                details: [:],
                error: "unsupported-command"
            )
            reply(response)
        }
    }

    private func normalizeCommand(_ command: String) -> String {
        let value = command.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch value {
        case "restartrelay", "restart-relay":
            return "restart-relay"
        case "reloadconfiguration", "reload-config":
            return "reload-config"
        case "flushmetrics", "flush-metrics":
            return "flush-metrics"
        default:
            return value
        }
    }

    private func makeResponse(
        ok: Bool,
        command: String,
        id: String?,
        status: StandaloneRuntimeStatus?,
        details: [String: String],
        error: String?
    ) -> Data {
        let envelope = ControlEnvelope(
            ok: ok,
            command: command,
            id: id,
            timestamp: Date().timeIntervalSince1970,
            details: details,
            status: status,
            error: error
        )
        if let data = try? encoder.encode(envelope) {
            var line = data
            line.append(0x0A)
            return line
        }
        return Data("{\"ok\":false,\"error\":\"encoding-failed\"}\n".utf8)
    }
}

private final class ControlServer {
    private let controller: StandaloneController
    private let listener: NWListener
    private let queue = DispatchQueue(label: "com.relative.protocol.standalone.listener")
    private let parserQueue = DispatchQueue(label: "com.relative.protocol.standalone.listener.parser")

    init(port: UInt16, controller: StandaloneController) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw StandaloneError.controlPortInvalid(port)
        }
        self.controller = controller
        self.listener = try NWListener(using: .tcp, on: nwPort)
    }

    func start() {
        listener.newConnectionHandler = { [weak self] connection in
            self?.handleConnection(connection)
        }
        listener.start(queue: queue)
    }

    func stop() {
        listener.cancel()
    }

    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: parserQueue)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, _, error in
            guard let self else { return }
            guard error == nil else {
                connection.cancel()
                return
            }
            guard let data, !data.isEmpty else {
                connection.cancel()
                return
            }
            let payload: Data
            if let newlineIndex = data.firstIndex(of: 0x0A) {
                payload = data[..<newlineIndex]
            } else {
                payload = data
            }
            guard let request = try? JSONDecoder().decode(ControlRequest.self, from: payload) else {
                connection.send(content: Data("{\"ok\":false,\"error\":\"invalid-json\"}\n".utf8), completion: .contentProcessed { _ in
                    connection.cancel()
                })
                return
            }
            self.controller.handle(request) { response in
                connection.send(content: response, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
    }
}

private func printUsage() {
    print("""
Usage: swift run Standalone [options]

Options:
  --socks-port <port>          SOCKS5 listener port (default: 1080)
  --control-port <port>        JSON control TCP port (default: 19090)
  --mtu <bytes>                Tunnel MTU (default: 1400)
  --engine-log-level <level>   tun2socks log level (default: warn)
  --status-interval-ms <ms>    Health output interval in ms (default: 2000)
""")
}

private func emitHarnessStatus(_ status: StandaloneRuntimeStatus) {
    let payload = [
        "running": status.running ? "true" : "false",
        "restarting": status.restarting ? "true" : "false",
        "socksPort": String(status.socksPort),
        "restartCount": String(status.restartCount),
        "backpressured": status.backpressured ? "true" : "false",
        "inboundPackets": String(status.inboundPacketCount),
        "outboundPackets": String(status.outboundPacketCount),
        "inboundBytes": String(status.inboundBytes),
        "outboundBytes": String(status.outboundBytes),
        "uptimeSeconds": String(status.uptimeSeconds),
        "lastError": status.lastError ?? "none"
    ]
    let line = payload.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
    print("[HARNESS] \(line)")
}

private func installSignalHandlers(stop: @escaping () -> Void) -> [DispatchSourceSignal] {
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    sigint.setEventHandler(handler: stop)
    sigint.resume()

    let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    sigterm.setEventHandler(handler: stop)
    sigterm.resume()

    return [sigint, sigterm]
}

do {
    let options = try CLIOptions.parse(arguments: Array(CommandLine.arguments.dropFirst()))
    let runtimeOptions = StandaloneRuntimeOptions(
        socksPort: options.socksPort,
        mtu: options.mtu,
        engineLogLevel: options.engineLogLevel
    )
    let runtime = StandaloneTunnelRuntime(options: runtimeOptions)
    let stopSemaphore = DispatchSemaphore(value: 0)
    let controller = StandaloneController(runtime: runtime, stopSemaphore: stopSemaphore)
    let controlServer = try ControlServer(port: options.controlPort, controller: controller)

    let startGroup = DispatchGroup()
    var startError: Error?
    startGroup.enter()
    runtime.start { error in
        startError = error
        startGroup.leave()
    }
    startGroup.wait()
    if let startError {
        throw StandaloneError.listenerStartFailure(startError.localizedDescription)
    }

    controlServer.start()

    print(
        "[HARNESS] started socksPort=\(options.socksPort) controlPort=\(options.controlPort) mtu=\(options.mtu) engineLogLevel=\(options.engineLogLevel)"
    )

    let statusTimer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
    let interval = DispatchTimeInterval.milliseconds(options.statusIntervalMs)
    statusTimer.schedule(deadline: .now() + interval, repeating: interval)
    statusTimer.setEventHandler {
        emitHarnessStatus(runtime.status())
    }
    statusTimer.resume()

    let signalSources = installSignalHandlers {
        runtime.stop()
        stopSemaphore.signal()
    }
    _ = signalSources

    stopSemaphore.wait()

    statusTimer.cancel()
    controlServer.stop()
    runtime.stop()
    print("[HARNESS] stopped")
} catch StandaloneExit.help {
    printUsage()
} catch let error as StandaloneError {
    fputs("Failed to start SOCKS5 standalone: \(error.description)\n", stderr)
    exit(1)
} catch {
    fputs("Failed to start SOCKS5 standalone: \(error.localizedDescription)\n", stderr)
    exit(1)
}
