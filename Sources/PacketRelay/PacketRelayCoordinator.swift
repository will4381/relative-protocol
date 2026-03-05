import Foundation
import Network
import Observability

/// Coordinates outbound relay sockets and path monitoring without NetworkExtension coupling.
public actor PacketRelayCoordinator {
    private let factory: any RelayConnectionFactory
    private let logger: StructuredLogger
    // Docs: https://developer.apple.com/documentation/network/nwpathmonitor
    private let pathMonitor: NWPathMonitor
    private let pathQueue = DispatchQueue(label: "relay.path.monitor")

    private var connection: RelayConnection?
    private var runId: String?

    /// Creates a relay coordinator with injectable connection factory and logger.
    /// - Parameters:
    ///   - factory: Factory used to create outbound relay connections.
    ///   - logger: Structured logger used for relay/path lifecycle events.
    public init(factory: any RelayConnectionFactory, logger: StructuredLogger) {
        self.factory = factory
        self.logger = logger
        self.pathMonitor = NWPathMonitor()
    }

    /// Starts path monitoring and establishes a relay connection to `endpoint`.
    /// Existing connection state is replaced by the newly created connection.
    /// - Parameters:
    ///   - endpoint: Remote relay destination and transport metadata.
    ///   - runId: Optional run identifier attached to emitted logs.
    public func start(endpoint: RelayEndpoint, runId: String?) async {
        self.runId = runId
        await logger.log(
            level: .info,
            phase: .relay,
            category: endpoint.useUDP ? .relayUDP : .relayTCP,
            component: "PacketRelayCoordinator",
            event: "start",
            runId: runId,
            message: "Starting packet relay",
            metadata: [
                "host": endpoint.host,
                "port": String(endpoint.port),
                "transport": endpoint.useUDP ? "udp" : "tcp"
            ]
        )

        // Docs: https://developer.apple.com/documentation/network/nwpathmonitor/pathupdatehandler
        // Docs: https://developer.apple.com/documentation/network/nwpath/status
        pathMonitor.pathUpdateHandler = { [logger, runId] path in
            Task {
                await logger.log(
                    level: .debug,
                    phase: .path,
                    category: .samplerPath,
                    component: "PacketRelayCoordinator",
                    event: "path-update",
                    runId: runId,
                    message: "Observed NWPath update",
                    metadata: [
                        "status": String(describing: path.status),
                        "expensive": path.isExpensive ? "true" : "false"
                    ]
                )
            }
        }
        // Docs: https://developer.apple.com/documentation/network/nwpathmonitor/start(queue:)
        pathMonitor.start(queue: pathQueue)

        let connection = factory.makeConnection(endpoint: endpoint)
        connection.stateUpdate = { [logger, runId] state in
            Task {
                await logger.log(
                    level: .info,
                    phase: .relay,
                    category: endpoint.useUDP ? .relayUDP : .relayTCP,
                    component: "PacketRelayCoordinator",
                    event: "state",
                    runId: runId,
                    result: "\(state)",
                    message: "Relay connection state changed"
                )
            }
        }

        connection.pathUpdate = { [logger, runId] metadata in
            Task {
                await logger.log(
                    level: .debug,
                    phase: .path,
                    category: .samplerPath,
                    component: "PacketRelayCoordinator",
                    event: "connection-path",
                    runId: runId,
                    message: "Connection path metadata",
                    metadata: metadata
                )
            }
        }

        connection.start()
        self.connection = connection
    }

    /// Sends payload bytes over the active relay connection, when one exists.
    /// - Parameter data: Payload to forward toward the upstream relay.
    public func send(_ data: Data) {
        connection?.send(data)
    }

    /// Stops relay I/O and cancels path monitoring.
    public func stop() async {
        connection?.cancel()
        connection = nil
        // Docs: https://developer.apple.com/documentation/network/nwpathmonitor/cancel()
        pathMonitor.cancel()
        await logger.log(
            level: .info,
            phase: .relay,
            category: .control,
            component: "PacketRelayCoordinator",
            event: "stop",
            runId: runId,
            message: "Stopped packet relay"
        )
    }
}
