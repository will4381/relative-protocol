import Foundation

/// Async sink protocol implemented by all log outputs.
public protocol LogSink: Sendable {
    /// Writes a structured envelope to the sink destination.
    /// - Parameter envelope: Structured event payload.
    func write(_ envelope: LogEnvelope) async
}

/// Fanout sink that forwards each event to every configured destination.
public actor FanoutLogSink: LogSink {
    private let sinks: [any LogSink]

    /// Creates a fanout sink that forwards events to each provided sink.
    /// - Parameter sinks: Ordered sink list for sequential event forwarding.
    public init(sinks: [any LogSink]) {
        self.sinks = sinks
    }

    /// Forwards an envelope to all configured sinks in order.
    /// - Parameter envelope: Envelope to fan out.
    public func write(_ envelope: LogEnvelope) async {
        for sink in sinks {
            await sink.write(envelope)
        }
    }
}

/// In-memory sink used by tests and replay verification.
public actor InMemoryLogSink: LogSink {
    private var records: [LogEnvelope] = []

    /// Creates an empty in-memory sink.
    public init() {}

    /// Appends one envelope to in-memory storage.
    /// - Parameter envelope: Envelope to store.
    public func write(_ envelope: LogEnvelope) async {
        records.append(envelope)
    }

    /// Returns all stored envelopes in insertion order.
    public func snapshot() -> [LogEnvelope] {
        records
    }
}
