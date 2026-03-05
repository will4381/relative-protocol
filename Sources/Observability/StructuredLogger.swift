import Foundation

/// Facade used by runtime and analytics to emit structured events consistently.
public actor StructuredLogger {
    private let sink: any LogSink
    private let redactor: EndpointMetadataRedactor

    /// Creates a structured logger with one sink and endpoint metadata redaction policy.
    /// - Parameters:
    ///   - sink: Destination sink implementation (OSLog, JSONL, fanout, etc.).
    ///   - redactor: Redaction policy applied to metadata before serialization.
    public init(sink: any LogSink, redactor: EndpointMetadataRedactor = EndpointMetadataRedactor()) {
        self.sink = sink
        self.redactor = redactor
    }

    /// Emits one structured event using the canonical logging envelope.
    /// - Parameters:
    ///   - level: Event severity.
    ///   - phase: Logical runtime phase for the event.
    ///   - category: Stable category used for indexing and dashboards.
    ///   - component: Component/type emitting the event.
    ///   - event: Event name within the component.
    ///   - runId: Optional run identifier.
    ///   - sessionId: Optional session identifier.
    ///   - connId: Optional connection identifier.
    ///   - flowId: Optional flow identifier.
    ///   - traceId: Optional trace identifier.
    ///   - result: Optional outcome classification (for example, `ok` or `partial`).
    ///   - errorCode: Optional machine-readable error code.
    ///   - message: Human-readable event message.
    ///   - metadata: Additional string metadata values.
    public func log(
        level: LogLevel,
        phase: LogPhase,
        category: LogCategory,
        component: String,
        event: String,
        runId: String? = nil,
        sessionId: String? = nil,
        connId: String? = nil,
        flowId: String? = nil,
        traceId: String? = nil,
        result: String? = nil,
        errorCode: String? = nil,
        message: String,
        metadata: [String: String] = [:]
    ) async {
        let mergedMetadata = redactor.redact(metadata.merging(["category": category.rawValue], uniquingKeysWith: { _, newValue in newValue }))
        let envelope = LogEnvelope(
            level: level,
            phase: phase,
            component: component,
            event: event,
            runId: runId,
            sessionId: sessionId,
            connId: connId,
            flowId: flowId,
            traceId: traceId,
            result: result,
            errorCode: errorCode,
            message: message,
            metadata: mergedMetadata
        )
        await sink.write(envelope)
    }
}
