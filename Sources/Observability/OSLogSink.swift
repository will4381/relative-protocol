import Foundation
import os

/// Unified logging sink that emits structured tunnel events to Apple log streams.
public actor OSLogSink: LogSink {
    // Docs: https://developer.apple.com/documentation/os/logger
    private let logger: Logger

    /// Creates an OS log sink bound to a subsystem/category pair.
    /// - Parameters:
    ///   - subsystem: Unified logging subsystem identifier.
    ///   - category: Unified logging category for emitted entries.
    public init(subsystem: String, category: String) {
        self.logger = Logger(subsystem: subsystem, category: category)
    }

    /// Writes one structured event into Apple unified logging.
    /// - Parameter envelope: Structured log envelope to render and emit.
    public func write(_ envelope: LogEnvelope) async {
        logger.log(level: envelope.level.unifiedLogType, "\(envelope.renderedForUnifiedLog, privacy: .public)")
    }
}

extension LogLevel {
    /// Maps structured log levels onto the closest supported unified logging severity.
    var unifiedLogType: OSLogType {
        switch self {
        case .trace, .debug:
            return .debug
        case .info:
            return .info
        case .notice:
            return .default
        case .warning:
            return .default
        case .error:
            return .error
        case .fault:
            return .fault
        }
    }
}

extension LogEnvelope {
    /// Renders the full logging envelope into a single-line unified logging message.
    var renderedForUnifiedLog: String {
        let metadataPairs = metadata
            .sorted(by: { $0.key < $1.key })
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ",")

        var fields: [String] = [
            "timestamp=\(timestamp.ISO8601Format())",
            "level=\(level.rawValue)",
            "phase=\(phase.rawValue)",
            "component=\(component)",
            "event=\(event)"
        ]

        if let runId {
            fields.append("runId=\(runId)")
        }
        if let sessionId {
            fields.append("sessionId=\(sessionId)")
        }
        if let connId {
            fields.append("connId=\(connId)")
        }
        if let flowId {
            fields.append("flowId=\(flowId)")
        }
        if let traceId {
            fields.append("traceId=\(traceId)")
        }
        if let result {
            fields.append("result=\(result)")
        }
        if let errorCode {
            fields.append("errorCode=\(errorCode)")
        }

        fields.append("message=\(message)")
        fields.append("metadata={\(metadataPairs)}")
        return fields.joined(separator: " ")
    }
}
