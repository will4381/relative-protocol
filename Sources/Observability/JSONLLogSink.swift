// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation

/// Rotation and retention policy for JSONL log files.
public struct JSONLRotationPolicy: Sendable, Equatable {
    public let maxBytesPerFile: Int
    public let maxFiles: Int
    public let maxTotalBytes: Int
    public let maxQueueDepth: Int

    /// - Parameters:
    ///   - maxBytesPerFile: Rotation threshold for active file size.
    ///   - maxFiles: Maximum number of retained active/rotated files for one stream.
    ///   - maxTotalBytes: Maximum retained bytes across active/rotated files for one stream.
    ///   - maxQueueDepth: In-memory pending envelope limit before queue drops.
    public init(
        maxBytesPerFile: Int,
        maxFiles: Int,
        maxTotalBytes: Int,
        maxQueueDepth: Int = 2048
    ) {
        self.maxBytesPerFile = max(1, maxBytesPerFile)
        self.maxFiles = max(1, maxFiles)
        self.maxTotalBytes = max(self.maxBytesPerFile, maxTotalBytes)
        self.maxQueueDepth = max(1, maxQueueDepth)
    }
}

/// Exposes drop counters so tests and diagnostics can verify sink pressure behavior.
public struct JSONLDropCounters: Sendable, Equatable {
    public var droppedQueueFull: Int
    public var droppedIOError: Int
    public var droppedSizePolicy: Int

    /// - Parameters:
    ///   - droppedQueueFull: Count of events dropped due to queue pressure.
    ///   - droppedIOError: Count of events dropped due to I/O errors.
    ///   - droppedSizePolicy: Count of events dropped due to size policy violations.
    public init(droppedQueueFull: Int = 0, droppedIOError: Int = 0, droppedSizePolicy: Int = 0) {
        self.droppedQueueFull = droppedQueueFull
        self.droppedIOError = droppedIOError
        self.droppedSizePolicy = droppedSizePolicy
    }

    /// Total number of drops across all drop categories.
    public var total: Int {
        Self.saturatingAdd(Self.saturatingAdd(droppedQueueFull, droppedIOError), droppedSizePolicy)
    }

    mutating func incrementQueueFull() {
        droppedQueueFull = Self.saturatingAdd(droppedQueueFull, 1)
    }

    mutating func incrementIOError() {
        droppedIOError = Self.saturatingAdd(droppedIOError, 1)
    }

    mutating func incrementSizePolicy() {
        droppedSizePolicy = Self.saturatingAdd(droppedSizePolicy, 1)
    }

    private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int.max : value
    }
}

/// JSONL sink with single-writer semantics and deterministic rotation behavior.
public actor JSONLLogSink: LogSink {
    private static var protectionAttributes: [FileAttributeKey: Any] {
#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
#else
        [:]
#endif
    }

    private static func excludeFromBackupIfNeeded(_ url: URL) throws {
#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        // Docs: https://developer.apple.com/documentation/foundation/urlresourcevalues
        // Docs: https://developer.apple.com/documentation/foundation/nsurl/setresourcevalues(_:)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(values)
#endif
    }

    private let encoder: JSONEncoder
    private let policy: JSONLRotationPolicy
    private let rootProvider: any LogRootPathProvider
    private let eventQueueLabel: String
    private let filePrefix: String

    private var initialized = false
    private var rootURL: URL = URL(fileURLWithPath: "/")
    private var activeURL: URL = URL(fileURLWithPath: "/events.current.jsonl")
    private var handle: FileHandle?
    private var activeSize = 0
    private var rotationSequence = 0
    private var pending: ArraySlice<Data> = []
    private var drainTask: Task<Void, Never>?
    private var drops = JSONLDropCounters()

    /// Creates a JSONL sink with deterministic rotation/retention policies.
    /// - Parameters:
    ///   - rootProvider: Root path provider used to resolve log directory.
    ///   - policy: Rotation, retention, and queue limits.
    ///   - eventQueueLabel: Component label used by sink-generated events.
    ///   - filePrefix: File prefix for the active and rotated stream. Use one prefix per process.
    public init(
        rootProvider: any LogRootPathProvider,
        policy: JSONLRotationPolicy,
        eventQueueLabel: String = "jsonl",
        filePrefix: String = "events"
    ) {
        self.rootProvider = rootProvider
        self.policy = policy
        self.eventQueueLabel = eventQueueLabel
        self.filePrefix = Self.normalizedFilePrefix(filePrefix)
        self.encoder = JSONEncoder()
        self.encoder.dateEncodingStrategy = .iso8601
        self.encoder.outputFormatting = [.sortedKeys]
    }

    /// Enqueues one envelope for JSONL persistence.
    /// - Parameter envelope: Structured event envelope.
    public func write(_ envelope: LogEnvelope) async {
        do {
            try ensureInitialized()
            let payload = try serialize(envelope)
            guard payload.count <= policy.maxBytesPerFile else {
                drops.incrementSizePolicy()
                await emitDropSummaryIfNeeded(trigger: "size-policy")
                return
            }
            guard pending.count < policy.maxQueueDepth else {
                drops.incrementQueueFull()
                await emitDropSummaryIfNeeded(trigger: "queue-full")
                return
            }
            pending.append(payload)
            startDrainTaskIfNeeded()
        } catch {
            drops.incrementIOError()
            await emitDropSummaryIfNeeded(trigger: "io-error")
        }
    }

    /// Returns cumulative drop counters not yet emitted/reconciled.
    public func dropCounters() -> JSONLDropCounters {
        drops
    }

    /// Lists active and rotated JSONL files currently retained by the sink.
    /// - Returns: Sorted list of `events*` file URLs.
    /// - Throws: Root resolution or directory listing errors.
    public func listLogFiles() throws -> [URL] {
        try ensureInitialized()
        let files = try FileManager.default.contentsOfDirectory(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        return files
            .filter { isOwnedLogFileName($0.lastPathComponent) }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func serialize(_ envelope: LogEnvelope) throws -> Data {
        var serialized = try encoder.encode(envelope)
        serialized.append(0x0A)
        return serialized
    }

    private func drainQueue() async {
        while true {
            guard let next = pending.popFirst() else {
                pending = []
                drainTask = nil
                await emitDropSummaryIfNeeded(trigger: "drain")
                return
            }
            do {
                try rotateIfNeeded(for: next.count)
                try append(next)
            } catch {
                drops.incrementIOError()
            }
        }
    }

    private func startDrainTaskIfNeeded() {
        guard drainTask == nil else {
            return
        }
        drainTask = Task { [weak self] in
            await self?.drainQueue()
        }
    }

    private func ensureInitialized() throws {
        guard !initialized else {
            return
        }

        rootURL = try rootProvider.resolveRootPath()
        activeURL = rootURL.appendingPathComponent(activeFileName, isDirectory: false)
        try FileManager.default.createDirectory(
            atPath: rootURL.path,
            withIntermediateDirectories: true,
            attributes: Self.protectionAttributes
        )
        try Self.excludeFromBackupIfNeeded(rootURL)
        if !FileManager.default.fileExists(atPath: activeURL.path) {
            let created = FileManager.default.createFile(
                atPath: activeURL.path,
                contents: nil,
                attributes: Self.protectionAttributes
            )
            guard created else {
                throw CocoaError(.fileWriteUnknown)
            }
        } else if !Self.protectionAttributes.isEmpty {
            try FileManager.default.setAttributes(Self.protectionAttributes, ofItemAtPath: activeURL.path)
        }
        try Self.excludeFromBackupIfNeeded(activeURL)
        handle = try FileHandle(forWritingTo: activeURL)
        try handle?.seekToEnd()
        let attrs = try FileManager.default.attributesOfItem(atPath: activeURL.path)
        activeSize = attrs[.size] as? Int ?? 0
        initialized = true
    }

    private func rotateIfNeeded(for incomingBytes: Int) throws {
        guard activeSize + incomingBytes > policy.maxBytesPerFile else {
            return
        }
        guard let handle else {
            throw CocoaError(.fileNoSuchFile)
        }

        try handle.synchronize()
        try handle.close()

        let timestampMillis = Self.timestampMilliseconds(Date())
        let rotatedName = "\(filePrefix).\(timestampMillis).\(rotationSequence).jsonl"
        rotationSequence &+= 1
        let rotatedURL = rootURL.appendingPathComponent(rotatedName, isDirectory: false)
        try FileManager.default.moveItem(at: activeURL, to: rotatedURL)
        if !Self.protectionAttributes.isEmpty {
            try FileManager.default.setAttributes(Self.protectionAttributes, ofItemAtPath: rotatedURL.path)
        }
        try Self.excludeFromBackupIfNeeded(rotatedURL)
        let created = FileManager.default.createFile(
            atPath: activeURL.path,
            contents: nil,
            attributes: Self.protectionAttributes
        )
        guard created else {
            throw CocoaError(.fileWriteUnknown)
        }
        try Self.excludeFromBackupIfNeeded(activeURL)
        self.handle = try FileHandle(forWritingTo: activeURL)
        activeSize = 0

        try enforceRetention()

        let rotationEvent = LogEnvelope(
            level: .notice,
            phase: .storage,
            component: eventQueueLabel,
            event: "rotation",
            result: "success",
            message: "Rotated active log file",
            metadata: [
                "rotated_file": rotatedName,
                "max_bytes_per_file": String(policy.maxBytesPerFile)
            ]
        )
        let payload = try serialize(rotationEvent)
        try append(payload)
    }

    private static func timestampMilliseconds(_ date: Date) -> Int {
        let milliseconds = (date.timeIntervalSince1970 * 1_000).rounded()
        guard milliseconds.isFinite else {
            return 0
        }
        if milliseconds >= Double(Int.max) {
            return Int.max
        }
        if milliseconds <= Double(Int.min) {
            return Int.min
        }
        return Int(milliseconds)
    }

    private func enforceRetention() throws {
        var files = try fileMetadata()

        if files.count > policy.maxFiles {
            for entry in files.prefix(files.count - policy.maxFiles) {
                try FileManager.default.removeItem(at: entry.url)
            }
            files.removeFirst(files.count - policy.maxFiles)
        }

        var totalBytes = files.reduce(0) { $0 + $1.size }
        var index = 0
        while totalBytes > policy.maxTotalBytes && index < files.count {
            let candidate = files[index]
            index += 1
            if candidate.url == activeURL {
                continue
            }
            try FileManager.default.removeItem(at: candidate.url)
            totalBytes -= candidate.size
        }
    }

    private func fileMetadata() throws -> [(url: URL, size: Int)] {
        let files = try FileManager.default.contentsOfDirectory(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey, .creationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        )
        return try files
            .filter { isOwnedLogFileName($0.lastPathComponent) }
            .map { url in
                let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
                let created = attrs[.creationDate] as? Date ?? .distantPast
                let size = attrs[.size] as? Int ?? 0
                return (url: url, created: created, size: size)
            }
            .sorted { lhs, rhs in
                if lhs.created == rhs.created {
                    return lhs.url.lastPathComponent < rhs.url.lastPathComponent
                }
                return lhs.created < rhs.created
            }
            .map { (url: $0.url, size: $0.size) }
    }

    private func append(_ data: Data) throws {
        guard let handle else {
            throw CocoaError(.fileNoSuchFile)
        }
        try handle.write(contentsOf: data)
        activeSize = Self.saturatingAdd(activeSize, data.count)
    }

    private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int.max : value
    }

    private var activeFileName: String {
        "\(filePrefix).current.jsonl"
    }

    private func isOwnedLogFileName(_ name: String) -> Bool {
        if name == activeFileName {
            return true
        }

        let rotatedPrefix = "\(filePrefix)."
        guard name.hasPrefix(rotatedPrefix), name.hasSuffix(".jsonl") else {
            return false
        }

        let suffix = name.dropFirst(rotatedPrefix.count)
        return suffix.first?.isNumber == true
    }

    private static func normalizedFilePrefix(_ prefix: String) -> String {
        let trimmed = prefix.trimmingCharacters(in: .whitespacesAndNewlines)
        var normalized = ""
        normalized.reserveCapacity(trimmed.count)

        for scalar in trimmed.unicodeScalars {
            switch scalar.value {
            case 48...57, 65...90, 97...122, 45, 46, 95:
                normalized.unicodeScalars.append(scalar)
            default:
                normalized.append("_")
            }
        }

        normalized = normalized.trimmingCharacters(in: CharacterSet(charactersIn: "._-"))
        return normalized.isEmpty ? "events" : normalized
    }

    private func emitDropSummaryIfNeeded(trigger: String) async {
        guard drops.total > 0 else {
            return
        }
        let snapshot = drops
        let summary = LogEnvelope(
            level: .warning,
            phase: .storage,
            component: eventQueueLabel,
            event: "drop-summary",
            result: "partial",
            errorCode: trigger,
            message: "Log drops recorded",
            metadata: [
                "dropped_queue_full": String(snapshot.droppedQueueFull),
                "dropped_io_error": String(snapshot.droppedIOError),
                "dropped_size_policy": String(snapshot.droppedSizePolicy)
            ]
        )

        do {
            try ensureInitialized()
            let payload = try serialize(summary)
            try rotateIfNeeded(for: payload.count)
            try append(payload)
            drops = JSONLDropCounters()
        } catch {
            // Keep counters for subsequent retries.
        }
    }
}
