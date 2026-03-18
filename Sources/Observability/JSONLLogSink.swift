import Foundation

/// Rotation and retention policy for JSONL log files.
public struct JSONLRotationPolicy: Sendable, Equatable {
    public let maxBytesPerFile: Int
    public let maxFiles: Int
    public let maxTotalBytes: Int
    public let maxQueueDepth: Int

    /// - Parameters:
    ///   - maxBytesPerFile: Rotation threshold for active file size.
    ///   - maxFiles: Maximum number of retained `events*` files.
    ///   - maxTotalBytes: Maximum retained bytes across all `events*` files.
    ///   - maxQueueDepth: In-memory pending envelope limit before queue drops.
    public init(
        maxBytesPerFile: Int,
        maxFiles: Int,
        maxTotalBytes: Int,
        maxQueueDepth: Int = 2048
    ) {
        self.maxBytesPerFile = maxBytesPerFile
        self.maxFiles = maxFiles
        self.maxTotalBytes = maxTotalBytes
        self.maxQueueDepth = maxQueueDepth
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
        droppedQueueFull + droppedIOError + droppedSizePolicy
    }
}

/// JSONL sink with single-writer semantics and deterministic rotation behavior.
public actor JSONLLogSink: LogSink {
    private static var protectionAttributes: [FileAttributeKey: Any] {
#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        [.protectionKey: FileProtectionType.complete]
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

    private var initialized = false
    private var rootURL: URL = URL(fileURLWithPath: "/")
    private var activeURL: URL = URL(fileURLWithPath: "/events.current.jsonl")
    private var handle: FileHandle?
    private var activeSize = 0
    private var rotationSequence = 0
    private var pending: ArraySlice<Data> = []
    private var isDraining = false
    private var drops = JSONLDropCounters()

    /// Creates a JSONL sink with deterministic rotation/retention policies.
    /// - Parameters:
    ///   - rootProvider: Root path provider used to resolve log directory.
    ///   - policy: Rotation, retention, and queue limits.
    ///   - eventQueueLabel: Component label used by sink-generated events.
    public init(rootProvider: any LogRootPathProvider, policy: JSONLRotationPolicy, eventQueueLabel: String = "jsonl") {
        self.rootProvider = rootProvider
        self.policy = policy
        self.eventQueueLabel = eventQueueLabel
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
                drops.droppedSizePolicy += 1
                await emitDropSummaryIfNeeded(trigger: "size-policy")
                return
            }
            guard pending.count < policy.maxQueueDepth else {
                drops.droppedQueueFull += 1
                await emitDropSummaryIfNeeded(trigger: "queue-full")
                return
            }
            pending.append(payload)
            if !isDraining {
                isDraining = true
                await drainQueue()
            }
        } catch {
            drops.droppedIOError += 1
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
            .filter { $0.lastPathComponent.hasPrefix("events") }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func serialize(_ envelope: LogEnvelope) throws -> Data {
        var serialized = try encoder.encode(envelope)
        serialized.append(0x0A)
        return serialized
    }

    private func drainQueue() async {
        while !pending.isEmpty {
            let next = pending.removeFirst()
            do {
                try rotateIfNeeded(for: next.count)
                try append(next)
            } catch {
                drops.droppedIOError += 1
            }
        }
        pending = []
        isDraining = false
        await emitDropSummaryIfNeeded(trigger: "drain")
    }

    private func ensureInitialized() throws {
        guard !initialized else {
            return
        }

        rootURL = try rootProvider.resolveRootPath()
        activeURL = rootURL.appendingPathComponent("events.current.jsonl", isDirectory: false)
        try FileManager.default.createDirectory(
            atPath: rootURL.path,
            withIntermediateDirectories: true,
            attributes: Self.protectionAttributes
        )
        try Self.excludeFromBackupIfNeeded(rootURL)
        if !FileManager.default.fileExists(atPath: activeURL.path) {
            FileManager.default.createFile(
                atPath: activeURL.path,
                contents: nil,
                attributes: Self.protectionAttributes
            )
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

        let timestampMillis = Int(Date().timeIntervalSince1970 * 1000)
        let rotatedName = "events.\(timestampMillis).\(rotationSequence).jsonl"
        rotationSequence += 1
        let rotatedURL = rootURL.appendingPathComponent(rotatedName, isDirectory: false)
        try FileManager.default.moveItem(at: activeURL, to: rotatedURL)
        if !Self.protectionAttributes.isEmpty {
            try FileManager.default.setAttributes(Self.protectionAttributes, ofItemAtPath: rotatedURL.path)
        }
        try Self.excludeFromBackupIfNeeded(rotatedURL)
        FileManager.default.createFile(
            atPath: activeURL.path,
            contents: nil,
            attributes: Self.protectionAttributes
        )
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
            .filter { $0.lastPathComponent.hasPrefix("events") }
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
        activeSize += data.count
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
