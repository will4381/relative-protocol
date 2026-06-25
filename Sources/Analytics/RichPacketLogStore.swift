// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation

public struct RichPacketLogDropCounters: Sendable, Equatable {
    public var droppedIOError: Int
    public var droppedSizePolicy: Int

    public init(droppedIOError: Int = 0, droppedSizePolicy: Int = 0) {
        self.droppedIOError = droppedIOError
        self.droppedSizePolicy = droppedSizePolicy
    }

    public var total: Int {
        Self.saturatingAdd(droppedIOError, droppedSizePolicy)
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

public struct RichPacketLogStoreSnapshot: Sendable, Equatable {
    public let files: [URL]
    public let activeFileURL: URL?
    public let activeSizeBytes: Int
    public let dropCounters: RichPacketLogDropCounters

    public init(
        files: [URL],
        activeFileURL: URL?,
        activeSizeBytes: Int,
        dropCounters: RichPacketLogDropCounters
    ) {
        self.files = files
        self.activeFileURL = activeFileURL
        self.activeSizeBytes = max(0, activeSizeBytes)
        self.dropCounters = dropCounters
    }
}

public struct RichPacketLogReader: Sendable {
    public let rootURL: URL
    public let filePrefix: String

    public init(rootURL: URL, filePrefix: String = RichPacketLogPolicy.defaultFilePrefix) {
        self.rootURL = rootURL
        self.filePrefix = RichPacketLogFiles.normalizedFilePrefix(filePrefix)
    }

    public func listLogFiles() throws -> [URL] {
        try RichPacketLogFiles.listFiles(rootURL: rootURL, filePrefix: filePrefix)
    }

    public func readRecords(limit: Int? = nil) throws -> [RichPacketLogRecord] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        var records: [RichPacketLogRecord] = []

        for url in try listLogFiles() {
            guard FileManager.default.fileExists(atPath: url.path) else {
                continue
            }
            let data = try Data(contentsOf: url)
            guard let text = String(data: data, encoding: .utf8) else {
                continue
            }
            for line in text.split(whereSeparator: \.isNewline) where !line.isEmpty {
                guard let lineData = String(line).data(using: .utf8) else {
                    continue
                }
                records.append(try decoder.decode(RichPacketLogRecord.self, from: lineData))
            }
        }

        if let limit {
            return Array(records.suffix(max(0, limit)))
        }
        return records
    }

    public func clear() throws {
        for url in try listLogFiles() {
            try FileManager.default.removeItem(at: url)
        }
    }
}

/// Dedicated JSONL writer for high-volume packet metadata debug streams.
/// Decision: this is separate from `JSONLLogSink` so packet facts remain queryable as first-class records instead
/// of being flattened into operational-log metadata.
public actor RichPacketLogStore {
    public nonisolated let rootURL: URL
    public nonisolated let policy: RichPacketLogPolicy

    private let encoder: JSONEncoder
    private let filePrefix: String

    private var initialized = false
    private var activeURL: URL
    private var handle: FileHandle?
    private var activeSizeBytes = 0
    private var rotationSequence = 0
    private var drops = RichPacketLogDropCounters()

    public init(rootURL: URL, policy: RichPacketLogPolicy) {
        self.rootURL = rootURL
        self.policy = policy
        self.filePrefix = RichPacketLogFiles.normalizedFilePrefix(policy.filePrefix)
        self.activeURL = rootURL.appendingPathComponent(
            RichPacketLogFiles.activeFileName(filePrefix: RichPacketLogFiles.normalizedFilePrefix(policy.filePrefix)),
            isDirectory: false
        )
        self.encoder = JSONEncoder()
        self.encoder.dateEncodingStrategy = .millisecondsSince1970
        self.encoder.outputFormatting = [.sortedKeys]
    }

    public func append(records: [RichPacketLogRecord]) async {
        guard policy.isEnabled, !records.isEmpty else {
            return
        }

        do {
            try ensureInitialized()
            for record in records {
                let payload = try serialize(record)
                guard payload.count <= policy.maxBytesPerFile else {
                    drops.incrementSizePolicy()
                    continue
                }
                try rotateIfNeeded(for: payload.count)
                try append(payload)
            }
        } catch {
            drops.incrementIOError()
        }
    }

    public func snapshot() throws -> RichPacketLogStoreSnapshot {
        try ensureInitialized()
        return RichPacketLogStoreSnapshot(
            files: try RichPacketLogFiles.listFiles(rootURL: rootURL, filePrefix: filePrefix),
            activeFileURL: activeURL,
            activeSizeBytes: activeSizeBytes,
            dropCounters: drops
        )
    }

    public func readRecords(limit: Int? = nil) throws -> [RichPacketLogRecord] {
        try RichPacketLogReader(rootURL: rootURL, filePrefix: filePrefix).readRecords(limit: limit)
    }

    public func clear() throws {
        try handle?.synchronize()
        try handle?.close()
        handle = nil
        initialized = false
        activeSizeBytes = 0
        try RichPacketLogReader(rootURL: rootURL, filePrefix: filePrefix).clear()
    }

    public func dropCounters() -> RichPacketLogDropCounters {
        drops
    }

    private func ensureInitialized() throws {
        guard !initialized else {
            return
        }

        try ProtectedAnalyticsFileIO.createProtectedDirectory(at: rootURL)
        activeURL = rootURL.appendingPathComponent(
            RichPacketLogFiles.activeFileName(filePrefix: filePrefix),
            isDirectory: false
        )
        if !FileManager.default.fileExists(atPath: activeURL.path) {
            try ProtectedAnalyticsFileIO.writeProtectedData(Data(), to: activeURL)
        }
        handle = try FileHandle(forWritingTo: activeURL)
        try handle?.seekToEnd()
        let attrs = try FileManager.default.attributesOfItem(atPath: activeURL.path)
        activeSizeBytes = attrs[.size] as? Int ?? 0
        initialized = true
    }

    private func serialize(_ record: RichPacketLogRecord) throws -> Data {
        var data = try encoder.encode(record)
        data.append(0x0A)
        return data
    }

    private func rotateIfNeeded(for incomingBytes: Int) throws {
        guard activeSizeBytes + incomingBytes > policy.maxBytesPerFile else {
            return
        }
        guard let handle else {
            throw CocoaError(.fileNoSuchFile)
        }

        try handle.synchronize()
        try handle.close()

        let rotatedURL = rootURL.appendingPathComponent(
            RichPacketLogFiles.rotatedFileName(
                filePrefix: filePrefix,
                timestampMilliseconds: Self.timestampMilliseconds(Date()),
                sequence: rotationSequence
            ),
            isDirectory: false
        )
        rotationSequence &+= 1
        try FileManager.default.moveItem(at: activeURL, to: rotatedURL)
        try ProtectedAnalyticsFileIO.writeProtectedData(Data(), to: activeURL)
        self.handle = try FileHandle(forWritingTo: activeURL)
        activeSizeBytes = 0
        try enforceRetention()
    }

    private func append(_ data: Data) throws {
        guard let handle else {
            throw CocoaError(.fileNoSuchFile)
        }
        try handle.write(contentsOf: data)
        activeSizeBytes = Self.saturatingAdd(activeSizeBytes, data.count)
    }

    private func enforceRetention() throws {
        var files = try RichPacketLogFiles.fileMetadata(rootURL: rootURL, filePrefix: filePrefix)

        if files.count > policy.maxFileCount {
            for entry in files.prefix(files.count - policy.maxFileCount) {
                try FileManager.default.removeItem(at: entry.url)
            }
            files.removeFirst(files.count - policy.maxFileCount)
        }

        var totalBytes = files.reduce(0) { Self.saturatingAdd($0, $1.size) }
        var index = 0
        while totalBytes > policy.maxTotalBytes && index < files.count {
            let candidate = files[index]
            index += 1
            if candidate.url == activeURL {
                continue
            }
            try FileManager.default.removeItem(at: candidate.url)
            totalBytes = max(0, totalBytes - candidate.size)
        }
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

    private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int.max : value
    }
}

private enum RichPacketLogFiles {
    static func activeFileName(filePrefix: String) -> String {
        "\(filePrefix).current.jsonl"
    }

    static func rotatedFileName(filePrefix: String, timestampMilliseconds: Int, sequence: Int) -> String {
        "\(filePrefix).\(timestampMilliseconds).\(sequence).jsonl"
    }

    static func listFiles(rootURL: URL, filePrefix: String) throws -> [URL] {
        guard FileManager.default.fileExists(atPath: rootURL.path) else {
            return []
        }
        return try fileMetadata(rootURL: rootURL, filePrefix: filePrefix).map(\.url)
    }

    static func fileMetadata(rootURL: URL, filePrefix: String) throws -> [(url: URL, size: Int)] {
        let normalizedPrefix = normalizedFilePrefix(filePrefix)
        let activeName = activeFileName(filePrefix: normalizedPrefix)
        let files = try FileManager.default.contentsOfDirectory(
            at: rootURL,
            includingPropertiesForKeys: [.creationDateKey, .fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        return try files
            .filter { isOwnedFileName($0.lastPathComponent, filePrefix: normalizedPrefix) }
            .map { url in
                let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
                let created = attrs[.creationDate] as? Date ?? .distantPast
                let size = attrs[.size] as? Int ?? 0
                let activeRank = url.lastPathComponent == activeName ? 1 : 0
                return (url: url, created: created, size: size, activeRank: activeRank)
            }
            .sorted { lhs, rhs in
                if lhs.activeRank != rhs.activeRank {
                    return lhs.activeRank < rhs.activeRank
                }
                if lhs.created == rhs.created {
                    return lhs.url.lastPathComponent < rhs.url.lastPathComponent
                }
                return lhs.created < rhs.created
            }
            .map { (url: $0.url, size: $0.size) }
    }

    static func isOwnedFileName(_ name: String, filePrefix: String) -> Bool {
        if name == activeFileName(filePrefix: filePrefix) {
            return true
        }

        let rotatedPrefix = "\(filePrefix)."
        guard name.hasPrefix(rotatedPrefix), name.hasSuffix(".jsonl") else {
            return false
        }

        let suffix = name.dropFirst(rotatedPrefix.count)
        return suffix.first?.isNumber == true
    }

    static func normalizedFilePrefix(_ prefix: String) -> String {
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
        return normalized.isEmpty ? RichPacketLogPolicy.defaultFilePrefix : normalized
    }
}
