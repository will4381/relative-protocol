// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Darwin
import Foundation

public final class MetricsStore {
    public static let defaultKey = "metrics.snapshots"

    private let fileURL: URL?
    private let maxSnapshots: Int
    private let maxBytes: Int
    private let format: MetricsStoreFormat
    private let lockFileURL: URL?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let useLock: Bool
    private let lock = NSLock()
    private var cachedSnapshots: [MetricsSnapshot] = []
    private var cachedEncodedSnapshots: [Data] = []
    private var cachedFileModificationDate: Date?
    private var hasCache = false

    public init(
        appGroupID: String,
        key: String = MetricsStore.defaultKey,
        maxSnapshots: Int,
        maxBytes: Int = 1_500_000,
        format: MetricsStoreFormat = .json,
        useLock: Bool = true
    ) {
        self.maxSnapshots = max(1, maxSnapshots)
        self.maxBytes = max(1, maxBytes)
        self.fileURL = MetricsStore.makeStoreURL(appGroupID: appGroupID, key: key)
        self.lockFileURL = self.fileURL?.appendingPathExtension("lock")
        self.format = format
        self.useLock = useLock
    }

    public func append(_ snapshot: MetricsSnapshot) {
        withLock {
            guard let fileURL else { return }

            guard let snapshotData = try? encoder.encode(snapshot) else { return }
            guard snapshotData.count <= maxBytes else { return }

            var snapshots = loadSnapshotsLocked(from: fileURL)
            var encodedSnapshots = encodedSnapshotsForCurrentCache(fallingBackTo: snapshots)
            snapshots.append(snapshot)
            encodedSnapshots.append(snapshotData)
            trimSnapshots(&snapshots, encodedSnapshots: &encodedSnapshots)
            writeSnapshotsLocked(snapshots, encodedSnapshots: encodedSnapshots, to: fileURL)
        }
    }

    public func load() -> [MetricsSnapshot] {
        withLock {
            guard let fileURL else { return [] }
            return loadSnapshotsLocked(from: fileURL)
        }
    }

    public func clear() {
        withLock {
            guard let fileURL else { return }
            try? FileManager.default.removeItem(at: fileURL)
            cachedSnapshots = []
            cachedEncodedSnapshots = []
            cachedFileModificationDate = nil
            hasCache = true
        }
    }

    private func withLock<T>(_ body: () -> T) -> T {
        if useLock {
            return withFileLock {
                lock.lock()
                defer { lock.unlock() }
                return body()
            }
        }
        return withFileLock(body)
    }

    private func withFileLock<T>(_ body: () -> T) -> T {
        guard let lockFileURL else { return body() }
        let fd = open(lockFileURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { return body() }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { return body() }
        defer { _ = flock(fd, LOCK_UN) }
        return body()
    }

    private func loadSnapshotsLocked(from url: URL) -> [MetricsSnapshot] {
        let fileManager = FileManager.default
        let attributes = try? fileManager.attributesOfItem(atPath: url.path)
        let modificationDate = attributes?[.modificationDate] as? Date
        if hasCache, cachedFileModificationDate == modificationDate {
            return cachedSnapshots
        }

        guard let data = try? Data(contentsOf: url) else {
            cachedSnapshots = []
            cachedFileModificationDate = modificationDate
            hasCache = true
            return []
        }

        let snapshots: [MetricsSnapshot]
        switch format {
        case .json:
            snapshots = (try? decoder.decode([MetricsSnapshot].self, from: data)) ?? []
        case .ndjson:
            snapshots = decodeNDJSON(data)
        }
        cachedSnapshots = snapshots
        cachedEncodedSnapshots = snapshots.compactMap { try? encoder.encode($0) }
        cachedFileModificationDate = modificationDate
        hasCache = true
        return snapshots
    }

    private func writeSnapshotsLocked(_ snapshots: [MetricsSnapshot], encodedSnapshots: [Data], to url: URL) {
        switch format {
        case .json:
            var data = Data()
            data.reserveCapacity(serializedSize(of: encodedSnapshots))
            data.append(0x5B) // [
            for (index, encoded) in encodedSnapshots.enumerated() {
                if index > 0 {
                    data.append(0x2C) // ,
                }
                data.append(encoded)
            }
            data.append(0x5D) // ]
            guard data.count <= maxBytes else { return }
            try? data.write(to: url, options: [.atomic])
        case .ndjson:
            var data = Data()
            data.reserveCapacity(serializedSize(of: encodedSnapshots))
            for encoded in encodedSnapshots {
                data.append(encoded)
                data.append(0x0A)
            }
            guard data.count <= maxBytes else { return }
            try? data.write(to: url, options: [.atomic])
        }
        cachedSnapshots = snapshots
        cachedEncodedSnapshots = encodedSnapshots
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        cachedFileModificationDate = attributes?[.modificationDate] as? Date
        hasCache = true
    }

    private func trimSnapshots(_ snapshots: inout [MetricsSnapshot], encodedSnapshots: inout [Data]) {
        if snapshots.count > maxSnapshots {
            let removeCount = snapshots.count - maxSnapshots
            snapshots.removeFirst(removeCount)
            encodedSnapshots.removeFirst(removeCount)
        }

        while !snapshots.isEmpty && serializedSize(of: encodedSnapshots) > maxBytes {
            snapshots.removeFirst()
            encodedSnapshots.removeFirst()
        }
    }

    private static func makeStoreURL(appGroupID: String, key: String) -> URL? {
        let fileManager = FileManager.default
        let sanitizedKey = sanitizeForFilename(key)

        if let container = fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) {
            let dir = container.appendingPathComponent("MetricsStore", isDirectory: true)
            ensureDirectory(dir)
            return dir.appendingPathComponent("\(sanitizedKey).json")
        }

        let caches = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first ?? fileManager.temporaryDirectory
        let dir = caches.appendingPathComponent("RelativeProtocolMetrics", isDirectory: true)
        ensureDirectory(dir)
        let sanitizedGroup = sanitizeForFilename(appGroupID)
        return dir.appendingPathComponent("\(sanitizedGroup).\(sanitizedKey).json")
    }

    private static func ensureDirectory(_ url: URL) {
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: nil)
    }

    private static func sanitizeForFilename(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        return value.unicodeScalars
            .map { allowed.contains($0) ? String($0) : "_" }
            .joined()
    }

    private func decodeNDJSON(_ data: Data) -> [MetricsSnapshot] {
        guard !data.isEmpty else { return [] }
        var snapshots: [MetricsSnapshot] = []
        data.split(separator: 0x0A).forEach { line in
            guard !line.isEmpty else { return }
            if let snapshot = try? decoder.decode(MetricsSnapshot.self, from: line) {
                snapshots.append(snapshot)
            }
        }
        return snapshots
    }

    private func encodedSnapshotsForCurrentCache(fallingBackTo snapshots: [MetricsSnapshot]) -> [Data] {
        if cachedEncodedSnapshots.count == snapshots.count {
            return cachedEncodedSnapshots
        }
        return snapshots.compactMap { try? encoder.encode($0) }
    }

    private func serializedSize(of encodedSnapshots: [Data]) -> Int {
        switch format {
        case .json:
            guard !encodedSnapshots.isEmpty else { return 2 }
            let payloadBytes = encodedSnapshots.reduce(0) { $0 + $1.count }
            let commaCount = max(0, encodedSnapshots.count - 1)
            return 2 + payloadBytes + commaCount
        case .ndjson:
            return encodedSnapshots.reduce(0) { $0 + $1.count + 1 }
        }
    }
}

public enum MetricsStoreFormat: String, Codable, Sendable {
    case json
    case ndjson
}
