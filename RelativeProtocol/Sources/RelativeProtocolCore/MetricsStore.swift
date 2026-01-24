// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Foundation

public final class MetricsStore {
    public static let defaultKey = "metrics.snapshots"

    private let fileURL: URL?
    private let maxSnapshots: Int
    private let maxBytes: Int
    private let format: MetricsStoreFormat
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let useLock: Bool
    private let lock = NSLock()
    private var cachedSnapshots: [MetricsSnapshot] = []
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
        self.format = format
        self.useLock = useLock
    }

    public func append(_ snapshot: MetricsSnapshot) {
        withLock {
            guard let fileURL else { return }

        guard let snapshotData = try? encoder.encode(snapshot) else { return }
        guard snapshotData.count <= maxBytes else { return }

        var snapshots = loadSnapshotsLocked(from: fileURL)
        snapshots.append(snapshot)
        trimSnapshots(&snapshots)
            writeSnapshotsLocked(snapshots, to: fileURL)
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
            cachedFileModificationDate = nil
            hasCache = true
        }
    }

    private func withLock<T>(_ body: () -> T) -> T {
        if useLock {
            lock.lock()
            let result = body()
            lock.unlock()
            return result
        }
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
        cachedFileModificationDate = modificationDate
        hasCache = true
        return snapshots
    }

    private func writeSnapshotsLocked(_ snapshots: [MetricsSnapshot], to url: URL) {
        switch format {
        case .json:
            guard let data = try? encoder.encode(snapshots) else { return }
            guard data.count <= maxBytes else { return }
            try? data.write(to: url, options: [.atomic])
        case .ndjson:
            var data = Data()
            for snapshot in snapshots {
                guard let encoded = try? encoder.encode(snapshot) else { continue }
                data.append(encoded)
                data.append(0x0A)
            }
            guard data.count <= maxBytes else { return }
            try? data.write(to: url, options: [.atomic])
        }
        cachedSnapshots = snapshots
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        cachedFileModificationDate = attributes?[.modificationDate] as? Date
        hasCache = true
    }

    private func trimSnapshots(_ snapshots: inout [MetricsSnapshot]) {
        if snapshots.count > maxSnapshots {
            snapshots.removeFirst(snapshots.count - maxSnapshots)
        }

        while !snapshots.isEmpty {
            guard let data = try? encoder.encode(snapshots) else { return }
            if data.count <= maxBytes { return }
            snapshots.removeFirst()
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
}

public enum MetricsStoreFormat: String, Codable, Sendable {
    case json
    case ndjson
}
