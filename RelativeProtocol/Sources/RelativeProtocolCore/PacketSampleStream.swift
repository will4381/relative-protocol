// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Foundation

public struct PacketSampleStreamLocation {
    public static let defaultKey = "packet.stream"

    public static func makeURL(appGroupID: String, key: String = defaultKey) -> URL? {
        let fileManager = FileManager.default
        let sanitizedKey = sanitizeForFilename(key)

        if let container = fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) {
            let dir = container.appendingPathComponent("PacketStream", isDirectory: true)
            ensureDirectory(dir)
            return dir.appendingPathComponent("\(sanitizedKey).ndjson")
        }

        let caches = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first ?? fileManager.temporaryDirectory
        let dir = caches.appendingPathComponent("RelativeProtocolPacketStream", isDirectory: true)
        ensureDirectory(dir)
        let sanitizedGroup = sanitizeForFilename(appGroupID)
        return dir.appendingPathComponent("\(sanitizedGroup).\(sanitizedKey).ndjson")
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
}

public final class PacketSampleStreamWriter {
    private let fileURL: URL?
    private let maxBytes: Int
    private let encoder = JSONEncoder()
    private let useLock: Bool
    private let lock = NSLock()
    private var currentSize: Int
    private var payloadBuffer = Data()
    private var fileHandle: FileHandle?

    public init(
        appGroupID: String,
        key: String = PacketSampleStreamLocation.defaultKey,
        maxBytes: Int = 5_000_000,
        useLock: Bool = true
    ) {
        self.fileURL = PacketSampleStreamLocation.makeURL(appGroupID: appGroupID, key: key)
        self.maxBytes = max(1, maxBytes)
        self.useLock = useLock
        if let fileURL {
            self.currentSize = Self.fileSize(at: fileURL)
        } else {
            self.currentSize = 0
        }
    }

    public func append(_ samples: [PacketSample]) {
        withLock {
            guard let fileURL, !samples.isEmpty else { return }

            payloadBuffer.removeAll(keepingCapacity: true)
            for sample in samples {
                guard let encoded = try? encoder.encode(sample) else { continue }
                payloadBuffer.append(encoded)
                payloadBuffer.append(0x0A)
            }
            guard !payloadBuffer.isEmpty else { return }

            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: fileURL.path) {
                fileManager.createFile(atPath: fileURL.path, contents: nil)
                currentSize = 0
            }
            if currentSize + payloadBuffer.count > maxBytes {
                fileHandle?.closeFile()
                fileHandle = nil
                try? fileManager.removeItem(at: fileURL)
                fileManager.createFile(atPath: fileURL.path, contents: nil)
                currentSize = 0
            }

            if fileHandle == nil {
                fileHandle = try? FileHandle(forWritingTo: fileURL)
                fileHandle?.seekToEndOfFile()
            }
            guard let handle = fileHandle else { return }
            handle.write(payloadBuffer)
            currentSize += payloadBuffer.count
            if payloadBuffer.count > maxBytes {
                payloadBuffer = Data()
            }
        }
    }

    public func close() {
        withLock {
            fileHandle?.closeFile()
            fileHandle = nil
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

    private static func fileSize(at url: URL) -> Int {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes?[.size] as? NSNumber)?.intValue ?? 0
    }
}

public struct PacketStreamCursor: Codable, Hashable, Sendable {
    public var offset: UInt64
    public var fileSignature: PacketStreamFileSignature?

    public init(offset: UInt64 = 0, fileSignature: PacketStreamFileSignature? = nil) {
        self.offset = offset
        self.fileSignature = fileSignature
    }

    public mutating func reset() {
        offset = 0
        fileSignature = nil
    }
}

public struct PacketStreamFileSignature: Codable, Hashable, Sendable {
    public let fileID: UInt64?
    public let creationDate: TimeInterval?
    public let modificationDate: TimeInterval?

    public init(fileID: UInt64?, creationDate: TimeInterval?, modificationDate: TimeInterval?) {
        self.fileID = fileID
        self.creationDate = creationDate
        self.modificationDate = modificationDate
    }

    public init(attributes: [FileAttributeKey: Any]) {
        let fileNumber = (attributes[.systemFileNumber] as? NSNumber)?.uint64Value
        let created = (attributes[.creationDate] as? Date)?.timeIntervalSince1970
        let modified = (attributes[.modificationDate] as? Date)?.timeIntervalSince1970
        self.init(fileID: fileNumber, creationDate: created, modificationDate: modified)
    }
}

public struct PacketSampleStreamReader {
    private let fileURL: URL?
    private let decoder = JSONDecoder()

    public init(appGroupID: String, key: String = PacketSampleStreamLocation.defaultKey) {
        self.fileURL = PacketSampleStreamLocation.makeURL(appGroupID: appGroupID, key: key)
    }

    public func readAll() -> [PacketSample] {
        guard let fileURL, let data = try? Data(contentsOf: fileURL) else { return [] }
        return decodeLines(data)
    }

    public func readNew(sinceOffset offset: UInt64) -> (samples: [PacketSample], nextOffset: UInt64) {
        guard let fileURL, let handle = try? FileHandle(forReadingFrom: fileURL) else {
            return ([], offset)
        }
        let attributes = try? FileManager.default.attributesOfItem(atPath: fileURL.path)
        let fileSize = (attributes?[.size] as? NSNumber)?.uint64Value
        var startOffset = offset
        if let fileSize, offset > fileSize {
            startOffset = 0
        }
        do {
            try handle.seek(toOffset: startOffset)
        } catch {
            startOffset = 0
            _ = try? handle.seek(toOffset: 0)
        }
        let data = handle.readDataToEndOfFile()
        handle.closeFile()
        guard let newlineIndex = data.lastIndex(of: 0x0A) else {
            return ([], startOffset)
        }
        let readData = data.prefix(upTo: data.index(after: newlineIndex))
        let samples = decodeLines(readData)
        let nextOffset = startOffset + UInt64(readData.count)
        return (samples, nextOffset)
    }

    public func readNew(cursor: inout PacketStreamCursor) -> [PacketSample] {
        guard let fileURL else { return [] }
        let signature = Self.fileSignature(at: fileURL)
        if let signature, signature != cursor.fileSignature {
            cursor.offset = 0
        }
        let result = readNew(sinceOffset: cursor.offset)
        cursor.offset = result.nextOffset
        if let signature {
            cursor.fileSignature = signature
        }
        return result.samples
    }

    private func decodeLines(_ data: Data) -> [PacketSample] {
        guard !data.isEmpty else { return [] }
        var samples: [PacketSample] = []
        data.split(separator: 0x0A).forEach { line in
            guard !line.isEmpty else { return }
            if let sample = try? decoder.decode(PacketSample.self, from: line) {
                samples.append(sample)
            }
        }
        return samples
    }

    private static func fileSignature(at url: URL) -> PacketStreamFileSignature? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else { return nil }
        return PacketStreamFileSignature(attributes: attributes)
    }
}