import Foundation

/// Supported raw-text artifacts persisted into the shared App Group container.
public enum AppGroupDiagnosticFileKind: String, Sendable, Equatable, Hashable {
    case analytics
    case currentLog
    case rotatedLog
}

/// Controls whether a file should be read from the start or tailed from the end.
public enum AppGroupDiagnosticReadStrategy: Sendable, Equatable, Hashable {
    case full(maxBytes: Int)
    case tail(maxBytes: Int)
}

/// Metadata for one diagnostic text artifact stored in the shared App Group container.
/// Identity is anchored to the relative path so the same file stays stable across refreshes.
public struct AppGroupDiagnosticFile: Sendable, Equatable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let relativePath: String
    public let url: URL
    public let kind: AppGroupDiagnosticFileKind
    public let sizeBytes: Int64
    public let modifiedAt: Date?
    public let readStrategy: AppGroupDiagnosticReadStrategy

    /// - Parameters:
    ///   - id: Stable file identifier, typically the relative path.
    ///   - name: User-facing filename.
    ///   - relativePath: Path relative to the App Group container root.
    ///   - url: Absolute file URL.
    ///   - kind: File category used for grouping and display.
    ///   - sizeBytes: File size in bytes at listing time.
    ///   - modifiedAt: Best-effort modification timestamp.
    ///   - readStrategy: Default bounded read behavior for the file.
    public init(
        id: String,
        name: String,
        relativePath: String,
        url: URL,
        kind: AppGroupDiagnosticFileKind,
        sizeBytes: Int64,
        modifiedAt: Date?,
        readStrategy: AppGroupDiagnosticReadStrategy
    ) {
        self.id = id
        self.name = name
        self.relativePath = relativePath
        self.url = url
        self.kind = kind
        self.sizeBytes = sizeBytes
        self.modifiedAt = modifiedAt
        self.readStrategy = readStrategy
    }
}

/// Result of reading one diagnostic file with bounded I/O.
public struct AppGroupDiagnosticFileContents: Sendable, Equatable {
    public let file: AppGroupDiagnosticFile
    public let text: String
    public let wasTrimmed: Bool

    /// - Parameters:
    ///   - file: File metadata associated with the read.
    ///   - text: UTF-8-decoded text payload.
    ///   - wasTrimmed: Indicates the file exceeded the configured read bound.
    public init(file: AppGroupDiagnosticFile, text: String, wasTrimmed: Bool) {
        self.file = file
        self.text = text
        self.wasTrimmed = wasTrimmed
    }
}

/// Errors surfaced while resolving or reading shared App Group diagnostics files.
public enum AppGroupDiagnosticsReaderError: LocalizedError {
    case containerUnavailable(String)
    case fileOutsideContainer(URL)

    public var errorDescription: String? {
        switch self {
        case .containerUnavailable(let appGroupID):
            return "Shared container is unavailable for App Group '\(appGroupID)'."
        case .fileOutsideContainer(let url):
            return "The diagnostic file is outside the shared container: \(url.path)"
        }
    }
}

/// Reads raw analytics and JSONL log artifacts from the shared App Group container.
/// Decision: expose bounded raw file access for device debugging without requiring Finder or Console.app.
public struct AppGroupDiagnosticsReader: Sendable {
    private let appGroupID: String
    private let containerURLResolver: @Sendable (String) -> URL?

    /// - Parameter appGroupID: App Group identifier shared with the tunnel extension.
    public init(appGroupID: String) {
        self.init(
            appGroupID: appGroupID,
            containerURLResolver: { identifier in
                // Docs: https://developer.apple.com/documentation/foundation/filemanager/containerurl(forsecurityapplicationgroupidentifier:)
                FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
            }
        )
    }

    /// Test-only initializer that injects a deterministic container resolver.
    /// - Parameters:
    ///   - appGroupID: Logical App Group identifier.
    ///   - containerURLResolver: Closure that resolves the shared container root.
    init(appGroupID: String, containerURLResolver: @escaping @Sendable (String) -> URL?) {
        self.appGroupID = appGroupID
        self.containerURLResolver = containerURLResolver
    }

    /// Lists all supported raw diagnostic files currently available in the shared container.
    /// - Returns: Files ordered as analytics artifacts first, then active log, then rotated logs newest-first.
    /// - Throws: `AppGroupDiagnosticsReaderError` when the App Group container cannot be resolved.
    public func listFiles() throws -> [AppGroupDiagnosticFile] {
        let container = try containerURL()
        var files: [AppGroupDiagnosticFile] = []

        files.append(contentsOf: try analyticsFiles(container: container))
        files.append(contentsOf: try logFiles(container: container))
        return files
    }

    /// Reads one diagnostic file using its default bounded strategy.
    /// - Parameter file: File metadata returned by `listFiles()`.
    /// - Returns: Decoded text payload and trim status.
    /// - Throws: I/O errors or `AppGroupDiagnosticsReaderError.fileOutsideContainer` if the URL is invalid.
    public func readFile(_ file: AppGroupDiagnosticFile) throws -> AppGroupDiagnosticFileContents {
        let container = try containerURL()
        let standardizedContainer = container.standardizedFileURL.path
        let standardizedFile = file.url.standardizedFileURL.path
        let containerPrefix = standardizedContainer.hasSuffix("/") ? standardizedContainer : standardizedContainer + "/"
        guard standardizedFile == standardizedContainer || standardizedFile.hasPrefix(containerPrefix) else {
            throw AppGroupDiagnosticsReaderError.fileOutsideContainer(file.url)
        }

        let (data, wasTrimmed) = try readData(at: file.url, strategy: file.readStrategy)
        let text = String(decoding: data, as: UTF8.self)
        return AppGroupDiagnosticFileContents(file: file, text: text, wasTrimmed: wasTrimmed)
    }

    private func analyticsFiles(container: URL) throws -> [AppGroupDiagnosticFile] {
        let root = container.appendingPathComponent("Analytics", isDirectory: true)
        let descriptors: [(name: String, strategy: AppGroupDiagnosticReadStrategy)] = [
            ("last-stop.json", .full(maxBytes: 16_384)),
            ("metrics.json", .full(maxBytes: 262_144)),
            ("packet-stream.ndjson", .tail(maxBytes: 131_072))
        ]

        return try descriptors.compactMap { descriptor in
            let url = root.appendingPathComponent(descriptor.name, isDirectory: false)
            guard FileManager.default.fileExists(atPath: url.path) else {
                return nil
            }
            return try diagnosticFile(
                url: url,
                relativePath: "Analytics/\(descriptor.name)",
                kind: .analytics,
                readStrategy: descriptor.strategy
            )
        }
    }

    private func logFiles(container: URL) throws -> [AppGroupDiagnosticFile] {
        let root = container.appendingPathComponent("Logs", isDirectory: true)
        guard FileManager.default.fileExists(atPath: root.path) else {
            return []
        }

        let urls = try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        )

        var active: [AppGroupDiagnosticFile] = []
        var rotated: [AppGroupDiagnosticFile] = []

        for url in urls {
            let resourceValues = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard resourceValues.isRegularFile == true else {
                continue
            }

            let name = url.lastPathComponent
            if name == "events.current.jsonl" {
                active.append(
                    try diagnosticFile(
                        url: url,
                        relativePath: "Logs/\(name)",
                        kind: .currentLog,
                        readStrategy: .tail(maxBytes: 131_072)
                    )
                )
                continue
            }

            guard name.hasPrefix("events."), name.hasSuffix(".jsonl") else {
                continue
            }
            rotated.append(
                try diagnosticFile(
                    url: url,
                    relativePath: "Logs/\(name)",
                    kind: .rotatedLog,
                    readStrategy: .tail(maxBytes: 131_072)
                )
            )
        }

        rotated.sort {
            if $0.modifiedAt != $1.modifiedAt {
                return ($0.modifiedAt ?? .distantPast) > ($1.modifiedAt ?? .distantPast)
            }
            return $0.name > $1.name
        }

        return active + rotated
    }

    private func diagnosticFile(
        url: URL,
        relativePath: String,
        kind: AppGroupDiagnosticFileKind,
        readStrategy: AppGroupDiagnosticReadStrategy
    ) throws -> AppGroupDiagnosticFile {
        let values = try url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
        return AppGroupDiagnosticFile(
            id: relativePath,
            name: url.lastPathComponent,
            relativePath: relativePath,
            url: url,
            kind: kind,
            sizeBytes: Int64(values.fileSize ?? 0),
            modifiedAt: values.contentModificationDate,
            readStrategy: readStrategy
        )
    }

    private func readData(at url: URL, strategy: AppGroupDiagnosticReadStrategy) throws -> (Data, Bool) {
        let fileHandle = try FileHandle(forReadingFrom: url)
        defer {
            try? fileHandle.close()
        }

        let fileSize = (try? fileHandle.seekToEnd()) ?? 0
        try fileHandle.seek(toOffset: 0)

        switch strategy {
        case .full(let maxBytes):
            let bounded = max(1, maxBytes)
            let count = Int(min(fileSize, UInt64(bounded)))
            let data = try fileHandle.read(upToCount: count) ?? Data()
            return (data, fileSize > UInt64(bounded))

        case .tail(let maxBytes):
            let bounded = UInt64(max(1, maxBytes))
            let shouldTrim = fileSize > bounded
            let startOffset = shouldTrim ? fileSize - bounded : 0
            try fileHandle.seek(toOffset: startOffset)
            let data = try fileHandle.readToEnd() ?? Data()
            return (data, shouldTrim)
        }
    }

    private func containerURL() throws -> URL {
        guard let container = containerURLResolver(appGroupID) else {
            throw AppGroupDiagnosticsReaderError.containerUnavailable(appGroupID)
        }
        return container
    }
}
