// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Analytics
import Foundation

/// Host-side reader for optional rich packet JSONL debug artifacts.
/// Decision: separate apps can read the same App Group artifact without knowing the package's directory layout.
public struct TunnelRichPacketLogStore: Sendable {
    public let appGroupID: String
    public let filePrefix: String

    public init(
        appGroupID: String,
        filePrefix: String = RichPacketLogPolicy.defaultFilePrefix
    ) {
        self.appGroupID = appGroupID
        self.filePrefix = filePrefix
    }

    public func listLogFiles() throws -> [URL] {
        try reader().listLogFiles()
    }

    public func readRecords(limit: Int? = nil) throws -> [RichPacketLogRecord] {
        try reader().readRecords(limit: limit)
    }

    public func clear() throws {
        try reader().clear()
    }

    private func reader() throws -> RichPacketLogReader {
        RichPacketLogReader(
            rootURL: try AnalyticsStoragePaths.richPacketLogsRoot(appGroupID: appGroupID),
            filePrefix: filePrefix
        )
    }
}
