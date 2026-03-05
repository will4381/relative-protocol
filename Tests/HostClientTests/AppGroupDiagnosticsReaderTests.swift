import Foundation
@testable import HostClient
import XCTest

final class AppGroupDiagnosticsReaderTests: XCTestCase {
    /// Verifies file listing order stays stable for the simple in-app diagnostics browser.
    func testListFilesOrdersAnalyticsThenCurrentThenRotatedLogs() throws {
        let root = try makeTemporaryContainer()
        try createFile(at: root.appendingPathComponent("Analytics/last-stop.json"), text: "{\"reason\":\"providerFailed\"}")
        try createFile(at: root.appendingPathComponent("Analytics/metrics.json"), text: "[]")
        try createFile(at: root.appendingPathComponent("Analytics/packet-stream.ndjson"), text: "{\"flow\":\"a\"}\n")
        try createFile(at: root.appendingPathComponent("Logs/events.current.jsonl"), text: "{\"event\":\"active\"}\n")
        try createFile(at: root.appendingPathComponent("Logs/events.10.1.jsonl"), text: "{\"event\":\"older\"}\n")
        try createFile(at: root.appendingPathComponent("Logs/events.20.1.jsonl"), text: "{\"event\":\"newer\"}\n")

        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 10)],
            ofItemAtPath: root.appendingPathComponent("Logs/events.10.1.jsonl").path
        )
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 20)],
            ofItemAtPath: root.appendingPathComponent("Logs/events.20.1.jsonl").path
        )

        let reader = AppGroupDiagnosticsReader(appGroupID: "group.test") { _ in root }
        let files = try reader.listFiles()

        XCTAssertEqual(
            files.map(\.relativePath),
            [
                "Analytics/last-stop.json",
                "Analytics/metrics.json",
                "Analytics/packet-stream.ndjson",
                "Logs/events.current.jsonl",
                "Logs/events.20.1.jsonl",
                "Logs/events.10.1.jsonl"
            ]
        )
    }

    /// Confirms large log files are tailed instead of fully loaded into memory.
    func testReadFileTailsLargeLog() throws {
        let root = try makeTemporaryContainer()
        let largePrefix = String(repeating: "a", count: 140_000)
        let suffix = "\n{\"event\":\"target\"}\n"
        try createFile(
            at: root.appendingPathComponent("Logs/events.current.jsonl"),
            text: largePrefix + suffix
        )

        let reader = AppGroupDiagnosticsReader(appGroupID: "group.test") { _ in root }
        let file = try XCTUnwrap(reader.listFiles().first(where: { $0.relativePath == "Logs/events.current.jsonl" }))
        let contents = try reader.readFile(file)

        XCTAssertTrue(contents.wasTrimmed)
        XCTAssertTrue(contents.text.contains("\"target\""))
        XCTAssertFalse(contents.text.contains(String(repeating: "a", count: 140_000)))
    }

    private func makeTemporaryContainer() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func createFile(at url: URL, text: String) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url, options: .atomic)
    }
}
