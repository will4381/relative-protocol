// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.

import Foundation
import XCTest
import RelativeProtocolCore

final class AppSignatureStoreEdgeTests: XCTestCase {
    func testLoadSupportsSetPayload() throws {
        let url = try makeTempURL()
        defer { cleanup(url) }

        let payload = """
        {
          "version": 1,
          "updatedAt": "2026-01-01T00:00:00Z",
          "signatures": [
            {"label": "a", "domains": ["a.example.com"]},
            {"label": "b", "domains": ["b.example.com"]}
          ]
        }
        """
        try Data(payload.utf8).write(to: url, options: .atomic)

        let loaded = AppSignatureStore.load(from: url)
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded[0].label, "a")
        XCTAssertEqual(loaded[1].label, "b")
    }

    func testLoadSupportsArrayPayload() throws {
        let url = try makeTempURL()
        defer { cleanup(url) }

        let payload = """
        [
          {"label": "social", "domains": ["social.example.com"]}
        ]
        """
        try Data(payload.utf8).write(to: url, options: .atomic)

        let loaded = AppSignatureStore.load(from: url)
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0].label, "social")
    }

    func testLoadReturnsEmptyForInvalidJSON() throws {
        let url = try makeTempURL()
        defer { cleanup(url) }
        try Data("not-json".utf8).write(to: url, options: .atomic)

        XCTAssertTrue(AppSignatureStore.load(from: url).isEmpty)
        XCTAssertTrue(AppSignatureStore.loadValidated(from: url).isEmpty)
    }

    func testWriteThenLoadValidatedRoundTrip() throws {
        let url = try makeTempURL()
        defer { cleanup(url) }

        let signatures = [
            AppSignature(label: "video", domains: ["video.example.com"]),
            AppSignature(label: "social", domains: ["social.example.com"])
        ]
        AppSignatureStore.write(signatures, to: url)

        let loaded = AppSignatureStore.loadValidated(from: url)
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(Set(loaded.map(\.label)), Set(["video", "social"]))
    }

    func testWriteIfMissingDoesNotOverwriteExistingFile() throws {
        let url = try makeTempURL()
        defer { cleanup(url) }

        let original = [AppSignature(label: "first", domains: ["first.example.com"])]
        AppSignatureStore.write(original, to: url)

        let replacement = [AppSignature(label: "second", domains: ["second.example.com"])]
        AppSignatureStore.writeIfMissing(replacement, to: url)

        let loaded = AppSignatureStore.load(from: url)
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0].label, "first")
    }

    func testWriteIfMissingWritesWhenFileDoesNotExist() throws {
        let url = try makeTempURL()
        defer { cleanup(url) }

        try? FileManager.default.removeItem(at: url)
        let signatures = [AppSignature(label: "new", domains: ["new.example.com"])]
        AppSignatureStore.writeIfMissing(signatures, to: url)

        let loaded = AppSignatureStore.load(from: url)
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0].label, "new")
    }

    func testValidateRejectsMissingDotDomain() {
        let signatures = [AppSignature(label: "bad", domains: ["localhost"])]
        XCTAssertThrowsError(try AppSignatureStore.validate(signatures)) { error in
            guard case AppSignatureValidationError.invalidDomain(let domain, _) = error else {
                return XCTFail("Expected invalidDomain")
            }
            XCTAssertEqual(domain, "localhost")
        }
    }

    func testValidateRejectsLeadingOrTrailingDotDomain() {
        XCTAssertThrowsError(try AppSignatureStore.validate([
            AppSignature(label: "bad", domains: [".example.com"])
        ]))
        XCTAssertThrowsError(try AppSignatureStore.validate([
            AppSignature(label: "bad", domains: ["example.com."])
        ]))
    }

    func testDefaultURLPointsToAppSignaturesDirectory() {
        let url = AppSignatureStore.defaultURL(appGroupID: "group.does.not.exist.\(UUID().uuidString)")
        XCTAssertNotNil(url)
        XCTAssertTrue(url?.path.contains("AppSignatures") ?? false)
        XCTAssertEqual(url?.lastPathComponent, AppSignatureStore.defaultFileName)
    }

    func testValidationErrorsProvideHumanReadableDescriptions() {
        XCTAssertEqual(
            AppSignatureValidationError.emptySignatures.errorDescription,
            "Signature list is empty."
        )
        XCTAssertEqual(
            AppSignatureValidationError.invalidLabel("x").errorDescription,
            "Signature label is invalid: x"
        )
        XCTAssertEqual(
            AppSignatureValidationError.invalidDomain("bad", label: "app").errorDescription,
            "Invalid domain 'bad' for label 'app'."
        )
        XCTAssertEqual(
            AppSignatureValidationError.duplicateLabel("dup").errorDescription,
            "Duplicate signature label: dup"
        )
    }

    private func makeTempURL() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("app-signatures-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("signatures.json")
    }

    private func cleanup(_ url: URL) {
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }
}
