// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import XCTest
import RelativeProtocolCore

final class AppSignatureStoreTests: XCTestCase {
    func testValidateEmptySignatures() {
        XCTAssertThrowsError(try AppSignatureStore.validate([])) { error in
            guard case AppSignatureValidationError.emptySignatures = error else {
                return XCTFail("Expected emptySignatures error")
            }
        }
    }

    func testValidateInvalidLabel() {
        let signatures = [AppSignature(label: "   ", domains: ["example.com"])]
        XCTAssertThrowsError(try AppSignatureStore.validate(signatures)) { error in
            guard case AppSignatureValidationError.invalidLabel = error else {
                return XCTFail("Expected invalidLabel error")
            }
        }
    }

    func testValidateInvalidDomain() {
        let signatures = [AppSignature(label: "social", domains: ["http://example.com"])]
        XCTAssertThrowsError(try AppSignatureStore.validate(signatures)) { error in
            guard case AppSignatureValidationError.invalidDomain = error else {
                return XCTFail("Expected invalidDomain error")
            }
        }
    }

    func testValidateDuplicateLabel() {
        let signatures = [
            AppSignature(label: "Social", domains: ["example.com"]),
            AppSignature(label: "social", domains: ["example.org"])
        ]
        XCTAssertThrowsError(try AppSignatureStore.validate(signatures)) { error in
            guard case AppSignatureValidationError.duplicateLabel = error else {
                return XCTFail("Expected duplicateLabel error")
            }
        }
    }

    func testValidateNormalizesDomains() throws {
        let signatures = [
            AppSignature(label: " Social ", domains: ["Example.COM", " example.com ", "cdn.example.com"])
        ]
        let validated = try AppSignatureStore.validate(signatures)
        XCTAssertEqual(validated.count, 1)
        XCTAssertEqual(validated[0].label, "Social")
        XCTAssertEqual(validated[0].domains, ["cdn.example.com", "example.com"])
    }
}
