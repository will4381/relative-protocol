// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
//
//  ExampleUITests.swift
//  ExampleUITests
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/23/2025.
//
//  Template UI tests for the sample application; customize as scenarios evolve.
//

import XCTest

final class ExampleUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testHomeScreenControlsAreVisible() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-testing"]
        app.launch()

        XCTAssertTrue(app.navigationBars["VPN Bridge"].exists)
        XCTAssertTrue(app.staticTexts["VPN Status"].exists)
        XCTAssertTrue(app.buttons["Connect"].exists)
        XCTAssertTrue(app.buttons["Disconnect"].exists)
        XCTAssertTrue(app.buttons["Refresh metrics"].exists)
        XCTAssertTrue(app.buttons["Clear local metrics"].exists)
    }

    @MainActor
    func testDisclosureAppearsOnFirstConnectTap() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-testing"]
        app.launch()

        app.buttons["Connect"].tap()

        XCTAssertTrue(app.staticTexts["Before you connect"].waitForExistence(timeout: 2))
        XCTAssertTrue(app.buttons["Continue"].exists)
        XCTAssertTrue(app.buttons["Not now"].exists)

        app.buttons["Not now"].tap()
        XCTAssertFalse(app.staticTexts["Before you connect"].exists)
    }

    @MainActor
    func testLaunchPerformance() throws {
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            let app = XCUIApplication()
            app.launchArguments = ["-ui-testing"]
            app.launch()
        }
    }
}
