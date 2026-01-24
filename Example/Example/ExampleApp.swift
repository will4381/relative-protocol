// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Foundation
import SwiftUI

@main
struct ExampleApp: App {
    @StateObject private var vpnManager = VPNManager()

    init() {
        if ProcessInfo.processInfo.arguments.contains("-ui-testing") {
            UserDefaults.standard.removeObject(forKey: "pre_use_disclosure_accepted")
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpnManager)
        }
    }
}
