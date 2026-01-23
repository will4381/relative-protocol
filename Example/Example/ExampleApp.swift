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
