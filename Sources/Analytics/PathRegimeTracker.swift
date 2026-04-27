import Foundation
import Network

internal struct PathRegimeSnapshot: Sendable, Equatable {
    let epoch: UInt32
    let interfaceClass: PathInterfaceClass
    let isExpensive: Bool
    let isConstrained: Bool
    let supportsDNS: Bool
    let changedAt: Date?

    static let unavailable = PathRegimeSnapshot(
        epoch: 0,
        interfaceClass: .unavailable,
        isExpensive: false,
        isConstrained: false,
        supportsDNS: false,
        changedAt: nil
    )

    func changedRecently(at now: Date, window: TimeInterval = 2) -> Bool {
        guard let changedAt else {
            return false
        }
        return now.timeIntervalSince(changedAt) <= window
    }
}

internal protocol PathRegimeProvider: Sendable {
    var currentSnapshot: PathRegimeSnapshot { get }
    func stop()
}

/// `NWPathMonitor` is the Apple-supported way to react to path changes without leaving the packet-tunnel model.
/// Docs: https://developer.apple.com/documentation/network/nwpathmonitor
/// Docs: https://developer.apple.com/documentation/network/nwpath/usesinterfacetype(_:)
internal final class NWPathRegimeMonitor: PathRegimeProvider, @unchecked Sendable {
    private struct Signature: Equatable {
        let interfaceClass: PathInterfaceClass
        let isExpensive: Bool
        let isConstrained: Bool
        let supportsDNS: Bool
    }

    private let monitor: NWPathMonitor
    private let queue = DispatchQueue(label: "com.relativecompanies.vpnbridge.analytics.path-regime", qos: .utility)
    private let lock = NSLock()
    private var snapshot = PathRegimeSnapshot.unavailable
    private var lastSignature: Signature?

    init() {
        self.monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            self?.handle(path: path)
        }
        monitor.start(queue: queue)
    }

    deinit {
        monitor.cancel()
    }

    var currentSnapshot: PathRegimeSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshot
    }

    func stop() {
        monitor.cancel()
    }

    private func handle(path: NWPath) {
        let signature = Signature(
            interfaceClass: Self.interfaceClass(for: path),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            supportsDNS: path.supportsDNS
        )
        let now = Date()

        lock.lock()
        if signature != lastSignature {
            snapshot = PathRegimeSnapshot(
                epoch: snapshot.epoch &+ 1,
                interfaceClass: signature.interfaceClass,
                isExpensive: signature.isExpensive,
                isConstrained: signature.isConstrained,
                supportsDNS: signature.supportsDNS,
                changedAt: now
            )
            lastSignature = signature
        } else if snapshot.changedAt == nil {
            snapshot = PathRegimeSnapshot(
                epoch: snapshot.epoch,
                interfaceClass: signature.interfaceClass,
                isExpensive: signature.isExpensive,
                isConstrained: signature.isConstrained,
                supportsDNS: signature.supportsDNS,
                changedAt: now
            )
        }
        lock.unlock()
    }

    private static func interfaceClass(for path: NWPath) -> PathInterfaceClass {
        guard path.status == .satisfied else {
            return .unavailable
        }

        var classes: [PathInterfaceClass] = []
        if path.usesInterfaceType(.wifi) {
            classes.append(.wifi)
        }
        if path.usesInterfaceType(.cellular) {
            classes.append(.cellular)
        }
        if path.usesInterfaceType(.wiredEthernet) {
            classes.append(.wiredEthernet)
        }
        if path.usesInterfaceType(.loopback) {
            classes.append(.loopback)
        }
        if classes.isEmpty {
            return .other
        }
        if classes.count == 1 {
            return classes[0]
        }
        return .mixed
    }
}
