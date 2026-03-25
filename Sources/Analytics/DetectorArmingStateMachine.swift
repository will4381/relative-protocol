import Foundation

/// Generic detector lifecycle state used to suppress cold-start, regime-change, and cooldown noise.
public enum DetectorArmingState: String, Sendable, Equatable {
    case coldStart
    case settling
    case armed
    case cooldown
    case suppressed
}

/// Generic timing policy for detector-owned arm/suppress/count state machines.
public struct DetectorArmingPolicy: Sendable, Equatable {
    public let settlingWindow: TimeInterval
    public let cooldownWindow: TimeInterval
    public let suppressionWindow: TimeInterval

    public init(
        settlingWindow: TimeInterval = 1.5,
        cooldownWindow: TimeInterval = 0.8,
        suppressionWindow: TimeInterval = 2
    ) {
        self.settlingWindow = max(0, settlingWindow)
        self.cooldownWindow = max(0, cooldownWindow)
        self.suppressionWindow = max(0, suppressionWindow)
    }
}

/// Lightweight helper for detectors that need a stable online arm/suppress/count gate without adding their own
/// bespoke timing state.
public struct DetectorArmingStateMachine: Sendable {
    public private(set) var state: DetectorArmingState

    private let policy: DetectorArmingPolicy
    private var stateEnteredAt: Date?
    private var firstSeenAt: Date?
    private var lastCountedAt: Date?

    public init(policy: DetectorArmingPolicy = DetectorArmingPolicy()) {
        self.policy = policy
        self.state = .coldStart
    }

    /// Advances the state machine on a new detector-facing sparse record.
    /// Decision: regime-change suppression is generic enough to share, but actual event-counting semantics remain
    /// detector-owned and call `markCounted(at:)` explicitly when a product event is confirmed.
    @discardableResult
    public mutating func observe(_ record: DetectorRecord) -> DetectorArmingState {
        let timestamp = record.timestamp
        if firstSeenAt == nil {
            firstSeenAt = timestamp
            transition(to: .settling, at: timestamp)
        }

        if record.pathChangedRecently == true {
            transition(to: .suppressed, at: timestamp)
            return state
        }

        switch state {
        case .coldStart:
            transition(to: .settling, at: timestamp)
        case .settling:
            if elapsedSinceStateEntry(at: timestamp) >= policy.settlingWindow {
                transition(to: .armed, at: timestamp)
            }
        case .cooldown:
            if elapsedSinceReference(lastCountedAt, at: timestamp) >= policy.cooldownWindow {
                transition(to: .armed, at: timestamp)
            }
        case .suppressed:
            if elapsedSinceStateEntry(at: timestamp) >= policy.suppressionWindow {
                transition(to: .settling, at: timestamp)
            }
        case .armed:
            break
        }

        return state
    }

    /// Marks a detector-owned product event as counted and enters cooldown.
    public mutating func markCounted(at timestamp: Date) {
        lastCountedAt = timestamp
        transition(to: .cooldown, at: timestamp)
    }

    /// Forces temporary suppression, typically when a detector identifies autonomous refill or launch noise.
    public mutating func suppress(at timestamp: Date) {
        transition(to: .suppressed, at: timestamp)
    }

    private mutating func transition(to nextState: DetectorArmingState, at timestamp: Date) {
        guard state != nextState else {
            return
        }
        state = nextState
        stateEnteredAt = timestamp
    }

    private func elapsedSinceStateEntry(at timestamp: Date) -> TimeInterval {
        elapsedSinceReference(stateEnteredAt, at: timestamp)
    }

    private func elapsedSinceReference(_ reference: Date?, at timestamp: Date) -> TimeInterval {
        guard let reference else {
            return .infinity
        }
        return timestamp.timeIntervalSince(reference)
    }
}
