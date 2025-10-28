//
//  TrafficEventBus.swift
//  RelativeProtocolCore
//
//  Created by Codex on 11/07/2025.
//

import Foundation

public extension RelativeProtocol {
    /// Token returned when registering a listener with `TrafficEventBus`.
    struct TrafficListenerToken: Hashable, Sendable {
        fileprivate let identifier: UUID

        public init() {
            self.identifier = UUID()
        }
    }

    /// Dispatches traffic events to registered listeners on a dedicated queue.
    final class TrafficEventBus: @unchecked Sendable {
        public typealias Listener = @Sendable (_ event: TrafficEvent) -> Void

        private let queue: DispatchQueue
        private var listeners: [UUID: Listener] = [:]
        private let redactor: TrafficRedactor?

        public init(
            label: String = "RelativeProtocol.TrafficEventBus",
            qos: DispatchQoS = .utility,
            redactor: TrafficRedactor? = nil
        ) {
            self.queue = DispatchQueue(label: label, qos: qos)
            self.redactor = redactor
        }

        /// Registers a listener that will receive events serialized on the bus
        /// queue. Returns a token that must be used to remove the listener.
        @discardableResult
        public func addListener(_ listener: @escaping Listener) -> TrafficListenerToken {
            let token = TrafficListenerToken()
            queue.async { [weak self] in
                self?.listeners[token.identifier] = listener
            }
            return token
        }

        /// Unregisters a previously added listener.
        public func removeListener(_ token: TrafficListenerToken) {
            queue.async { [weak self] in
                self?.listeners.removeValue(forKey: token.identifier)
            }
        }

        /// Publishes an event to all registered listeners.
        public func publish(_ event: TrafficEvent) {
            queue.async { [weak self] in
                guard let self else { return }
                let sanitized = self.redactor?.sanitize(event: event) ?? event
                for listener in self.listeners.values {
                    listener(sanitized)
                }
            }
        }
    }
}
