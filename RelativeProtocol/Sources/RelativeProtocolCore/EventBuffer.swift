//
//  EventBuffer.swift
//  RelativeProtocolCore
//
//  Created by Codex on 11/07/2025.
//

import Foundation
import Dispatch

public extension RelativeProtocol {
    /// Stores generated traffic events until the consumer is ready to flush.
    final class EventBuffer: @unchecked Sendable {
        public struct Configuration: Sendable {
            public var capacity: Int
            public var flushInterval: TimeInterval

            public init(capacity: Int = 50, flushInterval: TimeInterval = 10) {
                self.capacity = max(1, capacity)
                self.flushInterval = flushInterval > 0 ? max(0.001, flushInterval) : 0.001
            }
        }

        private let queue: DispatchQueue
        private let configuration: Configuration
        private var events: [TrafficEvent] = []
        private var lastFlush = Date()

        public init(
            label: String = "RelativeProtocol.EventBuffer",
            configuration: Configuration = .init()
        ) {
            self.queue = DispatchQueue(label: label)
            self.configuration = configuration
        }

        /// Appends an event to the buffer. Returns `true` when the buffer should
        /// be flushed because capacity or time thresholds have been met.
        @discardableResult
        public func append(_ event: TrafficEvent) -> Bool {
            var shouldFlush = false
            queue.sync {
                events.append(event)
                if events.count >= configuration.capacity {
                    shouldFlush = true
                } else {
                    shouldFlush = Date().timeIntervalSince(lastFlush) >= configuration.flushInterval
                }
            }
            return shouldFlush
        }

        /// Atomically drains the buffer and returns the collected events.
        public func drain() -> [TrafficEvent] {
            queue.sync {
                defer {
                    events.removeAll(keepingCapacity: true)
                    lastFlush = Date()
                }
                return events
            }
        }

        /// Returns the current buffered count.
        public func count() -> Int {
            queue.sync {
                events.count
            }
        }
    }
}
