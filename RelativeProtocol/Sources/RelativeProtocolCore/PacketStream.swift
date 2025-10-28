//
//  PacketStream.swift
//  RelativeProtocolCore
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 11/07/2025.
//
//  Serialises packet samples into time-based buffers for downstream analysis
//  via stages and batch observers.
//

import Foundation
import Dispatch

public extension RelativeProtocol {
    /// Lightweight packet metadata forwarded into filtering pipelines.
    struct PacketSample: Sendable {
        public var timestamp: Date
        public var direction: RelativeProtocol.Direction
        public var payload: Data
        public var protocolNumber: Int32
        public var byteCount: Int

        public init(
            timestamp: Date = Date(),
            direction: RelativeProtocol.Direction,
            payload: Data,
            protocolNumber: Int32,
            byteCount: Int? = nil
        ) {
            self.timestamp = timestamp
            self.direction = direction
            self.payload = payload
            self.protocolNumber = protocolNumber
            self.byteCount = byteCount ?? payload.count
        }
    }

    /// Serial pipeline that buffers packet samples for later batch analysis.
    final class PacketStream: @unchecked Sendable {
        public struct Configuration: Sendable {
            public static let minDuration: TimeInterval = 30
            public static let maxDuration: TimeInterval = 600

            public var bufferDuration: TimeInterval
            public var snapshotQueue: DispatchQueue?

            public init(bufferDuration: TimeInterval = 120, snapshotQueue: DispatchQueue? = nil) {
                self.bufferDuration = max(Self.minDuration, min(bufferDuration, Self.maxDuration))
                self.snapshotQueue = snapshotQueue
            }

            public static var `default`: Configuration { Configuration() }
        }

        public struct Stage: Sendable {
            public var name: String
            public var predicate: (@Sendable (_ sample: PacketSample) -> Bool)?
            public var handler: @Sendable (_ sample: PacketSample) -> Void

            public init(
                name: String,
                predicate: (@Sendable (_ sample: PacketSample) -> Bool)? = nil,
                handler: @escaping @Sendable (_ sample: PacketSample) -> Void
            ) {
                self.name = name
                self.predicate = predicate
                self.handler = handler
            }
        }

        public struct BatchObserver: Sendable {
            public var name: String
            public var interval: TimeInterval
            public var handler: @Sendable (_ samples: [PacketSample]) -> Void

            public init(
                name: String,
                interval: TimeInterval,
                handler: @escaping @Sendable (_ samples: [PacketSample]) -> Void
            ) {
                self.name = name
                self.interval = interval > 0 ? max(0.01, interval) : 0.01
                self.handler = handler
            }
        }

        private let queue: DispatchQueue
        private let configuration: Configuration
        private var samples: [PacketSample] = []
        private var headIndex: Int = 0
        private var stages: [Stage] = []
        private var batchObservers: [BatchObserver] = []
        private var lastBatchFire: [String: Date] = [:]

        public init(
            label: String = "RelativeProtocol.PacketStream",
            configuration: Configuration = .default
        ) {
            self.queue = DispatchQueue(label: label)
            self.configuration = configuration
        }

        public func addStage(_ stage: Stage) {
            queue.async { [weak self] in
                self?.stages.append(stage)
            }
        }

        public func addBatchObserver(_ observer: BatchObserver) {
            queue.async { [weak self] in
                guard let self else { return }
                batchObservers.append(observer)
                lastBatchFire[observer.name] = Date()
            }
        }

        public func process(_ sample: PacketSample) {
            queue.async { [weak self] in
                guard let self else { return }
                let processingTime = Date()
                self.samples.append(sample)
                self.purgeExpiredSamples(olderThan: sample.timestamp)
                for stage in self.stages {
                    guard stage.predicate?(sample) ?? true else { continue }
                    stage.handler(sample)
                }
                self.evaluateBatchObservers(currentTime: max(processingTime, sample.timestamp))
            }
        }

        /// Returns a snapshot of the buffered samples. The snapshot is produced
        /// on the stream's serial queue and delivered on `configuration.snapshotQueue`
        /// if provided, otherwise on the caller's queue.
        public func snapshot(_ completion: @escaping @Sendable ([PacketSample]) -> Void) {
            queue.async { [weak self] in
                guard let self else {
                    completion([])
                    return
                }
                let buffer = self.currentSamples()
                if let queue = self.configuration.snapshotQueue {
                    queue.async {
                        completion(buffer)
                    }
                } else {
                    completion(buffer)
                }
            }
        }

        private func purgeExpiredSamples(olderThan timestamp: Date) {
            let cutoff = timestamp.addingTimeInterval(-configuration.bufferDuration)
            while headIndex < samples.count {
                if samples[headIndex].timestamp >= cutoff {
                    break
                }
                headIndex += 1
            }
            if headIndex > 0 && headIndex * 2 >= samples.count {
                samples.removeFirst(headIndex)
                headIndex = 0
            }
        }

        private func currentSamples() -> [PacketSample] {
            guard headIndex < samples.count else { return [] }
            return Array(samples[headIndex...])
        }

        private func evaluateBatchObservers(currentTime: Date) {
            let buffer = currentSamples()
            guard !buffer.isEmpty else { return }
            for observer in batchObservers {
                let lastFire = lastBatchFire[observer.name] ?? .distantPast
                guard currentTime.timeIntervalSince(lastFire) >= observer.interval else { continue }
                lastBatchFire[observer.name] = currentTime
                if let queue = configuration.snapshotQueue {
                    queue.async {
                        observer.handler(buffer)
                    }
                } else {
                    observer.handler(buffer)
                }
            }
        }
    }
}
