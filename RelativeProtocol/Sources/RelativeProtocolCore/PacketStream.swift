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
        private static let nanosPerSecond = 1_000_000_000.0

        private var timestampTicks: UInt64
        public var direction: RelativeProtocol.Direction
        public var protocolNumber: Int32
        public var byteCount: Int
        public var metadata: PacketMetadata?

        @available(*, deprecated, message: "Packet payloads are no longer retained to minimize memory usage.")
        public var payload: Data {
            get { Data() }
            set { _ = newValue }
        }

        public var timestamp: Date {
            get {
                Date(timeIntervalSinceReferenceDate: TimeInterval(timestampTicks) / Self.nanosPerSecond)
            }
            set {
                timestampTicks = Self.ticks(for: newValue)
            }
        }

        public init(
            timestamp: Date = Date(),
            direction: RelativeProtocol.Direction,
            protocolNumber: Int32,
            byteCount: Int,
            metadata: PacketMetadata? = nil
        ) {
            self.timestampTicks = Self.ticks(for: timestamp)
            self.direction = direction
            self.protocolNumber = protocolNumber
            self.byteCount = byteCount
            self.metadata = metadata
        }

        public init(
            timestamp: Date = Date(),
            direction: RelativeProtocol.Direction,
            payload: Data,
            protocolNumber: Int32,
            byteCount: Int? = nil,
            metadata: PacketMetadata? = nil
        ) {
            let resolvedMetadata = metadata ?? PacketMetadataParser.parse(packet: payload, hintProtocolNumber: protocolNumber)
            self.init(
                timestamp: timestamp,
                direction: direction,
                protocolNumber: protocolNumber,
                byteCount: byteCount ?? payload.count,
                metadata: resolvedMetadata
            )
        }

        @available(*, deprecated, message: "Payloads are not retained; this method now returns the sample unchanged.")
        public func discardingPayload() -> PacketSample {
            self
        }

        private static func ticks(for date: Date) -> UInt64 {
            let interval = date.timeIntervalSinceReferenceDate
            if interval <= 0 {
                return 0
            }
            let nanos = interval * Self.nanosPerSecond
            if nanos >= Double(UInt64.max) {
                return UInt64.max
            }
            return UInt64(nanos)
        }
    }

    /// Serial pipeline that buffers packet samples for later batch analysis.
    final class PacketStream: @unchecked Sendable {
        public struct Configuration: Sendable {
            public static let minDuration: TimeInterval = 5
            public static let maxDuration: TimeInterval = 600

            public var bufferDuration: TimeInterval
            public var snapshotQueue: DispatchQueue?
            public var maxSampleCount: Int

            public init(
                bufferDuration: TimeInterval = 60,
                snapshotQueue: DispatchQueue? = nil,
                maxSampleCount: Int = PacketStream.defaultMaxSampleCount
            ) {
                self.bufferDuration = max(Self.minDuration, min(bufferDuration, Self.maxDuration))
                self.snapshotQueue = snapshotQueue
                self.maxSampleCount = max(1, maxSampleCount)
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

        private struct RingBuffer {
            private var storage: ContiguousArray<PacketSample> = []
            private var start: Int = 0
            private var count: Int = 0
            private let capacity: Int

            init(capacity: Int) {
                self.capacity = max(1, capacity)
                storage.reserveCapacity(self.capacity)
            }

            mutating func append(_ sample: PacketSample) {
                guard capacity > 0 else { return }
                if storage.count < capacity {
                    storage.append(sample)
                    count += 1
                    return
                }
                let endIndex = (start + count) % capacity
                storage[endIndex] = sample
                if count < capacity {
                    count += 1
                } else {
                    start = (start + 1) % capacity
                }
            }

            mutating func removeFirst() {
                guard count > 0 else { return }
                start = (start + 1) % capacity
                count -= 1
                if count == 0 {
                    start = 0
                }
            }

            var first: PacketSample? {
                guard count > 0 else { return nil }
                return storage[start]
            }

            var isEmpty: Bool { count == 0 }

            func toArray() -> [PacketSample] {
                guard count > 0 else { return [] }
                var result: [PacketSample] = []
                result.reserveCapacity(count)
                if start + count <= storage.count {
                    result.append(contentsOf: storage[start..<(start + count)])
                } else {
                    let firstChunk = storage[start..<storage.count]
                    result.append(contentsOf: firstChunk)
                    let remaining = count - firstChunk.count
                    if remaining > 0 {
                        result.append(contentsOf: storage[0..<remaining])
                    }
                }
                return result
            }

            func withUnsafeBufferPointer<R>(_ body: (UnsafeBufferPointer<PacketSample>) -> R) -> R {
                guard count > 0 else {
                    return ContiguousArray<PacketSample>().withUnsafeBufferPointer(body)
                }
                if start == 0 && count == storage.count {
                    return storage.withUnsafeBufferPointer { buffer in
                        let slice = UnsafeBufferPointer(rebasing: buffer[..<count])
                        return body(slice)
                    }
                }
                if start + count <= storage.count {
                    return storage.withUnsafeBufferPointer { buffer in
                        let slice = UnsafeBufferPointer(rebasing: buffer[start..<(start + count)])
                        return body(slice)
                    }
                }
                var scratch = ContiguousArray<PacketSample>()
                scratch.reserveCapacity(count)
                let firstChunk = storage[start..<storage.count]
                scratch.append(contentsOf: firstChunk)
                let remaining = count - firstChunk.count
                if remaining > 0 {
                    scratch.append(contentsOf: storage[0..<remaining])
                }
                return scratch.withUnsafeBufferPointer(body)
            }
        }

        private let queue: DispatchQueue
        public static let defaultMaxSampleCount = 8_000

        private let configuration: Configuration
        private var samples: RingBuffer
        private var stages: [Stage] = []
        private var batchObservers: [BatchObserver] = []
        private var lastBatchFire: [String: Date] = [:]

        public init(
            label: String = "RelativeProtocol.PacketStream",
            configuration: Configuration = .default
        ) {
            self.queue = DispatchQueue(label: label)
            self.configuration = configuration
            self.samples = RingBuffer(capacity: configuration.maxSampleCount)
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
            awaitSnapshot({ Array($0) }, completion: completion)
        }

        public func snapshot() async -> [PacketSample] {
            await withSnapshot { Array($0) }
        }

        public func withSnapshot<R>(_ body: @escaping @Sendable (UnsafeBufferPointer<PacketSample>) -> R) async -> R {
            await withCheckedContinuation { continuation in
                awaitSnapshot(body) { result in
                    continuation.resume(returning: result)
                }
            }
        }

        private func purgeExpiredSamples(olderThan timestamp: Date) {
            let cutoff = timestamp.addingTimeInterval(-configuration.bufferDuration)
            while let first = samples.first, first.timestamp < cutoff {
                samples.removeFirst()
            }
        }

        private func evaluateBatchObservers(currentTime: Date) {
            guard !samples.isEmpty else { return }
            let buffer = samples.toArray()
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

        private func awaitSnapshot<R>(
            _ body: @escaping @Sendable (UnsafeBufferPointer<PacketSample>) -> R,
            completion: @escaping (R) -> Void
        ) {
            queue.async { [weak self] in
                guard let self else {
                    let empty = UnsafeBufferPointer<PacketSample>(start: nil, count: 0)
                    completion(body(empty))
                    return
                }
                let result: R = self.samples.withUnsafeBufferPointer { buffer in
                    self.invokeSnapshotBody(buffer: buffer, body: body)
                }
                if let queue = self.configuration.snapshotQueue, queue !== self.queue {
                    queue.async {
                        completion(result)
                    }
                } else {
                    completion(result)
                }
            }
        }

        private func invokeSnapshotBody<R>(
            buffer: UnsafeBufferPointer<PacketSample>,
            body: @Sendable (UnsafeBufferPointer<PacketSample>) -> R
        ) -> R {
            if let queue = configuration.snapshotQueue, queue !== self.queue {
                var output: R!
                queue.sync {
                    output = body(buffer)
                }
                return output
            }
            return body(buffer)
        }
    }
}
