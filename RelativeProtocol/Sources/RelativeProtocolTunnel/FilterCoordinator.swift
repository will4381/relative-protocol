//
//  FilterCoordinator.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 11/07/2025.
//
//  Coordinates traffic filters by collecting packet batches, running
//  evaluations, and buffering emitted events before publishing them.
//

import Foundation
import AsyncAlgorithms
import RelativeProtocolCore

/// Filters operate on buffered packet snapshots and emit normalized events.
public protocol TrafficFilter: Sendable {
    var identifier: String { get }
    func evaluate(snapshot: UnsafeBufferPointer<RelativeProtocol.PacketSample>, emit: @escaping @Sendable (RelativeProtocol.TrafficEvent) -> Void)
}

/// Configuration describing how frequently filters should evaluate buffered
/// packets and how events are staged before emission.
public struct FilterConfiguration: Sendable {
    public var evaluationInterval: TimeInterval
    public var eventBufferConfiguration: RelativeProtocol.EventBuffer.Configuration?

    public init(
        evaluationInterval: TimeInterval = 2,
        eventBufferConfiguration: RelativeProtocol.EventBuffer.Configuration? = .init()
    ) {
        self.evaluationInterval = evaluationInterval > 0 ? max(0.01, evaluationInterval) : 0.01
        self.eventBufferConfiguration = eventBufferConfiguration
    }
}

/// Orchestrates registered filters and forwards their outputs to the analyzer's
/// event bus, optionally buffering results to reduce churn.
public final class FilterCoordinator: @unchecked Sendable {
    private let analyzer: TrafficAnalyzer
    private let configuration: FilterConfiguration
    private let filtersQueue = DispatchQueue(label: "RelativeProtocolTunnel.FilterCoordinator.filters", attributes: .concurrent)
    private var filters: [TrafficFilter] = []
    private let eventBuffer: RelativeProtocol.EventBuffer?
    private var evaluationTask: Task<Void, Never>?

    init(analyzer: TrafficAnalyzer, configuration: FilterConfiguration = .init()) {
        self.analyzer = analyzer
        self.configuration = configuration
        if let bufferConfig = configuration.eventBufferConfiguration {
            self.eventBuffer = RelativeProtocol.EventBuffer(configuration: bufferConfig)
        } else {
            self.eventBuffer = nil
        }
        startEvaluationLoop()
    }

    deinit {
        evaluationTask?.cancel()
        flushBufferIfNeeded(force: true)
    }

    public func register(_ filter: TrafficFilter) {
        filtersQueue.async(flags: .barrier) { [weak self] in
            self?.filters.append(filter)
        }
    }

    public func removeAllFilters() {
        filtersQueue.async(flags: .barrier) { [weak self] in
            self?.filters.removeAll()
        }
    }

    public func flush() {
        flushBufferIfNeeded(force: true)
    }

    private func startEvaluationLoop() {
        evaluationTask?.cancel()
        let interval = configuration.evaluationInterval
        evaluationTask = Task { [weak self] in
            let duration = FilterCoordinator.makeDuration(interval: interval)
            let timer = AsyncTimerSequence(interval: duration, clock: ContinuousClock())
            for await _ in timer {
                if Task.isCancelled { break }
                guard let self else { break }
                await self.processTimerTick()
            }
        }
    }

    private static func makeDuration(interval: TimeInterval) -> Duration {
        let seconds = max(interval, 0)
        let nanosecondsDouble = seconds * 1_000_000_000
        let capped = min(Double(Int64.max), max(0, nanosecondsDouble))
        let nanoseconds = Int64(capped)
        return .nanoseconds(nanoseconds)
    }

    private func processTimerTick() async {
        await analyzer.stream.withSnapshot { [weak self] buffer in
            self?.evaluate(snapshot: buffer)
        }
    }

    private func evaluate(snapshot: UnsafeBufferPointer<RelativeProtocol.PacketSample>) {
        guard !snapshot.isEmpty else { return }
        let filters = filtersQueue.sync { self.filters }
        guard !filters.isEmpty else { return }
        for filter in filters {
            filter.evaluate(snapshot: snapshot) { [weak self] event in
                self?.handle(event: event)
            }
        }
        if let buffer = eventBuffer, buffer.count() > 0 {
            flushBufferIfNeeded(force: false)
        }
    }

    private func handle(event: RelativeProtocol.TrafficEvent) {
        if let buffer = eventBuffer {
            if buffer.append(event) {
                flushBufferIfNeeded(force: true)
            }
        } else {
            analyzer.publish(event: event)
        }
    }

    private func flushBufferIfNeeded(force: Bool) {
        guard let buffer = eventBuffer else { return }
        if force || buffer.count() >= configuration.eventBufferConfiguration?.capacity ?? 0 {
            let events = buffer.drain()
            events.forEach { analyzer.publish(event: $0) }
        }
    }
}
