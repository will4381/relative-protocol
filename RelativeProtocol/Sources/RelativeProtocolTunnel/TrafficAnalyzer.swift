//
//  TrafficAnalyzer.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 11/07/2025.
//
//  Bridges packet streams and event buses, redacting data as needed before
//  publishing analysis results.
//

import Foundation
import RelativeProtocolCore

/// Coordinates packet buffering and higher-level traffic analysis.
final class TrafficAnalyzer: @unchecked Sendable {
    struct Configuration: Sendable {
        var redactor: RelativeProtocol.TrafficRedactor?

        init(redactor: RelativeProtocol.TrafficRedactor? = nil) {
            self.redactor = redactor
        }
    }

    let stream: RelativeProtocol.PacketStream
    let eventBus: RelativeProtocol.TrafficEventBus?
    private let configuration: Configuration

    init(
        stream: RelativeProtocol.PacketStream,
        eventBus: RelativeProtocol.TrafficEventBus?,
        configuration: Configuration = .init()
    ) {
        self.stream = stream
        self.eventBus = eventBus
        self.configuration = configuration
    }

    func ingest(sample: RelativeProtocol.PacketSample) {
        stream.process(sample)
    }

    func publish(event: RelativeProtocol.TrafficEvent) {
        if let redactor = configuration.redactor {
            eventBus?.publish(redactor.sanitize(event: event))
        } else {
            eventBus?.publish(event)
        }
    }
}
