//
//  TrafficShaper.swift
//  RelativeProtocolTunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Applies traffic shaping policies with minimal buffering by delaying packet
//  batches in place before forwarding them to the engine.
//

import Foundation
import RelativeProtocolCore

struct ShapingPolicy: Sendable {
    var fixedLatencyMilliseconds: Int
    var jitterMilliseconds: Int
    var bytesPerSecond: Int?

    init(fixedLatencyMilliseconds: Int, jitterMilliseconds: Int, bytesPerSecond: Int?) {
        self.fixedLatencyMilliseconds = max(0, fixedLatencyMilliseconds)
        self.jitterMilliseconds = max(0, jitterMilliseconds)
        if let bytesPerSecond, bytesPerSecond > 0 {
            self.bytesPerSecond = bytesPerSecond
        } else {
            self.bytesPerSecond = nil
        }
    }

    var isNoop: Bool {
        fixedLatencyMilliseconds == 0 &&
            jitterMilliseconds == 0 &&
            bytesPerSecond == nil
    }
}

struct PolicyKey: Hashable, Sendable {
    var host: String?
    var ip: String
    var port: UInt16?
    var protocolNumber: UInt8
}

struct TrafficShapingPolicyStore {
    private struct Rule {
        enum HostPattern: Hashable {
            case exact(String)
            case suffix(String)
            case contains(String)

            func matches(_ candidate: String) -> Bool {
                switch self {
                case .exact(let value):
                    return candidate == value
                case .suffix(let suffix):
                    return candidate == suffix || candidate.hasSuffix("." + suffix)
                case .contains(let fragment):
                    return candidate.contains(fragment)
                }
            }
        }

        var patterns: [HostPattern]
        var ports: Set<UInt16>?
        var policy: ShapingPolicy

        func matches(host: String?, ip: String, port: UInt16?) -> Bool {
            if let ports, let port {
                guard ports.contains(port) else { return false }
            }

            if let host, !host.isEmpty {
                let lowered = host.lowercased()
                for pattern in patterns {
                    if pattern.matches(lowered) {
                        return true
                    }
                }
            }

            let ipLowered = ip.lowercased()
            for pattern in patterns {
                if case .exact(let value) = pattern, value == ipLowered {
                    return true
                }
                if case .contains(let fragment) = pattern, ipLowered.contains(fragment) {
                    return true
                }
            }

            return false
        }
    }

    private let defaultPolicy: ShapingPolicy?
    private let rules: [Rule]

    init(configuration: RelativeProtocol.Configuration.TrafficShaping) {
        if let policy = configuration.defaultPolicy {
            let shaped = ShapingPolicy(
                fixedLatencyMilliseconds: policy.fixedLatencyMilliseconds,
                jitterMilliseconds: policy.jitterMilliseconds,
                bytesPerSecond: policy.bytesPerSecond
            )
            defaultPolicy = shaped.isNoop ? nil : shaped
        } else {
            defaultPolicy = nil
        }

        var compiled: [Rule] = []
        compiled.reserveCapacity(configuration.rules.count)
        for rule in configuration.rules {
            let policy = ShapingPolicy(
                fixedLatencyMilliseconds: rule.policy.fixedLatencyMilliseconds,
                jitterMilliseconds: rule.policy.jitterMilliseconds,
                bytesPerSecond: rule.policy.bytesPerSecond
            )
            guard !policy.isNoop else { continue }

            let normalizedHosts = rule.hosts
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { !$0.isEmpty }
            guard !normalizedHosts.isEmpty else { continue }

            var patterns: [Rule.HostPattern] = []
            patterns.reserveCapacity(normalizedHosts.count * 3)
            func appendUnique(_ pattern: Rule.HostPattern) {
                if !patterns.contains(pattern) {
                    patterns.append(pattern)
                }
            }
            for host in normalizedHosts {
                if host.hasPrefix("*.") {
                    let suffix = String(host.dropFirst(2))
                    guard !suffix.isEmpty else { continue }
                    appendUnique(.suffix(suffix))
                    appendUnique(.contains(suffix))
                } else if host.contains("*") {
                    let fragment = host.replacingOccurrences(of: "*", with: "")
                    guard !fragment.isEmpty else { continue }
                    appendUnique(.contains(fragment))
                } else {
                    appendUnique(.exact(host))
                    appendUnique(.suffix(host))
                    appendUnique(.contains(host))
                }
            }

            let filteredPorts = rule.ports
                .map { UInt16(clamping: $0) }
                .filter { $0 > 0 }
            let portsSet = filteredPorts.isEmpty ? nil : Set(filteredPorts)
            compiled.append(Rule(patterns: patterns, ports: portsSet, policy: policy))
        }
        rules = compiled
    }

    func policy(for key: PolicyKey) -> ShapingPolicy? {
        guard hasPolicies else {
            return nil
        }

        for rule in rules {
            if rule.matches(host: key.host, ip: key.ip, port: key.port) {
                return rule.policy
            }
        }

        return defaultPolicy
    }

    var hasPolicies: Bool {
        defaultPolicy != nil || !rules.isEmpty
    }
}

actor TrafficShaper {
    private let clock = ContinuousClock()
    private var reservations: [PolicyKey: ContinuousClock.Instant] = [:]
    private var cleanupTick = 0
    private let cleanupInterval = 64
    private let retentionWindow = ContinuousClock.Duration.seconds(5)
    private let maxReservations = 512

    func reserve(policy: ShapingPolicy, key: PolicyKey, packetBytes: Int) -> TimeInterval {
        guard !policy.isNoop else { return 0 }

        var releaseInstant = clock.now

        if policy.fixedLatencyMilliseconds > 0 {
            var latency = policy.fixedLatencyMilliseconds
            if policy.jitterMilliseconds > 0 {
                let range = (-policy.jitterMilliseconds)...policy.jitterMilliseconds
                latency = max(0, latency + Int.random(in: range))
            }
            releaseInstant += .milliseconds(latency)
        }

        if let rate = policy.bytesPerSecond, rate > 0 {
            let previous = reservations[key] ?? releaseInstant
            if releaseInstant < previous {
                releaseInstant = previous
            }
            let seconds = Double(packetBytes) / Double(rate)
            let nanos = seconds * 1_000_000_000.0
            let interval = ContinuousClock.Duration.nanoseconds(Int64(nanos.rounded(.up)))
            reservations[key] = releaseInstant + interval
        } else {
            if let previous = reservations[key], releaseInstant < previous {
                releaseInstant = previous
            }
            reservations[key] = releaseInstant
        }

        cleanupTick &+= 1
        if cleanupTick >= cleanupInterval {
            cleanupTick = 0
            pruneExpired()
        }

        let now = clock.now
        guard releaseInstant > now else { return 0 }
        let duration = releaseInstant - now
        let components = duration.components
        let seconds = Double(components.seconds)
        let attoseconds = Double(components.attoseconds) / 1_000_000_000_000_000_000.0
        let delay = seconds + attoseconds
        return max(0, delay)
    }

    private func pruneExpired() {
        let cutoff = clock.now - retentionWindow
        reservations = reservations.filter { _, instant in instant > cutoff }
        if reservations.count > maxReservations {
            var iterator = reservations.keys.makeIterator()
            var removals = reservations.count - maxReservations
            while removals > 0, let key = iterator.next() {
                reservations.removeValue(forKey: key)
                removals -= 1
            }
        }
    }
}
