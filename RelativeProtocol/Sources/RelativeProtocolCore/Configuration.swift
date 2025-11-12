//
//  Configuration.swift
//  RelativeProtocolCore
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Defines the public configuration and error surfaces used to drive the
//  Relative Protocol tunnel. These types are intentionally lightweight data
//  containers so they can be persisted and transported between the host app
//  and the Network Extension target.
//

import Foundation
import Dispatch

public enum RelativeProtocol {}

public extension RelativeProtocol {
    /// Errors surfaced by the RelativeProtocol package.
    enum PackageError: Swift.Error, Sendable {
        case invalidConfiguration([String])
        case networkSettingsFailed(String)
        case engineStartFailed(String)
    }
}

extension RelativeProtocol.PackageError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let issues):
            let description = issues.joined(separator: "; ")
            return "Invalid Relative Protocol configuration: \(description)."
        case .networkSettingsFailed(let message):
            return "Failed to apply Relative Protocol network settings: \(message)."
        case .engineStartFailed(let message):
            return "Unable to start Relative Protocol engine: \(message)."
        }
    }
}

public extension RelativeProtocol {
    /// Direction of packet travel through the virtual interface.
    enum Direction: String, Sendable {
        case inbound
        case outbound
    }

    /// Top-level configuration object consumed by both host apps and
    /// `NEPacketTunnelProvider` implementations.
    struct Configuration: Sendable {
        public var provider: Provider
        public var hooks: Hooks
        public var logging: LoggingOptions

        public init(
            provider: Provider = .default,
            hooks: Hooks = .init(),
            logging: LoggingOptions = .default
        ) {
            self.provider = provider
            self.hooks = hooks
            self.logging = logging
        }

        /// Canonical default configuration used when a host application has not
        /// supplied one.
        public static var `default`: Configuration {
            Configuration()
        }

        /// Validates the configuration and throws if any fatal errors are detected.
        @discardableResult
        public func validateOrThrow() throws -> [ValidationMessage] {
            let messages = provider.validate()
            let failures = messages.compactMap { message -> String? in
                if case let .error(description) = message { return description }
                return nil
            }
            if !failures.isEmpty {
                throw RelativeProtocol.PackageError.invalidConfiguration(failures)
            }
            return messages
        }

        /// Serialises the provider-facing configuration into the dictionary
        /// format expected by `NETunnelProviderProtocol.providerConfiguration`.
        public func providerConfigurationDictionary() -> [String: NSObject] {
            do {
                let payload = WirePayload(provider: provider, logging: logging)
                let data = try JSONEncoder().encode(payload)
                let object = try JSONSerialization.jsonObject(with: data)
                if let dictionary = object as? [String: AnyObject] {
                    return dictionary as NSDictionary as? [String: NSObject] ?? [:]
                }
            } catch {
                // Fall through and return an empty dictionary.
            }
            return [:]
        }

        /// Decodes a configuration payload supplied by the host application.
        public static func load(from providerConfiguration: [String: NSObject]?) -> Configuration {
            guard
                let providerConfiguration,
                JSONSerialization.isValidJSONObject(providerConfiguration),
                let data = try? JSONSerialization.data(withJSONObject: providerConfiguration)
            else {
                return Configuration()
            }
            do {
                let payload = try JSONDecoder().decode(WirePayload.self, from: data)
                return Configuration(provider: payload.provider, logging: payload.logging)
            } catch {
                if let provider = try? JSONDecoder().decode(Provider.self, from: data) {
                    return Configuration(provider: provider)
                }
                return Configuration()
            }
        }

        /// Returns `true` when the supplied host matches the configured block
        /// list rules.
        public func matchesBlockedHost(_ host: String) -> Bool {
            guard !provider.policies.blockedHosts.isEmpty else { return false }
            let matcher = BlockedHostMatcher.lookup(for: provider.policies.blockedHosts)
            return matcher.contains(host: host)
        }
    }

    private struct WirePayload: Codable {
        var provider: RelativeProtocol.Configuration.Provider
        var logging: RelativeProtocol.Configuration.LoggingOptions
    }
}

// MARK: - Configuration Models

public extension RelativeProtocol.Configuration {
    /// Concrete tunnel-facing options. Everything maps directly to Network
    /// Extension primitives such as MTU, IPv4 routes, and DNS settings.
    struct Provider: Codable, Equatable, Sendable {
        public var mtu: Int
        public var ipv4: IPv4
        public var ipv6: IPv6?
        public var includeAllNetworks: Bool = true
        public var excludeLocalNetworks: Bool = false
        public var excludeAPNs: Bool = false
        public var dns: DNS
        public var metrics: MetricsOptions
        public var policies: Policies
        public var memory: MemoryBudget

        public init(
            mtu: Int = 1500,
            ipv4: IPv4 = .default,
            ipv6: IPv6? = nil,
            includeAllNetworks: Bool = true,
            excludeLocalNetworks: Bool = false,
            excludeAPNs: Bool = false,
            dns: DNS = .default,
            metrics: MetricsOptions = .default,
            policies: Policies = .default,
            memory: MemoryBudget = .default
        ) {
            self.mtu = mtu
            self.ipv4 = ipv4
            self.ipv6 = ipv6
            self.includeAllNetworks = includeAllNetworks
            self.excludeLocalNetworks = excludeLocalNetworks
            self.excludeAPNs = excludeAPNs
            self.dns = dns
            self.metrics = metrics
            self.policies = policies
            self.memory = memory
        }

        public static var `default`: Provider {
            Provider()
        }

        /// Performs lightweight validation and returns warnings or errors that
        /// describe issues which might prevent the tunnel from starting.
        public func validate() -> [ValidationMessage] {
            var messages: [ValidationMessage] = []
            if !(576...9_000).contains(mtu) {
                messages.append(.warning("MTU \(mtu) is outside the recommended range (576-9000)."))
            }
            if !ipv4.address.isValidIPv4 {
                messages.append(.error("IPv4 address \(ipv4.address) is invalid."))
            }
            if !ipv4.subnetMask.isValidIPv4 {
                messages.append(.error("IPv4 subnet mask \(ipv4.subnetMask) is invalid."))
            }
            if !ipv4.remoteAddress.isValidIPv4 {
                messages.append(.error("Tunnel remote address \(ipv4.remoteAddress) is invalid."))
            }
            if dns.servers.isEmpty {
                messages.append(.warning("No DNS servers configured; system defaults will apply."))
            }
            if memory.packetPoolBytes <= 0 {
                messages.append(.error("Global packet pool must be greater than zero bytes."))
            }
            if memory.perFlowBytes <= 0 {
                messages.append(.error("Per-flow buffer limit must be greater than zero bytes."))
            }
            if memory.packetBatchLimit < 1 {
                messages.append(.error("Packet batch limit must be at least 1."))
            }
            if memory.maxConcurrentNetworkSends < 1 {
                messages.append(.error("Maximum concurrent network sends must be at least 1."))
            }
            return messages
        }
    }

    /// Tunnel interface addressing and optional static routes.
    struct IPv4: Codable, Equatable, Sendable {
        public var address: String
        public var subnetMask: String
        public var remoteAddress: String
        public var includedRoutes: [Route] = [.default]
        public var excludedRoutes: [Route] = []

        public init(
            address: String,
            subnetMask: String,
            remoteAddress: String,
            includedRoutes: [Route] = [.default],
            excludedRoutes: [Route] = []
        ) {
            self.address = address
            self.subnetMask = subnetMask
            self.remoteAddress = remoteAddress
            self.includedRoutes = includedRoutes
            self.excludedRoutes = excludedRoutes
        }

        public static var `default`: IPv4 {
            IPv4(
                address: "10.0.0.2",
                subnetMask: "255.255.255.0",
                remoteAddress: "198.51.100.1",
                includedRoutes: [.default],
                excludedRoutes: []
            )
        }
    }

    /// Description of a single IPv4 route to include inside the tunnel.
    struct Route: Codable, Equatable, Sendable {
        public var destinationAddress: String
        public var subnetMask: String

        public init(destinationAddress: String, subnetMask: String) {
            self.destinationAddress = destinationAddress
            self.subnetMask = subnetMask
        }

        public static var `default`: Route {
            Route(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0")
        }
    }

    struct IPv6: Codable, Equatable, Sendable {
        public var addresses: [String]
        public var networkPrefixLengths: [Int]
        public var includedRoutes: [IPv6Route]
        public var excludedRoutes: [IPv6Route]

        public init(
            addresses: [String],
            networkPrefixLengths: [Int],
            includedRoutes: [IPv6Route] = [.default],
            excludedRoutes: [IPv6Route] = []
        ) {
            self.addresses = addresses
            self.networkPrefixLengths = networkPrefixLengths
            self.includedRoutes = includedRoutes
            self.excludedRoutes = excludedRoutes
        }
    }

    struct IPv6Route: Codable, Equatable, Sendable {
        public var destinationAddress: String
        public var networkPrefixLength: Int

        public init(destinationAddress: String, networkPrefixLength: Int) {
            self.destinationAddress = destinationAddress
            self.networkPrefixLength = networkPrefixLength
        }

        public static var `default`: IPv6Route {
            IPv6Route(destinationAddress: "::", networkPrefixLength: 0)
        }
    }

    /// DNS resolver configuration applied to the virtual interface.
    struct DNS: Codable, Equatable, Sendable {
        public var servers: [String]
        public var searchDomains: [String]
        public var matchDomains: [String]

        public init(
            servers: [String],
            searchDomains: [String] = [],
            matchDomains: [String] = [""]
        ) {
            self.servers = servers
            self.searchDomains = searchDomains
            self.matchDomains = matchDomains
        }

        public static var `default`: DNS {
            DNS(servers: ["1.1.1.1", "8.8.8.8"])
        }
    }

    struct MetricsOptions: Codable, Equatable, Sendable {
        public var isEnabled: Bool
        public var reportingInterval: TimeInterval

        public init(isEnabled: Bool = true, reportingInterval: TimeInterval = 5.0) {
            self.isEnabled = isEnabled
            self.reportingInterval = reportingInterval
        }

        public static var `default`: MetricsOptions {
            MetricsOptions()
        }
    }

    struct MemoryBudget: Codable, Equatable, Sendable {
        public var packetPoolBytes: Int
        public var perFlowBytes: Int
        public var packetBatchLimit: Int
        public var maxConcurrentNetworkSends: Int

        public init(
            packetPoolBytes: Int = 8 * 1_048_576,
            perFlowBytes: Int = 128 * 1_024,
            packetBatchLimit: Int = 4,
            maxConcurrentNetworkSends: Int = 64
        ) {
            self.packetPoolBytes = packetPoolBytes
            self.perFlowBytes = perFlowBytes
            self.packetBatchLimit = packetBatchLimit
            self.maxConcurrentNetworkSends = maxConcurrentNetworkSends
        }

        public static var `default`: MemoryBudget {
            MemoryBudget()
        }
    }

    struct Policies: Codable, Equatable, Sendable {
        public var blockedHosts: [String]
        public var trafficShaping: TrafficShaping

        public init(
            blockedHosts: [String] = [],
            trafficShaping: TrafficShaping = .init()
        ) {
            self.blockedHosts = blockedHosts
            self.trafficShaping = trafficShaping
        }

        public static var `default`: Policies {
            Policies()
        }
    }

    struct TrafficShaping: Codable, Equatable, Sendable {
        public var defaultPolicy: TrafficShapingPolicy?
        public var rules: [TrafficShapingRule]

        public init(
            defaultPolicy: TrafficShapingPolicy? = nil,
            rules: [TrafficShapingRule] = []
        ) {
            self.defaultPolicy = defaultPolicy
            self.rules = rules
        }
    }

    struct TrafficShapingRule: Codable, Equatable, Sendable {
        public var hosts: [String]
        public var ports: [Int]
        public var policy: TrafficShapingPolicy

        public init(hosts: [String], ports: [Int] = [], policy: TrafficShapingPolicy) {
            self.hosts = hosts
            self.ports = ports
            self.policy = policy
        }
    }

    struct TrafficShapingPolicy: Codable, Equatable, Sendable {
        public var fixedLatencyMilliseconds: Int
        public var jitterMilliseconds: Int
        public var bytesPerSecond: Int?

        public init(
            fixedLatencyMilliseconds: Int = 0,
            jitterMilliseconds: Int = 0,
            bytesPerSecond: Int? = nil
        ) {
            self.fixedLatencyMilliseconds = max(0, fixedLatencyMilliseconds)
            self.jitterMilliseconds = max(0, jitterMilliseconds)
            if let bytesPerSecond, bytesPerSecond > 0 {
                self.bytesPerSecond = bytesPerSecond
            } else {
                self.bytesPerSecond = nil
            }
        }

        public var isNoop: Bool {
            fixedLatencyMilliseconds == 0 &&
                jitterMilliseconds == 0 &&
                bytesPerSecond == nil
        }
    }

    enum ValidationMessage: Sendable {
        case warning(String)
        case error(String)
    }

    struct LoggingOptions: Codable, Equatable, Sendable {
        public struct Breadcrumbs: OptionSet, Codable, Sendable {
            public let rawValue: UInt32

            public init(rawValue: UInt32) {
                self.rawValue = rawValue
            }

            public init(from decoder: Decoder) throws {
                let container = try decoder.singleValueContainer()
                let value = try container.decode(UInt32.self)
                self.init(rawValue: value)
            }

            public func encode(to encoder: Encoder) throws {
                var container = encoder.singleValueContainer()
                try container.encode(rawValue)
            }

            public static let device = Breadcrumbs(rawValue: 0b0000_0001)
            public static let flow = Breadcrumbs(rawValue: 0b0000_0010)
            public static let dns = Breadcrumbs(rawValue: 0b0000_0100)
            public static let metrics = Breadcrumbs(rawValue: 0b0000_1000)
            public static let ffi = Breadcrumbs(rawValue: 0b0001_0000)
            public static let poll = Breadcrumbs(rawValue: 0b0010_0000)
            public static let all = Breadcrumbs(rawValue: .max)
        }

        public var enableDebug: Bool
        public var breadcrumbs: Breadcrumbs

        public init(
            enableDebug: Bool = false,
            breadcrumbs: Breadcrumbs = []
        ) {
            self.enableDebug = enableDebug
            self.breadcrumbs = breadcrumbs
        }

        public static let `default` = LoggingOptions()
    }
}

public extension RelativeProtocol.Configuration.ValidationMessage {
    var message: String {
        switch self {
        case .warning(let text), .error(let text):
            return text
        }
    }

    var isError: Bool {
        if case .error = self { return true }
        return false
    }

    var severityLabel: String {
        switch self {
        case .warning:
            return "warning"
        case .error:
            return "error"
        }
    }
}

public extension RelativeProtocol {
    struct MetricsSnapshot: Sendable {
        public struct Counter: Sendable {
            public var packets: Int
            public var bytes: Int

            public init(packets: Int, bytes: Int) {
                self.packets = packets
                self.bytes = bytes
            }
        }

        public struct ErrorEvent: Sendable {
            public var message: String
            public var timestamp: Date

            public init(message: String, timestamp: Date = Date()) {
                self.message = message
                self.timestamp = timestamp
            }
        }

        public var timestamp: Date
        public var inbound: Counter
        public var outbound: Counter
        public var activeTCP: Int
        public var activeUDP: Int
        public var errors: [ErrorEvent]
        public var flow: FlowMetrics?

        public struct FlowMetrics: Sendable {
            public struct Counters: Sendable {
                public var tcpAdmissionFail: UInt64
                public var udpAdmissionFail: UInt64
                public var tcpBackpressureDrops: UInt64
                public var udpBackpressureDrops: UInt64

                public init(
                    tcpAdmissionFail: UInt64,
                    udpAdmissionFail: UInt64,
                    tcpBackpressureDrops: UInt64,
                    udpBackpressureDrops: UInt64
                ) {
                    self.tcpAdmissionFail = tcpAdmissionFail
                    self.udpAdmissionFail = udpAdmissionFail
                    self.tcpBackpressureDrops = tcpBackpressureDrops
                    self.udpBackpressureDrops = udpBackpressureDrops
                }
            }

            public struct Stats: Sendable {
                public var pollIterations: UInt64
                public var framesEmitted: UInt64
                public var bytesEmitted: UInt64
                public var tcpFlushEvents: UInt64
                public var udpFlushEvents: UInt64

                public init(
                    pollIterations: UInt64,
                    framesEmitted: UInt64,
                    bytesEmitted: UInt64,
                    tcpFlushEvents: UInt64,
                    udpFlushEvents: UInt64
                ) {
                    self.pollIterations = pollIterations
                    self.framesEmitted = framesEmitted
                    self.bytesEmitted = bytesEmitted
                    self.tcpFlushEvents = tcpFlushEvents
                    self.udpFlushEvents = udpFlushEvents
                }
            }

            public var counters: Counters
            public var stats: Stats

            public init(counters: Counters, stats: Stats) {
                self.counters = counters
                self.stats = stats
            }
        }

        public init(
            timestamp: Date,
            inbound: Counter,
            outbound: Counter,
            activeTCP: Int,
            activeUDP: Int,
            errors: [ErrorEvent],
            flow: FlowMetrics? = nil
        ) {
            self.timestamp = timestamp
            self.inbound = inbound
            self.outbound = outbound
            self.activeTCP = activeTCP
            self.activeUDP = activeUDP
            self.errors = errors
            self.flow = flow
        }
    }
}

// MARK: - Hooks & Runtime Extensions

public extension RelativeProtocol.Configuration {
    /// Aggregates optional closures that allow the host to observe or
    /// influence runtime behaviour without subclassing package types.
    struct Hooks: Sendable {
        public var packetTap: PacketTap?
        public var packetStreamBuilder: PacketStreamBuilder?
        public var trafficEventBusBuilder: TrafficEventBusBuilder?
        public var dnsResolver: DNSResolver?
        public var connectionPolicy: ConnectionPolicy?
        public var eventSink: EventSink?

        public init(
            packetTap: PacketTap? = nil,
            packetStreamBuilder: PacketStreamBuilder? = nil,
            trafficEventBusBuilder: TrafficEventBusBuilder? = nil,
            dnsResolver: DNSResolver? = nil,
            connectionPolicy: ConnectionPolicy? = nil,
            eventSink: EventSink? = nil
        ) {
            self.packetTap = packetTap
            self.packetStreamBuilder = packetStreamBuilder
            self.trafficEventBusBuilder = trafficEventBusBuilder
            self.dnsResolver = dnsResolver
            self.connectionPolicy = connectionPolicy
            self.eventSink = eventSink
        }
    }

    /// Metadata accompanying packets delivered to the packet tap hook.
    struct PacketContext: Sendable {
        public var direction: RelativeProtocol.Direction
        public var payload: Data
        public var protocolNumber: Int32

        public init(direction: RelativeProtocol.Direction, payload: Data, protocolNumber: Int32) {
            self.direction = direction
            self.payload = payload
            self.protocolNumber = protocolNumber
        }
    }

    /// Describes a remote endpoint the engine intends to contact.
    struct Endpoint: Sendable {
        public enum Transport: String, Sendable {
            case tcp
            case udp
        }

        public var host: String
        public var port: Int
        public var transport: Transport

        public init(host: String, port: Int, transport: Transport) {
            self.host = host
            self.port = port
            self.transport = transport
        }
    }

    /// Policy decision returned by a connection policy hook.
    enum ConnectionDecision: Sendable {
        case allow
        case block(reason: String?)
        case deferToDefault
    }

    /// Lifecycle events surfaced to the host through the event sink hook.
    enum Event: Sendable {
        case willStart
        case didStart
        case didStop
        case didFail(String)
    }

    /// Invoked whenever packets traverse the tunnel in either direction.
    typealias PacketTap = @Sendable (_ context: PacketContext) -> Void
    /// Produces a per-session packet stream pipeline used to apply reusable
    /// filters inside the tunnel.
    typealias PacketStreamBuilder = @Sendable () -> RelativeProtocol.PacketStream?
    /// Produces a traffic event bus that receives normalized events from the
    /// detection pipeline.
    typealias TrafficEventBusBuilder = @Sendable () -> RelativeProtocol.TrafficEventBus?
    /// Resolves hostnames prior to establishing outbound connections.
    typealias DNSResolver = @Sendable (_ host: String) async throws -> [String]
    /// Determines whether an outbound connection should proceed, be blocked,
    /// or fall back to default handling.
    typealias ConnectionPolicy = @Sendable (_ endpoint: Endpoint) async -> ConnectionDecision
    /// Receives lifecycle events as the tunnel transitions between states.
    typealias EventSink = @Sendable (_ event: Event) -> Void
}

// MARK: - Helpers

private extension String {
    var isValidIPv4: Bool {
        let parts = split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { segment in
            guard let value = UInt8(segment) else { return false }
            return segment == "\(value)"
        }
    }
}

// MARK: - Blocked host matcher cache

private enum BlockedHostMatcher {
    private static let queue = DispatchQueue(label: "RelativeProtocolCore.BlockedHostMatcher", attributes: .concurrent)
    private static var cache: [BlockedHostCacheKey: Lookup] = [:]

    struct Lookup {
        private let patterns: Set<String>

        init(patterns: Set<String>) {
            self.patterns = patterns
        }

        func contains(host: String) -> Bool {
            guard !patterns.isEmpty else { return false }
            var normalized = host
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "."))
                .lowercased()
            if patterns.contains(normalized) {
                return true
            }
            while let separator = normalized.firstIndex(of: ".") {
                normalized = String(normalized[normalized.index(after: separator)...])
                if patterns.contains(normalized) {
                    return true
                }
            }
            return false
        }
    }

    static func lookup(for hosts: [String]) -> Lookup {
        guard !hosts.isEmpty else { return Lookup(patterns: []) }
        let key = BlockedHostCacheKey(hosts: hosts)

        var cached: Lookup?
        queue.sync {
            cached = cache[key]
        }
        if let cached {
            return cached
        }

        let normalized = Set(
            hosts.compactMap { host -> String? in
                let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    .lowercased()
                return trimmed.isEmpty ? nil : trimmed
            }
        )
        let lookup = Lookup(patterns: normalized)

        queue.async(flags: .barrier) {
            cache[key] = lookup
        }
        return lookup
    }
}

private struct BlockedHostCacheKey: Hashable {
    private let hosts: [String]
    private let cachedHash: Int

    init(hosts: [String]) {
        self.hosts = hosts
        var hasher = Hasher()
        hasher.combine(hosts.count)
        for host in hosts {
            hasher.combine(host)
        }
        cachedHash = hasher.finalize()
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(cachedHash)
    }

    static func == (lhs: BlockedHostCacheKey, rhs: BlockedHostCacheKey) -> Bool {
        lhs.cachedHash == rhs.cachedHash && lhs.hosts == rhs.hosts
    }
}

// MARK: - Equatable

extension RelativeProtocol.Configuration: Equatable {
    public static func == (lhs: RelativeProtocol.Configuration, rhs: RelativeProtocol.Configuration) -> Bool {
        lhs.provider == rhs.provider && lhs.logging == rhs.logging
    }
}
