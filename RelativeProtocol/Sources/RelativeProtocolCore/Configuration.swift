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
import os.lock

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
        private let providerConfigurationCache = ProviderConfigurationCacheBox()

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
            providerConfigurationCache.dictionary(provider: provider, logging: logging) {
                buildProviderConfigurationDictionary()
            }
        }

        private func buildProviderConfigurationDictionary() -> [String: NSObject] {
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
            provider.policies.containsBlockedHost(host)
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
        public var dns: DNS
        public var metrics: MetricsOptions
        public var policies: Policies

        public init(
            mtu: Int = 1500,
            ipv4: IPv4 = .default,
            dns: DNS = .default,
            metrics: MetricsOptions = .default,
            policies: Policies = .default
        ) {
            self.mtu = mtu
            self.ipv4 = ipv4
            self.dns = dns
            self.metrics = metrics
            self.policies = policies
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
            return messages
        }
    }

    /// Tunnel interface addressing and optional static routes.
    struct IPv4: Codable, Equatable, Sendable {
        public var address: String
        public var subnetMask: String
        public var remoteAddress: String
        public var includedRoutes: [Route]

        public init(
            address: String,
            subnetMask: String,
            remoteAddress: String,
            includedRoutes: [Route] = [.default]
        ) {
            self.address = address
            self.subnetMask = subnetMask
            self.remoteAddress = remoteAddress
            self.includedRoutes = includedRoutes
        }

        public static var `default`: IPv4 {
            IPv4(
                address: "10.0.0.2",
                subnetMask: "255.255.255.0",
                remoteAddress: "198.51.100.1"
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

    struct Policies: Codable, Equatable, Sendable {
        public var blockedHosts: [String] {
            didSet {
                if skipNextBlockedHostsRebuild, let last = blockedHosts.last {
                    // Incremental update when appended via API to avoid O(n) rebuilds.
                    skipNextBlockedHostsRebuild = false
                    let normalized = Self.normalizeBlockedHost(last)
                    if !normalized.isEmpty { blockedHostExactMatches.insert(normalized) }
                } else {
                    rebuildBlockedHostCache()
                }
            }
        }
        public var latencyRules: [LatencyRule]

        public init(blockedHosts: [String] = [], latencyRules: [LatencyRule] = []) {
            self.blockedHosts = blockedHosts
            self.latencyRules = latencyRules
            rebuildBlockedHostCache()
        }

        public static var `default`: Policies {
            Policies()
        }

        public mutating func appendBlockedHost(_ host: String) {
            // Signal didSet to skip full rebuild and apply incremental insert instead.
            skipNextBlockedHostsRebuild = true
            blockedHosts.append(host)
        }

        fileprivate func containsBlockedHost(_ host: String) -> Bool {
            guard !blockedHosts.isEmpty else { return false }
            let normalizedHost = Self.normalizeBlockedHost(host)
            guard !normalizedHost.isEmpty else { return false }
            if blockedHostExactMatches.contains(normalizedHost) {
                return true
            }
            // Walk label boundaries (after each '.') and check for suffix matches in the set.
            var searchStart = normalizedHost.startIndex
            while let dot = normalizedHost[searchStart...].firstIndex(of: ".") {
                let next = normalizedHost.index(after: dot)
                if blockedHostExactMatches.contains(String(normalizedHost[next...])) {
                    return true
                }
                searchStart = next
            }
            return false
        }

        private var blockedHostExactMatches: Set<String> = []
        private var skipNextBlockedHostsRebuild = false

        private mutating func rebuildBlockedHostCache() {
            var exact = Set<String>(minimumCapacity: blockedHosts.count)
            for entry in blockedHosts {
                let normalized = Self.normalizeBlockedHost(entry)
                guard !normalized.isEmpty else { continue }
                exact.insert(normalized)
            }
            blockedHostExactMatches = exact
        }

        private static func normalizeBlockedHost(_ host: String) -> String {
            host.trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
        }

        private enum CodingKeys: String, CodingKey {
            case blockedHosts
            case latencyRules
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            blockedHosts = try container.decodeIfPresent([String].self, forKey: .blockedHosts) ?? []
            latencyRules = try container.decodeIfPresent([LatencyRule].self, forKey: .latencyRules) ?? []
            rebuildBlockedHostCache()
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(blockedHosts, forKey: .blockedHosts)
            try container.encode(latencyRules, forKey: .latencyRules)
        }
    }

    struct LatencyRule: Codable, Equatable, Sendable {
        public enum Scope: String, Codable, Sendable {
            case global
            case host
        }

        public var scope: Scope
        public var host: String?
        public var milliseconds: Int

        public init(scope: Scope, host: String? = nil, milliseconds: Int) {
            self.scope = scope
            self.host = host
            self.milliseconds = milliseconds
        }

        public static func global(_ milliseconds: Int) -> LatencyRule {
            LatencyRule(scope: .global, milliseconds: milliseconds)
        }

        public static func host(_ host: String, milliseconds: Int) -> LatencyRule {
            LatencyRule(scope: .host, host: host, milliseconds: milliseconds)
        }
    }

    enum ValidationMessage: Sendable {
        case warning(String)
        case error(String)
    }

    struct LoggingOptions: Codable, Equatable, Sendable {
        public var enableDebug: Bool

        public init(enableDebug: Bool = false) {
            self.enableDebug = enableDebug
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

        public init(
            timestamp: Date,
            inbound: Counter,
            outbound: Counter,
            activeTCP: Int,
            activeUDP: Int,
            errors: [ErrorEvent]
        ) {
            self.timestamp = timestamp
            self.inbound = inbound
            self.outbound = outbound
            self.activeTCP = activeTCP
            self.activeUDP = activeUDP
            self.errors = errors
        }
    }
}

// MARK: - Hooks & Runtime Extensions

public extension RelativeProtocol.Configuration {
    /// Aggregates optional closures that allow the host to observe or
    /// influence runtime behaviour without subclassing package types.
    struct Hooks: Sendable {
        public var packetTap: PacketTap?
        public var packetTapBatch: PacketTapBatch?
        public var dnsResolver: DNSResolver?
        public var connectionPolicy: ConnectionPolicy?
        public var latencyInjector: LatencyInjector?
        public var eventSink: EventSink?

        public init(
            packetTap: PacketTap? = nil,
            packetTapBatch: PacketTapBatch? = nil,
            dnsResolver: DNSResolver? = nil,
            connectionPolicy: ConnectionPolicy? = nil,
            latencyInjector: LatencyInjector? = nil,
            eventSink: EventSink? = nil
        ) {
            self.packetTap = packetTap
            self.packetTapBatch = packetTapBatch
            self.dnsResolver = dnsResolver
            self.connectionPolicy = connectionPolicy
            self.latencyInjector = latencyInjector
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
    /// Batched variant to minimize per-packet closure and dispatch overhead.
    typealias PacketTapBatch = @Sendable (_ contexts: [PacketContext]) -> Void
    /// Resolves hostnames prior to establishing outbound connections.
    typealias DNSResolver = @Sendable (_ host: String) async throws -> [String]
    /// Determines whether an outbound connection should proceed, be blocked,
    /// or fall back to default handling.
    typealias ConnectionPolicy = @Sendable (_ endpoint: Endpoint) async -> ConnectionDecision
    /// Returns an artificial latency budget (milliseconds) to apply to the
    /// specified endpoint.
    typealias LatencyInjector = @Sendable (_ endpoint: Endpoint) async -> Int?
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

// MARK: - Equatable

extension RelativeProtocol.Configuration: Equatable {
    public static func == (lhs: RelativeProtocol.Configuration, rhs: RelativeProtocol.Configuration) -> Bool {
        lhs.provider == rhs.provider && lhs.logging == rhs.logging
    }
}

// MARK: - Provider Configuration Cache

private final class ProviderConfigurationCacheBox: @unchecked Sendable {
    private var cachedProvider: RelativeProtocol.Configuration.Provider?
    private var cachedLogging: RelativeProtocol.Configuration.LoggingOptions?
    private var cachedDictionary: [String: NSObject]?
    private var lock = os_unfair_lock_s()

    func dictionary(
        provider: RelativeProtocol.Configuration.Provider,
        logging: RelativeProtocol.Configuration.LoggingOptions,
        builder: () -> [String: NSObject]
    ) -> [String: NSObject] {
        if let cached = load(provider: provider, logging: logging) {
            return cached
        }

        let dictionary = builder()
        store(provider: provider, logging: logging, dictionary: dictionary)
        return dictionary
    }

    private func load(
        provider: RelativeProtocol.Configuration.Provider,
        logging: RelativeProtocol.Configuration.LoggingOptions
    ) -> [String: NSObject]? {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        guard
            let cachedProvider,
            let cachedLogging,
            let cachedDictionary
        else {
            return nil
        }
        guard cachedProvider == provider && cachedLogging == logging else {
            return nil
        }
        return cachedDictionary
    }

    private func store(
        provider: RelativeProtocol.Configuration.Provider,
        logging: RelativeProtocol.Configuration.LoggingOptions,
        dictionary: [String: NSObject]
    ) {
        os_unfair_lock_lock(&lock)
        cachedProvider = provider
        cachedLogging = logging
        cachedDictionary = dictionary
        os_unfair_lock_unlock(&lock)
    }
}
