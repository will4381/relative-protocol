//
//  PacketTunnelProvider.swift
//  Example Tunnel
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/23/2025.
//
//  Implements the Network Extension provider by bootstrapping the Relative
//  Protocol tunnel engine and coordinating example-specific filters.
//

#if canImport(Darwin)
import Darwin
#endif
import NetworkExtension
import Network
import OSLog
import RelativeProtocolTunnel
import RelativeProtocolCore

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "relative.example", category: "PacketTunnelProvider")
    private lazy var controller = RelativeProtocolTunnel.ProviderController(provider: self)
private let siteCatalog = ExampleSiteCatalog(capacity: 200)
    private let hostResolver = ExampleReverseDNSResolver()
    private let dnsClient = RelativeProtocol.DNSClient()

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration as? [String: NSObject]
        var configuration = RelativeProtocol.Configuration.load(from: providerConfig)

        // Respect the host application's logging preference; do not force debug logs on.
        var hooks = configuration.hooks
        hooks.eventSink = { [weak self] event in
            guard case let .didFail(message) = event else { return }
            self?.logger.error("Tunnel didFail: \(message, privacy: .public)")
        }
        hooks.packetStreamBuilder = {
            let config = RelativeProtocol.PacketStream.Configuration(
                bufferDuration: 12,
                snapshotQueue: DispatchQueue(label: "relative.example.filters")
            )
            return RelativeProtocol.PacketStream(configuration: config)
        }
        hooks.dnsResolver = { [dnsClient, controller] host in
            let result = try await dnsClient.resolve(host: host)
            let addresses = result.ipv4Addresses + result.ipv6Addresses
            controller.forwardHostTracker?.record(host: host, addresses: addresses, ttl: nil)
            return addresses
        }
        configuration.hooks = hooks

        controller.setFilterConfiguration(.init(evaluationInterval: 1.0))
        controller.configureFilters { [weak self] coordinator in
            guard let self else { return }
            coordinator.register(ExampleSiteTrackerFilter(
                catalog: self.siteCatalog,
                resolver: self.hostResolver,
                forwardHostTracker: self.controller.forwardHostTracker
            ))
        }
        controller.start(configuration: configuration, completion: completionHandler)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        siteCatalog.clear()
        controller.stop(reason: reason, completion: completionHandler)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Intercept "probe" messages from the host to test direct network reachability
        if let text = String(data: messageData, encoding: .utf8), text.hasPrefix("probe") {
            performProbe { result in
                completionHandler?(Data(result.utf8))
            }
            return
        }
        if let response = handleControlMessage(messageData) {
            completionHandler?(response)
            return
        }
        controller.handleAppMessage(messageData, completionHandler: completionHandler)
    }
}

// MARK: - Probe

private extension PacketTunnelProvider {
    /// Attempts to establish a TCP connection to 1.1.1.1:443 using NWConnection
    /// with parameters that avoid utun recursion, then reports a one-line result.
    func performProbe(completion: @escaping (String) -> Void) {
        let params = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        params.allowLocalEndpointReuse = true
        params.prohibitedInterfaceTypes = [.loopback, .other]

        let connection = NWConnection(host: "1.1.1.1", port: 443, using: params)
        let queue = DispatchQueue(label: "relative.example.probe")
        var finished = false

        func finish(_ message: String) {
            if finished { return }
            finished = true
            connection.cancel()
            completion(message)
        }

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                finish("ok")
            case .waiting(let error):
                finish("waiting: \(error.localizedDescription)")
            case .failed(let error):
                finish("error: \(error.localizedDescription)")
            case .cancelled:
                finish("cancelled")
            default:
                break
            }
        }

        connection.start(queue: queue)

        // Timeout after 5 seconds
        queue.asyncAfter(deadline: .now() + 5.0) { finish("timeout") }
    }

    func handleControlMessage(_ data: Data) -> Data? {
        if let raw = String(data: data, encoding: .utf8) {
            logger.notice("control message payload: \(raw, privacy: .public)")
        } else {
            logger.notice("control message payload length \(data.count, privacy: .public) bytes (non-UTF8)")
        }
        let decoder = JSONDecoder()
        let command: ExampleControlCommand
        do {
            command = try decoder.decode(ExampleControlCommand.self, from: data)
            logger.notice("decoded control command: \(command.command, privacy: .public)")
        } catch {
            logger.error("control message decode failed: \(error.localizedDescription, privacy: .public)")
            return encodeErrorResponse(command: "invalid", message: error.localizedDescription)
        }

        switch command.command {
        case "events":
            let limit = max(1, min(command.limit ?? 50, 200))
            logger.notice("handling events command, limit=\(limit, privacy: .public)")
            let sites = siteCatalog.summaries(limit: limit)
            let response = ExampleSitesResponse(
                sites: sites,
                total: siteCatalog.totalCount()
            )
            logger.notice("returning \(sites.count, privacy: .public) site summaries")
            return encodeResponse(response, command: command.command)
        case "clearEvents":
            siteCatalog.clear()
            logger.notice("clearEvents command processed")
            let response = ExampleAckResponse(
                command: command.command,
                total: siteCatalog.totalCount()
            )
            return encodeResponse(response, command: command.command)
        default:
            return encodeErrorResponse(command: command.command, message: "unsupported command")
        }
    }

    private func encodeResponse<T: Encodable>(_ payload: T, command: String) -> Data? {
        do {
            logger.debug("encoding response for \(command, privacy: .public)")
            return try JSONEncoder().encode(payload)
        } catch {
            logger.error("control message encode failed for \(command, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return encodeErrorResponse(command: command, message: error.localizedDescription)
        }
    }

    private func encodeErrorResponse(command: String, message: String) -> Data? {
        let response = ExampleErrorResponse(command: command, error: message)
        logger.error("sending error response for \(command, privacy: .public): \(message, privacy: .public)")
        if let data = try? JSONEncoder().encode(response) {
            return data
        }
        logger.error("failed to encode error response for \(command, privacy: .public)")
        return Data("{\"command\":\"\(command)\",\"error\":\"\(message)\"}".utf8)
    }
}

private struct ExampleControlCommand: Decodable {
    var command: String
    var value: Int?
    var limit: Int?
}

private struct ExampleSitesResponse: Encodable {
    var sites: [ExampleSiteSummary]
    var total: Int
}

private struct ExampleAckResponse: Encodable {
    var command: String
    var total: Int
}

private struct ExampleErrorResponse: Encodable {
    var command: String
    var error: String
}

// MARK: - Site Tracking

private struct ExampleSiteSummary: Codable {
    var remoteIP: String
    var host: String?
    var site: String?
    var firstSeen: Date
    var lastSeen: Date
    var inboundBytes: Int
    var outboundBytes: Int
    var inboundPackets: Int
    var outboundPackets: Int
}

private final class ExampleSiteCatalog: @unchecked Sendable {
    private struct Entry {
        var key: String
        var remoteIP: String
        var host: String?
        var site: String?
        var firstSeen: Date
        var lastSeen: Date
        var inboundBytes: Int
        var outboundBytes: Int
        var inboundPackets: Int
        var outboundPackets: Int

        func summary() -> ExampleSiteSummary {
            ExampleSiteSummary(
                remoteIP: remoteIP,
                host: host,
                site: site,
                firstSeen: firstSeen,
                lastSeen: lastSeen,
                inboundBytes: inboundBytes,
                outboundBytes: outboundBytes,
                inboundPackets: inboundPackets,
                outboundPackets: outboundPackets
            )
        }
    }

    private let queue = DispatchQueue(label: "relative.example.siteCatalog", attributes: .concurrent)
    private var entries: [String: Entry] = [:]
    private let capacity: Int
    private let log = Logger(subsystem: "relative.example", category: "SiteCatalog")

    init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    func record(
        remoteIP: String,
        host: String?,
        site: String?,
        direction: RelativeProtocol.Direction,
        bytes: Int,
        timestamp: Date
    ) {
        let key = site?.lowercased() ?? host?.lowercased() ?? remoteIP
        queue.async(flags: .barrier) {
            var entry = self.entries[key] ?? Entry(
                key: key,
                remoteIP: remoteIP,
                host: host,
                site: site,
                firstSeen: timestamp,
                lastSeen: timestamp,
                inboundBytes: 0,
                outboundBytes: 0,
                inboundPackets: 0,
                outboundPackets: 0
            )
            entry.remoteIP = remoteIP
            if let host {
                entry.host = host
            }
            if let site {
                entry.site = site
            }
            entry.lastSeen = max(entry.lastSeen, timestamp)
            switch direction {
            case .inbound:
                entry.inboundBytes += bytes
                entry.inboundPackets += 1
            case .outbound:
                entry.outboundBytes += bytes
                entry.outboundPackets += 1
            }
            self.entries[key] = entry
            self.trimIfNeeded()
        }
    }

    func summaries(limit: Int) -> [ExampleSiteSummary] {
        return queue.sync {
            log.notice("catalog snapshot requested (limit \(limit, privacy: .public)) currentCount=\(self.entries.count, privacy: .public)")
            return self.entries.values
                .sorted(by: { $0.lastSeen > $1.lastSeen })
                .prefix(limit)
                .map { $0.summary() }
        }
    }

    func totalCount() -> Int {
        queue.sync { entries.count }
    }

    func clear() {
        queue.async(flags: .barrier) {
            self.log.notice("catalog clearing all entries (count \(self.entries.count, privacy: .public))")
            self.entries.removeAll(keepingCapacity: true)
        }
    }

    private func trimIfNeeded() {
        guard entries.count > capacity else { return }
        let overflow = entries.count - capacity
        let staleKeys = entries.values
            .sorted(by: { $0.lastSeen < $1.lastSeen })
            .prefix(overflow)
            .map(\.key)
        if !staleKeys.isEmpty {
            log.notice("catalog trimming \(staleKeys.count, privacy: .public) entries")
        }
        for key in staleKeys {
            entries.removeValue(forKey: key)
        }
    }

}

private struct ExampleSiteTrackerFilter: TrafficFilter {
    let identifier = "relative.example.filters.siteTracker"
    private let catalog: ExampleSiteCatalog
    private let resolver: ExampleReverseDNSResolver
    private let forwardHostTracker: RelativeProtocolTunnel.ForwardHostTracker?

    init(catalog: ExampleSiteCatalog, resolver: ExampleReverseDNSResolver, forwardHostTracker: RelativeProtocolTunnel.ForwardHostTracker?) {
        self.catalog = catalog
        self.resolver = resolver
        self.forwardHostTracker = forwardHostTracker
    }

    func evaluate(snapshot: UnsafeBufferPointer<RelativeProtocol.PacketSample>, emit _: @escaping @Sendable (RelativeProtocol.TrafficEvent) -> Void) {
        guard !snapshot.isEmpty else { return }
        for sample in snapshot {
            guard let metadata = sample.metadata else { continue }
            let remoteIP = metadata.remoteAddress(for: sample.direction)
            guard isLikelyPublicIP(remoteIP) else { continue }
            let forwardHost = forwardHostTracker?.lookup(ip: remoteIP, at: sample.timestamp)
            let host = forwardHost ?? resolver.cachedHostname(for: remoteIP)
            let site = forwardHost.flatMap(apexDomain(for:)) ?? host.flatMap(apexDomain(for:))
            catalog.record(
                remoteIP: remoteIP,
                host: host,
                site: site,
                direction: sample.direction,
                bytes: sample.byteCount,
                timestamp: sample.timestamp
            )
            resolver.resolveIfNeeded(ip: remoteIP)
        }
    }
}

private func apexDomain(for host: String) -> String {
    let parts = host.split(separator: ".")
    guard parts.count >= 2 else { return host }
    return parts.suffix(2).joined(separator: ".")
}

private func isLikelyPublicIP(_ ip: String) -> Bool {
    if ip.contains(":") {
        return isLikelyPublicIPv6(ip)
    }
    return isLikelyPublicIPv4(ip)
}

private func isLikelyPublicIPv4(_ ip: String) -> Bool {
    let octets = ip.split(separator: ".")
    guard octets.count == 4,
          let first = Int(octets[0]),
          let second = Int(octets[1]) else { return false }

    if first == 0 || first == 10 || first == 127 { return false }
    if first == 169 && second == 254 { return false }
    if first == 172 && (16...31).contains(second) { return false }
    if first == 192 && second == 168 { return false }
    if first == 100 && (64...127).contains(second) { return false }
    if first >= 224 && first <= 239 { return false }
    if first == 255 { return false }
    return true
}

private func isLikelyPublicIPv6(_ ip: String) -> Bool {
    guard let octets = ipv6Octets(from: ip) else { return false }
    if octets.allSatisfy({ $0 == 0 }) { return false } // Unspecified ::
    if octets.dropLast().allSatisfy({ $0 == 0 }) && octets.last == 1 { return false } // Loopback ::1
    if (octets[0] & 0xfe) == 0xfc { return false } // Unique local fc00::/7
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 { return false } // Link-local fe80::/10
    if octets[0] == 0xff { return false } // Multicast ff00::/8
    if octets[0] == 0x20, octets[1] == 0x01, octets[2] == 0x0d, octets[3] == 0xb8 { return false } // Documentation 2001:db8::/32

    if ipv4MappedOctets(octets) {
        let ipv4 = "\(octets[12]).\(octets[13]).\(octets[14]).\(octets[15])"
        return isLikelyPublicIPv4(ipv4)
    }

    // Global unicast 2000::/3
    return (octets[0] & 0xe0) == 0x20
}

private func ipv4MappedOctets(_ octets: [UInt8]) -> Bool {
    guard octets.count == 16 else { return false }
    if !octets[0..<10].allSatisfy({ $0 == 0 }) { return false }
    if octets[10] != 0xff || octets[11] != 0xff { return false }
    return true
}

private func ipv6Octets(from ip: String) -> [UInt8]? {
    guard let address = IPv6Address(ip) else { return nil }
    var raw = address.rawValue
    return withUnsafeBytes(of: &raw) { buffer -> [UInt8] in
        Array(buffer)
    }
}

private final class ExampleReverseDNSResolver: @unchecked Sendable {
    private let queue = DispatchQueue(label: "relative.example.reverseDNS", attributes: .concurrent)
    private var cache: [String: String] = [:]
    private var inflight: Set<String> = []
    private let dnsClient = RelativeProtocol.DNSClient()
    private let log = Logger(subsystem: "relative.example", category: "ReverseDNS")

    func cachedHostname(for ip: String) -> String? {
        let result: String? = queue.sync {
            guard let value = cache[ip], !value.isEmpty else { return nil }
            return value
        }
        if let host = result {
            log.debug("cache hit for \(ip, privacy: .public) -> \(host, privacy: .public)")
        } else {
            log.debug("cache miss for \(ip, privacy: .public)")
        }
        return result
    }

    func resolveIfNeeded(ip: String) {
        var shouldStart = false
        queue.sync {
            if cache[ip] == nil && !inflight.contains(ip) {
                inflight.insert(ip)
                log.notice("starting reverse DNS lookup for \(ip, privacy: .public)")
                shouldStart = true
            }
        }
        guard shouldStart else {
            log.debug("reverse DNS lookup already in-flight or cached for \(ip, privacy: .public)")
            return
        }

        Task.detached { [weak self] in
            guard let self else { return }
            do {
                let host = try await self.dnsClient.reverseLookup(address: ip)
                self.markCompleted(ip: ip, host: host)
            } catch let error as RelativeProtocol.DNSClient.LookupError {
                self.log.error("reverse DNS lookup failed for \(ip, privacy: .public): \(describe(error: error), privacy: .public)")
                self.markCompleted(ip: ip, host: nil)
            } catch {
                self.log.error("reverse DNS lookup failed for \(ip, privacy: .public): \(error.localizedDescription, privacy: .public)")
                self.markCompleted(ip: ip, host: nil)
            }
        }
    }

    private func markCompleted(ip: String, host: String?) {
        queue.async(flags: .barrier) {
            if let host, !host.isEmpty {
                self.cache[ip] = host
                self.log.notice("reverse DNS resolved \(ip, privacy: .public) -> \(host, privacy: .public)")
            } else {
                self.cache[ip] = ""
                self.log.debug("reverse DNS no hostname for \(ip, privacy: .public)")
            }
            self.inflight.remove(ip)
        }
    }
}

private func describe(error: RelativeProtocol.DNSClient.LookupError) -> String {
    switch error {
    case .invalidInput:
        return "invalid input"
    case .systemError(let code):
        return String(cString: gai_strerror(code))
    }
}

// MARK: - Packet Parsing Helpers
