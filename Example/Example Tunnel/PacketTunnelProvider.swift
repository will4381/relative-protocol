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
                bufferDuration: 120,
                snapshotQueue: DispatchQueue(label: "relative.example.filters")
            )
            return RelativeProtocol.PacketStream(configuration: config)
        }
        hooks.dnsResolver = { [dnsClient] host in
            let result = try await dnsClient.resolve(host: host)
            return result.ipv4Addresses + result.ipv6Addresses
        }
        configuration.hooks = hooks

        controller.setFilterConfiguration(.init(evaluationInterval: 1.0))
        controller.configureFilters { [weak self] coordinator in
            guard let self else { return }
            coordinator.register(ExampleSiteTrackerFilter(catalog: self.siteCatalog, resolver: self.hostResolver))
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
            let isNew = self.entries[key] == nil
            self.entries[key] = entry
            if isNew {
                self.log.notice("catalog added entry for \(key, privacy: .public) (IP \(remoteIP, privacy: .public))")
            } else {
                self.log.notice("catalog updated \(key, privacy: .public) inbound=\(entry.inboundBytes, privacy: .public) outbound=\(entry.outboundBytes, privacy: .public)")
            }
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
    private let log = Logger(subsystem: "relative.example", category: "SiteTrackerFilter")

    init(catalog: ExampleSiteCatalog, resolver: ExampleReverseDNSResolver) {
        self.catalog = catalog
        self.resolver = resolver
    }

    func evaluate(snapshot: [RelativeProtocol.PacketSample], emit _: @escaping @Sendable (RelativeProtocol.TrafficEvent) -> Void) {
        guard !snapshot.isEmpty else {
            log.debug("evaluate called with empty snapshot")
            return
        }
        log.notice("processing snapshot with \(snapshot.count, privacy: .public) samples")
        for sample in snapshot {
            guard let parsed = ExamplePacketParser.parse(sample.payload) else {
                log.notice("skipping sample: unable to parse payload")
                continue
            }
            if parsed.isDNS {
                log.notice("skipping sample: DNS traffic")
                continue
            }
            let remoteIP: String
            switch sample.direction {
            case .inbound:
                remoteIP = parsed.sourceIP
            case .outbound:
                remoteIP = parsed.destinationIP
            }
            log.notice("candidate remote IP \(remoteIP, privacy: .public)")
            guard isLikelyPublicIP(remoteIP) else {
                log.notice("skipping sample: non-public IP \(remoteIP, privacy: .public)")
                continue
            }
            let host = resolver.cachedHostname(for: remoteIP)
            let site = host.flatMap(apexDomain(for:))
            log.notice("sample for \(remoteIP, privacy: .public) host=\(host ?? "nil", privacy: .public) site=\(site ?? "nil", privacy: .public)")
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

private enum ExamplePacketParser {
    struct ParsedPacket {
        enum Transport {
            case udp(srcPort: UInt16, dstPort: UInt16, payload: Data)
            case tcp
            case other
        }

        var sourceIP: String
        var destinationIP: String
        var transport: Transport
    }

    static func parse(_ data: Data) -> ParsedPacket? {
        guard let firstByte = data.first else { return nil }
        let version = firstByte >> 4

        switch version {
        case 4:
            let ihl = Int(firstByte & 0x0F) * 4
            guard ihl >= 20, data.count >= ihl else { return nil }

            let protocolNumber = data[9]
            let srcIP = ipv4String(from: data[12..<16])
            let dstIP = ipv4String(from: data[16..<20])
            guard !srcIP.isEmpty, !dstIP.isEmpty else { return nil }
            let payload = data[ihl...]
            let transport = transport(for: protocolNumber, payload: payload)
            return ParsedPacket(sourceIP: srcIP, destinationIP: dstIP, transport: transport)
        case 6:
            let headerLength = 40
            guard data.count >= headerLength else { return nil }

            let nextHeader = data[6]
            let srcIP = ipv6String(from: data[8..<24])
            let dstIP = ipv6String(from: data[24..<40])
            guard !srcIP.isEmpty, !dstIP.isEmpty else { return nil }
            let payload = data[headerLength...]
            let transport = transport(for: nextHeader, payload: payload)
            return ParsedPacket(sourceIP: srcIP, destinationIP: dstIP, transport: transport)
        default:
            return nil
        }
    }

    private static func ipv4String(from bytes: Data.SubSequence) -> String {
        guard bytes.count == 4 else { return "" }
        return bytes.map { String($0) }.joined(separator: ".")
    }

    private static func ipv6String(from bytes: Data.SubSequence) -> String {
        guard bytes.count == 16 else { return "" }
        return bytes.withUnsafeBytes { rawBuffer -> String in
            guard let baseAddress = rawBuffer.baseAddress else { return "" }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            if inet_ntop(AF_INET6, baseAddress, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                return String(cString: buffer)
            }
            return ""
        }
    }

    private static func transport(for protocolNumber: UInt8, payload: Data.SubSequence) -> ParsedPacket.Transport {
        switch protocolNumber {
        case 17: // UDP
            guard payload.count >= 8 else { return .other }
            let srcPort = UInt16(payload[payload.startIndex]) << 8 | UInt16(payload[payload.startIndex + 1])
            let dstPort = UInt16(payload[payload.startIndex + 2]) << 8 | UInt16(payload[payload.startIndex + 3])
            let udpPayload = payload.dropFirst(8)
            return .udp(srcPort: srcPort, dstPort: dstPort, payload: Data(udpPayload))
        case 6:
            return .tcp
        default:
            return .other
        }
    }
}

private extension ExamplePacketParser.ParsedPacket {
    var isDNS: Bool {
        switch transport {
        case let .udp(srcPort, dstPort, _):
            return srcPort == 53 || dstPort == 53
        default:
            return false
        }
    }
}
