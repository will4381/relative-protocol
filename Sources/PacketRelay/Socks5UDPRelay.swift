import Darwin
import Foundation
import Network
@preconcurrency import NetworkExtension
import Observability

/// Minimal lifecycle for per-connection UDP relay helpers.
protocol Socks5UDPRelayProtocol: AnyObject {
    var port: UInt16 { get }
    func start()
    func stop()
}

/// UDP session abstraction used by SOCKS relay to support Network/NetworkExtension backends.
protocol Socks5UDPSession: AnyObject, Sendable {
    var eventHandler: ((Socks5UDPSessionEvent) -> Void)? { get set }
    func setReadHandler(_ handler: @escaping @Sendable (Data?, Error?) -> Void)
    func writeDatagram(_ datagram: Data, completionHandler: @escaping @Sendable (Error?) -> Void)
    func restart()
    func cancel()
}

enum Socks5UDPSessionEvent: Sendable {
    case ready
    case waiting
    case failed
    case viabilityChanged(Bool)
    case betterPathAvailable
}

/// Factory interface used by relay to create outbound UDP sessions.
protocol Socks5ConnectionProvider: AnyObject, Sendable {
    // Docs: https://developer.apple.com/documentation/networkextension/nwhostendpoint
    func makeUDPSession(to endpoint: NWHostEndpoint) -> Socks5UDPSession
}

/// SOCKS5 UDP ASSOCIATE relay bound to localhost.
/// Queue ownership: all socket I/O and session mutation happen on `queue`.
final class Socks5UDPRelay: @unchecked Sendable, Socks5UDPRelayProtocol {
    private enum SessionPolicy {
        static let maxSessions = 256
        static let idleTimeoutSeconds: TimeInterval = 60
        static let idleReapIntervalSeconds: TimeInterval = 10
        static let usageQueueCompactionThreshold = 128
        static let pmtuReplacementThreshold = 3
        static let pmtuReplacementWindowSeconds: TimeInterval = 5
        static let maxSocksDatagramBytes = 65_535
    }

    private struct SessionKey: Hashable, Sendable {
        let address: Socks5Address
        let port: UInt16
    }

    private struct SessionEntry: Sendable {
        struct PMTUFeedback: Sendable {
            var latestObservedMaximumDatagramSize: Int?
            var minimumObservedMaximumDatagramSize: Int?
            var oversizedDropCount: Int
            var lastOversizedDropAt: Date?
            var lastPathSummary: String?
        }

        let session: Socks5UDPSession
        var lastUsedAt: Date
        var lastUsedSequence: UInt64
        var needsReplacement: Bool
        var pmtuFeedback: PMTUFeedback
    }

    private struct SessionUsageStamp {
        let key: SessionKey
        let sequence: UInt64
    }

    private struct IPv4ClientEndpoint: Equatable {
        let address: in_addr_t
        let port: in_port_t
    }

    private let logger: StructuredLogger
    private let provider: Socks5ConnectionProvider
    private let queue: DispatchQueue
    private let mtu: Int
    private let nowProvider: @Sendable () -> Date
    private let queueSpecificKey = DispatchSpecificKey<UUID>()
    private let queueSpecificValue = UUID()

    private var socketFD: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var sessions: [SessionKey: SessionEntry] = [:]
    private var sessionUsageQueue: ArraySlice<SessionUsageStamp> = []
    private var nextUsageSequence: UInt64 = 0
    private var nextIdleReapAt = Date.distantPast
    private var clientEndpoint: IPv4ClientEndpoint?
    private var clientAddress = sockaddr_storage()
    private var clientAddressLen: socklen_t = 0

    private(set) var port: UInt16 = 0

    /// - Parameters:
    ///   - provider: Outbound session provider.
    ///   - queue: Serial queue for socket I/O and state.
    ///   - mtu: Max expected datagram size.
    ///   - logger: Structured logger for relay events.
    ///   - nowProvider: Time source used for bounded UDP session eviction.
    init(
        provider: Socks5ConnectionProvider,
        queue: DispatchQueue,
        mtu: Int,
        logger: StructuredLogger,
        nowProvider: @escaping @Sendable () -> Date = { Date() }
    ) throws {
        self.provider = provider
        self.queue = queue
        self.mtu = max(256, mtu)
        self.logger = logger
        self.nowProvider = nowProvider
        queue.setSpecific(key: queueSpecificKey, value: queueSpecificValue)
        try openSocket()
    }

    deinit {
        stop()
    }

    var activeSessionCount: Int {
        sessions.count
    }

    /// Starts local UDP socket read loop for SOCKS5 UDP ASSOCIATE traffic.
    func start() {
        performOnQueue {
            guard readSource == nil else { return }
            if socketFD < 0 {
                do {
                    try openSocket()
                } catch {
                    let logger = self.logger
                    Task {
                        await logger.log(
                            level: .error,
                            phase: .relay,
                            category: .relayUDP,
                            component: "Socks5UDPRelay",
                            event: "socket-open-failed",
                            errorCode: String(describing: error),
                            message: "UDP relay socket open failed"
                        )
                    }
                    return
                }
            }

            let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
            source.setEventHandler { [weak self] in
                self?.drainReadable()
            }
            source.resume()
            readSource = source
        }
    }

    /// Stops socket read loop and cancels all outbound UDP sessions.
    func stop() {
        performOnQueue {
            readSource?.cancel()
            readSource = nil
            sessions.values.forEach { $0.session.cancel() }
            sessions.removeAll()
            sessionUsageQueue.removeAll(keepingCapacity: false)
            nextUsageSequence = 0
            nextIdleReapAt = Date.distantPast
            clientEndpoint = nil
            clientAddress = sockaddr_storage()
            clientAddressLen = 0
            closeSocketIfNeeded()
        }
    }

    private func drainReadable() {
        var buffer = [UInt8](repeating: 0, count: SessionPolicy.maxSocksDatagramBytes)

        while true {
            var addr = sockaddr_storage()
            var addrLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let bytes = recvfrom(socketFD, &buffer, buffer.count, 0, withUnsafeMutablePointer(to: &addr) {
                UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self)
            }, &addrLen)
            if bytes < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    break
                }
                let logger = self.logger
                Task {
                    await logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayUDP,
                        component: "Socks5UDPRelay",
                        event: "recv-failed",
                        errorCode: String(errno),
                        message: "UDP relay recvfrom failed"
                    )
                }
                break
            }
            guard bytes > 0 else { break }

            guard rememberOrValidateClient(addr, addrLen: addrLen) else {
                logUnauthorizedClientDatagram()
                continue
            }

            guard let packet = buffer.withUnsafeBufferPointer({ ptr in
                Socks5Codec.parseUDPPacket(ptr, count: bytes)
            }) else {
                continue
            }

            let now = nowProvider()
            reapIdleSessionsIfNeeded(now: now)
            let key = SessionKey(address: packet.address, port: packet.port)
            let entry = sessionEntry(for: key, now: now)
            let session = entry.session
            entry.session.writeDatagram(packet.payload) { [weak self] error in
                guard let self, let error else { return }
                self.performOnQueue {
                    guard self.isCurrentSession(session, for: key) else { return }
                    if let metadata = self.handleDatagramLimitError(error, for: key, at: self.nowProvider()) {
                        let logger = self.logger
                        Task {
                            await logger.log(
                                level: metadata["replacement_scheduled"] == "true" ? .error : .warning,
                                phase: .relay,
                                category: .relayUDP,
                                component: "Socks5UDPRelay",
                                event: "write-failed",
                                errorCode: Socks5UDPDatagramError.datagramTooLargeErrorCode,
                                message: metadata["replacement_scheduled"] == "true"
                                    ? "UDP relay repeatedly hit live datagram ceiling; scheduling session replacement"
                                    : "UDP relay dropped oversized datagram without resetting session",
                                metadata: metadata
                            )
                        }
                        return
                    }
                    self.removeSession(for: key)
                    let logger = self.logger
                    Task {
                        await logger.log(
                            level: .error,
                            phase: .relay,
                            category: .relayUDP,
                            component: "Socks5UDPRelay",
                            event: "write-failed",
                            errorCode: String(describing: error),
                            message: "UDP relay write failed"
                        )
                    }
                }
            }
        }
    }

    private func reapIdleSessionsIfNeeded(now: Date) {
        guard now >= nextIdleReapAt else {
            return
        }
        reapIdleSessions(now: now)
        nextIdleReapAt = now.addingTimeInterval(SessionPolicy.idleReapIntervalSeconds)
    }

    func reapIdleSessions(now: Date) {
        dispatchPrecondition(condition: .onQueue(queue))

        let expiredKeys = sessions.compactMap { key, entry in
            now.timeIntervalSince(entry.lastUsedAt) > SessionPolicy.idleTimeoutSeconds ? key : nil
        }

        for key in expiredKeys {
            removeSession(for: key)
        }
    }

    private func sessionEntry(for key: SessionKey, now: Date) -> SessionEntry {
        if let entry = sessions[key], !entry.needsReplacement {
            return markSessionUsed(for: key, at: now)
        }

        if sessions[key] != nil {
            removeSession(for: key)
        }

        evictOldestSessionIfNeeded()
        return createSession(for: key, now: now)
    }

    private func createSession(for key: SessionKey, now: Date) -> SessionEntry {
        let hostString: String
        switch key.address {
        case .ipv4(let value), .ipv6(let value), .domain(let value):
            hostString = value
        }
        // Docs: https://developer.apple.com/documentation/networkextension/nwhostendpoint
        let endpoint = NWHostEndpoint(hostname: hostString, port: String(key.port))
        let session = provider.makeUDPSession(to: endpoint)
        session.eventHandler = { [weak self, weak session] event in
            guard let self, let session else { return }
            self.performOnQueue {
                guard self.isCurrentSession(session, for: key) else { return }
                switch event {
                case .ready:
                    self.clearReplacementNeed(for: key)
                case .waiting:
                    self.replaceSession(for: key, reason: "waiting")
                case .failed:
                    self.removeSession(for: key)
                case .viabilityChanged(let isViable):
                    if isViable {
                        self.clearReplacementNeed(for: key)
                    } else {
                        self.replaceSession(for: key, reason: "not-viable")
                    }
                case .betterPathAvailable:
                    self.replaceSession(for: key, reason: "better-path")
                }
            }
        }
        session.setReadHandler({ [weak self] datagram, error in
            guard let self else { return }
            if let error {
                self.removeSession(for: key)
                let logger = self.logger
                Task {
                    await logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayUDP,
                        component: "Socks5UDPRelay",
                        event: "read-failed",
                        errorCode: String(describing: error),
                        message: "UDP relay read failed"
                    )
                }
                return
            }
            guard let datagram else { return }
            _ = self.markSessionUsed(for: key, at: self.nowProvider())
            let response = Socks5Codec.buildUDPPacket(address: key.address, port: key.port, payload: datagram)
            self.sendToClient(response)
        })

        let entry = SessionEntry(
            session: session,
            lastUsedAt: now,
            lastUsedSequence: nextSessionUsageSequence(),
            needsReplacement: false,
            pmtuFeedback: .init(
                latestObservedMaximumDatagramSize: nil,
                minimumObservedMaximumDatagramSize: nil,
                oversizedDropCount: 0,
                lastOversizedDropAt: nil,
                lastPathSummary: nil
            )
        )
        sessions[key] = entry
        sessionUsageQueue.append(SessionUsageStamp(key: key, sequence: entry.lastUsedSequence))
        pruneUsageQueueIfNeeded()
        return entry
    }

    private func evictOldestSessionIfNeeded() {
        guard sessions.count >= SessionPolicy.maxSessions else {
            return
        }

        pruneUsageQueueIfNeeded(force: true)
        while sessions.count >= SessionPolicy.maxSessions {
            if let stamp = sessionUsageQueue.popFirst() {
                guard let entry = sessions[stamp.key], entry.lastUsedSequence == stamp.sequence else {
                    continue
                }
                removeSession(for: stamp.key)
                pruneUsageQueueIfNeeded()
                return
            }

            guard let fallback = sessions.keys.first else {
                return
            }
            // Decision: this should stay cold because the usage queue is the primary eviction path.
            // If the queue is unexpectedly empty, removing any active session is cheaper than re-scanning the whole map.
            removeSession(for: fallback)
        }
    }

    private func markSessionUsed(for key: SessionKey, at now: Date) -> SessionEntry {
        guard var entry = sessions[key] else {
            preconditionFailure("Attempted to mark a missing UDP session as used")
        }
        entry.lastUsedAt = now
        entry.lastUsedSequence = nextSessionUsageSequence()
        sessions[key] = entry
        sessionUsageQueue.append(SessionUsageStamp(key: key, sequence: entry.lastUsedSequence))
        pruneUsageQueueIfNeeded()
        return entry
    }

    private func removeSession(for key: SessionKey) {
        guard let entry = sessions.removeValue(forKey: key) else {
            return
        }
        entry.session.cancel()
    }

    private func replaceSession(for key: SessionKey, reason: String) {
        guard sessions[key] != nil else {
            return
        }
        removeSession(for: key)
        _ = createSession(for: key, now: nowProvider())
        Task {
            await logger.log(
                level: .notice,
                phase: .relay,
                category: .relayUDP,
                component: "Socks5UDPRelay",
                event: "session-replaced",
                result: reason,
                message: "Replaced UDP session after Network.framework path signal"
            )
        }
    }

    private func handleDatagramLimitError(
        _ error: Error,
        for key: SessionKey,
        at now: Date
    ) -> [String: String]? {
        guard let error = error as? Socks5UDPDatagramError else {
            return nil
        }
        guard case .exceedsMaximumDatagramSize(let datagramSize, let maximumDatagramSize, let pathSummary) = error,
              var entry = sessions[key]
        else {
            return nil
        }

        if let lastOversizedDropAt = entry.pmtuFeedback.lastOversizedDropAt,
           now.timeIntervalSince(lastOversizedDropAt) > SessionPolicy.pmtuReplacementWindowSeconds {
            entry.pmtuFeedback.oversizedDropCount = 0
        }

        entry.pmtuFeedback.latestObservedMaximumDatagramSize = maximumDatagramSize
        if let minimumObservedMaximumDatagramSize = entry.pmtuFeedback.minimumObservedMaximumDatagramSize {
            entry.pmtuFeedback.minimumObservedMaximumDatagramSize = min(
                minimumObservedMaximumDatagramSize,
                maximumDatagramSize
            )
        } else {
            entry.pmtuFeedback.minimumObservedMaximumDatagramSize = maximumDatagramSize
        }
        entry.pmtuFeedback.oversizedDropCount += 1
        entry.pmtuFeedback.lastOversizedDropAt = now
        entry.pmtuFeedback.lastPathSummary = pathSummary

        let replacementScheduled = entry.pmtuFeedback.oversizedDropCount >= SessionPolicy.pmtuReplacementThreshold
        if replacementScheduled {
            entry.needsReplacement = true
        }
        sessions[key] = entry

        return [
            "error_kind": "maximum-datagram-size",
            "datagram_size": String(datagramSize),
            "maximum_datagram_size": String(maximumDatagramSize),
            "latest_observed_maximum_datagram_size": String(
                entry.pmtuFeedback.latestObservedMaximumDatagramSize ?? maximumDatagramSize
            ),
            "minimum_observed_maximum_datagram_size": String(
                entry.pmtuFeedback.minimumObservedMaximumDatagramSize ?? maximumDatagramSize
            ),
            "oversized_drop_count": String(entry.pmtuFeedback.oversizedDropCount),
            "pmtu_feedback_window_seconds": String(Int(SessionPolicy.pmtuReplacementWindowSeconds)),
            "replacement_scheduled": replacementScheduled ? "true" : "false",
            "session_retained": "true",
            "path": pathSummary,
        ]
    }

    private func clearReplacementNeed(for key: SessionKey) {
        guard var entry = sessions[key] else {
            return
        }
        entry.needsReplacement = false
        sessions[key] = entry
    }

    private func isCurrentSession(_ session: Socks5UDPSession, for key: SessionKey) -> Bool {
        guard let entry = sessions[key] else {
            return false
        }
        return entry.session === session
    }

    private func nextSessionUsageSequence() -> UInt64 {
        nextUsageSequence &+= 1
        return nextUsageSequence
    }

    private func pruneUsageQueueIfNeeded(force: Bool = false) {
        let queueLimit = max(SessionPolicy.maxSessions * 4, 256)
        guard force ||
                sessionUsageQueue.startIndex > SessionPolicy.usageQueueCompactionThreshold ||
                sessionUsageQueue.count > queueLimit else {
            return
        }

        var activeQueue: [SessionUsageStamp] = []
        activeQueue.reserveCapacity(min(sessions.count, SessionPolicy.maxSessions))

        for stamp in sessionUsageQueue {
            guard let entry = sessions[stamp.key], entry.lastUsedSequence == stamp.sequence else {
                continue
            }
            activeQueue.append(stamp)
        }

        sessionUsageQueue = ArraySlice(activeQueue)
    }

    private func sendToClient(_ data: Data) {
        guard clientAddressLen > 0 else { return }
        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            let sent = withUnsafePointer(to: &clientAddress) {
                sendto(socketFD, base, data.count, 0, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), clientAddressLen)
            }
            if sent < 0, errno != EAGAIN, errno != EWOULDBLOCK {
                let logger = self.logger
                Task {
                    await logger.log(
                        level: .error,
                        phase: .relay,
                        category: .relayUDP,
                        component: "Socks5UDPRelay",
                        event: "send-failed",
                        errorCode: String(errno),
                        message: "UDP relay sendto failed"
                    )
                }
            }
        }
    }

    private func rememberOrValidateClient(_ address: sockaddr_storage, addrLen: socklen_t) -> Bool {
        guard let endpoint = ipv4ClientEndpoint(from: address, addrLen: addrLen) else {
            return false
        }
        if let clientEndpoint {
            return clientEndpoint == endpoint
        }
        clientEndpoint = endpoint
        clientAddress = address
        clientAddressLen = addrLen
        return true
    }

    private func ipv4ClientEndpoint(from address: sockaddr_storage, addrLen: socklen_t) -> IPv4ClientEndpoint? {
        guard addrLen >= socklen_t(MemoryLayout<sockaddr_in>.size),
              Int32(address.ss_family) == AF_INET else {
            return nil
        }
        return withUnsafePointer(to: address) { pointer in
            pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ipv4 in
                IPv4ClientEndpoint(address: ipv4.pointee.sin_addr.s_addr, port: ipv4.pointee.sin_port)
            }
        }
    }

    private func logUnauthorizedClientDatagram() {
        let logger = self.logger
        Task {
            await logger.logRateLimited(
                key: "Socks5UDPRelay.unauthorized-client",
                minimumInterval: 10,
                level: .warning,
                phase: .relay,
                category: .relayUDP,
                component: "Socks5UDPRelay",
                event: "unauthorized-client-datagram",
                result: "dropped",
                message: "Dropped UDP ASSOCIATE datagram from an endpoint outside the established client association"
            )
        }
    }

    private func openSocket() throws {
        guard socketFD < 0 else { return }

        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(0).bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &addr) {
            bind(fd, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
        }
        guard bindResult == 0 else {
            close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        var actual = sockaddr_in()
        var actualLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &actual) {
            getsockname(fd, UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self), &actualLen)
        }
        guard nameResult == 0 else {
            let error = POSIXError(.init(rawValue: errno) ?? .EINVAL)
            close(fd)
            throw error
        }
        port = UInt16(bigEndian: actual.sin_port)

        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0 else {
            let error = POSIXError(.init(rawValue: errno) ?? .EINVAL)
            close(fd)
            throw error
        }
        guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            let error = POSIXError(.init(rawValue: errno) ?? .EINVAL)
            close(fd)
            throw error
        }

        socketFD = fd
    }

    private func closeSocketIfNeeded() {
        guard socketFD >= 0 else { return }
        close(socketFD)
        socketFD = -1
        port = 0
    }

    private func performOnQueue(_ work: () -> Void) {
        if DispatchQueue.getSpecific(key: queueSpecificKey) == queueSpecificValue {
            work()
        } else {
            queue.sync(execute: work)
        }
    }
}
