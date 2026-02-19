// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Darwin
import Foundation
import Network
@preconcurrency import NetworkExtension
import RelativeProtocolCore

protocol Socks5UDPRelayProtocol: AnyObject {
    var port: UInt16 { get }
    func start()
    func stop()
}

final class Socks5UDPRelay {
    private struct SessionKey: Hashable {
        let address: Socks5Address
        let port: UInt16
    }

    private struct SessionEntry {
        let address: Socks5Address
        let port: UInt16
        let session: Socks5UDPSession
        var lastActivity: TimeInterval
    }

    private let logger = RelativeLog.logger(.tunnel)
    private let provider: Socks5ConnectionProvider
    private let queue: DispatchQueue
    private let mtu: Int
    private let sessionIdleTimeout: TimeInterval = 60
    private let sessionCleanupInterval: TimeInterval = 15
    private let maxSessions = 256
    private var readBuffer: [UInt8]
    private var socketFD: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var cleanupTimer: DispatchSourceTimer?
    private var sessions: [SessionKey: SessionEntry] = [:]
    private var clientAddress = sockaddr_storage()
    private var clientAddressLen: socklen_t = 0
    private(set) var port: UInt16 = 0

    init(provider: Socks5ConnectionProvider, queue: DispatchQueue, mtu: Int) throws {
        self.provider = provider
        self.queue = queue
        self.mtu = max(256, mtu)
        self.readBuffer = Array(repeating: 0, count: self.mtu + 256)
        try openSocket()
    }

    func start() {
        guard socketFD >= 0 else { return }
        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainReadable()
        }
        source.setCancelHandler { [socketFD] in
            close(socketFD)
        }
        source.resume()
        readSource = source
        startSessionCleanupTimer()
    }

    func stop() {
        readSource?.cancel()
        readSource = nil
        cleanupTimer?.cancel()
        cleanupTimer = nil
        sessions.values.forEach { $0.session.cancel() }
        sessions.removeAll()
    }

    private func drainReadable() {
        while true {
            var addr = sockaddr_storage()
            var addrLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let bytes = readBuffer.withUnsafeMutableBytes { rawBuffer -> ssize_t in
                guard let baseAddress = rawBuffer.baseAddress else { return -1 }
                return recvfrom(socketFD, baseAddress, rawBuffer.count, 0, withUnsafeMutablePointer(to: &addr) {
                    UnsafeMutableRawPointer($0).assumingMemoryBound(to: sockaddr.self)
                }, &addrLen)
            }
            if bytes < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    break
                }
                logger.error("udp relay recv failed: errno=\(errno, privacy: .public)")
                break
            }
            guard bytes > 0 else { break }

            guard let packet = readBuffer.withUnsafeBufferPointer({ ptr in
                Socks5Codec.parseUDPPacket(ptr, count: bytes)
            }) else { continue }
            clientAddress = addr
            clientAddressLen = addrLen

            let key = SessionKey(address: packet.address, port: packet.port)
            if sessions[key] == nil {
                _ = createSession(for: key)
            }
            touchSession(for: key)
            guard let entry = sessions[key] else { continue }
            entry.session.writeDatagram(packet.payload) { error in
                if let error {
                    self.logger.error("udp relay write failed: \(error.localizedDescription, privacy: .public)")
                    self.queue.async {
                        self.removeSession(for: key)
                    }
                }
            }
        }
    }

    private func createSession(for key: SessionKey) -> SessionEntry {
        let hostString: String
        switch key.address {
        case .ipv4(let value), .ipv6(let value), .domain(let value):
            hostString = value
        }
        let endpoint = NWHostEndpoint(hostname: hostString, port: String(key.port))
        let session = provider.makeUDPSession(to: endpoint)
        session.setReadHandler({ [weak self] (datagrams: [Data]?, error: Error?) in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.logger.error("udp relay read error: \(error.localizedDescription, privacy: .public)")
                    self.removeSession(for: key)
                    return
                }
                guard let datagrams, !datagrams.isEmpty else { return }
                self.touchSession(for: key)
                for datagram in datagrams {
                    let response = Socks5Codec.buildUDPPacket(address: key.address, port: key.port, payload: datagram)
                    self.sendToClient(response)
                }
            }
        }, maxDatagrams: 32)

        evictSessionsIfNeeded()
        let entry = SessionEntry(
            address: key.address,
            port: key.port,
            session: session,
            lastActivity: TunnelTime.nowMonotonicSeconds()
        )
        sessions[key] = entry
        return entry
    }

    private func startSessionCleanupTimer() {
        cleanupTimer?.cancel()
        cleanupTimer = nil
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + sessionCleanupInterval,
            repeating: sessionCleanupInterval
        )
        timer.setEventHandler { [weak self] in
            self?.pruneIdleSessions()
        }
        timer.resume()
        cleanupTimer = timer
    }

    private func touchSession(for key: SessionKey) {
        guard var entry = sessions[key] else { return }
        entry.lastActivity = TunnelTime.nowMonotonicSeconds()
        sessions[key] = entry
    }

    private func removeSession(for key: SessionKey) {
        guard let entry = sessions.removeValue(forKey: key) else { return }
        entry.session.cancel()
    }

    private func pruneIdleSessions() {
        let now = TunnelTime.nowMonotonicSeconds()
        let expiredKeys = sessions.compactMap { (key, entry) -> SessionKey? in
            now - entry.lastActivity >= sessionIdleTimeout ? key : nil
        }
        for key in expiredKeys {
            removeSession(for: key)
        }
    }

    private func evictSessionsIfNeeded() {
        while sessions.count >= maxSessions {
            guard let oldestKey = sessions.min(by: { $0.value.lastActivity < $1.value.lastActivity })?.key else {
                break
            }
            removeSession(for: oldestKey)
        }
    }

    private func sendToClient(_ data: Data) {
        guard clientAddressLen > 0 else { return }
        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            let sent = withUnsafePointer(to: &clientAddress) {
                sendto(socketFD, base, data.count, 0, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), clientAddressLen)
            }
            if sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK {
                logger.error("udp relay send failed: errno=\(errno, privacy: .public)")
            }
        }
    }

    private func openSocket() throws {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EINVAL) }

        var addr = sockaddr_in()
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
        if nameResult == 0 {
            port = UInt16(bigEndian: actual.sin_port)
        }

        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 {
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }

        socketFD = fd
    }
}

extension Socks5UDPRelay: Socks5UDPRelayProtocol {}
