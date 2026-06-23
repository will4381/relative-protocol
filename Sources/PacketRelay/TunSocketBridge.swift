// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Darwin
import Foundation
import Observability

/// Result of attempting to hand one packet to the dataplane bridge.
public enum BridgeWriteResult: Sendable, Equatable {
    /// Packet was written immediately or accepted into the bridge's internal queue.
    case accepted
    /// Bridge queue is saturated and caller should retry later without dropping the packet.
    case backpressured
    /// Bridge hit a non-recoverable write failure.
    case failed(errorCode: Int32)
}

/// Bridges NE packetFlow data into a file descriptor pair consumed by the dataplane engine.
/// Queue ownership: read/write sources and pending write state are only touched on `queue`.
public final class TunSocketBridge: @unchecked Sendable {
    private enum PacketSizing {
        static let frameHeaderBytes = MemoryLayout<UInt32>.size
        static let maxIPPacketBytes = 65_535
        static let maxBridgeFrameBytes = frameHeaderBytes + maxIPPacketBytes
    }

    private let logger: StructuredLogger
    private let mtu: Int
    private let queue: DispatchQueue
    private let lifecycleLock = NSLock()
    private let queueSpecificKey = DispatchSpecificKey<UUID>()
    private let queueSpecificValue = UUID()
    private let appFD: Int32
    public let engineFD: Int32

    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private var writeSourceActive = false
    private var pendingWrites: ArraySlice<Data> = []
    private var pendingBytes = 0
    private var backpressureSignals: UInt64 = 0
    private let maxPendingBytes: Int
    private let backpressureThreshold: Int
    private var readBuffer: [UInt8]
    private var isStopped = false

    public var onBackpressureRelieved: (@Sendable () -> Void)?

    /// - Parameters:
    ///   - mtu: Expected tunnel MTU used to size buffers.
    ///   - queue: Serial queue for socket read/write dispatch sources.
    ///   - logger: Structured logger for bridge errors and backpressure events.
    public init(mtu: Int, queue: DispatchQueue, logger: StructuredLogger) throws {
        self.logger = logger
        self.mtu = min(max(256, mtu), 65_535)
        self.queue = queue
        queue.setSpecific(key: queueSpecificKey, value: queueSpecificValue)
        self.maxPendingBytes = max(4_194_304, self.mtu * 1024)
        self.backpressureThreshold = maxPendingBytes * 3 / 4
        // Apple NEPacketTunnelFlow read/write APIs move full IP packets; the configured MTU is an interface policy,
        // not a safe receive-buffer ceiling for dataplane recovery paths.
        self.readBuffer = [UInt8](repeating: 0, count: PacketSizing.maxBridgeFrameBytes)

        var fds = [Int32](repeating: 0, count: 2)
        let result = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard result == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        engineFD = fds[0]
        appFD = fds[1]

        setSocketBuffer(fd: engineFD)
        setSocketBuffer(fd: appFD)

        do {
            try setNonBlocking(fd: engineFD)
            try setNonBlocking(fd: appFD)
        } catch {
            close(engineFD)
            close(appFD)
            throw error
        }

        let writeSource = DispatchSource.makeWriteSource(fileDescriptor: appFD, queue: queue)
        writeSource.setEventHandler { [weak self] in
            self?.drainWritable()
        }
        self.writeSource = writeSource
    }

    deinit {
        stop()
    }

    /// Starts consuming packets written by the dataplane and forwards decoded frames to `handler`.
    /// - Parameter handler: Called with a packet batch and per-packet address family values.
    public func startReadLoop(handler: @escaping @Sendable ([Data], [Int32]) -> Void) {
        performOnQueue {
            lifecycleLock.lock()
            guard !isStopped, readSource == nil else {
                lifecycleLock.unlock()
                return
            }

            let source = DispatchSource.makeReadSource(fileDescriptor: appFD, queue: queue)
            source.setEventHandler { [weak self] in
                self?.drainReadable(handler: handler)
            }
            source.setCancelHandler { [appFD] in
                close(appFD)
            }
            readSource = source
            lifecycleLock.unlock()
            source.resume()
        }
    }

    @discardableResult
    /// Enqueues one packet for dataplane consumption.
    /// - Parameters:
    ///   - packet: Full IP packet from `NEPacketTunnelFlow`.
    ///   - ipVersionHint: Optional family hint (`AF_INET` or `AF_INET6`).
    /// - Returns: Bridge acceptance, saturation, or terminal failure status.
    public func writePacket(_ packet: Data, ipVersionHint: Int32) -> BridgeWriteResult {
        if DispatchQueue.getSpecific(key: queueSpecificKey) != queueSpecificValue {
            var result = BridgeWriteResult.backpressured
            performOnQueue {
                result = writePacketOnQueue(packet, ipVersionHint: ipVersionHint)
            }
            return result
        }
        return writePacketOnQueue(packet, ipVersionHint: ipVersionHint)
    }

    private func writePacketOnQueue(_ packet: Data, ipVersionHint: Int32) -> BridgeWriteResult {
        // Refuse writes once stopped: the descriptors are closed (or about to close), and the kernel can
        // recycle those fd numbers, so a late writev would corrupt an unrelated descriptor.
        lifecycleLock.lock()
        let stopped = isStopped
        lifecycleLock.unlock()
        guard !stopped else {
            return .failed(errorCode: EBADF)
        }

        var family: Int32 = ipVersionHint
        if family != AF_INET && family != AF_INET6 {
            family = packet.first.map { (($0 >> 4) & 0x0F) == 6 ? AF_INET6 : AF_INET } ?? AF_INET
        }

        guard let expectedLength = frameLength(for: packet) else {
            return .failed(errorCode: EMSGSIZE)
        }

        if pendingWrites.isEmpty {
            let result = writePacketImmediate(packet, family: family)
            if result == expectedLength {
                return .accepted
            }
            if result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                return enqueueWrite(framedPacket(packet, family: family, expectedLength: expectedLength))
            }
            let errorCode = Int32(errno)
            Task {
                await logger.log(
                    level: .error,
                    phase: .relay,
                    category: .control,
                    component: "TunSocketBridge",
                    event: "write-immediate-failed",
                    errorCode: String(errorCode),
                    message: "Failed to write packet to bridge"
                )
            }
            return .failed(errorCode: errorCode)
        }

        return enqueueWrite(framedPacket(packet, family: family, expectedLength: expectedLength))
    }

    /// Returns whether queued bytes have crossed the backpressure threshold.
    public func isBackpressured() -> Bool {
        var result = false
        performOnQueue {
            result = pendingBytes >= backpressureThreshold
        }
        return result
    }

    /// Stops read/write sources and closes owned descriptors.
    public func stop() {
        lifecycleLock.lock()
        guard !isStopped else {
            lifecycleLock.unlock()
            return
        }
        isStopped = true
        lifecycleLock.unlock()

        // `writeSourceActive` is only mutated on `queue`, so the suspend/resume balance for the write source
        // must also be decided on `queue`. Reading it off-queue can race `drainWritable` and either cancel a
        // suspended source or over-resume an active one.
        performOnQueue {
            lifecycleLock.lock()
            let source = readSource
            readSource = nil
            let writeSource = self.writeSource
            self.writeSource = nil
            lifecycleLock.unlock()

            if let source {
                source.cancel()
            } else {
                close(appFD)
            }

            if let writeSource {
                if !writeSourceActive {
                    writeSource.resume()
                }
                writeSource.cancel()
            }
            writeSourceActive = false

            pendingWrites.removeAll(keepingCapacity: false)
            pendingBytes = 0
            onBackpressureRelieved = nil
        }
        close(engineFD)
    }

    private func drainReadable(handler: @escaping @Sendable ([Data], [Int32]) -> Void) {
        let bufferSize = PacketSizing.maxBridgeFrameBytes
        if readBuffer.count != bufferSize {
            readBuffer = [UInt8](repeating: 0, count: bufferSize)
        }

        let batchLimit = 32
        var packets: [Data] = []
        var families: [Int32] = []
        packets.reserveCapacity(batchLimit)
        families.reserveCapacity(batchLimit)

        while true {
            let bytesRead = readBuffer.withUnsafeMutableBufferPointer { bufferPtr -> Int in
                guard let base = bufferPtr.baseAddress else { return -1 }
                return recv(appFD, base, bufferPtr.count, 0)
            }
            if bytesRead < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    break
                }
                Task {
                    await logger.log(
                        level: .error,
                        phase: .relay,
                        category: .control,
                        component: "TunSocketBridge",
                        event: "read-failed",
                        errorCode: String(errno),
                        message: "Bridge read failed"
                    )
                }
                break
            }
            guard bytesRead > 0 else { break }
            guard bytesRead > MemoryLayout<UInt32>.size else { continue }

            let headerSize = MemoryLayout<UInt32>.size
            let payloadRange = headerSize ..< bytesRead
            let payload = Data(readBuffer[payloadRange])
            let familyRaw = (UInt32(readBuffer[0]) << 24)
                | (UInt32(readBuffer[1]) << 16)
                | (UInt32(readBuffer[2]) << 8)
                | UInt32(readBuffer[3])
            var family = Int32(familyRaw)
            if family != AF_INET && family != AF_INET6 {
                family = payload.first.map { (($0 >> 4) & 0x0F) == 6 ? AF_INET6 : AF_INET } ?? AF_INET
            }

            packets.append(payload)
            families.append(family)
            if packets.count >= batchLimit {
                handler(packets, families)
                packets.removeAll(keepingCapacity: true)
                families.removeAll(keepingCapacity: true)
            }
        }

        if !packets.isEmpty {
            handler(packets, families)
        }
    }

    private func enqueueWrite(_ data: Data) -> BridgeWriteResult {
        let remainingCapacity = max(0, maxPendingBytes - pendingBytes)
        if data.count > remainingCapacity {
            backpressureSignals &+= 1
            if backpressureSignals == 1 || backpressureSignals % 100 == 0 {
                Task {
                    await logger.log(
                        level: .notice,
                        phase: .relay,
                        category: .control,
                        component: "TunSocketBridge",
                        event: "write-backpressured",
                        result: "retry",
                        message: "Bridge write queue is saturated",
                        metadata: [
                            "signals": String(backpressureSignals),
                            "pending_bytes": String(pendingBytes),
                            "max_pending_bytes": String(maxPendingBytes)
                        ]
                    )
                }
            }
            return .backpressured
        }
        pendingWrites.append(data)
        pendingBytes += data.count
        startWriteSourceIfNeeded()
        return .accepted
    }

    private func drainWritable() {
        let wasBackpressured = pendingBytes >= backpressureThreshold

        while let next = pendingWrites.first {
            let result = next.withUnsafeBytes { ptr -> ssize_t in
                guard let base = ptr.baseAddress else { return -1 }
                return write(appFD, base, next.count)
            }
            if result == next.count {
                pendingWrites.removeFirst()
                pendingBytes -= next.count
                continue
            }
            if result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                break
            }
            pendingWrites.removeFirst()
            pendingBytes -= next.count
            Task {
                await logger.log(
                    level: .error,
                    phase: .relay,
                    category: .control,
                    component: "TunSocketBridge",
                    event: "write-drain-failed",
                    errorCode: String(errno),
                    message: "Bridge write drain failed"
                )
            }
        }

        if pendingWrites.isEmpty {
            stopWriteSourceIfNeeded()
            pendingWrites.removeAll(keepingCapacity: false)
        }

        let isBackpressured = pendingBytes >= backpressureThreshold
        if wasBackpressured && !isBackpressured {
            onBackpressureRelieved?()
        }
    }

    private func startWriteSourceIfNeeded() {
        guard let writeSource, !writeSourceActive else { return }
        writeSource.resume()
        writeSourceActive = true
    }

    private func stopWriteSourceIfNeeded() {
        guard let writeSource, writeSourceActive else { return }
        writeSource.suspend()
        writeSourceActive = false
    }

    private func setSocketBuffer(fd: Int32) {
        var size = Int32(maxPendingBytes)
        let sendResult = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        if sendResult != 0 {
            Task {
                await logger.log(
                    level: .warning,
                    phase: .relay,
                    category: .control,
                    component: "TunSocketBridge",
                    event: "setsockopt-sndbuf-failed",
                    errorCode: String(errno),
                    message: "Failed to set SO_SNDBUF"
                )
            }
        }

        size = Int32(maxPendingBytes)
        let recvResult = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        if recvResult != 0 {
            Task {
                await logger.log(
                    level: .warning,
                    phase: .relay,
                    category: .control,
                    component: "TunSocketBridge",
                    event: "setsockopt-rcvbuf-failed",
                    errorCode: String(errno),
                    message: "Failed to set SO_RCVBUF"
                )
            }
        }
    }

    private func setNonBlocking(fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }
    }

    private func framedPacket(_ packet: Data, family: Int32, expectedLength: Int) -> Data {
        var header = UInt32(family).bigEndian
        var buffer = Data(capacity: expectedLength)
        withUnsafeBytes(of: &header) { headerPtr in
            buffer.append(headerPtr.bindMemory(to: UInt8.self))
        }
        buffer.append(packet)
        return buffer
    }

    private func frameLength(for packet: Data) -> Int? {
        let (length, overflow) = MemoryLayout<UInt32>.size.addingReportingOverflow(packet.count)
        guard !overflow, length <= PacketSizing.maxBridgeFrameBytes else {
            return nil
        }
        return length
    }

    private func writePacketImmediate(_ packet: Data, family: Int32) -> Int {
        var header = UInt32(family).bigEndian
        return withUnsafeBytes(of: &header) { headerPtr -> Int in
            packet.withUnsafeBytes { packetPtr -> Int in
                var iov = [
                    iovec(
                        iov_base: UnsafeMutableRawPointer(mutating: headerPtr.baseAddress),
                        iov_len: headerPtr.count
                    ),
                    iovec(
                        iov_base: UnsafeMutableRawPointer(mutating: packetPtr.baseAddress),
                        iov_len: packetPtr.count
                    )
                ]
                return writev(appFD, &iov, Int32(iov.count))
            }
        }
    }

    private func performOnQueue(_ work: () -> Void) {
        if DispatchQueue.getSpecific(key: queueSpecificKey) == queueSpecificValue {
            work()
        } else {
            queue.sync(execute: work)
        }
    }
}
