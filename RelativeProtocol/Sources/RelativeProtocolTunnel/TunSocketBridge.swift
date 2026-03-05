// Copyright (c) 2026 Relative Companies Inc.
// See LICENSE for terms.
// Created by Will Kusch 1/23/26

import Darwin
import Foundation
import RelativeProtocolCore

struct TunSocketBufferStats: Sendable {
    let requestedBytes: Int
    let appSendBytes: Int
    let appReceiveBytes: Int
    let engineSendBytes: Int
    let engineReceiveBytes: Int

    var effectiveSendBytes: Int {
        min(appSendBytes, engineSendBytes)
    }

    var effectiveReceiveBytes: Int {
        min(appReceiveBytes, engineReceiveBytes)
    }

    var wasCapped: Bool {
        appSendBytes < requestedBytes
            || appReceiveBytes < requestedBytes
            || engineSendBytes < requestedBytes
            || engineReceiveBytes < requestedBytes
    }
}

struct TunSocketQueueStats: Sendable {
    let pendingPackets: Int
    let pendingBytes: Int
    let droppedWrites: UInt64
    let backpressured: Bool
    let maxPendingBytes: Int
}

final class TunSocketBridge {
    private let logger = RelativeLog.logger(.tunnel)
    private let mtu: Int
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<Void>()
    private let appFD: Int32
    let engineFD: Int32
    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private var writeSourceActive = false
    private var pendingWrites: ArraySlice<Data> = []
    private var pendingBytes: Int = 0
    private var droppedWrites: UInt64 = 0
    private let maxPendingBytes: Int
    private let backpressureThreshold: Int
    private var socketBufferStatsValue: TunSocketBufferStats
    private var readBuffer: [UInt8]
    var onBackpressureRelieved: (() -> Void)?

    init(mtu: Int, queue: DispatchQueue) throws {
        self.mtu = max(256, mtu)
        self.queue = queue
        self.maxPendingBytes = max(524_288, self.mtu * 256)
        self.backpressureThreshold = maxPendingBytes * 3 / 4
        self.readBuffer = [UInt8](repeating: 0, count: self.mtu + MemoryLayout<UInt32>.size)
        self.socketBufferStatsValue = TunSocketBufferStats(
            requestedBytes: maxPendingBytes,
            appSendBytes: maxPendingBytes,
            appReceiveBytes: maxPendingBytes,
            engineSendBytes: maxPendingBytes,
            engineReceiveBytes: maxPendingBytes
        )

        var fds = [Int32](repeating: 0, count: 2)
        let result = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard result == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        engineFD = fds[0]
        appFD = fds[1]

        let engineBuffers = setSocketBuffer(fd: engineFD)
        let appBuffers = setSocketBuffer(fd: appFD)
        self.socketBufferStatsValue = TunSocketBufferStats(
            requestedBytes: maxPendingBytes,
            appSendBytes: appBuffers.send,
            appReceiveBytes: appBuffers.recv,
            engineSendBytes: engineBuffers.send,
            engineReceiveBytes: engineBuffers.recv
        )
        if socketBufferStatsValue.wasCapped {
            logger.warning(
                "tun socket buffers capped by kernel requested=\(self.maxPendingBytes, privacy: .public) appSend=\(appBuffers.send, privacy: .public) appRecv=\(appBuffers.recv, privacy: .public) engineSend=\(engineBuffers.send, privacy: .public) engineRecv=\(engineBuffers.recv, privacy: .public)"
            )
        }

        try setNonBlocking(fd: engineFD)
        try setNonBlocking(fd: appFD)

        let writeSource = DispatchSource.makeWriteSource(fileDescriptor: appFD, queue: queue)
        writeSource.setEventHandler { [weak self] in
            self?.drainWritable()
        }
        self.writeSource = writeSource
        self.queue.setSpecific(key: queueKey, value: ())
    }

    func startReadLoop(handler: @escaping ([Data], [Int32]) -> Void) {
        runSyncOnQueue {
            let source = DispatchSource.makeReadSource(fileDescriptor: appFD, queue: queue)
            source.setEventHandler { [weak self] in
                self?.drainReadable(handler: handler)
            }
            source.setCancelHandler { [appFD] in
                close(appFD)
            }
            source.resume()
            readSource = source
        }
    }

    func writePacket(_ packet: Data, ipVersionHint: Int32) -> Bool {
        runSyncOnQueue {
            var family: Int32 = ipVersionHint
            if family != AF_INET && family != AF_INET6 {
                family = packet.first.map { (($0 >> 4) & 0x0F) == 6 ? AF_INET6 : AF_INET } ?? AF_INET
            }

            if pendingWrites.isEmpty {
                let expectedLength = MemoryLayout<UInt32>.size + packet.count
                let result = writePacketImmediate(packet, family: family)
                if result == expectedLength {
                    return true
                }
                if result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                    return enqueueWrite(framedPacket(packet, family: family))
                }
                if result < 0 {
                    logger.error("tun write failed: errno=\(errno, privacy: .public)")
                } else {
                    logger.error("tun write failed: partial datagram write (\(result, privacy: .public) of \(expectedLength, privacy: .public))")
                }
                return false
            } else {
                return enqueueWrite(framedPacket(packet, family: family))
            }
        }
    }

    func isBackpressured() -> Bool {
        runSyncOnQueue {
            pendingBytes >= backpressureThreshold
        }
    }

    func socketBufferStats() -> TunSocketBufferStats {
        runSyncOnQueue {
            socketBufferStatsValue
        }
    }

    func queueStats() -> TunSocketQueueStats {
        runSyncOnQueue {
            TunSocketQueueStats(
                pendingPackets: pendingWrites.count,
                pendingBytes: pendingBytes,
                droppedWrites: droppedWrites,
                backpressured: pendingBytes >= backpressureThreshold,
                maxPendingBytes: maxPendingBytes
            )
        }
    }

    func stop() {
        runSyncOnQueue {
            let source = readSource
            readSource = nil
            if let source {
                source.cancel()
            } else {
                close(appFD)
            }
            if let writeSource {
                if !writeSourceActive {
                    writeSource.resume()
                    writeSourceActive = true
                }
                writeSource.cancel()
                self.writeSource = nil
            }
            pendingWrites.removeAll(keepingCapacity: false)
            pendingBytes = 0
            onBackpressureRelieved = nil
            close(engineFD)
        }
    }

    private func runSyncOnQueue<T>(_ work: () -> T) -> T {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            return work()
        }
        return queue.sync(execute: work)
    }

    private func drainReadable(handler: @escaping ([Data], [Int32]) -> Void) {
        let bufferSize = mtu + MemoryLayout<UInt32>.size
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
                logger.error("tun read failed: errno=\(errno, privacy: .public)")
                break
            }
            guard bytesRead > 0 else { break }
            guard bytesRead > MemoryLayout<UInt32>.size else { continue }

            let headerSize = MemoryLayout<UInt32>.size
            let payloadRange = headerSize..<bytesRead
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

    private func enqueueWrite(_ data: Data) -> Bool {
        if pendingBytes + data.count > maxPendingBytes {
            droppedWrites &+= 1
            if droppedWrites % 100 == 0 {
                logger.error("tun write backlog exceeded; dropped \(self.droppedWrites, privacy: .public) packets")
            }
            return false
        }
        pendingWrites.append(data)
        pendingBytes += data.count
        startWriteSourceIfNeeded()
        return true
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
            if result < 0 {
                logger.error("tun write failed while draining: errno=\(errno, privacy: .public)")
                pendingWrites.removeFirst()
                pendingBytes -= next.count
                continue
            }
            logger.error("tun write failed while draining: partial datagram write (\(result, privacy: .public) of \(next.count, privacy: .public))")
            break
        }

        if pendingWrites.isEmpty {
            stopWriteSourceIfNeeded()
            pendingWrites.removeAll(keepingCapacity: false)
        }

        let isBackpressured = pendingBytes >= backpressureThreshold
        if wasBackpressured && !isBackpressured, let onBackpressureRelieved {
            onBackpressureRelieved()
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

    @discardableResult
    private func setSocketBuffer(fd: Int32) -> (send: Int, recv: Int) {
        var size = Int32(maxPendingBytes)
        let result = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        if result != 0 {
            logger.error("tun setsockopt SO_SNDBUF failed: errno=\(errno, privacy: .public)")
        }
        size = Int32(maxPendingBytes)
        let recvResult = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        if recvResult != 0 {
            logger.error("tun setsockopt SO_RCVBUF failed: errno=\(errno, privacy: .public)")
        }
        let actualSend = socketBufferValue(fd: fd, option: SO_SNDBUF) ?? maxPendingBytes
        let actualRecv = socketBufferValue(fd: fd, option: SO_RCVBUF) ?? maxPendingBytes
        return (send: actualSend, recv: actualRecv)
    }

    private func socketBufferValue(fd: Int32, option: Int32) -> Int? {
        var value: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        let rc = getsockopt(fd, SOL_SOCKET, option, &value, &length)
        guard rc == 0 else {
            logger.error("tun getsockopt failed option=\(option, privacy: .public) errno=\(errno, privacy: .public)")
            return nil
        }
        return Int(value)
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

    private func framedPacket(_ packet: Data, family: Int32) -> Data {
        var header = UInt32(family).bigEndian
        var buffer = Data(capacity: MemoryLayout<UInt32>.size + packet.count)
        withUnsafeBytes(of: &header) { headerPtr in
            buffer.append(headerPtr.bindMemory(to: UInt8.self))
        }
        buffer.append(packet)
        return buffer
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
}

#if DEBUG
extension TunSocketBridge {
    func _test_enqueueWrite(_ data: Data) -> Bool {
        enqueueWrite(data)
    }

    func _test_seedPendingWrites(_ writes: [Data]) {
        pendingWrites = ArraySlice(writes)
        pendingBytes = writes.reduce(0) { $0 + $1.count }
    }

    func _test_drainWritable() {
        drainWritable()
    }

    var _test_pendingWriteCount: Int {
        pendingWrites.count
    }

    var _test_pendingBytes: Int {
        pendingBytes
    }

    var _test_maxPendingBytes: Int {
        maxPendingBytes
    }

    var _test_droppedWrites: UInt64 {
        droppedWrites
    }
}
#endif
