// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Darwin
import Foundation
import RelativeProtocolCore

final class TunSocketBridge {
    private let logger = RelativeLog.logger(.tunnel)
    private let mtu: Int
    private let queue: DispatchQueue
    private let appFD: Int32
    let engineFD: Int32
    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private var writeSourceActive = false
    private var pendingWrites: [Data] = []
    private var pendingBytes: Int = 0
    private var droppedWrites: UInt64 = 0
    private let maxPendingBytes: Int
    private let backpressureThreshold: Int

    init(mtu: Int, queue: DispatchQueue) throws {
        self.mtu = max(256, mtu)
        self.queue = queue
        self.maxPendingBytes = max(4_194_304, self.mtu * 1024)
        self.backpressureThreshold = maxPendingBytes * 3 / 4

        var fds = [Int32](repeating: 0, count: 2)
        let result = socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard result == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EINVAL)
        }

        engineFD = fds[0]
        appFD = fds[1]

        setSocketBuffer(fd: engineFD)
        setSocketBuffer(fd: appFD)

        try setNonBlocking(fd: engineFD)
        try setNonBlocking(fd: appFD)

        let writeSource = DispatchSource.makeWriteSource(fileDescriptor: appFD, queue: queue)
        writeSource.setEventHandler { [weak self] in
            self?.drainWritable()
        }
        self.writeSource = writeSource
    }

    func startReadLoop(handler: @escaping ([Data], [Int32]) -> Void) {
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

    func writePacket(_ packet: Data, ipVersionHint: Int32) -> Bool {
        var family: Int32 = ipVersionHint
        if family != AF_INET && family != AF_INET6 {
            family = packet.first.map { (($0 >> 4) & 0x0F) == 6 ? AF_INET6 : AF_INET } ?? AF_INET
        }

        var header = UInt32(family).bigEndian
        var buffer = Data(capacity: MemoryLayout<UInt32>.size + packet.count)
        withUnsafeBytes(of: &header) { headerPtr in
            buffer.append(headerPtr.bindMemory(to: UInt8.self))
        }
        buffer.append(packet)

        if pendingWrites.isEmpty {
            let result = buffer.withUnsafeBytes { ptr -> ssize_t in
                guard let base = ptr.baseAddress else { return -1 }
                return write(appFD, base, buffer.count)
            }
            if result == buffer.count {
                return true
            }
            if result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                return enqueueWrite(buffer)
            }
            if result < 0 {
                logger.error("tun write failed: errno=\(errno, privacy: .public)")
            }
            return false
        } else {
            return enqueueWrite(buffer)
        }
    }

    func isBackpressured() -> Bool {
        pendingBytes >= backpressureThreshold
    }

    func stop() {
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
        close(engineFD)
    }

    private func drainReadable(handler: @escaping ([Data], [Int32]) -> Void) {
        let bufferSize = mtu + MemoryLayout<UInt32>.size
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        let batchLimit = 32
        var packets: [Data] = []
        var families: [Int32] = []
        packets.reserveCapacity(batchLimit)
        families.reserveCapacity(batchLimit)

        while true {
            let bytesRead = recv(appFD, &buffer, buffer.count, 0)
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
            let payload = Data(buffer[payloadRange])
            let headerBytes = buffer[0..<headerSize]
            var familyValue: UInt32 = 0
            withUnsafeMutableBytes(of: &familyValue) { ptr in
                ptr.copyBytes(from: headerBytes)
            }
            var family = Int32(UInt32(bigEndian: familyValue))
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
        while !pendingWrites.isEmpty {
            let next = pendingWrites[0]
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
            break
        }

        if pendingWrites.isEmpty {
            stopWriteSourceIfNeeded()
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
        let result = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        if result != 0 {
            logger.error("tun setsockopt SO_SNDBUF failed: errno=\(errno, privacy: .public)")
        }
        size = Int32(maxPendingBytes)
        let recvResult = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        if recvResult != 0 {
            logger.error("tun setsockopt SO_RCVBUF failed: errno=\(errno, privacy: .public)")
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
}
