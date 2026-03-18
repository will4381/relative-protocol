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
        self.mtu = max(256, mtu)
        self.queue = queue
        queue.setSpecific(key: queueSpecificKey, value: queueSpecificValue)
        self.maxPendingBytes = max(4_194_304, self.mtu * 1024)
        self.backpressureThreshold = maxPendingBytes * 3 / 4
        self.readBuffer = [UInt8](repeating: 0, count: self.mtu + MemoryLayout<UInt32>.size)

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

    deinit {
        stop()
    }

    /// Starts consuming packets written by the dataplane and forwards decoded frames to `handler`.
    /// - Parameter handler: Called with a packet batch and per-packet address family values.
    public func startReadLoop(handler: @escaping @Sendable ([Data], [Int32]) -> Void) {
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

    @discardableResult
    /// Enqueues one packet for dataplane consumption.
    /// - Parameters:
    ///   - packet: Full IP packet from `NEPacketTunnelFlow`.
    ///   - ipVersionHint: Optional family hint (`AF_INET` or `AF_INET6`).
    /// - Returns: Bridge acceptance, saturation, or terminal failure status.
    public func writePacket(_ packet: Data, ipVersionHint: Int32) -> BridgeWriteResult {
        var family: Int32 = ipVersionHint
        if family != AF_INET && family != AF_INET6 {
            family = packet.first.map { (($0 >> 4) & 0x0F) == 6 ? AF_INET6 : AF_INET } ?? AF_INET
        }

        if pendingWrites.isEmpty {
            let expectedLength = MemoryLayout<UInt32>.size + packet.count
            let result = writePacketImmediate(packet, family: family)
            if result == expectedLength {
                return .accepted
            }
            if result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                return enqueueWrite(framedPacket(packet, family: family))
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

        return enqueueWrite(framedPacket(packet, family: family))
    }

    /// Returns whether queued bytes have crossed the backpressure threshold.
    public func isBackpressured() -> Bool {
        pendingBytes >= backpressureThreshold
    }

    /// Stops read/write sources and closes owned descriptors.
    public func stop() {
        let source: DispatchSourceRead?
        let writeSource: DispatchSourceWrite?
        let shouldResumeWriteSource: Bool

        lifecycleLock.lock()
        guard !isStopped else {
            lifecycleLock.unlock()
            return
        }
        isStopped = true
        source = readSource
        readSource = nil
        writeSource = self.writeSource
        self.writeSource = nil
        shouldResumeWriteSource = writeSource != nil && !writeSourceActive
        writeSourceActive = false
        lifecycleLock.unlock()

        performOnQueue {
            if let source {
                source.cancel()
            } else {
                close(appFD)
            }

            if let writeSource {
                if shouldResumeWriteSource {
                    writeSource.resume()
                }
                writeSource.cancel()
            }

            pendingWrites.removeAll(keepingCapacity: false)
            pendingBytes = 0
            onBackpressureRelieved = nil
        }
        close(engineFD)
    }

    private func drainReadable(handler: @escaping @Sendable ([Data], [Int32]) -> Void) {
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
        if pendingBytes + data.count > maxPendingBytes {
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

    private func performOnQueue(_ work: () -> Void) {
        if DispatchQueue.getSpecific(key: queueSpecificKey) == queueSpecificValue {
            work()
        } else {
            queue.sync(execute: work)
        }
    }
}
