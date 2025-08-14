import Foundation
import Network

final class TokenBucketLimiter<Payload> {
    typealias Sender = (_ payload: Payload) -> Void

    private let queue: DispatchQueue
    private var rateBytesPerSecond: Int
    private var tokens: Int
    private let tickMs: Int
    private var backlog: [Payload] = []
    private var timer: DispatchSourceTimer?
    private let sizeOf: (Payload) -> Int
    private let send: Sender
    private var onQueueDepthChanged: ((Int) -> Void)?

    init(label: String, rateBytesPerSecond: Int, tickMs: Int = 10, sizeOf: @escaping (Payload) -> Int, send: @escaping Sender, onQueueDepthChanged: ((Int) -> Void)? = nil) {
        self.queue = DispatchQueue(label: label)
        self.rateBytesPerSecond = rateBytesPerSecond
        self.tokens = rateBytesPerSecond
        self.tickMs = tickMs
        self.sizeOf = sizeOf
        self.send = send
        self.onQueueDepthChanged = onQueueDepthChanged
    }

    func setRate(bytesPerSecond: Int) {
        queue.async { self.rateBytesPerSecond = bytesPerSecond; self.tokens = min(self.tokens, bytesPerSecond) }
    }

    func enqueue(_ payload: Payload) {
        queue.async {
            self.backlog.append(payload)
            self.onQueueDepthChanged?(self.backlog.count)
            self.ensureTimer()
        }
    }

    private func ensureTimer() {
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(tickMs), repeating: .milliseconds(tickMs))
        t.setEventHandler { [weak self] in self?.onTick() }
        timer = t
        t.resume()
    }

    private func onTick() {
        if rateBytesPerSecond == Int.max {
            while !backlog.isEmpty {
                let item = backlog.removeFirst()
                send(item)
            }
            onQueueDepthChanged?(backlog.count)
            stopIfIdle()
            return
        }
        let refill = rateBytesPerSecond * tickMs / 1000
        tokens = min(tokens + refill, rateBytesPerSecond)
        var used = 0
        var toSend: [Payload] = []
        while let first = backlog.first, used + sizeOf(first) <= tokens {
            used += sizeOf(first)
            toSend.append(first)
            backlog.removeFirst()
        }
        tokens -= used
        for item in toSend { send(item) }
        onQueueDepthChanged?(backlog.count)
        stopIfIdle()
    }

    private func stopIfIdle() {
        if backlog.isEmpty && rateBytesPerSecond == Int.max {
            timer?.cancel(); timer = nil
        }
    }
}


