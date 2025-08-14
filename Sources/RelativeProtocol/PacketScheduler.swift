import Foundation

final class PacketScheduler {
	struct Item {
		let data: Data
		let proto: NSNumber
		let size: Int
	}

	private let queue = DispatchQueue(label: "com.relativeprotocol.scheduler")
	private var timer: DispatchSourceTimer?
	private var backlog: [Item] = []
	private var enqueuedBytes: Int = 0
	private var bytesPerSecond: Int
	private var tokens: Int
	private let tickMs: Int
	private let emit: (_ packets: [Data], _ protocols: [NSNumber]) -> Void
	private let maxEnqueuedBytes: Int
	private let backpressure: ((Bool) -> Void)?
	private var isBackpressured = false

	init(rateBytesPerSecond: Int = Int.max, tickMs: Int = 10, maxEnqueuedBytes: Int = Int.max, backpressure: ((Bool) -> Void)? = nil, emit: @escaping (_ packets: [Data], _ protocols: [NSNumber]) -> Void) {
		self.bytesPerSecond = rateBytesPerSecond
		self.tokens = rateBytesPerSecond
		self.tickMs = tickMs
		self.maxEnqueuedBytes = maxEnqueuedBytes
		self.backpressure = backpressure
		self.emit = emit
	}

	func start() {
		queue.async {
			guard self.timer == nil else { return }
			let t = DispatchSource.makeTimerSource(queue: self.queue)
			t.schedule(deadline: .now() + .milliseconds(self.tickMs), repeating: .milliseconds(self.tickMs))
			t.setEventHandler { [weak self] in self?.onTick() }
			self.timer = t
			t.resume()
		}
	}

	func stop() {
		queue.async {
			self.timer?.cancel()
			self.timer = nil
			self.backlog.removeAll(keepingCapacity: false)
		}
	}

	func setRate(bytesPerSecond: Int) {
		queue.async {
			self.bytesPerSecond = bytesPerSecond
			self.tokens = min(self.tokens, bytesPerSecond)
		}
	}

	func enqueue(_ data: Data, proto: NSNumber) {
		queue.async {
			self.backlog.append(Item(data: data, proto: proto, size: data.count))
			self.enqueuedBytes += data.count
			if self.enqueuedBytes > self.maxEnqueuedBytes && !self.isBackpressured {
				self.isBackpressured = true
				self.backpressure?(true)
			}
		}
	}

	private func onTick() {
		// Refill tokens
		if bytesPerSecond == Int.max {
			// Unlimited: flush all immediately
			if !backlog.isEmpty {
				let toSend = backlog
				backlog.removeAll(keepingCapacity: false)
				enqueuedBytes = 0
				if isBackpressured {
					isBackpressured = false
					backpressure?(false)
				}
				emit(toSend.map { $0.data }, toSend.map { $0.proto })
			}
			return
		}
		let refill = bytesPerSecond * tickMs / 1000
		tokens = min(tokens + refill, bytesPerSecond)
		guard !backlog.isEmpty, tokens > 0 else { return }
		var batch: [Item] = []
		var used = 0
		while let first = backlog.first, used + first.size <= tokens {
			batch.append(first)
			used += first.size
			backlog.removeFirst()
		}
		if !batch.isEmpty {
			tokens -= used
			enqueuedBytes -= used
			if isBackpressured && enqueuedBytes < maxEnqueuedBytes / 2 {
				isBackpressured = false
				backpressure?(false)
			}
			emit(batch.map { $0.data }, batch.map { $0.proto })
		}
	}
}


