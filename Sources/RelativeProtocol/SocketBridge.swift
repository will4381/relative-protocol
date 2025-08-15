import Foundation
import Network
#if !os(iOS)
@_silgen_name("rlwip_inject_proxynetif")
func rlwip_inject_proxynetif(_ data: UnsafePointer<UInt8>, _ len: Int) -> Int32
#endif

@available(iOS 12.0, macOS 10.14, *)
final class SocketBridge {
	static let shared = SocketBridge()

	protocol Delegate: AnyObject {
		func classify(flow: FlowIdentity) -> String?
	}

	struct FlowIdentity {
		let flowID: String
		let isIPv6: Bool
		let proto: String // "TCP" or "UDP"
		let sourceIP: String
		let sourcePort: UInt16
		let destinationIP: String
		let destinationPort: UInt16
	}

	weak var delegate: Delegate?

#if DEBUG
	var debug_disableNetworkSends: Bool = false
	private(set) var debug_sentData: [String: [Data]] = [:]
	func debug_clearSent() { flowsQueue.async(flags: .barrier) { self.debug_sentData.removeAll() } }
    func debug_flush() { flowsQueue.sync {} }
#endif

	private let lwipQueue = DispatchQueue(label: "com.relativeprotocol.lwip")
    private let flowsQueue = DispatchQueue(label: "com.relativeprotocol.flows", attributes: .concurrent)
    private let limitersQueue = DispatchQueue(label: "com.relativeprotocol.limiters")
    @available(iOS 12.0, macOS 10.14, *)
    private struct UdpFlowMeta {
		let version: Int // 4 or 6
		let srcIP: Data
		let dstIP: Data
		let srcPort: UInt16
		let dstPort: UInt16
		let connection: NWConnection
        let queue: DispatchQueue
		var lastOutboundHeader: Data
		var lastActivity: TimeInterval
		var tag: String?
	}
	private var udpFlows: [String: UdpFlowMeta] = [:]

    @available(iOS 12.0, macOS 10.14, *)
    private struct TcpFlowMeta {
		let version: Int // 4 or 6
		let srcIP: Data
		let dstIP: Data
		let srcPort: UInt16
		let dstPort: UInt16
		let connection: NWConnection
        let queue: DispatchQueue
		var deviceISN: UInt32
		var remoteISN: UInt32
		var deviceNextSeq: UInt32
		var remoteNextSeq: UInt32
		var handshakeComplete: Bool
		var lastActivity: TimeInterval
		var tag: String?
        var devicePending: [UInt32: Data] = [:]
	}
	private var tcpFlows: [String: TcpFlowMeta] = [:]

    // MSS clamp defaults (adjustable by engine)
    private var mssClampV4: UInt16 = 1360
    private var mssClampV6: UInt16 = 1220
	// TCP advertised receive window (bytes)
	private var tcpAdvertisedWindowBytes: UInt16 = 65535
    // Simple sender-side window (bytes) for device→network pacing
    private var tcpSenderWindowBytes: Int = 64 * 1024

	func setMSSClamp(ipv4: UInt16, ipv6: UInt16) {
		flowsQueue.async(flags: .barrier) {
			self.mssClampV4 = ipv4
			self.mssClampV6 = ipv6
		}
	}

	func setTCPWindow(bytes: UInt16) {
		flowsQueue.async(flags: .barrier) {
			self.tcpAdvertisedWindowBytes = max(1024, bytes)
		}
	}

    func setTCPSenderWindow(bytes: Int) {
        flowsQueue.async(flags: .barrier) {
            self.tcpSenderWindowBytes = max(4096, bytes)
        }
    }

    // Intentionally avoid importing NetworkExtension here to keep macOS SPM builds simple.

    private init() {}

    @available(iOS 12.0, macOS 10.14, *)
    private struct UDPLimiter {
        var rateBytesPerSecond: Int
        var tokens: Int
        let tickMs: Int
        var backlog: [(conn: NWConnection, payload: Data)] = []
        var timer: DispatchSourceTimer?
    }
    private var udpLimiters: [String: UDPLimiter] = [:]
    @available(iOS 12.0, macOS 10.14, *)
    private struct TCPLimiter {
        var rateBytesPerSecond: Int
        var tokens: Int
        let tickMs: Int
        var backlog: [(conn: NWConnection, payload: Data)] = []
        var timer: DispatchSourceTimer?
    }
    private var tcpLimiters: [String: TCPLimiter] = [:]

    func setUDPRate(forTag tag: String, bytesPerSecond: Int) {
        limitersQueue.async {
            var limiter = self.udpLimiters[tag] ?? UDPLimiter(rateBytesPerSecond: bytesPerSecond, tokens: bytesPerSecond, tickMs: 10, backlog: [], timer: nil)
            limiter.rateBytesPerSecond = bytesPerSecond
            limiter.tokens = min(limiter.tokens, bytesPerSecond)
            if limiter.timer == nil {
                let t = DispatchSource.makeTimerSource(queue: self.limitersQueue)
                t.schedule(deadline: .now() + .milliseconds(limiter.tickMs), repeating: .milliseconds(limiter.tickMs))
                t.setEventHandler { [weak self] in self?.onUDPLimiterTick(tag: tag) }
                limiter.timer = t
                t.resume()
            }
            self.udpLimiters[tag] = limiter
        }
    }

    private func onUDPLimiterTick(tag: String) {
        guard var limiter = udpLimiters[tag] else { return }
        if limiter.rateBytesPerSecond == Int.max {
            while !limiter.backlog.isEmpty {
                let item = limiter.backlog.removeFirst()
                item.conn.send(content: item.payload, completion: .contentProcessed { _ in })
                Metrics.shared.incNetEgress(bytes: item.payload.count)
                // Per-tag egress
                Metrics.shared.incTagNetEgress(tag: tag, bytes: item.payload.count)
            }
            udpLimiters[tag] = limiter
            return
        }
        let refill = limiter.rateBytesPerSecond * limiter.tickMs / 1000
        limiter.tokens = min(limiter.tokens + refill, limiter.rateBytesPerSecond)
        var used = 0
        var sent: [(NWConnection, Data)] = []
        while let first = limiter.backlog.first, used + first.payload.count <= limiter.tokens {
            used += first.payload.count
            sent.append(first)
            limiter.backlog.removeFirst()
        }
        limiter.tokens -= used
        udpLimiters[tag] = limiter
        for item in sent {
            item.0.send(content: item.1, completion: .contentProcessed { _ in })
            Metrics.shared.incNetEgress(bytes: item.1.count)
            Metrics.shared.incTagNetEgress(tag: tag, bytes: item.1.count)
        }
    }

    func setTCPRate(forTag tag: String, bytesPerSecond: Int) {
        limitersQueue.async {
            var limiter = self.tcpLimiters[tag] ?? TCPLimiter(rateBytesPerSecond: bytesPerSecond, tokens: bytesPerSecond, tickMs: 10, backlog: [], timer: nil)
            limiter.rateBytesPerSecond = bytesPerSecond
            limiter.tokens = min(limiter.tokens, bytesPerSecond)
            if limiter.timer == nil {
                let t = DispatchSource.makeTimerSource(queue: self.limitersQueue)
                t.schedule(deadline: .now() + .milliseconds(limiter.tickMs), repeating: .milliseconds(limiter.tickMs))
                t.setEventHandler { [weak self] in self?.onTCPLimiterTick(tag: tag) }
                limiter.timer = t
                t.resume()
            }
            self.tcpLimiters[tag] = limiter
        }
    }

    private func onTCPLimiterTick(tag: String) {
        guard var limiter = tcpLimiters[tag] else { return }
        if limiter.rateBytesPerSecond == Int.max {
            while !limiter.backlog.isEmpty {
                let item = limiter.backlog.removeFirst()
                item.conn.send(content: item.payload, completion: .contentProcessed { _ in })
                Metrics.shared.incNetEgress(bytes: item.payload.count)
            }
            tcpLimiters[tag] = limiter
            return
        }
        let refill = limiter.rateBytesPerSecond * limiter.tickMs / 1000
        limiter.tokens = min(limiter.tokens + refill, limiter.rateBytesPerSecond)
        var used = 0
        var sent: [(NWConnection, Data)] = []
        while let first = limiter.backlog.first, used + first.payload.count <= limiter.tokens {
            used += first.payload.count
            sent.append(first)
            limiter.backlog.removeFirst()
        }
        limiter.tokens -= used
        tcpLimiters[tag] = limiter
        for item in sent {
            item.0.send(content: item.1, completion: .contentProcessed { _ in })
            Metrics.shared.incNetEgress(bytes: item.1.count)
        }
    }

	// Called from C trampoline on arbitrary thread; keep minimal work here.
	func handleOutgoingIPPacket(packetPtr: UnsafePointer<UInt8>, length: Int) {
		// Parse minimal header fields to decide TCP vs UDP
        let sp = Observability.shared.begin("bridge_outgoing")
		guard length >= 1 else { return }
		let version = packetPtr.pointee >> 4
		if version == 4 {
			handleIPv4(packetPtr: packetPtr, length: length)
		} else if version == 6 {
			handleIPv6(packetPtr: packetPtr, length: length)
		} else {
			return
		}
		Observability.shared.end("bridge_outgoing", sp)
	}

	private func handleIPv4(packetPtr: UnsafePointer<UInt8>, length: Int) {
        let sp = Observability.shared.begin("parse_ipv4")
        guard length >= 20 else { Observability.shared.end("parse_ipv4", sp); return }
		let ihl = Int(packetPtr.pointee & 0x0F) * 4
		guard length >= ihl + 8 else { return }
		let proto = packetPtr.advanced(by: 9).pointee
		logInfo("IPv4 out proto=\(proto) len=\(length)")
		if proto == 17 { // UDP
			let srcIP = Data(bytes: packetPtr.advanced(by: 12), count: 4)
			let dstIP = Data(bytes: packetPtr.advanced(by: 16), count: 4)
			let srcPort = readBE16(packetPtr.advanced(by: ihl + 0))
			let dstPort = readBE16(packetPtr.advanced(by: ihl + 2))
			let key = flowKeyV4(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17)
			let payloadOffset = ihl + 8
			let payloadLen = max(0, length - payloadOffset)
            if payloadLen > 0 {
				let payload = Data(bytes: packetPtr.advanced(by: payloadOffset), count: payloadLen)
				let quotedLen = min(length, ihl + 8)
				let quoted = Data(bytes: packetPtr, count: quotedLen)
				sendUDP(key: key, version: 4, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, host: ipv4String(from: dstIP), port: dstPort, payload: payload, quotedHeader: quoted)
			}
		} else if proto == 6 { // TCP
			let srcIP = Data(bytes: packetPtr.advanced(by: 12), count: 4)
			let dstIP = Data(bytes: packetPtr.advanced(by: 16), count: 4)
			let srcPort = readBE16(packetPtr.advanced(by: ihl + 0))
			let dstPort = readBE16(packetPtr.advanced(by: ihl + 2))
			let key = flowKeyV4(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 6)
			let tcpHdrOffset = ihl
			let dataOffsetWords = Int(packetPtr.advanced(by: tcpHdrOffset + 12).pointee >> 4)
			let tcpHdrLen = dataOffsetWords * 4
			let flags = packetPtr.advanced(by: tcpHdrOffset + 13).pointee
			let seq = readBE32(packetPtr.advanced(by: tcpHdrOffset + 4))
			let ack = readBE32(packetPtr.advanced(by: tcpHdrOffset + 8))
			let payloadOffset = tcpHdrOffset + tcpHdrLen
			let payloadLen = max(0, length - payloadOffset)
			let payload = payloadLen > 0 ? Data(bytes: packetPtr.advanced(by: payloadOffset), count: payloadLen) : Data()
			handleTCPSend(key: key, host: ipv4String(from: dstIP), port: dstPort, flags: flags, payload: payload, version: 4, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, seq: seq, ack: ack)
        }
        Observability.shared.end("parse_ipv4", sp)
	}

	private func handleIPv6(packetPtr: UnsafePointer<UInt8>, length: Int) {
        let sp = Observability.shared.begin("parse_ipv6")
        guard length >= 40 else { Observability.shared.end("parse_ipv6", sp); return }
		let nextHeader = packetPtr.advanced(by: 6).pointee
		logInfo("IPv6 out nextHeader=\(nextHeader) len=\(length)")
		if nextHeader == 17 { // UDP
			let srcIP = Data(bytes: packetPtr.advanced(by: 8), count: 16)
			let dstIP = Data(bytes: packetPtr.advanced(by: 24), count: 16)
			let srcPort = readBE16(packetPtr.advanced(by: 40 + 0))
			let dstPort = readBE16(packetPtr.advanced(by: 40 + 2))
			let key = flowKeyV6(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17)
			let payloadOffset = 40 + 8
			let payloadLen = max(0, length - payloadOffset)
			if payloadLen > 0 {
				let payload = Data(bytes: packetPtr.advanced(by: payloadOffset), count: payloadLen)
				let quotedLen = min(length, 40 + 8)
				let quoted = Data(bytes: packetPtr, count: quotedLen)
				sendUDP(key: key, version: 6, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, host: ipv6String(from: dstIP), port: dstPort, payload: payload, quotedHeader: quoted)
			}
		} else if nextHeader == 6 { // TCP
			let srcIP = Data(bytes: packetPtr.advanced(by: 8), count: 16)
			let dstIP = Data(bytes: packetPtr.advanced(by: 24), count: 16)
			let srcPort = readBE16(packetPtr.advanced(by: 40 + 0))
			let dstPort = readBE16(packetPtr.advanced(by: 40 + 2))
			let key = flowKeyV6(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 6)
			let tcpHdrOffset = 40
			let dataOffsetWords = Int(packetPtr.advanced(by: tcpHdrOffset + 12).pointee >> 4)
			let tcpHdrLen = dataOffsetWords * 4
			let flags = packetPtr.advanced(by: tcpHdrOffset + 13).pointee
			let seq = readBE32(packetPtr.advanced(by: tcpHdrOffset + 4))
			let ack = readBE32(packetPtr.advanced(by: tcpHdrOffset + 8))
			let payloadOffset = tcpHdrOffset + tcpHdrLen
			let payloadLen = max(0, length - payloadOffset)
			let payload = payloadLen > 0 ? Data(bytes: packetPtr.advanced(by: payloadOffset), count: payloadLen) : Data()
			handleTCPSend(key: key, host: ipv6String(from: dstIP), port: dstPort, flags: flags, payload: payload, version: 6, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, seq: seq, ack: ack)
        }
        Observability.shared.end("parse_ipv6", sp)
	}

	private func handleTCPSend(key: String, host: String, port: UInt16, flags: UInt8, payload: Data, version: Int, srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, seq: UInt32, ack: UInt32) {
		let syn = (flags & 0x02) != 0
		let fin = (flags & 0x01) != 0
		let rst = (flags & 0x04) != 0
		var meta: TcpFlowMeta = {
			if let existing = flowsQueue.sync(execute: { tcpFlows[key] }) {
				return existing
			}
			let params = NWParameters.tcp
			let endpoint: NWEndpoint
			if version == 4, let ip = IPv4Address(host) {
				endpoint = NWEndpoint.hostPort(host: .ipv4(ip), port: .init(rawValue: port)!)
			} else if version == 6, let ip6 = IPv6Address(host) {
				endpoint = NWEndpoint.hostPort(host: .ipv6(ip6), port: .init(rawValue: port)!)
			} else {
				endpoint = NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
			}
			let flowQueue = DispatchQueue(label: "com.relativeprotocol.flow.tcp.\(key)")
			let conn = NWConnection(to: endpoint, using: params)
			let deviceISN = syn ? seq : 0
			let remoteISN = arc4random()
			let flowID = key
			let id = FlowIdentity(flowID: flowID, isIPv6: version == 6, proto: "TCP", sourceIP: version == 4 ? ipv4String(from: srcIP) : ipv6String(from: srcIP), sourcePort: srcPort, destinationIP: version == 4 ? ipv4String(from: dstIP) : ipv6String(from: dstIP), destinationPort: dstPort)
			let tag = self.delegate?.classify(flow: id)
			logInfo("TCP flow new tag=\(tag ?? "-") src=\(id.sourceIP):\(srcPort) dst=\(id.destinationIP):\(dstPort) flags=\(flags)")
			let newMeta = TcpFlowMeta(version: version, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, connection: conn, queue: flowQueue, deviceISN: deviceISN, remoteISN: remoteISN, deviceNextSeq: deviceISN &+ 1, remoteNextSeq: remoteISN, handshakeComplete: false, lastActivity: Date().timeIntervalSince1970, tag: tag)
			flowsQueue.async(flags: .barrier) { self.tcpFlows[key] = newMeta }
			if let tag = tag {
				TagStore.shared.setTagBothDirections(version: version, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 6, tag: tag)
			}
			Metrics.shared.setTcpFlows(flowsQueue.sync { tcpFlows.count })
			installTCPReceive(for: key, meta: newMeta)
			conn.stateUpdateHandler = { [weak self] state in
				guard let self = self else { return }
				switch state {
				case .failed, .cancelled:
					self.flowsQueue.async(flags: .barrier) {
						if var m = self.tcpFlows[key] {
							self.sendTCPRST(meta: &m)
							Metrics.shared.incRST()
							self.tcpFlows.removeValue(forKey: key)
							Metrics.shared.setTcpFlows(self.tcpFlows.count)
						}
					}
				default:
					logInfo("TCP conn state=\(state)")
				}
			}
#if DEBUG
			if !self.debug_disableNetworkSends { conn.start(queue: flowQueue) }
#else
			conn.start(queue: flowQueue)
#endif
			return newMeta
		}()
		if rst {
			meta.connection.cancel()
			flowsQueue.async(flags: .barrier) { self.tcpFlows.removeValue(forKey: key) }
			return
		}
			if syn && !meta.handshakeComplete {
			// Synthesize SYN-ACK back to lwIP to complete handshake locally
			let ackNum = meta.deviceISN &+ 1
			let seqNum = meta.remoteISN
			let synAckFlags: UInt8 = 0x12 // SYN|ACK
			let tcpPacket: Data
			if version == 4 {
					tcpPacket = buildIPv4TCPPacket(srcIP: dstIP, dstIP: srcIP, srcPort: dstPort, dstPort: srcPort, seq: seqNum, ack: ackNum, flags: synAckFlags, payload: Data(), mssOption: mssClampV4)
			} else {
					tcpPacket = buildIPv6TCPPacket(srcIP: dstIP, dstIP: srcIP, srcPort: dstPort, dstPort: srcPort, seq: seqNum, ack: ackNum, flags: synAckFlags, payload: Data(), mssOption: mssClampV6)
			}
			#if canImport(NetworkExtension) && os(iOS)
			RelativeProtocolEngine.emitToTun(tcpPacket)
			#else
			tcpPacket.withUnsafeBytes { bytes in
				if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
					_ = rlwip_inject_proxynetif(base, tcpPacket.count)
				}
			}
			#endif
			meta.remoteNextSeq = seqNum &+ 1
			meta.handshakeComplete = true
			flowsQueue.async(flags: .barrier) { self.tcpFlows[key] = meta }
		}
        if !payload.isEmpty {
            meta.queue.async {
                var updated = meta
                // Read latest flow state to avoid stale struct when multiple segments arrive
                self.flowsQueue.sync {
                    if let cur = self.tcpFlows[key] { updated = cur }
                }
                // Normalize segment against next expected device seq
                var segSeq = seq
                var segPayload = payload
                if segSeq &+ UInt32(segPayload.count) <= updated.deviceNextSeq {
                    // Fully duplicate/old segment; drop
                } else if segSeq < updated.deviceNextSeq {
                    // Partial overlap at the front; trim
                    let trim = Int(updated.deviceNextSeq &- segSeq)
                    if trim < segPayload.count { segPayload.removeFirst(trim) }
                    segSeq = updated.deviceNextSeq
                }
                if segPayload.isEmpty {
                    self.flowsQueue.sync(flags: .barrier) { self.tcpFlows[key] = updated }
                    return
                }
                func emit(_ data: Data) {
					if let tag = updated.tag {
                        self.limitersQueue.async {
                            var limiter = self.tcpLimiters[tag] ?? TCPLimiter(rateBytesPerSecond: Int.max, tokens: Int.max, tickMs: 10, backlog: [], timer: nil)
                            limiter.backlog.append((updated.connection, data))
                            if limiter.timer == nil {
                                let t = DispatchSource.makeTimerSource(queue: self.limitersQueue)
                                t.schedule(deadline: .now() + .milliseconds(limiter.tickMs), repeating: .milliseconds(limiter.tickMs))
                                t.setEventHandler { [weak self] in self?.onTCPLimiterTick(tag: tag) }
                                limiter.timer = t
                                t.resume()
                            }
                            self.tcpLimiters[tag] = limiter
                            Metrics.shared.setTagQueueDepth(tag: tag, tcpDepth: limiter.backlog.count)
                        }
                    } else {
						#if DEBUG
						if self.debug_disableNetworkSends {
							self.flowsQueue.async(flags: .barrier) {
								var arr = self.debug_sentData[key] ?? []
								arr.append(data)
								self.debug_sentData[key] = arr
							}
						} else {
							updated.connection.send(content: data, completion: .contentProcessed { _ in })
						}
						#else
						updated.connection.send(content: data, completion: .contentProcessed { _ in })
						#endif
                    }
                }
                // Respect a simple sender window: do not exceed tcpSenderWindowBytes over base seq
                let inFlight = Int(updated.deviceNextSeq &- updated.deviceISN)
                if inFlight + segPayload.count > self.tcpSenderWindowBytes {
                    // Buffer until window advances
                    updated.devicePending[segSeq] = segPayload
                } else if segSeq == updated.deviceNextSeq {
                    // In-order: send now
                    emit(segPayload)
                    updated.deviceNextSeq = updated.deviceNextSeq &+ UInt32(segPayload.count)
                    // Flush any contiguous buffered segments
                    while let next = updated.devicePending[updated.deviceNextSeq] {
                        updated.devicePending.removeValue(forKey: updated.deviceNextSeq)
                        emit(next)
                        updated.deviceNextSeq = updated.deviceNextSeq &+ UInt32(next.count)
                    }
                } else {
                    // Future segment: buffer
                    updated.devicePending[segSeq] = segPayload
                }
                self.flowsQueue.sync(flags: .barrier) { self.tcpFlows[key] = updated }
            }
        }
        if fin {
            meta.queue.async { meta.connection.send(content: nil, completion: .contentProcessed { _ in }) }
        }
	}

	private func sendTCPRST(meta: inout TcpFlowMeta) {
		let flags: UInt8 = 0x14 // RST|ACK
		let seqNum = meta.remoteNextSeq
		let ackNum = meta.deviceNextSeq
		let pkt: Data
		if meta.version == 4 {
			pkt = buildIPv4TCPPacket(srcIP: meta.dstIP, dstIP: meta.srcIP, srcPort: meta.dstPort, dstPort: meta.srcPort, seq: seqNum, ack: ackNum, flags: flags, payload: Data())
		} else {
			pkt = buildIPv6TCPPacket(srcIP: meta.dstIP, dstIP: meta.srcIP, srcPort: meta.dstPort, dstPort: meta.srcPort, seq: seqNum, ack: ackNum, flags: flags, payload: Data())
		}
		#if canImport(NetworkExtension) && os(iOS)
		RelativeProtocolEngine.emitToTun(pkt)
		#else
		pkt.withUnsafeBytes { bytes in
			if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
				_ = rlwip_inject_proxynetif(base, pkt.count)
			}
		}
		#endif
	}

	private func installTCPReceive(for key: String, meta: TcpFlowMeta) {
        meta.connection.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) { [weak self] data, _, isComplete, error in
			guard let self = self else { return }
            let sp = Observability.shared.begin("tcp_receive")
			if let data = data, !data.isEmpty {
				var current = data
				var m = meta
				while !current.isEmpty {
					let maxSeg = m.version == 4 ? Int(self.mssClampV4) : Int(self.mssClampV6)
					let wnd = Int(self.tcpAdvertisedWindowBytes)
					let segSize = max(1, min(maxSeg, wnd))
					let chunk = current.prefix(segSize)
					current.removeFirst(chunk.count)
					let flags: UInt8 = 0x10 // ACK
					let seqNum = m.remoteNextSeq
					let ackNum = m.deviceNextSeq
					let pkt: Data
					if m.version == 4 {
						pkt = self.buildIPv4TCPPacket(srcIP: m.dstIP, dstIP: m.srcIP, srcPort: m.dstPort, dstPort: m.srcPort, seq: seqNum, ack: ackNum, flags: flags, payload: chunk)
					} else {
						pkt = self.buildIPv6TCPPacket(srcIP: m.dstIP, dstIP: m.srcIP, srcPort: m.dstPort, dstPort: m.srcPort, seq: seqNum, ack: ackNum, flags: flags, payload: chunk)
					}
					#if canImport(NetworkExtension) && os(iOS)
					RelativeProtocolEngine.emitToTun(pkt)
					#else
					pkt.withUnsafeBytes { bytes in
						if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
							_ = rlwip_inject_proxynetif(base, pkt.count)
						}
					}
					#endif
					m.remoteNextSeq = m.remoteNextSeq &+ UInt32(chunk.count)
				}
				self.flowsQueue.async(flags: .barrier) { self.tcpFlows[key] = m }
			}
            if error == nil && !isComplete {
				self.installTCPReceive(for: key, meta: meta)
			} else {
				// Remote side closed or error: synthesize FIN|ACK if complete, then remove
				if isComplete {
					let m = meta
					let flags: UInt8 = 0x11 // FIN|ACK
					let seqNum = m.remoteNextSeq
					let ackNum = m.deviceNextSeq
					let pkt: Data
					if m.version == 4 {
						pkt = self.buildIPv4TCPPacket(srcIP: m.dstIP, dstIP: m.srcIP, srcPort: m.dstPort, dstPort: m.srcPort, seq: seqNum, ack: ackNum, flags: flags, payload: Data())
					} else {
						pkt = self.buildIPv6TCPPacket(srcIP: m.dstIP, dstIP: m.srcIP, srcPort: m.dstPort, dstPort: m.srcPort, seq: seqNum, ack: ackNum, flags: flags, payload: Data())
					}
					#if canImport(NetworkExtension) && os(iOS)
					RelativeProtocolEngine.emitToTun(pkt)
					#else
					pkt.withUnsafeBytes { bytes in
						if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
							_ = rlwip_inject_proxynetif(base, pkt.count)
            }
            Observability.shared.end("tcp_receive", sp)
					}
				}
				self.flowsQueue.async(flags: .barrier) {
					self.tcpFlows.removeValue(forKey: key)
					Metrics.shared.setTcpFlows(self.tcpFlows.count)
				}
			}
		}
	}

	private func readBE32(_ ptr: UnsafePointer<UInt8>) -> UInt32 {
		let b0 = UInt32(ptr.pointee)
		let b1 = UInt32(ptr.advanced(by: 1).pointee)
		let b2 = UInt32(ptr.advanced(by: 2).pointee)
		let b3 = UInt32(ptr.advanced(by: 3).pointee)
		return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
	}

	private func sendUDP(key: String, version: Int, srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, host: String, port: UInt16, payload: Data, quotedHeader: Data) {
		let meta: UdpFlowMeta = {
			if var existing = flowsQueue.sync(execute: { udpFlows[key] }) {
				existing.lastOutboundHeader = quotedHeader
				flowsQueue.async(flags: .barrier) { self.udpFlows[key] = existing }
				return existing
			}
			let params = NWParameters.udp
			let endpoint: NWEndpoint
			if version == 4, let ip = IPv4Address(host) {
				endpoint = NWEndpoint.hostPort(host: .ipv4(ip), port: .init(rawValue: port)!)
			} else if version == 6, let ip6 = IPv6Address(host) {
				endpoint = NWEndpoint.hostPort(host: .ipv6(ip6), port: .init(rawValue: port)!)
			} else {
				endpoint = NWEndpoint.hostPort(host: .name(host, nil), port: .init(rawValue: port)!)
			}
			let conn = NWConnection(to: endpoint, using: params)
			let flowID = key
			let id = FlowIdentity(flowID: flowID, isIPv6: version == 6, proto: "UDP", sourceIP: version == 4 ? ipv4String(from: srcIP) : ipv6String(from: srcIP), sourcePort: srcPort, destinationIP: version == 4 ? ipv4String(from: dstIP) : ipv6String(from: dstIP), destinationPort: dstPort)
            let tag = self.delegate?.classify(flow: id)
            logInfo("UDP flow new tag=\(tag ?? "-") src=\(id.sourceIP):\(srcPort) dst=\(id.destinationIP):\(dstPort)")
            let flowQueue = DispatchQueue(label: "com.relativeprotocol.flow.udp.\(key)")
            let newMeta = UdpFlowMeta(version: version, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, connection: conn, queue: flowQueue, lastOutboundHeader: quotedHeader, lastActivity: Date().timeIntervalSince1970, tag: tag)
			flowsQueue.async(flags: .barrier) { self.udpFlows[key] = newMeta }
			if let tag = tag {
				TagStore.shared.setTagBothDirections(version: version, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17, tag: tag)
			}
			installUDPReceive(for: key, meta: newMeta)
            conn.stateUpdateHandler = { [weak self] state in
				guard let self = self else { return }
				switch state {
				case .failed:
					logInfo("UDP conn state=failed")
					self.synthesizeICMPForUDPFailure(key: key)
				case .cancelled:
					logInfo("UDP conn state=cancelled")
					self.synthesizeICMPForUDPFailure(key: key)
				default:
					logInfo("UDP conn state=\(state)")
				}
			}
            conn.start(queue: flowQueue)
			return newMeta
		}()
        if let tag = meta.tag {
            limitersQueue.async {
                var limiter = self.udpLimiters[tag] ?? UDPLimiter(rateBytesPerSecond: Int.max, tokens: Int.max, tickMs: 10, backlog: [], timer: nil)
                limiter.backlog.append((meta.connection, payload))
                if limiter.timer == nil {
                    let t = DispatchSource.makeTimerSource(queue: self.limitersQueue)
                    t.schedule(deadline: .now() + .milliseconds(limiter.tickMs), repeating: .milliseconds(limiter.tickMs))
                    t.setEventHandler { [weak self] in self?.onUDPLimiterTick(tag: tag) }
                    limiter.timer = t
                    t.resume()
                }
                self.udpLimiters[tag] = limiter
                Metrics.shared.setTagQueueDepth(tag: tag, udpDepth: limiter.backlog.count)
            }
        } else {
            meta.connection.send(content: payload, completion: .contentProcessed { [weak self] error in
                if error != nil { self?.synthesizeICMPForUDPFailure(key: key) }
                Metrics.shared.incNetEgress(bytes: payload.count)
            })
        }
	}

    private func installUDPReceive(for key: String, meta: UdpFlowMeta) {
		meta.connection.receiveMessage { [weak self] data, _, _, error in
			guard let self = self else { return }
            let sp = Observability.shared.begin("udp_receive")
			if let data = data, !data.isEmpty {
				let packet: Data
				if meta.version == 4 {
					packet = self.buildIPv4UDPPacket(srcIP: meta.dstIP, dstIP: meta.srcIP, srcPort: meta.dstPort, dstPort: meta.srcPort, payload: data)
				} else {
					packet = self.buildIPv6UDPPacket(srcIP: meta.dstIP, dstIP: meta.srcIP, srcPort: meta.dstPort, dstPort: meta.srcPort, payload: data)
				}
				#if canImport(NetworkExtension) && os(iOS)
				RelativeProtocolEngine.emitToTun(packet)
				#else
				packet.withUnsafeBytes { bytes in
					if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
						_ = rlwip_inject_proxynetif(base, packet.count)
					}
				}
				#endif
				Metrics.shared.incNetIngress(bytes: data.count)
			}
			if error == nil {
				self.installUDPReceive(for: key, meta: meta)
			}
            Observability.shared.end("udp_receive", sp)
		}
	}

	private func readBE16(_ ptr: UnsafePointer<UInt8>) -> UInt16 {
		let b0 = UInt16(ptr.pointee)
		let b1 = UInt16(ptr.advanced(by: 1).pointee)
		return (b0 << 8) | b1
	}

	private func writeBE16(_ value: UInt16, into data: inout Data, at offset: Int) {
		data[offset] = UInt8((value >> 8) & 0xFF)
		data[offset + 1] = UInt8(value & 0xFF)
	}

	private func ipv4Checksum(_ data: Data) -> UInt16 {
		var sum: UInt32 = 0
		var i = 0
		while i + 1 < data.count {
			let word = (UInt32(data[i]) << 8) | UInt32(data[i + 1])
			sum &+= word
			i += 2
		}
		if i < data.count {
			sum &+= UInt32(data[i]) << 8
		}
		while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
		return ~UInt16(sum & 0xFFFF)
	}


#if DEBUG
	// Test-only helper
	func test_ipv4Checksum(_ data: Data) -> UInt16 { ipv4Checksum(data) }

	// Test-only builders to validate checksums and headers
	func test_buildIPv4UDPPacket(srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, payload: Data) -> Data {
		return buildIPv4UDPPacket(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, payload: payload)
	}

	func test_buildIPv6UDPPacket(srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, payload: Data) -> Data {
		return buildIPv6UDPPacket(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, payload: payload)
	}

	func test_buildIPv4TCPPacket(srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, seq: UInt32, ack: UInt32, flags: UInt8, payload: Data, mssOption: UInt16?) -> Data {
		return buildIPv4TCPPacket(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, seq: seq, ack: ack, flags: flags, payload: payload, mssOption: mssOption)
	}
#endif

	private func udpChecksumIPv4(srcIP: Data, dstIP: Data, udpHeaderAndPayload: Data) -> UInt16 {
		var pseudo = Data()
		pseudo.append(srcIP)
		pseudo.append(dstIP)
		pseudo.append(0) // zero
		pseudo.append(17) // UDP proto
		let len = UInt16(udpHeaderAndPayload.count)
		pseudo.append(UInt8((len >> 8) & 0xFF))
		pseudo.append(UInt8(len & 0xFF))
		var sum: UInt32 = 0
		func add(_ d: Data) {
			var i = 0
			while i + 1 < d.count {
				let word = (UInt32(d[i]) << 8) | UInt32(d[i+1])
				sum &+= word
				i += 2
			}
			if i < d.count { sum &+= UInt32(d[i]) << 8 }
		}
		add(pseudo)
		add(udpHeaderAndPayload)
		while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
		let result = ~UInt16(sum & 0xFFFF)
		return result == 0 ? 0xFFFF : result
	}

	private func udpChecksumIPv6(srcIP: Data, dstIP: Data, udpHeaderAndPayload: Data) -> UInt16 {
		var pseudo = Data()
		pseudo.append(srcIP)
		pseudo.append(dstIP)
		let len32 = UInt32(udpHeaderAndPayload.count)
		pseudo.append(UInt8((len32 >> 24) & 0xFF))
		pseudo.append(UInt8((len32 >> 16) & 0xFF))
		pseudo.append(UInt8((len32 >> 8) & 0xFF))
		pseudo.append(UInt8(len32 & 0xFF))
		pseudo.append(0)
		pseudo.append(0)
		pseudo.append(0)
		pseudo.append(17)
		var sum: UInt32 = 0
		func add(_ d: Data) {
			var i = 0
			while i + 1 < d.count {
				let word = (UInt32(d[i]) << 8) | UInt32(d[i+1])
				sum &+= word
				i += 2
			}
			if i < d.count { sum &+= UInt32(d[i]) << 8 }
		}
		add(pseudo)
		add(udpHeaderAndPayload)
		while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
		let result = ~UInt16(sum & 0xFFFF)
		return result == 0 ? 0xFFFF : result
	}

	private func tcpChecksumIPv4(srcIP: Data, dstIP: Data, tcpHeaderAndPayload: Data) -> UInt16 {
		var pseudo = Data()
		pseudo.append(srcIP)
		pseudo.append(dstIP)
		pseudo.append(0)
		pseudo.append(6) // TCP
		let len = UInt16(tcpHeaderAndPayload.count)
		pseudo.append(UInt8((len >> 8) & 0xFF))
		pseudo.append(UInt8(len & 0xFF))
		var sum: UInt32 = 0
		func add(_ d: Data) {
			var i = 0
			while i + 1 < d.count {
				let word = (UInt32(d[i]) << 8) | UInt32(d[i+1])
				sum &+= word
				i += 2
			}
			if i < d.count { sum &+= UInt32(d[i]) << 8 }
		}
		add(pseudo)
		add(tcpHeaderAndPayload)
		while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
		let result = ~UInt16(sum & 0xFFFF)
		return result == 0 ? 0xFFFF : result
	}

	private func tcpChecksumIPv6(srcIP: Data, dstIP: Data, tcpHeaderAndPayload: Data) -> UInt16 {
		var pseudo = Data()
		pseudo.append(srcIP)
		pseudo.append(dstIP)
		let len32 = UInt32(tcpHeaderAndPayload.count)
		pseudo.append(UInt8((len32 >> 24) & 0xFF))
		pseudo.append(UInt8((len32 >> 16) & 0xFF))
		pseudo.append(UInt8((len32 >> 8) & 0xFF))
		pseudo.append(UInt8(len32 & 0xFF))
		pseudo.append(0)
		pseudo.append(0)
		pseudo.append(0)
		pseudo.append(6)
		var sum: UInt32 = 0
		func add(_ d: Data) {
			var i = 0
			while i + 1 < d.count {
				let word = (UInt32(d[i]) << 8) | UInt32(d[i+1])
				sum &+= word
				i += 2
			}
			if i < d.count { sum &+= UInt32(d[i]) << 8 }
		}
		add(pseudo)
		add(tcpHeaderAndPayload)
		while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
		let result = ~UInt16(sum & 0xFFFF)
		return result == 0 ? 0xFFFF : result
	}

	private func buildIPv4TCPPacket(srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, seq: UInt32, ack: UInt32, flags: UInt8, payload: Data, mssOption: UInt16? = nil) -> Data {
		var ip = Data(count: 20)
		ip[0] = 0x45
		ip[1] = 0x00
		let tcpHeaderLen = mssOption != nil ? 24 : 20
		writeBE16(UInt16(ip.count + tcpHeaderLen + payload.count), into: &ip, at: 2)
		writeBE16(0, into: &ip, at: 4)
		writeBE16(0, into: &ip, at: 6)
		ip[8] = 64
		ip[9] = 6 // TCP
		var iph = ip
		iph.replaceSubrange(12..<16, with: srcIP)
		iph.replaceSubrange(16..<20, with: dstIP)
		let icsum = ipv4Checksum(iph.prefix(20))
		writeBE16(icsum, into: &iph, at: 10)
		var tcp = Data(count: tcpHeaderLen)
		writeBE16(srcPort, into: &tcp, at: 0)
		writeBE16(dstPort, into: &tcp, at: 2)
		writeBE32(seq, into: &tcp, at: 4)
		writeBE32(ack, into: &tcp, at: 8)
		let dataOffsetWords = UInt8(tcpHeaderLen / 4)
		tcp[12] = (dataOffsetWords << 4)
		tcp[13] = flags
		writeBE16(tcpAdvertisedWindowBytes, into: &tcp, at: 14) // window
		writeBE16(0, into: &tcp, at: 16) // checksum placeholder
		writeBE16(0, into: &tcp, at: 18) // urgent pointer
		if let mss = mssOption {
			// TCP option: MSS (kind=2, len=4)
			tcp[20] = 2
			tcp[21] = 4
			writeBE16(mss, into: &tcp, at: 22)
		}
		var tcpFull = tcp + payload
		let tcsum = tcpChecksumIPv4(srcIP: srcIP, dstIP: dstIP, tcpHeaderAndPayload: tcpFull)
		writeBE16(tcsum, into: &tcpFull, at: 16)
		var packet = iph
		packet.append(tcpFull)
		return packet
	}

	private func buildIPv6TCPPacket(srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, seq: UInt32, ack: UInt32, flags: UInt8, payload: Data, mssOption: UInt16? = nil) -> Data {
		var ip = Data(count: 40)
		ip[0] = 0x60
		let tcpHeaderLen = mssOption != nil ? 24 : 20
		writeBE16(UInt16(tcpHeaderLen + payload.count), into: &ip, at: 4)
		ip[6] = 6
		ip[7] = 64
		var iph = ip
		iph.replaceSubrange(8..<24, with: srcIP)
		iph.replaceSubrange(24..<40, with: dstIP)
		var tcp = Data(count: tcpHeaderLen)
		writeBE16(srcPort, into: &tcp, at: 0)
		writeBE16(dstPort, into: &tcp, at: 2)
		writeBE32(seq, into: &tcp, at: 4)
		writeBE32(ack, into: &tcp, at: 8)
		let dataOffsetWords = UInt8(tcpHeaderLen / 4)
		tcp[12] = (dataOffsetWords << 4)
		tcp[13] = flags
		writeBE16(tcpAdvertisedWindowBytes, into: &tcp, at: 14)
		writeBE16(0, into: &tcp, at: 16)
		writeBE16(0, into: &tcp, at: 18)
		if let mss = mssOption {
			// TCP option: MSS (kind=2, len=4)
			tcp[20] = 2
			tcp[21] = 4
			writeBE16(mss, into: &tcp, at: 22)
		}
		var tcpFull = tcp + payload
		let tcsum = tcpChecksumIPv6(srcIP: srcIP, dstIP: dstIP, tcpHeaderAndPayload: tcpFull)
		writeBE16(tcsum, into: &tcpFull, at: 16)
		var packet = iph
		packet.append(tcpFull)
		return packet
	}

	private func writeBE32(_ value: UInt32, into data: inout Data, at offset: Int) {
		data[offset] = UInt8((value >> 24) & 0xFF)
		data[offset + 1] = UInt8((value >> 16) & 0xFF)
		data[offset + 2] = UInt8((value >> 8) & 0xFF)
		data[offset + 3] = UInt8(value & 0xFF)
	}

	private func buildIPv4UDPPacket(srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, payload: Data) -> Data {
		// IPv4 header (20 bytes)
		var ip = Data(count: 20)
		ip[0] = 0x45
		ip[1] = 0x00
		let totalLen = UInt16(20 + 8 + payload.count)
		writeBE16(totalLen, into: &ip, at: 2)
		writeBE16(0, into: &ip, at: 4) // ID
		writeBE16(0, into: &ip, at: 6) // flags/frag
		ip[8] = 64 // TTL
		ip[9] = 17 // UDP
		// src/dst
		var hdr = ip
		hdr.replaceSubrange(12..<16, with: srcIP)
		hdr.replaceSubrange(16..<20, with: dstIP)
		// checksum
		let csum = ipv4Checksum(hdr.prefix(20))
		writeBE16(csum, into: &hdr, at: 10)
		var packet = hdr
		// UDP header
		var udp = Data(count: 8)
		writeBE16(srcPort, into: &udp, at: 0)
		writeBE16(dstPort, into: &udp, at: 2)
		writeBE16(UInt16(8 + payload.count), into: &udp, at: 4)
		var udpFull = udp + payload
		let ucsum = udpChecksumIPv4(srcIP: srcIP, dstIP: dstIP, udpHeaderAndPayload: udpFull)
		writeBE16(ucsum, into: &udpFull, at: 6)
		packet.append(udpFull)
		return packet
	}

	private func buildIPv6UDPPacket(srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, payload: Data) -> Data {
		var packet = Data(count: 40)
		// Version 6, Traffic Class/Flow Label zero
		packet[0] = 0x60
		// Payload length (UDP header + payload)
		writeBE16(UInt16(8 + payload.count), into: &packet, at: 4)
		packet[6] = 17 // Next header UDP
		packet[7] = 64 // Hop limit
		var hdr = packet
		hdr.replaceSubrange(8..<24, with: srcIP)
		hdr.replaceSubrange(24..<40, with: dstIP)
		packet = hdr
		var udp = Data(count: 8)
		writeBE16(srcPort, into: &udp, at: 0)
		writeBE16(dstPort, into: &udp, at: 2)
		writeBE16(UInt16(8 + payload.count), into: &udp, at: 4)
		var udpFull = udp + payload
		let ucsum = udpChecksumIPv6(srcIP: srcIP, dstIP: dstIP, udpHeaderAndPayload: udpFull)
		writeBE16(ucsum, into: &udpFull, at: 6)
		packet.append(udpFull)
		return packet
	}

	private func ipv4String(from data: Data) -> String {
		return data.map { String($0) }.joined(separator: ".")
	}

	private func ipv6String(from data: Data) -> String {
		guard data.count == 16 else { return "" }
		let words = stride(from: 0, to: 16, by: 2).map { i -> UInt16 in
			let hi = UInt16(data[i])
			let lo = UInt16(data[i+1])
			return (hi << 8) | lo
		}
		return words.map { String(format: "%x", $0) }.joined(separator: ":")
	}

	private func synthesizeICMPForUDPFailure(key: String) {
		flowsQueue.async {
			guard let meta = self.udpFlows[key] else { return }
			if meta.version == 4 {
				let icmp = self.buildIPv4ICMPDestUnreach(srcIP: meta.dstIP, dstIP: meta.srcIP, code: 0, quoted: meta.lastOutboundHeader)
				#if canImport(NetworkExtension) && os(iOS)
				RelativeProtocolEngine.emitToTun(icmp)
				#else
				icmp.withUnsafeBytes { bytes in
					if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
						_ = rlwip_inject_proxynetif(base, icmp.count)
					}
				}
				#endif
			} else {
				let icmp6 = self.buildIPv6ICMPDestUnreach(srcIP: meta.dstIP, dstIP: meta.srcIP, code: 4, quoted: meta.lastOutboundHeader)
				#if canImport(NetworkExtension) && os(iOS)
				RelativeProtocolEngine.emitToTun(icmp6)
				#else
				icmp6.withUnsafeBytes { bytes in
					if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
						_ = rlwip_inject_proxynetif(base, icmp6.count)
					}
				}
				#endif
			}
			self.udpFlows.removeValue(forKey: key)
		}
	}

#if DEBUG
	// Test-only helpers to create a UDP flow meta and trigger ICMP synthesis deterministically
	func debug_createUDPFlowForTest(version: Int, srcIP: Data, dstIP: Data, srcPort: UInt16, dstPort: UInt16, quotedHeader: Data) -> String {
        let key: String = (version == 4)
			? flowKeyV4(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17)
			: flowKeyV6(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17)
		flowsQueue.async(flags: .barrier) {
			let params = NWParameters.udp
			let endpoint: NWEndpoint = (version == 4 && IPv4Address("127.0.0.1") != nil)
				? NWEndpoint.hostPort(host: .ipv4(IPv4Address("127.0.0.1")!), port: .init(rawValue: 9)!)
				: NWEndpoint.hostPort(host: .name("localhost", nil), port: .init(rawValue: 9)!)
			let conn = NWConnection(to: endpoint, using: params)
            let q = DispatchQueue(label: "com.relativeprotocol.flow.udp.debug.\(key)")
            let meta = UdpFlowMeta(version: version, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, connection: conn, queue: q, lastOutboundHeader: quotedHeader, lastActivity: Date().timeIntervalSince1970, tag: nil)
			self.udpFlows[key] = meta
		}
		return key
	}

	func debug_triggerICMPForUDPFailure(key: String) {
		self.synthesizeICMPForUDPFailure(key: key)
	}
#endif

	private func buildIPv4ICMPDestUnreach(srcIP: Data, dstIP: Data, code: UInt8, quoted: Data) -> Data {
		var ip = Data(count: 20)
		ip[0] = 0x45
		ip[1] = 0x00
		let icmpLen = 8 + quoted.count
		writeBE16(UInt16(20 + icmpLen), into: &ip, at: 2)
		writeBE16(0, into: &ip, at: 4)
		writeBE16(0, into: &ip, at: 6)
		ip[8] = 64
		ip[9] = 1 // ICMP
		var iph = ip
		iph.replaceSubrange(12..<16, with: srcIP)
		iph.replaceSubrange(16..<20, with: dstIP)
		let icsum = ipv4Checksum(iph.prefix(20))
		writeBE16(icsum, into: &iph, at: 10)
		var icmp = Data(count: 8)
		icmp[0] = 3 // Destination Unreachable
		icmp[1] = code // 0: net unreachable, 3: port unreachable
		writeBE16(0, into: &icmp, at: 2) // checksum placeholder
		writeBE32(0, into: &icmp, at: 4) // unused
		var full = icmp + quoted
		let csum = ipv4Checksum(full)
		writeBE16(csum, into: &full, at: 2)
		var packet = iph
		packet.append(full)
		return packet
	}

	private func buildIPv6ICMPDestUnreach(srcIP: Data, dstIP: Data, code: UInt8, quoted: Data) -> Data {
		// ICMPv6 Type 1 (Destination Unreachable)
		var ip = Data(count: 40)
		ip[0] = 0x60
		let icmpLen = 8 + quoted.count
		writeBE16(UInt16(icmpLen), into: &ip, at: 4)
		ip[6] = 58 // ICMPv6
		ip[7] = 64
		var iph = ip
		iph.replaceSubrange(8..<24, with: srcIP)
		iph.replaceSubrange(24..<40, with: dstIP)
		var icmp = Data(count: 8)
		icmp[0] = 1 // Destination Unreachable
		icmp[1] = code // 4: Port unreachable
		writeBE16(0, into: &icmp, at: 2)
		writeBE32(0, into: &icmp, at: 4)
		var full = icmp + quoted
		// Compute ICMPv6 checksum over pseudo-header
		var pseudo = Data()
		pseudo.append(srcIP)
		pseudo.append(dstIP)
		let len32 = UInt32(full.count)
		pseudo.append(UInt8((len32 >> 24) & 0xFF))
		pseudo.append(UInt8((len32 >> 16) & 0xFF))
		pseudo.append(UInt8((len32 >> 8) & 0xFF))
		pseudo.append(UInt8(len32 & 0xFF))
		pseudo.append(0)
		pseudo.append(0)
		pseudo.append(0)
		pseudo.append(58)
		var sum: UInt32 = 0
		func add(_ d: Data) {
			var i = 0
			while i + 1 < d.count {
				let word = (UInt32(d[i]) << 8) | UInt32(d[i+1])
				sum &+= word
				i += 2
			}
			if i < d.count { sum &+= UInt32(d[i]) << 8 }
		}
		add(pseudo)
		add(full)
		while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
		let csum = ~UInt16(sum & 0xFFFF)
		writeBE16(csum == 0 ? 0xFFFF : csum, into: &full, at: 2)
		var packet = iph
		packet.append(full)
		return packet
	}

	private func flowKeyV4(srcIP: Data, srcPort: UInt16, dstIP: Data, dstPort: UInt16, proto: UInt8) -> String {
		let s = srcIP.base64EncodedString()
		let d = dstIP.base64EncodedString()
		return "4|\(s)|\(srcPort)|\(d)|\(dstPort)|\(proto)"
	}

	private func flowKeyV6(srcIP: Data, srcPort: UInt16, dstIP: Data, dstPort: UInt16, proto: UInt8) -> String {
		let s = srcIP.base64EncodedString()
		let d = dstIP.base64EncodedString()
		return "6|\(s)|\(srcPort)|\(d)|\(dstPort)|\(proto)"
	}
}


