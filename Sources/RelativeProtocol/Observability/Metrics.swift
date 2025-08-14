import Foundation

final class Metrics {
	struct Snapshot {
		let packetsInFromTunnel: UInt64
		let bytesInFromTunnel: UInt64
		let packetsOutToTunnel: UInt64
		let bytesOutToTunnel: UInt64
		let netIngressBytes: UInt64
		let netEgressBytes: UInt64
		let udpFlows: Int
		let tcpFlows: Int
		let rstSynthesized: UInt64
		let icmpSynthesized: UInt64
		let perTag: [String: TagSnapshot]
	}

	struct TagSnapshot {
		let netIngressBytes: UInt64
		let netEgressBytes: UInt64
		let udpQueueDepth: Int
		let tcpQueueDepth: Int
	}

	static let shared = Metrics()

	private let q = DispatchQueue(label: "com.relativeprotocol.metrics")
	private var _packetsInFromTunnel: UInt64 = 0
	private var _bytesInFromTunnel: UInt64 = 0
	private var _packetsOutToTunnel: UInt64 = 0
	private var _bytesOutToTunnel: UInt64 = 0
	private var _netIngressBytes: UInt64 = 0
	private var _netEgressBytes: UInt64 = 0
	private var _udpFlows: Int = 0
	private var _tcpFlows: Int = 0
	private var _rstSynthesized: UInt64 = 0
	private var _icmpSynthesized: UInt64 = 0

	// Per-tag
	private var _tagIngress: [String: UInt64] = [:]
	private var _tagEgress: [String: UInt64] = [:]
	private var _tagUdpDepth: [String: Int] = [:]
	private var _tagTcpDepth: [String: Int] = [:]

	func incPacketsIn(bytes: Int) { q.async { self._packetsInFromTunnel &+= 1; self._bytesInFromTunnel &+= UInt64(bytes) } }
	func incPacketsOut(bytes: Int) { q.async { self._packetsOutToTunnel &+= 1; self._bytesOutToTunnel &+= UInt64(bytes) } }
	func incNetIngress(bytes: Int) { q.async { self._netIngressBytes &+= UInt64(bytes) } }
	func incNetEgress(bytes: Int) { q.async { self._netEgressBytes &+= UInt64(bytes) } }
	func setUdpFlows(_ n: Int) { q.async { self._udpFlows = n } }
	func setTcpFlows(_ n: Int) { q.async { self._tcpFlows = n } }
	func incRST() { q.async { self._rstSynthesized &+= 1 } }
	func incICMP() { q.async { self._icmpSynthesized &+= 1 } }

	// Per-tag counters
	func incTagNetIngress(tag: String, bytes: Int) { q.async { self._tagIngress[tag, default: 0] &+= UInt64(bytes) } }
	func incTagNetEgress(tag: String, bytes: Int) { q.async { self._tagEgress[tag, default: 0] &+= UInt64(bytes) } }
	func setTagQueueDepth(tag: String, udpDepth: Int? = nil, tcpDepth: Int? = nil) {
		q.async {
			if let u = udpDepth { self._tagUdpDepth[tag] = u }
			if let t = tcpDepth { self._tagTcpDepth[tag] = t }
		}
	}

	func snapshot() -> Snapshot {
		var s: Snapshot!
		q.sync {
			s = Snapshot(
				packetsInFromTunnel: _packetsInFromTunnel,
				bytesInFromTunnel: _bytesInFromTunnel,
				packetsOutToTunnel: _packetsOutToTunnel,
				bytesOutToTunnel: _bytesOutToTunnel,
				netIngressBytes: _netIngressBytes,
				netEgressBytes: _netEgressBytes,
				udpFlows: _udpFlows,
				tcpFlows: _tcpFlows,
				rstSynthesized: _rstSynthesized,
				icmpSynthesized: _icmpSynthesized,
				perTag: {
					var map: [String: TagSnapshot] = [:]
					let tags = Set(_tagIngress.keys).union(_tagEgress.keys).union(_tagUdpDepth.keys).union(_tagTcpDepth.keys)
					for t in tags {
						map[t] = TagSnapshot(
							netIngressBytes: _tagIngress[t] ?? 0,
							netEgressBytes: _tagEgress[t] ?? 0,
							udpQueueDepth: _tagUdpDepth[t] ?? 0,
							tcpQueueDepth: _tagTcpDepth[t] ?? 0
						)
					}
					return map
				}()
			)
		}
		return s
	}
}


