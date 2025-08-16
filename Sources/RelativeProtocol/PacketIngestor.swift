import Foundation

#if canImport(NetworkExtension) && os(iOS)
import NetworkExtension

public enum PacketIngestor {
	public struct Packet {
		public let data: Data
		public let proto: sa_family_t
	}

	public static func packets(from packetFlow: NEPacketTunnelFlow) -> AsyncStream<Packet> {
		AsyncStream { continuation in
			func arm() {
				packetFlow.readPackets { packets, protocols in
					guard !packets.isEmpty else {
						// Immediately rearm to continue streaming
						arm()
						return
					}
					let count = packets.count
					for i in 0..<count {
						let pkt = packets[i]
						let proto: sa_family_t
						if i < protocols.count {
							proto = sa_family_t(truncating: protocols[i])
						} else {
							// Fallback: infer from header nibble
							let ver = pkt.first.map { $0 >> 4 } ?? 4
							proto = (ver == 6) ? sa_family_t(AF_INET6) : sa_family_t(AF_INET)
						}
						continuation.yield(Packet(data: pkt, proto: proto))
					}
					arm()
				}
			}
			arm()
		}
	}
}
#endif


