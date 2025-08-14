import Foundation
import Network

public enum SocketHelpers {
	public static func endpointForIPLiteral(version: Int, hostBytes: Data, port: UInt16) -> NWEndpoint? {
		if version == 4, let ip = IPv4Address(hostBytes.map { String($0) }.joined(separator: ".")) {
			return .hostPort(host: .ipv4(ip), port: .init(rawValue: port)!)
		}
		if version == 6 {
			let words = stride(from: 0, to: 16, by: 2).map { i -> UInt16 in
				(UInt16(hostBytes[i]) << 8) | UInt16(hostBytes[i+1])
			}
			let str = words.map { String(format: "%x", $0) }.joined(separator: ":")
			if let ip6 = IPv6Address(str) {
				return .hostPort(host: .ipv6(ip6), port: .init(rawValue: port)!)
			}
		}
		return nil
	}
}


