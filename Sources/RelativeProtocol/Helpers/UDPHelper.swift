import Foundation
import Network

public final class UDPHelper {
	private let queue = DispatchQueue(label: "com.relativeprotocol.udpsender")
	private var pool: [String: NWConnection] = [:]

	public init() {}

	public func send(to endpoint: NWEndpoint, payload: Data, completion: ((Error?) -> Void)? = nil) {
		queue.async {
			let key = String(describing: endpoint)
			let conn: NWConnection
			if let c = self.pool[key] { conn = c } else {
				conn = NWConnection(to: endpoint, using: .udp)
				conn.start(queue: self.queue)
				self.pool[key] = conn
			}
			conn.send(content: payload, completion: .contentProcessed { err in completion?(err) })
		}
	}
}


