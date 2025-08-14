import Foundation
import Network

public final class TCPHelper {
	public final class Connection {
		public let endpoint: NWEndpoint
		private let conn: NWConnection
		private let queue: DispatchQueue

		init(endpoint: NWEndpoint) {
			self.endpoint = endpoint
			self.queue = DispatchQueue(label: "com.relativeprotocol.tcphelper.\(UUID().uuidString)")
			self.conn = NWConnection(to: endpoint, using: .tcp)
			self.conn.start(queue: self.queue)
		}

		public func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
			conn.send(content: data, completion: .contentProcessed { err in completion?(err) })
		}

		public func receive(max: Int = 32 * 1024, handler: @escaping (Data?, Bool, Error?) -> Void) {
			conn.receive(minimumIncompleteLength: 1, maximumLength: max) { data, _, complete, error in
				handler(data, complete, error)
			}
		}

		public func cancel() { conn.cancel() }
	}

	public init() {}

	public func connect(to endpoint: NWEndpoint) -> Connection {
		return Connection(endpoint: endpoint)
	}
}


