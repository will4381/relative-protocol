import Foundation
import Network

public enum TransportState: CustomStringConvertible {
	case preparing
	case ready
	case waiting
	case failed(Error?)
	case cancelled

	public var description: String {
		switch self {
		case .preparing: return "preparing"
		case .ready: return "ready"
		case .waiting: return "waiting"
		case .failed(let err): return "failed(\(err.map { String(describing: $0) } ?? "nil"))"
		case .cancelled: return "cancelled"
		}
	}
}

public protocol TCPTransport: AnyObject {
	var stateChanged: ((TransportState) -> Void)? { get set }
	func start(queue: DispatchQueue)
	func send(_ data: Data)
	func closeWrite()
	func receive(minimumIncompleteLength: Int, maximumLength: Int, handler: @escaping (Data?, Bool, Error?) -> Void)
	func cancel()
}

public protocol UDPTransport: AnyObject {
	var stateChanged: ((TransportState) -> Void)? { get set }
	func start(queue: DispatchQueue)
	func send(_ data: Data)
	func receiveMessage(handler: @escaping (Data?, Error?) -> Void)
	func cancel()
}

public typealias MakeTCPTransport = (_ host: String, _ port: UInt16, _ params: NWParameters) -> TCPTransport
public typealias MakeUDPTransport = (_ host: String, _ port: UInt16, _ params: NWParameters) -> UDPTransport

public struct EgressConnectionFactory {
	public let makeTCP: MakeTCPTransport
	public let makeUDP: MakeUDPTransport
	public init(makeTCP: @escaping MakeTCPTransport, makeUDP: @escaping MakeUDPTransport) {
		self.makeTCP = makeTCP
		self.makeUDP = makeUDP
	}
}

final class NWConnectionTCPTransport: TCPTransport {
	private let connection: NWConnection
	var stateChanged: ((TransportState) -> Void)?

	init(endpoint: NWEndpoint, params: NWParameters) {
		self.connection = NWConnection(to: endpoint, using: params)
		self.connection.stateUpdateHandler = { [weak self] state in
			guard let self = self else { return }
			switch state {
			case .setup, .preparing:
				self.stateChanged?(.preparing)
			case .ready:
				self.stateChanged?(.ready)
			case .waiting(let err):
				self.stateChanged?(.waiting)
				self.stateChanged?(.failed(err))
			case .failed(let err):
				self.stateChanged?(.failed(err))
			case .cancelled:
				self.stateChanged?(.cancelled)
			@unknown default:
				self.stateChanged?(.failed(nil))
			}
		}
	}

	func start(queue: DispatchQueue) {
		connection.start(queue: queue)
	}

	func send(_ data: Data) {
		connection.send(content: data, completion: .contentProcessed { _ in })
	}

	func closeWrite() {
		connection.send(content: nil, completion: .contentProcessed { _ in })
	}

	func receive(minimumIncompleteLength: Int, maximumLength: Int, handler: @escaping (Data?, Bool, Error?) -> Void) {
		connection.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength) { data, _, isComplete, error in
			handler(data, isComplete, error)
		}
	}

	func cancel() {
		connection.cancel()
	}
}

final class NWConnectionUDPTransport: UDPTransport {
	private let connection: NWConnection
	var stateChanged: ((TransportState) -> Void)?

	init(endpoint: NWEndpoint, params: NWParameters) {
		self.connection = NWConnection(to: endpoint, using: params)
		self.connection.stateUpdateHandler = { [weak self] state in
			guard let self = self else { return }
			switch state {
			case .setup, .preparing:
				self.stateChanged?(.preparing)
			case .ready:
				self.stateChanged?(.ready)
			case .waiting(let err):
				self.stateChanged?(.waiting)
				self.stateChanged?(.failed(err))
			case .failed(let err):
				self.stateChanged?(.failed(err))
			case .cancelled:
				self.stateChanged?(.cancelled)
			@unknown default:
				self.stateChanged?(.failed(nil))
			}
		}
	}

	func start(queue: DispatchQueue) {
		connection.start(queue: queue)
	}

	func send(_ data: Data) {
		connection.send(content: data, completion: .contentProcessed { _ in })
	}

	func receiveMessage(handler: @escaping (Data?, Error?) -> Void) {
		connection.receiveMessage { data, _, _, error in
			handler(data, error)
		}
	}

	func cancel() {
		connection.cancel()
	}
}


