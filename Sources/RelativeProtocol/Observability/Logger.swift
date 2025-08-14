import Foundation

enum LogLevel: Int, Comparable {
	case error = 0
	case warn = 1
	case info = 2
	case debug = 3
	case trace = 4

	static func < (lhs: LogLevel, rhs: LogLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

final class Logger {
	static let shared = Logger()
	private let queue = DispatchQueue(label: "com.relativeprotocol.logger")
	private var _level: LogLevel = {
		#if DEBUG
		return .info
		#else
		return .warn
		#endif
	}()

	private init() {}

	func setLevel(_ level: LogLevel) { queue.async { self._level = level } }

	func getLevel() -> LogLevel { var l: LogLevel = .warn; queue.sync { l = _level }; return l }

	func log(_ level: LogLevel, _ message: @autoclosure () -> String) {
		let enabled = getLevel() >= level
		guard enabled else { return }
		let ts = ISO8601DateFormatter().string(from: Date())
		print("[RelativeProtocol][\(ts)][\(levelLabel(level))] \(message())")
	}

	private func levelLabel(_ l: LogLevel) -> String {
		switch l {
		case .error: return "ERROR"
		case .warn: return "WARN"
		case .info: return "INFO"
		case .debug: return "DEBUG"
		case .trace: return "TRACE"
		}
	}
}

// Convenience free functions
func logError(_ msg: @autoclosure () -> String) { Logger.shared.log(.error, msg()) }
func logWarn(_ msg: @autoclosure () -> String) { Logger.shared.log(.warn, msg()) }
func logInfo(_ msg: @autoclosure () -> String) { Logger.shared.log(.info, msg()) }
func logDebug(_ msg: @autoclosure () -> String) { Logger.shared.log(.debug, msg()) }
func logTrace(_ msg: @autoclosure () -> String) { Logger.shared.log(.trace, msg()) }


