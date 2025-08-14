import Foundation

#if canImport(os)
import os
#endif

final class Observability {
	static let shared = Observability()

	#if canImport(os)
	private let log: OSLog
	private let enabled: Bool

	private init() {
		#if DEBUG
		enabled = true
		#else
		enabled = false
		#endif
		if #available(iOS 12.0, macOS 10.14, *) {
			log = OSLog(subsystem: "com.relativeprotocol", category: "signpost")
		} else {
			log = OSLog.disabled
		}
	}

	@discardableResult
	func begin(_ name: StaticString) -> OSSignpostID? {
		if !enabled { return nil }
		if #available(iOS 12.0, macOS 10.14, *) {
			let id = OSSignpostID(log: log)
			os_signpost(.begin, log: log, name: name, signpostID: id)
			return id
		}
		return nil
	}

	func end(_ name: StaticString, _ id: OSSignpostID?) {
		guard let id = id, enabled else { return }
		if #available(iOS 12.0, macOS 10.14, *) {
			os_signpost(.end, log: log, name: name, signpostID: id)
		}
	}

	func event(_ name: StaticString) {
		if !enabled { return }
		if #available(iOS 12.0, macOS 10.14, *) {
			os_signpost(.event, log: log, name: name)
		}
	}
	#else
	private init() {}
	func begin(_ name: StaticString) -> Any? { return nil }
	func end(_ name: StaticString, _ id: Any?) {}
	func event(_ name: StaticString) {}
	#endif
}


