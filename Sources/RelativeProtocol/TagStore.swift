import Foundation

final class TagStore {
    static let shared = TagStore()
    private let queue = DispatchQueue(label: "com.relativeprotocol.tagstore", attributes: .concurrent)
    private var map: [String: String] = [:]

    private init() {}

    func setTagBothDirections(version: Int, srcIP: Data, srcPort: UInt16, dstIP: Data, dstPort: UInt16, proto: UInt8, tag: String) {
        let fwd = key(version: version, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: proto)
        let rev = key(version: version, srcIP: dstIP, srcPort: dstPort, dstIP: srcIP, dstPort: srcPort, proto: proto)
        queue.async(flags: .barrier) {
            self.map[fwd] = tag
            self.map[rev] = tag
        }
    }

	// Synchronous variant for tests to avoid races
	func setTagBothDirectionsSync(version: Int, srcIP: Data, srcPort: UInt16, dstIP: Data, dstPort: UInt16, proto: UInt8, tag: String) {
		let fwd = key(version: version, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: proto)
		let rev = key(version: version, srcIP: dstIP, srcPort: dstPort, dstIP: srcIP, dstPort: srcPort, proto: proto)
		queue.sync(flags: .barrier) {
			self.map[fwd] = tag
			self.map[rev] = tag
		}
	}

    func tagForPacket(bytes: UnsafePointer<UInt8>, length: Int) -> String? {
        guard length > 0 else { return nil }
        let version = bytes.pointee >> 4
        if version == 4 {
            guard length >= 20 else { return nil }
            let ihl = Int(bytes.pointee & 0x0F) * 4
            guard length >= ihl + 8 else { return nil }
            let proto = bytes.advanced(by: 9).pointee
            let srcIP = Data(bytes: bytes.advanced(by: 12), count: 4)
            let dstIP = Data(bytes: bytes.advanced(by: 16), count: 4)
            var srcPort: UInt16 = 0
            var dstPort: UInt16 = 0
            if proto == 6 || proto == 17 {
                srcPort = readBE16(bytes.advanced(by: ihl + 0))
                dstPort = readBE16(bytes.advanced(by: ihl + 2))
            }
            let k = key(version: 4, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: proto)
            return lookup(k)
        } else if version == 6 {
            guard length >= 40 else { return nil }
            let nextHeader = bytes.advanced(by: 6).pointee
            let srcIP = Data(bytes: bytes.advanced(by: 8), count: 16)
            let dstIP = Data(bytes: bytes.advanced(by: 24), count: 16)
            var srcPort: UInt16 = 0
            var dstPort: UInt16 = 0
            if nextHeader == 6 || nextHeader == 17 {
                srcPort = readBE16(bytes.advanced(by: 40 + 0))
                dstPort = readBE16(bytes.advanced(by: 40 + 2))
            }
            let k = key(version: 6, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: nextHeader)
            return lookup(k)
        }
        return nil
    }

    private func lookup(_ key: String) -> String? {
        var v: String?
        queue.sync { v = map[key] }
        return v
    }

    private func key(version: Int, srcIP: Data, srcPort: UInt16, dstIP: Data, dstPort: UInt16, proto: UInt8) -> String {
        let s = srcIP.base64EncodedString()
        let d = dstIP.base64EncodedString()
        return "\(version)|\(s)|\(srcPort)|\(d)|\(dstPort)|\(proto)"
    }

    private func readBE16(_ ptr: UnsafePointer<UInt8>) -> UInt16 {
        let b0 = UInt16(ptr.pointee)
        let b1 = UInt16(ptr.advanced(by: 1).pointee)
        return (b0 << 8) | b1
    }
}


