import Darwin
import Foundation
import RelativeProtocolCore

enum Socks5Command: UInt8 {
    case connect = 0x01
    case bind = 0x02
    case udpAssociate = 0x03
}

enum Socks5Address: Hashable {
    case ipv4(String)
    case ipv6(String)
    case domain(String)
}

struct Socks5Request: Hashable {
    let command: Socks5Command
    let address: Socks5Address
    let port: UInt16
}

struct Socks5UDPPacket: Hashable {
    let address: Socks5Address
    let port: UInt16
    let payload: Data
}

enum Socks5Codec {
    static func parseGreeting(_ buffer: inout Data) -> [UInt8]? {
        guard buffer.count >= 2 else { return nil }
        let version = buffer[buffer.startIndex]
        guard version == 0x05 else { return nil }
        let methodCount = Int(buffer[buffer.startIndex + 1])
        let totalLength = 2 + methodCount
        guard buffer.count >= totalLength else { return nil }
        let methods = Array(buffer[buffer.startIndex + 2..<buffer.startIndex + totalLength])
        buffer.removeSubrange(buffer.startIndex..<buffer.startIndex + totalLength)
        return methods
    }

    static func parseRequest(_ buffer: inout Data) -> Socks5Request? {
        guard buffer.count >= 4 else { return nil }
        let version = buffer[buffer.startIndex]
        guard version == 0x05 else { return nil }
        let commandRaw = buffer[buffer.startIndex + 1]
        guard let command = Socks5Command(rawValue: commandRaw) else { return nil }
        let atyp = buffer[buffer.startIndex + 3]
        var index = buffer.startIndex + 4

        guard let address = parseAddress(from: buffer, atyp: atyp, index: &index) else { return nil }
        guard buffer.count >= index + 2 else { return nil }
        let port = UInt16(buffer[index]) << 8 | UInt16(buffer[index + 1])
        buffer.removeSubrange(buffer.startIndex..<index + 2)
        return Socks5Request(command: command, address: address, port: port)
    }

    static func parseUDPPacket(_ data: Data) -> Socks5UDPPacket? {
        guard data.count >= 4 else { return nil }
        guard data[data.startIndex] == 0, data[data.startIndex + 1] == 0 else { return nil }
        let frag = data[data.startIndex + 2]
        guard frag == 0 else { return nil }
        let atyp = data[data.startIndex + 3]
        var index = data.startIndex + 4

        guard let address = parseAddress(from: data, atyp: atyp, index: &index) else { return nil }
        guard data.count >= index + 2 else { return nil }
        let port = UInt16(data[index]) << 8 | UInt16(data[index + 1])
        let payload = data.subdata(in: index + 2..<data.endIndex)
        return Socks5UDPPacket(address: address, port: port, payload: payload)
    }

    static func buildMethodSelection(method: UInt8) -> Data {
        Data([0x05, method])
    }

    static func buildReply(code: UInt8, bindAddress: Socks5Address, bindPort: UInt16) -> Data {
        var data = Data([0x05, code, 0x00])
        data.append(contentsOf: addressBytes(bindAddress))
        data.append(UInt8((bindPort >> 8) & 0xFF))
        data.append(UInt8(bindPort & 0xFF))
        return data
    }

    static func buildUDPPacket(address: Socks5Address, port: UInt16, payload: Data) -> Data {
        var data = Data([0x00, 0x00, 0x00])
        data.append(contentsOf: addressBytes(address))
        data.append(UInt8((port >> 8) & 0xFF))
        data.append(UInt8(port & 0xFF))
        data.append(payload)
        return data
    }

    private static func parseAddress(from data: Data, atyp: UInt8, index: inout Int) -> Socks5Address? {
        switch atyp {
        case 0x01:
            guard data.count >= index + 4 else { return nil }
            let addrData = data.subdata(in: index..<index + 4)
            index += 4
            guard let address = IPAddress(bytes: addrData) else { return nil }
            return .ipv4(address.stringValue)
        case 0x04:
            guard data.count >= index + 16 else { return nil }
            let addrData = data.subdata(in: index..<index + 16)
            index += 16
            guard let address = IPAddress(bytes: addrData) else { return nil }
            return .ipv6(address.stringValue)
        case 0x03:
            guard data.count > index else { return nil }
            let length = Int(data[index])
            index += 1
            guard data.count >= index + length else { return nil }
            let domainData = data.subdata(in: index..<index + length)
            index += length
            guard let domain = String(data: domainData, encoding: .utf8) else { return nil }
            return .domain(domain)
        default:
            return nil
        }
    }

    private static func addressBytes(_ address: Socks5Address) -> [UInt8] {
        switch address {
        case .ipv4(let value):
            var bytes = [UInt8](repeating: 0, count: 4)
            if let data = ipv4Data(from: value) {
                data.copyBytes(to: &bytes, count: 4)
            }
            return [0x01] + bytes
        case .ipv6(let value):
            var bytes = [UInt8](repeating: 0, count: 16)
            if let data = ipv6Data(from: value) {
                data.copyBytes(to: &bytes, count: 16)
            }
            return [0x04] + bytes
        case .domain(let domain):
            let utf8 = Array(domain.utf8)
            return [0x03, UInt8(utf8.count)] + utf8
        }
    }

    private static func ipv4Data(from string: String) -> Data? {
        var addr = in_addr()
        guard string.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return nil }
        return Data(bytes: &addr, count: MemoryLayout<in_addr>.size)
    }

    private static func ipv6Data(from string: String) -> Data? {
        var addr = in6_addr()
        guard string.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return nil }
        return Data(bytes: &addr, count: MemoryLayout<in6_addr>.size)
    }
}
