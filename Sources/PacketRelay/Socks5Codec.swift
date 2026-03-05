import Darwin
import Foundation

/// SOCKS5 command byte values from RFC 1928.
public enum Socks5Command: UInt8 {
    case connect = 0x01
    case bind = 0x02
    case udpAssociate = 0x03
}

/// SOCKS5 target address representation.
public enum Socks5Address: Hashable {
    case ipv4(String)
    case ipv6(String)
    case domain(String)
}

/// Parsed SOCKS5 request message.
public struct Socks5Request: Hashable {
    public let command: Socks5Command
    public let address: Socks5Address
    public let port: UInt16

    /// - Parameters:
    ///   - command: Requested SOCKS command.
    ///   - address: Requested destination address.
    ///   - port: Requested destination port.
    public init(command: Socks5Command, address: Socks5Address, port: UInt16) {
        self.command = command
        self.address = address
        self.port = port
    }
}

/// Parsed SOCKS5 UDP ASSOCIATE datagram.
public struct Socks5UDPPacket: Hashable {
    public let address: Socks5Address
    public let port: UInt16
    public let payload: Data

    /// - Parameters:
    ///   - address: Destination address encoded in UDP frame.
    ///   - port: Destination port encoded in UDP frame.
    ///   - payload: UDP payload bytes.
    public init(address: Socks5Address, port: UInt16, payload: Data) {
        self.address = address
        self.port = port
        self.payload = payload
    }
}

/// Stateless encoder/decoder for SOCKS5 handshake/request/UDP formats.
public enum Socks5Codec {
    /// Attempts to parse the SOCKS5 greeting from the front of `buffer`.
    /// - Parameter buffer: Mutable receive buffer. Consumed bytes are removed on success.
    /// - Returns: Supported auth methods, or `nil` if more bytes are required.
    public static func parseGreeting(_ buffer: inout Data) -> [UInt8]? {
        guard buffer.count >= 2 else { return nil }
        let version = buffer[buffer.startIndex]
        guard version == 0x05 else { return nil }
        let methodCount = Int(buffer[buffer.startIndex + 1])
        let totalLength = 2 + methodCount
        guard buffer.count >= totalLength else { return nil }
        let methods = Array(buffer[buffer.startIndex + 2 ..< buffer.startIndex + totalLength])
        buffer.removeSubrange(buffer.startIndex ..< buffer.startIndex + totalLength)
        return methods
    }

    /// Attempts to parse a SOCKS5 request from the front of `buffer`.
    /// - Parameter buffer: Mutable receive buffer. Consumed bytes are removed on success.
    /// - Returns: Parsed request, or `nil` if more bytes are required.
    public static func parseRequest(_ buffer: inout Data) -> Socks5Request? {
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
        buffer.removeSubrange(buffer.startIndex ..< index + 2)
        return Socks5Request(command: command, address: address, port: port)
    }

    /// Parses a SOCKS5 UDP request/response frame.
    /// - Parameters:
    ///   - data: Datagram bytes.
    ///   - count: Number of bytes in the buffer.
    public static func parseUDPPacket(_ data: UnsafeBufferPointer<UInt8>, count: Int) -> Socks5UDPPacket? {
        guard count >= 4 else { return nil }
        guard data[0] == 0, data[1] == 0 else { return nil }
        let frag = data[2]
        guard frag == 0 else { return nil }
        let atyp = data[3]
        var index = 4

        guard let address = parseAddress(from: data, count: count, atyp: atyp, index: &index) else { return nil }
        guard count >= index + 2 else { return nil }
        let port = UInt16(data[index]) << 8 | UInt16(data[index + 1])
        let payloadStart = index + 2
        let payload = Data(data[payloadStart ..< count])
        return Socks5UDPPacket(address: address, port: port, payload: payload)
    }

    /// Builds server method selection reply.
    /// - Parameter method: Chosen auth method byte.
    public static func buildMethodSelection(method: UInt8) -> Data {
        Data([0x05, method])
    }

    /// Builds a SOCKS5 command reply frame.
    /// - Parameters:
    ///   - code: Reply status code.
    ///   - bindAddress: Bound address to return.
    ///   - bindPort: Bound port to return.
    public static func buildReply(code: UInt8, bindAddress: Socks5Address, bindPort: UInt16) -> Data {
        var data = Data([0x05, code, 0x00])
        data.append(contentsOf: addressBytes(bindAddress))
        data.append(UInt8((bindPort >> 8) & 0xFF))
        data.append(UInt8(bindPort & 0xFF))
        return data
    }

    /// Builds a SOCKS5 UDP datagram frame.
    /// - Parameters:
    ///   - address: Destination/source address.
    ///   - port: Destination/source port.
    ///   - payload: UDP payload bytes.
    public static func buildUDPPacket(address: Socks5Address, port: UInt16, payload: Data) -> Data {
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
            let value = [data[index], data[index + 1], data[index + 2], data[index + 3]].map(String.init).joined(separator: ".")
            index += 4
            return .ipv4(value)
        case 0x04:
            guard data.count >= index + 16 else { return nil }
            let addressData = Data(data[index ..< index + 16])
            guard let value = ipv6String(from: addressData) else { return nil }
            index += 16
            return .ipv6(value)
        case 0x03:
            guard data.count > index else { return nil }
            let length = Int(data[index])
            index += 1
            guard data.count >= index + length else { return nil }
            let domain = String(decoding: data[index ..< index + length], as: UTF8.self)
            index += length
            return .domain(domain)
        default:
            return nil
        }
    }

    private static func parseAddress(
        from data: UnsafeBufferPointer<UInt8>,
        count: Int,
        atyp: UInt8,
        index: inout Int
    ) -> Socks5Address? {
        switch atyp {
        case 0x01:
            guard count >= index + 4 else { return nil }
            let octets = [data[index], data[index + 1], data[index + 2], data[index + 3]]
            index += 4
            let value = octets.map(String.init).joined(separator: ".")
            return .ipv4(value)
        case 0x04:
            guard count >= index + 16 else { return nil }
            let addressData = Data(data[index ..< index + 16])
            guard let value = ipv6String(from: addressData) else { return nil }
            index += 16
            return .ipv6(value)
        case 0x03:
            guard count > index else { return nil }
            let length = Int(data[index])
            index += 1
            guard count >= index + length else { return nil }
            let buffer = UnsafeBufferPointer(start: data.baseAddress?.advanced(by: index), count: length)
            index += length
            return .domain(String(decoding: buffer, as: UTF8.self))
        default:
            return nil
        }
    }

    private static func addressBytes(_ address: Socks5Address) -> [UInt8] {
        switch address {
        case .ipv4(let value):
            var bytes = [UInt8](repeating: 0, count: 4)
            _ = value.withCString { inet_pton(AF_INET, $0, &bytes) }
            return [0x01] + bytes
        case .ipv6(let value):
            var addr = in6_addr()
            let ok = value.withCString { inet_pton(AF_INET6, $0, &addr) }
            if ok == 1 {
                return [0x04] + withUnsafeBytes(of: &addr, { Array($0) })
            }
            return [0x04] + [UInt8](repeating: 0, count: 16)
        case .domain(let domain):
            let utf8 = Array(domain.utf8.prefix(255))
            return [0x03, UInt8(utf8.count)] + utf8
        }
    }

    private static func ipv6String(from data: Data) -> String? {
        guard data.count == 16 else { return nil }
        return data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return nil }
            var addr = in6_addr()
            memcpy(&addr, base, 16)
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &addr, &output, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return nil
            }
            return String(cString: output)
        }
    }
}
