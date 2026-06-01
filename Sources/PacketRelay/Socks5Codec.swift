import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif

/// SOCKS5 command byte values.
public enum Socks5Command: UInt8, Sendable {
    case connect = 0x01
    case bind = 0x02
    case udpAssociate = 0x03
    /// HEV extension: carries SOCKS UDP frames over the existing TCP control stream.
    case udpForward = 0x05
}

/// SOCKS5 target address representation.
public enum Socks5Address: Hashable, Sendable {
    case ipv4(String)
    case ipv6(String)
    case domain(String)
}

/// Parsed SOCKS5 request message.
public struct Socks5Request: Hashable, Sendable {
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
public struct Socks5UDPPacket: Hashable, Sendable {
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

/// Result of parsing HEV's TCP-carried UDP frame format from a stream buffer.
public enum Socks5TCPForwardUDPParseResult: Hashable, Sendable {
    case packet(Socks5UDPPacket, consumedBytes: Int)
    case needsMoreData
    case invalid
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
        guard buffer[buffer.startIndex + 2] == 0x00 else { return nil }
        let atyp = buffer[buffer.startIndex + 3]
        var index = buffer.startIndex + 4

        guard let address = parseAddress(from: buffer, atyp: atyp, index: &index) else { return nil }
        guard buffer.count >= index + 2 else { return nil }
        let port = UInt16(buffer[index]) << 8 | UInt16(buffer[index + 1])
        buffer.removeSubrange(buffer.startIndex ..< index + 2)
        return Socks5Request(command: command, address: address, port: port)
    }

    /// Returns the SOCKS5 reply code for a syntactically invalid request prefix, or `nil` if more bytes are needed.
    /// RFC 1928 reserves byte 2 as `0x00`; unsupported commands and address types have specific reply codes.
    public static func requestFailureReplyCode(_ buffer: Data) -> UInt8? {
        guard buffer.count >= 4 else { return nil }
        guard buffer[buffer.startIndex] == 0x05 else { return 0x01 }
        let commandRaw = buffer[buffer.startIndex + 1]
        if Socks5Command(rawValue: commandRaw) == nil {
            return 0x07
        }
        guard buffer[buffer.startIndex + 2] == 0x00 else { return 0x01 }
        let atyp = buffer[buffer.startIndex + 3]
        if atyp != 0x01, atyp != 0x03, atyp != 0x04 {
            return 0x08
        }
        return nil
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

    /// Parses HEV's TCP-carried UDP frame format.
    ///
    /// Frame layout:
    /// - 2 bytes: payload length, network byte order
    /// - 1 byte: header length, including the first 3 bytes
    /// - N bytes: SOCKS address and port
    /// - M bytes: UDP payload
    public static func parseTCPForwardUDPPacket(_ buffer: Data) -> Socks5TCPForwardUDPParseResult {
        parseTCPForwardUDPPacket(buffer, startIndex: buffer.startIndex)
    }

    static func parseTCPForwardUDPPacket(_ buffer: Data, startIndex start: Data.Index) -> Socks5TCPForwardUDPParseResult {
        let availableBytes = buffer.distance(from: start, to: buffer.endIndex)
        guard availableBytes >= 3 else {
            return .needsMoreData
        }

        let payloadLength = Int(UInt16(buffer[start]) << 8 | UInt16(buffer[start + 1]))
        let headerLength = Int(buffer[start + 2])
        guard headerLength >= 7 else {
            return .invalid
        }

        let totalLength = headerLength + payloadLength
        guard totalLength >= headerLength else {
            return .invalid
        }
        guard availableBytes >= totalLength else {
            return .needsMoreData
        }

        let addressStart = start + 3
        let payloadStart = start + headerLength
        guard addressStart < payloadStart else {
            return .invalid
        }

        var index = addressStart
        guard index < payloadStart else {
            return .invalid
        }
        let atyp = buffer[index]
        index += 1
        guard let address = parseAddress(from: buffer, endIndex: payloadStart, atyp: atyp, index: &index),
              payloadStart == index + 2
        else {
            return .invalid
        }

        let port = UInt16(buffer[index]) << 8 | UInt16(buffer[index + 1])
        let payload = Data(buffer[payloadStart ..< start + totalLength])
        return .packet(
            Socks5UDPPacket(address: address, port: port, payload: payload),
            consumedBytes: totalLength
        )
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
    public static func buildReply(code: UInt8, bindAddress: Socks5Address, bindPort: UInt16) -> Data? {
        guard let addressBytes = addressBytes(bindAddress) else {
            return nil
        }
        var data = Data([0x05, code, 0x00])
        data.append(contentsOf: addressBytes)
        data.append(UInt8((bindPort >> 8) & 0xFF))
        data.append(UInt8(bindPort & 0xFF))
        return data
    }

    /// Builds a SOCKS5 UDP datagram frame.
    /// - Parameters:
    ///   - address: Destination/source address.
    ///   - port: Destination/source port.
    ///   - payload: UDP payload bytes.
    public static func buildUDPPacket(address: Socks5Address, port: UInt16, payload: Data) -> Data? {
        guard let addressBytes = addressBytes(address) else {
            return nil
        }
        var data = Data([0x00, 0x00, 0x00])
        data.append(contentsOf: addressBytes)
        data.append(UInt8((port >> 8) & 0xFF))
        data.append(UInt8(port & 0xFF))
        data.append(payload)
        return data
    }

    /// Builds HEV's TCP-carried UDP frame format.
    public static func buildTCPForwardUDPPacket(address: Socks5Address, port: UInt16, payload: Data) -> Data? {
        guard payload.count <= Int(UInt16.max) else {
            return nil
        }
        guard let addressAndPort = validatedAddressPortBytes(address, port: port) else {
            return nil
        }
        let headerLength = 3 + addressAndPort.count
        guard headerLength <= Int(UInt8.max) else {
            return nil
        }

        var data = Data()
        data.append(UInt8((payload.count >> 8) & 0xFF))
        data.append(UInt8(payload.count & 0xFF))
        data.append(UInt8(headerLength))
        data.append(contentsOf: addressAndPort)
        data.append(payload)
        return data
    }

    private static func validatedAddressPortBytes(_ address: Socks5Address, port: UInt16) -> [UInt8]? {
        switch address {
        case .ipv4(let value):
            var bytes = [UInt8](repeating: 0, count: 4)
            let ok = bytes.withUnsafeMutableBufferPointer { buffer in
                value.withCString { inet_pton(AF_INET, $0, buffer.baseAddress) }
            }
            guard ok == 1 else { return nil }
            return [0x01] + bytes + [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)]
        case .ipv6(let value):
            var addr = in6_addr()
            let ok = value.withCString { inet_pton(AF_INET6, $0, &addr) }
            guard ok == 1 else { return nil }
            return [0x04] + withUnsafeBytes(of: &addr, { Array($0) }) + [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)]
        case .domain(let domain):
            let utf8 = Array(domain.utf8)
            guard !utf8.isEmpty, utf8.count <= Int(UInt8.max) else { return nil }
            return [0x03, UInt8(utf8.count)] + utf8 + [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)]
        }
    }

    private static func parseAddress(from data: Data, atyp: UInt8, index: inout Int) -> Socks5Address? {
        parseAddress(from: data, endIndex: data.endIndex, atyp: atyp, index: &index)
    }

    private static func parseAddress(from data: Data, endIndex: Data.Index, atyp: UInt8, index: inout Int) -> Socks5Address? {
        switch atyp {
        case 0x01:
            guard endIndex >= index + 4 else { return nil }
            let value = [data[index], data[index + 1], data[index + 2], data[index + 3]].map(String.init).joined(separator: ".")
            index += 4
            return .ipv4(value)
        case 0x04:
            guard endIndex >= index + 16 else { return nil }
            let addressData = Data(data[index ..< index + 16])
            guard let value = ipv6String(from: addressData) else { return nil }
            index += 16
            return .ipv6(value)
        case 0x03:
            guard endIndex > index else { return nil }
            let length = Int(data[index])
            index += 1
            guard length > 0 else { return nil }
            guard endIndex >= index + length else { return nil }
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
            guard length > 0 else { return nil }
            guard count >= index + length else { return nil }
            let buffer = UnsafeBufferPointer(start: data.baseAddress?.advanced(by: index), count: length)
            index += length
            return .domain(String(decoding: buffer, as: UTF8.self))
        default:
            return nil
        }
    }

    private static func addressBytes(_ address: Socks5Address) -> [UInt8]? {
        switch address {
        case .ipv4(let value):
            var bytes = [UInt8](repeating: 0, count: 4)
            let ok = bytes.withUnsafeMutableBufferPointer { buffer in
                value.withCString { inet_pton(AF_INET, $0, buffer.baseAddress) }
            }
            guard ok == 1 else { return nil }
            return [0x01] + bytes
        case .ipv6(let value):
            var addr = in6_addr()
            let ok = value.withCString { inet_pton(AF_INET6, $0, &addr) }
            guard ok == 1 else { return nil }
            return [0x04] + withUnsafeBytes(of: &addr, { Array($0) })
        case .domain(let domain):
            let utf8 = Array(domain.utf8)
            guard !utf8.isEmpty, utf8.count <= Int(UInt8.max) else { return nil }
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
