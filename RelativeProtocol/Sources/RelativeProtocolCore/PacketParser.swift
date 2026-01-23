import Darwin
import Foundation

public enum PacketParser {
    private static let dnsPort: UInt16 = 53
    private static let maxIPv6Extensions = 8

    public static func parse(_ data: Data, ipVersionHint: Int32?) -> PacketMetadata? {
        guard data.count >= 1 else { return nil }
        let version = data[data.startIndex] >> 4
        if version == 4 {
            return parseIPv4(data)
        }
        if version == 6 {
            return parseIPv6(data)
        }
        if ipVersionHint == AF_INET {
            return parseIPv4(data)
        }
        if ipVersionHint == AF_INET6 {
            return parseIPv6(data)
        }
        return nil
    }

    private static func parseIPv4(_ data: Data) -> PacketMetadata? {
        guard data.count >= 20 else { return nil }
        let versionAndIHL = data[data.startIndex]
        let version = versionAndIHL >> 4
        guard version == 4 else { return nil }
        let ihl = Int(versionAndIHL & 0x0F) * 4
        guard ihl >= 20, data.count >= ihl else { return nil }

        let protocolByte = data[data.startIndex + 9]
        let transport = TransportProtocol(rawValue: protocolByte)
        guard let srcAddress = IPAddress(bytes: data.subdata(in: 12..<16)),
              let dstAddress = IPAddress(bytes: data.subdata(in: 16..<20)) else {
            return nil
        }

        var srcPort: UInt16?
        var dstPort: UInt16?
        var dnsQuery: String?

        if transport == .tcp || transport == .udp {
            guard data.count >= ihl + 4 else { return nil }
            srcPort = readUInt16(data, offset: ihl)
            dstPort = readUInt16(data, offset: ihl + 2)

            if transport == .udp {
                if let srcPort, let dstPort, (srcPort == dnsPort || dstPort == dnsPort) {
                    let payloadOffset = ihl + 8
                    if data.count > payloadOffset {
                        dnsQuery = parseDNSQueryName(data, payloadOffset: payloadOffset)
                    }
                }
            }
        }

        return PacketMetadata(
            ipVersion: .v4,
            transport: transport,
            srcAddress: srcAddress,
            dstAddress: dstAddress,
            srcPort: srcPort,
            dstPort: dstPort,
            length: data.count,
            dnsQueryName: dnsQuery
        )
    }

    private static func parseIPv6(_ data: Data) -> PacketMetadata? {
        guard data.count >= 40 else { return nil }
        let version = data[data.startIndex] >> 4
        guard version == 6 else { return nil }

        var nextHeader = data[data.startIndex + 6]
        var offset = 40

        guard let srcAddress = IPAddress(bytes: data.subdata(in: 8..<24)),
              let dstAddress = IPAddress(bytes: data.subdata(in: 24..<40)) else {
            return nil
        }

        var extensionsSeen = 0
        while isIPv6ExtensionHeader(nextHeader) && extensionsSeen < maxIPv6Extensions {
            guard data.count >= offset + 2 else { return nil }
            let currentHeader = nextHeader
            nextHeader = data[data.startIndex + offset]
            let lengthField = data[data.startIndex + offset + 1]

            let headerLength: Int
            switch currentHeader {
            case 44: // Fragment
                headerLength = 8
            case 51: // AH
                headerLength = (Int(lengthField) + 2) * 4
            case 50: // ESP
                return PacketMetadata(
                    ipVersion: .v6,
                    transport: TransportProtocol(rawValue: currentHeader),
                    srcAddress: srcAddress,
                    dstAddress: dstAddress,
                    srcPort: nil,
                    dstPort: nil,
                    length: data.count,
                    dnsQueryName: nil
                )
            default:
                headerLength = (Int(lengthField) + 1) * 8
            }

            offset += headerLength
            extensionsSeen += 1
            guard data.count >= offset else { return nil }
        }

        let transport = TransportProtocol(rawValue: nextHeader)
        var srcPort: UInt16?
        var dstPort: UInt16?
        var dnsQuery: String?

        if transport == .tcp || transport == .udp {
            guard data.count >= offset + 4 else { return nil }
            srcPort = readUInt16(data, offset: offset)
            dstPort = readUInt16(data, offset: offset + 2)

            if transport == .udp {
                if let srcPort, let dstPort, (srcPort == dnsPort || dstPort == dnsPort) {
                    let payloadOffset = offset + 8
                    if data.count > payloadOffset {
                        dnsQuery = parseDNSQueryName(data, payloadOffset: payloadOffset)
                    }
                }
            }
        }

        return PacketMetadata(
            ipVersion: .v6,
            transport: transport,
            srcAddress: srcAddress,
            dstAddress: dstAddress,
            srcPort: srcPort,
            dstPort: dstPort,
            length: data.count,
            dnsQueryName: dnsQuery
        )
    }

    private static func isIPv6ExtensionHeader(_ header: UInt8) -> Bool {
        switch header {
        case 0, 43, 44, 50, 51, 60:
            return true
        default:
            return false
        }
    }

    private static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        let upper = UInt16(data[data.startIndex + offset]) << 8
        let lower = UInt16(data[data.startIndex + offset + 1])
        return upper | lower
    }

    private static func parseDNSQueryName(_ data: Data, payloadOffset: Int) -> String? {
        guard data.count >= payloadOffset + 12 else { return nil }
        let qdCount = readUInt16(data, offset: payloadOffset + 4)
        guard qdCount > 0 else { return nil }

        var index = payloadOffset + 12
        var labels: [String] = []
        var seen = 0

        while index < data.count && seen < 128 {
            let length = Int(data[data.startIndex + index])
            index += 1
            seen += 1

            if length == 0 {
                break
            }
            if length & 0xC0 == 0xC0 {
                return nil
            }
            guard index + length <= data.count else { return nil }
            let labelData = data.subdata(in: index..<(index + length))
            if let label = String(data: labelData, encoding: .ascii) {
                labels.append(label)
            } else {
                return nil
            }
            index += length
        }

        guard !labels.isEmpty else { return nil }
        return labels.joined(separator: ".")
    }
}
