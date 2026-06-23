// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Analytics
import Foundation
import TunnelRuntime

public enum PcapReplayError: Error, Equatable, CustomStringConvertible {
    case invalidHeader
    case unsupportedPcapNG
    case unsupportedLinkType(UInt32)
    case truncatedRecord(offset: Int)
    case invalidPacketLength(UInt32)

    public var description: String {
        switch self {
        case .invalidHeader:
            return "Invalid classic PCAP header"
        case .unsupportedPcapNG:
            return "PCAPNG is not replayed directly yet; convert to classic PCAP for this harness"
        case .unsupportedLinkType(let linkType):
            return "Unsupported PCAP link type \(linkType); use RAW/IP or Ethernet captures"
        case .truncatedRecord(let offset):
            return "Truncated PCAP record at byte offset \(offset)"
        case .invalidPacketLength(let length):
            return "Invalid PCAP packet length \(length)"
        }
    }
}

public struct PcapReplayOptions: Sendable, Equatable {
    public let maximumPackets: Int?
    public let direction: String

    public init(maximumPackets: Int? = nil, direction: String = "outbound") {
        self.maximumPackets = maximumPackets.map { max(0, $0) }
        self.direction = direction
    }
}

/// Classic PCAP replay adapter for unprivileged, deterministic packet-shape harness runs.
public struct PcapReplayAdapter: LocalFlowAdapter {
    private let fileURL: URL
    private let options: PcapReplayOptions

    public init(fileURL: URL, options: PcapReplayOptions = PcapReplayOptions()) {
        self.fileURL = fileURL
        self.options = options
    }

    public func producePackets(
        scenario: HarnessScenario,
        clock: any Clock,
        random: any RandomSource,
        emit: @escaping @Sendable (PacketSample) async throws -> Void
    ) async throws {
        _ = scenario
        _ = random
        let packets = try ClassicPcapFile(data: Data(contentsOf: fileURL)).ipPackets(maximumPackets: options.maximumPackets)
        for (index, packet) in packets.enumerated() {
            let timestamp: Date
            if let packetTimestamp = packet.timestamp {
                timestamp = packetTimestamp
            } else {
                timestamp = await clock.now()
            }
            try await emit(
                LocalPacketSampleFactory.makeSample(
                    packet: packet.payload,
                    timestamp: timestamp,
                    direction: options.direction,
                    sequence: index
                )
            )
            await clock.advance(by: 0.001)
        }
    }
}

private struct PcapPacket {
    let timestamp: Date?
    let payload: Data
}

private struct ClassicPcapFile {
    private enum ByteOrder {
        case little
        case big

        func uint16(_ data: Data, _ offset: Int) -> UInt16 {
            let value = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
            switch self {
            case .big:
                return value
            case .little:
                return value.byteSwapped
            }
        }

        func uint32(_ data: Data, _ offset: Int) -> UInt32 {
            let value = (UInt32(data[offset]) << 24) |
                (UInt32(data[offset + 1]) << 16) |
                (UInt32(data[offset + 2]) << 8) |
                UInt32(data[offset + 3])
            switch self {
            case .big:
                return value
            case .little:
                return value.byteSwapped
            }
        }
    }

    private enum TimestampResolution {
        case microseconds
        case nanoseconds

        var divisor: TimeInterval {
            switch self {
            case .microseconds:
                return 1_000_000
            case .nanoseconds:
                return 1_000_000_000
            }
        }
    }

    private let data: Data

    init(data: Data) throws {
        self.data = data
        guard data.count >= 4 else {
            throw PcapReplayError.invalidHeader
        }
    }

    func ipPackets(maximumPackets: Int?) throws -> [PcapPacket] {
        let header = try parseHeader()
        var offset = 24
        var packets: [PcapPacket] = []

        while offset < data.count {
            if let maximumPackets, packets.count >= maximumPackets {
                break
            }
            guard data.count >= offset + 16 else {
                throw PcapReplayError.truncatedRecord(offset: offset)
            }

            let seconds = header.byteOrder.uint32(data, offset)
            let fraction = header.byteOrder.uint32(data, offset + 4)
            let includedLength = header.byteOrder.uint32(data, offset + 8)
            let originalLength = header.byteOrder.uint32(data, offset + 12)
            guard includedLength <= originalLength, includedLength <= 262_144 else {
                throw PcapReplayError.invalidPacketLength(includedLength)
            }

            let packetStart = offset + 16
            let packetEnd = packetStart + Int(includedLength)
            guard data.count >= packetEnd else {
                throw PcapReplayError.truncatedRecord(offset: offset)
            }

            let frame = data[packetStart ..< packetEnd]
            if let ipPayload = try extractIPPacket(from: frame, linkType: header.linkType) {
                let timestamp = Date(timeIntervalSince1970: TimeInterval(seconds) + TimeInterval(fraction) / header.resolution.divisor)
                packets.append(PcapPacket(timestamp: timestamp, payload: ipPayload))
            }
            offset = packetEnd
        }

        return packets
    }

    private func parseHeader() throws -> (byteOrder: ByteOrder, resolution: TimestampResolution, linkType: UInt32) {
        let magic = [data[0], data[1], data[2], data[3]]
        let byteOrder: ByteOrder
        let resolution: TimestampResolution
        switch magic {
        case [0xd4, 0xc3, 0xb2, 0xa1]:
            byteOrder = .little
            resolution = .microseconds
        case [0xa1, 0xb2, 0xc3, 0xd4]:
            byteOrder = .big
            resolution = .microseconds
        case [0x4d, 0x3c, 0xb2, 0xa1]:
            byteOrder = .little
            resolution = .nanoseconds
        case [0xa1, 0xb2, 0x3c, 0x4d]:
            byteOrder = .big
            resolution = .nanoseconds
        case [0x0a, 0x0d, 0x0d, 0x0a]:
            throw PcapReplayError.unsupportedPcapNG
        default:
            throw PcapReplayError.invalidHeader
        }

        guard data.count >= 24 else {
            throw PcapReplayError.invalidHeader
        }
        let major = byteOrder.uint16(data, 4)
        guard major == 2 else {
            throw PcapReplayError.invalidHeader
        }
        return (byteOrder, resolution, byteOrder.uint32(data, 20))
    }

    private func extractIPPacket(from frame: Data.SubSequence, linkType: UInt32) throws -> Data? {
        switch linkType {
        case 1:
            return extractEthernetPayload(from: frame)
        case 101, 228, 229:
            return Data(frame)
        default:
            throw PcapReplayError.unsupportedLinkType(linkType)
        }
    }

    private func extractEthernetPayload(from frame: Data.SubSequence) -> Data? {
        guard frame.count >= 14 else {
            return nil
        }

        let start = frame.startIndex
        var etherTypeOffset = start + 12
        var payloadOffset = start + 14
        var etherType = (UInt16(frame[etherTypeOffset]) << 8) | UInt16(frame[etherTypeOffset + 1])
        if etherType == 0x8100, frame.count >= 18 {
            etherTypeOffset = start + 16
            payloadOffset = start + 18
            etherType = (UInt16(frame[etherTypeOffset]) << 8) | UInt16(frame[etherTypeOffset + 1])
        }

        guard etherType == 0x0800 || etherType == 0x86dd else {
            return nil
        }
        return Data(frame[payloadOffset ..< frame.endIndex])
    }
}
