// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

import Foundation
import Observability
import TunnelRuntime
#if os(Linux)
import Glibc
#else
import Darwin
#endif

/// Event kind used by the app-facing rolling packet tap.
/// Decision: the tunnel writes fewer, more meaningful events (`flowOpen`, `flowSlice`, `flowClose`, `metadata`,
/// `burst`, `activitySample`, `packetCue`, `sourceAppFlow`)
/// instead of one rich sample for every admitted packet.
public enum PacketSampleKind: String, Codable, Sendable, Equatable, CaseIterable {
    case flowOpen
    case flowSlice
    case flowClose
    case metadata
    case burst
    case activitySample
    case packetCue
    case sourceAppFlow
}

/// App-supplied session context stamped onto detector-facing records when available.
/// Ownership: the VPN can carry these fields, but cannot infer app-open or foreground readiness on its own.
public struct DetectorSessionContext: Codable, Sendable, Equatable {
    public let sessionId: String?
    public let packetStreamStartedAtMs: Double?
    public let foregroundReadyAtMs: Double?
    public let appOpenAtMs: Double?
    public let targetApp: String?

    public init(
        sessionId: String? = nil,
        packetStreamStartedAtMs: Double? = nil,
        foregroundReadyAtMs: Double? = nil,
        appOpenAtMs: Double? = nil,
        targetApp: String? = nil
    ) {
        self.sessionId = sessionId
        self.packetStreamStartedAtMs = packetStreamStartedAtMs
        self.foregroundReadyAtMs = foregroundReadyAtMs
        self.appOpenAtMs = appOpenAtMs
        self.targetApp = targetApp
    }
}

public enum SourceAppAttributionSource: String, Codable, Sendable, Equatable {
    case contentFilter
}

public enum SourceAppAttributionMode: Codable, Sendable, Equatable {
    case disabled
    case contentFilterPassive(targetBundleIDs: Set<String>)
}

public struct SourceAppFlowAttribution: Codable, Sendable, Equatable {
    public let observedAtMs: Double
    public let sourceAppIdentifier: String?
    public let sourceAppUniqueIdentifierHash: String?
    public let sourceAppVersion: String?
    public let attributionFlowId: String?
    public let attributionSource: SourceAppAttributionSource
    public let localEndpoint: String?
    public let remoteEndpoint: String?
    public let remoteHostname: String?

    public init(
        observedAtMs: Double,
        sourceAppIdentifier: String?,
        sourceAppUniqueIdentifierHash: String? = nil,
        sourceAppVersion: String? = nil,
        attributionFlowId: String? = nil,
        attributionSource: SourceAppAttributionSource = .contentFilter,
        localEndpoint: String? = nil,
        remoteEndpoint: String? = nil,
        remoteHostname: String? = nil
    ) {
        self.observedAtMs = observedAtMs
        self.sourceAppIdentifier = sourceAppIdentifier
        self.sourceAppUniqueIdentifierHash = sourceAppUniqueIdentifierHash
        self.sourceAppVersion = sourceAppVersion
        self.attributionFlowId = attributionFlowId
        self.attributionSource = attributionSource
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.remoteHostname = remoteHostname
    }
}

public enum AddressScopeFamily: String, Codable, Sendable, Equatable, Hashable {
    case meta
    case tiktok
    case unknown
}

public enum AddressScopeSource: String, Codable, Sendable, Equatable, Hashable {
    case prefix
    case role
    case sourceApp
}

/// Lifecycle reason attached to `flowClose` records.
public enum FlowCloseReason: String, Codable, Sendable, Equatable {
    case tcpFin
    case tcpRst
    case idleEviction
    case overflowEviction
}

/// One app-facing packet intelligence event.
public struct PacketSample: Codable, Sendable, Equatable {
    public let kind: PacketSampleKind
    public let timestamp: Date
    public let direction: String
    public let flowId: String
    public let bytes: Int
    public let packetCount: Int?
    public let flowPacketCount: Int?
    public let flowByteCount: Int?
    public let protocolHint: String
    public let ipVersion: UInt8?
    public let transportProtocolNumber: UInt8?
    public let sourceAddress: String?
    public let sourcePort: UInt16?
    public let destinationAddress: String?
    public let destinationPort: UInt16?
    public let registrableDomain: String?
    public let dnsQueryName: String?
    public let dnsCname: String?
    public let dnsAnswerAddresses: [String]?
    public let tlsServerName: String?
    public let quicVersion: UInt32?
    public let quicPacketType: String?
    public let quicDestinationConnectionId: String?
    public let quicSourceConnectionId: String?
    public let classification: String?
    public let closeReason: FlowCloseReason?
    public let largePacketCount: Int?
    public let smallPacketCount: Int?
    public let udpPacketCount: Int?
    public let tcpPacketCount: Int?
    public let quicInitialCount: Int?
    public let tcpSynCount: Int?
    public let tcpFinCount: Int?
    public let tcpRstCount: Int?
    public let burstDurationMs: Int?
    public let burstPacketCount: Int?
    public let leadingBytes200ms: Int?
    public let leadingPackets200ms: Int?
    public let leadingBytes600ms: Int?
    public let leadingPackets600ms: Int?
    public let burstLargePacketCount: Int?
    public let burstUdpPacketCount: Int?
    public let burstTcpPacketCount: Int?
    public let burstQuicInitialCount: Int?
    public let associatedDomain: String?
    public let associationSource: DetectorAssociationSource?
    public let associationAgeMs: Int?
    public let associationConfidence: Double?
    public let lineageID: UInt64?
    public let lineageGeneration: Int?
    public let lineageAgeMs: Int?
    public let lineageReuseGapMs: Int?
    public let lineageReopenCount: Int?
    public let lineageSiblingCount: Int?
    public let pathEpoch: UInt32?
    public let pathInterfaceClass: PathInterfaceClass?
    public let pathIsExpensive: Bool?
    public let pathIsConstrained: Bool?
    public let pathSupportsDNS: Bool?
    public let pathChangedRecently: Bool?
    public let serviceFamily: String?
    public let serviceFamilyConfidence: Double?
    public let serviceAttributionSourceMask: UInt16?
    public let packetLength: Int?
    public let transportPayloadLength: Int?
    public let tcpFlags: UInt8?
    public let tcpAck: Bool?
    public let tcpPsh: Bool?
    public let sessionId: String?
    public let packetStreamStartedAtMs: Double?
    public let foregroundReadyAtMs: Double?
    public let appOpenAtMs: Double?
    public let targetApp: String?
    public let remoteAddress: String?
    public let remotePort: UInt16?
    public let remoteEndpoint: String?
    public let ownerKey: String?
    public let role: String?
    public let addressScopeFamily: AddressScopeFamily?
    public let addressScopeSource: AddressScopeSource?
    public let addressScopeConfidence: Double?
    public let sourceAppIdentifier: String?
    public let sourceAppUniqueIdentifierHash: String?
    public let sourceAppVersion: String?
    public let attributionFlowId: String?
    public let attributionSource: SourceAppAttributionSource?
    public let attributionObservedAtMs: Double?
    public let localEndpoint: String?
    public let remoteHostname: String?

    public init(
        kind: PacketSampleKind = .activitySample,
        timestamp: Date,
        direction: String,
        flowId: String,
        bytes: Int,
        packetCount: Int? = nil,
        flowPacketCount: Int? = nil,
        flowByteCount: Int? = nil,
        protocolHint: String,
        ipVersion: UInt8? = nil,
        transportProtocolNumber: UInt8? = nil,
        sourceAddress: String? = nil,
        sourcePort: UInt16? = nil,
        destinationAddress: String? = nil,
        destinationPort: UInt16? = nil,
        registrableDomain: String? = nil,
        dnsQueryName: String? = nil,
        dnsCname: String? = nil,
        dnsAnswerAddresses: [String]? = nil,
        tlsServerName: String? = nil,
        quicVersion: UInt32? = nil,
        quicPacketType: String? = nil,
        quicDestinationConnectionId: String? = nil,
        quicSourceConnectionId: String? = nil,
        classification: String? = nil,
        closeReason: FlowCloseReason? = nil,
        largePacketCount: Int? = nil,
        smallPacketCount: Int? = nil,
        udpPacketCount: Int? = nil,
        tcpPacketCount: Int? = nil,
        quicInitialCount: Int? = nil,
        tcpSynCount: Int? = nil,
        tcpFinCount: Int? = nil,
        tcpRstCount: Int? = nil,
        burstDurationMs: Int? = nil,
        burstPacketCount: Int? = nil,
        leadingBytes200ms: Int? = nil,
        leadingPackets200ms: Int? = nil,
        leadingBytes600ms: Int? = nil,
        leadingPackets600ms: Int? = nil,
        burstLargePacketCount: Int? = nil,
        burstUdpPacketCount: Int? = nil,
        burstTcpPacketCount: Int? = nil,
        burstQuicInitialCount: Int? = nil,
        associatedDomain: String? = nil,
        associationSource: DetectorAssociationSource? = nil,
        associationAgeMs: Int? = nil,
        associationConfidence: Double? = nil,
        lineageID: UInt64? = nil,
        lineageGeneration: Int? = nil,
        lineageAgeMs: Int? = nil,
        lineageReuseGapMs: Int? = nil,
        lineageReopenCount: Int? = nil,
        lineageSiblingCount: Int? = nil,
        pathEpoch: UInt32? = nil,
        pathInterfaceClass: PathInterfaceClass? = nil,
        pathIsExpensive: Bool? = nil,
        pathIsConstrained: Bool? = nil,
        pathSupportsDNS: Bool? = nil,
        pathChangedRecently: Bool? = nil,
        serviceFamily: String? = nil,
        serviceFamilyConfidence: Double? = nil,
        serviceAttributionSourceMask: UInt16? = nil,
        packetLength: Int? = nil,
        transportPayloadLength: Int? = nil,
        tcpFlags: UInt8? = nil,
        tcpAck: Bool? = nil,
        tcpPsh: Bool? = nil,
        sessionContext: DetectorSessionContext? = nil,
        remoteAddress: String? = nil,
        remotePort: UInt16? = nil,
        remoteEndpoint: String? = nil,
        ownerKey: String? = nil,
        role: String? = nil,
        addressScopeFamily: AddressScopeFamily? = nil,
        addressScopeSource: AddressScopeSource? = nil,
        addressScopeConfidence: Double? = nil,
        sourceAppIdentifier: String? = nil,
        sourceAppUniqueIdentifierHash: String? = nil,
        sourceAppVersion: String? = nil,
        attributionFlowId: String? = nil,
        attributionSource: SourceAppAttributionSource? = nil,
        attributionObservedAtMs: Double? = nil,
        localEndpoint: String? = nil,
        remoteHostname: String? = nil
    ) {
        self.kind = kind
        self.timestamp = timestamp
        self.direction = direction
        self.flowId = flowId
        self.bytes = bytes
        self.packetCount = packetCount
        self.flowPacketCount = flowPacketCount
        self.flowByteCount = flowByteCount
        self.protocolHint = protocolHint
        self.ipVersion = ipVersion
        self.transportProtocolNumber = transportProtocolNumber
        self.sourceAddress = sourceAddress
        self.sourcePort = sourcePort
        self.destinationAddress = destinationAddress
        self.destinationPort = destinationPort
        self.registrableDomain = registrableDomain
        self.dnsQueryName = dnsQueryName
        self.dnsCname = dnsCname
        self.dnsAnswerAddresses = dnsAnswerAddresses
        self.tlsServerName = tlsServerName
        self.quicVersion = quicVersion
        self.quicPacketType = quicPacketType
        self.quicDestinationConnectionId = quicDestinationConnectionId
        self.quicSourceConnectionId = quicSourceConnectionId
        self.classification = classification
        self.closeReason = closeReason
        self.largePacketCount = largePacketCount
        self.smallPacketCount = smallPacketCount
        self.udpPacketCount = udpPacketCount
        self.tcpPacketCount = tcpPacketCount
        self.quicInitialCount = quicInitialCount
        self.tcpSynCount = tcpSynCount
        self.tcpFinCount = tcpFinCount
        self.tcpRstCount = tcpRstCount
        self.burstDurationMs = burstDurationMs
        self.burstPacketCount = burstPacketCount
        self.leadingBytes200ms = leadingBytes200ms
        self.leadingPackets200ms = leadingPackets200ms
        self.leadingBytes600ms = leadingBytes600ms
        self.leadingPackets600ms = leadingPackets600ms
        self.burstLargePacketCount = burstLargePacketCount
        self.burstUdpPacketCount = burstUdpPacketCount
        self.burstTcpPacketCount = burstTcpPacketCount
        self.burstQuicInitialCount = burstQuicInitialCount
        self.associatedDomain = associatedDomain
        self.associationSource = associationSource
        self.associationAgeMs = associationAgeMs
        self.associationConfidence = associationConfidence
        self.lineageID = lineageID
        self.lineageGeneration = lineageGeneration
        self.lineageAgeMs = lineageAgeMs
        self.lineageReuseGapMs = lineageReuseGapMs
        self.lineageReopenCount = lineageReopenCount
        self.lineageSiblingCount = lineageSiblingCount
        self.pathEpoch = pathEpoch
        self.pathInterfaceClass = pathInterfaceClass
        self.pathIsExpensive = pathIsExpensive
        self.pathIsConstrained = pathIsConstrained
        self.pathSupportsDNS = pathSupportsDNS
        self.pathChangedRecently = pathChangedRecently
        self.serviceFamily = serviceFamily
        self.serviceFamilyConfidence = serviceFamilyConfidence
        self.serviceAttributionSourceMask = serviceAttributionSourceMask
        self.packetLength = packetLength
        self.transportPayloadLength = transportPayloadLength
        self.tcpFlags = tcpFlags
        self.tcpAck = tcpAck
        self.tcpPsh = tcpPsh
        self.sessionId = sessionContext?.sessionId
        self.packetStreamStartedAtMs = sessionContext?.packetStreamStartedAtMs
        self.foregroundReadyAtMs = sessionContext?.foregroundReadyAtMs
        self.appOpenAtMs = sessionContext?.appOpenAtMs
        self.targetApp = sessionContext?.targetApp
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.remoteEndpoint = remoteEndpoint
        self.ownerKey = ownerKey
        self.role = role
        self.addressScopeFamily = addressScopeFamily
        self.addressScopeSource = addressScopeSource
        self.addressScopeConfidence = addressScopeConfidence
        self.sourceAppIdentifier = sourceAppIdentifier
        self.sourceAppUniqueIdentifierHash = sourceAppUniqueIdentifierHash
        self.sourceAppVersion = sourceAppVersion
        self.attributionFlowId = attributionFlowId
        self.attributionSource = attributionSource
        self.attributionObservedAtMs = attributionObservedAtMs
        self.localEndpoint = localEndpoint
        self.remoteHostname = remoteHostname
    }
}

public extension PacketSample {
    static func sourceAppFlow(
        timestamp: Date,
        attribution: SourceAppFlowAttribution,
        protocolHint: String = "ip",
        sourceAddress: String? = nil,
        sourcePort: UInt16? = nil,
        destinationAddress: String? = nil,
        destinationPort: UInt16? = nil,
        sessionContext: DetectorSessionContext? = nil
    ) -> PacketSample {
        let flowId = attribution.attributionFlowId
            ?? attribution.remoteEndpoint
            ?? attribution.sourceAppIdentifier
            ?? "source-app-flow"
        let scopeFamily = DetectorRecordDerivation.scopeFamily(
            sourceAppIdentifier: attribution.sourceAppIdentifier,
            role: nil,
            hosts: [attribution.remoteHostname]
        )
        return PacketSample(
            kind: .sourceAppFlow,
            timestamp: timestamp,
            direction: PacketDirection.outbound.rawValue,
            flowId: flowId,
            bytes: 0,
            packetCount: nil,
            protocolHint: protocolHint,
            sourceAddress: sourceAddress,
            sourcePort: sourcePort,
            destinationAddress: destinationAddress,
            destinationPort: destinationPort,
            sessionContext: sessionContext,
            remoteEndpoint: attribution.remoteEndpoint,
            ownerKey: DetectorRecordDerivation.ownerKey(
                sourceAppIdentifier: attribution.sourceAppIdentifier,
                role: nil,
                remoteEndpoint: attribution.remoteEndpoint,
                flowId: flowId
            ),
            addressScopeFamily: scopeFamily,
            addressScopeSource: scopeFamily == nil ? nil : .sourceApp,
            sourceAppIdentifier: attribution.sourceAppIdentifier,
            sourceAppUniqueIdentifierHash: attribution.sourceAppUniqueIdentifierHash,
            sourceAppVersion: attribution.sourceAppVersion,
            attributionFlowId: attribution.attributionFlowId,
            attributionSource: attribution.attributionSource,
            attributionObservedAtMs: attribution.observedAtMs,
            localEndpoint: attribution.localEndpoint,
            remoteHostname: attribution.remoteHostname
        )
    }
}

/// Bounded in-memory rolling packet tap retained inside the tunnel provider.
/// Decision: keep the last few seconds of detector events in memory and expose snapshots on demand through
/// `NETunnelProviderSession.sendProviderMessage`, instead of rewriting any persisted packet artifact in the tunnel
/// hot path.
public actor PacketSampleStream {
    public struct Snapshot: Sendable, Equatable {
        public let samples: [PacketSample]
        public let retainedSampleCount: Int
        public let retainedBytes: Int
        public let oldestSampleAt: Date?
        public let latestSampleAt: Date?

        public init(
            samples: [PacketSample],
            retainedSampleCount: Int,
            retainedBytes: Int,
            oldestSampleAt: Date?,
            latestSampleAt: Date?
        ) {
            self.samples = samples
            self.retainedSampleCount = retainedSampleCount
            self.retainedBytes = retainedBytes
            self.oldestSampleAt = oldestSampleAt
            self.latestSampleAt = latestSampleAt
        }
    }

    struct PacketStreamRecord: Sendable {
        let kind: PacketSampleKind
        let timestamp: Date
        let direction: String
        let bytes: Int
        let packetCount: Int?
        let flowPacketCount: Int?
        let flowByteCount: Int?
        let protocolHint: String
        let ipVersion: UInt8?
        let transportProtocolNumber: UInt8?
        let sourcePort: UInt16?
        let destinationPort: UInt16?
        let flowHash: UInt64?
        let textFlowId: String?
        let sourceAddressLength: UInt8?
        let sourceAddressHigh: UInt64?
        let sourceAddressLow: UInt64?
        let destinationAddressLength: UInt8?
        let destinationAddressHigh: UInt64?
        let destinationAddressLow: UInt64?
        let textSourceAddress: String?
        let textDestinationAddress: String?
        let registrableDomain: String?
        let dnsQueryName: String?
        let dnsCname: String?
        let dnsAnswerAddresses: [String]?
        let tlsServerName: String?
        let quicVersion: UInt32?
        let quicPacketType: String?
        let quicDestinationConnectionId: String?
        let quicSourceConnectionId: String?
        let classification: String?
        let closeReason: FlowCloseReason?
        let largePacketCount: Int?
        let smallPacketCount: Int?
        let udpPacketCount: Int?
        let tcpPacketCount: Int?
        let quicInitialCount: Int?
        let tcpSynCount: Int?
        let tcpFinCount: Int?
        let tcpRstCount: Int?
        let burstDurationMs: Int?
        let burstPacketCount: Int?
        let leadingBytes200ms: Int?
        let leadingPackets200ms: Int?
        let leadingBytes600ms: Int?
        let leadingPackets600ms: Int?
        let burstLargePacketCount: Int?
        let burstUdpPacketCount: Int?
        let burstTcpPacketCount: Int?
        let burstQuicInitialCount: Int?
        let associatedDomain: String?
        let associationSource: DetectorAssociationSource?
        let associationAgeMs: Int?
        let associationConfidence: Double?
        let lineageID: UInt64?
        let lineageGeneration: Int?
        let lineageAgeMs: Int?
        let lineageReuseGapMs: Int?
        let lineageReopenCount: Int?
        let lineageSiblingCount: Int?
        let pathEpoch: UInt32?
        let pathInterfaceClass: PathInterfaceClass?
        let pathIsExpensive: Bool?
        let pathIsConstrained: Bool?
        let pathSupportsDNS: Bool?
        let pathChangedRecently: Bool?
        let serviceFamily: String?
        let serviceFamilyConfidence: Double?
        let serviceAttributionSourceMask: UInt16?
        let packetLength: Int?
        let transportPayloadLength: Int?
        let tcpFlags: UInt8?
        let tcpAck: Bool?
        let tcpPsh: Bool?
        let sessionId: String?
        let packetStreamStartedAtMs: Double?
        let foregroundReadyAtMs: Double?
        let appOpenAtMs: Double?
        let targetApp: String?
        let remoteAddress: String?
        let remotePort: UInt16?
        let remoteEndpoint: String?
        let ownerKey: String?
        let role: String?
        let addressScopeFamily: AddressScopeFamily?
        let addressScopeSource: AddressScopeSource?
        let addressScopeConfidence: Double?
        let sourceAppIdentifier: String?
        let sourceAppUniqueIdentifierHash: String?
        let sourceAppVersion: String?
        let attributionFlowId: String?
        let attributionSource: SourceAppAttributionSource?
        let attributionObservedAtMs: Double?
        let localEndpoint: String?
        let remoteHostname: String?

        init(
            kind: PacketSampleKind,
            timestamp: Date,
            direction: String,
            bytes: Int,
            packetCount: Int?,
            flowPacketCount: Int?,
            flowByteCount: Int?,
            protocolHint: String,
            ipVersion: UInt8?,
            transportProtocolNumber: UInt8?,
            sourcePort: UInt16?,
            destinationPort: UInt16?,
            flowHash: UInt64?,
            textFlowId: String?,
            sourceAddressLength: UInt8?,
            sourceAddressHigh: UInt64?,
            sourceAddressLow: UInt64?,
            destinationAddressLength: UInt8?,
            destinationAddressHigh: UInt64?,
            destinationAddressLow: UInt64?,
            textSourceAddress: String?,
            textDestinationAddress: String?,
            registrableDomain: String?,
            dnsQueryName: String?,
            dnsCname: String?,
            dnsAnswerAddresses: [String]?,
            tlsServerName: String?,
            quicVersion: UInt32?,
            quicPacketType: String?,
            quicDestinationConnectionId: String?,
            quicSourceConnectionId: String?,
            classification: String?,
            closeReason: FlowCloseReason?,
            largePacketCount: Int?,
            smallPacketCount: Int?,
            udpPacketCount: Int?,
            tcpPacketCount: Int?,
            quicInitialCount: Int?,
            tcpSynCount: Int?,
            tcpFinCount: Int?,
            tcpRstCount: Int?,
            burstDurationMs: Int?,
            burstPacketCount: Int?,
            leadingBytes200ms: Int?,
            leadingPackets200ms: Int?,
            leadingBytes600ms: Int?,
            leadingPackets600ms: Int?,
            burstLargePacketCount: Int?,
            burstUdpPacketCount: Int?,
            burstTcpPacketCount: Int?,
            burstQuicInitialCount: Int?,
            associatedDomain: String?,
            associationSource: DetectorAssociationSource?,
            associationAgeMs: Int?,
            associationConfidence: Double?,
            lineageID: UInt64?,
            lineageGeneration: Int?,
            lineageAgeMs: Int?,
            lineageReuseGapMs: Int?,
            lineageReopenCount: Int?,
            lineageSiblingCount: Int?,
            pathEpoch: UInt32?,
            pathInterfaceClass: PathInterfaceClass?,
            pathIsExpensive: Bool?,
            pathIsConstrained: Bool?,
            pathSupportsDNS: Bool?,
            pathChangedRecently: Bool?,
            serviceFamily: String?,
            serviceFamilyConfidence: Double?,
            serviceAttributionSourceMask: UInt16?,
            packetLength: Int? = nil,
            transportPayloadLength: Int? = nil,
            tcpFlags: UInt8? = nil,
            tcpAck: Bool? = nil,
            tcpPsh: Bool? = nil,
            sessionContext: DetectorSessionContext? = nil,
            remoteAddress: String? = nil,
            remotePort: UInt16? = nil,
            remoteEndpoint: String? = nil,
            ownerKey: String? = nil,
            role: String? = nil,
            addressScopeFamily: AddressScopeFamily? = nil,
            addressScopeSource: AddressScopeSource? = nil,
            addressScopeConfidence: Double? = nil,
            sourceAppIdentifier: String? = nil,
            sourceAppUniqueIdentifierHash: String? = nil,
            sourceAppVersion: String? = nil,
            attributionFlowId: String? = nil,
            attributionSource: SourceAppAttributionSource? = nil,
            attributionObservedAtMs: Double? = nil,
            localEndpoint: String? = nil,
            remoteHostname: String? = nil
        ) {
            self.kind = kind
            self.timestamp = timestamp
            self.direction = direction
            self.bytes = bytes
            self.packetCount = packetCount
            self.flowPacketCount = flowPacketCount
            self.flowByteCount = flowByteCount
            self.protocolHint = protocolHint
            self.ipVersion = ipVersion
            self.transportProtocolNumber = transportProtocolNumber
            self.sourcePort = sourcePort
            self.destinationPort = destinationPort
            self.flowHash = flowHash
            self.textFlowId = textFlowId
            self.sourceAddressLength = sourceAddressLength
            self.sourceAddressHigh = sourceAddressHigh
            self.sourceAddressLow = sourceAddressLow
            self.destinationAddressLength = destinationAddressLength
            self.destinationAddressHigh = destinationAddressHigh
            self.destinationAddressLow = destinationAddressLow
            self.textSourceAddress = textSourceAddress
            self.textDestinationAddress = textDestinationAddress
            self.registrableDomain = registrableDomain
            self.dnsQueryName = dnsQueryName
            self.dnsCname = dnsCname
            self.dnsAnswerAddresses = dnsAnswerAddresses
            self.tlsServerName = tlsServerName
            self.quicVersion = quicVersion
            self.quicPacketType = quicPacketType
            self.quicDestinationConnectionId = quicDestinationConnectionId
            self.quicSourceConnectionId = quicSourceConnectionId
            self.classification = classification
            self.closeReason = closeReason
            self.largePacketCount = largePacketCount
            self.smallPacketCount = smallPacketCount
            self.udpPacketCount = udpPacketCount
            self.tcpPacketCount = tcpPacketCount
            self.quicInitialCount = quicInitialCount
            self.tcpSynCount = tcpSynCount
            self.tcpFinCount = tcpFinCount
            self.tcpRstCount = tcpRstCount
            self.burstDurationMs = burstDurationMs
            self.burstPacketCount = burstPacketCount
            self.leadingBytes200ms = leadingBytes200ms
            self.leadingPackets200ms = leadingPackets200ms
            self.leadingBytes600ms = leadingBytes600ms
            self.leadingPackets600ms = leadingPackets600ms
            self.burstLargePacketCount = burstLargePacketCount
            self.burstUdpPacketCount = burstUdpPacketCount
            self.burstTcpPacketCount = burstTcpPacketCount
            self.burstQuicInitialCount = burstQuicInitialCount
            self.associatedDomain = associatedDomain
            self.associationSource = associationSource
            self.associationAgeMs = associationAgeMs
            self.associationConfidence = associationConfidence
            self.lineageID = lineageID
            self.lineageGeneration = lineageGeneration
            self.lineageAgeMs = lineageAgeMs
            self.lineageReuseGapMs = lineageReuseGapMs
            self.lineageReopenCount = lineageReopenCount
            self.lineageSiblingCount = lineageSiblingCount
            self.pathEpoch = pathEpoch
            self.pathInterfaceClass = pathInterfaceClass
            self.pathIsExpensive = pathIsExpensive
            self.pathIsConstrained = pathIsConstrained
            self.pathSupportsDNS = pathSupportsDNS
            self.pathChangedRecently = pathChangedRecently
            self.serviceFamily = serviceFamily
            self.serviceFamilyConfidence = serviceFamilyConfidence
            self.serviceAttributionSourceMask = serviceAttributionSourceMask
            self.packetLength = packetLength
            self.transportPayloadLength = transportPayloadLength
            self.tcpFlags = tcpFlags
            self.tcpAck = tcpAck
            self.tcpPsh = tcpPsh
            self.sessionId = sessionContext?.sessionId
            self.packetStreamStartedAtMs = sessionContext?.packetStreamStartedAtMs
            self.foregroundReadyAtMs = sessionContext?.foregroundReadyAtMs
            self.appOpenAtMs = sessionContext?.appOpenAtMs
            self.targetApp = sessionContext?.targetApp
            self.remoteAddress = remoteAddress
            self.remotePort = remotePort
            self.remoteEndpoint = remoteEndpoint
            self.ownerKey = ownerKey
            self.role = role
            self.addressScopeFamily = addressScopeFamily
            self.addressScopeSource = addressScopeSource
            self.addressScopeConfidence = addressScopeConfidence
            self.sourceAppIdentifier = sourceAppIdentifier
            self.sourceAppUniqueIdentifierHash = sourceAppUniqueIdentifierHash
            self.sourceAppVersion = sourceAppVersion
            self.attributionFlowId = attributionFlowId
            self.attributionSource = attributionSource
            self.attributionObservedAtMs = attributionObservedAtMs
            self.localEndpoint = localEndpoint
            self.remoteHostname = remoteHostname
        }
    }

    private enum StoredPayload: Sendable {
        case sample(PacketSample)
        case record(PacketStreamRecord)
    }

    private struct StoredRecord: Sendable {
        let payload: StoredPayload
        let timestamp: Date
        let retainedAt: Date
        let estimatedBytes: Int

        var sample: PacketSample {
            switch payload {
            case .sample(let sample):
                return sample
            case .record(let record):
                return PacketSampleStream.makeSample(from: record)
            }
        }
    }

    private let maxBytes: Int
    private let retentionWindowSeconds: TimeInterval
    private let clock: any Clock
    private let logger: StructuredLogger

    private var records: [StoredRecord] = []
    private var startIndex = 0
    private var retainedBytes = 0

    /// Creates a bounded rolling packet tap.
    /// - Parameters:
    ///   - maxBytes: Approximate memory budget for retained samples.
    ///   - retentionWindowSeconds: Maximum age of retained samples.
    ///   - clock: Time source shared with the telemetry pipeline.
    ///   - logger: Logger used when a single record exceeds the memory budget.
    public init(
        maxBytes: Int,
        retentionWindowSeconds: TimeInterval = 10,
        clock: any Clock = SystemClock(),
        logger: StructuredLogger
    ) {
        self.maxBytes = max(1, maxBytes)
        self.retentionWindowSeconds = max(1, retentionWindowSeconds)
        self.clock = clock
        self.logger = logger
    }

    /// Appends one sample into the rolling tap.
    public func append(_ sample: PacketSample) async throws {
        try await append(contentsOf: [sample])
    }

    /// Appends a batch of already-decoded samples into the rolling tap.
    public func append(contentsOf samples: [PacketSample]) async throws {
        guard !samples.isEmpty else {
            return
        }

        let now = await clock.now()
        evictExpired(now: now)
        for sample in samples {
            try await store(sample, retainedAt: now)
        }
        compactStorageIfNeeded()
    }

    /// Appends compact detector records into the rolling tap.
    /// Decision: the worker still emits compact records to avoid rebuilding expensive flow metadata on every branch,
    /// and the app-facing snapshot reconstructs `PacketSample` values lazily only when a foreground reader asks.
    func append(records: [PacketStreamRecord]) async throws {
        guard !records.isEmpty else {
            return
        }

        let now = await clock.now()
        evictExpired(now: now)
        for record in records {
            try await store(record: record, retainedAt: now)
        }
        compactStorageIfNeeded()
    }

    /// Returns the current rolling window in oldest-to-newest order.
    /// - Parameter limit: Optional cap applied to the newest retained samples.
    public func snapshot(limit: Int? = nil) async -> Snapshot {
        let now = await clock.now()
        evictExpired(now: now)

        let liveRecords = liveRecordsSlice()
        let limitedRecords: ArraySlice<StoredRecord>
        if let limit {
            limitedRecords = liveRecords.suffix(max(0, limit))
        } else {
            limitedRecords = liveRecords
        }
        let limitedSamples = limitedRecords.map(\.sample)

        return Snapshot(
            samples: limitedSamples,
            retainedSampleCount: liveRecords.count,
            retainedBytes: retainedBytes,
            oldestSampleAt: liveRecords.first?.timestamp,
            latestSampleAt: liveRecords.last?.timestamp
        )
    }

    /// Returns all currently retained samples.
    public func readAll() async -> [PacketSample] {
        await snapshot().samples
    }

    /// Clears the rolling window immediately.
    public func reset() {
        records.removeAll(keepingCapacity: false)
        startIndex = 0
        retainedBytes = 0
    }

    /// Approximate memory cost used for eviction policy tests and capacity sizing.
    public static func estimatedRecordSize(for sample: PacketSample) -> Int {
        var size = 224

        func add(_ value: String?) {
            guard let value else { return }
            size = saturatingAdd(size, value.utf8.count)
        }

        func add(_ values: [String]?) {
            guard let values else { return }
            size = saturatingAdd(size, 16)
            for value in values {
                size = saturatingAdd(size, value.utf8.count)
            }
        }

        add(sample.direction)
        add(sample.flowId)
        add(sample.protocolHint)
        add(sample.sourceAddress)
        add(sample.destinationAddress)
        add(sample.registrableDomain)
        add(sample.dnsQueryName)
        add(sample.dnsCname)
        add(sample.dnsAnswerAddresses)
        add(sample.tlsServerName)
        add(sample.quicPacketType)
        add(sample.quicDestinationConnectionId)
        add(sample.quicSourceConnectionId)
        add(sample.classification)
        add(sample.associatedDomain)
        add(sample.serviceFamily)
        add(sample.sessionId)
        add(sample.targetApp)
        add(sample.remoteAddress)
        add(sample.remoteEndpoint)
        add(sample.ownerKey)
        add(sample.role)
        add(sample.sourceAppIdentifier)
        add(sample.sourceAppUniqueIdentifierHash)
        add(sample.sourceAppVersion)
        add(sample.attributionFlowId)
        add(sample.localEndpoint)
        add(sample.remoteHostname)
        return size
    }

    static func estimatedRecordSize(for record: PacketStreamRecord) -> Int {
        var size = 224

        func add(_ value: String?) {
            guard let value else { return }
            size = saturatingAdd(size, value.utf8.count)
        }

        func add(_ values: [String]?) {
            guard let values else { return }
            size = saturatingAdd(size, 16)
            for value in values {
                size = saturatingAdd(size, value.utf8.count)
            }
        }

        add(record.direction)
        if let textFlowId = record.textFlowId, !textFlowId.isEmpty {
            add(textFlowId)
        } else if record.flowHash != nil {
            size = saturatingAdd(size, 16)
        }
        add(record.protocolHint)
        add(record.textSourceAddress)
        add(record.textDestinationAddress)
        add(record.registrableDomain)
        add(record.dnsQueryName)
        add(record.dnsCname)
        add(record.dnsAnswerAddresses)
        add(record.tlsServerName)
        add(record.quicPacketType)
        add(record.quicDestinationConnectionId)
        add(record.quicSourceConnectionId)
        add(record.classification)
        add(record.associatedDomain)
        add(record.serviceFamily)
        add(record.sessionId)
        add(record.targetApp)
        add(record.remoteAddress)
        add(record.remoteEndpoint)
        add(record.ownerKey)
        add(record.role)
        add(record.sourceAppIdentifier)
        add(record.sourceAppUniqueIdentifierHash)
        add(record.sourceAppVersion)
        add(record.attributionFlowId)
        add(record.localEndpoint)
        add(record.remoteHostname)
        return size
    }

    private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int.max : value
    }

    private func store(_ sample: PacketSample, retainedAt: Date) async throws {
        let estimatedBytes = Self.estimatedRecordSize(for: sample)
        guard estimatedBytes <= maxBytes else {
            await logger.log(
                level: .warning,
                phase: .storage,
                category: .liveTap,
                component: "PacketSampleStream",
                event: "packet-sample-dropped",
                result: "oversized-record",
                message: "Dropped packet sample because it exceeds the in-memory rolling window budget",
                metadata: [
                    "record_bytes": String(estimatedBytes),
                    "window_bytes": String(maxBytes)
                ]
            )
            return
        }

        records.append(
            StoredRecord(
                payload: .sample(sample),
                timestamp: sample.timestamp,
                retainedAt: retainedAt,
                estimatedBytes: estimatedBytes
            )
        )
        retainedBytes = Self.saturatingAdd(retainedBytes, estimatedBytes)
        evictToFitBudget()
    }

    private func store(record: PacketStreamRecord, retainedAt: Date) async throws {
        let estimatedBytes = Self.estimatedRecordSize(for: record)
        guard estimatedBytes <= maxBytes else {
            await logger.log(
                level: .warning,
                phase: .storage,
                category: .liveTap,
                component: "PacketSampleStream",
                event: "packet-sample-dropped",
                result: "oversized-record",
                message: "Dropped packet sample because it exceeds the in-memory rolling window budget",
                metadata: [
                    "record_bytes": String(estimatedBytes),
                    "window_bytes": String(maxBytes)
                ]
            )
            return
        }

        records.append(
            StoredRecord(
                payload: .record(record),
                timestamp: record.timestamp,
                retainedAt: retainedAt,
                estimatedBytes: estimatedBytes
            )
        )
        retainedBytes = Self.saturatingAdd(retainedBytes, estimatedBytes)
        evictToFitBudget()
    }

    private func evictExpired(now: Date) {
        while startIndex < records.count,
              now.timeIntervalSince(records[startIndex].retainedAt) > retentionWindowSeconds {
            retainedBytes -= records[startIndex].estimatedBytes
            startIndex += 1
        }
        compactStorageIfNeeded()
    }

    private func evictToFitBudget() {
        while retainedBytes > maxBytes, startIndex < records.count {
            retainedBytes -= records[startIndex].estimatedBytes
            startIndex += 1
        }
        compactStorageIfNeeded()
    }

    private func compactStorageIfNeeded() {
        guard startIndex > 0 else {
            return
        }
        if startIndex >= 128 || startIndex * 2 >= records.count {
            records = Array(records[startIndex...])
            startIndex = 0
        }
        if startIndex >= records.count {
            records.removeAll(keepingCapacity: false)
            startIndex = 0
        }
        retainedBytes = max(0, retainedBytes)
    }

    private func liveRecordsSlice() -> ArraySlice<StoredRecord> {
        guard startIndex < records.count else {
            return []
        }
        return records[startIndex...]
    }

    private static func makeSample(from record: PacketStreamRecord) -> PacketSample {
        let flowId = flowIdentifier(for: record)
        let sourceAddress = decodedAddress(
            length: record.sourceAddressLength,
            high: record.sourceAddressHigh,
            low: record.sourceAddressLow,
            fallback: record.textSourceAddress
        )
        let destinationAddress = decodedAddress(
            length: record.destinationAddressLength,
            high: record.destinationAddressHigh,
            low: record.destinationAddressLow,
            fallback: record.textDestinationAddress
        )
        let remoteAddress = record.remoteAddress ?? DetectorRecordDerivation.remoteAddress(
            direction: record.direction,
            sourceAddress: sourceAddress,
            destinationAddress: destinationAddress
        )
        let remotePort = record.remotePort ?? DetectorRecordDerivation.remotePort(
            direction: record.direction,
            sourcePort: record.sourcePort,
            destinationPort: record.destinationPort
        )
        let remoteEndpoint = record.remoteEndpoint ?? DetectorRecordDerivation.endpoint(
            protocolHint: record.protocolHint,
            address: remoteAddress,
            port: remotePort
        )
        let role = record.role ?? DetectorRecordDerivation.role(
            serviceFamily: record.serviceFamily,
            associatedDomain: record.associatedDomain,
            registrableDomain: record.registrableDomain,
            tlsServerName: record.tlsServerName,
            dnsQueryName: record.dnsQueryName,
            dnsCname: record.dnsCname,
            classification: record.classification
        )
        let derivedScopeFamily = DetectorRecordDerivation.scopeFamily(
            sourceAppIdentifier: record.sourceAppIdentifier,
            role: role,
            hosts: [
                record.associatedDomain,
                record.registrableDomain,
                record.tlsServerName,
                record.dnsQueryName,
                record.dnsCname
            ]
        )
        let derivedScopeSource: AddressScopeSource? = {
            guard derivedScopeFamily != nil else { return nil }
            let sourceAppScope = DetectorRecordDerivation.scopeFamily(
                sourceAppIdentifier: record.sourceAppIdentifier,
                role: nil,
                hosts: []
            )
            return sourceAppScope == nil ? .role : .sourceApp
        }()
        let addressScopeFamily = record.addressScopeFamily ?? derivedScopeFamily
        let addressScopeSource = record.addressScopeSource ?? derivedScopeSource
        return PacketSample(
            kind: record.kind,
            timestamp: record.timestamp,
            direction: record.direction,
            flowId: flowId,
            bytes: record.bytes,
            packetCount: record.packetCount,
            flowPacketCount: record.flowPacketCount,
            flowByteCount: record.flowByteCount,
            protocolHint: record.protocolHint,
            ipVersion: record.ipVersion,
            transportProtocolNumber: record.transportProtocolNumber,
            sourceAddress: sourceAddress,
            sourcePort: record.sourcePort,
            destinationAddress: destinationAddress,
            destinationPort: record.destinationPort,
            registrableDomain: record.registrableDomain,
            dnsQueryName: record.dnsQueryName,
            dnsCname: record.dnsCname,
            dnsAnswerAddresses: record.dnsAnswerAddresses,
            tlsServerName: record.tlsServerName,
            quicVersion: record.quicVersion,
            quicPacketType: record.quicPacketType,
            quicDestinationConnectionId: record.quicDestinationConnectionId,
            quicSourceConnectionId: record.quicSourceConnectionId,
            classification: record.classification,
            closeReason: record.closeReason,
            largePacketCount: record.largePacketCount,
            smallPacketCount: record.smallPacketCount,
            udpPacketCount: record.udpPacketCount,
            tcpPacketCount: record.tcpPacketCount,
            quicInitialCount: record.quicInitialCount,
            tcpSynCount: record.tcpSynCount,
            tcpFinCount: record.tcpFinCount,
            tcpRstCount: record.tcpRstCount,
            burstDurationMs: record.burstDurationMs,
            burstPacketCount: record.burstPacketCount,
            leadingBytes200ms: record.leadingBytes200ms,
            leadingPackets200ms: record.leadingPackets200ms,
            leadingBytes600ms: record.leadingBytes600ms,
            leadingPackets600ms: record.leadingPackets600ms,
            burstLargePacketCount: record.burstLargePacketCount,
            burstUdpPacketCount: record.burstUdpPacketCount,
            burstTcpPacketCount: record.burstTcpPacketCount,
            burstQuicInitialCount: record.burstQuicInitialCount,
            associatedDomain: record.associatedDomain,
            associationSource: record.associationSource,
            associationAgeMs: record.associationAgeMs,
            associationConfidence: record.associationConfidence,
            lineageID: record.lineageID,
            lineageGeneration: record.lineageGeneration,
            lineageAgeMs: record.lineageAgeMs,
            lineageReuseGapMs: record.lineageReuseGapMs,
            lineageReopenCount: record.lineageReopenCount,
            lineageSiblingCount: record.lineageSiblingCount,
            pathEpoch: record.pathEpoch,
            pathInterfaceClass: record.pathInterfaceClass,
            pathIsExpensive: record.pathIsExpensive,
            pathIsConstrained: record.pathIsConstrained,
            pathSupportsDNS: record.pathSupportsDNS,
            pathChangedRecently: record.pathChangedRecently,
            serviceFamily: record.serviceFamily,
            serviceFamilyConfidence: record.serviceFamilyConfidence,
            serviceAttributionSourceMask: record.serviceAttributionSourceMask,
            packetLength: record.packetLength,
            transportPayloadLength: record.transportPayloadLength,
            tcpFlags: record.tcpFlags,
            tcpAck: record.tcpAck,
            tcpPsh: record.tcpPsh,
            sessionContext: DetectorSessionContext(
                sessionId: record.sessionId,
                packetStreamStartedAtMs: record.packetStreamStartedAtMs,
                foregroundReadyAtMs: record.foregroundReadyAtMs,
                appOpenAtMs: record.appOpenAtMs,
                targetApp: record.targetApp
            ),
            remoteAddress: remoteAddress,
            remotePort: remotePort,
            remoteEndpoint: remoteEndpoint,
            ownerKey: record.ownerKey ?? DetectorRecordDerivation.ownerKey(
                sourceAppIdentifier: record.sourceAppIdentifier,
                role: role,
                remoteEndpoint: remoteEndpoint,
                flowId: flowId
            ),
            role: role,
            addressScopeFamily: addressScopeFamily,
            addressScopeSource: addressScopeSource,
            addressScopeConfidence: record.addressScopeConfidence ?? (derivedScopeFamily == nil ? nil : 0.66),
            sourceAppIdentifier: record.sourceAppIdentifier,
            sourceAppUniqueIdentifierHash: record.sourceAppUniqueIdentifierHash,
            sourceAppVersion: record.sourceAppVersion,
            attributionFlowId: record.attributionFlowId,
            attributionSource: record.attributionSource,
            attributionObservedAtMs: record.attributionObservedAtMs,
            localEndpoint: record.localEndpoint,
            remoteHostname: record.remoteHostname
        )
    }

    private static func flowIdentifier(for record: PacketStreamRecord) -> String {
        if let textFlowId = record.textFlowId, !textFlowId.isEmpty {
            return textFlowId
        }
        if let flowHash = record.flowHash {
            return String(format: "%016llx", flowHash)
        }
        return "unknown-flow"
    }

    static func decodedAddress(
        length: UInt8?,
        high: UInt64?,
        low: UInt64?,
        fallback: String?
    ) -> String? {
        guard let length, let high, let low else {
            return fallback
        }

        var bytes = [UInt8](repeating: 0, count: 16)
        var highBE = high.bigEndian
        var lowBE = low.bigEndian
        let highBytes = withUnsafeBytes(of: &highBE) { Array($0) }
        let lowBytes = withUnsafeBytes(of: &lowBE) { Array($0) }
        bytes.replaceSubrange(0..<8, with: highBytes)
        bytes.replaceSubrange(8..<16, with: lowBytes)

        switch length {
        case 4:
            var address = in_addr()
            var didCopyAddress = false
            withUnsafeMutableBytes(of: &address) { addressBuffer in
                bytes.withUnsafeBytes { rawBuffer in
                    guard let destination = addressBuffer.baseAddress,
                          let source = rawBuffer.baseAddress?.advanced(by: 12) else {
                        return
                    }
                    memcpy(destination, source, 4)
                    didCopyAddress = true
                }
            }
            guard didCopyAddress else {
                return fallback
            }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
                return fallback
            }
            return String(cString: buffer)
        case 16:
            var address = in6_addr()
            var didCopyAddress = false
            withUnsafeMutableBytes(of: &address) { addressBuffer in
                bytes.withUnsafeBytes { rawBuffer in
                    guard let destination = addressBuffer.baseAddress,
                          let source = rawBuffer.baseAddress else {
                        return
                    }
                    memcpy(destination, source, 16)
                    didCopyAddress = true
                }
            }
            guard didCopyAddress else {
                return fallback
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return fallback
            }
            return String(cString: buffer)
        default:
            return fallback
        }
    }
}
